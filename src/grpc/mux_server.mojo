# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""A readiness-driven gRPC server that multiplexes every stream on every
connection through one Poller thread.

`PollingServer` serves one stream per connection and runs streaming handlers
to completion. `MuxServer` instead drives a `MuxService`: an explicit state
machine that receives call events (start, message, half-close, end) and is
pumped for output whenever a call's outbound backlog is below its bound. No
handler blocks, so a long server stream on one connection never delays a
unary call on the same or another connection.

Flow control follows HTTP/2: a call's framed output waits in a bounded
backlog until the peer grants stream and connection credit, and the service
is not pumped while the backlog is full. Socket output, the HTTP/2 queue, and
each call backlog have named bounds in `MuxServerConfig`.

TLS accepts `h2` or no ALPN. Plaintext h2c is used when no certificate is
configured.
"""

from std.ffi import c_int, external_call
from std.time import monotonic

from hpack import HeaderField
from h2 import Http2Connection
from net import Poller, TCPListener, is_would_block
from tls import TLSContext, TLSHandshake

from .framing import GRPC_MESSAGE_PREFIX_LEN, frame_message
from .metadata import encode_bin_value
from .polling_server import accepts_alpn
from .status import Status, StatusCode, percent_encode_message
from .timeout import decode_timeout
from .transport import GrpcTransport

comptime _ERR_NO_ERROR: UInt32 = 0
comptime _NS_PER_MS: Int64 = 1_000_000
comptime _SIGPIPE: c_int = 13
comptime _SIG_IGN: Int = 1


struct MuxServerConfig(Copyable, Movable):
    """Bounds for `MuxServer`. Every queue it owns has a limit here."""

    var max_connections: Int
    var max_streams_per_connection: Int
    var max_message_bytes: Int
    var initial_window_bytes: UInt32
    var max_h2_output_bytes: Int
    var max_socket_output_bytes: Int
    var max_call_backlog_bytes: Int
    var max_read_bytes_per_event: Int
    var idle_timeout_ms: Int
    var tls_handshake_timeout_ms: Int
    var max_accepts_per_event: Int

    def __init__(
        out self,
        *,
        max_connections: Int = 256,
        max_streams_per_connection: Int = 128,
        max_message_bytes: Int = 4 * 1024 * 1024,
        initial_window_bytes: UInt32 = 1024 * 1024,
        max_h2_output_bytes: Int = 256 * 1024,
        max_socket_output_bytes: Int = 1024 * 1024,
        max_call_backlog_bytes: Int = 256 * 1024,
        max_read_bytes_per_event: Int = 256 * 1024,
        idle_timeout_ms: Int = 600_000,
        tls_handshake_timeout_ms: Int = 10_000,
        max_accepts_per_event: Int = 32,
    ):
        self.max_connections = max_connections
        self.max_streams_per_connection = max_streams_per_connection
        self.max_message_bytes = max_message_bytes
        self.initial_window_bytes = initial_window_bytes
        self.max_h2_output_bytes = max_h2_output_bytes
        self.max_socket_output_bytes = max_socket_output_bytes
        self.max_call_backlog_bytes = max_call_backlog_bytes
        self.max_read_bytes_per_event = max_read_bytes_per_event
        self.idle_timeout_ms = idle_timeout_ms
        self.tls_handshake_timeout_ms = tls_handshake_timeout_ms
        self.max_accepts_per_event = max_accepts_per_event

    def validate(self) raises:
        if self.max_connections <= 0 or self.max_streams_per_connection <= 0:
            raise Error(
                "grpc: mux connection and stream limits must be positive"
            )
        if self.max_message_bytes <= 0 or self.max_message_bytes > 0xFFFFFFFF:
            raise Error("grpc: mux max_message_bytes out of range")
        if self.initial_window_bytes > 0x7FFFFFFF:
            raise Error("grpc: mux initial window exceeds 2^31-1")
        if self.max_h2_output_bytes < 16 * 1024:
            raise Error("grpc: mux max_h2_output_bytes below 16 KiB")
        if self.max_socket_output_bytes < self.max_h2_output_bytes:
            raise Error("grpc: mux socket output below the HTTP/2 queue")
        if (
            self.max_call_backlog_bytes <= 0
            or self.max_read_bytes_per_event <= 0
        ):
            raise Error("grpc: mux backlog and read limits must be positive")
        if self.idle_timeout_ms <= 0 or self.tls_handshake_timeout_ms <= 0:
            raise Error("grpc: mux timeouts must be positive")


struct MuxOutput(Movable):
    """What one `pump` produced for a call: messages and an optional final
    status. `room_bytes` is the backlog space left for this pump."""

    var messages: List[List[Byte]]
    var bytes: Int
    var room_bytes: Int
    var status: Optional[Status]

    def __init__(out self, room_bytes: Int):
        self.messages = List[List[Byte]]()
        self.bytes = 0
        self.room_bytes = room_bytes
        self.status = None

    def room(self) -> Int:
        return self.room_bytes - self.bytes

    def send(mut self, var message: List[Byte]):
        self.bytes += len(message) + GRPC_MESSAGE_PREFIX_LEN
        self.messages.append(message^)

    def finish(mut self, var status: Status):
        self.status = status^


trait MuxService(Deinitable, Movable):
    """The application state machine behind a `MuxServer`.

    Every call that reaches `on_start` gets exactly one `on_end`. Returning a
    status from `on_start` or `on_message` finishes the call with it. After
    `on_end` the service is never pumped for that call again.
    """

    def on_start(
        mut self,
        call: UInt64,
        path: String,
        headers: List[HeaderField],
        now_ns: Int64,
    ) raises -> Optional[Status]:
        ...

    def on_message(
        mut self, call: UInt64, message: List[Byte], now_ns: Int64
    ) raises -> Optional[Status]:
        ...

    def on_half_close(mut self, call: UInt64, now_ns: Int64) raises:
        ...

    def on_end(mut self, call: UInt64, cancelled: Bool, now_ns: Int64):
        ...

    def pump(mut self, call: UInt64, mut out: MuxOutput, now_ns: Int64) raises:
        ...

    def tick(mut self, now_ns: Int64) raises:
        ...

    def next_wake_ns(self, now_ns: Int64) -> Int64:
        """Absolute monotonic time of the next timer, or -1 for none."""
        ...


struct _Outbox(Movable, Sized):
    var data: List[Byte]
    var offset: Int

    def __init__(out self):
        self.data = List[Byte]()
        self.offset = 0

    def __len__(self) -> Int:
        return len(self.data) - self.offset

    def append(mut self, bytes: Span[Byte, _]):
        if self.offset > 0 and self.offset * 2 >= len(self.data):
            self.data = List[Byte](Span(self.data)[self.offset :])
            self.offset = 0
        self.data.extend(bytes)

    def pending(self) -> Span[Byte, origin_of(self.data)]:
        return Span(self.data)[self.offset :]

    def advance(mut self, count: Int):
        self.offset += count
        if self.offset == len(self.data):
            self.data = List[Byte]()
            self.offset = 0


struct _MuxCall(Movable):
    var id: UInt64
    var sid: UInt32
    var inbound: List[Byte]
    var half_closed: Bool
    var rejected: Bool
    var outbound: _Outbox
    var status: Optional[Status]
    var headers_sent: Bool
    var finished: Bool
    var ended: Bool
    var deadline_ns: Int64

    def __init__(out self, id: UInt64, sid: UInt32, deadline_ns: Int64):
        self.id = id
        self.sid = sid
        self.inbound = List[Byte]()
        self.half_closed = False
        self.rejected = False
        self.outbound = _Outbox()
        self.status = None
        self.headers_sent = False
        self.finished = False
        self.ended = False
        self.deadline_ns = deadline_ns


struct _MuxConnection(Movable):
    var h2: Http2Connection[GrpcTransport]
    var output: _Outbox
    var calls: List[_MuxCall]
    var last_activity_ns: Int64
    var peer_eof: Bool
    var resume_read: Bool
    var tls_wants_write: Bool

    def __init__(
        out self, var transport: GrpcTransport, config: MuxServerConfig
    ) raises:
        self.h2 = Http2Connection(
            transport^,
            is_client=False,
            initial_window_size=config.initial_window_bytes,
            max_concurrent_streams=config.max_streams_per_connection,
            max_pending_output_size=config.max_h2_output_bytes,
        )
        self.output = _Outbox()
        self.calls = List[_MuxCall]()
        self.last_activity_ns = Int64(monotonic())
        self.peer_eof = False
        self.resume_read = False
        self.tls_wants_write = False

    def descriptor(self) -> c_int:
        return self.h2.stream.descriptor()

    def has_call(self, sid: UInt32) -> Bool:
        for i in range(len(self.calls)):
            if self.calls[i].sid == sid:
                return True
        return False


def _find(headers: List[HeaderField], name: StringSpan) -> String:
    for field in headers:
        if field.name == name:
            return field.value.copy()
    return String()


def _response_headers() -> List[HeaderField]:
    var out = List[HeaderField]()
    out.append(HeaderField(name=String(":status"), value=String("200")))
    out.append(
        HeaderField(
            name=String("content-type"), value=String("application/grpc")
        )
    )
    return out^


def _append_status(mut headers: List[HeaderField], status: Status):
    headers.append(
        HeaderField(name=String("grpc-status"), value=String(status.code))
    )
    if status.message.byte_length() > 0:
        headers.append(
            HeaderField(
                name=String("grpc-message"),
                value=percent_encode_message(status.message),
            )
        )
    if len(status.details_bin) > 0 and status.code != StatusCode.OK:
        headers.append(
            HeaderField(
                name=String("grpc-status-details-bin"),
                value=encode_bin_value(Span(status.details_bin)),
            )
        )


def _status(code: Int, message: StringSpan) -> Status:
    return Status(code=code, message=String(message))


def _remaining_ms(deadline_ns: Int64, now_ns: Int64) -> Int:
    if deadline_ns <= now_ns:
        return 0
    return Int((deadline_ns - now_ns + _NS_PER_MS - 1) // _NS_PER_MS)


struct MuxServer[S: MuxService](Movable):
    """Serves one `MuxService` on a TCP listener, TLS or h2c."""

    var service: Self.S
    var config: MuxServerConfig
    var listener: TCPListener
    var port: UInt16
    var _tls: Optional[TLSContext]
    var _connections: List[_MuxConnection]
    var _handshakes: List[TLSHandshake]
    var _handshake_started_ns: List[Int64]
    var _next_call: UInt64

    def __init__(
        out self,
        var service: Self.S,
        host: StringSpan,
        port: UInt16,
        config: MuxServerConfig,
        *,
        cert_chain_pem: StringSpan = "",
        key_pem: StringSpan = "",
    ) raises:
        """Binds the listener; `port` reports the bound port."""
        config.validate()
        _ = external_call["signal", Int](_SIGPIPE, _SIG_IGN)
        self.service = service^
        self.config = config.copy()
        self.listener = TCPListener(host, port)
        self.listener.set_nonblocking(True)
        self.port = self.listener.local_port
        self._tls = None
        if cert_chain_pem.byte_length() > 0:
            self._tls = TLSContext.server(
                cert_chain_pem, key_pem, alpn=[String("h2")]
            )
        self._connections = List[_MuxConnection]()
        self._handshakes = List[TLSHandshake]()
        self._handshake_started_ns = List[Int64]()
        self._next_call = 1

    def serve(mut self) raises:
        var poller = Poller()
        poller.register(
            self.listener.descriptor(), readable=True, writable=False
        )
        while True:
            self.step(poller)

    def step(mut self, mut poller: Poller) raises:
        var now = Int64(monotonic())
        self.service.tick(now)
        self._drive_all(poller, now)
        var events = poller.wait(self._timeout_ms(Int64(monotonic())))
        var accept = False
        for event in events:
            if event.fd == self.listener.descriptor():
                accept = True
                continue
            var h = self._handshake_index(event.fd)
            if h >= 0:
                self._advance_handshake(poller, h)
                continue
            var c = self._connection_index(event.fd)
            if c >= 0:
                self._io(c, event.writable, event.error)
        self._expire_handshakes(poller)
        if accept:
            self._accept(poller)
        now = Int64(monotonic())
        self.service.tick(now)
        self._drive_all(poller, now)

    def _timeout_ms(self, now: Int64) -> Int:
        var wake = self.service.next_wake_ns(now)
        for c in range(len(self._connections)):
            if self._connections[c].resume_read:
                return 0
            for k in range(len(self._connections[c].calls)):
                var deadline_ns = self._connections[c].calls[k].deadline_ns
                if (
                    deadline_ns > 0
                    and not self._connections[c].calls[k].finished
                ):
                    if wake < 0 or deadline_ns < wake:
                        wake = deadline_ns
            var idle = (
                self._connections[c].last_activity_ns
                + Int64(self.config.idle_timeout_ms) * _NS_PER_MS
            )
            if wake < 0 or idle < wake:
                wake = idle
        for started_ns in self._handshake_started_ns:
            var limit = (
                started_ns
                + Int64(self.config.tls_handshake_timeout_ms) * _NS_PER_MS
            )
            if wake < 0 or limit < wake:
                wake = limit
        if wake < 0:
            return -1
        return _remaining_ms(wake, now)

    def _expire_handshakes(mut self, mut poller: Poller) raises:
        var limit = Int64(self.config.tls_handshake_timeout_ms) * _NS_PER_MS
        var now = Int64(monotonic())
        for i in range(len(self._handshakes) - 1, -1, -1):
            if now - self._handshake_started_ns[i] > limit:
                self._advance_handshake(poller, i)

    def _handshake_index(self, fd: c_int) -> Int:
        for i in range(len(self._handshakes)):
            if self._handshakes[i].descriptor() == fd:
                return i
        return -1

    def _connection_index(self, fd: c_int) -> Int:
        for i in range(len(self._connections)):
            if self._connections[i].descriptor() == fd:
                return i
        return -1

    def _open_count(self) -> Int:
        return len(self._connections) + len(self._handshakes)

    def _accept(mut self, mut poller: Poller) raises:
        for _ in range(self.config.max_accepts_per_event):
            if self._open_count() >= self.config.max_connections:
                return
            try:
                var tcp = self.listener.accept()
                tcp.set_nonblocking(True)
                if self._tls:
                    var tls = self._tls.value().start_accept(tcp^)
                    var fd = tls.descriptor()
                    poller.register(fd, readable=True, writable=False)
                    self._handshakes.append(tls^)
                    self._handshake_started_ns.append(Int64(monotonic()))
                    self._advance_handshake(poller, len(self._handshakes) - 1)
                else:
                    self._adopt(poller, GrpcTransport.plaintext(tcp^), False)
            except error:
                if is_would_block(error):
                    return

    def _adopt(
        mut self,
        mut poller: Poller,
        var transport: GrpcTransport,
        registered: Bool,
    ) raises:
        var connection = _MuxConnection(transport^, self.config)
        var fd = connection.descriptor()
        if registered:
            poller.modify(fd, readable=True, writable=False)
        else:
            poller.register(fd, readable=True, writable=False)
        connection.resume_read = True
        self._connections.append(connection^)

    def _advance_handshake(mut self, mut poller: Poller, index: Int) raises:
        var handshake = self._handshakes.pop(index)
        var started_ns = self._handshake_started_ns.pop(index)
        var fd = handshake.descriptor()
        try:
            var limit = Int64(self.config.tls_handshake_timeout_ms) * _NS_PER_MS
            if Int64(monotonic()) - started_ns > limit:
                raise Error("grpc: TLS handshake timed out")
            if handshake.advance():
                var stream = handshake^.finish()
                if not accepts_alpn(stream.negotiated_alpn()):
                    raise Error(
                        "grpc: TLS peer selected a protocol other than h2"
                    )
                self._adopt(poller, GrpcTransport.secure(stream^), True)
                return
            poller.modify(
                fd,
                readable=handshake.wants_read(),
                writable=handshake.wants_write(),
            )
            self._handshakes.insert(index, handshake^)
            self._handshake_started_ns.insert(index, started_ns)
        except:
            try:
                poller.unregister(fd)
            except:
                pass

    def _io(mut self, index: Int, writable: Bool, error: Bool):
        var connection = self._connections.pop(index)
        try:
            if writable or connection.tls_wants_write:
                self._write(connection)
            self._read(connection)
        except:
            connection.peer_eof = True
            connection.output = _Outbox()
        if error:
            connection.peer_eof = True
        self._connections.insert(index, connection^)

    def _read(mut self, mut connection: _MuxConnection) raises:
        connection.resume_read = False
        var budget = self.config.max_read_bytes_per_event
        while not connection.peer_eof:
            if connection.h2.pending_input_frame_count() > 0:
                self._move_output(connection)
                _ = connection.h2.feed_input(Span(List[Byte]()))
                if connection.h2.pending_input_frame_count() > 0:
                    return
            if len(connection.output) >= self.config.max_socket_output_bytes:
                return
            if budget <= 0:
                connection.resume_read = True
                return
            var chunk = List[Byte](length=min(budget, 64 * 1024), fill=0)
            try:
                var count = connection.h2.stream.read(chunk)
                if count == 0:
                    connection.peer_eof = True
                    return
                budget -= count
                connection.last_activity_ns = Int64(monotonic())
                _ = connection.h2.feed_input(Span(chunk)[:count])
                self._move_output(connection)
            except error:
                if is_would_block(error):
                    connection.tls_wants_write = (
                        connection.h2.stream.wants_write()
                    )
                    return
                raise error^

    def _write(mut self, mut connection: _MuxConnection) raises:
        connection.tls_wants_write = False
        self._move_output(connection)
        while len(connection.output) > 0:
            try:
                var count = connection.h2.stream.write_some(
                    connection.output.pending()
                )
                if count <= 0:
                    return
                connection.output.advance(count)
                connection.last_activity_ns = Int64(monotonic())
                self._move_output(connection)
            except error:
                if is_would_block(error):
                    connection.tls_wants_write = (
                        connection.h2.stream.wants_write()
                    )
                    return
                raise error^

    def _move_output(self, mut connection: _MuxConnection):
        if connection.h2.pending_output_len() == 0:
            return
        if len(connection.output) >= self.config.max_socket_output_bytes:
            return
        var bytes = connection.h2.take_pending_output()
        connection.output.append(Span(bytes))

    def _drive_all(mut self, mut poller: Poller, now: Int64) raises:
        var index = 0
        while index < len(self._connections):
            var connection = self._connections.pop(index)
            var keep = True
            try:
                if connection.resume_read:
                    self._read(connection)
                self._drive(connection, now)
                self._write(connection)
            except:
                connection.peer_eof = True
                connection.output = _Outbox()
            var idle_ns = Int64(self.config.idle_timeout_ms) * _NS_PER_MS
            if now - connection.last_activity_ns > idle_ns:
                connection.peer_eof = True
                connection.output = _Outbox()
            if connection.peer_eof and len(connection.output) == 0:
                keep = False
            if keep:
                try:
                    poller.modify(
                        connection.descriptor(),
                        readable=not connection.peer_eof,
                        writable=len(connection.output) > 0
                        or connection.tls_wants_write,
                    )
                except:
                    keep = False
            if keep:
                self._connections.insert(index, connection^)
                index += 1
            else:
                self._close(poller, connection^, now)

    def _close(
        mut self, mut poller: Poller, var connection: _MuxConnection, now: Int64
    ):
        for i in range(len(connection.calls)):
            self._end(connection.calls[i], True, now)
        try:
            poller.unregister(connection.descriptor())
        except:
            pass
        connection.h2.close()

    def _end(mut self, mut call: _MuxCall, cancelled: Bool, now: Int64):
        if not call.ended:
            call.ended = True
            self.service.on_end(call.id, cancelled, now)

    def _drive(mut self, mut connection: _MuxConnection, now: Int64) raises:
        self._discover(connection, now)
        var index = 0
        while index < len(connection.calls):
            var call = connection.calls.pop(index)
            self._drive_call(connection, call, now)
            if call.finished:
                self._end(call, False, now)
                if connection.h2.retire_stream(call.sid):
                    continue
            connection.calls.insert(index, call^)
            index += 1
        self._move_output(connection)

    def _discover(mut self, mut connection: _MuxConnection, now: Int64) raises:
        var ids = connection.h2.stream_ids.copy()
        for sid in ids:
            if sid % 2 == 0 or connection.has_call(sid):
                continue
            if sid not in connection.h2.streams:
                continue
            if not connection.h2.streams[sid].headers_done:
                continue
            if connection.h2.streams[sid].reset_code:
                continue
            var headers = connection.h2.streams[sid].headers.copy()
            var timeout = _find(headers, "grpc-timeout")
            var call = _MuxCall(self._next_call, sid, 0)
            self._next_call += 1
            var rejection: Optional[Status] = None
            try:
                if timeout.byte_length() > 0:
                    call.deadline_ns = now + decode_timeout(timeout)
            except:
                rejection = _status(
                    StatusCode.INTERNAL, "malformed grpc-timeout"
                )
            var content_type = _find(headers, "content-type")
            if _find(
                headers, ":method"
            ) != "POST" or not content_type.startswith("application/grpc"):
                rejection = _status(StatusCode.INTERNAL, "not a gRPC request")
            if not rejection:
                try:
                    rejection = self.service.on_start(
                        call.id, _find(headers, ":path"), headers, now
                    )
                except error:
                    rejection = _status(StatusCode.INTERNAL, String(error))
            else:
                call.ended = True
            if rejection:
                call.rejected = True
                call.status = rejection^
            connection.calls.append(call^)

    def _drive_call(
        mut self, mut connection: _MuxConnection, mut call: _MuxCall, now: Int64
    ) raises:
        if call.finished:
            self._drain_input(connection, call)
            return
        if connection.h2.streams[call.sid].reset_code:
            self._drain_input(connection, call)
            call.finished = True
            self._end(call, True, now)
            return
        if call.deadline_ns > 0 and now >= call.deadline_ns and not call.status:
            call.status = _status(
                StatusCode.DEADLINE_EXCEEDED, "Deadline Exceeded"
            )
            call.outbound = _Outbox()
            call.rejected = True
            self._end(call, True, now)
        self._receive(connection, call, now)
        if not call.status and not call.ended:
            if len(call.outbound) < self.config.max_call_backlog_bytes:
                var out = MuxOutput(
                    self.config.max_call_backlog_bytes - len(call.outbound)
                )
                try:
                    self.service.pump(call.id, out, now)
                except error:
                    out.status = _status(StatusCode.INTERNAL, String(error))
                for message in out.messages:
                    call.outbound.append(Span(frame_message(message)))
                if out.status:
                    call.status = out.status.copy()
        self._send(connection, call)

    def _drain_input(
        self, mut connection: _MuxConnection, mut call: _MuxCall
    ) raises:
        var buffered = connection.h2.buffered_data_len(call.sid)
        if buffered > 0:
            _ = connection.h2.take_buffered_data(call.sid, buffered)

    def _receive(
        mut self, mut connection: _MuxConnection, mut call: _MuxCall, now: Int64
    ) raises:
        var buffered = connection.h2.buffered_data_len(call.sid)
        if buffered > 0:
            var bytes = connection.h2.take_buffered_data(call.sid, buffered)
            if not call.rejected:
                call.inbound.extend(Span(bytes))
        while (
            not call.rejected and len(call.inbound) >= GRPC_MESSAGE_PREFIX_LEN
        ):
            var length = (
                (Int(call.inbound[1]) << 24)
                | (Int(call.inbound[2]) << 16)
                | (Int(call.inbound[3]) << 8)
                | Int(call.inbound[4])
            )
            if call.inbound[0] != 0:
                self._reject(
                    call,
                    StatusCode.UNIMPLEMENTED,
                    "compressed requests are not supported",
                    now,
                )
                return
            if length > self.config.max_message_bytes:
                self._reject(
                    call,
                    StatusCode.RESOURCE_EXHAUSTED,
                    "request message too large",
                    now,
                )
                return
            var end = GRPC_MESSAGE_PREFIX_LEN + length
            if len(call.inbound) < end:
                break
            var message = List[Byte](
                Span(call.inbound)[GRPC_MESSAGE_PREFIX_LEN:end]
            )
            call.inbound = List[Byte](Span(call.inbound)[end:])
            var answer: Optional[Status]
            try:
                answer = self.service.on_message(call.id, message, now)
            except error:
                answer = _status(StatusCode.INTERNAL, String(error))
            if answer:
                call.rejected = True
                call.status = answer^
                return
        if call.rejected or call.half_closed:
            return
        if connection.h2.streams[call.sid].end_stream:
            call.half_closed = True
            if len(call.inbound) > 0:
                self._reject(
                    call, StatusCode.INTERNAL, "truncated request message", now
                )
                return
            try:
                self.service.on_half_close(call.id, now)
            except error:
                call.status = _status(StatusCode.INTERNAL, String(error))

    def _reject(
        mut self, mut call: _MuxCall, code: Int, message: StringSpan, now: Int64
    ):
        call.rejected = True
        call.inbound = List[Byte]()
        call.status = _status(code, message)

    def _send(self, mut connection: _MuxConnection, mut call: _MuxCall) raises:
        var room = self.config.max_h2_output_bytes // 2
        if connection.h2.pending_output_len() > room:
            return
        if not call.headers_sent and len(call.outbound) > 0:
            connection.h2.queue_headers(
                call.sid, _response_headers(), end_stream=False
            )
            call.headers_sent = True
        while len(call.outbound) > 0:
            var taken = connection.h2.queue_data(
                call.sid, call.outbound.pending(), end_stream=False
            )
            if taken == 0:
                break
            call.outbound.advance(taken)
            self._move_output(connection)
        if len(call.outbound) > 0 or not call.status:
            return
        if connection.h2.pending_output_len() > room:
            return
        var headers = List[HeaderField]()
        if not call.headers_sent:
            headers = _response_headers()
        _append_status(headers, call.status.value())
        connection.h2.queue_headers(call.sid, headers, end_stream=True)
        call.headers_sent = True
        call.finished = True
        if not connection.h2.streams[call.sid].end_stream:
            connection.h2.queue_rst_stream(call.sid, _ERR_NO_ERROR)
