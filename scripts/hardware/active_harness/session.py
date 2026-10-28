#!/usr/bin/env python3
"""A DNP3-over-TCP master session with an explicit, monotonic transaction deadline.

Every transaction is given a budget in milliseconds. The deadline is computed once from
`time.monotonic()` and the *remaining* budget is handed to each blocking receive, so the
bound is on the transaction and not on one read. That is the difference from the frozen
drivers, whose `settimeout` was re-armed on every `recv` and therefore bounded nothing.

Outcomes are explicit and distinct. In particular:

  * `TIMEOUT` means the transaction deadline passed with no complete response.
  * `INVALID` means a complete response arrived and failed validation.
  * `PEER_CLOSED` means the outstation closed the connection.
  * `FRAME_ERROR` means bytes arrived that could not be framed or failed a CRC.

What this layer deliberately does **not** claim: a socket send does not wait for the peer to
acknowledge anything. `socket.sendall` returns when the bytes have been handed to the local
kernel. Transport acknowledgment is not observable from here at all; the `ack_evidence` field
records that explicitly rather than inventing a value, and a concurrent packet capture is the
only way to obtain it.

Standard library only. Opens a socket only when `connect()` is called.
"""
from __future__ import annotations

import math
import socket
import time
from dataclasses import dataclass, field

from dnp3_codec import (Reassembler, FrameError, TransportAssembler, TransportError,
                        parse_application_response, validate_response,
                        reassemble_application, read_workload_for_request, FUNC_READ,
                        FUNC_RESPONSE, STATUS_NAMES, READ_SCHEMAS)

# Transport acknowledgment is a property of the TCP connection, not of the socket API. A
# master process cannot observe it; only a capture on the link can.
ACK_NOT_OBSERVABLE = "not observable at the application layer; requires a link capture"

OUTCOME_OK = "OK"
OUTCOME_TIMEOUT = "TIMEOUT"
# A complete, valid response that arrived after the transaction budget had already expired.
# Kept distinct from TIMEOUT, which means no valid response arrived at all: conflating them
# would lose the fact that the outstation did answer, and reporting it as OK would break the
# bound the caller was given.
OUTCOME_DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
OUTCOME_INVALID = "INVALID"
OUTCOME_PEER_CLOSED = "PEER_CLOSED"
OUTCOME_FRAME_ERROR = "FRAME_ERROR"
OUTCOME_CANCELLED = "CANCELLED"
OUTCOME_NOT_ATTEMPTED = "NOT_ATTEMPTED"


@dataclass
class Outcome:
    """The result of one request/response transaction."""
    operation: str
    function: int
    app_seq: int
    outcome: str
    t_send: float | None = None                  # monotonic, seconds
    t_complete: float | None = None
    elapsed_ms: float | None = None
    budget_ms: float | None = None
    remaining_ms_at_completion: float | None = None
    response_function: int | None = None
    iin: int | None = None
    points: list = field(default_factory=list)   # (index, status name)
    problems: list = field(default_factory=list)
    stale_frames_discarded: int = 0
    bytes_left_buffered: int = 0
    request_wire_hex: str = ""
    request_app_hex: str | None = None
    request_frames_hex: list = field(default_factory=list)
    response_wire_hex: str = ""       # frames belonging to the completed matched fragment
    response_app_hex: str | None = None
    response_frames_hex: list = field(default_factory=list)
    received_frames_hex: list = field(default_factory=list)
    transport_bytes_buffered: int = 0
    received_wire_hex: str = ""       # all socket bytes, including stale/corrupt/trailing data
    response_objects: list = field(default_factory=list)
    local_address: tuple | None = None
    peer_address: tuple | None = None
    t_first_response: float | None = None
    ack_evidence: str = ACK_NOT_OBSERVABLE

    @property
    def ok(self) -> bool:
        return self.outcome == OUTCOME_OK

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["ok"] = self.ok
        return d


class Session:
    """One DNP3 TCP connection to one outstation."""

    def __init__(self, host: str, port: int = 20000, source_address=None,
                 connect_timeout_ms: float = 5000.0, verify_crc: bool = True):
        self.host, self.port = host, port
        self.source_address = source_address
        self.connect_timeout_ms = connect_timeout_ms
        self.sock = None
        self.rx = Reassembler(verify_crc=verify_crc)
        self.transport = TransportAssembler()
        self.fragment_frames = []
        self.local_address = None
        self.peer_address = None
        self.stale_discarded = 0

    # ---------------------------------------------------------------- connection

    def connect(self) -> None:
        if not math.isfinite(self.connect_timeout_ms) or self.connect_timeout_ms <= 0:
            raise ValueError("connect_timeout_ms must be finite and positive")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.source_address:
                s.bind(self.source_address)       # failure is explicit; never change source silently
            s.settimeout(self.connect_timeout_ms / 1e3)
            s.connect((self.host, self.port))
            self.local_address = s.getsockname()
            self.peer_address = s.getpeername()
        except Exception:
            s.close()
            raise
        self.rx = Reassembler(verify_crc=self.rx.verify_crc)
        self.transport.reset()
        self.fragment_frames = []
        self.sock = s

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.rx = Reassembler(verify_crc=self.rx.verify_crc)
                self.transport.reset()
                self.fragment_frames = []
                self.local_address = self.peer_address = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ---------------------------------------------------------------- transaction

    def transaction(self, *, operation: str, frame: bytes, function: int, app_seq: int,
                    budget_ms: float, expect_points=None,
                    require_success: bool = False, expect_read_groups=None,
                    expect_read_workload=None) -> Outcome:
        """Send one request and read until its response is complete, valid, or out of budget.

        The deadline is monotonic and computed before the send. Frames that arrive but do not
        answer this request are discarded and counted; they never complete the transaction.
        """
        if not math.isfinite(budget_ms) or budget_ms <= 0:
            raise ValueError("budget_ms must be finite and positive")
        if self.sock is None:
            raise RuntimeError("session is not connected")
        out = Outcome(operation=operation, function=function, app_seq=app_seq & 0x0F,
                      outcome=OUTCOME_TIMEOUT, budget_ms=budget_ms)
        # Validate the exact request and bind the response to its reversed link identities.
        request_rx = Reassembler()
        request_rx.feed(frame)
        request_frames = list(request_rx.frames())
        if request_rx.crc_failures or request_rx.pending_bytes or request_rx.dropped_leading or not request_frames:
            raise ValueError("request is not an exact CRC-valid link-frame stream")
        applications = reassemble_application(request_frames)
        if len(applications) != 1:
            raise ValueError("request must contain exactly one complete application fragment")
        application = applications[0]
        if len(application) < 2 or application[1] != function or application[0] & 15 != app_seq & 15:
            raise ValueError("request function/sequence differs from transaction metadata")
        if function == FUNC_READ:
            inferred_workload = read_workload_for_request(application)
            if expect_read_workload is not None and expect_read_workload != inferred_workload:
                raise ValueError("explicit READ workload differs from request bytes")
            if expect_read_groups is not None and set(expect_read_groups) != set(READ_SCHEMAS[inferred_workload]):
                raise ValueError("explicit READ groups differ from request bytes")
            expect_read_workload = inferred_workload
        out.request_wire_hex = frame.hex()
        out.request_frames_hex = [f.wire.hex() for f in request_frames]
        out.request_app_hex = application.hex()
        for attr, method in (("local_address", "getsockname"), ("peer_address", "getpeername")):
            getter = getattr(self.sock, method, None)
            setattr(out, attr, getter() if getter else getattr(self, attr))
        self.response_identity = (request_frames[0].source, request_frames[0].destination)
        # Bytes left from an earlier exchange cannot answer a request not yet sent. Keep the
        # previous outcome's buffered count as evidence, but start a new assembly epoch here.
        self.rx = Reassembler(verify_crc=self.rx.verify_crc)
        self.transport.reset()
        self.fragment_frames = []
        t0 = time.monotonic()
        deadline = t0 + budget_ms / 1e3
        out.t_send = t0
        # The send is inside the budget too. sendall hands the bytes to the local kernel and
        # does not wait for the peer, but it can still block when the socket buffer is full,
        # and an unbounded block there would defeat the deadline entirely.
        self.sock.settimeout(max(0.0, deadline - time.monotonic()))
        try:
            self.sock.sendall(frame)
        except socket.timeout:
            out.problems.append("send blocked past the %.1f ms transaction budget" % budget_ms)
            return self._finish(out, OUTCOME_TIMEOUT, deadline)

        while True:
            # anything already buffered may complete the transaction without a read
            done = self._match(out, expect_points, require_success, expect_read_groups, expect_read_workload)
            if done is not None:
                # The deadline is an invariant, not a hint. A response that is complete and
                # valid but arrived after the budget expired is reported as such; it is never
                # reported OK, because the caller was given a bound.
                if done == OUTCOME_OK and time.monotonic() > deadline:
                    out.problems.append(
                        "a complete, valid response arrived after the %.1f ms budget expired"
                        % budget_ms)
                    return self._finish(out, OUTCOME_DEADLINE_EXCEEDED, deadline)
                return self._finish(out, done, deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                out.problems.append("transaction budget of %.1f ms expired with no complete, "
                                    "valid response" % budget_ms)
                return self._finish(out, OUTCOME_TIMEOUT, deadline)
            self.sock.settimeout(remaining)       # the remaining budget, not a fresh one
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                out.problems.append("receive timed out with %.3f ms of budget remaining"
                                    % max(0.0, (deadline - time.monotonic()) * 1e3))
                return self._finish(out, OUTCOME_TIMEOUT, deadline)
            if not chunk:
                out.problems.append("outstation closed the connection")
                return self._finish(out, OUTCOME_PEER_CLOSED, deadline)
            if out.t_first_response is None:
                out.t_first_response = time.monotonic()
            out.received_wire_hex += chunk.hex()
            self.rx.feed(chunk)

    def _match(self, out: Outcome, expect_points, require_success, expect_read_groups=None,
               expect_read_workload=None):
        """Validate every complete frame already received before accepting this exchange.

        Complete stale responses are discarded and counted, on either side of the matched
        response. A duplicate current response, wrong address, orphan continuation or an
        unfinished transport fragment following the match makes the exchange INVALID.
        Partial link bytes remain explicitly buffered; no trailing frame can answer a
        request that has not yet been sent. All consumed CRC-valid frames are recorded.
        """
        before = self.rx.crc_failures
        dropped_before = self.rx.dropped_leading
        try:
            frames = list(self.rx.frames())
        except FrameError as exc:
            out.problems.append("framing: %s" % exc)
            return OUTCOME_FRAME_ERROR
        out.received_frames_hex.extend(frame.wire.hex() for frame in frames)
        if self.rx.crc_failures > before:
            out.problems.append("%d CRC failure(s) while resynchronising" %
                                (self.rx.crc_failures - before))
            return OUTCOME_FRAME_ERROR
        if self.rx.dropped_leading > dropped_before:
            out.problems.append("unexpected bytes while resynchronising link frames")
            return OUTCOME_FRAME_ERROR
        matched = False
        for frame in frames:
            if (frame.destination, frame.source) != self.response_identity:
                out.problems.append("response link source/destination do not match request")
                self.transport.reset()
                self.fragment_frames = []
                continue
            self.fragment_frames.append(frame)
            try:
                application = self.transport.add(frame.user_data)
            except TransportError as exc:
                out.problems.append("transport: %s" % exc)
                self.transport.reset()
                self.fragment_frames = []
                continue
            if application is None:
                continue
            fragment_frames, self.fragment_frames = self.fragment_frames, []
            resp = parse_application_response(application)
            if resp.function == FUNC_RESPONSE and resp.app_seq != out.app_seq:
                self.stale_discarded += len(fragment_frames)
                out.stale_frames_discarded += len(fragment_frames)
                if resp.problems:
                    out.problems.extend("stale response: " + problem for problem in resp.problems)
                continue
            if matched:
                out.problems.append("duplicate response for current application sequence")
                continue
            matched = True
            out.response_frames_hex = [f.wire.hex() for f in fragment_frames]
            out.response_wire_hex = "".join(out.response_frames_hex)
            out.response_app_hex = application.hex()
            out.response_function = resp.function
            out.iin = resp.iin
            out.points = [(i, STATUS_NAMES.get(status, status)) for i, status in resp.points]
            out.response_objects = resp.objects
            out.problems.extend(validate_response(resp, expect_seq=out.app_seq,
                expect_function=out.function, expect_points=expect_points,
                require_success=require_success, expect_read_groups=expect_read_groups,
                expect_read_workload=expect_read_workload))
        if matched and self.transport.in_progress:
            out.problems.append("unfinished transport fragment follows matched response")
        if out.problems:
            return OUTCOME_INVALID
        return OUTCOME_OK if matched else None

    def _finish(self, out: Outcome, outcome: str, deadline: float) -> Outcome:
        now = time.monotonic()
        out.outcome = outcome
        out.t_complete = now
        out.elapsed_ms = (now - out.t_send) * 1e3
        out.remaining_ms_at_completion = (deadline - now) * 1e3
        out.bytes_left_buffered = self.rx.pending_bytes
        out.transport_bytes_buffered = sum(frame.total for frame in self.fragment_frames)
        return out
