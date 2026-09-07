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

import socket
import time
from dataclasses import dataclass, field

from dnp3_codec import (Reassembler, FrameError, parse_response, validate_response,
                        FUNC_RESPONSE, STATUS_NAMES)

# Transport acknowledgment is a property of the TCP connection, not of the socket API. A
# master process cannot observe it; only a capture on the link can.
ACK_NOT_OBSERVABLE = "not observable at the application layer; requires a link capture"

OUTCOME_OK = "OK"
OUTCOME_TIMEOUT = "TIMEOUT"
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
        self.stale_discarded = 0

    # ---------------------------------------------------------------- connection

    def connect(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Nagle would let the kernel defer a small request behind unacknowledged bytes. The
        # frozen campaign driver left it on; here it is off deliberately.
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.source_address:
            try:
                s.bind(self.source_address)
            except OSError:
                pass                              # best effort; routing selects the interface
        s.settimeout(self.connect_timeout_ms / 1e3)
        s.connect((self.host, self.port))
        self.sock = s

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ---------------------------------------------------------------- transaction

    def transaction(self, *, operation: str, frame: bytes, function: int, app_seq: int,
                    budget_ms: float, expect_points=None,
                    require_success: bool = False) -> Outcome:
        """Send one request and read until its response is complete, valid, or out of budget.

        The deadline is monotonic and computed before the send. Frames that arrive but do not
        answer this request are discarded and counted; they never complete the transaction.
        """
        if self.sock is None:
            raise RuntimeError("session is not connected")
        out = Outcome(operation=operation, function=function, app_seq=app_seq & 0x0F,
                      outcome=OUTCOME_TIMEOUT, budget_ms=budget_ms)
        t0 = time.monotonic()
        deadline = t0 + budget_ms / 1e3
        out.t_send = t0
        # sendall hands the bytes to the local kernel; it does not wait for the peer.
        self.sock.sendall(frame)

        while True:
            # anything already buffered may complete the transaction without a read
            done = self._match(out, expect_points, require_success)
            if done is not None:
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
            self.rx.feed(chunk)

    def _match(self, out: Outcome, expect_points, require_success):
        """Consume buffered frames. Returns an outcome string, or None to keep reading."""
        before = self.rx.crc_failures
        try:
            for frame in self.rx.frames():
                resp = parse_response(frame.user_data)
                problems = validate_response(resp, expect_seq=out.app_seq,
                                             expect_function=out.function,
                                             expect_points=expect_points,
                                             require_success=require_success)
                # A frame for a different sequence number is somebody else's, or stale. It is
                # discarded and does not complete this transaction.
                if resp.function == FUNC_RESPONSE and resp.app_seq != out.app_seq:
                    self.stale_discarded += 1
                    out.stale_frames_discarded += 1
                    continue
                out.response_function = resp.function
                out.iin = resp.iin
                out.points = [(i, STATUS_NAMES.get(s, s)) for i, s in resp.points]
                if problems:
                    out.problems.extend(problems)
                    return OUTCOME_INVALID
                return OUTCOME_OK
        except FrameError as exc:
            out.problems.append("framing: %s" % exc)
            return OUTCOME_FRAME_ERROR
        if self.rx.crc_failures > before:
            out.problems.append("%d CRC failure(s) while resynchronising"
                                % (self.rx.crc_failures - before))
            return OUTCOME_FRAME_ERROR
        return None

    def _finish(self, out: Outcome, outcome: str, deadline: float) -> Outcome:
        now = time.monotonic()
        out.outcome = outcome
        out.t_complete = now
        out.elapsed_ms = (now - out.t_send) * 1e3
        out.remaining_ms_at_completion = (deadline - now) * 1e3
        out.bytes_left_buffered = self.rx.pending_bytes
        return out
