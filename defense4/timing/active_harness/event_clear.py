#!/usr/bin/env python3
"""One-time clear of the SEL-751's pending class-2 events (Philip, 2026-10-25: "I poll and confirm it once").

From 2026-10-25 22:25 the relay reported IIN1.2 (class 2 events available; IIN 84 00 instead of 80 00) with no test
traffic since 16:10. The integrity workload polls classes 1,2,3,0, so its response then carried event data and was no
longer the 134-octet class-0 shape. This polls class 2 (G60 V3 q 0x06, function READ) and answers every response
fragment that asks for confirmation (CON) with an application CONFIRM (function 0x00, the fragment's own sequence),
up to MAX_POLLS times while IIN1.2 stays set; then one class-0-only READ (G60 V1) checks the IIN.

It can emit only READ (0x01) and CONFIRM (0x00) and asserts that before every send: no control point, no write, no
configuration. Event objects are recorded as raw hex, never decoded by guess.
"""
from __future__ import annotations

import time

from dnp3_codec import Reassembler, TransportAssembler, crc_le
from read_requests import _read_frame, OUTSTATION_ADDR, MASTER_ADDR, CONTROL, TRANSPORT_FIR_FIN

FUNC_CONFIRM, FUNC_READ, FUNC_RESPONSE = 0x00, 0x01, 0x81
CLASS2 = bytes([60, 3, 0x06])
CLASS0 = bytes([60, 1, 0x06])
IIN1_CLASS2 = 0x04
APP_FIR, APP_FIN, APP_CON, APP_UNS = 0x80, 0x40, 0x20, 0x10
MAX_POLLS = 3


def confirm_frame(seq: int) -> bytes:
    """Application CONFIRM for a response fragment with sequence `seq` (FIR|FIN, no CON, no UNS)."""
    app = bytes([TRANSPORT_FIR_FIN, 0xC0 | (seq & 0x0F), FUNC_CONFIRM])
    header = bytes([0x05, 0x64, 5 + len(app), CONTROL, OUTSTATION_ADDR, 0x00, MASTER_ADDR, 0x00])
    return header + crc_le(header) + app + crc_le(app)


def _function(frame: bytes) -> int:
    """Application function of a single-block frame this module built."""
    return frame[12]


def _send(sock, frame: bytes, sent: list) -> None:
    if _function(frame) not in (FUNC_READ, FUNC_CONFIRM):
        raise ValueError('event_clear may send only READ or CONFIRM')
    sock.sendall(frame)
    sent.append(dict(t=time.monotonic(), function=_function(frame), hex=frame.hex()))


def _fragments(sock, budget_s: float, sent: list, expect_seq: int):
    """Yield matching solicited fragments until application FIN or the budget.

    The first fragment must have FIR and the READ's sequence; continuations must
    clear FIR and increment the application sequence. A partial response may be
    yielded, so its final fragment must have FIN before its IIN can verify a clear.
    """
    rx, asm, end = Reassembler(verify_crc=True), TransportAssembler(), time.monotonic() + budget_s
    first = True
    while time.monotonic() < end:
        sock.settimeout(max(0.01, end - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except OSError:
            return
        if not chunk:
            return
        rx.feed(chunk)
        for frame in rx.frames():
            application = asm.add(frame.user_data)
            if application is None or len(application) < 4:
                continue
            ctrl, func = application[0], application[1]
            if func != FUNC_RESPONSE or ctrl & APP_UNS or (ctrl & 0x0F) != expect_seq:
                continue
            if bool(ctrl & APP_FIR) != first:
                continue
            first = False
            expect_seq = (expect_seq + 1) & 0x0F
            iin = int.from_bytes(application[2:4], 'big')
            yield ctrl, func, iin, application.hex()
            if ctrl & APP_CON:
                _send(sock, confirm_frame(ctrl & 0x0F), sent)
            if ctrl & APP_FIN:
                return


def clear(session, budget_ms: float = 3000.0) -> dict:
    sock, sent, polls, seq = session.sock, [], [], 0
    for _ in range(MAX_POLLS):
        _send(sock, _read_frame(seq, CLASS2), sent)
        fragments = [dict(control=c, function=f, iin='%04x' % i if i is not None else None, application_hex=a)
                     for c, f, i, a in _fragments(sock, budget_ms / 1000, sent, seq)]
        polls.append(dict(app_seq=seq, fragments=fragments))
        if fragments:
            seq = fragments[-1]['control'] & 0x0F
        seq = (seq + 1) & 0x0F
        last = fragments[-1]['iin'] if fragments and fragments[-1]['control'] & APP_FIN else None
        if last is not None and not (int(last, 16) >> 8) & IIN1_CLASS2:
            break
    _send(sock, _read_frame(seq, CLASS0), sent)
    check = [dict(control=c, function=f, iin='%04x' % i if i is not None else None, application_hex=a)
             for c, f, i, a in _fragments(sock, budget_ms / 1000, sent, seq)]
    final = check[-1]['iin'] if check and check[-1]['control'] & APP_FIN else None
    cleared = final is not None and not (int(final, 16) >> 8) & IIN1_CLASS2
    return dict(schema='sel751-event-clear-v1', ok=cleared, polls=polls, class0_check=check, final_iin=final,
                sent=sent, functions_sent=sorted({item['function'] for item in sent}))
