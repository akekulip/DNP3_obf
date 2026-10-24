#!/usr/bin/env python3
"""READ-ONLY request builders for the two relay READ workloads, framed exactly like the frozen
`relay_read_g10_23.read_frame` (master=1, outstation=0, control 0xC4, transport FIR|FIN, app FIR|FIN|seq).

Two workloads, matching the classifier in protocol/hw_vepa/read_classes.classify_request:

  * mixed:     G1 V2 (binary input) qual 0x00 range 0..15, then G30 V1 (analog input) qual 0x00 range 0..7
  * integrity: G60 V2, V3, V4, V1 each qual 0x06 (class 1, 2, 3, 0) -- the all-classes poll

Both are function 0x01 (READ) and assert it, so neither can emit a control frame. CRC and framing are taken from
dnp3_codec so a built frame parses cleanly under the same codec that validates the response.
"""
from __future__ import annotations

from dnp3_codec import crc_le, parse_frame, FUNC_READ

OUTSTATION_ADDR, MASTER_ADDR, CONTROL = 0x00, 0x01, 0xC4
TRANSPORT_FIR_FIN = 0xC0                      # transport header: FIN(0x80) | FIR(0x40) | seq 0

# object-header bytes of each workload (group, variation, qualifier, [range...])
MIXED_OBJECTS = bytes([0x01, 0x02, 0x00, 0, 15,   0x1E, 0x01, 0x00, 0, 7])
INTEGRITY_OBJECTS = bytes([60, 2, 0x06,  60, 3, 0x06,  60, 4, 0x06,  60, 1, 0x06])


def _read_frame(seq: int, objects: bytes) -> bytes:
    app = bytes([TRANSPORT_FIR_FIN, 0xC0 | (seq & 0x0F), FUNC_READ]) + objects
    if app[2] != FUNC_READ:                   # belt and braces: never emit a non-READ here
        raise ValueError("refusing: built frame is not a READ")
    header = bytes([0x05, 0x64, 5 + len(app), CONTROL, OUTSTATION_ADDR, 0x00, MASTER_ADDR, 0x00])
    frame = bytearray(header + crc_le(header))
    for i in range(0, len(app), 16):
        block = app[i:i + 16]
        frame += block + crc_le(block)
    frame = bytes(frame)
    parsed, rest = parse_frame(frame)         # CRC-validate what we are about to send
    if parsed is None or rest or parsed.user_data[2] != FUNC_READ:
        raise ValueError("built READ frame does not parse cleanly")
    return frame


def mixed_read_frame(seq: int) -> bytes:
    """G1V2 0..15 + G30V1 0..7 READ (the 'mixed' workload; relay native 91 B)."""
    return _read_frame(seq, MIXED_OBJECTS)


def integrity_read_frame(seq: int) -> bytes:
    """G60 V2/V3/V4/V1 q0x06 all-classes READ (the 'integrity' workload; relay native 134 B)."""
    return _read_frame(seq, INTEGRITY_OBJECTS)
