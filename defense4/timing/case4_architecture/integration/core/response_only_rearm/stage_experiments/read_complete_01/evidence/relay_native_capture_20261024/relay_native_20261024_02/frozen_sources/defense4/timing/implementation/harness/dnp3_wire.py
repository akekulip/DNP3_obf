#!/usr/bin/env python3
"""dnp3_wire.py -- shared DNP3-over-TCP wire helpers for the H3 software-endpoint harness.

These are the SAME link-layer CRC and framing routines proven against the physical SEL-751 by the
hardware drivers (relay_read_g10_23.py / relay_sbo_2crob_loop.py). They are reused verbatim so the
H3 software master and outstation put exactly the SEL-751 wire bytes on the link:

  * 2-CROB Select-Before-Operate with the one-byte count qualifier 0x17 (Group 12 Var 1),
    real point 0 + decoy point 1.
  * A 49-byte NATIVE application response (the "native echo") for both SELECT and OPERATE, which
    is what the SEL-751 emits before the switch carves it into the [28,21] segmentation vector.

DNP3 link addresses (fixed for this rig): master = 1, outstation = 0.
No CRC recompute of captured traffic happens here -- these frames are BUILT from scratch by the
software endpoints, so every CRC is a genuine DNP3 CRC over freshly-authored bytes.
"""
from __future__ import annotations

# DNP3 link addresses on the rig.
MASTER_ADDR = 1
OUTSTATION_ADDR = 0

# CROB: control_code=0x01 (LATCH_ON/pulse), count=0x01, on-time=200ms (0xC8), off-time=0, status=0.
# This is byte-identical to the CROB the SEL-751 echoes back (verified from phase7_h2 capture).
CROB_BODY = bytes([0x01, 0x01, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
REAL_POINT = 0   # real even point
DECOY_POINT = 1  # inert odd decoy point

FUNC_SELECT = 0x03
FUNC_OPERATE = 0x04
FUNC_RESPONSE = 0x81

# Outstation echo IIN, transport, and app-control constants -- matched to the SEL-751 echo shape.
ECHO_IIN = bytes([0x84, 0x00])
ECHO_TRANSPORT = 0xE0  # FIR+FIN, transport seq 0 (rolled per response by the outstation)


def dnp3_crc(data: bytes) -> int:
    """DNP3 link-layer CRC-16 (validated against the physical SEL-751)."""
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if (c & 1) else (c >> 1)
    return (c ^ 0xFFFF) & 0xFFFF


def _crc_le(d: bytes) -> bytes:
    x = dnp3_crc(d)
    return bytes([x & 0xFF, (x >> 8) & 0xFF])


def build_frame(userdata: bytes, dst: int, src: int, ctrl: int) -> bytes:
    """Wrap `userdata` (transport byte + application bytes) in a DNP3 link frame with block CRCs.

    LEN field = 5 (ctrl+addr octets) + len(userdata); user data is split into 16-byte blocks,
    each followed by its own CRC-16. This is the exact framing the SEL-751 uses.
    """
    ln = 5 + len(userdata)
    assert 0 <= ln <= 255, "link LEN out of range"
    hdr = bytes([0x05, 0x64, ln, ctrl,
                 dst & 0xFF, (dst >> 8) & 0xFF,
                 src & 0xFF, (src >> 8) & 0xFF])
    f = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(userdata), 16):
        blk = userdata[i:i + 16]
        f += blk + _crc_le(blk)
    return bytes(f)


def deframe(buf: bytes):
    """Yield (total_frame_bytes, userdata) for each DNP3 link frame found in `buf`.

    userdata is the transport byte + application bytes with per-block CRCs stripped.
    """
    i = 0
    while i + 10 <= len(buf):
        if buf[i] != 0x05 or buf[i + 1] != 0x64:
            i += 1
            continue
        ulen = buf[i + 2] - 5
        nblk = (ulen + 15) // 16 if ulen > 0 else 0
        total = 10 + ulen + 2 * nblk
        if i + total > len(buf):
            break
        u = bytearray()
        p = i + 10
        rem = ulen
        while rem > 0:
            t = min(16, rem)
            u += buf[p:p + t]
            p += t + 2
            rem -= t
        yield total, bytes(u)
        i += total


# ---------------------------------------------------------------------------
# Master-side request builders (2-CROB, qualifier 0x17).
# ---------------------------------------------------------------------------

def _two_crob_object() -> bytes:
    """G12 V1 object block: qual 0x17 (1-byte count/prefix), count 2, real point 0 + decoy point 1."""
    return (bytes([0x0C, 0x01, 0x17, 0x02, REAL_POINT]) + CROB_BODY
            + bytes([DECOY_POINT]) + CROB_BODY)


def build_request(func: int, app_seq: int) -> bytes:
    """Build a 2-CROB SELECT (func 0x03) or OPERATE (func 0x04) request frame.

    userdata = transport(FIR+FIN,seq) + app_control(FIR+FIN+CON,seq) + func + 2-CROB object.
    dst = outstation(0), src = master(1), ctrl = 0xC4 (PRM master, unconfirmed user data).
    """
    assert func in (FUNC_SELECT, FUNC_OPERATE), "H3 master issues only SELECT/OPERATE"
    transport = 0xC0 | (app_seq & 0x0F)
    app_ctrl = 0xC0 | (app_seq & 0x0F)
    userdata = bytes([transport, app_ctrl, func]) + _two_crob_object()
    return build_frame(userdata, dst=OUTSTATION_ADDR, src=MASTER_ADDR, ctrl=0xC4)


# ---------------------------------------------------------------------------
# Outstation-side echo builder + request parser.
# ---------------------------------------------------------------------------

def parse_request(userdata: bytes):
    """Parse a deframed request's userdata. Returns dict or None if not a recognised 2-CROB request."""
    if len(userdata) < 3:
        return None
    app_ctrl = userdata[1]
    func = userdata[2]
    obj = userdata[3:]
    info = {"app_seq": app_ctrl & 0x0F, "func": func,
            "group": None, "var": None, "qual": None, "count": None, "points": []}
    if len(obj) >= 5:
        info["group"], info["var"], info["qual"], info["count"] = obj[0], obj[1], obj[2], obj[3]
        # Walk count prefix/CROB pairs when qual is 0x17 (1-byte count, 1-byte prefix index).
        if obj[2] == 0x17:
            p = 4
            for _ in range(obj[3]):
                if p + 1 + 11 > len(obj):
                    break
                info["points"].append(obj[p])
                p += 1 + 11
    return info


def build_echo(req_app_seq: int, transport_seq: int) -> bytes:
    """Build the 49-byte NATIVE echo (func 0x81) for a 2-CROB SELECT/OPERATE.

    Echoes G12 V1 qual 0x17 count 2, real point 0 + decoy point 1, each CROB with status 0x00
    (SUCCESS). The application sequence number mirrors the request (real DNP3 behaviour). The
    on-wire frame is exactly 49 bytes -- byte-shape-identical to the SEL-751 native echo.
    """
    app_ctrl = 0xC0 | (req_app_seq & 0x0F)   # app-control seq is 4 bits
    transport = 0xC0 | (transport_seq & 0x3F)  # transport seq is 6 bits (FIN+FIR | seq)
    obj = (bytes([0x0C, 0x01, 0x17, 0x02, REAL_POINT]) + CROB_BODY
           + bytes([DECOY_POINT]) + CROB_BODY)
    userdata = bytes([transport, app_ctrl, FUNC_RESPONSE]) + ECHO_IIN + obj
    frame = build_frame(userdata, dst=MASTER_ADDR, src=OUTSTATION_ADDR, ctrl=0x44)
    return frame


if __name__ == "__main__":
    # Self-check: the built echo must be 49 bytes and, at the captured transport seq (0x20), be
    # BYTE-IDENTICAL to the SEL-751 native echo reassembled from the phase7_h2 [28,21] carve.
    echo = build_echo(req_app_seq=0, transport_seq=0x20)
    ref = bytes.fromhex(
        "05642644010000002f77e0c08184000c011702000101c8000000f05a"
        "0000000000010101c80000000000000097da00ffff")
    print("echo len   :", len(echo))
    print("echo hex   :", echo.hex())
    print("ref  hex   :", ref.hex())
    print("BYTE-IDENTICAL to captured SEL-751 native echo:", echo == ref)
    sel = build_request(FUNC_SELECT, 0)
    op = build_request(FUNC_OPERATE, 0)
    # On the wire: byte 10=transport, 11=app-ctrl, 12=func, 13=G12, 14=V1, 15=qual(0x17), 16=count.
    print("SELECT req len:", len(sel), "func=0x%02x qual=0x%02x count=%d" % (sel[12], sel[15], sel[16]))
    print("OPERATE req len:", len(op), "func=0x%02x qual=0x%02x count=%d" % (op[12], op[15], op[16]))
    print("SELECT parse:", parse_request(next(deframe(sel))[1]))
