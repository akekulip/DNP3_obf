"""Wire-frame primitives used by the guarded physical control builder."""
MASTER_ADDR=1
OUTSTATION_ADDR=0
FUNC_SELECT=3
FUNC_OPERATE=4
CROB_BODY=bytes([1,1,200,0,0,0,0,0,0,0,0])

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
