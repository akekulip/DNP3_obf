"""Bounded byte-preserving response split: the RRC_49_CUT28 profile, in software.

Reads classic pcap and pcapng, checks IPv4/TCP checksums and DNP3 link CRCs independently, and implements
the carve the 2026-08-12 design describes (RID 1 = payload[0:28], seq unchanged, PSH/FIN cleared; RID 2 =
payload[28:], seq + 28, original flags; IP total length and both checksums recomputed; options preserved).
This is a software model of the mechanism, not evidence about Tofino fit.
"""
import struct
from dataclasses import dataclass

CUT = 28
EXPECT_PAYLOAD = 49
PSH, FIN, SYN, RST, ACK = 0x08, 0x01, 0x02, 0x04, 0x10


# ---- capture reading -------------------------------------------------------------------------
def read_records(path):
    """Yield (ts_ns, raw frame) from a classic pcap or a pcapng, in file order."""
    d = open(path, "rb").read()
    if d[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(d)
        return
    magic = d[:4]
    end, nano = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
                 b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}[magic]
    i = 24
    while i < len(d):
        s, f, cl, _ = struct.unpack(end + "IIII", d[i:i + 16])
        i += 16
        yield s * 10 ** 9 + (f if nano else f * 1000), d[i:i + cl]
        i += cl


def _pcapng(d):
    end, i, tsres = "<", 0, {}
    while i < len(d):
        btype, blen = struct.unpack(end + "II", d[i:i + 8])
        body = d[i + 8:i + blen - 4]
        if btype == 0x0A0D0D0A:
            end = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
        elif btype == 1:                                           # interface description
            res, j = 6, 8
            while j + 4 <= len(body):
                code, ln = struct.unpack(end + "HH", body[j:j + 4])
                if code == 0:
                    break
                if code == 9:
                    res = body[j + 4]
                j += 4 + ((ln + 3) & ~3)
            tsres[len(tsres)] = 10 ** 9 // (10 ** res if res < 128 else 2 ** (res - 128))
        elif btype == 6:                                           # enhanced packet
            ifid, hi, lo, cl, _ = struct.unpack(end + "IIIII", body[:20])
            yield ((hi << 32) | lo) * tsres.get(ifid, 1000), body[20:20 + cl]
        i += blen


# ---- packet fields ---------------------------------------------------------------------------
@dataclass
class Pkt:
    raw: bytes
    ihl: int
    doff: int
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: bytes

    @property
    def tcp_off(self):
        return 14 + self.ihl


def parse(raw):
    if len(raw) < 34 or raw[12:14] != b"\x08\x00" or raw[23] != 6:
        return None
    ihl = (raw[14] & 15) * 4
    t = 14 + ihl
    if len(raw) < t + 20:
        return None
    doff = (raw[t + 12] >> 4) * 4
    tl = struct.unpack(">H", raw[16:18])[0]
    sport, dport, seq, ack = struct.unpack(">HHII", raw[t:t + 12])
    return Pkt(raw, ihl, doff, sport, dport, seq, ack, raw[t + 13], raw[14 + ihl + doff:14 + tl])


def _csum(b):
    if len(b) & 1:
        b += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_ok(p):
    return _csum(p.raw[14:14 + p.ihl]) == 0


def tcp_ok(p):
    tl = struct.unpack(">H", p.raw[16:18])[0]
    seg = p.raw[p.tcp_off:14 + tl]
    return _csum(p.raw[26:34] + struct.pack(">BBH", 0, 6, len(seg)) + seg) == 0


def dnp3_crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return (c ^ 0xFFFF) & 0xFFFF


def dnp3_frame_ok(b):
    """Header CRC and every data-block CRC, and the declared length matches: absence of a check is not a pass."""
    if len(b) < 10 or b[:2] != b"\x05\x64" or dnp3_crc(b[:8]) != int.from_bytes(b[8:10], "little"):
        return False
    left, i = b[2] - 5, 10
    while left > 0:
        take = min(16, left)
        if i + take + 2 > len(b) or dnp3_crc(b[i:i + take]) != int.from_bytes(b[i + take:i + take + 2], "little"):
            return False
        i += take + 2
        left -= take
    return i == len(b)


# ---- eligibility and carve --------------------------------------------------------------------
def eligible(p):
    """(ok, reason). Single complete 49-byte frame, IPv4 without options, ACK set, no SYN/RST, no fragment."""
    if p is None:
        return False, "not IPv4/TCP"
    if p.ihl != 20:
        return False, "IPv4 options"
    if p.raw[20] & 0x3F or p.raw[21]:
        return False, "fragment"
    if not p.flags & ACK or p.flags & (SYN | RST):
        return False, "flags"
    if len(p.payload) != EXPECT_PAYLOAD:
        return False, "payload is %d bytes, not %d" % (len(p.payload), EXPECT_PAYLOAD)
    if not dnp3_frame_ok(p.payload):
        return False, "payload is not one valid DNP3 frame"
    return True, ""


def _build(p, payload, seq, flags):
    t = p.tcp_off
    ip = bytearray(p.raw[14:14 + p.ihl])
    tcp = bytearray(p.raw[t:t + p.doff])
    struct.pack_into(">H", ip, 2, p.ihl + p.doff + len(payload))
    struct.pack_into(">H", ip, 10, 0)
    struct.pack_into(">H", ip, 10, _csum(bytes(ip)))
    struct.pack_into(">I", tcp, 4, seq)
    tcp[13] = flags
    struct.pack_into(">H", tcp, 16, 0)
    seg = bytes(tcp) + payload
    struct.pack_into(">H", tcp, 16, _csum(bytes(ip[12:20]) + struct.pack(">BBH", 0, 6, len(seg)) + seg))
    return p.raw[:14] + bytes(ip) + bytes(tcp) + payload


def carve(raw, cut=CUT):
    """Return (segment1, segment2) in sequence order, or None when the packet is not eligible (unsplit).

    The profile is fixed: any cut other than 28 is rejected, not silently honoured."""
    if cut != CUT:
        raise ValueError("RRC_49_CUT28 is not runtime-configurable (cut=%r)" % cut)
    p = parse(raw)
    ok, _ = eligible(p)
    if not ok:
        return None
    first = _build(p, p.payload[:cut], p.seq, p.flags & ~(PSH | FIN))
    second = _build(p, p.payload[cut:], (p.seq + cut) & 0xFFFFFFFF, p.flags)
    return first, second
