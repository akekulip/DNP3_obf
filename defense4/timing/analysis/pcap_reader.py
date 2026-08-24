"""Minimal, dependency-free reader for the capture formats in this evidence package.

Supports classic pcap (microsecond and nanosecond) and pcapng (Section Header Block /
Interface Description Block / Enhanced Packet Block), which is what `dumpcap` wrote here
even though the files carry a .pcap extension.

Timestamps are returned as INTEGER NANOSECONDS since the epoch. That matters: these
captures have nanosecond resolution, and the quantities of interest are millisecond
intervals measured on epoch-scale timestamps. Carrying them as float64 seconds loses
roughly a quarter of a microsecond per timestamp, and older scapy releases mis-scale
pcapng timestamps by a factor of 1000 outright. Integer nanoseconds avoid both problems,
so the extraction does not depend on which scapy happens to be installed.

Only Ethernet -> IPv4 -> TCP is decoded, which is all this testbed produces.
"""
from __future__ import annotations

import struct

ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6


class CaptureFormatError(Exception):
    pass


def _iter_pcapng(data):
    off, endian, tsresol = 0, "<", {}
    if_index = 0
    while off + 12 <= len(data):
        btype, = struct.unpack_from(endian + "I", data, off)
        if btype == 0x0A0D0D0A:                       # Section Header Block
            bom, = struct.unpack_from("<I", data, off + 8)
            endian = "<" if bom == 0x1A2B3C4D else ">"
            tsresol, if_index = {}, 0
        blen, = struct.unpack_from(endian + "I", data, off + 4)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8: off + blen - 4]
        if btype == 0x00000001:                       # Interface Description Block
            res = 6                                   # default 10^-6 s
            p = 8                                     # skip linktype(2) reserved(2) snaplen(4)
            while p + 4 <= len(body):
                ocode, olen = struct.unpack_from(endian + "HH", body, p)
                if ocode == 0:
                    break
                if ocode == 9 and olen >= 1:          # if_tsresol
                    res = body[p + 4]
                p += 4 + ((olen + 3) // 4) * 4
            tsresol[if_index] = res
            if_index += 1
        elif btype == 0x00000006:                     # Enhanced Packet Block
            iface, tsh, tsl, caplen, _olen = struct.unpack_from(endian + "IIIII", body, 0)
            raw_ts = (tsh << 32) | tsl
            res = tsresol.get(iface, 6)
            if res & 0x80:                            # power-of-two resolution
                ns = raw_ts * (10 ** 9) >> (res & 0x7F)
            else:
                ns = raw_ts * (10 ** (9 - res)) if res <= 9 else raw_ts // (10 ** (res - 9))
            yield ns, body[20: 20 + caplen]
        off += blen


def _iter_classic(data):
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, scale = "<", 1000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, scale = ">", 1000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, scale = "<", 1
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, scale = ">", 1
    else:
        raise CaptureFormatError("unrecognised capture magic %r" % magic)
    off = 24
    while off + 16 <= len(data):
        sec, frac, caplen, _orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        yield sec * 10 ** 9 + frac * scale, data[off: off + caplen]
        off += caplen


def iter_frames(path):
    """Yield (timestamp_ns, raw_link_layer_bytes) for every packet record."""
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        raise CaptureFormatError("empty capture file: %s" % path)
    it = _iter_pcapng(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else _iter_classic(data)
    for rec in it:
        yield rec


def decode_tcp(frame):
    """Decode Ethernet/IPv4/TCP. Returns a dict or None if the frame is not IPv4 TCP.

    The TCP payload is trimmed to the IP total length, so Ethernet padding on short frames
    (a pure ACK is padded to the 60-byte minimum here) is never mistaken for payload.
    """
    if len(frame) < 34:
        return None
    ethertype, = struct.unpack_from("!H", frame, 12)
    off = 14
    while ethertype in (0x8100, 0x88A8):              # VLAN tags, if ever present
        if len(frame) < off + 4:
            return None
        ethertype, = struct.unpack_from("!H", frame, off + 2)
        off += 4
    if ethertype != ETHERTYPE_IPV4:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl:
        return None
    total_len, = struct.unpack_from("!H", frame, off + 2)
    proto = frame[off + 9]
    if proto != IPPROTO_TCP:
        return None
    src = ".".join(str(b) for b in frame[off + 12: off + 16])
    dst = ".".join(str(b) for b in frame[off + 16: off + 20])
    toff = off + ihl
    if len(frame) < toff + 20:
        return None
    doff = (frame[toff + 12] >> 4) * 4
    flags = frame[toff + 13]
    seq, = struct.unpack_from("!I", frame, toff + 4)
    payload_len = total_len - ihl - doff
    if payload_len < 0:
        payload_len = 0
    payload = frame[toff + doff: toff + doff + payload_len]
    return {"src": src, "dst": dst, "flags": flags, "seq": seq, "payload": payload}
