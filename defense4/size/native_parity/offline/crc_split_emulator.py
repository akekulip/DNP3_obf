#!/usr/bin/env python3
"""Byte-precise behavioral emulator of defense4_crc_split_kernel.p4 (egress).

Mirrors the P4 egress EXACTLY for the compile-only native-parity splitter:

  * FAIL-OPEN gate. Only a clean IPv4/TCP segment (ihl==5, not fragmented,
    dofs==5, not SYN, not RST) whose payload is a RECOGNIZED splittable DNP3
    frame (starts with 05 64 and ip.total_len in {86, 89, 101, 104}, i.e. a
    2- or 3-block frame) enters the size layer; everything else is passed
    NATIVE (original bytes, original checksums, no state).

  * SPLIT (policy SPLIT). The frame is re-segmented into a fixed 2-way split on a
    COMPLETED DNP3 CRC-block boundary `cut` (28 = header block + blk0, or
    46 = + blk1). This is BYTE-PRESERVING: window0 = payload[:cut] (seq = base,
    PSH/FIN cleared), window1 = payload[cut:] (seq = base + cut, PSH/FIN kept).
    b"".join(windows) == payload, exactly. No byte is inserted or deleted, so
    there is NO sequence-space translation and NO transport state (no registers).
    Each window gets its own IPv4 total_len and recomputed IPv4/TCP checksums.
    (The P4 produces the two windows physically via egress mirror -> multicast;
    here we model the two output segments directly. Runtime replication is
    UNPROVEN — a compile is not silicon.)

  * REVERSE (master -> outstation). Byte-preserving split touches nothing on the
    reverse path — ACK space is never translated — so reverse packets pass NATIVE.

Same `cut` for READ and SBO: READ and SBO share one TCP/DNP3 connection, hence one
policy entry and one `cut`; once the endpoint has enlarged both responses to the
same size S, the identical byte-preserving vector is emitted for both classes.

Validated against the reference model readsbo_normalizer.py by
test_crc_split_conformance.py. Pure stdlib. `python3 crc_split_emulator.py` self-demo.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

PORT_DNP3 = 20000
SEQ_MOD = 1 << 32
MTU = 1500
DNP3_START = b"\x05\x64"

# recognized splittable frames: ip.total_len -> wire payload size S
SIZE_OK_TOTALS = {86: 46, 89: 49, 101: 61, 104: 64}
# valid completed-block cut boundaries
CUT_28, CUT_46 = 28, 46
POL_NONE, POL_SPLIT = "NONE", "SPLIT"


def mod32(x: int) -> int:
    return x % SEQ_MOD


# --------------------------------------------------------------------------- #
# DNP3 CRC-16/DNP + link framing (copied from the reference model, self-contained)
# --------------------------------------------------------------------------- #
def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF


def _crc_le(data: bytes) -> bytes:
    c = crc_dnp(data)
    return bytes([c & 0xFF, (c >> 8) & 0xFF])   # transmitted low byte first


HEADER_USER_OVERHEAD = 5
BLOCK_USER = 16


def build_frame(ctrl: int, dest: int, src: int, user: bytes) -> bytes:
    hdr = bytes([0x05, 0x64, HEADER_USER_OVERHEAD + len(user), ctrl,
                 dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    frame = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(user), BLOCK_USER):
        blk = user[i:i + BLOCK_USER]
        frame += blk + _crc_le(blk)
    return bytes(frame)


def frame_blocks(frame: bytes) -> List[bytes]:
    out = [frame[:10]]
    i = 10
    while i < len(frame):
        n = min(BLOCK_USER + 2, len(frame) - i)
        out.append(frame[i:i + n])
        i += n
    return out


def block_boundaries(frame: bytes) -> set:
    """Cumulative byte offsets at completed DNP3 CRC-block boundaries."""
    offs, acc = {0}, 0
    for b in frame_blocks(frame):
        acc += len(b)
        offs.add(acc)
    return offs


# --------------------------------------------------------------------------- #
# checksums (independent, standard ones-complement) — used to PROVE validity
# --------------------------------------------------------------------------- #
def _ones_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def ipv4_checksum(hdr20: bytes) -> int:
    return (~_ones_sum(hdr20)) & 0xFFFF


def tcp_checksum(sip: int, dip: int, tcp_hdr_and_payload: bytes) -> int:
    pseudo = struct.pack("!IIBBH", sip, dip, 0, 6, len(tcp_hdr_and_payload))
    return (~_ones_sum(pseudo + tcp_hdr_and_payload)) & 0xFFFF


# --------------------------------------------------------------------------- #
# packet model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pkt:
    sip: int
    dip: int
    sport: int
    dport: int
    seq: int
    ack: int
    payload: bytes = b""
    syn: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = True                 # a DNP3 data response is normally pushed
    win: int = 65535
    ihl: int = 5
    dofs: int = 5
    mf: int = 0
    frag: int = 0
    is_ipv4: bool = True
    proto: int = 6

    def flags_byte(self) -> int:
        v = 0x10                     # ACK
        if self.fin: v |= 0x01
        if self.syn: v |= 0x02
        if self.rst: v |= 0x04
        if self.psh: v |= 0x08
        return v

    def total_len(self) -> int:
        return 20 + 4 * (self.ihl - 5) + 4 * self.dofs + len(self.payload)


def wire(p: Pkt, seq: Optional[int] = None, payload: Optional[bytes] = None,
         flags: Optional[int] = None) -> bytes:
    """Serialize eth+ip+tcp+payload with VALID IPv4/TCP checksums."""
    seq = p.seq if seq is None else seq
    payload = p.payload if payload is None else payload
    flags = p.flags_byte() if flags is None else flags
    eth = bytes.fromhex("0000000000010000000000020800")
    total = 20 + 4 * (p.ihl - 5) + 4 * p.dofs + len(payload)
    ip_opts = b"\x00" * (4 * (p.ihl - 5))
    ver_ihl = (4 << 4) | p.ihl
    flags_frag = (p.mf << 13) | (p.frag & 0x1FFF)
    ip_wo = struct.pack("!BBHHHBBH", ver_ihl, 0, total, 0x1234, flags_frag, 64, p.proto, 0) + \
        struct.pack("!II", p.sip, p.dip) + ip_opts
    ipc = ipv4_checksum(ip_wo[:20]) if p.ihl == 5 else ipv4_checksum(ip_wo)
    ip = ip_wo[:10] + struct.pack("!H", ipc) + ip_wo[12:]
    tcp_opts = b"\x00" * (4 * (p.dofs - 5))
    off = (p.dofs << 4)
    tcp_wo = struct.pack("!HHIIBBHHH", p.sport, p.dport, mod32(seq), mod32(p.ack),
                         off, flags, p.win, 0, 0) + tcp_opts
    tc = tcp_checksum(p.sip, p.dip, tcp_wo + payload)
    tcp = tcp_wo[:16] + struct.pack("!H", tc) + tcp_wo[18:]
    return eth + ip + tcp + payload


def verify_checksums(w: bytes) -> Tuple[bool, bool]:
    ip_off = 14
    ihl = (w[ip_off] & 0xF) * 4
    ipv4_ok = (_ones_sum(w[ip_off:ip_off + ihl]) == 0xFFFF)
    total_len = struct.unpack("!H", w[ip_off + 2:ip_off + 4])[0]
    sip = struct.unpack("!I", w[ip_off + 12:ip_off + 16])[0]
    dip = struct.unpack("!I", w[ip_off + 16:ip_off + 20])[0]
    tcp_seg = w[ip_off + ihl:ip_off + total_len]
    pseudo = struct.pack("!IIBBH", sip, dip, 0, 6, len(tcp_seg))
    tcp_ok = (_ones_sum(pseudo + tcp_seg) == 0xFFFF)
    return ipv4_ok, tcp_ok


# --------------------------------------------------------------------------- #
# output model
# --------------------------------------------------------------------------- #
@dataclass
class Seg:
    seq: int
    payload: bytes
    total_len: int
    flags: int
    ack: int
    win: int
    wire: bytes
    ipv4_ok: bool
    tcp_ok: bool
    kind: str                        # WINDOW0 / WINDOW1 / NATIVE


@dataclass
class Result:
    outcome: str                     # SPLIT / NATIVE
    segs: List[Seg]
    touched_state: bool = False      # always False for this stateless splitter


def _mkseg(p: Pkt, seq: int, payload: bytes, flags: int, kind: str) -> Seg:
    w = wire(p, seq=seq, payload=payload, flags=flags)
    ip_ok, tcp_ok = verify_checksums(w)
    return Seg(seq=mod32(seq), payload=payload, total_len=40 + len(payload),
               flags=flags, ack=mod32(p.ack), win=p.win, wire=w,
               ipv4_ok=ip_ok, tcp_ok=tcp_ok, kind=kind)


# PSH (0x08) + FIN (0x01) cleared on the earlier segment
CLR_PSH_FIN = 0xF6


# --------------------------------------------------------------------------- #
# the emulator
# --------------------------------------------------------------------------- #
class CrcSplitEmulator:
    def __init__(self, owner_tuple: Optional[Tuple[int, int, int, int]] = None,
                 policy: str = POL_NONE, cut: int = CUT_28):
        self.owner_tuple = owner_tuple   # normalized (nm_ip, nr_ip, nm_pt, nr_pt)
        self.policy = policy
        self.cut = cut

    @staticmethod
    def _norm(p: Pkt) -> Tuple[int, Tuple[int, int, int, int]]:
        # DIR_OUT (outstation -> master) iff sport is the DNP3 listen port
        if p.sport == PORT_DNP3:
            return 1, (p.dip, p.sip, p.dport, p.sport)
        return 0, (p.sip, p.dip, p.sport, p.dport)

    def _native(self, p: Pkt) -> Result:
        return Result("NATIVE", [_mkseg(p, p.seq, p.payload, p.flags_byte(), "NATIVE")])

    def process(self, p: Pkt) -> Result:
        # FAIL-OPEN gate 1: clean unfragmented IPv4/TCP with no options
        if not (p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0
                and p.frag == 0 and p.dofs == 5):
            return self._native(p)

        d_out, norm = self._norm(p)
        owner = (self.owner_tuple is not None and norm == self.owner_tuple)

        # REVERSE direction: byte-preserving split never touches ACK space
        if d_out == 0:
            return self._native(p)

        # FORWARD: SYN/RST are conservative fail-open; FIN is allowed (rides window1)
        if p.syn or p.rst:
            return self._native(p)

        # recognized splittable DNP3 frame?
        size_ok = (p.total_len() in SIZE_OK_TOTALS
                   and len(p.payload) >= 10 and p.payload[:2] == DNP3_START
                   and len(p.payload) == SIZE_OK_TOTALS[p.total_len()])
        if not owner or self.policy != POL_SPLIT or not size_ok:
            return self._native(p)

        cut = self.cut
        S = len(p.payload)
        # cut must land on a real completed-block boundary and be interior
        if cut not in block_boundaries(p.payload) or not (0 < cut < S):
            return self._native(p)

        f = p.payload
        base_flags = p.flags_byte()
        w0_flags = base_flags & CLR_PSH_FIN                    # earlier segment
        w0 = _mkseg(p, p.seq, f[:cut], w0_flags, "WINDOW0")
        w1 = _mkseg(p, mod32(p.seq + cut), f[cut:], base_flags, "WINDOW1")
        return Result("SPLIT", [w0, w1])


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
    owner = (MAS_IP, OUT_IP, 40000, PORT_DNP3)

    def show(tag, user, cut):
        f = build_frame(0x44, 1, 0, user)
        e = CrcSplitEmulator(owner_tuple=owner, policy=POL_SPLIT, cut=cut)
        r = e.process(Pkt(OUT_IP, MAS_IP, PORT_DNP3, 40000, seq=1000, ack=5, payload=f))
        join = b"".join(s.payload for s in r.segs)
        print(f"{tag}: S={len(f)} cut={cut} -> segs={[s.total_len for s in r.segs]} "
              f"seqs={[s.seq for s in r.segs]} flags={[hex(s.flags) for s in r.segs]} "
              f"join_ok={join == f} csum_ok={all(s.ipv4_ok and s.tcp_ok for s in r.segs)}")
        assert join == f and all(s.ipv4_ok and s.tcp_ok for s in r.segs)
        return r

    # S=49 -> [28,21]; S=61 -> [28,33] and [46,15]; S=64 -> [28,36]
    show("S49", bytes([0xC0]) + bytes(range(32)), CUT_28)          # 33 user -> 49B
    show("S61", bytes([0xC0]) + bytes(range(44)), CUT_28)          # 45 user -> 61B
    show("S61", bytes([0xC0]) + bytes(range(44)), CUT_46)
    show("S64", bytes([0xC0]) + bytes(range(47)), CUT_28)          # 48 user -> 64B

    # READ and SBO of the same size share one cut -> identical vector
    read_u = bytes([0xC0]) + bytes(range(44))
    sbo_u = bytes([0xC0]) + bytes([0xFF]) * 44
    rr = show("READ", read_u, CUT_28)
    ss = show("SBO ", sbo_u, CUT_28)
    assert [s.total_len for s in rr.segs] == [s.total_len for s in ss.segs]
    print("self-demo OK")
