#!/usr/bin/env python3
"""Byte-precise behavioral emulator of the REPAIRED defense4_cover_kernel.p4 egress.

This mirrors the P4 egress register/table logic exactly (single-insertion transport
epoch, poison-folded SACK reject, owner-exact validation, fail-closed eligibility,
front-prepend cover, clamp reverse-ack) and emits the real output wire bytes with
recomputed IPv4/TCP checksums. It is the P4 side of the conformance corpus
(test_cover_conformance.py runs the SAME corpus through this AND an independent
front-cover reference AND the depth-1 restriction of transport_oracle.py).

A `mode="legacy"` path reproduces the ORIGINAL scalar {delta_grow, last_resp_seq,
dlast, delta_reset-before-owner} semantics, so the regression vectors can show the
exact packets where the old source CORRUPTS while the repaired source is correct.

Pure stdlib. Run `python3 p4_cover_emulator.py` for a short self-demo.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

COVER_LEN = 16
PORT_DNP3 = 20000
MTU = 1500
DELTA_POISON = 0xFFFFFFFF
SEQ_MOD = 1 << 32
# The verified golden cover frame (see cover_frame_golden.py). Prepended at the front.
COVER_BYTES = bytes.fromhex("0564094432000100" "50C7" "C0C10200" "D82E")
assert len(COVER_BYTES) == COVER_LEN


def mod32(x: int) -> int:
    return x % SEQ_MOD


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
    """One TCP segment arriving at the egress (as it would be after the timing hold)."""
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
    ack_flag: bool = True
    ihl: int = 5              # >5 => IP options present
    dofs: int = 5             # >5 => TCP options present (SACK/timestamps)
    mf: int = 0               # more-fragments bit
    frag: int = 0             # fragment offset (13-bit)
    is_ipv4: bool = True
    proto: int = 6            # TCP
    total_len_override: Optional[int] = None   # for malformed-length vectors

    # --- derived ---
    def flags_byte(self) -> int:
        v = 0
        if self.fin: v |= 0x01
        if self.syn: v |= 0x02
        if self.rst: v |= 0x04
        if self.ack_flag: v |= 0x10
        return v

    def ip_total_len(self) -> int:
        if self.total_len_override is not None:
            return self.total_len_override
        return 20 + 4 * (self.ihl - 5) + 4 * self.dofs + len(self.payload)

    def wire(self, seq: Optional[int] = None, ack: Optional[int] = None,
             extra_total: int = 0, prepend: bytes = b"") -> bytes:
        """Serialize to on-wire bytes with VALID IPv4/TCP checksums. `prepend` is inserted
        immediately after the TCP header (the cover). eth is a fixed 14-byte L2 header."""
        seq = self.seq if seq is None else seq
        ack = self.ack if ack is None else ack
        eth = bytes.fromhex("0000000000010000000000020800")
        ip_opts = b"\x00" * (4 * (self.ihl - 5))
        tcp_opts = b"\x00" * (4 * (self.dofs - 5))
        total = self.ip_total_len() + extra_total
        # IPv4 header (20 + options)
        ver_ihl = (4 << 4) | self.ihl
        flags_frag = (self.mf << 13) | (self.frag & 0x1FFF)   # MF is bit 13 within flags|frag word
        ip_wo_csum = struct.pack("!BBHHHBBH", ver_ihl, 0, total, 0x1234,
                                 flags_frag, 64, self.proto, 0) + \
                     struct.pack("!II", self.sip, self.dip) + ip_opts
        ipc = ipv4_checksum(ip_wo_csum[:20] + ip_opts) if self.ihl == 5 else ipv4_checksum(ip_wo_csum)
        ip = ip_wo_csum[:10] + struct.pack("!H", ipc) + ip_wo_csum[12:]
        # TCP header (20 + options) + prepend(cover) + payload
        off = (self.dofs << 4)
        tcp_wo = struct.pack("!HHIIBBHHH", self.sport, self.dport, mod32(seq), mod32(ack),
                             off, self.flags_byte(), 65535, 0, 0) + tcp_opts
        body = prepend + self.payload
        tc = tcp_checksum(self.sip, self.dip, tcp_wo + body)
        tcp = tcp_wo[:16] + struct.pack("!H", tc) + tcp_wo[18:]
        return eth + ip + tcp + body


@dataclass
class Result:
    outcome: str
    out_seq: int
    out_ack: int
    cover_on: bool
    translated: bool
    delta_after: int
    touched_state: bool          # did this packet access ANY size register?
    wire: bytes = b""
    ipv4_ok: bool = False
    tcp_ok: bool = False
    eligible: bool = False
    owner: bool = False
    note: str = ""


# --------------------------------------------------------------------------- #
# the emulator
# --------------------------------------------------------------------------- #
class CoverEmulator:
    def __init__(self, owner_tuple: Optional[Tuple[int, int, int, int]] = None,
                 mode: str = "repaired"):
        assert mode in ("repaired", "legacy")
        self.mode = mode
        # per-flow state, keyed by the 10-bit flow_idx (like the P4 register array)
        self.delta: Dict[int, int] = {}
        self.b0: Dict[int, int] = {}
        # legacy-only scalar state
        self.last_seq: Dict[int, int] = {}
        self.dlast: Dict[int, int] = {}
        # the ONE protected flow's normalized tuple (control-plane t_owner entry).
        # None => t_owner empty => everything fails closed (native).
        self.owner_tuple = owner_tuple

    # -- normalization mirrors e_fold (DIR_OUT iff sport==PORT_DNP3) --
    @staticmethod
    def _norm(p: Pkt) -> Tuple[int, Tuple[int, int, int, int]]:
        if p.sport == PORT_DNP3:                # out -> master
            return 1, (p.dip, p.sip, p.dport, p.sport)   # (nm_ip,nr_ip,nm_pt,nr_pt), DIR_OUT
        return 0, (p.sip, p.dip, p.sport, p.dport)       # DIR_MASTER

    @staticmethod
    def _flow_idx(norm: Tuple[int, int, int, int]) -> int:
        # any stable hash mod 1024; both directions share it because _norm is symmetric
        return (hash(norm) & 0x3FF)

    def process(self, p: Pkt) -> Result:
        if self.mode == "legacy":
            return self._process_legacy(p)
        return self._process_repaired(p)

    # --------------------------------------------------------------- repaired
    def _process_repaired(self, p: Pkt) -> Result:
        # FAIL-CLOSED gate 1: only a fully parsed TCP segment enters the size layer.
        tcp_ok = p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0 and p.frag == 0
        if not tcp_ok:
            return self._native(p, note="not TCP-parsed (fragment/IP-options/non-IPv4)")

        d_out, norm = self._norm(p)
        idx = self._flow_idx(norm)
        owner = (self.owner_tuple is not None and norm == self.owner_tuple)
        eligible = (p.dofs == 5)                 # parser: dofs==5 (no TCP options)
        has_opt = (p.dofs > 5)
        is_syn, is_rst, is_ctl = p.syn, p.rst, (p.syn or p.fin or p.rst)

        # classify
        has_pay = p.ip_total_len() > 40
        if is_ctl:            cls = "CTL"
        elif d_out == 1:      cls = "RESP" if has_pay else "OUT_BARE"
        else:                 cls = "REV"
        is_fwd = cls in ("RESP", "OUT_BARE") or (is_ctl and d_out == 1)
        is_rev = cls == "REV" or (is_ctl and d_out == 0)

        if not owner:
            return self._native(p, note="non-owner (t_owner miss)", eligible=eligible)

        mtu_ok = 41 <= p.ip_total_len() <= (MTU - COVER_LEN)
        syn_delta = DELTA_POISON if (is_syn and has_opt) else 0
        open_req = (cls == "RESP" and eligible and mtu_ok)

        touched = False
        delta_old = 0
        # reg_delta (owner-gated; SYN/RST always, DATA only if eligible)
        if is_syn:
            delta_old = self.delta.get(idx, 0); self.delta[idx] = syn_delta; touched = True
        elif is_rst:
            delta_old = self.delta.get(idx, 0); self.delta[idx] = 0; touched = True
        elif eligible:
            delta_old = self.delta.get(idx, 0); touched = True
            if open_req and delta_old == 0:
                self.delta[idx] = COVER_LEN
        did_open = (open_req and delta_old == 0)

        b0_old = 0
        if is_syn or is_rst:
            b0_old = self.b0.get(idx, 0); self.b0[idx] = 0
        elif eligible:
            b0_old = self.b0.get(idx, 0)
            if did_open:
                self.b0[idx] = p.seq

        # boundary compares (mod32, signed via top bit)
        d_seq = mod32(p.seq - b0_old)
        a_diff = mod32(p.ack - b0_old)
        seq_add = COVER_LEN if (0 < d_seq < (SEQ_MOD >> 1)) else 0
        is_opener_retx = (d_seq == 0)
        if a_diff == 0 or a_diff >= (SEQ_MOD >> 1):
            ack_sub = 0
        elif a_diff < COVER_LEN:
            ack_sub = a_diff                     # snap inside the pad
        else:
            ack_sub = COVER_LEN

        cover_on = False
        if did_open:
            cover_on = True
        elif delta_old == COVER_LEN and cls == "RESP" and eligible and mtu_ok and is_opener_retx:
            cover_on = True

        out_seq, out_ack, translated = p.seq, p.ack, False
        if eligible and not is_syn:
            if is_fwd:
                if not did_open and delta_old == COVER_LEN and seq_add != 0:
                    out_seq = mod32(p.seq + seq_add); translated = True
                if cover_on:
                    translated = True
            if is_rev:
                if delta_old == COVER_LEN and ack_sub != 0:
                    out_ack = mod32(p.ack - ack_sub); translated = True

        prepend = COVER_BYTES if cover_on else b""
        extra = COVER_LEN if cover_on else 0
        if translated:
            wire = p.wire(seq=out_seq, ack=out_ack, extra_total=extra, prepend=prepend)
            outcome = "INSERTED" if cover_on else "TRANSLATED"
        else:
            wire = p.wire()                       # native, original valid checksum
            outcome = "NATIVE"
        return self._finish(p, wire, outcome, out_seq, out_ack, cover_on, translated,
                            self.delta.get(idx, 0), touched, eligible, True)

    # ----------------------------------------------------------------- legacy
    def _process_legacy(self, p: Pkt) -> Result:
        """The ORIGINAL buggy scalar semantics (for the regression control):
        - delta_reset runs on ANY control packet BEFORE ownership (10-bit index);
        - forward adds the TOTAL cumulative delta to every response;
        - reverse subtracts the TOTAL delta regardless of ack position;
        - retransmit detect via a single last_resp_seq (seq==0 first response misread).
        Deliberately faithful to the defects the repair fixes."""
        d_out, norm = self._norm(p)
        idx = self._flow_idx(norm)
        owner = (self.owner_tuple is not None and norm == self.owner_tuple)
        is_ctl = (p.syn or p.fin or p.rst)
        has_pay = p.ip_total_len() > 40
        if is_ctl:            cls = "CTL"
        elif d_out == 1:      cls = "RESP" if has_pay else "OUT_BARE"
        else:                 cls = "REV"

        touched = False
        # BUG: delta_reset before ownership, on the hash index
        if is_ctl:
            self.delta[idx] = 0; touched = True
            delta = 0
        elif cls == "RESP" and owner:
            is_retx = (self.last_seq.get(idx, 0) == p.seq)       # BUG: reg init 0 -> seq 0 misread as retx
            touched = True
            if not is_retx:
                self.last_seq[idx] = p.seq
                delta = self.delta.get(idx, 0)
                self.dlast[idx] = delta
                self.delta[idx] = delta + COVER_LEN               # BUG: grows every response
            else:
                delta = self.dlast.get(idx, 0)
        else:
            delta = self.delta.get(idx, 0)
            if owner:
                touched = True

        out_seq, out_ack, translated, cover_on = p.seq, p.ack, False, False
        if owner and cls in ("RESP", "OUT_BARE"):
            out_seq = mod32(p.seq + delta); translated = True                 # BUG: total delta
            if cls == "RESP":
                cover_on = (self.last_seq.get(idx) == p.seq)
        elif owner and cls == "REV":
            out_ack = mod32(p.ack - self.delta.get(idx, 0)); translated = True  # BUG: total delta
        prepend = COVER_BYTES if cover_on else b""
        extra = COVER_LEN if cover_on else 0
        wire = p.wire(seq=out_seq, ack=out_ack, extra_total=extra, prepend=prepend) if translated else p.wire()
        return self._finish(p, wire, "LEGACY", out_seq, out_ack, cover_on, translated,
                            self.delta.get(idx, 0), touched, p.dofs == 5, owner)

    # -------------------------------------------------------------- helpers
    def _native(self, p: Pkt, note: str = "", eligible: bool = False) -> Result:
        wire = p.wire()
        return self._finish(p, wire, "NATIVE", p.seq, p.ack, False, False,
                            0, False, eligible, False, note)

    def _finish(self, p, wire, outcome, out_seq, out_ack, cover_on, translated,
                delta_after, touched, eligible, owner, note="") -> Result:
        ipv4_ok, tcp_ok = self._verify_checksums(wire)
        return Result(outcome, out_seq, out_ack, cover_on, translated, delta_after,
                      touched, wire, ipv4_ok, tcp_ok, eligible, owner, note)

    @staticmethod
    def _verify_checksums(wire: bytes) -> Tuple[bool, bool]:
        """Recompute IPv4 + TCP checksums over the EMITTED bytes; both must verify to 0."""
        if len(wire) < 14 + 20:
            return True, True
        ip_off = 14
        ver_ihl = wire[ip_off]
        if (ver_ihl >> 4) != 4:
            return True, True
        ihl = (ver_ihl & 0xF) * 4
        ip_hdr = wire[ip_off:ip_off + ihl]
        ipv4_ok = (_ones_sum(ip_hdr) == 0xFFFF)
        proto = wire[ip_off + 9]
        if proto != 6:
            return ipv4_ok, True
        total_len = struct.unpack("!H", wire[ip_off + 2:ip_off + 4])[0]
        sip = struct.unpack("!I", wire[ip_off + 12:ip_off + 16])[0]
        dip = struct.unpack("!I", wire[ip_off + 16:ip_off + 20])[0]
        tcp_seg = wire[ip_off + ihl: ip_off + total_len]
        pseudo = struct.pack("!IIBBH", sip, dip, 0, 6, len(tcp_seg))
        tcp_ok = (_ones_sum(pseudo + tcp_seg) == 0xFFFF)
        return ipv4_ok, tcp_ok


if __name__ == "__main__":
    # tiny self-demo: open on the first response, translate the second, ack back.
    OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
    owner = (MAS_IP, OUT_IP, 40000, PORT_DNP3)      # normalized (nm,nr,nmpt,nrpt)
    e = CoverEmulator(owner_tuple=owner)
    isn = 1000
    r1 = e.process(Pkt(OUT_IP, MAS_IP, PORT_DNP3, 40000, seq=isn, ack=500, payload=b"\x05\x64" + b"\x00" * 52))
    r2 = e.process(Pkt(OUT_IP, MAS_IP, PORT_DNP3, 40000, seq=isn + 54, ack=500, payload=b"\x05\x64" + b"\x00" * 52))
    # master received padded stream cover(16)+resp1(54)+resp2(54)=124 bytes -> acks isn+124
    rack = e.process(Pkt(MAS_IP, OUT_IP, 40000, PORT_DNP3, seq=500, ack=isn + 124, payload=b""))
    for tag, r in [("resp1", r1), ("resp2", r2), ("ack", rack)]:
        print(f"{tag:6s} outcome={r.outcome:9s} out_seq={r.out_seq} out_ack={r.out_ack} "
              f"cover={int(r.cover_on)} ip_ok={int(r.ipv4_ok)} tcp_ok={int(r.tcp_ok)} "
              f"delta={r.delta_after} touched={int(r.touched_state)}")
    assert r1.cover_on and r1.out_seq == isn
    assert not r2.cover_on and r2.out_seq == isn + 54 + COVER_LEN
    assert rack.out_ack == isn + 108           # -16 (past the single boundary)
    assert all(r.ipv4_ok and r.tcp_ok for r in (r1, r2, rack))
    print("self-demo OK")
