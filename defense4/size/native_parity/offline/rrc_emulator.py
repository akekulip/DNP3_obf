#!/usr/bin/env python3
"""Behavioral emulator of defense4_rrc_kernel.p4 — the RELEASE-REPLICATE-CARVE (RRC)
native primitive. Models the FULL per-function transaction: request (READ/SELECT/OPERATE)
-> pure ACK -> 49 B response -> hold-to-deadline -> RELEASE -> PRE replicate -> CARVE.

It mirrors the P4 kernel's decisions rather than any one control:
  * ADMIT (RRC section 1). READ 0x01, SELECT 0x03, OPERATE 0x04 all arm the SAME
    transaction engine (arm-once). Each is an independent transaction that arms, ACKs,
    releases and RETIRES on its own; a SELECT must retire before an OPERATE can arm.
  * EXP_ACK (RRC section 2). Per FUNCTION: READ +20, SELECT/OPERATE +45. The old global
    read_len=18 is retired.
  * payload49 (RRC section 3). Eligibility of the 49 B response is derived from (dofs,
    total_len) WITH TCP options: dofs 5->89, 6->93, 7->97, 8->101 (the corpus TS case),
    plus the DNP3 single-fragment framing. The actual TCP options are preserved.
  * RELEASE -> PRE (RRC section 4/5). On the deadline-release pass a shape-armed, eligible,
    protected 49 B response is REPLICATED into one PRE group producing RID 1 (prefix) and
    RID 2 (suffix) and NOTHING else (no unicast source copy). The egress carves per RID:
       RID 1 = payload[0:28]  (dnp3_dl + blk0)  seq = base       clear PSH/FIN  tl -= 21
       RID 2 = payload[28:49] (blk1 + res3)     seq = base + 28   keep flags     tl -= 28
    join(RID1, RID2) == the original 49 B on a DNP3 CRC-block boundary; the carve is
    type-AGNOSTIC (READ-response and SBO-response take the identical path); IPv4+TCP
    checksums are recomputed per replica WITH the TCP options included.

`python3 rrc_emulator.py` runs the section-9 conformance asserts on the clean model and
then confirms every section-9 MUTANT is killed. Pure stdlib. NOT silicon — a compile is
not silicon; runtime PRE replication is verified by the hardware gates R1-R6.
"""
from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crc_split_emulator import (  # noqa: E402
    Pkt, build_frame, block_boundaries, verify_checksums, wire, mod32,
    tcp_checksum, ipv4_checksum, PORT_DNP3,
)

# ---- DNP3 function codes (payload offset 12 == func_code; see build_frame layout) ------
FC_READ, FC_SELECT, FC_OPERATE, FC_RESPONSE = 0x01, 0x03, 0x04, 0x81
FUNC_NAME = {FC_READ: "READ", FC_SELECT: "SELECT", FC_OPERATE: "OPERATE"}

# ---- RRC size profile RRC_49_CUT28 -----------------------------------------------------
SHAPE_SIZE = 49
CUT = 28                     # dnp3_dl(10) + blk0(18); the only supported cut
RID1_TL_DELTA = 21           # prefix total_len = orig - 21
RID2_TL_DELTA = 28           # suffix total_len = orig - 28
CLR_PSH_FIN = 0xF6
# (dofs -> ip.total_len) for a 49 B DNP3 payload, including TCP options
TL_FOR_DOFS = {5: 89, 6: 93, 7: 97, 8: 101}
# per-function request TCP payload length (RRC_REQUEST_PROFILES.txt)
REQ_LEN = {FC_READ: 20, FC_SELECT: 45, FC_OPERATE: 45}


def req_frame(func: int, size: int) -> bytes:
    """A master->outstation request whose TCP payload is exactly `size` bytes and whose
    DNP3 app func_code == func. user = tp_ctrl(0xC0) app_control(0xC0) func_code obj..."""
    # frame = 10 (link) + sum(block user + 2 CRC). Solve user length for the target size.
    user_target = _user_len_for_frame(size)
    user = bytes([0xC0, 0xC0, func]) + bytes((i * 5 + 3) & 0xFF for i in range(user_target - 3))
    f = build_frame(0x44, 1, 0, user)
    assert len(f) == size, (func, size, len(f))
    assert f[12] == func
    return f


def resp_frame_49(flavour: int) -> bytes:
    """A 49 B solicited RESPONSE (func 129). `flavour` varies the OBJECT bytes only, so a
    READ-flavour and an SBO-flavour 49 B response differ in content but not structure."""
    user = bytes([0xC0, 0xC0, FC_RESPONSE]) + bytes((i * flavour + 11) & 0xFF for i in range(30))
    f = build_frame(0x44, 0, 1, user)      # src=outstation(0), dest=master(1)
    assert len(f) == 49 and f[:2] == b"\x05\x64" and f[12] == FC_RESPONSE
    return f


def _user_len_for_frame(frame_size: int) -> int:
    """Inverse of build_frame's block chunking: user bytes for a given wire frame size."""
    body = frame_size - 10                 # bytes after the 10-byte link header
    user = 0
    while body > 0:
        take = min(18, body)               # a full block is 16 user + 2 CRC
        user += take - 2
        body -= take
    return user


# --------------------------------------------------------------------------- #
# emitted replica
# --------------------------------------------------------------------------- #
@dataclass
class Replica:
    rid: int
    seq: int
    payload: bytes
    total_len: int
    flags: int
    dofs: int
    ipv4_ok: bool
    tcp_ok: bool


@dataclass
class TxnResult:
    func: int
    admitted: bool
    exp_ack: int
    ack_matched: bool
    held_passes: int              # response hold passes before release
    carve_pass: int               # hold-pass index the carve fired at (== held_passes clean)
    source_copy: bool             # a unicast source copy was emitted (must be False)
    replicas: List[Replica] = field(default_factory=list)
    retired: bool = False
    trace: List[str] = field(default_factory=list)

    def reassemble(self) -> bytes:
        """Master TCP reassembly: order the carve replicas by seq, concatenate payloads."""
        return b"".join(r.payload for r in sorted(self.replicas, key=lambda r: r.seq))


# --------------------------------------------------------------------------- #
# the engine (one connection, one transaction at a time == arm-once)
# --------------------------------------------------------------------------- #
class RRCEngine:
    def __init__(self, owner_norm: Tuple[int, int, int, int], mode: str = "D4",
                 shape_enable: bool = True, deadline_passes: int = 4,
                 mutants: frozenset = frozenset()):
        self.owner = owner_norm            # (nm_ip, nr_ip, nm_pt, nr_pt)
        self.mode = mode                   # OFF / D2 / D3 / D4
        self.shape_enable = shape_enable
        self.deadline_passes = deadline_passes
        self.mutants = frozenset(mutants)
        self.active = None                 # the live transaction's func, or None (idle)

    # ---- RRC section 1: multi-function admission -------------------------------------
    def admit(self, func: int) -> bool:
        if "read_only_admit" in self.mutants:
            return func == FC_READ
        return func in (FC_READ, FC_SELECT, FC_OPERATE)

    # ---- RRC section 2: per-function expected ACK ------------------------------------
    def exp_ack(self, req_seq: int, func: int) -> int:
        if "global_read_len18" in self.mutants:
            return mod32(req_seq + 18)
        return mod32(req_seq + REQ_LEN[func])

    # ---- RRC section 3: parser eligibility, options-aware ----------------------------
    def payload49(self, resp: Pkt) -> bool:
        if not (resp.is_ipv4 and resp.proto == 6 and resp.ihl == 5
                and resp.mf == 0 and resp.frag == 0):
            return False
        if resp.syn or resp.rst:
            return False
        if "tl89_only" in self.mutants:
            if not (resp.dofs == 5 and resp.total_len() == 89):
                return False
        else:
            if resp.dofs not in TL_FOR_DOFS or resp.total_len() != TL_FOR_DOFS[resp.dofs]:
                return False
        return (len(resp.payload) == SHAPE_SIZE and resp.payload[:2] == b"\x05\x64")

    @staticmethod
    def _norm(p: Pkt) -> Tuple[int, Tuple[int, int, int, int]]:
        if p.sport == PORT_DNP3:                      # DIR_OUT: outstation -> master
            return 1, (p.dip, p.sip, p.dport, p.sport)
        return 0, (p.sip, p.dip, p.sport, p.dport)

    def _owner_resp(self, resp: Pkt) -> bool:
        d_out, norm = self._norm(resp)
        return d_out == 1 and norm == self.owner

    # ---- the carve (RRC section 5): type-agnostic, options-preserving ----------------
    def _carve(self, resp: Pkt) -> List[Replica]:
        f = resp.payload
        assert CUT in block_boundaries(f) and 0 < CUT < len(f)
        base = resp.seq
        base_flags = resp.flags_byte()
        out: List[Replica] = []

        def mk(rid, seq, payl, flags):
            seg = Pkt(resp.sip, resp.dip, resp.sport, resp.dport, mod32(seq), resp.ack,
                      payload=payl, dofs=resp.dofs, psh=bool(flags & 0x08),
                      fin=bool(flags & 0x01), win=resp.win)
            if "drop_options_in_csum" in self.mutants and resp.dofs > 5:
                # compute the TCP checksum over the header+payload MINUS the option bytes,
                # while still emitting the options -> an independent verifier rejects it.
                w = _wire_bad_csum_no_options(seg, seq, payl, flags)
            else:
                w = wire(seg, seq=seq, payload=payl, flags=flags)
            ip_ok, tcp_ok = verify_checksums(w)
            return Replica(rid=rid, seq=mod32(seq), payload=payl,
                           total_len=20 + 4 * (resp.dofs - 5) + 4 * 5 + len(payl),
                           flags=flags, dofs=resp.dofs, ipv4_ok=ip_ok, tcp_ok=tcp_ok)

        prefix = (f[:CUT], base, base_flags & CLR_PSH_FIN)
        suffix = (f[CUT:], mod32(base + CUT), base_flags)
        if "swap_rids" in self.mutants:
            out.append(mk(1, suffix[1], suffix[0], suffix[2]))
            out.append(mk(2, prefix[1], prefix[0], prefix[2]))
        else:
            out.append(mk(1, prefix[1], prefix[0], prefix[2]))
            if "one_pre_node" not in self.mutants:
                out.append(mk(2, suffix[1], suffix[0], suffix[2]))
        return out

    # ---- full request -> ACK -> response sequence ------------------------------------
    def run_sequence(self, req: Pkt, ack: Pkt, resp: Pkt) -> TxnResult:
        func = req.payload[12]
        tr = TxnResult(func=func, admitted=False, exp_ack=0, ack_matched=False,
                       held_passes=0, carve_pass=-1, source_copy=False)

        # ADMIT (arm-once): a busy engine rejects a second arm (concurrent-txn escape).
        if not self.admit(func):
            tr.trace.append("REQ func %s NOT admitted (bypass)" % FUNC_NAME.get(func, func))
            return tr
        if self.active is not None:
            tr.trace.append("REQ func %s while txn %s active -> ARM_BUSY (no arm)"
                            % (FUNC_NAME.get(func, func), FUNC_NAME.get(self.active)))
            return tr
        self.active = func
        tr.admitted = True
        tr.exp_ack = self.exp_ack(req.seq, func)
        tr.trace.append("ARM %s exp_ack=%d" % (FUNC_NAME[func], tr.exp_ack))

        # ACK: must match the per-function expected ACK on the protected session.
        tr.ack_matched = (mod32(ack.ack) == tr.exp_ack and ack.sport == PORT_DNP3
                          and len(ack.payload) == 0)
        tr.trace.append("ACK ack_no=%d matched=%s" % (mod32(ack.ack), tr.ack_matched))

        # RESPONSE: eligible + protected -> HELD to the deadline, then RELEASED + carved.
        eligible = self.payload49(resp) and self._owner_resp(resp)
        do_shape = self.shape_enable and eligible
        held = self.deadline_passes if self.mode != "OFF" else 0

        # split-before-release mutant: fire the carve on the FIRST hold pass, not the last.
        carve_at = 0 if "split_before_release" in self.mutants else held
        for k in range(held):
            tr.trace.append("HOLD pass %d (bypass_egress=1, no carve)" % k)
            if do_shape and k == carve_at:
                tr.replicas = self._carve(resp)
                tr.carve_pass = k
        tr.held_passes = held

        if do_shape and tr.carve_pass < 0:            # release pass
            tr.replicas = self._carve(resp)
            tr.carve_pass = held
            tr.trace.append("RELEASE -> PRE mcast RID1+RID2 (carve on the release pass)")
        elif not do_shape:
            # native unicast release: one rid==0 whole frame
            tr.replicas = [Replica(rid=0, seq=resp.seq, payload=resp.payload,
                                   total_len=resp.total_len(), flags=resp.flags_byte(),
                                   dofs=resp.dofs, ipv4_ok=True, tcp_ok=True)]
            tr.trace.append("RELEASE -> native unicast (no shape)")

        # source-copy duplication mutant: a unicast copy rides alongside the mcast replicas.
        if do_shape and "source_unicast_copy" in self.mutants:
            tr.source_copy = True
            tr.replicas.append(Replica(rid=0, seq=resp.seq, payload=resp.payload,
                                       total_len=resp.total_len(), flags=resp.flags_byte(),
                                       dofs=resp.dofs, ipv4_ok=True, tcp_ok=True))

        # the released RESPONSE retires the transaction (engine idle again).
        self.active = None
        tr.retired = True
        return tr


def _wire_bad_csum_no_options(p: Pkt, seq: int, payload: bytes, flags: int) -> bytes:
    """Serialize a segment whose TCP checksum was (wrongly) computed WITHOUT the option
    bytes, though the options ARE emitted — models the 'missing options in checksum' bug."""
    eth = bytes.fromhex("0000000000010000000000020800")
    total = 20 + 4 * (p.dofs) + len(payload)
    ver_ihl = (4 << 4) | 5
    ip_wo = struct.pack("!BBHHHBBH", ver_ihl, 0, total, 0x1234, 0, 64, 6, 0) + \
        struct.pack("!II", p.sip, p.dip)
    ipc = ipv4_checksum(ip_wo[:20])
    ip = ip_wo[:10] + struct.pack("!H", ipc) + ip_wo[12:]
    tcp_opts = b"\x00" * (4 * (p.dofs - 5))
    off = (p.dofs << 4)
    tcp_wo = struct.pack("!HHIIBBHHH", p.sport, p.dport, mod32(seq), mod32(p.ack),
                         off, flags, p.win, 0, 0) + tcp_opts
    tc = tcp_checksum(p.sip, p.dip, tcp_wo[:20] + payload)   # BUG: options excluded
    tcp = tcp_wo[:16] + struct.pack("!H", tc) + tcp_wo[18:]
    return eth + ip + tcp + payload


# =========================================================================== #
# section-9 conformance
# =========================================================================== #
OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613       # outstation, master
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)     # normalized response-direction 5-tuple


def _mk_req(func: int, seq: int) -> Pkt:
    f = req_frame(func, REQ_LEN[func])
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=1, payload=f)


def _mk_ack(exp_ack: int) -> Pkt:
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=500, ack=exp_ack, payload=b"", psh=False)


def _mk_resp(flavour: int, dofs: int, seq: int = 500) -> Pkt:
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=1,
               payload=resp_frame_49(flavour), dofs=dofs)


def _full_txn(eng: RRCEngine, func: int, dofs: int, flavour: int, req_seq: int = 1000):
    req = _mk_req(func, req_seq)
    exp = eng.exp_ack(req_seq, func)
    ack = _mk_ack(exp)
    resp = _mk_resp(flavour, dofs)
    return eng.run_sequence(req, ack, resp)


def run_conformance(mutants: frozenset = frozenset()) -> Dict[str, bool]:
    """Drive full READ/SELECT/OPERATE sequences and return the section-9 checks. On the
    clean model every value is True; each mutant flips at least one to False."""
    checks: Dict[str, bool] = {}

    # (1) all three functions ARM the same engine, each an independent transaction
    arm_ok = True
    exp_ok = True
    for func in (FC_READ, FC_SELECT, FC_OPERATE):
        eng = RRCEngine(OWNER, mode="D4", shape_enable=True, mutants=mutants)
        r = _full_txn(eng, func, dofs=8, flavour=7)
        arm_ok &= r.admitted and r.ack_matched and r.retired
        want = mod32(1000 + REQ_LEN[func])
        exp_ok &= (r.exp_ack == want)
    checks["all_functions_arm_same_engine"] = arm_ok
    checks["per_function_exp_ack"] = exp_ok

    # (2) hold to the deadline, then carve on the RELEASE pass (exactly once)
    eng = RRCEngine(OWNER, mode="D4", shape_enable=True, deadline_passes=4, mutants=mutants)
    r = _full_txn(eng, FC_READ, dofs=8, flavour=7)
    checks["held_to_deadline"] = (r.held_passes == 4)
    checks["carve_on_release_pass"] = (r.carve_pass == r.held_passes and r.held_passes == 4)

    # (3) exactly ONE PRE group -> RID1 + RID2, and NO source copy
    rids = sorted(x.rid for x in r.replicas)
    checks["exactly_rid1_and_rid2"] = (rids == [1, 2])
    checks["no_source_copy"] = (not r.source_copy and all(x.rid != 0 for x in r.replicas))

    # (4) both TS-option fixtures (dofs 5 tl 89 AND dofs 8 tl 101) carve to [28,21]
    both_ok = True
    for dofs in (5, 8):
        eng = RRCEngine(OWNER, mode="D4", shape_enable=True, mutants=mutants)
        rr = _full_txn(eng, FC_READ, dofs=dofs, flavour=7)
        pay = sorted((len(x.payload) for x in rr.replicas if x.rid in (1, 2)))
        both_ok &= (pay == [21, 28])
        both_ok &= (rr.reassemble() == resp_frame_49(7))                  # byte-exact
        both_ok &= all(x.ipv4_ok and x.tcp_ok for x in rr.replicas)      # checksums
    checks["both_option_fixtures_28_21"] = both_ok

    # (5) byte-exact reassembly + contiguous seq on the dofs=8 case
    r8 = _full_txn(RRCEngine(OWNER, mutants=mutants), FC_READ, dofs=8, flavour=7)
    r1 = [x for x in r8.replicas if x.rid == 1][0] if any(x.rid == 1 for x in r8.replicas) else None
    checks["reassembly_byte_exact"] = (r8.reassemble() == resp_frame_49(7))
    r2s = [x for x in r8.replicas if x.rid == 2]
    checks["contiguous_seq"] = bool(r1 and r2s and r2s[0].seq == mod32(r1.seq + CUT)
                                    and r1.payload == resp_frame_49(7)[:CUT])
    checks["checksums_valid"] = all(x.ipv4_ok and x.tcp_ok for x in r8.replicas)

    # (6) carve is type-AGNOSTIC: READ-response and SBO-response -> identical structure
    ra = _full_txn(RRCEngine(OWNER, mutants=mutants), FC_READ, dofs=8, flavour=7)
    rb = _full_txn(RRCEngine(OWNER, mutants=mutants), FC_OPERATE, dofs=8, flavour=99)
    struct_a = [(x.rid, x.seq - ra.replicas[0].seq, len(x.payload), x.total_len) for x in ra.replicas]
    struct_b = [(x.rid, x.seq - rb.replicas[0].seq, len(x.payload), x.total_len) for x in rb.replicas]
    checks["carve_type_agnostic"] = (struct_a == struct_b)

    # (7) SELECT retires before OPERATE arms (independent transactions, arm-once)
    eng = RRCEngine(OWNER, mode="D4", shape_enable=True, mutants=mutants)
    rsel = _full_txn(eng, FC_SELECT, dofs=8, flavour=7, req_seq=2000)
    idle_between = (eng.active is None)
    roper = _full_txn(eng, FC_OPERATE, dofs=8, flavour=7, req_seq=3000)
    checks["select_retires_before_operate"] = (rsel.retired and idle_between
                                               and roper.admitted and roper.ack_matched)
    return checks


MUTANTS = [
    "read_only_admit", "global_read_len18", "tl89_only", "drop_options_in_csum",
    "source_unicast_copy", "one_pre_node", "swap_rids", "split_before_release",
]


def main() -> int:
    clean = run_conformance(frozenset())
    print("== CLEAN MODEL (section 9) ==")
    for k, v in clean.items():
        print("  [%s] %s" % ("ok" if v else "FAIL", k))
    clean_ok = all(clean.values())

    print("\n== MUTANTS (each must be KILLED: >=1 check flips to FAIL) ==")
    killed = {}
    for m in MUTANTS:
        c = run_conformance(frozenset([m]))
        failed = [k for k, v in c.items() if not v]
        killed[m] = len(failed) > 0
        print("  [%s] %-22s killed_by=%s"
              % ("killed" if killed[m] else "SURVIVED", m, failed or "NONE"))

    all_killed = all(killed.values())
    ok = clean_ok and all_killed
    print("\nRESULT: %s  (clean=%s, mutants_killed=%d/%d)"
          % ("PASS" if ok else "FAIL", clean_ok, sum(killed.values()), len(MUTANTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
