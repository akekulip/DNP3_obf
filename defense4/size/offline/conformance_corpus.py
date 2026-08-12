#!/usr/bin/env python3
"""Shared machine-readable packet-vector corpus for the Defense-4 size cover kernel.

Every vector is a `Pkt` (p4_cover_emulator.Pkt) plus a per-packet expectation. The
SAME corpus is consumed by test_cover_conformance.py, which runs it through the P4
behavioral emulator AND an independent front-cover reference AND (for the transport
accounting) the depth-1 restriction of transport_oracle.py. Scenarios cover:

  seq-zero first response; 2-3 responses then retransmit resp1; retransmit/OOO of the
  opener and of a later response; an ACK landing inside the pad (partial-ack snap);
  SYN / both FINs / final ACK / RST / tuple reuse; a non-owner colliding flow; TCP
  options (dofs>5) / IP options (ihl>5) / fragments / malformed length / SACK-permitted
  SYN / MTU edge; and the exact-cover-bytes + checksum checks (done in the test).

`build_corpus()` returns a list of Scenario. `dump_json()` writes a machine-readable
snapshot. Pure stdlib.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from p4_cover_emulator import Pkt, PORT_DNP3, COVER_LEN

OUT_IP = 0x0A0A360A       # outstation 10.10.54.10
MAS_IP = 0x0A0A3613       # master     10.10.54.19
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)     # normalized (nm_ip, nr_ip, nm_pt, nr_pt)
RLEN = 54                                       # response payload length -> total_len 94


def _payload(tag: int, n: int = RLEN) -> bytes:
    # deterministic DNP3-shaped payload (starts with the 0x0564 sync so it looks real)
    body = bytes([0x05, 0x64]) + bytes(((tag * 131 + i * 17) & 0xFF) for i in range(n - 2))
    return body


def resp(seq: int, ack: int, tag: int = 0, n: int = RLEN, **kw) -> Pkt:
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=ack, payload=_payload(tag, n), **kw)


def out_ack(seq: int, ack: int, **kw) -> Pkt:      # bare segment from the outstation
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=ack, payload=b"", **kw)


def mack(seq: int, ack: int, **kw) -> Pkt:         # master -> outstation (REV)
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=ack, payload=b"", **kw)


def mreq(seq: int, ack: int, n: int = 20, **kw) -> Pkt:   # master request (REV, with payload)
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=ack,
               payload=bytes([0x05, 0x64] + [0] * (n - 2)), **kw)


@dataclass
class Step:
    pkt: Pkt
    exp: dict = field(default_factory=dict)     # subset of {out_seq,out_ack,cover_on,outcome,touched,translated,eligible}
    tag: int = 0                                 # response tag for reconstruction (>=1 for FWD data)


@dataclass
class Scenario:
    name: str
    steps: List[Step]
    owner: Optional[Tuple[int, int, int, int]] = OWNER
    reconstruct_fwd: bool = False                # check the receiver-visible FWD stream
    note: str = ""


def build_corpus() -> List[Scenario]:
    S: List[Scenario] = []
    O = 1000        # outstation ISN (FWD)
    M = 5000        # master ISN (REV)

    # 1. mainline: two responses, master acks whole padded stream. Reconstruct FWD.
    S.append(Scenario("mainline_two_responses", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O, outcome="INSERTED"), tag=1),
        Step(mack(M, O + RLEN + COVER_LEN), dict(out_ack=O + RLEN, translated=True)),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN, outcome="TRANSLATED"), tag=2),
        Step(mack(M, O + 2 * RLEN + COVER_LEN), dict(out_ack=O + 2 * RLEN)),
    ], reconstruct_fwd=True, note="one cover on resp1; resp2 shifted +16; acks translated back"))

    # 2. seq-zero first response (must NOT be misread as a retransmit)
    S.append(Scenario("seq_zero_first_response", [
        Step(resp(0, M, tag=1), dict(cover_on=True, out_seq=0, outcome="INSERTED"), tag=1),
        Step(resp(RLEN, M, tag=2), dict(cover_on=False, out_seq=RLEN + COVER_LEN), tag=2),
    ], reconstruct_fwd=True, note="first response has seq 0; valid-bit is reg_delta, not seq"))

    # 3. 2 responses then RETRANSMIT resp1 (re-emit cover, seq unchanged, no re-grow)
    S.append(Scenario("retransmit_opener", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN), tag=2),
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O, outcome="INSERTED"), tag=1),   # retransmit resp1
    ], reconstruct_fwd=True, note="retransmit of the opener re-emits the identical cover"))

    # 4. retransmit of a LATER response (no cover, same +16 shift)
    S.append(Scenario("retransmit_later", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN), tag=2),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN), tag=2),  # retransmit resp2
    ], reconstruct_fwd=True))

    # 5. out-of-order: resp2 arrives, then resp1 (opener) after it
    S.append(Scenario("ooo_resp2_before_resp1", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),                    # opener first (defines b0)
        Step(resp(O + 2 * RLEN, M, tag=3), dict(cover_on=False, out_seq=O + 2 * RLEN + COVER_LEN), tag=3),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN), tag=2),  # older, still +16
    ], reconstruct_fwd=True, note="every response after the boundary shifts +16 regardless of arrival order"))

    # 6. ACK landing INSIDE the pad (partial-ack snap to the boundary)
    S.append(Scenario("ack_inside_pad", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        # master acks only the first 8 cover bytes (padded O+8) -> snap to boundary O
        Step(mack(M, O + 8), dict(out_ack=O, translated=True)),
        # master acks the whole cover+resp1 (padded O+16+RLEN) -> O+RLEN
        Step(mack(M, O + COVER_LEN + RLEN), dict(out_ack=O + RLEN)),
    ], note="a cumulative ack inside the 16-byte cover snaps to the boundary"))

    # 7. bare outstation ACK before the boundary (native), then after (shifted)
    S.append(Scenario("bare_out_acks", [
        Step(out_ack(O, M), dict(out_seq=O, translated=False, outcome="NATIVE")),    # pre-boundary, delta 0
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),              # opener at same seq
        Step(out_ack(O + RLEN, M), dict(out_seq=O + RLEN + COVER_LEN, translated=True)),  # post-boundary
    ]))

    # 8. teardown: master FIN, outstation FIN, final ACK, then RST; single boundary open
    S.append(Scenario("teardown_fin_fin_ack", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(mack(M, O + RLEN + COVER_LEN), dict(out_ack=O + RLEN)),
        Step(mreq(M, O + RLEN + COVER_LEN, fin=True), dict()),                 # master FIN (REV) - ack translated
        Step(resp(O + RLEN, M + 1, tag=2, fin=True), dict(out_seq=O + RLEN + COVER_LEN), tag=2),  # out FIN (FWD)
        Step(mack(M + 1, O + 2 * RLEN + COVER_LEN + 1), dict(out_ack=O + 2 * RLEN + 1)),
    ], note="FIN is translated but does NOT retire; a first FIN must not strand the offset"))

    # 9. RST retires (owner): after reset a NEW opener re-opens
    S.append(Scenario("rst_then_reopen", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(mack(M, O, rst=True), dict()),                                    # owner RST -> reset
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=True, out_seq=O + RLEN, outcome="INSERTED"), tag=2),  # re-opens
    ], note="RST hard-resets the epoch; the next eligible response re-opens (new boundary)"))

    # 10. tuple reuse via SYN: SYN resets the epoch for a fresh connection
    S.append(Scenario("syn_reset_new_epoch", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(mack(M, O, syn=True, dofs=5), dict()),                            # clean SYN -> reset
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=True, out_seq=O + RLEN, outcome="INSERTED"), tag=2),
    ], note="a clean SYN opens a new epoch (reg_delta reset to 0)"))

    # ---- FAIL-CLOSED eligibility: MUST bypass native with NO state access -------------
    # 11. non-owner colliding flow (different tuple) must never touch state or reset us
    S.append(Scenario("non_owner_collision", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        # foreign flow: different master port; a SYN/RST that must NOT reset the protected flow
        Step(Pkt(0x0B0B0B0B, OUT_IP, 55555, PORT_DNP3, seq=7, ack=0, rst=True),
             dict(touched=False, outcome="NATIVE")),
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, out_seq=O + RLEN + COVER_LEN), tag=2),
    ], note="a foreign colliding RST must NOT reset the protected epoch (owner-qualified)"))

    # 12. IPv4 fragment (mf/offset) -> not TCP-parsed -> native, no state
    S.append(Scenario("ipv4_fragment", [
        Step(resp(O, M, tag=1, mf=1), dict(touched=False, translated=False, outcome="NATIVE", eligible=False)),
        Step(resp(O, M, tag=1, frag=100), dict(touched=False, outcome="NATIVE")),
    ], note="MF set or non-zero fragment offset -> ineligible, native, no register access"))

    # 13. IP options (ihl>5) -> not TCP-parsed -> native, no state
    S.append(Scenario("ip_options", [
        Step(resp(O, M, tag=1, ihl=6), dict(touched=False, outcome="NATIVE", eligible=False)),
    ], note="ihl>5 -> IP options -> ineligible, native"))

    # 14. TCP options (dofs>5) DATA -> ineligible -> native, NO translate/checksum-from-zero-residual
    S.append(Scenario("tcp_options_data", [
        Step(resp(O, M, tag=1), dict(cover_on=True, out_seq=O), tag=1),
        Step(resp(O + RLEN, M, tag=2, dofs=8), dict(touched=False, translated=False,
                                                    outcome="NATIVE", eligible=False)),
    ], note="a dofs>5 data segment is passed native (never translated from a zero residual)"))

    # 15. SACK-permitted SYN poisons the epoch: the flow is NEVER covered afterwards
    S.append(Scenario("sack_permitted_reject", [
        Step(mack(M, O, syn=True, dofs=8), dict()),                           # SYN with options -> poison
        Step(resp(O, M, tag=1), dict(cover_on=False, translated=False, outcome="NATIVE")),  # never opens
        Step(resp(O + RLEN, M, tag=2), dict(cover_on=False, outcome="NATIVE")),
    ], note="a SACK/option-bearing SYN poisons reg_delta -> the flow is never covered (fail-closed)"))

    # 16. MTU edge: a response whose native+cover would exceed the MTU is not opened
    big = 1500 - 20 - 20        # payload that makes total_len == MTU (no headroom for +16)
    S.append(Scenario("mtu_exceeded", [
        Step(resp(O, M, tag=1, n=big), dict(cover_on=False, translated=False, outcome="NATIVE")),
    ], note="native + 16 would exceed the MTU -> cover refused, native"))

    # 17. malformed length: total_len claims < 40 -> treated as no-payload, never opened
    S.append(Scenario("malformed_length", [
        Step(resp(O, M, tag=1, total_len_override=30), dict(cover_on=False, outcome="NATIVE")),
    ], note="a truncated/again-malformed total_len is bounded by the has_pay/mtu ranges"))

    # 18. control-plane fail-closed: t_owner EMPTY -> every packet native, no state
    S.append(Scenario("owner_unpopulated_failclosed", [
        Step(resp(O, M, tag=1), dict(touched=False, cover_on=False, translated=False, outcome="NATIVE")),
        Step(mack(M, O + RLEN), dict(touched=False, translated=False, outcome="NATIVE")),
    ], owner=None, note="unpopulated t_owner => owner never set => fail closed (all native)"))

    # 19. sequence wrap: boundary near 2^32, later response wraps past 0
    W = (1 << 32) - 30
    S.append(Scenario("seq_wrap", [
        Step(resp(W, M, tag=1, n=40), dict(cover_on=True, out_seq=W), tag=1),
        # next response seq = W+40 mod 2^32 = 10 (wrapped), still after the boundary -> +16
        Step(resp((W + 40) % (1 << 32), M, tag=2, n=40),
             dict(cover_on=False, out_seq=((W + 40) % (1 << 32) + COVER_LEN) % (1 << 32)), tag=2),
    ], note="modular seq arithmetic keeps the +16 shift correct across a wire wrap"))

    return S


def dump_json(path: str) -> None:
    out = []
    for sc in build_corpus():
        out.append({
            "name": sc.name, "owner": sc.owner, "note": sc.note,
            "reconstruct_fwd": sc.reconstruct_fwd,
            "steps": [{"pkt": {k: getattr(s.pkt, k) for k in
                               ("sip", "dip", "sport", "dport", "seq", "ack",
                                "syn", "fin", "rst", "ihl", "dofs", "mf", "frag")},
                       "payload_len": len(s.pkt.payload), "exp": s.exp, "tag": s.tag}
                      for s in sc.steps],
        })
    with open(path, "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    corpus = build_corpus()
    print(f"{len(corpus)} scenarios, {sum(len(s.steps) for s in corpus)} packet vectors")
    for sc in corpus:
        print(f"  - {sc.name:32s} ({len(sc.steps)} steps){'  [reconstruct]' if sc.reconstruct_fwd else ''}")
