#!/usr/bin/env python3
"""Conformance test for the REPAIRED defense4_cover_kernel.p4 (single-insertion size epoch).

Runs the shared corpus (conformance_corpus.py) through:
  (A) the P4 behavioral emulator (p4_cover_emulator.py, mode="repaired");
  (B) an INDEPENDENT front-cover reference coded here from the plain spec;
and checks, for every vector:
  * out_seq / out_ack / cover_on / outcome / touched_state / eligible == expected;
  * emulator == independent reference (seq/ack/cover/state);
  * every EMITTED packet carries a VALID IPv4 AND TCP checksum;
  * the covered opener's emitted TCP payload BEGINS with the exact golden cover bytes;
  * for reconstruct scenarios, the receiver-visible FWD stream reassembles BYTE-EXACT
    to COVER_BYTES + the concatenated response payloads (no gaps, no conflicts),
    across retransmit and out-of-order delivery;
  * fail-closed vectors (fragment / IP options / TCP options / SACK / MTU / non-owner /
    unpopulated t_owner) touch NO size state and emit the native bytes unchanged.
Then two cross-checks:
  * DEPTH-1 ORACLE: the same forward/reverse seq/ack run through
    transport_oracle.TransportOracle(ledger_depth=1) produces the identical +/-16
    deltas (the P4 is exactly the depth-1 restriction of the reference oracle);
  * LEGACY REGRESSION: the ORIGINAL scalar semantics (emulator mode="legacy") CORRUPT
    the ack-inside-pad, non-owner-collision, and seq-zero vectors that the repair fixes.

Pure stdlib. Exit 0 iff every check passes.
"""
from __future__ import annotations
import struct
import sys
from typing import Dict, List, Optional, Tuple

from p4_cover_emulator import CoverEmulator, Pkt, COVER_LEN, COVER_BYTES, PORT_DNP3, mod32
from conformance_corpus import build_corpus, Scenario, Step, OWNER

FAILS: List[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        FAILS.append(msg)


# --------------------------------------------------------------------------- #
# Independent front-cover REFERENCE (coded from the plain spec, not the P4 logic)
# --------------------------------------------------------------------------- #
class RefState:
    def __init__(self):
        self.opened = False
        self.poisoned = False
        self.b0: Optional[int] = None


def ref_process(state: Dict, owner_tuple, p: Pkt) -> dict:
    """Return {out_seq,out_ack,cover_on,touched,translated,eligible,outcome}."""
    tcp_ok = p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0 and p.frag == 0
    if not tcp_ok:
        return dict(out_seq=p.seq, out_ack=p.ack, cover_on=False, touched=False,
                    translated=False, eligible=False, outcome="NATIVE")
    d_out = 1 if p.sport == PORT_DNP3 else 0
    norm = (p.dip, p.sip, p.dport, p.sport) if d_out else (p.sip, p.dip, p.sport, p.dport)
    owner = (owner_tuple is not None and norm == owner_tuple)
    eligible = (p.dofs == 5)
    st = state.setdefault(norm, RefState()) if owner else RefState()
    if not owner:
        return dict(out_seq=p.seq, out_ack=p.ack, cover_on=False, touched=False,
                    translated=False, eligible=eligible, outcome="NATIVE")

    touched = False
    # control packets manage the epoch
    if p.syn:
        touched = True
        st.opened = False; st.b0 = None
        st.poisoned = (p.dofs > 5)
        return dict(out_seq=p.seq, out_ack=p.ack, cover_on=False, touched=touched,
                    translated=False, eligible=eligible, outcome="NATIVE")
    if p.rst:
        touched = True
        st.opened = False; st.b0 = None; st.poisoned = False
        # (translate then reset — but for these vectors RST carries no data offset past b0)
        return dict(out_seq=p.seq, out_ack=p.ack, cover_on=False, touched=touched,
                    translated=False, eligible=eligible, outcome="NATIVE")
    if not eligible:      # dofs>5 data etc.
        return dict(out_seq=p.seq, out_ack=p.ack, cover_on=False, touched=False,
                    translated=False, eligible=False, outcome="NATIVE")

    has_pay = p.ip_total_len() > 40
    mtu_ok = 41 <= p.ip_total_len() <= (1500 - COVER_LEN)
    cls = "RESP" if (d_out and has_pay) else ("OUT_BARE" if d_out else "REV")
    touched = True     # eligible owner data reads state

    out_seq, out_ack, cover_on, translated = p.seq, p.ack, False, False
    if cls == "RESP" and not st.opened and not st.poisoned and mtu_ok:
        st.opened = True; st.b0 = p.seq
        cover_on = True; translated = True                       # opener: seq unchanged
    elif st.opened:
        b0 = st.b0
        if cls in ("RESP", "OUT_BARE"):
            d = mod32(p.seq - b0)
            if cls == "RESP" and d == 0 and mtu_ok:
                cover_on = True; translated = True               # opener retransmit
            elif 0 < d < (1 << 31):
                out_seq = mod32(p.seq + COVER_LEN); translated = True
        elif cls == "REV":
            a = mod32(p.ack - b0)
            if a == 0 or a >= (1 << 31):
                sub = 0
            elif a < COVER_LEN:
                sub = a
            else:
                sub = COVER_LEN
            if sub:
                out_ack = mod32(p.ack - sub); translated = True
    outcome = ("INSERTED" if cover_on else ("TRANSLATED" if translated else "NATIVE"))
    return dict(out_seq=out_seq, out_ack=out_ack, cover_on=cover_on, touched=touched,
                translated=translated, eligible=eligible, outcome=outcome)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def tcp_payload_of(wire: bytes) -> bytes:
    ihl = (wire[14] & 0xF) * 4
    total = struct.unpack("!H", wire[16:18])[0]
    dofs = (wire[14 + ihl + 12] >> 4) * 4
    return wire[14 + ihl + dofs: 14 + total]


def run_scenario(sc: Scenario) -> None:
    emu = CoverEmulator(owner_tuple=sc.owner, mode="repaired")
    refstate: Dict = {}
    reasm: Dict[int, int] = {}          # padded offset -> byte
    conflicts = 0
    b0 = None
    payload_by_seq: Dict[int, bytes] = {}

    for i, step in enumerate(sc.steps):
        r = emu.process(step.pkt)
        ref = ref_process(refstate, sc.owner, step.pkt)
        loc = f"{sc.name}[{i}]"

        # (A) expectation checks
        for k, v in step.exp.items():
            got = {"out_seq": r.out_seq, "out_ack": r.out_ack, "cover_on": r.cover_on,
                   "outcome": r.outcome, "touched": r.touched_state,
                   "translated": r.translated, "eligible": r.eligible}[k]
            check(got == v, f"{loc}: {k} expected {v} got {got}")

        # (B) emulator vs independent reference
        check(r.out_seq == ref["out_seq"], f"{loc}: ref out_seq {ref['out_seq']} != emu {r.out_seq}")
        check(r.out_ack == ref["out_ack"], f"{loc}: ref out_ack {ref['out_ack']} != emu {r.out_ack}")
        check(bool(r.cover_on) == ref["cover_on"], f"{loc}: ref cover {ref['cover_on']} != emu {r.cover_on}")
        check(bool(r.touched_state) == ref["touched"], f"{loc}: ref touched {ref['touched']} != emu {r.touched_state}")

        # every emitted packet must carry valid checksums (a deliberately MALFORMED-length
        # input cannot be checksum-valid; the switch correctly passes it native, so the
        # invariant we assert there is "not acted on", not "checksum valid").
        wellformed = step.pkt.total_len_override is None
        if wellformed:
            check(r.ipv4_ok, f"{loc}: emitted IPv4 checksum invalid")
            check(r.tcp_ok, f"{loc}: emitted TCP checksum invalid")

        # covered opener/retransmit must carry the exact golden cover bytes at the front
        if r.cover_on:
            pay = tcp_payload_of(r.wire)
            check(pay[:COVER_LEN] == COVER_BYTES, f"{loc}: cover bytes wrong: {pay[:COVER_LEN].hex()}")

        # collect FWD data for reconstruction
        if sc.reconstruct_fwd and step.tag >= 1 and step.pkt.sport == PORT_DNP3 and step.pkt.payload:
            if r.cover_on and b0 is None:
                b0 = step.pkt.seq
            payload_by_seq[step.pkt.seq] = step.pkt.payload
            pay = tcp_payload_of(r.wire)
            base = mod32(r.out_seq - (b0 if b0 is not None else r.out_seq))
            for j, byte in enumerate(pay):
                off = base + j
                if off in reasm and reasm[off] != byte:
                    conflicts += 1
                reasm[off] = byte

    # (C) byte-exact FWD reconstruction vs an independently built canonical stream
    if sc.reconstruct_fwd and b0 is not None:
        ordered = sorted(payload_by_seq.items(), key=lambda kv: mod32(kv[0] - b0))
        canonical = COVER_BYTES + b"".join(pl for _, pl in ordered)
        hi = max(reasm) + 1 if reasm else 0
        gaps = [o for o in range(hi) if o not in reasm]
        recon = bytes(reasm.get(o, 0) for o in range(hi))
        check(conflicts == 0, f"{sc.name}: reconstruction had {conflicts} byte conflict(s)")
        check(not gaps, f"{sc.name}: reconstruction had {len(gaps)} gap(s)")
        check(recon == canonical,
              f"{sc.name}: FWD stream != canonical (len {len(recon)} vs {len(canonical)})")


# --------------------------------------------------------------------------- #
# cross-check 1: depth-1 restriction of transport_oracle.py
# --------------------------------------------------------------------------- #
def depth1_oracle_crosscheck() -> None:
    try:
        from transport_oracle import TransportOracle, Segment, Dir
    except Exception as e:
        FAILS.append(f"depth1 oracle import failed: {e}")
        return
    o = TransportOracle(table_size=64, ledger_depth=1)
    F = "flow"
    isn_f, isn_r = 1000, 5000
    # resp1 inserts 16 (the single boundary); resp2 is a later segment.
    r1 = o.process(Segment(F, Dir.FWD, seq=isn_f, ack=isn_r, payload_len=54, insert=COVER_LEN))
    r2 = o.process(Segment(F, Dir.FWD, seq=isn_f + 54, ack=isn_r, payload_len=54))
    # master acks the whole padded response stream (108 orig + 16 pad)
    ra = o.process(Segment(F, Dir.REV, seq=isn_r, ack=isn_f + 108 + COVER_LEN, payload_len=0))
    check(r1.seq == isn_f, f"oracle depth1: opener seq shifted ({r1.seq})")
    check(r2.seq == isn_f + 54 + COVER_LEN, f"oracle depth1: later seq {r2.seq} != +16")
    check(ra.ack == isn_f + 108, f"oracle depth1: reverse ack {ra.ack} != -16")

    # the emulator on the SAME numbers must agree on the +/-16 deltas
    emu = CoverEmulator(owner_tuple=OWNER)
    OUT, MAS = OWNER[1], OWNER[0]
    e1 = emu.process(Pkt(OUT, MAS, PORT_DNP3, OWNER[2], seq=isn_f, ack=isn_r, payload=b"\x05\x64" + b"\0" * 52))
    e2 = emu.process(Pkt(OUT, MAS, PORT_DNP3, OWNER[2], seq=isn_f + 54, ack=isn_r, payload=b"\x05\x64" + b"\0" * 52))
    ea = emu.process(Pkt(MAS, OUT, OWNER[2], PORT_DNP3, seq=isn_r, ack=isn_f + 108 + COVER_LEN, payload=b""))
    check(e1.out_seq == r1.seq and e2.out_seq == r2.seq and ea.out_ack == ra.ack,
          f"emulator vs depth1-oracle mismatch: emu({e1.out_seq},{e2.out_seq},{ea.out_ack}) "
          f"oracle({r1.seq},{r2.seq},{ra.ack})")


# --------------------------------------------------------------------------- #
# cross-check 2: LEGACY semantics CORRUPT the vectors the repair fixes
# --------------------------------------------------------------------------- #
def legacy_regression() -> None:
    O, M = 1000, 5000
    OUT, MAS = OWNER[1], OWNER[0]

    def resp(e, seq, tag=1):
        body = bytes([0x05, 0x64]) + bytes((tag * 131 + i) & 0xFF for i in range(52))
        return e.process(Pkt(OUT, MAS, PORT_DNP3, OWNER[2], seq=seq, ack=M, payload=body))

    def mack(e, ack, **kw):
        return e.process(Pkt(MAS, OUT, OWNER[2], PORT_DNP3, seq=M, ack=ack, payload=b"", **kw))

    # R1: ack-inside-pad. Repaired snaps to boundary; legacy subtracts the full delta.
    er = CoverEmulator(owner_tuple=OWNER, mode="repaired")
    el = CoverEmulator(owner_tuple=OWNER, mode="legacy")
    resp(er, O); resp(el, O)
    rr = mack(er, O + 8); rl = mack(el, O + 8)
    check(rr.out_ack == O, f"repaired ack-in-pad snap wrong: {rr.out_ack}")
    check(rl.out_ack != rr.out_ack, "legacy did NOT corrupt ack-inside-pad (regression not demonstrated)")

    # R2: non-owner colliding RST. Repaired keeps the epoch; legacy resets it.
    er = CoverEmulator(owner_tuple=OWNER, mode="repaired")
    el = CoverEmulator(owner_tuple=OWNER, mode="legacy")
    resp(er, O, tag=1); resp(el, O, tag=1)
    foreign = Pkt(0x0B0B0B0B, OUT, 55555, PORT_DNP3, seq=7, ack=0, rst=True)
    fr = er.process(foreign); fl = el.process(foreign)
    check(fr.touched_state is False, "repaired: foreign RST touched state")
    r2r = resp(er, O + 54, tag=2); r2l = resp(el, O + 54, tag=2)
    check(r2r.out_seq == O + 54 + COVER_LEN, f"repaired later-resp seq wrong: {r2r.out_seq}")
    # legacy reset delta on the foreign RST's colliding index (or regrows), so its resp2 seq differs
    check(r2l.out_seq != r2r.out_seq or fl.touched_state is True,
          "legacy did NOT corrupt on the foreign collision (regression not demonstrated)")

    # R3: seq-zero first response. Repaired covers it; legacy (last_seq init 0) misreads as retx.
    er = CoverEmulator(owner_tuple=OWNER, mode="repaired")
    el = CoverEmulator(owner_tuple=OWNER, mode="legacy")
    z_r = resp(er, 0); z_l = resp(el, 0)
    check(z_r.cover_on is True and z_r.delta_after == COVER_LEN,
          f"repaired seq-zero not opened: cover={z_r.cover_on} delta={z_r.delta_after}")
    check(z_l.delta_after != z_r.delta_after or z_l.cover_on != z_r.cover_on,
          "legacy did NOT corrupt seq-zero (regression not demonstrated)")


# --------------------------------------------------------------------------- #
def main() -> int:
    corpus = build_corpus()
    for sc in corpus:
        run_scenario(sc)
    n_steps = sum(len(s.steps) for s in corpus)
    print(f"[corpus]   {len(corpus)} scenarios, {n_steps} packet vectors through emulator+reference")

    depth1_oracle_crosscheck()
    print("[oracle]   depth-1 transport_oracle cross-check")

    legacy_regression()
    print("[regress]  legacy-vs-repaired corruption on ack-in-pad / non-owner / seq-zero")

    if FAILS:
        print(f"\nFAIL ({len(FAILS)}):")
        for f in FAILS[:40]:
            print("  -", f)
        return 1
    print(f"\nPASS: all conformance checks green "
          f"({n_steps} vectors, checksums valid, byte-exact reconstruction, "
          f"depth-1 oracle agrees, legacy regressions demonstrated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
