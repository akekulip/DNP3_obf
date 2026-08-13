#!/usr/bin/env python3
"""Behavioral model of the TWO-PIPE BOR split (BOR_TWO_PIPE_PROPOSAL.md).

The one-pipe BOR-in-RRC model is bor_rrc_emulator.py. This model splits the SAME lifecycle
across TWO Tofino-1 pipes joined by an internal cross-pipe loopback, and proves the property
the split adds risk to: the released OPERATE reaches the relay EXACTLY ONCE across the
cross-pipe handoff, retransmits, and the readiness / fail-open cases.

  PIPE 0  = frozen RRC transaction engine + T0-admission + cross-pipe route. On the protected
            OPERATE it records T0, T0-ANCHORS reg_deadline=T0+A / reg_tresp=T0+R (so the relay
            ACK/echo, later FRESH packets back to pipe 0, are held T0-anchored and NEVER
            re-anchored to the delayed release), stamps T0 into an internal xpipe header, and
            routes ONE copy to pipe 1. It does NOT hold the OPERATE. A retransmit of a still-
            active OPERATE is a duplicate (reg_tag) and is DROPPED — it never crosses twice.
  PIPE 1  = BOR OPERATE hold/release core. It receives the cross-pipe OPERATE, selects a
            leak-safe J, arms reg_topj=T0+J on its OWN per-pipe register (T0 comes IN the
            packet, never a shared register), holds the byte-identical original in qid2 behind
            its own qid3 reservoir, and releases to the relay EXACTLY ONCE at T0+J. Readiness
            unproven -> fail open WITHOUT holding (forward once).

STATE IS PER-PIPE. T0 travels in the xpipe header to pipe 1; the response-anchor T0 lives in
pipe 0's own reg_deadline/reg_tresp. Neither pipe reads the other's registers.

GROUND TRUTH FOR EXACTLY-ONCE: `relay_rx` — every OPERATE byte-string the relay receives, with
its source leg. For one protected OPERATE transaction (and its retransmits), len(relay_rx) MUST
be exactly 1.  `python3 bor_twopipe_emulator.py` runs the conformance asserts + kills the design
mutants. Pure stdlib; NOT silicon (a model is not a compile is not silicon).
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rrc_emulator import req_frame, FC_OPERATE, REQ_LEN                 # noqa: E402
from bor_rrc_emulator import BORConfig, CODEBOOK, EPS                   # noqa: E402

GEN_INACTIVE = 0

# ------------------------- cross-pipe frame (the pipe0 -> pipe1 leg) ------------------------- #
@dataclass
class XPipeFrame:
    """What pipe 0 emits toward pipe 1: the ORIGINAL OPERATE bytes + an internal xpipe header
    carrying T0 (and orig_etype for byte-identical restoration). Stripped at pipe-1 release."""
    t0: float
    gen: int
    orig_bytes: bytes
    orig_etype: int = 0x0800


@dataclass
class RelayRx:
    """One OPERATE the relay received, and which leg delivered it (for exactly-once auditing)."""
    time: float
    payload: bytes
    leg: str                     # "pipe1_hold_release" | "pipe1_fail_open" | "pipe0_bypass"


@dataclass
class Verdict:
    FRESH = "FRESH"
    DUP = "DUP"
    BUSY = "BUSY"


# --------------------------------- PIPE 0 (RRC + T0-admission) ------------------------------- #
class Pipe0:
    """RRC transaction engine (abstracted to the OPERATE path) + T0-admission + cross-pipe route.
    Per-pipe registers: reg_tag (active generation), reg_deadline (T0+A), reg_tresp (T0+R)."""

    def __init__(self, cfg: BORConfig, mutants: frozenset = frozenset()):
        self.cfg = cfg
        self.mutants = frozenset(mutants)
        self.reg_tag = GEN_INACTIVE           # active OPERATE generation
        self.reg_deadline: Optional[float] = None   # armed absolute ACK release word (T0+A)
        self.reg_tresp: Optional[float] = None      # armed absolute echo release word (T0+R)
        self.crossings: List[XPipeFrame] = []       # every copy routed to pipe 1 (must be 1/txn)
        self.recorded_T0: Optional[float] = None

    def _classify(self, gen: int) -> str:
        if self.reg_tag == GEN_INACTIVE:
            return Verdict.FRESH
        if self.reg_tag == gen:
            return Verdict.DUP
        return Verdict.BUSY

    def operate(self, gen: int, T0: float, relay_rx: List[RelayRx],
                original: bytes) -> Optional[XPipeFrame]:
        """A master OPERATE arrives fresh on the master-facing port at T0."""
        v = self._classify(gen)
        if v == Verdict.FRESH:
            # arm the generation (reg_tag) — arm-once, so a same-gen retransmit reads DUP
            self.reg_tag = gen
            self.recorded_T0 = T0
            # T0-ANCHOR: reg_deadline := T0+A, reg_tresp := T0+R  (NEVER t_ack+D, NEVER T0+J)
            self.reg_deadline = T0 + self.cfg.A
            self.reg_tresp = T0 + self.cfg.R
            # stamp T0 into xpipe and route ONE copy to pipe 1
            xf = XPipeFrame(t0=T0, gen=gen, orig_bytes=original)
            self.crossings.append(xf)
            if "pipe0_cross_twice" in self.mutants:
                self.crossings.append(xf)         # WRONG: two copies cross -> double release
            return xf
        if v == Verdict.DUP:
            # exact retransmit of a still-active OPERATE. Must NOT cross again (exactly-once).
            if "pipe0_no_dup_drop" in self.mutants:
                # WRONG: forward/cross the retransmit -> a second OPERATE reaches the relay
                self.crossings.append(XPipeFrame(t0=T0, gen=gen, orig_bytes=original))
                return self.crossings[-1]
            return None                            # dropped: no second cross
        # BUSY: a different generation is already active -> forward unprotected to the relay ONCE
        relay_rx.append(RelayRx(T0, original, "pipe0_bypass"))
        return None

    def ack_release_time(self, gen: int) -> Optional[float]:
        """The relay ACK (a later FRESH packet to pipe 0) is held to the T0-anchored reg_deadline."""
        if self.reg_deadline is None:
            return None
        if "reanchor_ack_to_release" in self.mutants:
            # WRONG: re-anchor to the delayed release T0+J -> leaks J via response timing
            return self.recorded_T0 + max(self.cfg.codebook) + self.cfg.A
        return self.reg_deadline

    def echo_release_time(self) -> Optional[float]:
        return self.reg_tresp

    def retire(self):
        self.reg_tag = GEN_INACTIVE
        self.reg_deadline = None
        self.reg_tresp = None


# --------------------------------- PIPE 1 (BOR hold/release) --------------------------------- #
class Pipe1:
    """BOR OPERATE hold/release core. Per-pipe registers: reg_gen, reg_topj (T0+J), reg_ready."""

    def __init__(self, cfg: BORConfig, mutants: frozenset = frozenset()):
        self.cfg = cfg
        self.mutants = frozenset(mutants)
        self.reg_gen = GEN_INACTIVE
        self.reg_topj: Optional[float] = None
        self.reg_ready = GEN_INACTIVE          # generation for which qid3 residency is confirmed
        self.held: Optional[Tuple[float, int, bytes]] = None   # (t0, gen, bytes) in qid2
        self.released = 0

    def _select_j(self, scn_j_index: int, app_seq: int) -> float:
        if "j_from_public_seq" in self.mutants:
            return float(self.cfg.codebook[app_seq % len(self.cfg.codebook)])
        return float(self.cfg.codebook[scn_j_index])

    def confirm_residency(self, gen: int):
        """A live qid3 token that completed a loop stamps reg_ready for its generation."""
        self.reg_ready = gen

    def receive_xpipe(self, xf: XPipeFrame, j_index: int, app_seq: int,
                      relay_rx: List[RelayRx], readiness_policy: str) -> None:
        """Fresh cross-pipe OPERATE on PORT_X1. T0 is xf.t0 (from the header, not a register)."""
        if self.reg_gen != GEN_INACTIVE:
            if self.reg_gen == xf.gen:
                # a duplicate crossed (should not happen if pipe 0 drops dups) -> DROP, no release
                return
            # a different generation active: forward unprotected once (scope limit)
            relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "pipe1_fail_open"))
            return
        self.reg_gen = xf.gen
        j = self._select_j(j_index, app_seq)
        self.reg_topj = xf.t0 + j                     # arm on pipe 1's OWN register, T0 from header
        ready = (self.reg_ready == xf.gen)
        if readiness_policy == "structural_guarantee" and not ready:
            # residency not yet confirmed for this gen -> FAIL OPEN WITHOUT HOLDING (forward once)
            relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "pipe1_fail_open"))
            self.reg_gen = GEN_INACTIVE
            self.reg_topj = None
            return
        # HOLD: strip xpipe (byte-identical original) into qid2
        self.held = (xf.t0, xf.gen, xf.orig_bytes)

    def drain_release(self, relay_rx: List[RelayRx]) -> None:
        """qid3 drains at T0+J -> release the qid2-held OPERATE to the relay EXACTLY ONCE."""
        if self.held is None:
            return
        t0, gen, payload = self.held
        assert self.reg_topj is not None
        relay_rx.append(RelayRx(self.reg_topj, payload, "pipe1_hold_release"))
        self.released += 1
        if "pipe1_duplicate_release" in self.mutants:
            relay_rx.append(RelayRx(self.reg_topj, payload, "pipe1_hold_release"))  # WRONG
            self.released += 1
        self.held = None
        self.reg_gen = GEN_INACTIVE
        self.reg_topj = None


# ------------------------------------- the joined lifecycle ---------------------------------- #
@dataclass
class Scenario:
    gen: int = 0xC1
    T0: float = 1000.0
    j_index: int = 5
    app_seq: int = 3
    retransmit: bool = False        # an exact retransmit arrives at pipe 0 while the OP is held
    residency_ready: bool = True    # was pipe-1 qid3 pre-confirmed resident for this gen?
    readiness_policy: str = "structural_guarantee"


@dataclass
class TwoPipeResult:
    relay_rx: List[RelayRx] = field(default_factory=list)
    crossings: int = 0
    ack_time: Optional[float] = None
    echo_time: Optional[float] = None
    byte_identical: bool = False
    released_bytes: Optional[bytes] = None
    original: bytes = b""


def run_two_pipe(scn: Scenario, cfg: BORConfig = BORConfig(),
                 mutants: frozenset = frozenset()) -> TwoPipeResult:
    p0 = Pipe0(cfg, mutants)
    p1 = Pipe1(cfg, mutants)
    original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])
    relay_rx: List[RelayRx] = []
    res = TwoPipeResult(relay_rx=relay_rx, original=original)

    # pre-confirm pipe-1 qid3 residency for this generation (the structural-guarantee precondition;
    # in silicon this is the qid3-resident flag set by a live blocker loop before the OPERATE holds)
    if scn.residency_ready:
        p1.confirm_residency(scn.gen)

    # 1) master OPERATE arrives fresh at pipe 0 -> record T0, T0-anchor, cross to pipe 1
    xf = p0.operate(scn.gen, scn.T0, relay_rx, original)

    # 2) each crossed copy is received by pipe 1 (there must be exactly one for a FRESH txn)
    for cross in p0.crossings:
        p1.receive_xpipe(cross, scn.j_index, scn.app_seq, relay_rx, scn.readiness_policy)

    # 3) an exact TCP retransmit of the OPERATE arrives at pipe 0 while it is held
    if scn.retransmit:
        xf2 = p0.operate(scn.gen, scn.T0 + 0.05, relay_rx, original)
        if xf2 is not None:
            p1.receive_xpipe(xf2, scn.j_index, scn.app_seq, relay_rx, scn.readiness_policy)

    # 4) qid3 drains at T0+J -> pipe 1 releases the held OPERATE exactly once
    p1.drain_release(relay_rx)

    # 5) pipe 0 T0-anchored ACK/echo release instants (independent of J)
    res.ack_time = p0.ack_release_time(scn.gen)
    res.echo_time = p0.echo_release_time()
    res.crossings = len(p0.crossings)

    # byte-identity of whatever the relay actually received (xpipe stripped at pipe 1)
    if relay_rx:
        res.released_bytes = relay_rx[0].payload
        res.byte_identical = (relay_rx[0].payload == original)
    return res


# =========================================================================================== #
# conformance
# =========================================================================================== #
def run_conformance(mutants: frozenset = frozenset()) -> Dict[str, bool]:
    cfg = BORConfig()
    checks: Dict[str, bool] = {}

    # nominal: exactly one cross, exactly one relay reception, via pipe-1 hold-release
    r = run_two_pipe(Scenario(), cfg, mutants)
    checks["cross_pipe_exactly_once"] = (r.crossings == 1)
    checks["relay_receives_exactly_once"] = (len(r.relay_rx) == 1)
    checks["released_via_pipe1_hold"] = (len(r.relay_rx) == 1
                                         and r.relay_rx[0].leg == "pipe1_hold_release")
    checks["released_byte_identical"] = r.byte_identical
    # release happens at T0+J on pipe 1 (J = codebook[5] = 10 on the clean model)
    j = float(cfg.codebook[Scenario().j_index])
    checks["release_at_T0_plus_J"] = (len(r.relay_rx) == 1
                                      and abs(r.relay_rx[0].time - (Scenario().T0 + j)) < EPS)
    # T0-anchoring: ACK@T0+A, echo@T0+R (pipe 0, recorded T0), INDEPENDENT of J
    checks["ack_echo_T0_anchored"] = (
        r.ack_time is not None and abs(r.ack_time - (Scenario().T0 + cfg.A)) < EPS
        and r.echo_time is not None and abs(r.echo_time - (Scenario().T0 + cfg.R)) < EPS)

    # exactly-once UNDER RETRANSMIT across the cross-pipe handoff: pipe 0 drops the dup, so still
    # exactly one cross and exactly one relay reception
    rt = run_two_pipe(Scenario(retransmit=True), cfg, mutants)
    checks["retransmit_still_one_cross"] = (rt.crossings == 1)
    checks["retransmit_still_one_relay_rx"] = (len(rt.relay_rx) == 1)

    # readiness NOT confirmed -> pipe 1 fails open WITHOUT holding: forwarded once, no hold-release
    fo = run_two_pipe(Scenario(residency_ready=False), cfg, mutants)
    checks["fail_open_forwards_once"] = (len(fo.relay_rx) == 1
                                         and fo.relay_rx[0].leg == "pipe1_fail_open")

    # no shared-register assumption: T0 used by pipe 1 came from the packet header (xf.t0), and
    # the release time equals header-T0 + J. (Modeled structurally: Pipe1 never reads Pipe0 state.)
    checks["t0_travels_in_header"] = (len(r.relay_rx) == 1
                                      and abs(r.relay_rx[0].time - (Scenario().T0 + j)) < EPS)
    return checks


MUTANTS: List[Tuple[str, str]] = [
    ("pipe0_no_dup_drop",
     "pipe 0 fails to suppress a retransmit and crosses it AGAIN -> a redundant cross-pipe "
     "transmission. NOTE: relay exactly-once still HOLDS here because pipe 1 independently "
     "dedups the same-generation re-cross (V_OP_DUP -> drop) — defense in depth. The observable "
     "defect is the extra cross, which this mutant is caught by."),
    ("pipe0_cross_twice",
     "pipe 0 routes two copies of the fresh OPERATE -> double release"),
    ("pipe1_duplicate_release",
     "pipe 1 releases the held OPERATE twice -> two physical operations"),
    ("reanchor_ack_to_release",
     "pipe 0 re-anchors the ACK to T0+J -> response-timing leak of J (anti-subtraction)"),
]

# each mutant + the check it MUST break
EXPECT_BREAKS: Dict[str, str] = {
    "pipe0_no_dup_drop": "retransmit_still_one_cross",   # pipe-1 dedup backstops the relay count
    "pipe0_cross_twice": "cross_pipe_exactly_once",
    "pipe1_duplicate_release": "relay_receives_exactly_once",
    "reanchor_ack_to_release": "ack_echo_T0_anchored",
}


def main() -> int:
    clean = run_conformance(frozenset())
    print("== CLEAN MODEL (two-pipe BOR split lifecycle) ==")
    for k, v in clean.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    clean_ok = all(clean.values())

    print("\n== MUTANTS (each MUST be KILLED: its expected invariant check flips to FAIL) ==")
    killed = {}
    for name, desc in MUTANTS:
        c = run_conformance(frozenset([name]))
        failed = [k for k, val in c.items() if not val]
        expect = EXPECT_BREAKS[name]
        killed[name] = (expect in failed)
        print("  [%s] %-26s expect_break=%-30s actual_failed=%s"
              % ("KILLED" if killed[name] else "SURVIVED", name, expect, failed or "NONE"))
        print("           %s" % desc)

    ok = clean_ok and all(killed.values())
    print("\nRESULT: %s  (clean=%s, mutants_killed=%d/%d)"
          % ("PASS" if ok else "FAIL", clean_ok, sum(killed.values()), len(MUTANTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
