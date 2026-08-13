#!/usr/bin/env python3
"""FAITHFUL two-pipe BOR lifecycle model (BOR_RRC_DESIGN.md section 3, "Faithful readiness —
SELECT prepares a BOR epoch", split across TWO Tofino-1 pipes).

The sibling model bor_twopipe_emulator.py proves the two-pipe TOPOLOGY / cross-pipe handoff /
exactly-once, but it PRE-CONFIRMS pipe-1 qid3 residency before the OPERATE (the fail-open-first
resource-probe shortcut). THIS model proves the FAITHFUL readiness the P4 program
defense4_twopipe_pipe1_faithful_probe.p4 implements: the reservoir is prepared DURING the SELECT
so it is resident BEFORE the OPERATE, and the FIRST OPERATE is genuinely HELD and SHAPED (never
fail-opened). Nothing is pre-confirmed by fiat — residency is seeded by the SELECT-prepare crossing
and becomes true at an async fill time that precedes the OPERATE because SBO always SELECTs first.

  PIPE 0  = frozen RRC + T0-admission + the two cross-pipe crossings.
     * On the protected SELECT: allocate a FRESH BOR epoch (an internal monotonic id, NOT the
       4-bit DNP3 generation), cross a SELECT-PREPARE frame (carrying the epoch) to pipe 1, and
       keep RRC's own SELECT ACK/echo handling. (Pipe 1 forwards the SELECT to the relay.)
     * On the protected OPERATE: record T0, T0-ANCHOR reg_deadline=T0+A / reg_tresp=T0+R (so the
       relay ACK/echo, later FRESH packets back to pipe 0, are held T0-anchored and NEVER
       re-anchored to the delayed release), re-read the SAME epoch, and cross ONE OPERATE frame
       (epoch + T0 + gen) to pipe 1. A retransmit of a still-active OPERATE is a reg_tag duplicate
       and is DROPPED — it never crosses twice.
  PIPE 1  = the FAITHFUL BOR hold/release core, per-pipe state only (T0 + epoch arrive IN the
     packet, never a shared register):
     * SELECT-PREPARE -> reg_epoch := epoch (BOR_PENDING), reset reg_ready/reg_gen, SEED qid3 for
       that epoch (resident_at = t_select + t_pktgen_fill), forward the SELECT to the relay.
     * a live qid3 token (epoch-stamped) confirms residency (reg_ready := epoch) BEFORE the OPERATE.
     * OPERATE -> REQUIRE reg_epoch == epoch AND reg_ready == epoch, else FORWARD once + count
       (fail-open, never enqueue). On match: select a leak-safe J (epoch is NEVER the source of J),
       arm reg_topj = T0+J, hold the byte-identical original in qid2, release it to the relay
       EXACTLY ONCE at T0+J.
     * retransmit while held -> reg_gen dedup -> DROP. missing-OPERATE watchdog / release -> retire
       the epoch, so a later stray OPERATE (incl. a 4-bit DNP3 sequence WRAP with no fresh SELECT)
       fails open (the internal epoch identity gates the hold, never the public sequence).

GROUND TRUTH FOR EXACTLY-ONCE: `relay_rx` — every OPERATE the relay receives, with its leg. For one
protected OPERATE transaction (and its retransmits) len([r for r in relay_rx if r is an operate])
MUST be exactly 1.  `python3 bor_twopipe_faithful_emulator.py` runs the conformance asserts + kills
the design mutants. Pure stdlib; NOT silicon (a model is not a compile is not silicon)."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rrc_emulator import req_frame, resp_frame_49, FC_OPERATE, REQ_LEN          # noqa: E402
from bor_rrc_emulator import BORConfig, CODEBOOK, EPS                            # noqa: E402
from crc_split_emulator import CrcSplitEmulator, Pkt, POL_SPLIT, PORT_DNP3, CUT_28  # noqa: E402

GEN_INACTIVE = 0
EPOCH_NONE = 0


# ------------------------- cross-pipe frames (pipe 0 -> pipe 1) ------------------------- #
@dataclass
class XPipeFrame:
    """What pipe 0 emits toward pipe 1. kind='prepare' carries the crossed SELECT + the fresh
    epoch; kind='operate' carries the original OPERATE bytes + T0 + epoch + the DNP3 gen. The
    xpipe header (epoch/t0/orig_etype) is stripped on pipe 1 before the frame reaches the relay."""
    kind: str                # "prepare" | "operate"
    epoch: int               # the FRESH BOR epoch (internal id, NOT the DNP3 generation)
    t0: float
    gen: int                 # DNP3 generation (operate only)
    orig_bytes: bytes
    orig_etype: int = 0x0800


@dataclass
class RelayRx:
    """One frame the relay received, and which leg delivered it (exactly-once auditing)."""
    time: float
    payload: bytes
    kind: str                # "select_fwd" | "operate_hold_release" | "operate_fail_open"
                             #  | "operate_bypass" | "operate_source_copy"
    leg: str


def _is_operate_rx(r: RelayRx) -> bool:
    return r.kind.startswith("operate")


# --------------------------------- PIPE 0 (RRC + T0-admission) ------------------------------- #
class Pipe0:
    """RRC + T0-admission + the SELECT-prepare and OPERATE crossings. Per-pipe registers:
    reg_epoch (fresh-epoch allocator), reg_tag (active OPERATE gen), reg_deadline/reg_tresp
    (T0-anchored ACK/echo release words)."""

    def __init__(self, cfg: BORConfig, mutants: frozenset = frozenset()):
        self.cfg = cfg
        self.mutants = frozenset(mutants)
        self.reg_epoch = 0                       # monotonic internal epoch allocator
        self.reg_tag = GEN_INACTIVE              # active OPERATE generation
        self.reg_deadline: Optional[float] = None
        self.reg_tresp: Optional[float] = None
        self.crossings: List[XPipeFrame] = []    # every frame routed to pipe 1
        self.recorded_T0: Optional[float] = None
        self.last_epoch = 0                       # the last-allocated epoch (stamped on the OPERATE)

    # ---- SELECT admission: allocate a fresh epoch, cross a SELECT-prepare to pipe 1 -------
    def select(self, select_bytes: bytes, t_select: float) -> XPipeFrame:
        self.reg_epoch += 1
        self.last_epoch = self.reg_epoch
        xf = XPipeFrame(kind="prepare", epoch=self.last_epoch, t0=t_select, gen=0,
                        orig_bytes=select_bytes)
        self.crossings.append(xf)
        return xf

    def _classify(self, gen: int) -> str:
        if self.reg_tag == GEN_INACTIVE:
            return "FRESH"
        if self.reg_tag == gen:
            return "DUP"
        return "BUSY"

    # ---- OPERATE admission: T0-anchor, re-read the epoch, cross ONE OPERATE frame ---------
    def operate(self, gen: int, T0: float, relay_rx: List[RelayRx],
                original: bytes) -> Optional[XPipeFrame]:
        v = self._classify(gen)
        if v == "FRESH":
            self.reg_tag = gen
            self.recorded_T0 = T0
            self.reg_deadline = T0 + self.cfg.A          # T0-anchored (NEVER T0+J)
            self.reg_tresp = T0 + self.cfg.R
            epoch = self.last_epoch                      # the SAME epoch as the paired SELECT
            xf = XPipeFrame(kind="operate", epoch=epoch, t0=T0, gen=gen, orig_bytes=original)
            self.crossings.append(xf)
            if "pipe0_cross_twice" in self.mutants:
                self.crossings.append(xf)                # WRONG: two copies cross -> double release
            return xf
        if v == "DUP":
            if "pipe0_no_dup_drop" in self.mutants:
                dup = XPipeFrame(kind="operate", epoch=self.last_epoch, t0=T0, gen=gen,
                                 orig_bytes=original)
                self.crossings.append(dup)               # WRONG: cross the retransmit again
                return dup
            return None                                  # dropped: no second cross
        relay_rx.append(RelayRx(T0, original, "operate_bypass", "pipe0_bypass"))
        return None

    def ack_release_time(self) -> Optional[float]:
        if self.reg_deadline is None:
            return None
        if "reanchor_ack_to_release" in self.mutants:
            return self.recorded_T0 + max(self.cfg.codebook) + self.cfg.A   # leaks J
        return self.reg_deadline

    def echo_release_time(self) -> Optional[float]:
        return self.reg_tresp

    def retire(self):
        self.reg_tag = GEN_INACTIVE
        self.reg_deadline = None
        self.reg_tresp = None


# --------------------------------- PIPE 1 (FAITHFUL BOR core) --------------------------------- #
class Pipe1:
    """The FAITHFUL BOR hold/release core. Per-pipe registers: reg_epoch (BOR_PENDING), reg_ready
    (residency-confirmed epoch), reg_gen (DNP3-gen dedup), reg_topj (T0+J). qid3 residency is
    SEEDED by the SELECT-prepare and becomes true at an async fill time BEFORE the OPERATE."""

    def __init__(self, cfg: BORConfig, mutants: frozenset = frozenset()):
        self.cfg = cfg
        self.mutants = frozenset(mutants)
        self.reg_epoch = EPOCH_NONE
        self.reg_ready = EPOCH_NONE
        self.reg_gen = GEN_INACTIVE
        self.reg_topj: Optional[float] = None
        self.qid3_resident_at: Optional[float] = None     # async qid3 fill time for the epoch
        self.ready_seq: Optional[int] = None              # 4-bit seq at prep (only a mutant keys on it)
        # qid2 hold slots — a LIST so a double-cross that ESCAPES the dedup yields >1 release
        # (a single overwriting slot would hide the double-release the dedup exists to prevent).
        self.held: List[Tuple[float, int, int, bytes]] = []   # (t0, epoch, gen, bytes)
        self.released = 0

    # ---- leak-safe J: never derive from a public value or the epoch ----------------------
    def _select_j(self, j_index: int, app_seq: int) -> float:
        if "j_from_public_seq" in self.mutants:
            return float(self.cfg.codebook[app_seq % len(self.cfg.codebook)])
        return float(self.cfg.codebook[j_index])

    # ---- SELECT-prepare: create the epoch, seed qid3, forward the SELECT to the relay ------
    def receive_prepare(self, xf: XPipeFrame, relay_rx: List[RelayRx], app_seq: int,
                        reservoir_ready: bool) -> None:
        self.reg_epoch = xf.epoch                          # BOR_PENDING(epoch)
        self.reg_ready = EPOCH_NONE                        # a clean epoch: nothing confirmed yet
        self.reg_gen = GEN_INACTIVE
        self.ready_seq = app_seq & 0xF
        # SEED qid3 for this epoch; residency becomes true at an ASYNC fill time.
        if reservoir_ready and "ready_without_reservoir" not in self.mutants:
            self.qid3_resident_at = xf.t0 + self.cfg.t_pktgen_fill
        elif "ready_without_reservoir" in self.mutants:
            self.qid3_resident_at = None                   # CLAIM ready without a resident reservoir
            self.reg_ready = xf.epoch                       # ...(mutant asserts readiness anyway)
        else:
            self.qid3_resident_at = None                   # the SELECT-seeded burst never fills
        # forward the SELECT byte-identically to the relay (SBO needs it)
        relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "select_fwd", "pipe1_select_fwd"))

    # ---- a live qid3 token confirms residency for the current epoch (async, before OPERATE) --
    def confirm_residency_if_due(self, now: float) -> None:
        if (self.reg_epoch != EPOCH_NONE and self.qid3_resident_at is not None
                and self.qid3_resident_at <= now):
            self.reg_ready = self.reg_epoch

    # ---- OPERATE: require BOR_PENDING(epoch) AND residency, else fail open -----------------
    def receive_operate(self, xf: XPipeFrame, j_index: int, app_seq: int,
                        relay_rx: List[RelayRx]) -> None:
        # reg_gen dedup (defence in depth for a pipe-0 dup-drop miss / cross-pipe double-cross)
        if self.reg_gen != GEN_INACTIVE and self.reg_gen == xf.gen \
                and "pipe1_no_dedup" not in self.mutants:
            return                                          # retransmit / re-cross -> DROP
        if self.reg_gen == GEN_INACTIVE:
            self.reg_gen = xf.gen                           # arm dedup (fresh OPERATE)
        matched = (self.reg_epoch != EPOCH_NONE and self.reg_epoch == xf.epoch)
        ready = (self.reg_ready != EPOCH_NONE and self.reg_ready == xf.epoch)
        if "hold_when_reservoir_not_ready" in self.mutants:
            matched = ready = True                          # hold regardless (should fail open)
        if not (matched and ready):
            # FAIL OPEN WITHOUT HOLDING: forward once + count. Never enqueue on a stale flag.
            relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "operate_fail_open", "pipe1_fail_open"))
            return
        # commit the shaped hold: strip xpipe (byte-identical original) into qid2
        j = self._select_j(j_index, app_seq)
        self.reg_topj = xf.t0 + j
        self.held.append((xf.t0, xf.epoch, xf.gen, xf.orig_bytes))   # a NEW qid2 hold slot
        if "source_copy_leaks_to_relay" in self.mutants:
            relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "operate_source_copy", "pipe1_ingress"))

    # ---- qid3 drains at T0+J -> release EACH held OPERATE (exactly one in the clean model) ---
    def drain_release(self, relay_rx: List[RelayRx]) -> None:
        if not self.held:
            return
        for (t0, epoch, gen, payload) in self.held:
            assert self.reg_topj is not None
            t_release = self.reg_topj
            relay_rx.append(RelayRx(t_release, payload, "operate_hold_release", "pipe1_hold_release"))
            self.released += 1
            if "pipe1_duplicate_release" in self.mutants:
                relay_rx.append(RelayRx(t_release, payload, "operate_hold_release", "pipe1_hold_release"))
        self.held = []
        self._retire()                                      # retire on release

    # ---- retire the epoch (clear BOR_PENDING/ready/gen) so a stray OPERATE fails open ------
    def _retire(self) -> None:
        self.reg_topj = None
        if "stale_ready_after_seq_wrap" in self.mutants:
            # BUG: keep a public-4-bit-seq key so a wrapped seq revalidates stale readiness
            self.reg_epoch = EPOCH_NONE
            self.reg_ready = EPOCH_NONE
            self.reg_gen = GEN_INACTIVE
            # ready_seq deliberately RETAINED (the defect)
            return
        self.reg_epoch = EPOCH_NONE
        self.reg_ready = EPOCH_NONE
        self.reg_gen = GEN_INACTIVE
        self.ready_seq = None

    # ---- missing-OPERATE watchdog: the reservoir drains, epoch retired (no output) ---------
    def watchdog_retire(self) -> None:
        if "watchdog_no_retire" in self.mutants:
            return
        self._retire()

    # ---- a stray OPERATE with NO fresh SELECT: fail open unless a stale-ready mutant lets it in
    def stray_operate(self, xf: XPipeFrame, j_index: int, app_seq: int,
                      relay_rx: List[RelayRx]) -> None:
        pending = (self.reg_epoch != EPOCH_NONE and self.reg_epoch == xf.epoch)
        ready = (self.reg_ready != EPOCH_NONE and self.reg_ready == xf.epoch)
        if ("stale_ready_after_seq_wrap" in self.mutants and self.ready_seq is not None
                and self.ready_seq == (app_seq & 0xF)):
            pending = ready = True                          # BUG: a 4-bit wrap revalidates
        if not (pending and ready):
            relay_rx.append(RelayRx(xf.t0, xf.orig_bytes, "operate_fail_open", "pipe1_fail_open"))
            return
        j = self._select_j(j_index, app_seq)
        self.reg_topj = xf.t0 + j
        self.held.append((xf.t0, xf.epoch, xf.gen, xf.orig_bytes))


# ------------------------------------- carve helper (pipe 0) --------------------------------- #
def carve_echo(owner: Tuple[int, int, int, int], flavour: int) -> Tuple[Tuple[int, ...], bytes, bool]:
    split = CrcSplitEmulator(owner, POL_SPLIT, CUT_28)
    echo = resp_frame_49(flavour)
    r = split.process(Pkt(owner[1], owner[0], PORT_DNP3, owner[2], seq=500, ack=1, payload=echo))
    segs = tuple(len(s.payload) for s in r.segs)
    joined = b"".join(s.payload for s in r.segs)
    csum_ok = all(s.ipv4_ok and s.tcp_ok for s in r.segs)
    return segs, joined, csum_ok


# ------------------------------------- the joined lifecycle ---------------------------------- #
OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)


@dataclass
class Scenario:
    gen: int = 0xC1                 # the OPERATE's DNP3 generation
    T0: float = 1000.0              # the OPERATE's ingress MAC timestamp
    j_index: int = 5                # the leak-safe secret codebook index
    app_seq: int = 3                # the public DNP3 app sequence (4-bit)
    select_lead: float = 100.0      # SELECT-admitted-to-OPERATE wall gap (>> t_pktgen_fill)
    reservoir_ready: bool = True    # did the SELECT-seeded qid3 burst fill?
    retransmit: bool = False        # an exact retransmit arrives at pipe 0 while the OP is held
    first_operate_fail_open: bool = False   # force the SR4 read-before-arm defect (no SELECT prep)
    force_double_cross: bool = False        # pipe 0 crosses the fresh OPERATE TWICE (backstop test)


@dataclass
class TwoPipeResult:
    relay_rx: List[RelayRx] = field(default_factory=list)
    crossings: int = 0
    prepare_crossings: int = 0
    operate_crossings: int = 0
    first_operate_shaped: bool = False
    fail_open: bool = False
    ack_time: Optional[float] = None
    echo_time: Optional[float] = None
    echo_segments: Tuple[int, ...] = ()
    echo_reassembled: Optional[bytes] = None
    echo_csum_ok: bool = False
    released_bytes: Optional[bytes] = None
    byte_identical: bool = False
    original: bytes = b""
    epoch_resident_before_operate: bool = False


def run_two_pipe(scn: Scenario, cfg: BORConfig = BORConfig(),
                 mutants: frozenset = frozenset()) -> TwoPipeResult:
    p0 = Pipe0(cfg, mutants)
    p1 = Pipe1(cfg, mutants)
    original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])
    select_bytes = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])   # a SELECT frame (same shape family)
    relay_rx: List[RelayRx] = []
    res = TwoPipeResult(relay_rx=relay_rx, original=original)

    t_select = scn.T0 - scn.select_lead

    # 1) SELECT: pipe 0 allocates a fresh epoch and crosses a SELECT-PREPARE to pipe 1.
    #    In the SR4 (fail-open-first) mode, NO SELECT-prepare happens (the OPERATE arms the
    #    reservoir), so the reservoir is never resident before the OPERATE.
    if not scn.first_operate_fail_open:
        xprep = p0.select(select_bytes, t_select)
        p1.receive_prepare(xprep, relay_rx, scn.app_seq, scn.reservoir_ready)
        # 2) the SELECT-seeded qid3 tokens confirm residency (async) BEFORE the OPERATE at T0
        p1.confirm_residency_if_due(scn.T0)

    res.epoch_resident_before_operate = (p1.reg_ready != EPOCH_NONE)

    # 3) OPERATE: pipe 0 T0-anchors + crosses ONE OPERATE frame; pipe 1 holds it (first try).
    xf = p0.operate(scn.gen, scn.T0, relay_rx, original)
    if scn.force_double_cross and xf is not None:
        p0.crossings.append(xf)                       # force a cross-pipe DOUBLE-CROSS (backstop)
    for cross in [c for c in p0.crossings if c.kind == "operate"]:
        p1.receive_operate(cross, scn.j_index, scn.app_seq, relay_rx)

    # 4) an exact TCP retransmit of the OPERATE arrives at pipe 0 while it is held
    if scn.retransmit:
        before = len(p0.crossings)
        xf2 = p0.operate(scn.gen, scn.T0 + 0.05, relay_rx, original)
        for cross in p0.crossings[before:]:
            if cross.kind == "operate":
                p1.receive_operate(cross, scn.j_index, scn.app_seq, relay_rx)

    # 5) qid3 drains at T0+J -> pipe 1 releases the held OPERATE exactly once
    p1.drain_release(relay_rx)

    # 6) pipe 0 T0-anchored ACK/echo release instants (independent of J) + the [28,21] carve
    res.ack_time = p0.ack_release_time()
    res.echo_time = p0.echo_release_time()
    segs, joined, csum_ok = carve_echo(OWNER, scn.app_seq % 251 + 1)
    res.echo_segments, res.echo_reassembled, res.echo_csum_ok = segs, joined, csum_ok

    res.prepare_crossings = len([c for c in p0.crossings if c.kind == "prepare"])
    res.operate_crossings = len([c for c in p0.crossings if c.kind == "operate"])
    res.crossings = len(p0.crossings)
    op_rx = [r for r in relay_rx if _is_operate_rx(r)]
    res.first_operate_shaped = any(r.kind == "operate_hold_release" for r in op_rx)
    res.fail_open = any(r.kind == "operate_fail_open" for r in op_rx)
    if op_rx:
        rel = [r for r in op_rx if r.kind == "operate_hold_release"]
        pick = rel[0] if rel else op_rx[0]
        res.released_bytes = pick.payload
        res.byte_identical = (pick.payload == original)
    return res


# =========================================================================================== #
# conformance
# =========================================================================================== #
def _operate_rx(relay_rx: List[RelayRx]) -> List[RelayRx]:
    return [r for r in relay_rx if _is_operate_rx(r)]


def run_conformance(mutants: frozenset = frozenset()) -> Dict[str, bool]:
    cfg = BORConfig()
    checks: Dict[str, bool] = {}
    j = float(cfg.codebook[Scenario().j_index])

    # nominal: SELECT-prepare crosses, epoch resident BEFORE the OPERATE, first OPERATE shaped
    r = run_two_pipe(Scenario(), cfg, mutants)
    checks["select_prepare_crosses_once"] = (r.prepare_crossings == 1)
    checks["epoch_resident_before_operate"] = r.epoch_resident_before_operate
    checks["first_operate_shaped"] = (r.first_operate_shaped and not r.fail_open)
    checks["cross_pipe_operate_exactly_once"] = (r.operate_crossings == 1)
    checks["relay_receives_operate_exactly_once"] = (len(_operate_rx(r.relay_rx)) == 1)
    checks["released_via_pipe1_hold"] = (len(_operate_rx(r.relay_rx)) == 1
                                         and _operate_rx(r.relay_rx)[0].kind == "operate_hold_release")
    checks["released_byte_identical"] = r.byte_identical
    checks["release_at_T0_plus_J"] = (len(_operate_rx(r.relay_rx)) == 1
                                      and abs(_operate_rx(r.relay_rx)[0].time - (Scenario().T0 + j)) < EPS)
    # T0-anchoring: ACK@T0+A, echo@T0+R (pipe 0), INDEPENDENT of J
    checks["ack_echo_T0_anchored"] = (
        r.ack_time is not None and abs(r.ack_time - (Scenario().T0 + cfg.A)) < EPS
        and r.echo_time is not None and abs(r.echo_time - (Scenario().T0 + cfg.R)) < EPS)
    # the 49 B echo carved [28,21], byte-identical, valid checksums
    checks["echo_carved_28_21"] = (r.echo_segments == (28, 21))
    checks["echo_byte_identical"] = (r.echo_reassembled == resp_frame_49(Scenario().app_seq % 251 + 1)
                                     and r.echo_csum_ok)
    checks["no_source_copy_to_relay"] = not any(rr.kind == "operate_source_copy" for rr in r.relay_rx)

    # exactly-once UNDER RETRANSMIT (pipe 0 drops the dup; pipe 1 dedups a re-cross as backstop)
    rt = run_two_pipe(Scenario(retransmit=True), cfg, mutants)
    checks["retransmit_operate_crosses_once"] = (rt.operate_crossings == 1)
    checks["retransmit_relay_operate_once"] = (len(_operate_rx(rt.relay_rx)) == 1)

    # cross-pipe DOUBLE-CROSS: pipe 0 emits two copies of the fresh OPERATE; pipe 1's reg_gen
    # dedup is the BACKSTOP, so the relay still receives it EXACTLY ONCE (pipe1_no_dedup breaks it).
    dc = run_two_pipe(Scenario(force_double_cross=True), cfg, mutants)
    checks["double_cross_backstopped_by_pipe1_dedup"] = (len(_operate_rx(dc.relay_rx)) == 1)

    # readiness NOT confirmed -> pipe 1 fails open WITHOUT holding
    fo = run_two_pipe(Scenario(reservoir_ready=False), cfg, mutants)
    checks["fail_open_when_reservoir_not_ready"] = (
        len(_operate_rx(fo.relay_rx)) == 1
        and _operate_rx(fo.relay_rx)[0].kind == "operate_fail_open" and not fo.first_operate_shaped)

    return checks


def run_first_operate_discrimination(mutants: frozenset = frozenset()) -> Tuple[bool, bool]:
    """FAITHFUL select-prepared -> first OPERATE shaped=True; SR4 fail-open-first -> shaped=False."""
    faithful = run_two_pipe(Scenario(), BORConfig(), mutants)
    sr4 = run_two_pipe(Scenario(first_operate_fail_open=True), BORConfig(), mutants)
    return (faithful.first_operate_shaped and not faithful.fail_open,
            sr4.first_operate_shaped)


def run_seq_wrap_stray(mutants: frozenset = frozenset()) -> bool:
    """SELECT+OPERATE at seq 3 completes+retires; a later stray OPERATE at a WRAPPED seq (19->3)
    with NO fresh SELECT must FAIL OPEN (the internal epoch gates it, not the 4-bit sequence)."""
    cfg = BORConfig()
    p0 = Pipe0(cfg, mutants)
    p1 = Pipe1(cfg, mutants)
    relay_rx: List[RelayRx] = []
    original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])
    # full transaction at seq 3
    xprep = p0.select(original, 900.0)
    p1.receive_prepare(xprep, relay_rx, 3, True)
    p1.confirm_residency_if_due(1000.0)
    xf = p0.operate(0xC3, 1000.0, relay_rx, original)
    for c in [c for c in p0.crossings if c.kind == "operate"]:
        p1.receive_operate(c, 5, 3, relay_rx)
    p1.drain_release(relay_rx)
    p0.retire()
    # a stray OPERATE at wrapped seq 19->3 with NO fresh SELECT (pipe 0 stamps the last epoch)
    stray_rx: List[RelayRx] = []
    stray = XPipeFrame(kind="operate", epoch=p0.last_epoch, t0=2000.0, gen=0xC9, orig_bytes=original)
    p1.stray_operate(stray, 4, 19, stray_rx)
    p1.drain_release(stray_rx)
    op_rx = _operate_rx(stray_rx)
    return (len(op_rx) == 1 and op_rx[0].kind == "operate_fail_open")


# each REQUIRED mutant + the check it MUST break
MUTANTS: List[Tuple[str, str, str]] = [
    ("first_operate_fail_open_mode", "first_operate_shaped",
     "SR4 read-before-arm: no SELECT-prepare -> the FIRST OPERATE fails open, unshaped"),
    ("pipe0_cross_twice", "cross_pipe_operate_exactly_once",
     "pipe 0 routes two copies of the fresh OPERATE -> double release"),
    ("pipe1_duplicate_release", "relay_receives_operate_exactly_once",
     "pipe 1 releases the held OPERATE twice -> two physical operations"),
    ("pipe1_no_dedup", "double_cross_backstopped_by_pipe1_dedup",
     "pipe 1 fails to dedup a cross-pipe double-cross -> a second release reaches the relay"),
    ("hold_when_reservoir_not_ready", "fail_open_when_reservoir_not_ready",
     "qid3 not resident but OPERATE held anyway -> should fail open, not hold"),
    ("stale_ready_after_seq_wrap", "seq_wrap_stray_fails_open",
     "a 4-bit DNP3 sequence wrap revalidates stale readiness (no fresh SELECT)"),
    ("source_copy_leaks_to_relay", "no_source_copy_to_relay",
     "a source copy of the OPERATE leaks to the relay -> a second physical operation"),
    ("reanchor_ack_to_release", "ack_echo_T0_anchored",
     "pipe 0 re-anchors the ACK to T0+J -> response-timing leak of J"),
]

EXPECT_BREAKS: Dict[str, str] = {name: expect for name, expect, _ in MUTANTS}


def main() -> int:
    clean = run_conformance(frozenset())
    faithful_ok, sr4_shaped = run_first_operate_discrimination()
    wrap_ok = run_seq_wrap_stray()
    print("== FAITHFUL TWO-PIPE MODEL (SELECT prepares a BOR epoch) ==")
    for k, v in clean.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    print("  [%s] seq_wrap_stray_fails_open (%s)" % ("PASS" if wrap_ok else "FAIL", wrap_ok))
    clean_ok = all(clean.values()) and wrap_ok

    print("\n== FIRST-OPERATE DISCRIMINATION (faithful shapes; SR4 fail-open-first does NOT) ==")
    print("  [%s] first_operate_shaped(faithful select-prepared) = %s"
          % ("PASS" if faithful_ok else "FAIL", faithful_ok))
    print("  [%s] first_operate_shaped(SR4 fail-open-first)       = %s  (check correctly FAILS)"
          % ("PASS" if not sr4_shaped else "FAIL", sr4_shaped))
    disc_ok = faithful_ok and not sr4_shaped

    print("\n== MUTANTS (each MUST be KILLED: its expected invariant check flips to FAIL) ==")
    killed = {}
    for name, expect, desc in MUTANTS:
        if name == "first_operate_fail_open_mode":
            # this mutant is a scenario mode, not a state-mutation flag
            f_ok, _ = run_first_operate_discrimination()
            r_sr4 = run_two_pipe(Scenario(first_operate_fail_open=True))
            killed[name] = (not r_sr4.first_operate_shaped)
            failed = ["first_operate_shaped"] if killed[name] else []
        else:
            c = dict(run_conformance(frozenset([name])))
            c["seq_wrap_stray_fails_open"] = run_seq_wrap_stray(frozenset([name]))
            failed = [k for k, v in c.items() if not v]
            killed[name] = (expect in failed)
        print("  [%s] %-30s expect_break=%-38s" % ("KILLED" if killed[name] else "SURVIVED",
                                                    name, expect))
        print("           %s" % desc)
        print("           actual_failed=%s" % (failed or "NONE (mutant undetected)"))

    ok = clean_ok and disc_ok and all(killed.values())
    print("\nRESULT: %s  (clean=%s, discrimination=%s, mutants_killed=%d/%d)"
          % ("PASS" if ok else "FAIL", clean_ok, disc_ok, sum(killed.values()), len(MUTANTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
