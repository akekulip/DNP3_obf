#!/usr/bin/env python3
"""Behavioral emulator of the FAITHFUL BOR-in-RRC lifecycle (BOR_RRC_DESIGN.md section 3,
"Faithful readiness — SELECT prepares a BOR epoch") — Bounded OPERATE Release run as the
OPERATE-request phase of the RRC transaction engine, plus a passive UPSTREAM observer used to
prove the anti-subtraction invariant offline.

WHY THIS REWRITE. The current SR4 P4 probe is NOT faithful BOR. It reads an `op_ready` flag on
the OPERATE *before* it arms the qid3 blocker burst, so the FIRST real OPERATE always reads 0,
FAILS OPEN (forwards unshaped), then arms qid3 asynchronously; an exact retransmit is
duplicate-suppressed. That is *safe bypass*, NOT *successful shaping* — the SR4 stage number is a
RESOURCE PROBE (it answers "does the reservoir machinery fit / arm", nothing about hiding J on
the first OPERATE). It also never clears `op_ready`, so a 4-bit DNP3 sequence wrap can revalidate
a stale ready value. This emulator models the SR4 defect AND the faithful mechanism that fixes it,
and it separates "safe bypass" from "successful shaping" everywhere.

THE FAITHFUL MECHANISM (SELECT prepares a BOR epoch). SBO always sends SELECT before OPERATE, so
the reservoir is prepared during SELECT and the OPERATE is held on its FIRST try:

  * SELECT admitted        -> create a BOR EPOCH (a SEPARATE internal preparation identity, NOT
                             the 4-bit DNP3 generation, since SELECT and OPERATE are independent
                             DNP3 transactions); seed qid3 for that epoch; confirm qid3 residency;
                             retain BOR_PENDING(epoch) across SELECT completion.
  * OPERATE arrives at T0   -> REQUIRE matching BOR_PENDING(epoch) AND confirmed residency, else
                             forward IMMEDIATELY at T0 + increment a failure counter (never
                             enqueue on a stale flag). On match: select a LEAK-SAFE J (Random<T> /
                             bounded selector -- the epoch is NEVER the source of J); arm T0+J,
                             T0+A, T0+R; enqueue the ORIGINAL OPERATE into qid2; qid3 blocks qid2
                             until T0+J; release the original byte-identically EXACTLY ONCE to dp64.
  * ACK, echo arrive later  -> release at ABSOLUTE T0+A, T0+R (never re-anchored to the delayed
                             T0+J release); carve the 49 B echo [28,21]; retire the BOR epoch.

THE ASYNC EVENT ORDER (BOR_RRC_DESIGN.md READINESS RACE). An OPERATE-armed design runs, in
discrete steps: original OPERATE ingress -> register reads/writes -> clone trigger -> asynchronous
pktgen generation -> token ingress -> qid3 residency -> qid2 eligibility -> deadline drain ->
original OPERATE release. Because pktgen tokens arrive at a LATER TM event, the reservoir becomes
resident at an ASYNC time AFTER the OPERATE. The faithful design prepares the reservoir at SELECT
so it is resident BEFORE the OPERATE -- there is NO async gap to bridge, and NO magic buffer is
needed (a held packet lives only in the real qid2 queue, gated by the already-resident qid3).

THE SECURITY PROPERTY (BOR_RRC_DESIGN.md section 2). A passive upstream observer measures
`M = T_SER_event - T_OPERATE_observed = J + T_physical`. Anti-subtraction HOLDS iff the observer
CANNOT recover J from any channel, so M stays an inseparable blob and the native device
fingerprint T_physical is hidden. Channels: (a) response timing J=(echo-operate)-R (T0-anchoring
with constant R -> 0); (b) TCP TSval, stamped at the relay's receive of the released OPERATE
(~T0+J) -> the MVP requires a no-TCP-timestamp protected flow; (c) the public DNP3 app sequence
(J must never be derived from it).

WHAT IS NOT DONE. A combined build that fuses (i) SELECT-prepared readiness and (ii) a leak-safe
random J selector has NOT yet been compiled on bf-p4c -- that is the P4 agent's job; this file
only models the intended behavior and detects the SR4 defect. A behavioral model is not a compile,
and a compile is not silicon; the physical divergence floor needs an authorized physical campaign.

`python3 bor_rrc_emulator.py` runs the conformance asserts on the faithful model, the async
readiness demonstration, the 1000-transaction + sequence-wrap drivers, and confirms every design
mutant is killed. Pure stdlib.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crc_split_emulator import (  # noqa: E402
    CrcSplitEmulator, Pkt, POL_SPLIT, PORT_DNP3, CUT_28,
)
from rrc_emulator import resp_frame_49, req_frame, FC_OPERATE, REQ_LEN  # noqa: E402

# ---- bounded delay codebook + deadline totals (BOR_RRC_DESIGN.md sections 1, 7) ----------
CODEBOOK = (0, 2, 4, 6, 8, 10, 12)     # J in ms; J_max = 12
EPS = 1e-6

# readiness models (BOR_RRC_DESIGN.md section 3)
RM_SELECT_PREPARED = "select_prepared"     # FAITHFUL: SELECT seeds+confirms qid3 before OPERATE
RM_OPERATE_ARMED_SR4 = "operate_armed_sr4"  # the current SR4 probe: read op_ready BEFORE arming


@dataclass(frozen=True)
class BORConfig:
    """Control-plane parameters. `deadlines_valid()` is the pre-install admissibility gate;
    a bad set is REJECTED, never silently defaulted (BOR_RRC_DESIGN.md section 1)."""
    codebook: Tuple[int, ...] = CODEBOOK
    A: float = 16.0                    # ACK release total from T0
    R: float = 20.0                    # echo release total from T0
    native_ack_bound: float = 2.0      # relay's worst-case native ACK latency
    native_resp_bound: float = 3.0     # relay's worst-case native response latency
    native_ack: float = 1.0            # relay's actual native ACK latency (for the SER model)
    native_resp: float = 2.0
    watchdog_horizon: float = 50.0     # bounded qid3 watchdog / fail-open horizon
    tcp_ts_enabled: bool = False       # did the protected flow negotiate TCP timestamps?
    # ---- qid3 readiness (BOR_RRC_DESIGN.md READINESS RACE) -------------------------------
    t_pktgen_fill: float = 0.408       # ASYNC qid3 burst fill latency (resident_at = t_arm + this)
    t_qid2_drain: float = 0.0          # qid2 drain latency after the OPERATE is enqueued
    readiness_model: str = RM_SELECT_PREPARED   # FAITHFUL default; RM_OPERATE_ARMED_SR4 = SR4 probe

    @property
    def j_max(self) -> int:
        return max(self.codebook)

    def deadlines_valid(self) -> bool:
        return (self.A > self.j_max + self.native_ack_bound
                and self.R > self.j_max + self.native_resp_bound
                and self.R >= self.A
                and max(self.A, self.R, self.j_max) < self.watchdog_horizon)


@dataclass
class Scenario:
    """One SELECT->OPERATE lifecycle instance. `T0` is the OPERATE's ingress MAC timestamp;
    `select_lead` is the wall gap from SELECT admission to the OPERATE (SBO always SELECTs first),
    so the SELECT-prepared reservoir is resident well before T0."""
    T0: float
    j_index: int                       # the leak-safe secret index into the codebook
    app_seq: int = 0                   # PUBLIC DNP3 app sequence (an observer sees this; 4-bit)
    t_physical: float = 5.0            # the device's native actuation time (the fingerprint)
    select_lead: float = 100.0         # SELECT-admitted-to-OPERATE wall gap (> t_pktgen_fill)
    select_admitted: bool = True
    select_ok: bool = True
    operate_arrives: bool = True
    reservoir_ready: bool = True       # did the SELECT-seeded qid3 burst actually fill?
    retransmit: bool = False           # an exact TCP retransmit arrives while OPERATE is held


@dataclass
class ObservableStream:
    """Exactly what a passive UPSTREAM (WAN-side) observer records for one transaction."""
    operate_time: float                # T0: OPERATE command observed toward the switch
    ack_time: Optional[float]          # pure ACK observed back to the master (T0 + A)
    echo_time: Optional[float]         # OPERATE echo observed back to the master (T0 + R)
    echo_segments: Tuple[int, ...]     # the echo's segment-length vector, [28, 21]
    ser_event_ts: Optional[float]      # SER report EMBEDDED timestamp = T0 + J + T_physical
    tcp_ts_present: bool               # were TCP timestamps negotiated on the protected flow?
    ack_tsval: Optional[float]         # if present, the relay's receive time of released OP (~T0+J)
    app_seq: int                       # the public DNP3 app sequence
    codebook: Tuple[int, ...]          # the PUBLIC delay codebook (Kerckhoffs)
    R: float                           # the PUBLIC design constant echo offset


@dataclass
class LifecycleResult:
    phases: List[str] = field(default_factory=list)
    event_order: List[str] = field(default_factory=list)   # the discrete async step trace
    bor_epoch: Optional[int] = None              # the SELECT-created internal epoch (NOT DNP3 gen)
    first_operate: bool = False                  # was this the first OPERATE on a clean-start engine
    reservoir_seeded: bool = False               # qid3 seeded (at SELECT, faithful)
    reservoir_resident: bool = False             # qid3 confirmed resident and the hold committed
    ready_flag_set: bool = False                 # the readiness flag was asserted
    qid3_actually_resident: bool = False         # the reservoir was TRULY resident (vs a claim)
    qid3_resident_at: Optional[float] = None     # the (async) time qid3 became resident
    magic_buffer_used: bool = False              # claimed to hold with NO hardware storage path
    operate_release_shaped: bool = False         # the release was actually shaped by J
    # INVARIANT: the qid3 blocker was resident before the held OPERATE released (no early escape).
    reservoir_resident_before_release: bool = True
    recorded_T0: Optional[float] = None
    J: Optional[float] = None
    fail_open: bool = False
    op_failure_count_delta: int = 0              # OPERATE-without-prepared-epoch failures counted
    operate_releases: List[Tuple[float, bytes]] = field(default_factory=list)  # (time, bytes)->dp64
    source_copies_to_relay: List[Tuple[float, bytes]] = field(default_factory=list)  # LEAKED copies
    original_operate: bytes = b""
    ack_time: Optional[float] = None
    echo_time: Optional[float] = None
    echo_segments: Tuple[int, ...] = ()
    echo_reassembled: Optional[bytes] = None
    echo_checksums_ok: bool = False
    retire_count: int = 0
    watchdog_retired: bool = False
    observable: Optional[ObservableStream] = None


# --------------------------------------------------------------------------- #
# the integrated engine (one connection, one OPERATE transaction, one T0)
# --------------------------------------------------------------------------- #
class BORRRCEngine:
    def __init__(self, owner: Tuple[int, int, int, int], config: BORConfig = BORConfig(),
                 mutants: frozenset = frozenset()):
        self.owner = owner                 # normalized response-direction (nm_ip, nr_ip, nm_pt, nr_pt)
        self.cfg = config
        self.mutants = frozenset(mutants)
        self.split = CrcSplitEmulator(owner, POL_SPLIT, CUT_28)
        # ---- BOR epoch state (persists across SELECT completion, until retire) -----------
        self._epoch_counter = 0
        self.bor_epoch: Optional[int] = None
        self.bor_pending = False           # a prepared, not-yet-consumed BOR epoch exists
        self.qid3_resident = False         # the reservoir is TRULY resident for that epoch
        self.ready_flag = False            # the readiness flag (should track qid3_resident)
        self.ready_seq: Optional[int] = None   # the 4-bit seq at prep (only a mutant keys on this)
        self._qid3_resident_at: Optional[float] = None
        self._first_operate_done = False
        self.op_failure_count = 0          # OPERATE-without-live-epoch failures (fail-open count)

    # ---- leak-safe delay selection (section 7): NEVER derive J from a public value --------
    def _select_j_index(self, scn: Scenario) -> int:
        if "public_sequence_selects_j" in self.mutants:
            return scn.app_seq % len(self.cfg.codebook)   # WRONG: predictable from the wire
        return scn.j_index                                 # secret-salt / random extern source

    def _readiness_model(self) -> str:
        if "first_operate_always_fail_open" in self.mutants:
            return RM_OPERATE_ARMED_SR4            # force the SR4 read-before-arm defect
        return self.cfg.readiness_model

    # ---- the 49 B OPERATE echo carved [28,21] on a completed CRC-block boundary -----------
    def _carve_echo(self, flavour: int) -> Tuple[Tuple[int, ...], bytes, bool]:
        echo = resp_frame_49(flavour)
        r = self.split.process(Pkt(self.owner[1], self.owner[0], PORT_DNP3, self.owner[2],
                                   seq=500, ack=1, payload=echo))
        segs = tuple(len(s.payload) for s in r.segs)
        joined = b"".join(s.payload for s in r.segs)
        csum_ok = all(s.ipv4_ok and s.tcp_ok for s in r.segs)
        return segs, joined, csum_ok

    # ---- discrete async event-order traces (BOR_RRC_DESIGN.md READINESS RACE) -------------
    def _faithful_event_order(self, scn: Scenario) -> List[str]:
        return [
            "SELECT admit -> create BOR epoch %s (internal id, NOT the DNP3 generation)"
            % self.bor_epoch,
            "SELECT: register write -> clone trigger -> async pktgen generation -> token ingress",
            "SELECT: qid3 residency CONFIRMED (resident BEFORE the OPERATE)",
            "SELECT: BOR_PENDING(epoch %s) retained across SELECT completion" % self.bor_epoch,
            "OPERATE ingress at T0=%s" % scn.T0,
            "OPERATE: register reads (BOR_PENDING? residency? epoch match) -> all TRUE",
            "OPERATE: select leak-safe J (epoch is NEVER the source of J)",
            "OPERATE: enqueue original into qid2 (blocker qid3 already RESIDENT)",
            "OPERATE: qid3 blocks qid2 -> deadline drain at T0+J -> qid2 eligibility",
            "OPERATE: release the original byte-identically EXACTLY ONCE to dp64",
        ]

    @staticmethod
    def _operate_armed_event_order(scn: Scenario) -> List[str]:
        return [
            "OPERATE ingress at T0=%s" % scn.T0,
            "OPERATE: register reads/writes (op_ready read BEFORE arming qid3)",
            "OPERATE: clone trigger (OPERATE)",
            "OPERATE: asynchronous pktgen generation",
            "OPERATE: token ingress",
            "OPERATE: qid3 residency (LATE -- an async TM event AFTER qid2 would drain)",
            "OPERATE: qid2 eligibility",
            "OPERATE: deadline drain",
            "OPERATE: original OPERATE release",
        ]

    # ---- retire: clear the epoch exactly (a mutant may leave stale readiness behind) ------
    def _retire(self) -> None:
        keep_all = "ready_not_cleared_on_retire" in self.mutants
        keep_seq = "stale_ready_after_seq_wrap" in self.mutants
        if keep_all:
            return                                    # BUG: nothing cleared, stale ready persists
        self.bor_pending = False
        self.ready_flag = False
        self.qid3_resident = False
        self.bor_epoch = None
        if not keep_seq:
            self.ready_seq = None                     # faithful: internal epoch, not public seq
        # keep_seq: bor_pending IS cleared, but the public-4-bit-seq key is (wrongly) retained

    # ---- SELECT admission: create + prepare the BOR epoch (faithful) ----------------------
    def _prepare_select(self, scn: Scenario, res: LifecycleResult, model: str) -> None:
        cfg = self.cfg
        if model == RM_OPERATE_ARMED_SR4:
            res.phases.append("SELECT admitted (SR4 model: does NOT prepare qid3; the OPERATE "
                              "arms it -> the FIRST OPERATE reads op_ready=0 -> fails open)")
            res.ready_flag_set = False
            return
        self._epoch_counter += 1
        epoch = self._epoch_counter
        self.bor_epoch = epoch
        res.bor_epoch = epoch
        t_select = scn.T0 - scn.select_lead
        if scn.reservoir_ready:
            resident_at = t_select + cfg.t_pktgen_fill
            resident = (resident_at <= scn.T0)        # confirmed resident before the OPERATE
        else:
            resident_at = None
            resident = False                          # the SELECT-seeded burst never filled
        self.qid3_resident = resident
        self.ready_flag = resident
        if "ready_without_reservoir" in self.mutants:
            self.ready_flag = True                    # CLAIM ready...
            self.qid3_resident = False                # ...without an actually-resident reservoir
        self.bor_pending = True
        self.ready_seq = scn.app_seq & 0xF
        self._qid3_resident_at = resident_at
        res.reservoir_seeded = True
        res.qid3_resident_at = resident_at
        res.ready_flag_set = self.ready_flag
        res.qid3_actually_resident = self.qid3_resident
        res.phases.append(
            "SELECT admitted -> create BOR epoch %s (internal id, NOT the DNP3 generation); "
            "seed qid3; residency confirmed=%s at %s; BOR_PENDING(%s) retained"
            % (epoch, self.qid3_resident, resident_at, epoch))

    # ---- the full SELECT -> OPERATE lifecycle ---------------------------------------------
    def run_lifecycle(self, scn: Scenario) -> LifecycleResult:
        original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])   # the protected OPERATE bytes
        res = LifecycleResult(original_operate=original)
        ph = res.phases
        model = self._readiness_model()

        # ---- Phase 1: SELECT admission -----------------------------------------------------
        if not scn.select_admitted:
            ph.append("SELECT not admitted -> bypass")
            return res
        self._prepare_select(scn, res, model)

        # ---- Phase 2: SELECT completes, or fails (watchdog retire, no output) --------------
        if not scn.select_ok:
            res.watchdog_retired = ("watchdog_no_retire" not in self.mutants)
            self._retire()
            ph.append("SELECT FAILED -> watchdog retire=%s, NO output (BOR epoch retired)"
                      % res.watchdog_retired)
            return res
        ph.append("SELECT ACK+response complete (existing RRC path)")

        # ---- Phase 3: OPERATE arrival (or never -> watchdog retire, no output) -------------
        if not scn.operate_arrives:
            res.watchdog_retired = ("watchdog_no_retire" not in self.mutants)
            self._retire()
            ph.append("OPERATE never arrives -> watchdog retire=%s, NO output (BOR epoch retired)"
                      % res.watchdog_retired)
            return res

        # ---- Phase 4: OPERATE processing (readiness-model dispatch) ------------------------
        res.first_operate = not self._first_operate_done
        self._first_operate_done = True
        if model == RM_OPERATE_ARMED_SR4:
            return self._operate_armed(scn, res, original, variant="sr4")
        if "early_qid2_release" in self.mutants:
            return self._operate_armed(scn, res, original, variant="naive")
        if "magic_buffer_until_ready" in self.mutants:
            return self._operate_armed(scn, res, original, variant="magic")
        return self._operate_faithful(scn, res, original)

    # ---- an OPERATE with NO fresh SELECT (a stray / retried OPERATE) ----------------------
    def run_operate_only(self, scn: Scenario) -> LifecycleResult:
        """Models an OPERATE arriving with no live prepared epoch. Faithful: fail-open + count
        (never enqueue on a stale flag). A stale-readiness mutant WRONGLY revalidates and shapes."""
        original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])
        res = LifecycleResult(original_operate=original)
        res.first_operate = not self._first_operate_done
        self._first_operate_done = True
        pending = self.bor_pending
        resident = self.qid3_resident
        if ("stale_ready_after_seq_wrap" in self.mutants and self.ready_seq is not None
                and self.ready_seq == (scn.app_seq & 0xF)):
            pending = True            # BUG: a 4-bit public-seq wrap revalidates stale readiness
            resident = True
        if not (pending and resident):
            return self._fail_open_operate(scn, res, original,
                                           reason="OPERATE with no live BOR_PENDING epoch")
        res.event_order = self._faithful_event_order(scn)
        return self._do_shaped_operate(scn, res, original, hold_start=scn.T0,
                                       resident_at=self._qid3_resident_at)

    # ---- fail-open forward (a real control request: forward, never drop) ------------------
    def _fail_open_operate(self, scn: Scenario, res: LifecycleResult, original: bytes,
                           reason: str) -> LifecycleResult:
        res.fail_open = True
        res.op_failure_count_delta = 1
        self.op_failure_count += 1
        res.operate_releases.append((scn.T0, original))
        res.retire_count = 1
        self._retire()
        res.phases.append("FAIL-OPEN forward at T0 (no hold, no J): %s (+failure count)" % reason)
        res.observable = self._observe(scn, res, j=None, fail_open=True)
        return res

    # ---- faithful OPERATE: require BOR_PENDING(epoch) + confirmed residency ----------------
    def _operate_faithful(self, scn: Scenario, res: LifecycleResult,
                          original: bytes) -> LifecycleResult:
        ph = res.phases
        # explicit reservoir-not-ready -> fail-open (unless the hold_when_reservoir_not_ready bug)
        if not self.qid3_resident:
            if "hold_when_reservoir_not_ready" in self.mutants:
                ph.append("qid3 NOT resident but HOLDING anyway (mutant: should fail-open)")
            else:
                return self._fail_open_operate(scn, res, original,
                                               reason="qid3 residency not confirmed")
        if not self.bor_pending:
            return self._fail_open_operate(scn, res, original, reason="no BOR_PENDING epoch")
        res.event_order = self._faithful_event_order(scn)
        ph.append("OPERATE matches BOR_PENDING(epoch %s) + confirmed residency -> commit shaped hold"
                  % self.bor_epoch)
        return self._do_shaped_operate(scn, res, original, hold_start=scn.T0,
                                       resident_at=self._qid3_resident_at)

    # ---- the committed shaped hold + release + ACK/echo + retire --------------------------
    def _do_shaped_operate(self, scn: Scenario, res: LifecycleResult, original: bytes,
                           hold_start: float, resident_at: Optional[float]) -> LifecycleResult:
        cfg = self.cfg
        ph = res.phases
        res.reservoir_resident = True
        recorded_t0 = None if "missing_t0" in self.mutants else scn.T0
        res.recorded_T0 = recorded_t0
        j = float(cfg.codebook[self._select_j_index(scn)])
        res.J = j

        # the shaped release fires at T0+J and cannot precede the confirmed-resident hold start
        t_release = max(scn.T0 + j, hold_start)
        res.operate_release_shaped = True
        res.reservoir_resident_before_release = (
            resident_at is not None and t_release >= resident_at and resident_at <= hold_start)
        res.operate_releases.append((t_release, original))     # qid3 drains -> release ORIGINAL

        if "duplicate_release" in self.mutants:
            res.operate_releases.append((t_release, original))  # WRONG: a second physical operation
            ph.append("OPERATE released TWICE (mutant duplicate_release)")
        if scn.retransmit and "retransmit_releases_second_copy" in self.mutants:
            res.operate_releases.append((t_release, original))  # WRONG: retransmit -> second copy
            ph.append("TCP retransmit -> SECOND release (mutant retransmit_releases_second_copy)")
        elif scn.retransmit:
            ph.append("TCP retransmit while held -> same seq recognized, NO second release")
        if "source_copy_leaks_to_relay" in self.mutants:
            res.source_copies_to_relay.append((scn.T0, original))  # WRONG: ingress copy -> relay
            ph.append("ingress SOURCE COPY leaked to dp64 (mutant) -> a 2nd physical operation")
        ph.append("qid3 drains -> release ORIGINAL to dp64 at %s (byte-identical, exactly once)"
                  % t_release)

        # ---- WAIT_ACK using stored T0 -> ACK@T0+A, echo@T0+R carved [28,21] ----------------
        # deadlines anchor to the RECORDED T0; missing_t0 falls back to a WRONG reference.
        anchor = recorded_t0 if recorded_t0 is not None else (scn.T0 + j + cfg.native_ack)
        # re-anchoring the schedule to T0+J re-opens the response-timing leak (section 2).
        sched = (anchor + j) if "deadline_reanchored_to_operate_release" in self.mutants else anchor
        res.ack_time = sched + cfg.A
        res.echo_time = sched + cfg.R
        if "echo_before_ack" in self.mutants:
            res.echo_time = res.ack_time - 1.0                 # WRONG: echo before ACK (R < A)
        segs, joined, csum_ok = self._carve_echo(scn.app_seq % 251 + 1)
        res.echo_segments, res.echo_reassembled, res.echo_checksums_ok = segs, joined, csum_ok
        ph.append("ACK@T0+A=%s, echo@T0+R=%s carved %s (anchored to %s)"
                  % (res.ack_time, res.echo_time, list(segs),
                     "T0" if "deadline_reanchored_to_operate_release" not in self.mutants
                     else "T0+J"))

        # ---- retire exactly once -----------------------------------------------------------
        res.retire_count = 2 if "retire_twice" in self.mutants else 1
        self._retire()
        ph.append("retire (count=%d)" % res.retire_count)
        res.observable = self._observe(scn, res, j=j, fail_open=False)
        return res

    # ---- the OPERATE-armed (SR4 / naive / magic) paths: the design's async-gap failures ----
    def _operate_armed(self, scn: Scenario, res: LifecycleResult, original: bytes,
                       variant: str) -> LifecycleResult:
        cfg = self.cfg
        ph = res.phases
        res.reservoir_seeded = True
        res.event_order = self._operate_armed_event_order(scn)
        resident_at = scn.T0 + cfg.t_pktgen_fill              # ASYNC: LATER than T0 (the race)
        res.qid3_resident_at = resident_at
        t_qid2_ready = scn.T0 + cfg.t_qid2_drain
        resident_in_time = resident_at <= t_qid2_ready        # False under an async fill gap

        if variant == "sr4":
            # read op_ready BEFORE arming -> the FIRST OPERATE reads 0 -> FAIL OPEN (resource probe)
            res.fail_open = True
            res.op_failure_count_delta = 1
            self.op_failure_count += 1
            res.operate_releases.append((scn.T0, original))
            res.retire_count = 1
            self._retire()
            ph.append("SR4 operate-armed: op_ready read BEFORE arm = 0 on the FIRST OPERATE -> "
                      "FAIL OPEN at T0 (SAFE BYPASS, unshaped); qid3 armed async AFTER "
                      "(RESOURCE PROBE, NOT BOR shaping)")
            res.observable = self._observe(scn, res, j=None, fail_open=True)
            return res

        j = float(cfg.codebook[self._select_j_index(scn)])
        res.J = j
        res.recorded_T0 = scn.T0

        if variant == "naive":
            # hold regardless of residency -> blocker ABSENT -> early UNSHAPED escape
            res.operate_releases.append((t_qid2_ready, original))
            res.operate_release_shaped = False
            res.reservoir_resident_before_release = False
            res.retire_count = 1
            self._retire()
            ph.append("NAIVE race: resident_at=%s > qid2_ready=%s -> blocker ABSENT -> OPERATE "
                      "ESCAPES EARLY at %s, UNSHAPED (J=%s selected but NOT applied)"
                      % (resident_at, t_qid2_ready, t_qid2_ready, j))
            res.observable = self._observe(scn, res, j=None, fail_open=False)   # native leaks
            return res

        # variant == "magic": claim to buffer the original in NON-EXISTENT storage until resident
        res.magic_buffer_used = True
        t_release = scn.T0 + j
        res.operate_release_shaped = True
        res.reservoir_resident_before_release = True          # FALSELY claims resident-before-release
        res.operate_releases.append((t_release, original))
        res.retire_count = 1
        anchor = scn.T0
        res.ack_time = anchor + cfg.A
        res.echo_time = anchor + cfg.R
        segs, joined, csum_ok = self._carve_echo(scn.app_seq % 251 + 1)
        res.echo_segments, res.echo_reassembled, res.echo_checksums_ok = segs, joined, csum_ok
        self._retire()
        ph.append("MAGIC BUFFER: claims to hold the original from T0 to resident_at=%s with NO "
                  "hardware storage path, then release shaped @%s -- UNPHYSICAL (must be caught)"
                  % (resident_at, t_release))
        res.observable = self._observe(scn, res, j=j, fail_open=False)
        return res

    # ---- the passive UPSTREAM observable this transaction produces ------------------------
    def _observe(self, scn: Scenario, res: LifecycleResult, j: Optional[float],
                 fail_open: bool) -> ObservableStream:
        cfg = self.cfg
        operate_time = scn.T0              # the observer sees the master's OPERATE command at T0
        if fail_open:
            # forwarded at T0, no hold, no J: the physical op happens at T0 + T_physical
            return ObservableStream(operate_time, None, None, (), scn.T0 + scn.t_physical,
                                    False, None, scn.app_seq, cfg.codebook, cfg.R)
        # the relay operates when it RECEIVES the released OPERATE (T0+J) + its native actuation
        ser_ts = scn.T0 + (j or 0.0) + scn.t_physical
        ts_present = cfg.tcp_ts_enabled or ("tcp_timestamp_subtraction" in self.mutants)
        # the relay's TSval is stamped at its receive of the released OPERATE (~T0+J)
        ack_tsval = (scn.T0 + (j or 0.0)) if ts_present else None
        return ObservableStream(operate_time, res.ack_time, res.echo_time, res.echo_segments,
                                ser_ts, ts_present, ack_tsval, scn.app_seq, cfg.codebook, cfg.R)


# --------------------------------------------------------------------------- #
# the observer model (parser of the wire, knows the PUBLIC design, not the secret J)
# --------------------------------------------------------------------------- #
@dataclass
class ObserverEstimate:
    M: float                           # the measured blob J + T_physical
    j_timing: Optional[float]          # response-timing channel estimate
    j_tsval: Optional[float]           # TCP-timestamp channel estimate (None if no TS)
    j_public: float                    # public-sequence predictor codebook[app_seq % len]


def observer_recover_J(stream: ObservableStream) -> ObserverEstimate:
    """A passive upstream observer's attempt to recover J from EVERY channel it can see. It knows
    the public design (constant R, the codebook) but not the secret selection. It cannot recover J
    iff no channel yields the true J (BOR_RRC_DESIGN.md section 2)."""
    M = ((stream.ser_event_ts - stream.operate_time)
         if stream.ser_event_ts is not None else float("nan"))
    j_timing = ((stream.echo_time - stream.operate_time) - stream.R
                if stream.echo_time is not None else None)
    j_tsval = ((stream.ack_tsval - stream.operate_time)
               if (stream.tcp_ts_present and stream.ack_tsval is not None) else None)
    j_public = float(stream.codebook[stream.app_seq % len(stream.codebook)])
    return ObserverEstimate(M=M, j_timing=j_timing, j_tsval=j_tsval, j_public=j_public)


# a family of OPERATE transactions whose SECRET j_index is deliberately decoupled from the public
# app_seq % len(codebook), so the public predictor cannot match the clean model.
_ANTI_SUB_FAMILY = [
    # (T0,    j_index, app_seq, t_physical)
    (100.0, 3, 0, 5.0),    # J=6   codebook[0%7]=0
    (250.0, 5, 1, 7.0),    # J=10  codebook[1%7]=2
    (400.0, 1, 2, 4.0),    # J=2   codebook[2%7]=4
    (550.0, 6, 4, 9.0),    # J=12  codebook[4%7]=8
    (900.0, 2, 5, 6.0),    # J=4   codebook[5%7]=10
]


def anti_subtraction_holds(owner: Tuple[int, int, int, int], config: BORConfig = BORConfig(),
                           mutants: frozenset = frozenset()) -> Tuple[bool, Dict[str, bool]]:
    """Run the family and decide, per observer channel, whether it RELIABLY recovers the true J
    across EVERY member. Anti-subtraction HOLDS iff no channel does (so J + T_physical stays an
    inseparable blob and T_physical is hidden)."""
    eng = BORRRCEngine(owner, config, mutants)
    n = len(_ANTI_SUB_FAMILY)
    timing_hits = tsval_hits = public_hits = 0
    for (t0, j_index, app_seq, tphys) in _ANTI_SUB_FAMILY:
        res = eng.run_lifecycle(Scenario(T0=t0, j_index=j_index, app_seq=app_seq, t_physical=tphys))
        true_j = res.J
        est = observer_recover_J(res.observable)
        if est.j_timing is not None and true_j is not None and abs(est.j_timing - true_j) < EPS:
            timing_hits += 1
        if est.j_tsval is not None and true_j is not None and abs(est.j_tsval - true_j) < EPS:
            tsval_hits += 1
        if true_j is not None and abs(est.j_public - true_j) < EPS:
            public_hits += 1
    channels = {
        "response_timing": timing_hits == n,
        "tcp_tsval": tsval_hits == n,
        "public_seq": public_hits == n,
    }
    return (not any(channels.values())), channels


# =========================================================================== #
# conformance (all True on the faithful model; each mutant flips >= its expected check)
# =========================================================================== #
OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613       # outstation, master
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)     # normalized response-direction 5-tuple


def _check_ready_cleared_on_retire(mutants: frozenset) -> bool:
    """A full lifecycle retires the epoch; a later OPERATE with NO fresh SELECT (non-wrapping
    seq) must fail-open. `ready_not_cleared_on_retire` leaves the flag set -> it wrongly shapes."""
    eng = BORRRCEngine(OWNER, BORConfig(), mutants)
    eng.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=1))
    second = eng.run_operate_only(Scenario(T0=2000.0, j_index=4, app_seq=2))
    return second.fail_open


def _check_no_stale_ready_after_seq_wrap(mutants: frozenset) -> bool:
    """SELECT+OPERATE at seq 3 retires; a later OPERATE at a WRAPPED seq (19 -> 3) with NO fresh
    SELECT must fail-open. `stale_ready_after_seq_wrap` keys readiness on the 4-bit seq -> it
    wrongly revalidates and shapes."""
    eng = BORRRCEngine(OWNER, BORConfig(), mutants)
    eng.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3))
    second = eng.run_operate_only(Scenario(T0=2000.0, j_index=4, app_seq=19))
    return second.fail_open


def run_conformance(mutants: frozenset = frozenset()) -> Dict[str, bool]:
    cfg = BORConfig()
    eng = BORRRCEngine(OWNER, cfg, mutants)
    checks: Dict[str, bool] = {}

    # nominal faithful OPERATE transaction (J = codebook[5] = 10 ms on the clean model)
    scn = Scenario(T0=1000.0, j_index=5, app_seq=3, t_physical=5.0)
    r = eng.run_lifecycle(scn)
    j = r.J if r.J is not None else float("nan")

    # control-plane admissibility: A > Jmax + native_ACK, R > Jmax + native_response, R >= A
    checks["deadline_constraints_valid"] = cfg.deadlines_valid()

    # T0-anchored deadlines: engine recorded T0 and computed T0+J / T0+A / T0+R
    checks["t0_anchored_deadlines"] = (
        r.recorded_T0 == scn.T0 and r.J is not None and len(r.operate_releases) >= 1
        and abs(r.operate_releases[0][0] - (scn.T0 + j)) < EPS
        and r.ack_time is not None and abs(r.ack_time - (scn.T0 + cfg.A)) < EPS
        and r.echo_time is not None and abs(r.echo_time - (scn.T0 + cfg.R)) < EPS)

    # FIRST OPERATE after a clean start IS held and shaped (the faithful-vs-SR4 property)
    checks["first_operate_shaped"] = (
        r.first_operate and r.operate_release_shaped and not r.fail_open)

    # qid3 reservoir seeded at SELECT (BOR epoch) and resident by release
    checks["reservoir_seeded_resident"] = (r.reservoir_seeded and r.reservoir_resident)

    # the readiness flag was only asserted with a TRULY resident reservoir
    checks["ready_implies_reservoir_resident"] = (
        (not r.ready_flag_set) or r.qid3_actually_resident)

    # the qid3 blocker was resident BEFORE the held OPERATE released (no early/unshaped escape,
    # and no magic buffer bridging an async gap)
    checks["reservoir_resident_before_release"] = (
        r.reservoir_resident_before_release and r.operate_release_shaped)
    checks["no_magic_buffer_storage"] = (not r.magic_buffer_used)

    # exactly-once OPERATE release + byte-identical original bytes toward dp64, no leaked copy
    checks["exactly_once_operate_release"] = (len(r.operate_releases) == 1)
    checks["operate_byte_identical"] = (len(r.operate_releases) >= 1
                                        and r.operate_releases[0][1] == r.original_operate)
    checks["no_source_copy_to_relay"] = (not r.source_copies_to_relay)

    # echo carved [28,21], byte-identical reassembly, valid IPv4/TCP checksums
    checks["echo_carved_28_21"] = (r.echo_segments == (28, 21))
    checks["echo_byte_identical"] = (r.echo_reassembled == resp_frame_49(scn.app_seq % 251 + 1)
                                     and r.echo_checksums_ok)

    # ordering: echo released at/after the ACK (R >= A observed on the wire)
    checks["echo_after_ack_ordering"] = (r.ack_time is not None and r.echo_time is not None
                                         and r.echo_time >= r.ack_time)

    # retire exactly once
    checks["retire_exactly_once"] = (r.retire_count == 1)

    # exactly-once under an exact TCP retransmit while OPERATE is held
    rt = eng.run_lifecycle(Scenario(T0=2000.0, j_index=4, app_seq=7, retransmit=True))
    checks["exactly_once_under_retransmit"] = (len(rt.operate_releases) == 1)

    # fail-open when the SELECT-seeded qid3 reservoir did not fill: forward at T0, no hold, no J
    fo = eng.run_lifecycle(Scenario(T0=3000.0, j_index=6, app_seq=1, reservoir_ready=False))
    checks["fail_open_when_reservoir_not_ready"] = (
        fo.fail_open and len(fo.operate_releases) == 1
        and abs(fo.operate_releases[0][0] - 3000.0) < EPS and fo.J is None)

    # watchdog retires the BOR epoch on no-OPERATE and on failed-SELECT, with NO output change
    wd_noop = eng.run_lifecycle(Scenario(T0=4000.0, j_index=3, operate_arrives=False))
    checks["watchdog_retire_no_operate"] = (wd_noop.watchdog_retired
                                            and not wd_noop.operate_releases
                                            and wd_noop.observable is None)
    wd_sel = eng.run_lifecycle(Scenario(T0=5000.0, j_index=3, select_ok=False))
    checks["watchdog_retire_failed_select"] = (wd_sel.watchdog_retired
                                               and not wd_sel.operate_releases
                                               and wd_sel.observable is None)

    # readiness flag cleared on retire: a later OPERATE with no fresh SELECT fails open
    checks["ready_cleared_on_retire"] = _check_ready_cleared_on_retire(mutants)

    # a 4-bit DNP3 sequence wrap does NOT revalidate stale readiness (internal epoch gates it)
    checks["no_stale_ready_after_seq_wrap"] = _check_no_stale_ready_after_seq_wrap(mutants)

    # anti-subtraction: the observer CANNOT recover J (timestamps off) from any channel
    holds, _ = anti_subtraction_holds(OWNER, cfg, mutants)
    checks["observer_cannot_recover_J"] = holds

    return checks


# --------------------------------------------------------------------------- #
# the faithful-vs-SR4 discrimination (BOR_RRC_DESIGN.md READINESS RACE, "Known non-solution")
# --------------------------------------------------------------------------- #
def first_operate_is_shaped(config: BORConfig, mutants: frozenset = frozenset()) -> bool:
    """Run ONE SELECT+OPERATE on a clean-start engine and report whether the FIRST OPERATE was
    actually held and shaped (J applied). The FAITHFUL select-prepared config returns True; the
    SR4-style operate-armed (fail_open_first) config returns False (the first OPERATE fails open,
    which is SAFE BYPASS, not successful shaping)."""
    eng = BORRRCEngine(OWNER, config, mutants)
    r = eng.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3, t_physical=5.0))
    return bool(r.first_operate and r.operate_release_shaped and not r.fail_open)


FAITHFUL_CFG = BORConfig(readiness_model=RM_SELECT_PREPARED)
FAIL_OPEN_FIRST_CFG = BORConfig(readiness_model=RM_OPERATE_ARMED_SR4)


# --------------------------------------------------------------------------- #
# scale + sequence-wrap drivers (>= 1000 modeled transactions; multiple 4-bit wraps)
# --------------------------------------------------------------------------- #
# a SECRET J-index schedule deliberately decoupled from the public 4-bit app sequence
_SECRET_J_SCHEDULE = tuple((i * 3 + 2) % len(CODEBOOK) for i in range(97))


def run_scale_driver(n: int = 1000) -> Dict[str, object]:
    """Drive >= n faithful SELECT+OPERATE transactions through one engine, cycling the public
    app_seq through its 4-bit range (so many wraps occur), and check every per-transaction
    invariant. Returns per-invariant PASS counts and an overall all_ok."""
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])
    c = dict(shaped=0, exactly_once=0, byte_identical=0, retired_once=0, state_cleared=0,
             timing_channel_zero=0, no_tsval_channel=0, resident_before_release=0)
    public_hits = 0
    for i in range(n):
        T0 = 1000.0 + i * 100.0
        j_index = _SECRET_J_SCHEDULE[i % len(_SECRET_J_SCHEDULE)]
        app_seq = i % 16                                       # exercises 4-bit wraps
        tphys = 3.0 + (i % 7)
        r = eng.run_lifecycle(Scenario(T0=T0, j_index=j_index, app_seq=app_seq, t_physical=tphys))
        c["shaped"] += bool(r.operate_release_shaped and not r.fail_open)
        c["exactly_once"] += bool(len(r.operate_releases) == 1 and not r.source_copies_to_relay)
        c["byte_identical"] += bool(r.operate_releases and r.operate_releases[0][1] == original)
        c["retired_once"] += bool(r.retire_count == 1)
        c["state_cleared"] += bool(not eng.bor_pending and eng.bor_epoch is None)
        c["resident_before_release"] += bool(r.reservoir_resident_before_release)
        est = observer_recover_J(r.observable)
        c["timing_channel_zero"] += bool(est.j_timing is not None and abs(est.j_timing) < EPS)
        c["no_tsval_channel"] += bool(est.j_tsval is None)
        public_hits += bool(r.J is not None and abs(est.j_public - r.J) < EPS)
    all_perfect = all(v == n for v in c.values())
    public_not_oracle = public_hits < n           # the public predictor is not a reliable oracle
    return {"n": n, "counts": c, "public_hits": public_hits,
            "public_not_oracle": public_not_oracle, "all_ok": bool(all_perfect and public_not_oracle)}


def run_seq_wrap_driver(cycles: int = 4) -> Dict[str, object]:
    """Drive the public app_seq through `cycles` FULL 0..15 wraps (fresh SELECT+OPERATE each,
    all shaped exactly once); then confirm a stray OPERATE at a WRAPPED seq with NO fresh SELECT
    fails open (no stale-ready cross-contamination across the wrap)."""
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    total = cycles * 16
    shaped_once = 0
    for cyc in range(cycles):
        for s in range(16):
            T0 = 1000.0 + (cyc * 16 + s) * 100.0
            r = eng.run_lifecycle(Scenario(T0=T0, j_index=(s % len(CODEBOOK)), app_seq=s,
                                           t_physical=5.0))
            shaped_once += bool(r.operate_release_shaped and len(r.operate_releases) == 1)
    stray = eng.run_operate_only(Scenario(T0=999999.0, j_index=0, app_seq=16 + 3))   # wraps to 3
    all_ok = bool(shaped_once == total and stray.fail_open and eng.op_failure_count >= 1)
    return {"cycles": cycles, "total": total, "shaped_once": shaped_once,
            "stray_fail_open": bool(stray.fail_open), "op_failure_count": eng.op_failure_count,
            "all_ok": all_ok}


# each mutant + the conformance check it is EXPECTED to break (a design invariant it violates).
# The first 12 are the REQUIRED mutants; the remaining 5 are legacy guards for frozen checks.
MUTANTS: List[Tuple[str, str, str]] = [
    ("first_operate_always_fail_open", "first_operate_shaped",
     "read op_ready BEFORE arming (SR4) -> the FIRST OPERATE always fails open -> unshaped"),
    ("early_qid2_release", "reservoir_resident_before_release",
     "naive race: qid3 blocker NOT yet resident (async pktgen/TM) when qid2 drains -> held "
     "OPERATE escapes EARLY, UNSHAPED -> observer recovers native T_physical"),
    ("magic_buffer_until_ready", "no_magic_buffer_storage",
     "claims the original is buffered between T0 and resident_at with NO hardware storage path"),
    ("stale_ready_after_seq_wrap", "no_stale_ready_after_seq_wrap",
     "a 4-bit DNP3 sequence wrap revalidates a stale readiness flag (no fresh SELECT)"),
    ("ready_without_reservoir", "ready_implies_reservoir_resident",
     "readiness asserted without an actually-resident reservoir"),
    ("ready_not_cleared_on_retire", "ready_cleared_on_retire",
     "the readiness flag is not cleared on retire -> a later OPERATE wrongly shapes"),
    ("duplicate_release", "exactly_once_operate_release",
     "duplicate OPERATE release -> two physical operations"),
    ("retransmit_releases_second_copy", "exactly_once_under_retransmit",
     "an exact TCP retransmit while held triggers a SECOND release -> two physical operations"),
    ("deadline_reanchored_to_operate_release", "observer_cannot_recover_J",
     "re-anchor ACK/echo to the T0+J release -> observer recovers J from response timing"),
    ("public_sequence_selects_j", "observer_cannot_recover_J",
     "J selected from the public DNP3 sequence -> observer predicts J"),
    ("tcp_timestamp_subtraction", "observer_cannot_recover_J",
     "TCP timestamps negotiated -> observer recovers J from the stale TSval (subtraction attack)"),
    ("source_copy_leaks_to_relay", "no_source_copy_to_relay",
     "a source copy of the OPERATE leaks to the relay -> a second physical operation"),
    # ---- legacy guards for frozen conformance checks (killed too, not in the required 12) ----
    ("missing_t0", "t0_anchored_deadlines",
     "T0 not recorded -> deadlines undefined / anchored wrong"),
    ("hold_when_reservoir_not_ready", "fail_open_when_reservoir_not_ready",
     "qid3 not resident but OPERATE still held -> should fail-open, not hold"),
    ("echo_before_ack", "echo_after_ack_ordering",
     "response released before ACK -> ordering violation, R < A"),
    ("watchdog_no_retire", "watchdog_retire_no_operate",
     "no-OPERATE cleanup fails -> watchdog does not retire the BOR epoch"),
    ("retire_twice", "retire_exactly_once",
     "transaction retires twice (fails to retire exactly once)"),
]

# the 12 mutants the task requires by name (a subset of MUTANTS)
REQUIRED_MUTANTS: Tuple[str, ...] = tuple(name for name, _, _ in MUTANTS[:12])

EXPECT_BREAKS: Dict[str, str] = {name: expect for name, expect, _ in MUTANTS}


def _note() -> str:
    return (
        "NOTE (report correction, BOR_RRC_DESIGN.md section 3):\n"
        "  * The current SR4 P4 result is a RESOURCE PROBE (fail-open-only): it proves the qid3\n"
        "    reservoir machinery arms/fits, NOT that BOR protects the first OPERATE. It reads\n"
        "    op_ready BEFORE arming, so the FIRST OPERATE fails open.\n"
        "  * SAFE BYPASS (forward-unshaped, correctness-preserving) is NOT successful shaping\n"
        "    (held to T0+J, J hidden). This model scores them separately: fail_open vs\n"
        "    operate_release_shaped.\n"
        "  * The faithful fix = SELECT prepares a BOR epoch (internal identity, not the DNP3\n"
        "    generation) so the reservoir is resident BEFORE the OPERATE and the first OPERATE\n"
        "    is shaped.\n"
        "  * A COMBINED build fusing SELECT-prepared readiness + a leak-safe random J selector\n"
        "    has NOT yet been compiled on bf-p4c -- that is the P4 agent's job. This file is a\n"
        "    behavioral model only (not a compile; a compile is not silicon).")


def main() -> int:
    clean = run_conformance(frozenset())
    print("== FAITHFUL MODEL (BOR_RRC_DESIGN conformance) ==")
    for k, v in clean.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    clean_ok = all(clean.values())

    print("\n== FIRST-OPERATE DISCRIMINATION (faithful shapes; SR4 fail_open_first does NOT) ==")
    faithful = first_operate_is_shaped(FAITHFUL_CFG)
    sr4 = first_operate_is_shaped(FAIL_OPEN_FIRST_CFG)
    print("  [%s] first_operate_shaped(faithful select_prepared) = %s"
          % ("PASS" if faithful else "FAIL", faithful))
    print("  [%s] first_operate_shaped(fail_open_first SR4)       = %s  (check correctly FAILS)"
          % ("PASS" if not sr4 else "FAIL", sr4))
    disc_ok = faithful and not sr4

    print("\n== ASYNC EVENT ORDER (faithful vs SR4 operate-armed) ==")
    eng_f = BORRRCEngine(OWNER, FAITHFUL_CFG)
    rf = eng_f.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3))
    for step in rf.event_order:
        print("   faithful : %s" % step)
    eng_s = BORRRCEngine(OWNER, FAIL_OPEN_FIRST_CFG)
    rs = eng_s.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3))
    for step in rs.event_order:
        print("   SR4      : %s" % step)

    print("\n== SCALE DRIVER (>= 1000 modeled faithful transactions, many 4-bit wraps) ==")
    scale = run_scale_driver(1000)
    print("  n=%d  counts=%s" % (scale["n"], scale["counts"]))
    print("  public_hits=%d (< n so the public predictor is not an oracle: %s)"
          % (scale["public_hits"], scale["public_not_oracle"]))
    print("  [%s] scale_driver_all_ok" % ("PASS" if scale["all_ok"] else "FAIL"))

    print("\n== SEQUENCE-WRAP DRIVER (4 full 0..15 wraps + a stray wrapped OPERATE) ==")
    wrap = run_seq_wrap_driver(4)
    print("  total=%d shaped_once=%d stray_fail_open=%s op_failure_count=%d"
          % (wrap["total"], wrap["shaped_once"], wrap["stray_fail_open"], wrap["op_failure_count"]))
    print("  [%s] seq_wrap_driver_all_ok" % ("PASS" if wrap["all_ok"] else "FAIL"))

    print("\n== MUTANTS (each MUST be KILLED: its expected invariant check flips to FAIL) ==")
    killed = {}
    for name, expect, desc in MUTANTS:
        c = run_conformance(frozenset([name]))
        failed = [k for k, v in c.items() if not v]
        killed[name] = (expect in failed)
        tag = "REQUIRED" if name in REQUIRED_MUTANTS else "legacy  "
        print("  [%s] %-38s (%s) expect_break=%-32s"
              % ("KILLED" if killed[name] else "SURVIVED", name, tag, expect))
        print("           %s" % desc)
        print("           actual_failed=%s" % (failed or "NONE (mutant undetected)"))

    required_all_killed = all(killed[m] for m in REQUIRED_MUTANTS)
    all_killed = all(killed.values())
    ok = (clean_ok and disc_ok and bool(scale["all_ok"]) and bool(wrap["all_ok"]) and all_killed)
    print("\n" + _note())
    print("\nRESULT: %s  (clean=%s, discrimination=%s, scale=%s, seq_wrap=%s, "
          "required_mutants_killed=%d/%d, all_mutants_killed=%d/%d)"
          % ("PASS" if ok else "FAIL", clean_ok, disc_ok, scale["all_ok"], wrap["all_ok"],
             sum(killed[m] for m in REQUIRED_MUTANTS), len(REQUIRED_MUTANTS),
             sum(killed.values()), len(MUTANTS)))
    return 0 if (ok and required_all_killed) else 1


if __name__ == "__main__":
    sys.exit(main())
