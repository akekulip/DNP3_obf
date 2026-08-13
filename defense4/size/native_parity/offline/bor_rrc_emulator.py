#!/usr/bin/env python3
"""Behavioral emulator of the BOR-in-RRC lifecycle (BOR_RRC_DESIGN.md) — Bounded OPERATE
Release run as the OPERATE-request phase of the RRC transaction engine, plus a passive
UPSTREAM observer used to prove the anti-subtraction invariant offline.

WHAT IT MODELS. One transaction, one T0, spanning request-hold -> ACK-hold -> response-hold:

  * SELECT admitted        -> seed the qid3 OPERATE blocker reservoir (marked resident; it
                              stays queue-resident behind higher-priority qids 4-7 across the
                              ~0.408 ms SELECT-response -> OPERATE turnaround).
  * SELECT ACK+response     -> complete through the existing RRC path.
  * OPERATE arrives at T0    -> record T0 (a passed-in ingress timestamp), select J from a
                              bounded codebook {0,2,4,6,8,10,12} ms via a LEAK-SAFE source
                              (never a public DNP3 sequence value), hold the ORIGINAL OPERATE
                              in qid2.
  * qid3 drains at T0 + J    -> release the ORIGINAL bytes EXACTLY ONCE toward the relay (dp64),
                              then transition THIS SAME transaction to WAIT_ACK using stored T0.
  * relay ACK                -> released at T0 + A (dp9), ANCHORED TO T0 (never to T0+J).
  * relay OPERATE echo (49B) -> released at T0 + R, carved [28,21] on the CRC-block boundary.
  * retire                   -> exactly once.
  * SELECT fails / OPERATE   -> qid3 retires via a bounded watchdog, NO output change.
    never arrives

THE SECURITY PROPERTY (BOR_RRC_DESIGN.md section 2). A passive upstream observer measures
`M = T_SER_event - T_OPERATE_observed = J + T_physical`. Anti-subtraction HOLDS iff the
observer CANNOT recover J from any channel, so M stays an inseparable blob and the native
device-fingerprint T_physical is hidden. Two channels can leak J:
  (a) response timing: J = (echo_time - operate_time) - R. T0-anchoring with a constant R
      collapses this to 0 -> no leak.
  (b) TCP TSval: the relay stamps its pure ACK when it RECEIVES the released OPERATE (~T0+J);
      even if the switch holds the ACK to T0+A, the stale TSval recovers J. T0-anchoring does
      NOT close this -> the MVP requires a no-TCP-timestamp protected flow.

`python3 bor_rrc_emulator.py` runs the conformance asserts on the clean model and confirms every
design mutant is killed. Pure stdlib. NOT silicon — a behavioral model is not a compile, and a
compile is not silicon; the physical divergence floor needs an authorized physical campaign.
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
    """One OPERATE lifecycle instance. `T0` is the passed-in ingress MAC timestamp."""
    T0: float
    j_index: int                       # the leak-safe secret index into the codebook
    app_seq: int = 0                   # PUBLIC DNP3 app sequence (an observer sees this)
    t_physical: float = 5.0            # the device's native actuation time (the fingerprint)
    select_admitted: bool = True
    select_ok: bool = True
    operate_arrives: bool = True
    reservoir_ready: bool = True
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
    reservoir_seeded: bool = False
    reservoir_resident: bool = False
    recorded_T0: Optional[float] = None
    J: Optional[float] = None
    fail_open: bool = False
    operate_releases: List[Tuple[float, bytes]] = field(default_factory=list)  # (time, bytes)->dp64
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

    # ---- leak-safe delay selection (section 7): NEVER derive J from a public value --------
    def _select_j_index(self, scn: Scenario) -> int:
        if "j_from_public_seq" in self.mutants:
            return scn.app_seq % len(self.cfg.codebook)   # WRONG: predictable from the wire
        return scn.j_index                                 # secret-salt / random extern source

    # ---- the 49 B OPERATE echo carved [28,21] on a completed CRC-block boundary -----------
    def _carve_echo(self, flavour: int) -> Tuple[Tuple[int, ...], bytes, bool]:
        echo = resp_frame_49(flavour)
        r = self.split.process(Pkt(self.owner[1], self.owner[0], PORT_DNP3, self.owner[2],
                                   seq=500, ack=1, payload=echo))
        segs = tuple(len(s.payload) for s in r.segs)
        joined = b"".join(s.payload for s in r.segs)
        csum_ok = all(s.ipv4_ok and s.tcp_ok for s in r.segs)
        return segs, joined, csum_ok

    def run_lifecycle(self, scn: Scenario) -> LifecycleResult:
        cfg = self.cfg
        original = req_frame(FC_OPERATE, REQ_LEN[FC_OPERATE])   # the protected OPERATE bytes
        res = LifecycleResult(original_operate=original)
        ph = res.phases

        # ---- Phase 1: SELECT admission seeds the qid3 OPERATE reservoir -------------------
        if not scn.select_admitted:
            ph.append("SELECT not admitted -> bypass, no qid3 seed")
            return res
        res.reservoir_seeded = True
        res.reservoir_resident = True      # resident behind higher-priority qids 4-7
        ph.append("SELECT admitted -> seed qid3 OPERATE reservoir (resident)")

        # ---- Phase 2: SELECT completes, or fails (watchdog retire, no output) -------------
        if not scn.select_ok:
            res.watchdog_retired = ("watchdog_no_retire" not in self.mutants)
            ph.append("SELECT FAILED -> qid3 watchdog retire=%s, NO output" % res.watchdog_retired)
            return res
        ph.append("SELECT ACK+response complete (existing RRC path)")

        # ---- Phase 3: OPERATE arrival (or never -> watchdog retire, no output) ------------
        if not scn.operate_arrives:
            res.watchdog_retired = ("watchdog_no_retire" not in self.mutants)
            ph.append("OPERATE never arrives -> qid3 watchdog retire=%s, NO output"
                      % res.watchdog_retired)
            return res

        # ---- Phase 4: reservoir readiness -> fail-open if not ready ------------------------
        if not scn.reservoir_ready:
            if "hold_when_reservoir_not_ready" in self.mutants:
                ph.append("qid3 NOT ready but HOLDING anyway (mutant: should fail-open)")
                # WRONG: fall through into the hold path below
            else:
                res.fail_open = True
                res.operate_releases.append((scn.T0, original))
                res.retire_count = 1
                ph.append("qid3 NOT ready -> fail-open immediate forward at T0 (no hold, no J)")
                res.observable = self._observe(scn, res, j=None, fail_open=True)
                return res

        # ---- Phase 5: record T0, select J, hold original in qid2, release at T0+J ----------
        recorded_t0 = None if "missing_t0" in self.mutants else scn.T0
        res.recorded_T0 = recorded_t0
        j = float(cfg.codebook[self._select_j_index(scn)])
        res.J = j
        ph.append("OPERATE at T0=%s -> record T0, select J=%s ms (qid3), hold original in qid2"
                  % (scn.T0, j))

        t_release = scn.T0 + j
        res.operate_releases.append((t_release, original))     # qid3 drains -> release ORIGINAL
        if "duplicate_operate_release" in self.mutants:
            res.operate_releases.append((t_release, original)) # WRONG: a second physical operation
            ph.append("OPERATE released TWICE (mutant duplicate)")
        elif scn.retransmit:
            ph.append("TCP retransmit while held -> same seq recognized, NO second release")
        ph.append("qid3 drains at T0+J=%s -> release ORIGINAL to dp64 (exactly once)" % t_release)

        # ---- Phase 6: WAIT_ACK using stored T0 -> ACK@T0+A, echo@T0+R carved [28,21] -------
        # deadlines anchor to the RECORDED T0; missing_t0 falls back to a WRONG reference.
        anchor = recorded_t0 if recorded_t0 is not None else (scn.T0 + j + cfg.native_ack)
        # re-anchoring the schedule to T0+J re-opens the response-timing leak (section 2).
        sched = (anchor + j) if "reanchor_ack_echo_to_release" in self.mutants else anchor
        res.ack_time = sched + cfg.A
        res.echo_time = sched + cfg.R
        if "echo_before_ack" in self.mutants:
            res.echo_time = res.ack_time - 1.0                 # WRONG: echo before ACK (R < A)

        segs, joined, csum_ok = self._carve_echo(scn.app_seq % 251 + 1)
        res.echo_segments, res.echo_reassembled, res.echo_checksums_ok = segs, joined, csum_ok
        ph.append("ACK@T0+A=%s, echo@T0+R=%s carved %s (anchored to %s)"
                  % (res.ack_time, res.echo_time, list(segs),
                     "T0" if "reanchor_ack_echo_to_release" not in self.mutants else "T0+J"))

        # ---- Phase 7: retire exactly once -------------------------------------------------
        res.retire_count = 2 if "retire_twice" in self.mutants else 1
        ph.append("retire (count=%d)" % res.retire_count)

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
        ts_present = cfg.tcp_ts_enabled or ("tcp_timestamps_negotiated" in self.mutants)
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
    """A passive upstream observer's attempt to recover J from EVERY channel it can see. It
    knows the public design (constant R, the codebook) but not the secret selection. It cannot
    recover J iff no channel yields the true J (section 2)."""
    M = ((stream.ser_event_ts - stream.operate_time)
         if stream.ser_event_ts is not None else float("nan"))
    # (a) response-timing channel: J = (echo - operate) - R  (T0-anchored constant R -> 0)
    j_timing = ((stream.echo_time - stream.operate_time) - stream.R
                if stream.echo_time is not None else None)
    # (b) TCP-timestamp channel: the stale TSval encodes the relay's receive time of released OP
    j_tsval = ((stream.ack_tsval - stream.operate_time)
               if (stream.tcp_ts_present and stream.ack_tsval is not None) else None)
    # (c) public-sequence predictor: only leaks if the design derived J from this public value
    j_public = float(stream.codebook[stream.app_seq % len(stream.codebook)])
    return ObserverEstimate(M=M, j_timing=j_timing, j_tsval=j_tsval, j_public=j_public)


# a family of OPERATE transactions whose SECRET j_index is deliberately decoupled from the
# public app_seq % len(codebook), so the public predictor cannot match the clean model.
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
        if est.j_timing is not None and abs(est.j_timing - true_j) < EPS:
            timing_hits += 1
        if est.j_tsval is not None and abs(est.j_tsval - true_j) < EPS:
            tsval_hits += 1
        if abs(est.j_public - true_j) < EPS:
            public_hits += 1
    channels = {
        "response_timing": timing_hits == n,
        "tcp_tsval": tsval_hits == n,
        "public_seq": public_hits == n,
    }
    return (not any(channels.values())), channels


# =========================================================================== #
# conformance (all True on the clean model; each mutant flips >= its expected check)
# =========================================================================== #
OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613       # outstation, master
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)     # normalized response-direction 5-tuple


def run_conformance(mutants: frozenset = frozenset()) -> Dict[str, bool]:
    cfg = BORConfig()
    eng = BORRRCEngine(OWNER, cfg, mutants)
    checks: Dict[str, bool] = {}

    # nominal OPERATE transaction (J = codebook[5] = 10 ms on the clean model)
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

    # qid3 reservoir seeded at SELECT and resident across the turnaround
    checks["reservoir_seeded_resident"] = (r.reservoir_seeded and r.reservoir_resident)

    # exactly-once OPERATE release + byte-identical original bytes toward dp64
    checks["exactly_once_operate_release"] = (len(r.operate_releases) == 1)
    checks["operate_byte_identical"] = (len(r.operate_releases) >= 1
                                        and r.operate_releases[0][1] == r.original_operate)

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

    # fail-open when the qid3 reservoir is not ready: forward at T0, no hold, no J
    fo = eng.run_lifecycle(Scenario(T0=3000.0, j_index=6, app_seq=1, reservoir_ready=False))
    checks["fail_open_when_reservoir_not_ready"] = (
        fo.fail_open and len(fo.operate_releases) == 1
        and abs(fo.operate_releases[0][0] - 3000.0) < EPS and fo.J is None)

    # watchdog retires qid3 on no-OPERATE and on failed-SELECT, with NO output change
    wd_noop = eng.run_lifecycle(Scenario(T0=4000.0, j_index=3, operate_arrives=False))
    checks["watchdog_retire_no_operate"] = (wd_noop.watchdog_retired
                                            and not wd_noop.operate_releases
                                            and wd_noop.observable is None)
    wd_sel = eng.run_lifecycle(Scenario(T0=5000.0, j_index=3, select_ok=False))
    checks["watchdog_retire_failed_select"] = (wd_sel.watchdog_retired
                                               and not wd_sel.operate_releases
                                               and wd_sel.observable is None)

    # anti-subtraction: the observer CANNOT recover J (timestamps off) from any channel
    holds, _ = anti_subtraction_holds(OWNER, cfg, mutants)
    checks["observer_cannot_recover_J"] = holds

    return checks


# each mutant + the conformance check it is EXPECTED to break (a design invariant it violates)
MUTANTS: List[Tuple[str, str]] = [
    ("reanchor_ack_echo_to_release",
     "re-anchor ACK/echo to T0+J -> observer recovers J from response timing"),
    ("j_from_public_seq",
     "delay selected from a public DNP3 sequence -> observer predicts J"),
    ("missing_t0",
     "T0 not recorded -> deadlines undefined / anchored wrong"),
    ("duplicate_operate_release",
     "duplicate OPERATE release (retransmit) -> two physical operations"),
    ("hold_when_reservoir_not_ready",
     "qid3 not ready but OPERATE still held -> should fail-open, not hold"),
    ("tcp_timestamps_negotiated",
     "TCP timestamps negotiated -> observer recovers J from TSval (anti-subtraction INVALID)"),
    ("echo_before_ack",
     "response released before ACK -> ordering violation, R < A"),
    ("watchdog_no_retire",
     "no-OPERATE cleanup fails -> watchdog does not retire qid3"),
    ("retire_twice",
     "transaction retires twice (fails to retire exactly once)"),
]

EXPECT_BREAKS: Dict[str, str] = {
    "reanchor_ack_echo_to_release": "observer_cannot_recover_J",
    "j_from_public_seq": "observer_cannot_recover_J",
    "missing_t0": "t0_anchored_deadlines",
    "duplicate_operate_release": "exactly_once_operate_release",
    "hold_when_reservoir_not_ready": "fail_open_when_reservoir_not_ready",
    "tcp_timestamps_negotiated": "observer_cannot_recover_J",
    "echo_before_ack": "echo_after_ack_ordering",
    "watchdog_no_retire": "watchdog_retire_no_operate",
    "retire_twice": "retire_exactly_once",
}


def main() -> int:
    clean = run_conformance(frozenset())
    print("== CLEAN MODEL (BOR_RRC_DESIGN conformance) ==")
    for k, v in clean.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    clean_ok = all(clean.values())

    print("\n== MUTANTS (each MUST be KILLED: its expected invariant check flips to FAIL) ==")
    killed = {}
    for name, desc in MUTANTS:
        c = run_conformance(frozenset([name]))
        failed = [k for k, v in c.items() if not v]
        expect = EXPECT_BREAKS[name]
        killed[name] = (expect in failed)
        print("  [%s] %-30s expect_break=%-32s actual_failed=%s"
              % ("KILLED" if killed[name] else "SURVIVED", name, expect, failed or "NONE"))
        print("           %s" % desc)

    ok = clean_ok and all(killed.values())
    print("\nRESULT: %s  (clean=%s, mutants_killed=%d/%d)"
          % ("PASS" if ok else "FAIL", clean_ok, sum(killed.values()), len(MUTANTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
