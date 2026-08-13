#!/usr/bin/env python3
"""Phase-6 consolidated offline acceptance gate for the FAITHFUL two-pipe BOR+RRC.

This runner ASSERTS every gate listed in autonomous_overnight.md "Phase 6: Offline acceptance
gates" and prints each PASS/FAIL by name. It does NOT re-implement the mechanism: it drives the
three existing behavioral emulators and reuses their conformance checks + mutant suites, adding
only the few gate checks those suites did not already cover (invalid-deadline rejection, the
bounded-support bucket sweep, the no-internal-header relay check, and the teardown/clears-state
gate). The gates map to the emulators as:

  * bor_rrc_emulator.py              — the single-pipe faithful BOR-in-RRC lifecycle + observer +
                                       scale/seq-wrap drivers + the 12 required mutants.
  * bor_twopipe_faithful_emulator.py — the FAITHFUL two-pipe split: SELECT-prepare crossing,
                                       cross-pipe exactly-once (pipe0 + pipe1 dedup), the 8
                                       two-pipe mutants.
  * rrc_emulator.py                  — the frozen RRC regression (shared response engine, carve,
                                       reassembly, checksums).

Every gate is backed by real emulator output — a behavioral model is not a compile and a compile
is not silicon (BOR_RRC_DESIGN.md sections 8, 3). "FIN/RST clears state" is checked through the
shared retire/teardown path the design routes FIN/RST to (BOR_RRC_DESIGN.md section 6); the
emulators carry no distinct FIN/RST packet event, and that is stated where the gate prints.

Run: `$RESEARCH_PYTHON test_bor_acceptance_gate.py`  (pure stdlib; pytest functions also defined).
Exit 0 iff EVERY Phase-6 gate passes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bor_rrc_emulator import (  # noqa: E402
    run_conformance as bor_conf, BORRRCEngine, BORConfig, Scenario as BORScenario,
    OWNER, CODEBOOK, EPS, anti_subtraction_holds, run_scale_driver, run_seq_wrap_driver,
    first_operate_is_shaped, FAITHFUL_CFG, FAIL_OPEN_FIRST_CFG,
    REQUIRED_MUTANTS, EXPECT_BREAKS as BOR_EXPECT,
)
from bor_twopipe_faithful_emulator import (  # noqa: E402
    run_conformance as tp_conf, run_two_pipe, Scenario as TPScenario,
    run_seq_wrap_stray as tp_wrap, MUTANTS as TP_MUTANTS, EXPECT_BREAKS as TP_EXPECT,
    _operate_rx as tp_operate_rx,
)
from rrc_emulator import run_conformance as rrc_conf, MUTANTS as RRC_MUTANTS  # noqa: E402


# --------------------------------------------------------------------------- #
# gate ledger
# --------------------------------------------------------------------------- #
class Gates:
    def __init__(self) -> None:
        self.rows = []   # (name, passed, backing)

    def check(self, name: str, passed: bool, backing: str) -> bool:
        self.rows.append((name, bool(passed), backing))
        return bool(passed)

    def all_pass(self) -> bool:
        return all(p for _, p, _ in self.rows)

    def report(self) -> None:
        width = max(len(n) for n, _, _ in self.rows)
        for name, passed, backing in self.rows:
            print("  [%s] %-*s  <- %s" % ("PASS" if passed else "FAIL", width, name, backing))
        n_pass = sum(p for _, p, _ in self.rows)
        print("\n  %d/%d gates PASS" % (n_pass, len(self.rows)))


# --------------------------------------------------------------------------- #
# the individual gate evaluators (each returns (passed, backing))
# --------------------------------------------------------------------------- #
def _bor_clean():
    return bor_conf(frozenset())


def _tp_clean():
    return tp_conf(frozenset())


def g_first_operate_bor_shaped(bc, tc):
    # single-pipe: FIRST OPERATE after a clean start held+shaped; two-pipe: same; and the SR4
    # fail-open-first config is correctly NOT shaped (discrimination).
    ok = (bc["first_operate_shaped"] and tc["first_operate_shaped"]
          and first_operate_is_shaped(FAITHFUL_CFG) and not first_operate_is_shaped(FAIL_OPEN_FIRST_CFG))
    return ok, "bor.first_operate_shaped & twopipe.first_operate_shaped & SR4-discrimination"


def g_select_prepares_before_operate(bc, tc):
    ok = (tc["select_prepare_crosses_once"] and tc["epoch_resident_before_operate"]
          and bc["reservoir_seeded_resident"])
    return ok, "twopipe.select_prepare_crosses_once & epoch_resident_before_operate & bor.reservoir_seeded_resident"


def g_qid3_resident_before_qid2(bc, tc):
    ok = (bc["reservoir_resident_before_release"] and bc["reservoir_seeded_resident"]
          and tc["epoch_resident_before_operate"])
    return ok, "bor.reservoir_resident_before_release & twopipe.epoch_resident_before_operate"


def g_operate_byte_identical(bc, tc):
    ok = bc["operate_byte_identical"] and tc["released_byte_identical"]
    return ok, "bor.operate_byte_identical & twopipe.released_byte_identical"


def g_exactly_one_reaches_relay(bc, tc):
    ok = (bc["exactly_once_operate_release"] and tc["relay_receives_operate_exactly_once"]
          and tc["cross_pipe_operate_exactly_once"] and tc["released_via_pipe1_hold"])
    return ok, "bor.exactly_once_operate_release & twopipe.relay_receives_operate_exactly_once"


def g_top_release_t0_plus_j(bc, tc):
    ok = bc["t0_anchored_deadlines"] and tc["release_at_T0_plus_J"]
    return ok, "bor.t0_anchored_deadlines (release==T0+J) & twopipe.release_at_T0_plus_J"


def g_ack_at_t0_plus_a(bc, tc):
    # the single check t0_anchored_deadlines verifies ack_time==T0+A; twopipe ack_echo covers ACK.
    ok = bc["t0_anchored_deadlines"] and tc["ack_echo_T0_anchored"]
    return ok, "bor.t0_anchored_deadlines (ack==T0+A) & twopipe.ack_echo_T0_anchored"


def g_echo_at_t0_plus_r(bc, tc):
    ok = bc["t0_anchored_deadlines"] and bc["echo_after_ack_ordering"] and tc["ack_echo_T0_anchored"]
    return ok, "bor.t0_anchored_deadlines (echo==T0+R, R>=A) & twopipe.ack_echo_T0_anchored"


def g_echo_28_21(bc, tc):
    rc = rrc_conf(frozenset())
    ok = bc["echo_carved_28_21"] and tc["echo_carved_28_21"] and rc["both_option_fixtures_28_21"]
    return ok, "bor.echo_carved_28_21 & twopipe.echo_carved_28_21 & rrc.both_option_fixtures_28_21"


def g_reassembly_byte_exact(bc, tc):
    rc = rrc_conf(frozenset())
    ok = bc["echo_byte_identical"] and tc["echo_byte_identical"] and rc["reassembly_byte_exact"]
    return ok, "bor.echo_byte_identical & twopipe.echo_byte_identical & rrc.reassembly_byte_exact"


def g_checksums_valid(bc, tc):
    rc = rrc_conf(frozenset())
    # echo_byte_identical in both models includes the per-segment IPv4/TCP checksum verification.
    ok = bc["echo_byte_identical"] and tc["echo_byte_identical"] and rc["checksums_valid"]
    return ok, "bor/twopipe echo checksum-verified & rrc.checksums_valid"


def g_no_internal_header_leaves():
    # every frame the relay receives must be the byte-identical original/SELECT (xpipe STRIPPED),
    # never an internal cross-pipe (xpipe) wrapped frame. In the model relay_rx payloads are the
    # stripped originals, so payload==original is the proxy for the P4's STRIP_XPIPE at release.
    r = run_two_pipe(TPScenario())
    op_rx = tp_operate_rx(r.relay_rx)
    all_stripped = bool(r.relay_rx) and all(rr.payload == r.original for rr in r.relay_rx)
    op_stripped = bool(op_rx) and all(rr.payload == r.original for rr in op_rx)
    echo_native = (r.echo_reassembled is not None and r.echo_segments == (28, 21))
    ok = all_stripped and op_stripped and echo_native
    return ok, "twopipe relay_rx payloads == byte-identical original (xpipe stripped) + native echo"


def g_missing_preparation_fails_open(bc, tc):
    # (a) reservoir seeded but never filled -> fail open; (b) OPERATE with no prior SELECT -> fail open.
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    miss_select = eng.run_operate_only(BORScenario(T0=1234.0, j_index=5, app_seq=1))
    ok = (bc["fail_open_when_reservoir_not_ready"] and tc["fail_open_when_reservoir_not_ready"]
          and miss_select.fail_open and len(miss_select.operate_releases) == 1
          and miss_select.J is None)
    return ok, "bor/twopipe fail_open_when_reservoir_not_ready & bor.run_operate_only(no SELECT)->fail_open"


def g_invalid_deadline_rejected():
    # good set is admissible; each invalid set (A<=Jmax+ackbound, R<=Jmax+respbound, R<A) is rejected.
    good = BORConfig()                                        # A=16 R=20 Jmax=12 ackb=2 respb=3
    a_too_small = BORConfig(A=13.0)                           # 13 !> 12+2 -> reject
    r_too_small = BORConfig(R=15.0)                           # 15 !> 12+3 -> reject
    r_below_a = BORConfig(A=18.0, R=16.0)                     # R < A -> reject
    over_horizon = BORConfig(A=60.0, R=61.0, watchdog_horizon=50.0)  # exceeds fail-open horizon
    ok = (good.deadlines_valid()
          and not a_too_small.deadlines_valid()
          and not r_too_small.deadlines_valid()
          and not r_below_a.deadlines_valid()
          and not over_horizon.deadlines_valid())
    return ok, "BORConfig.deadlines_valid(): good=True; A<=Jmax+ackb / R<=Jmax+respb / R<A / >horizon all rejected"


def g_timestamp_cannot_claim_antisub():
    holds_off, _ = anti_subtraction_holds(OWNER, BORConfig(tcp_ts_enabled=False), frozenset())
    holds_on, ch_on = anti_subtraction_holds(OWNER, BORConfig(tcp_ts_enabled=True), frozenset())
    # with timestamps OFF anti-subtraction holds; with timestamps NEGOTIATED it must NOT hold
    # (the observer recovers J from the stale TSval), i.e. the design cannot claim timestamp-safe.
    ok = holds_off and (not holds_on) and ch_on["tcp_tsval"]
    return ok, "anti_subtraction_holds: ts-off=True, ts-on=False via tcp_tsval channel"


def g_public_seq_does_not_predict_j():
    scale = run_scale_driver(1000)
    clean = bor_conf(frozenset())
    leak = bor_conf(frozenset(["public_sequence_selects_j"]))
    # the faithful design: the public predictor is NOT an oracle; and IF J were derived from the
    # public sequence (the mutant) the observer WOULD recover it (observer_cannot_recover_J -> False).
    ok = (scale["public_not_oracle"] and clean["observer_cannot_recover_J"]
          and not leak["observer_cannot_recover_J"])
    return ok, "scale.public_not_oracle & clean.observer_cannot_recover_J & public_sequence_selects_j mutant leaks"


def g_random_buckets_bounded_support():
    # every codebook bucket is selectable and yields exactly its configured delay; nothing outside
    # the codebook is ever produced (bounded support == the configured codebook).
    eng_cfg = BORConfig()
    used = set()
    all_in_support = True
    for idx in range(len(CODEBOOK)):
        eng = BORRRCEngine(OWNER, eng_cfg, frozenset())
        r = eng.run_lifecycle(BORScenario(T0=1000.0 + idx, j_index=idx, app_seq=idx))
        if r.J is None or abs(r.J - float(CODEBOOK[idx])) > EPS:
            all_in_support = False
        else:
            used.add(r.J)
        if r.J is not None and r.J not in {float(c) for c in CODEBOOK}:
            all_in_support = False
    ok = all_in_support and used == {float(c) for c in CODEBOOK}
    return ok, "each j_index -> codebook[j_index]; selected-J set == configured bounded support %s" % (CODEBOOK,)


def g_retransmit_no_second_operation(bc, tc):
    ok = (bc["exactly_once_under_retransmit"] and tc["retransmit_relay_operate_once"]
          and tc["retransmit_operate_crosses_once"]
          and tc["double_cross_backstopped_by_pipe1_dedup"])
    return ok, "bor.exactly_once_under_retransmit & twopipe retransmit/double-cross exactly-once"


def g_fin_rst_clears_state():
    # BOR_RRC_DESIGN.md section 6 routes FIN/RST to the shared retire/teardown path (there is no
    # distinct FIN/RST packet event in the emulators). Assert that teardown CLEARS state: after a
    # full lifecycle retire, the engine holds no pending epoch and a later stray OPERATE fails open.
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    eng.run_lifecycle(BORScenario(T0=1000.0, j_index=5, app_seq=2))
    cleared = (not eng.bor_pending) and eng.bor_epoch is None and (not eng.qid3_resident)
    stray = eng.run_operate_only(BORScenario(T0=2000.0, j_index=4, app_seq=9))
    ok = cleared and stray.fail_open
    return ok, "shared retire/teardown clears bor_pending/epoch/ready; later stray OPERATE fails open (design section 6)"


def g_at_least_1000_transactions():
    scale = run_scale_driver(1000)
    ok = (scale["n"] == 1000 and scale["all_ok"] and all(v == 1000 for v in scale["counts"].values()))
    return ok, "bor.run_scale_driver(1000).all_ok, every per-txn invariant 1000/1000"


def g_multiple_seq_wraps():
    wrap = run_seq_wrap_driver(4)
    tp_ok = tp_wrap(frozenset())
    ok = (wrap["all_ok"] and wrap["total"] == 64 and wrap["shaped_once"] == 64
          and wrap["stray_fail_open"] and tp_ok)
    return ok, "bor.run_seq_wrap_driver(4).all_ok (4x0..15) & twopipe.seq_wrap_stray_fails_open"


def g_required_mutants_killed():
    # single-pipe: each of the 12 REQUIRED mutants breaks its expected invariant.
    bor_ok = True
    bor_detail = []
    for m in REQUIRED_MUTANTS:
        c = bor_conf(frozenset([m]))
        failed = [k for k, v in c.items() if not v]
        killed = BOR_EXPECT[m] in failed
        bor_ok &= killed
        if not killed:
            bor_detail.append(m)
    # two-pipe: each of the 8 mutants breaks its expected invariant (replicate the emulator's
    # per-mutant dispatch: first_operate_fail_open_mode is a scenario mode, not a state flag).
    tp_ok = True
    tp_detail = []
    for name, expect, _desc in TP_MUTANTS:
        if name == "first_operate_fail_open_mode":
            killed = not run_two_pipe(TPScenario(first_operate_fail_open=True)).first_operate_shaped
        else:
            c = dict(tp_conf(frozenset([name])))
            c["seq_wrap_stray_fails_open"] = tp_wrap(frozenset([name]))
            killed = expect in [k for k, v in c.items() if not v]
        tp_ok &= killed
        if not killed:
            tp_detail.append(name)
    ok = bor_ok and tp_ok
    backing = ("12/12 required bor mutants + 8/8 twopipe mutants killed"
               if ok else "UNKILLED bor=%s twopipe=%s" % (bor_detail, tp_detail))
    return ok, backing


def g_frozen_rrc_regression_green():
    rc = rrc_conf(frozenset())
    clean_ok = all(rc.values())
    mut_ok = True
    survived = []
    for m in RRC_MUTANTS:
        c = rrc_conf(frozenset([m]))
        if not any(not v for v in c.values()):
            mut_ok = False
            survived.append(m)
    # the BOR model's frozen prior conformance checks must also all be green (no regression).
    bc = bor_conf(frozenset())
    bor_green = all(bc.values())
    ok = clean_ok and mut_ok and bor_green
    backing = ("rrc clean all-pass + 8/8 rrc mutants killed + bor clean all-pass"
               if ok else "rrc_clean=%s rrc_survived=%s bor_clean=%s" % (clean_ok, survived, bor_green))
    return ok, backing


def g_shared_response_engine():
    rc = rrc_conf(frozenset())
    ok = (rc["all_functions_arm_same_engine"] and rc["per_function_exp_ack"]
          and rc["carve_type_agnostic"] and rc["select_retires_before_operate"])
    return ok, "rrc.all_functions_arm_same_engine & carve_type_agnostic & select_retires_before_operate"


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def run_gates() -> Gates:
    bc = _bor_clean()
    tc = _tp_clean()
    g = Gates()

    g.check("first_operate_after_clean_start_is_BOR_shaped", *g_first_operate_bor_shaped(bc, tc))
    g.check("select_preparation_completes_before_operate", *g_select_prepares_before_operate(bc, tc))
    g.check("qid3_confirmed_resident_before_qid2_admission", *g_qid3_resident_before_qid2(bc, tc))
    g.check("original_operate_byte_identical", *g_operate_byte_identical(bc, tc))
    g.check("exactly_one_original_reaches_relay", *g_exactly_one_reaches_relay(bc, tc))
    g.check("T_OP_RELEASE_equals_T0_plus_J", *g_top_release_t0_plus_j(bc, tc))
    g.check("ACK_release_anchored_to_T0_plus_A", *g_ack_at_t0_plus_a(bc, tc))
    g.check("echo_release_anchored_to_T0_plus_R", *g_echo_at_t0_plus_r(bc, tc))
    g.check("echo_remains_28_21", *g_echo_28_21(bc, tc))
    g.check("reassembly_byte_exact", *g_reassembly_byte_exact(bc, tc))
    g.check("ip_tcp_checksums_valid", *g_checksums_valid(bc, tc))
    g.check("no_internal_xpipe_header_leaves_switch", *g_no_internal_header_leaves())
    g.check("missing_preparation_fails_open_and_counts", *g_missing_preparation_fails_open(bc, tc))
    g.check("invalid_deadline_config_rejected", *g_invalid_deadline_rejected())
    g.check("timestamp_negotiated_cannot_claim_antisubtraction", *g_timestamp_cannot_claim_antisub())
    g.check("public_dnp3_sequence_does_not_predict_J", *g_public_seq_does_not_predict_j())
    g.check("random_buckets_match_bounded_support", *g_random_buckets_bounded_support())
    g.check("retransmission_never_causes_second_operation", *g_retransmit_no_second_operation(bc, tc))
    g.check("fin_rst_clears_state", *g_fin_rst_clears_state())
    g.check("at_least_1000_modeled_transactions_pass", *g_at_least_1000_transactions())
    g.check("multiple_4bit_sequence_wraps_pass", *g_multiple_seq_wraps())
    g.check("every_required_mutant_killed", *g_required_mutants_killed())
    g.check("frozen_rrc_regression_stays_green", *g_frozen_rrc_regression_green())
    g.check("read_select_operate_share_response_engine", *g_shared_response_engine())
    return g


# --------------------------------------------------------------------------- #
# pytest entry points (pytest is optional; the __main__ report is the primary path)
# --------------------------------------------------------------------------- #
def test_all_phase6_gates_pass():
    g = run_gates()
    failed = [n for n, p, _ in g.rows if not p]
    assert not failed, "Phase-6 gates FAILED: %s" % failed


def main() -> int:
    print("== PHASE 6 OFFLINE ACCEPTANCE GATES (FAITHFUL two-pipe BOR+RRC) ==")
    print("   sources: bor_rrc_emulator.py, bor_twopipe_faithful_emulator.py, rrc_emulator.py")
    print("   (a behavioral model is not a compile; a compile is not silicon)\n")
    g = run_gates()
    g.report()
    ok = g.all_pass()
    print("\nRESULT: %s" % ("PASS  (all Phase-6 gates met)" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
