#!/usr/bin/env python3
"""Conformance for bor_rrc_emulator.py — the FAITHFUL BOR-in-RRC lifecycle (BOR_RRC_DESIGN.md
section 3, "Faithful readiness — SELECT prepares a BOR epoch"), its mutants, the first-OPERATE
discrimination, and the scale + sequence-wrap drivers.

WHAT THIS PROVES.
  * The faithful model (SELECT prepares a BOR epoch = a separate INTERNAL identity, not the 4-bit
    DNP3 generation) passes all frozen conformance checks AND the new BOR-faithfulness checks.
  * `first_operate_shaped`: with the faithful select-prepared config the FIRST OPERATE after a
    clean start is held and shaped; with a `fail_open_first` config that mimics the current SR4
    probe (read op_ready BEFORE arming qid3) the first OPERATE is NOT shaped -> that check FAILS,
    which is how the emulator DETECTS the SR4 defect (SAFE BYPASS != successful shaping).
  * Every required mutant is killed: the specific invariant it violates flips to FAIL.
  * >= 1000 modeled faithful transactions and multiple 4-bit DNP3 sequence wraps all pass, and
    the frozen prior conformance checks stay green.

REPORT CORRECTION (see bor_rrc_emulator._note): the SR4 P4 stage is a RESOURCE PROBE
(fail-open-only), not BOR protection. A combined build fusing SELECT-prepared readiness with a
leak-safe random J selector has NOT yet been compiled on bf-p4c — that is the P4 agent's job;
this is a behavioral model only (a compile is not silicon).

pytest is not installed in the research venv, so run this file directly for the full report:
    $RESEARCH_PYTHON test_bor_rrc_conformance.py
(pytest test functions are also defined, for environments that have pytest.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bor_rrc_emulator import (  # noqa: E402
    run_conformance, anti_subtraction_holds, observer_recover_J, first_operate_is_shaped,
    run_scale_driver, run_seq_wrap_driver, BORRRCEngine, BORConfig, Scenario, OWNER,
    MUTANTS, REQUIRED_MUTANTS, EXPECT_BREAKS, EPS, FAITHFUL_CFG, FAIL_OPEN_FIRST_CFG,
)

# the conformance obligations that must all be present and pass on the faithful model.
# The first 15 are the FROZEN prior checks; the last 6 are the new BOR-faithfulness checks.
FROZEN_CHECKS = (
    "deadline_constraints_valid", "t0_anchored_deadlines", "reservoir_seeded_resident",
    "reservoir_resident_before_release", "exactly_once_operate_release", "operate_byte_identical",
    "echo_carved_28_21", "echo_byte_identical", "echo_after_ack_ordering", "retire_exactly_once",
    "exactly_once_under_retransmit", "fail_open_when_reservoir_not_ready",
    "watchdog_retire_no_operate", "watchdog_retire_failed_select", "observer_cannot_recover_J",
)
NEW_CHECKS = (
    "first_operate_shaped", "ready_implies_reservoir_resident", "no_magic_buffer_storage",
    "no_source_copy_to_relay", "ready_cleared_on_retire", "no_stale_ready_after_seq_wrap",
)
REQUIRED_CHECKS = FROZEN_CHECKS + NEW_CHECKS


def test_faithful_model_passes_all_conformance_checks():
    checks = run_conformance(frozenset())
    failed = [k for k, v in checks.items() if not v]
    assert not failed, "faithful model failed: %s" % failed
    for req in REQUIRED_CHECKS:
        assert req in checks, "missing conformance check %s" % req


def test_frozen_prior_checks_stay_green():
    checks = run_conformance(frozenset())
    for req in FROZEN_CHECKS:
        assert checks.get(req) is True, "frozen prior check regressed: %s" % req


def test_first_operate_shaped_faithful_vs_fail_open_first():
    # faithful select-prepared config: the FIRST OPERATE is held and shaped
    assert first_operate_is_shaped(FAITHFUL_CFG) is True
    # fail_open_first (SR4) config: the first OPERATE fails open -> the check FAILS (detected)
    assert first_operate_is_shaped(FAIL_OPEN_FIRST_CFG) is False


def test_faithful_model_observer_cannot_recover_J():
    holds, channels = anti_subtraction_holds(OWNER, BORConfig(), frozenset())
    assert holds, "anti-subtraction must HOLD on the faithful model; leaking channels=%s" % (
        [c for c, hit in channels.items() if hit])


def test_faithful_timing_channel_yields_zero():
    # T0-anchored + constant R -> the response-timing observer recovers 0, not the true J
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    res = eng.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3, t_physical=5.0))
    est = observer_recover_J(res.observable)
    assert abs(est.j_timing - 0.0) < EPS and abs(res.J - 10.0) < EPS
    assert est.j_tsval is None                     # timestamps off -> no TSval channel


def test_every_mutant_is_killed_by_its_expected_invariant():
    for name, _expect, _desc in MUTANTS:
        checks = run_conformance(frozenset([name]))
        failed = [k for k, v in checks.items() if not v]
        expect = EXPECT_BREAKS[name]
        assert expect in failed, (
            "mutant %s SURVIVED: expected check %s to FAIL, actual failed=%s"
            % (name, expect, failed))


def test_all_required_mutants_present_and_killed():
    names = {name for name, _, _ in MUTANTS}
    for m in REQUIRED_MUTANTS:
        assert m in names, "required mutant missing: %s" % m
        checks = run_conformance(frozenset([m]))
        assert EXPECT_BREAKS[m] in [k for k, v in checks.items() if not v], (
            "required mutant %s not killed by %s" % (m, EXPECT_BREAKS[m]))


def test_magic_buffer_mutant_is_caught():
    # a design that claims to buffer the original with no hardware storage path must be caught
    checks = run_conformance(frozenset(["magic_buffer_until_ready"]))
    assert not checks["no_magic_buffer_storage"]


def test_source_copy_leak_mutant_is_caught():
    checks = run_conformance(frozenset(["source_copy_leaks_to_relay"]))
    assert not checks["no_source_copy_to_relay"]


def test_stale_ready_after_seq_wrap_mutant_is_caught():
    checks = run_conformance(frozenset(["stale_ready_after_seq_wrap"]))
    assert not checks["no_stale_ready_after_seq_wrap"]


def test_ready_not_cleared_on_retire_mutant_is_caught():
    checks = run_conformance(frozenset(["ready_not_cleared_on_retire"]))
    assert not checks["ready_cleared_on_retire"]


def test_ready_without_reservoir_mutant_is_caught():
    checks = run_conformance(frozenset(["ready_without_reservoir"]))
    assert not checks["ready_implies_reservoir_resident"]


def test_early_qid2_release_mutant_is_killed_by_readiness_invariant():
    checks = run_conformance(frozenset(["early_qid2_release"]))
    assert not checks["reservoir_resident_before_release"]


def test_first_operate_always_fail_open_mutant_breaks_first_operate_shaped():
    checks = run_conformance(frozenset(["first_operate_always_fail_open"]))
    assert not checks["first_operate_shaped"]


def test_scale_driver_1000_transactions_all_pass():
    scale = run_scale_driver(1000)
    assert scale["n"] == 1000
    assert all(v == 1000 for v in scale["counts"].values()), scale["counts"]
    assert scale["public_not_oracle"] is True
    assert scale["all_ok"] is True


def test_sequence_wrap_driver_all_pass():
    wrap = run_seq_wrap_driver(4)
    assert wrap["total"] == 64 and wrap["shaped_once"] == 64
    assert wrap["stray_fail_open"] is True and wrap["op_failure_count"] >= 1
    assert wrap["all_ok"] is True


def _report() -> int:
    clean = run_conformance(frozenset())
    print("== FAITHFUL MODEL: BOR-in-RRC conformance (FROZEN + new BOR-faithfulness checks) ==")
    for k in REQUIRED_CHECKS:
        tag = "frozen" if k in FROZEN_CHECKS else "new"
        print("  [%s] %-34s (%s)" % ("PASS" if clean.get(k) else "FAIL", k, tag))
    clean_ok = all(clean.values()) and all(k in clean for k in REQUIRED_CHECKS)

    print("\n== FIRST-OPERATE DISCRIMINATION ==")
    faithful = first_operate_is_shaped(FAITHFUL_CFG)
    sr4 = first_operate_is_shaped(FAIL_OPEN_FIRST_CFG)
    print("  [%s] faithful select_prepared -> first_operate_shaped = %s" %
          ("PASS" if faithful else "FAIL", faithful))
    print("  [%s] fail_open_first (SR4)     -> first_operate_shaped = %s (check FAILS: detected)" %
          ("PASS" if not sr4 else "FAIL", sr4))
    disc_ok = faithful and not sr4

    print("\n== SCALE DRIVER (>= 1000 modeled faithful transactions) ==")
    scale = run_scale_driver(1000)
    print("  n=%d counts=%s public_hits=%d public_not_oracle=%s"
          % (scale["n"], scale["counts"], scale["public_hits"], scale["public_not_oracle"]))
    print("  [%s] scale_driver_all_ok" % ("PASS" if scale["all_ok"] else "FAIL"))

    print("\n== SEQUENCE-WRAP DRIVER (4 full 0..15 wraps + stray wrapped OPERATE) ==")
    wrap = run_seq_wrap_driver(4)
    print("  total=%d shaped_once=%d stray_fail_open=%s op_failure_count=%d"
          % (wrap["total"], wrap["shaped_once"], wrap["stray_fail_open"], wrap["op_failure_count"]))
    print("  [%s] seq_wrap_driver_all_ok" % ("PASS" if wrap["all_ok"] else "FAIL"))

    print("\n== MUTANTS (expected/actual; each MUST be KILLED) ==")
    all_killed = True
    required_killed = True
    for name, expect, desc in MUTANTS:
        checks = run_conformance(frozenset([name]))
        failed = [k for k, v in checks.items() if not v]
        killed = expect in failed
        all_killed &= killed
        is_req = name in REQUIRED_MUTANTS
        if is_req:
            required_killed &= killed
        print("  [%s] %-38s (%s)" % ("KILLED" if killed else "SURVIVED", name,
                                     "REQUIRED" if is_req else "legacy"))
        print("           %s" % desc)
        print("           expected FAIL : %s" % expect)
        print("           actual FAILED : %s" % (failed or "NONE (mutant undetected)"))

    ok = clean_ok and disc_ok and bool(scale["all_ok"]) and bool(wrap["all_ok"]) and all_killed
    print("\nRESULT: %s  (clean_all_pass=%s, discrimination=%s, scale=%s, seq_wrap=%s, "
          "required_mutants_killed=%s, all_mutants_killed=%s)"
          % ("PASS" if ok else "FAIL", clean_ok, disc_ok, scale["all_ok"], wrap["all_ok"],
             required_killed, all_killed))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(_report())
