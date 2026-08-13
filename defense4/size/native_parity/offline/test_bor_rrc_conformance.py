#!/usr/bin/env python3
"""pytest conformance for bor_rrc_emulator.py — the BOR-in-RRC lifecycle conformance asserts
plus the 10 design mutants. Each mutant MUST be killed: the specific invariant check it violates
(EXPECT_BREAKS) flips to FAIL, either because the observer recovers J/native timing or a
lifecycle invariant breaks. Includes the qid3 READINESS RACE (BOR_RRC_DESIGN.md): under async
pktgen/TM arrival, both faithful policies (structural-guarantee, fail-open-without-holding) pass
and the naive race (`early_qid2_release`) is killed.

Run: pytest -q test_bor_rrc_conformance.py   (or `python3 test_bor_rrc_conformance.py` for the
full expected/actual report).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bor_rrc_emulator import (  # noqa: E402
    run_conformance, anti_subtraction_holds, observer_recover_J, readiness_conformance,
    _run_readiness, BORRRCEngine, BORConfig, Scenario, OWNER, MUTANTS, EXPECT_BREAKS, EPS,
)

# the conformance obligations that must all be present and pass on the clean model
REQUIRED_CHECKS = (
    "deadline_constraints_valid", "t0_anchored_deadlines", "reservoir_seeded_resident",
    "reservoir_resident_before_release",
    "exactly_once_operate_release", "operate_byte_identical", "echo_carved_28_21",
    "echo_byte_identical", "echo_after_ack_ordering", "retire_exactly_once",
    "exactly_once_under_retransmit", "fail_open_when_reservoir_not_ready",
    "watchdog_retire_no_operate", "watchdog_retire_failed_select", "observer_cannot_recover_J",
)


def test_clean_model_passes_all_conformance_checks():
    checks = run_conformance(frozenset())
    failed = [k for k, v in checks.items() if not v]
    assert not failed, "clean model failed: %s" % failed
    for req in REQUIRED_CHECKS:
        assert req in checks, "missing conformance check %s" % req


def test_clean_model_observer_cannot_recover_J():
    holds, channels = anti_subtraction_holds(OWNER, BORConfig(), frozenset())
    assert holds, "anti-subtraction must HOLD on the clean model; leaking channels=%s" % (
        [c for c, hit in channels.items() if hit])


def test_clean_timing_channel_yields_zero():
    # T0-anchored + constant R -> the response-timing observer recovers 0, not the true J
    eng = BORRRCEngine(OWNER, BORConfig(), frozenset())
    res = eng.run_lifecycle(Scenario(T0=1000.0, j_index=5, app_seq=3, t_physical=5.0))
    est = observer_recover_J(res.observable)
    assert abs(est.j_timing - 0.0) < EPS and abs(res.J - 10.0) < EPS
    assert est.j_tsval is None                     # timestamps off -> no TSval channel


def test_every_mutant_is_killed_by_its_expected_invariant():
    for name, _desc in MUTANTS:
        checks = run_conformance(frozenset([name]))
        failed = [k for k, v in checks.items() if not v]
        expect = EXPECT_BREAKS[name]
        assert expect in failed, (
            "mutant %s SURVIVED: expected check %s to FAIL, actual failed=%s"
            % (name, expect, failed))


def test_early_qid2_release_mutant_is_killed_by_readiness_invariant():
    # the new critical mutant: naive race -> held OPERATE escapes before qid3 is resident
    assert "early_qid2_release" in dict(MUTANTS)
    assert EXPECT_BREAKS["early_qid2_release"] == "reservoir_resident_before_release"
    checks = run_conformance(frozenset(["early_qid2_release"]))
    assert not checks["reservoir_resident_before_release"], (
        "early_qid2_release SURVIVED: reservoir_resident_before_release did not FAIL")


def test_readiness_two_faithful_policies_pass_and_naive_race_fails():
    # under async pktgen/TM arrival, both faithful policies avoid an early/unshaped hold
    checks = readiness_conformance()
    failed = [k for k, v in checks.items() if not v]
    assert not failed, "readiness conformance failed: %s" % failed
    assert checks["structural_guarantee_PASS"]
    assert checks["fail_open_unconfirmed_PASS"]
    assert checks["naive_race_FAIL_early_unshaped"]


def test_structural_guarantee_shapes_and_hides_native_timing():
    # qid3 confirmed resident before release -> shaped, observer sees the blob J + T_physical
    sg = _run_readiness("structural_guarantee")
    assert sg.qid3_confirmed_resident and sg.operate_release_shaped
    assert sg.reservoir_resident_before_release and not sg.fail_open
    obs = observer_recover_J(sg.observable)
    assert abs(obs.M - (sg.J + 5.0)) < EPS          # M is the inseparable blob, not native 5.0


def test_fail_open_without_holding_is_counted_and_unshaped():
    # residency unconfirmed at admission -> counted fail-open, no shaped-hold claim
    fo = _run_readiness("fail_open_unconfirmed")
    assert fo.fail_open and not fo.operate_release_shaped
    assert fo.reservoir_resident_before_release          # vacuous: no held-shaped claim
    assert fo.J is None and abs(fo.operate_releases[0][0] - 1000.0) < EPS


def test_naive_race_leaks_native_physical_time():
    # the bug: held OPERATE escapes unshaped -> observer recovers native T_physical (no J)
    nr = _run_readiness("naive_race")
    assert not nr.reservoir_resident_before_release and not nr.operate_release_shaped
    obs = observer_recover_J(nr.observable)
    assert abs(obs.M - 5.0) < EPS                    # native T_physical recovered, no J mixed in


def _report() -> int:
    clean = run_conformance(frozenset())
    print("== CLEAN MODEL: BOR-in-RRC conformance ==")
    for k in REQUIRED_CHECKS:
        print("  [%s] %s" % ("PASS" if clean.get(k) else "FAIL", k))
    clean_ok = all(clean.values()) and all(k in clean for k in REQUIRED_CHECKS)

    print("\n== READINESS RACE (async pktgen/TM; two faithful policies PASS, naive race FAILS) ==")
    rr = readiness_conformance()
    for k, v in rr.items():
        print("  [%s] %s" % ("PASS" if v else "FAIL", k))
    rr_ok = all(rr.values())

    print("\n== MUTANTS (expected/actual; each MUST be KILLED) ==")
    all_killed = True
    for name, desc in MUTANTS:
        checks = run_conformance(frozenset([name]))
        failed = [k for k, v in checks.items() if not v]
        expect = EXPECT_BREAKS[name]
        killed = expect in failed
        all_killed &= killed
        print("  [%s] %s" % ("KILLED" if killed else "SURVIVED", name))
        print("           %s" % desc)
        print("           expected FAIL : %s" % expect)
        print("           actual FAILED : %s" % (failed or "NONE (mutant undetected)"))
    print("\nRESULT: %s  (clean_all_pass=%s, readiness_all_pass=%s, mutants_killed=%s)"
          % ("PASS" if (clean_ok and rr_ok and all_killed) else "FAIL",
             clean_ok, rr_ok, all_killed))
    return 0 if (clean_ok and rr_ok and all_killed) else 1


if __name__ == "__main__":
    sys.exit(_report())
