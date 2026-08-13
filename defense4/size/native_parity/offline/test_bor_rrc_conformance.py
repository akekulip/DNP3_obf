#!/usr/bin/env python3
"""pytest conformance for bor_rrc_emulator.py — the BOR-in-RRC lifecycle conformance asserts
plus the 9 design mutants. Each mutant MUST be killed: the specific invariant check it violates
(EXPECT_BREAKS) flips to FAIL, either because the observer recovers J or a lifecycle invariant
breaks.

Run: pytest -q test_bor_rrc_conformance.py   (or `python3 test_bor_rrc_conformance.py` for the
full expected/actual report).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bor_rrc_emulator import (  # noqa: E402
    run_conformance, anti_subtraction_holds, observer_recover_J,
    BORRRCEngine, BORConfig, Scenario, OWNER, MUTANTS, EXPECT_BREAKS, EPS,
)

# the conformance obligations that must all be present and pass on the clean model
REQUIRED_CHECKS = (
    "deadline_constraints_valid", "t0_anchored_deadlines", "reservoir_seeded_resident",
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


def _report() -> int:
    clean = run_conformance(frozenset())
    print("== CLEAN MODEL: BOR-in-RRC conformance ==")
    for k in REQUIRED_CHECKS:
        print("  [%s] %s" % ("PASS" if clean.get(k) else "FAIL", k))
    clean_ok = all(clean.values()) and all(k in clean for k in REQUIRED_CHECKS)

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
    print("\nRESULT: %s  (clean_all_pass=%s, mutants_killed=%s)"
          % ("PASS" if (clean_ok and all_killed) else "FAIL", clean_ok, all_killed))
    return 0 if (clean_ok and all_killed) else 1


if __name__ == "__main__":
    sys.exit(_report())
