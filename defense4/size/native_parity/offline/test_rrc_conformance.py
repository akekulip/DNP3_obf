#!/usr/bin/env python3
"""pytest conformance for rrc_emulator.py — the RRC section-9 asserts + mutant kills.

Run: pytest -q test_rrc_conformance.py   (or `python3 rrc_emulator.py` for the report).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rrc_emulator import run_conformance, MUTANTS  # noqa: E402


def test_clean_model_passes_all_section9_checks():
    checks = run_conformance(frozenset())
    failed = [k for k, v in checks.items() if not v]
    assert not failed, "clean model failed: %s" % failed
    # the section-9 obligations must all be present, not silently dropped
    for req in ("all_functions_arm_same_engine", "per_function_exp_ack", "held_to_deadline",
                "carve_on_release_pass", "exactly_rid1_and_rid2", "no_source_copy",
                "both_option_fixtures_28_21", "reassembly_byte_exact", "checksums_valid",
                "carve_type_agnostic", "select_retires_before_operate"):
        assert req in checks, "missing section-9 check %s" % req


def test_every_mutant_is_killed():
    for m in MUTANTS:
        checks = run_conformance(frozenset([m]))
        failed = [k for k, v in checks.items() if not v]
        assert failed, "mutant %s SURVIVED (no check failed)" % m


if __name__ == "__main__":
    test_clean_model_passes_all_section9_checks()
    test_every_mutant_is_killed()
    print("test_rrc_conformance: PASS")
