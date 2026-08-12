#!/usr/bin/env python3
"""Automated mutation harness for the transport-translation oracle.

The README once called the fixes "mutation-checked" with no committed harness -- narrative,
not evidence. This IS the harness. For every critical transport invariant it:

  1. copies the offline source + both test suites into a fresh temp dir,
  2. applies ONE behavior-reverting source mutation (re-introducing a specific bug),
  3. runs BOTH suites (legacy + repairs) against the mutated source,
  4. proves the mutation is KILLED: at least one NAMED test fails, and the specific
     test that is meant to defend that invariant is among the failures.

A mutation that SURVIVES (no test fails) is an UNDEFENDED invariant -> the harness fails.
A mutation whose `old` text is missing or non-unique is source drift -> harness error.
The baseline (no mutation) must pass cleanly, proving the temp tree is runnable.

Output is machine-readable. Run:
    python3 mutation_harness.py            # human summary + exit code
    python3 mutation_harness.py --json     # + MACHINE_MUTATION_SUMMARY {...}
No hardcoded absolute paths (module-relative), no network, no P4, stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC_FILES = [
    "transport_oracle.py",
    "stream_reconstruction.py",
    "test_transport_oracle.py",
    "test_transport_repairs.py",
]
TEST_MODULES = ("test_transport_oracle", "test_transport_repairs")

_RUNNER = (
    "import json, unittest\n"
    "loader = unittest.TestLoader()\n"
    "suite = unittest.TestSuite()\n"
    "for mod in %r:\n"
    "    suite.addTests(loader.loadTestsFromName(mod))\n"
    "total = suite.countTestCases()\n"
    "res = unittest.TestResult()\n"
    "suite.run(res)\n"
    "bad = sorted([t.id() for t, _ in res.failures] + [t.id() for t, _ in res.errors])\n"
    "print('RESULT_JSON ' + json.dumps({'total': total, 'failed': bad}))\n"
) % (TEST_MODULES,)


# Each mutation reverts one repaired invariant. `old` must occur EXACTLY once in `file`.
# `expected_killer` is the named test that must die when the invariant is broken.
MUTATIONS = [
    {
        "id": "M01_retx_no_reemit",
        "invariant": "a retransmit RE-EMITS the inserted bytes (audit bug: inserted=committed)",
        "file": "transport_oracle.py",
        "old": "inserted_len = sum(len(e.data) for e in ins)",
        "new": "inserted_len = committed",
        "expected_killer": "test_retx_switch_reinserts_when_segment_carries_no_insert",
    },
    {
        "id": "M02_template_conflict_to_idempotent",
        "invariant": "same boundary+size, different template_id is a CONFLICT not idempotent",
        "file": "transport_oracle.py",
        "old": "if existing.size == size and existing.template_id == template_id:",
        "new": "if existing.size == size:",
        "expected_killer": "test_template_conflict_different_id_not_idempotent",
    },
    {
        "id": "M03_sack_trusts_data_segment",
        "invariant": "SACK eligibility learned at handshake, never trusted from a data segment",
        "file": "transport_oracle.py",
        "old": "learned_sack = self._sack_hint.get(seg.flow, False)",
        "new": "learned_sack = seg.sack_permitted",
        "expected_killer": "test_sacklearn_syn_negotiated_rejects_insertion",
    },
    {
        "id": "M04_reuse_no_new_epoch_guard",
        "invariant": "new-incarnation packets never translated with the old ledger",
        "file": "transport_oracle.py",
        "old": "if fl is not None and fl.reuse_pending and self._reuse_is_new_incarnation(fl, seg):",
        "new": "if False and fl is not None and fl.reuse_pending and self._reuse_is_new_incarnation(fl, seg):",
        "expected_killer": "test_reuse_new_epoch_not_translated_with_old_ledger",
    },
    {
        "id": "M05_sweep_never_reclaims",
        "invariant": "wall-clock sweep reclaims a silent flow (no state leak)",
        "file": "transport_oracle.py",
        "old": "if occ is not None and self.wall - occ.last_seen >= self.idle_horizon:",
        "new": "if occ is not None and False:",
        "expected_killer": "test_sweep_reclaims_silent_flow",
    },
    {
        "id": "M06_timewait_no_quarantine",
        "invariant": "delayed duplicate after retirement quarantined (no phantom epoch)",
        "file": "transport_oracle.py",
        "old": "if fl is None and self._tombstone_is_delayed_dup(seg):",
        "new": "if False and fl is None and self._tombstone_is_delayed_dup(seg):",
        "expected_killer": "test_timewait_delayed_dup_after_rst_native",
    },
    {
        "id": "M07_retire_on_both_fins_seen",
        "invariant": "state retained until both FINs ACKED; final ACK translated not native",
        "file": "transport_oracle.py",
        "old": " and (both_acked or timed_out):",
        "new": ":",
        "expected_killer": "test_fin_each_side_acked_final_ack_translated",
    },
    {
        "id": "M08_emit_double_at_segment_start",
        "invariant": "boundary-emit convention (start<b<=end): no double emission across segments",
        "file": "transport_oracle.py",
        "old": "if i > 0:",
        "new": "if i >= 0:",
        "expected_killer": "test_overlap_adjacent_segments_emit_shared_boundary_once",
    },
    {
        "id": "M09_ack_inside_pad_no_snap",
        "invariant": "a cumulative ACK landing inside a pad snaps to the boundary (partial)",
        "file": "transport_oracle.py",
        "old": "if a_off < tstart + e.size:",
        "new": "if a_off < tstart + 0:",
        "expected_killer": "test_ackpos_inside_pad",
    },
    {
        "id": "M10_owner_ignores_full_key",
        "invariant": "full-key ownership detects a hash collision and denies the intruder",
        "file": "transport_oracle.py",
        "old": "matched = (occ.full_key == flow)",
        "new": "matched = True",
        "expected_killer": "test_owner2_hash_collision_denies_intruder_preserves_incumbent",
    },
    {
        "id": "M11_seq_no_delta",
        "invariant": "own-stream seq translation adds the cumulative insertion delta",
        "file": "transport_oracle.py",
        "old": "seq_out = fl.to_wire(d, led.translate_seq(off))",
        "new": "seq_out = fl.to_wire(d, off)",
        "expected_killer": "test_seqack_two_sequential_transforms_cumulative",
    },
    {
        "id": "M12_ack_no_deshift",
        "invariant": "opposite-stream ACK inverse de-shifts by the crossed insertions",
        "file": "transport_oracle.py",
        "old": "cum += e.size ",
        "new": "cum += 0 ",
        "expected_killer": "test_ackpos_after_pad",
    },
]


def _run_suite(workdir: str) -> dict:
    """Run both suites in workdir via a child interpreter; return {'total','failed'}."""
    proc = subprocess.run(
        [sys.executable, "-c", _RUNNER],
        cwd=workdir, capture_output=True, text=True, timeout=120,
    )
    line = ""
    for ln in proc.stdout.splitlines():
        if ln.startswith("RESULT_JSON "):
            line = ln[len("RESULT_JSON "):]
    if not line:
        return {"total": 0, "failed": ["<runner-error>"], "stderr": proc.stderr[-800:]}
    return json.loads(line)


def _stage(workdir: str) -> None:
    for f in SRC_FILES:
        shutil.copy2(os.path.join(HERE, f), os.path.join(workdir, f))


def _apply(workdir: str, mut: dict) -> str:
    """Apply one mutation; return '' on success or an error string (drift)."""
    path = os.path.join(workdir, mut["file"])
    with open(path, "r") as fh:
        text = fh.read()
    n = text.count(mut["old"])
    if n != 1:
        return f"expected exactly 1 occurrence of target, found {n} (source drift)"
    with open(path, "w") as fh:
        fh.write(text.replace(mut["old"], mut["new"], 1))
    return ""


def run(verbose: bool = True) -> dict:
    # Baseline: unmutated copy must pass cleanly.
    base_dir = tempfile.mkdtemp(prefix="mut_base_")
    try:
        _stage(base_dir)
        baseline = _run_suite(base_dir)
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
    baseline_ok = baseline["failed"] == []

    results = []
    for mut in MUTATIONS:
        wd = tempfile.mkdtemp(prefix="mut_")
        try:
            _stage(wd)
            drift = _apply(wd, mut)
            if drift:
                rec = {"id": mut["id"], "invariant": mut["invariant"], "applied": False,
                       "killed": False, "expected_killer": mut["expected_killer"],
                       "expected_killer_died": False, "failing_tests": [], "error": drift}
            else:
                out = _run_suite(wd)
                failed = out["failed"]
                killer_died = any(fid.endswith(mut["expected_killer"]) for fid in failed)
                rec = {"id": mut["id"], "invariant": mut["invariant"], "applied": True,
                       "killed": len(failed) > 0, "expected_killer": mut["expected_killer"],
                       "expected_killer_died": killer_died,
                       "failing_tests": failed}
        finally:
            shutil.rmtree(wd, ignore_errors=True)
        results.append(rec)
        if verbose:
            status = "KILLED" if (rec["applied"] and rec["killed"]
                                  and rec["expected_killer_died"]) else "SURVIVED/ERROR"
            print(f"  [{status:14}] {rec['id']}: {len(rec['failing_tests'])} test(s) died"
                  + ("" if not rec.get("error") else f"  ERROR: {rec['error']}"))

    all_killed = all(r["applied"] and r["killed"] and r["expected_killer_died"] for r in results)
    harness_pass = baseline_ok and all_killed and len(results) == len(MUTATIONS)
    summary = {
        "harness": "mutation_harness",
        "baseline_total": baseline["total"],
        "baseline_clean": baseline_ok,
        "mutations_total": len(results),
        "mutations_killed": sum(1 for r in results if r["applied"] and r["killed"]
                                and r["expected_killer_died"]),
        "mutations_survived": [r["id"] for r in results
                               if not (r["applied"] and r["killed"] and r["expected_killer_died"])],
        "harness_pass": harness_pass,
        "results": results,
    }
    return summary


if __name__ == "__main__":
    want_json = "--json" in sys.argv
    print("mutation harness: reverting each critical invariant, proving a named test dies")
    s = run(verbose=True)
    print(f"\nbaseline clean: {s['baseline_clean']} ({s['baseline_total']} tests)")
    print(f"mutations killed: {s['mutations_killed']}/{s['mutations_total']}   "
          f"harness_pass: {s['harness_pass']}")
    if s["mutations_survived"]:
        print(f"SURVIVING MUTANTS (undefended invariants): {s['mutations_survived']}")
    if want_json:
        print("MACHINE_MUTATION_SUMMARY " + json.dumps(s))
    sys.exit(0 if s["harness_pass"] else 1)
