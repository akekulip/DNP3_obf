#!/usr/bin/env python3
"""Gate A orchestrator for the transport-translation oracle repair.

Runs the whole verification and emits ONE honest verdict plus a machine-readable run
manifest (input hashes + per-suite results + mutation results + an output hash). Gate A
opens ONLY if every one of these holds:

  * the legacy suite passes (every required area) with zero failures,
  * the repair suite passes (every required area) with zero failures,
  * the scenario demo exits 0 (mainline + byte-exact reconstruction),
  * the mandatory tuple-reuse counterexample is fixed (its named test passes),
  * the mutation harness kills EVERY critical-invariant mutant (baseline clean).

Paths are resolved at runtime relative to this file and the repo root (found by walking up
to the `.git` entry, which is a FILE in a worktree); no absolute paths are embedded in the
manifest. Stdlib only, no network, no P4.

Run:  python3 gate_a.py            # human verdict + writes gate_results/*.json
      python3 gate_a.py --json     # + MACHINE_GATE_A {...} on stdout
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

import mutation_harness

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT_FILES = [
    "transport_oracle.py",
    "stream_reconstruction.py",
    "test_transport_oracle.py",
    "test_transport_repairs.py",
    "mutation_harness.py",
    "gate_a.py",
]
COUNTEREXAMPLE = "test_transport_repairs.RepairTests." \
                 "test_reuse_new_epoch_not_translated_with_old_ledger"


def repo_root(start: str) -> str:
    """Walk up to the directory holding a `.git` entry (a FILE in a worktree, a dir in a
    normal checkout). Falls back to `start` if none is found."""
    d = os.path.abspath(start)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.abspath(start)
        d = parent


def _sha256(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return os.path.basename(path)


def _run_suite_json(module: str) -> dict:
    """Run one test module with --json; parse its MACHINE_SUMMARY."""
    proc = subprocess.run(
        [sys.executable, f"{module}.py", "--json"],
        cwd=HERE, capture_output=True, text=True, timeout=180,
    )
    out = proc.stdout + "\n" + proc.stderr
    for ln in out.splitlines():
        if ln.startswith("MACHINE_SUMMARY "):
            return json.loads(ln[len("MACHINE_SUMMARY "):])
    return {"suite": module, "transport_gate": "FAIL", "failed": -1,
            "error": "no MACHINE_SUMMARY", "tail": out[-800:]}


def _run_demo() -> dict:
    proc = subprocess.run(
        [sys.executable, "transport_oracle.py"],
        cwd=HERE, capture_output=True, text=True, timeout=120,
    )
    summary = {}
    # the demo prints a JSON blob then a human line; grab the JSON object
    txt = proc.stdout
    try:
        start = txt.index("{")
        depth, end = 0, None
        for i in range(start, len(txt)):
            if txt[i] == "{":
                depth += 1
            elif txt[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        blob = json.loads(txt[start:end])
        summary = {"pass": blob.get("pass"), "total": blob.get("total"),
                   "retransmit_reemits_pad": blob.get("retransmit_reemits_pad"),
                   "reconstruction_byte_exact": blob.get("reconstruction_byte_exact")}
    except Exception as exc:  # noqa: BLE001 -- demo output shape is our own, report if odd
        summary = {"parse_error": str(exc)}
    summary["exit"] = proc.returncode
    return summary


def _counterexample_fixed() -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", COUNTEREXAMPLE],
        cwd=HERE, capture_output=True, text=True, timeout=120,
    )
    return {"test": COUNTEREXAMPLE, "exit": proc.returncode,
            "passed": proc.returncode == 0}


def main() -> int:
    want_json = "--json" in sys.argv
    root = repo_root(HERE)

    inputs = {_rel(os.path.join(HERE, f), root): _sha256(os.path.join(HERE, f))
              for f in INPUT_FILES}

    legacy = _run_suite_json("test_transport_oracle")
    repairs = _run_suite_json("test_transport_repairs")
    demo = _run_demo()
    counter = _counterexample_fixed()
    mut = mutation_harness.run(verbose=False)

    tests_total = int(legacy.get("total", 0)) + int(repairs.get("total", 0))
    tests_failed = int(legacy.get("failed", 0)) + int(repairs.get("failed", 0))

    reasons = []
    if not (legacy.get("transport_gate") == "PASS" and legacy.get("failed") == 0):
        reasons.append("legacy suite did not pass")
    if not (repairs.get("transport_gate") == "PASS" and repairs.get("failed") == 0):
        reasons.append("repair suite did not pass")
    if demo.get("exit") != 0:
        reasons.append("scenario demo did not exit 0")
    if not counter.get("passed"):
        reasons.append("tuple-reuse counterexample not fixed")
    if not mut.get("harness_pass"):
        reasons.append("mutation harness has surviving/undefended mutants")

    gate_pass = len(reasons) == 0

    manifest = {
        "gate": "A",
        "verdict": "PASS" if gate_pass else "FAIL",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "repo_root_basename": os.path.basename(root),
        "module_rel": _rel(HERE, root),
        "inputs": inputs,
        "suites": {"legacy": legacy, "repairs": repairs, "demo": demo},
        "counterexample": counter,
        "mutation": {
            "baseline_total": mut["baseline_total"],
            "baseline_clean": mut["baseline_clean"],
            "mutations_total": mut["mutations_total"],
            "mutations_killed": mut["mutations_killed"],
            "mutations_survived": mut["mutations_survived"],
            "harness_pass": mut["harness_pass"],
            "results": mut["results"],
        },
        "totals": {"tests": tests_total, "passed": tests_total - tests_failed,
                   "failed": tests_failed},
        "gate_a_pass": gate_pass,
        "gate_a_reasons": reasons,
    }

    # Write machine-readable artifacts (module-relative; hash the manifest itself).
    out_dir = os.path.join(HERE, "gate_results")
    os.makedirs(out_dir, exist_ok=True)
    mut_path = os.path.join(out_dir, "mutation_results.json")
    with open(mut_path, "w") as fh:
        json.dump(mut, fh, indent=2, sort_keys=True)
    body = json.dumps(manifest, indent=2, sort_keys=True)
    man_path = os.path.join(out_dir, "gate_a_manifest.json")
    with open(man_path, "w") as fh:
        fh.write(body + "\n")
    manifest_hash = hashlib.sha256(body.encode()).hexdigest()
    # append the self-hash as a sidecar so the manifest file's own content stays stable
    with open(os.path.join(out_dir, "gate_a_manifest.sha256"), "w") as fh:
        fh.write(manifest_hash + "  gate_a_manifest.json\n")

    # Human summary
    print("=" * 72)
    print(f"GATE A: {manifest['verdict']}    (Python {manifest['python']})")
    print("=" * 72)
    print(f"  legacy suite : {legacy.get('passed')}/{legacy.get('total')} "
          f"gate={legacy.get('transport_gate')}")
    print(f"  repair suite : {repairs.get('passed')}/{repairs.get('total')} "
          f"gate={repairs.get('transport_gate')}")
    print(f"  demo         : {demo.get('pass')}/{demo.get('total')} exit={demo.get('exit')} "
          f"recon_exact={demo.get('reconstruction_byte_exact')}")
    print(f"  counterexmpl : fixed={counter.get('passed')}  ({COUNTEREXAMPLE.split('.')[-1]})")
    print(f"  mutation     : {mut['mutations_killed']}/{mut['mutations_total']} killed, "
          f"baseline_clean={mut['baseline_clean']}, survived={mut['mutations_survived']}")
    print(f"  total tests  : {manifest['totals']['passed']}/{manifest['totals']['tests']} "
          f"passed")
    if reasons:
        print(f"  FAIL reasons : {reasons}")
    print(f"  manifest     : {_rel(man_path, root)}  sha256={manifest_hash[:16]}...")
    print(f"  mutation json: {_rel(mut_path, root)}")

    if want_json:
        print("MACHINE_GATE_A " + json.dumps(
            {"verdict": manifest["verdict"], "gate_a_pass": gate_pass,
             "manifest_sha256": manifest_hash, "totals": manifest["totals"],
             "mutations_killed": mut["mutations_killed"],
             "mutations_total": mut["mutations_total"]}))

    return 0 if gate_pass else 1


if __name__ == "__main__":
    sys.exit(main())
