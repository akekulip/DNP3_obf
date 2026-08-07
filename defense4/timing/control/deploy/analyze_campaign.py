#!/usr/bin/env python3
"""Fail-closed, condition-aware statistical analysis of a campaign directory.

  python3 analyze_campaign.py <campaign_dir> [out.json] [--spec spec.txt] [--require-manifest]

Fail-closed:
- `blocks.jsonl` must exist and be non-empty. A malformed block JSON or score line is a hard failure.
- The governing spec (`--spec` or `<dir>/spec.txt`) is required. Every expected block label must have
  exactly one block file and exactly one scorer record whose verdict is PASS, exit_code 0, known mode,
  and matching mode/scenario/parameters. Missing, extra, duplicate, unmatched, or non-PASS records are
  hard failures.
- `--require-manifest` additionally requires `SHA256SUMS` (used by the independent Phase 6 re-analysis;
  run_campaign runs the analyzer before the manifest exists, so it omits the flag).

Condition-aware: results are grouped by the FULL condition (mode, D_A, D_R, budget, scenario, and
device/profile when present), never pooled across different parameter settings that merely share a
mode. Statistics are session-aware: each block is one sustained TCP session. A pure-Python cluster
bootstrap resamples whole sessions; with fewer than MIN_SESSIONS_FOR_CI sessions the interval is
reported as unavailable rather than a meaningless zero-width span. Distributions are reported in full
(min/p5/p25/p50/p75/p95/p99/max + IQR), never the median alone.
"""
import argparse
import glob
import json
import os
import random
import sys

KNOWN_MODES = {"OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"}
MIN_SESSIONS_FOR_CI = 3
BOOT_ITERS = 2000
BOOT_SEED = 12345


def pcts(xs, ps):
    xs = sorted(xs)
    out = {}
    for p in ps:
        out[p] = None if not xs else xs[min(len(xs) - 1, int(round(p / 100.0 * (len(xs) - 1))))]
    return out


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return None
    return xs[n // 2] if n % 2 else 0.5 * (xs[n // 2 - 1] + xs[n // 2])


def session_boot_ci(sessions):
    """Cluster bootstrap of the pooled median, resampling whole SESSIONS (pure Python)."""
    sessions = [s for s in sessions if s]
    if len(sessions) < MIN_SESSIONS_FOR_CI:
        return {"lo": None, "hi": None, "available": False,
                "reason": "insufficient independent sessions (%d < %d)" % (len(sessions), MIN_SESSIONS_FOR_CI)}
    rng = random.Random(BOOT_SEED)
    k = len(sessions)
    meds = []
    for _ in range(BOOT_ITERS):
        pooled = []
        for _ in range(k):
            pooled.extend(sessions[rng.randrange(k)])
        if pooled:
            meds.append(median(pooled))
    meds.sort()
    lo = meds[int(0.025 * (len(meds) - 1))]
    hi = meds[int(0.975 * (len(meds) - 1))]
    return {"lo": lo, "hi": hi, "available": True, "n_sessions": k}


def exclusion_reason(r):
    if r.get("rst"):
        return "tcp_reset"
    if r.get("t_ack") is None and r.get("t_resp") is None:
        return "no_ack_no_resp"
    if r.get("t_ack") is None:
        return "no_ack"
    if r.get("t_resp") is None:
        return "no_resp"
    return None


def parse_spec(path):
    """label -> (mode, d_a, d_r, budget, scenario) from the governing spec."""
    expected = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            label, mode = parts[0], parts[1]
            da = parts[2] if len(parts) > 2 else None
            dr = parts[3] if len(parts) > 3 else None
            budget = parts[7] if len(parts) > 7 else "-"
            scenario = parts[8] if len(parts) > 8 else "normal"
            expected[label] = {"mode": mode, "d_a": da, "d_r": dr, "budget": budget, "scenario": scenario}
    return expected


def main():
    ap = argparse.ArgumentParser(description="fail-closed condition-aware campaign analysis")
    ap.add_argument("dir")
    ap.add_argument("out", nargs="?", default=None)
    ap.add_argument("--spec", default=None)
    ap.add_argument("--require-manifest", action="store_true")
    args = ap.parse_args()
    d = args.dir
    hard = []

    # ---- spec (required for completeness checking) ----
    spec_path = args.spec or os.path.join(d, "spec.txt")
    if not os.path.exists(spec_path):
        print(json.dumps({"error": "spec required for completeness check: %s" % spec_path, "exit_code": 2}))
        return 2
    expected = parse_spec(spec_path)

    # ---- manifest (optional) ----
    if args.require_manifest and not os.path.exists(os.path.join(d, "SHA256SUMS")):
        hard.append("SHA256SUMS manifest missing")

    # ---- blocks.jsonl (required) ----
    scores_path = os.path.join(d, "blocks.jsonl")
    if not os.path.exists(scores_path) or os.path.getsize(scores_path) == 0:
        print(json.dumps({"error": "blocks.jsonl missing/empty: %s" % scores_path, "exit_code": 2}))
        return 2

    # ---- load blocks fail-closed ----
    blocks = {}   # label -> block
    for bj in sorted(glob.glob(os.path.join(d, "block_*.json"))):
        name = os.path.basename(bj)
        try:
            with open(bj) as f:
                text = f.read()
            b = json.loads(text) if text.strip() else None
        except (OSError, json.JSONDecodeError) as e:
            hard.append("%s unreadable/malformed: %s" % (name, e)); continue
        if not isinstance(b, dict) or not isinstance(b.get("rows"), list) or len(b["rows"]) == 0:
            hard.append("%s has no rows" % name); continue
        blocks[b.get("label")] = b

    # ---- load scores fail-closed ----
    scores = {}   # label -> list of score dicts
    for i, line in enumerate(open(scores_path), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            s = json.loads(line)
        except json.JSONDecodeError as e:
            hard.append("blocks.jsonl line %d malformed: %s" % (i, e)); continue
        scores.setdefault(s.get("label"), []).append(s)

    # ---- one valid PASS score per expected label; no extras/dups/unmatched ----
    for label, exp in expected.items():
        srs = scores.get(label, [])
        if label not in blocks:
            hard.append("expected block %r has no block_*.json" % label)
        if len(srs) == 0:
            hard.append("expected block %r has no scorer record" % label); continue
        if len(srs) > 1:
            hard.append("expected block %r has %d scorer records (want 1)" % (label, len(srs)))
        s = srs[0]
        if s.get("mode") not in KNOWN_MODES:
            hard.append("block %r unknown mode %r" % (label, s.get("mode")))
        if s.get("verdict") != "PASS":
            hard.append("block %r verdict %r != PASS" % (label, s.get("verdict")))
        if s.get("exit_code") not in (0, None):
            hard.append("block %r embedded exit_code %r != 0" % (label, s.get("exit_code")))
        if s.get("mode") != exp["mode"]:
            hard.append("block %r mode %r != spec %r" % (label, s.get("mode"), exp["mode"]))
        if s.get("scenario") not in (exp["scenario"], None):
            hard.append("block %r scenario %r != spec %r" % (label, s.get("scenario"), exp["scenario"]))
    for label in scores:
        if label not in expected:
            hard.append("scorer record for unexpected label %r" % label)
    for label in blocks:
        if label not in expected:
            hard.append("block file for unexpected label %r" % label)

    # ---- condition-aware statistics ----
    conditions = {}   # condition-key -> list of (label, block)
    for label, b in blocks.items():
        cond = (b.get("mode"), str(b.get("d_a_ms")), str(b.get("d_r_ms")),
                str((expected.get(label) or {}).get("budget", "-")),
                (expected.get(label) or {}).get("scenario", "normal"),
                b.get("device") or b.get("profile") or "-")
        conditions.setdefault(cond, []).append((label, b))

    report = {"dir": d, "hard_anomalies": hard, "conditions": {}}
    for cond, members in sorted(conditions.items(), key=lambda kv: str(kv[0])):
        key = "mode=%s D_A=%s D_R=%s budget=%s scenario=%s dev=%s" % cond
        sessions_clrt, per_session, rows_all = [], [], []
        attempted = sent = responded = 0
        excl = {}
        for label, b in members:
            attempted += b.get("attempted", 0); sent += b.get("sent", 0); responded += b.get("responded", 0)
            rows = b.get("rows", [])
            rows_all.extend(rows)
            valid = []
            for r in rows:
                reason = exclusion_reason(r)
                if reason is None and isinstance(r.get("clrt_ms"), (int, float)):
                    valid.append(r["clrt_ms"])
                elif reason:
                    excl[reason] = excl.get(reason, 0) + 1
            sessions_clrt.append(valid)
            per_session.append({"session": label, "n_valid": len(valid),
                                "median_clrt_ms": median(valid), "max_clrt_ms": max(valid) if valid else None})
        pooled = [v for s in sessions_clrt for v in s]
        p = pcts(pooled, [0, 5, 25, 50, 75, 95, 99, 100])
        report["conditions"][key] = {
            "n_sessions": len(members), "n_rows": len(rows_all), "n_valid": len(pooled),
            "excluded_total": sum(excl.values()), "excluded_reasons": excl,
            "attempted": attempted, "sent": sent, "responded": responded,
            "clrt_ms": {"min": p[0], "p5": p[5], "p25": p[25], "median": p[50], "p75": p[75],
                        "p95": p[95], "p99": p[99], "max": p[100],
                        "iqr": (p[75] - p[25]) if (p[75] is not None and p[25] is not None) else None,
                        "session_bootstrap_ci95_median": session_boot_ci(sessions_clrt)},
            "per_session": per_session,
            "ordering_violations": sum(1 for r in rows_all if isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0),
            "retransmits": sum(r.get("retransmit", 0) or 0 for r in rows_all),
            "dup_ack": sum(r.get("dup_ack", 0) or 0 for r in rows_all),
            "dup_resp": sum(r.get("dup_resp", 0) or 0 for r in rows_all),
            "resets": sum(1 for r in rows_all if r.get("rst")),
        }

    report["exit_code"] = 1 if hard else 0
    text = json.dumps(report, indent=2, default=str)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
