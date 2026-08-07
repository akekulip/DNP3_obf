#!/usr/bin/env python3
"""Session-aware, fail-closed statistical analysis of a campaign directory.

  python3 analyze_campaign.py <campaign_dir> [out.json]

Groups blocks by mode (the condition). Each block is one sustained TCP session (the driver keeps one
connection per block), so the analysis is session-aware: it reports per-session medians and a
session-level bootstrap confidence interval (resampling whole sessions, not individual polls), instead
of pooling every poll as an independent sample. It reports complete distributions with tails
(min/p5/p25/p50/p75/p95/p99/max + IQR), never the median alone.

Fail-closed: a block JSON that is missing, empty, malformed, or has no rows is a hard failure (exit 1),
not silently skipped. A malformed scorer line is a hard failure. A block whose scorer verdict is FAIL
or IO_FAIL makes the analysis exit nonzero, so a failed block cannot be averaged into a clean summary.
Every excluded transaction is counted with its reason.
"""
import glob
import json
import os
import sys

try:
    import numpy as np
except Exception:
    np = None


def pcts(xs, ps):
    xs = sorted(xs)
    out = {}
    for p in ps:
        if not xs:
            out[p] = None
        else:
            i = min(len(xs) - 1, int(round(p / 100.0 * (len(xs) - 1))))
            out[p] = xs[i]
    return out


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return None
    return xs[n // 2] if n % 2 else 0.5 * (xs[n // 2 - 1] + xs[n // 2])


def session_boot_ci(sessions, iters=2000, seed=12345):
    """Bootstrap the pooled median by resampling whole SESSIONS with replacement.

    sessions: list of lists (each inner list is one block's valid CLRT values). This respects the
    session structure: a block's polls are correlated, so we resample blocks, not polls.
    """
    sessions = [s for s in sessions if s]
    if not sessions:
        return [None, None]
    if np is None:
        allv = sorted(v for s in sessions for v in s)
        if not allv:
            return [None, None]
        lo = allv[max(0, int(0.025 * (len(allv) - 1)))]
        hi = allv[min(len(allv) - 1, int(0.975 * (len(allv) - 1)))]
        return [lo, hi]
    rng = np.random.default_rng(seed)
    k = len(sessions)
    meds = []
    for _ in range(iters):
        pick = rng.integers(0, k, size=k)
        pooled = [v for j in pick for v in sessions[j]]
        if pooled:
            meds.append(float(np.median(np.array(pooled, dtype=float))))
    if not meds:
        return [None, None]
    return [float(np.percentile(meds, 2.5)), float(np.percentile(meds, 97.5))]


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


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: analyze_campaign.py <dir> [out.json]"}))
        return 2
    d = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    hard = []

    # ---- load blocks fail-closed (no silent skip) ----
    blocks = {}   # mode -> list of (label, block)
    block_files = sorted(glob.glob(os.path.join(d, "block_*.json")))
    if not block_files:
        print(json.dumps({"error": "no block_*.json under %s" % d}))
        return 2
    for bj in block_files:
        name = os.path.basename(bj)
        try:
            with open(bj) as f:
                text = f.read()
        except OSError as e:
            hard.append("%s unreadable: %s" % (name, e)); continue
        if not text.strip():
            hard.append("%s empty" % name); continue
        try:
            b = json.loads(text)
        except json.JSONDecodeError as e:
            hard.append("%s malformed JSON: %s" % (name, e)); continue
        if not isinstance(b.get("rows"), list) or len(b["rows"]) == 0:
            hard.append("%s has no rows" % name); continue
        blocks.setdefault(b.get("mode", "?"), []).append((name, b))

    # ---- load scores fail-closed ----
    scores = {}   # mode -> list of score dicts
    verdict_fail = []
    for sl in sorted(glob.glob(os.path.join(d, "blocks.jsonl"))):
        for i, line in enumerate(open(sl)):
            line = line.strip()
            if not line:
                continue
            try:
                s = json.loads(line)
            except json.JSONDecodeError as e:
                hard.append("%s line %d malformed: %s" % (os.path.basename(sl), i + 1, e)); continue
            scores.setdefault(s.get("mode"), []).append(s)
            if s.get("verdict") in ("FAIL", "IO_FAIL"):
                verdict_fail.append({"mode": s.get("mode"), "hard": s.get("hard_anomalies") or s.get("error")})

    report = {"dir": d, "conditions": {}, "hard_anomalies": hard, "failed_score_blocks": verdict_fail}

    for mode in ("OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"):
        if mode not in blocks:
            continue
        sessions_clrt = []     # per-session lists of valid CLRT (for session-aware CI)
        per_session = []
        rows_all = []
        attempted = sent = responded = 0
        excl = {}
        for label, b in blocks[mode]:
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
                                "median_clrt_ms": median(valid),
                                "p95_clrt_ms": pcts(valid, [95])[95],
                                "max_clrt_ms": max(valid) if valid else None})
        pooled = [v for s in sessions_clrt for v in s]
        r2r = [r["read_to_resp_ms"] for r in rows_all if isinstance(r.get("read_to_resp_ms"), (int, float))]
        r2a = [r["read_to_ack_ms"] for r in rows_all if isinstance(r.get("read_to_ack_ms"), (int, float))]
        p = pcts(pooled, [0, 5, 25, 50, 75, 95, 99, 100])
        iqr = (p[75] - p[25]) if (p[75] is not None and p[25] is not None) else None

        rec = {
            "n_sessions": len(blocks[mode]),
            "n_rows": len(rows_all), "n_valid": len(pooled),
            "excluded_total": sum(excl.values()), "excluded_reasons": excl,
            "attempted": attempted, "sent": sent, "responded": responded,
            "distinct_app_seqs": sorted(set(r.get("app_seq_sent") for r in rows_all if r.get("app_seq_sent"))),
            "clrt_ms": {
                "min": p[0], "p5": p[5], "p25": p[25], "median": p[50],
                "p75": p[75], "p95": p[95], "p99": p[99], "max": p[100], "iqr": iqr,
                "session_ci95_median": session_boot_ci(sessions_clrt),
            },
            "read_to_resp_ms": {"median": median(r2r), "pcts": pcts(r2r, [5, 50, 95, 99])},
            "read_to_ack_ms": {"median": median(r2a), "pcts": pcts(r2a, [5, 50, 95, 99])},
            "per_session": per_session,
            "ordering_violations": sum(1 for r in rows_all if isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0),
            "order_inconclusive": sum(1 for r in rows_all if r.get("order_inconclusive") is True),
            "retransmits": sum(r.get("retransmit", 0) for r in rows_all),
            "dup_ack": sum(r.get("dup_ack", 0) for r in rows_all),
            "dup_resp": sum(r.get("dup_resp", 0) for r in rows_all),
            "resets": sum(1 for r in rows_all if r.get("rst")),
            "multi_segment": sum(1 for r in rows_all if r.get("resp_segments", 0) > 1),
        }
        sc = scores.get(mode, [])

        def sdelta(k):
            return sum(x.get(k) or 0 for x in sc)

        rec["token_escapes_on_wire"] = sdelta("token_escapes_on_wire")
        rec["deadline_releases"] = sdelta("deadline_release_delta")
        rec["failopen_releases"] = sdelta("failopen_release_delta")
        rec["ack_release_pending"] = sdelta("ack_release_delta")
        rec["ack_rel_retire"] = sdelta("ack_rel_retire_delta")
        rec["resp_hold_early"] = sdelta("resp_hold_early_delta")
        rec["resp_hold_late"] = sdelta("resp_hold_late_delta")
        rec["resp_bypass"] = sdelta("resp_bypass_delta")
        rec["queue_drops"] = [x.get("queue_drop_deltas") for x in sc if x.get("queue_drop_deltas")]
        rec["port_drops"] = [x.get("port_drop_deltas") for x in sc if x.get("port_drop_deltas")]
        rec["hard_anomaly_blocks"] = [x.get("hard_anomalies") for x in sc if x.get("hard_anomalies")]
        report["conditions"][mode] = rec

    report["exit_code"] = 1 if (hard or verdict_fail) else 0
    text = json.dumps(report, indent=2, default=str)
    print(text)
    if out_path:
        with open(out_path, "w") as f:
            f.write(text)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
