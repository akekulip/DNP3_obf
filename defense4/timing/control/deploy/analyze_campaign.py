#!/usr/bin/env python3
"""D6 statistical analysis of a campaign directory: per-condition CLRT/latency distributions,
bootstrap CIs, reliability, ordering, release-cause split, and counter-consistency.

  $RESEARCH_PYTHON analyze_campaign.py <campaign_dir> [out.json]

Groups blocks by mode (the condition), pools their driver rows, and reports the metrics the
overnight spec requires. A "valid" transaction responded with both an ACK and a RESPONSE and no
reset. Uses numpy for bootstrap CIs when available; falls back to a percentile CI otherwise.
"""
import glob, json, os, sys

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


def boot_ci_median(xs, iters=2000, seed=12345):
    if not xs:
        return [None, None]
    if np is None:
        s = sorted(xs)
        lo = s[max(0, int(0.025 * (len(s) - 1)))]
        hi = s[min(len(s) - 1, int(0.975 * (len(s) - 1)))]
        return [lo, hi]
    rng = np.random.default_rng(seed)
    arr = np.array(xs, dtype=float)
    meds = [float(np.median(rng.choice(arr, size=len(arr), replace=True))) for _ in range(iters)]
    return [float(np.percentile(meds, 2.5)), float(np.percentile(meds, 97.5))]


def main():
    d = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    blocks = {}   # mode -> list of (label, block_json)
    for bj in sorted(glob.glob(os.path.join(d, "block_*.json"))):
        try:
            b = json.load(open(bj))
        except Exception:
            continue
        blocks.setdefault(b.get("mode", "?"), []).append((os.path.basename(bj), b))

    scores = {}
    for sl in glob.glob(os.path.join(d, "blocks.jsonl")):
        for line in open(sl):
            try:
                s = json.loads(line)
            except Exception:
                continue
            scores.setdefault(s.get("mode"), []).append(s)

    report = {"dir": d, "conditions": {}}
    for mode in ("OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"):
        if mode not in blocks:
            continue
        rows = []
        attempted = sent = responded = 0
        for _, b in blocks[mode]:
            attempted += b.get("attempted", 0); sent += b.get("sent", 0); responded += b.get("responded", 0)
            rows.extend(b.get("rows", []))
        valid = [r for r in rows if r.get("t_ack") is not None and r.get("t_resp") is not None and not r.get("rst")]
        excluded = len(rows) - len(valid)
        clrt = [r["clrt_ms"] for r in valid if isinstance(r.get("clrt_ms"), (int, float))]
        r2r = [r["read_to_resp_ms"] for r in valid if isinstance(r.get("read_to_resp_ms"), (int, float))]
        r2a = [r["read_to_ack_ms"] for r in valid if isinstance(r.get("read_to_ack_ms"), (int, float))]
        rec = {
            "n_rows": len(rows), "n_valid": len(valid), "excluded": excluded,
            "attempted": attempted, "sent": sent, "responded": responded,
            "distinct_app_seqs": sorted(set(r.get("app_seq_sent") for r in rows if r.get("app_seq_sent"))),
            "clrt_ms": {"median": median(clrt), "ci95_median": boot_ci_median(clrt),
                        "pcts": pcts(clrt, [5, 25, 50, 75, 95, 99]), "min": min(clrt) if clrt else None,
                        "max": max(clrt) if clrt else None},
            "read_to_resp_ms": {"median": median(r2r), "pcts": pcts(r2r, [5, 50, 95, 99])},
            "read_to_ack_ms": {"median": median(r2a), "pcts": pcts(r2a, [5, 50, 95, 99])},
            "ordering_violations": sum(1 for r in valid if isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0),
            "order_inconclusive": sum(1 for r in valid if r.get("order_inconclusive") is True),
            "retransmits": sum(r.get("retransmit", 0) for r in rows),
            "dup_ack": sum(r.get("dup_ack", 0) for r in rows),
            "dup_resp": sum(r.get("dup_resp", 0) for r in rows),
            "resets": sum(1 for r in rows if r.get("rst")),
            "multi_segment": sum(1 for r in rows if r.get("resp_segments", 0) > 1),
        }
        # release-cause + drop consistency from the block scores
        sc = scores.get(mode, [])
        def sdelta(k):
            return sum(x.get(k) or 0 for x in sc)
        rec["token_escapes_on_wire"] = sdelta("token_escapes_on_wire")
        rec["deadline_releases"] = sdelta("deadline_release_delta")
        rec["failopen_releases"] = sdelta("failopen_release_delta")
        rec["ack_release_pending"] = sdelta("ack_release_delta")
        rec["ack_rel_retire"] = sdelta("ack_rel_retire_delta")
        rec["queue_drops"] = [x.get("queue_drop_deltas") for x in sc if x.get("queue_drop_deltas")]
        rec["port_drops"] = [x.get("port_drop_deltas") for x in sc if x.get("port_drop_deltas")]
        rec["hard_anomaly_blocks"] = [x.get("hard_anomalies") for x in sc if x.get("hard_anomalies")]
        report["conditions"][mode] = rec

    print(json.dumps(report, indent=2, default=str))
    if out_path:
        json.dump(report, open(out_path, "w"), indent=2, default=str)


if __name__ == "__main__":
    main()
