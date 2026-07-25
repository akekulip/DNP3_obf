#!/usr/bin/env python3
"""aggregate_campaign.py — reconcile a Part 12 repetition campaign into the distributions
Gate 12.9 requires. Reads every rep's on-chip reader json and its Vision PCAP, cross-checks
them, and prints count/min/mean/median/p95/p99/max/sd/range/failures per quantity.

Usage: aggregate_campaign.py <campaign_dir> <rep_glob> [--json out.json]

Deliberately recomputes each derived quantity from the RAW registers rather than trusting the
reader's own `derived` block, so a bug there cannot launder itself into the campaign summary.
"""
import glob
import json
import os
import struct
import sys

MASK32 = 0xFFFFFFFF


def d32(later, earlier):
    """Wrapping 32-bit ns difference; None if either stamp is unset."""
    if not later or not earlier:
        return None
    return (later - earlier) & MASK32


def stats(xs):
    xs = sorted(x for x in xs if x is not None)
    n = len(xs)
    if n == 0:
        return {"count": 0}
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n

    def pct(p):
        return xs[min(n - 1, int(round(p * (n - 1))))]
    return {"count": n, "min": xs[0], "mean": round(mean, 2), "median": pct(0.5),
            "p95": pct(0.95), "p99": pct(0.99), "max": xs[-1],
            "sd": round(var ** 0.5, 2), "range": xs[-1] - xs[0]}


def pcap_ack_resp_gap_ns(path):
    """ACK->RESPONSE gap from the Vision capture (host clock, coarse). Also returns the
    ethertype histogram so blocker escapes are counted per rep."""
    try:
        f = open(path, "rb").read()
    except OSError:
        return None, {}
    if len(f) < 24:
        return None, {}
    off, frames, hist = 24, [], {}
    while off + 16 <= len(f):
        ts, tu, cl, ol = struct.unpack("<IIII", f[off:off + 16])
        off += 16
        fr = f[off:off + cl]
        off += cl
        if len(fr) >= 21:
            et = struct.unpack(">H", fr[12:14])[0]
            hist[et] = hist.get(et, 0) + 1
            frames.append((ts + tu / 1e6, et, fr[14]))
    acks = [t for t, et, role in frames if et == 0x88C0 and role == 7]
    resps = [t for t, et, role in frames if et == 0x88C0 and role == 2]
    gap = None
    if acks and resps:
        gap = int(round((min(resps) - max(acks)) * 1e9))
    return gap, hist


def main():
    cdir, pat = sys.argv[1], sys.argv[2]
    outp = None
    if "--json" in sys.argv:
        outp = sys.argv[sys.argv.index("--json") + 1]

    rows, failures = [], []
    for rj in sorted(glob.glob(os.path.join(cdir, pat))):
        rid = os.path.basename(rj).split(".")[0]
        txt = open(rj).read()
        if "P12READ " not in txt:
            failures.append({"rep": rid, "why": "reader json missing P12READ line"})
            continue
        d = json.loads(txt.split("P12READ ", 1)[1])
        r, c = d["registers"], d["counters"]
        g_ns = d.get("derived", {}).get("g_ns")
        t_ack = r.get("reg_ts_ack_arm") or 0
        t_dl = r.get("reg_deadline") or 0
        t_bt = r.get("reg_ts_block_term") or 0
        t_rel = r.get("reg_ts_first_resp_release") or 0

        gap_ns, hist = pcap_ack_resp_gap_ns(os.path.join(cdir, rid + ".pcap"))
        rows.append({
            "rep": rid, "g_ns": g_ns,
            # on-chip: the deadline the switch actually armed, vs the one we asked for
            "deadline_arith_ok": (t_ack and t_dl and ((t_ack + g_ns) & MASK32) == t_dl),
            "g_observed_ns": d32(t_rel, t_ack),
            "deadline_error_ns": (d32(t_rel, t_ack) - g_ns) if (t_rel and t_ack) else None,
            # release-tail decomposition
            "c1_deadline_to_block_term_ns": d32(t_bt, t_dl),
            "c2_block_term_to_release_ns": d32(t_rel, t_bt),
            "host_pcap_gap_ns": gap_ns,
            "blocker_loops": c.get("ctr_block_loop"),
            "release_reason": ("deadline" if c.get("ctr_block_term_deadline")
                               else "fail_open" if c.get("ctr_block_term_timeout")
                               else "stale" if c.get("ctr_block_term_stale") else "none"),
            "blocker_escapes": sum(v for k, v in hist.items() if k == 0x88C1),
            "counters": c,
        })

    # per-rep integrity: every one of these must hold for a campaign PASS
    for w in rows:
        c = w["counters"]
        bad = []
        if not w["deadline_arith_ok"]:
            bad.append("deadline != t_ack + G on chip")
        if c.get("ctr_block_term_deadline") != 64:
            bad.append("not all 64 blockers deadline-terminated")
        if c.get("ctr_block_term_timeout"):
            bad.append("watchdog/fail-open fired in a deadline trial")
        if c.get("ctr_block_term_stale"):
            bad.append("stale termination in a deadline trial")
        if c.get("ctr_resp_enq") != 1 or c.get("ctr_resp_release") != 1:
            bad.append("response enqueue/release != 1 (missing or duplicate)")
        if c.get("ctr_ack_arm") != 1 or c.get("ctr_ack_bypass"):
            bad.append("ACK did not qualify exactly once")
        if c.get("ctr_block_enq") != 64:
            bad.append("reservoir != 64")
        if w["blocker_escapes"]:
            bad.append("blocker token seen at Vision")
        if w["deadline_error_ns"] is None or w["deadline_error_ns"] < 0:
            bad.append("premature release (negative deadline error)")
        if bad:
            failures.append({"rep": w["rep"], "why": "; ".join(bad)})

    keys = ["g_observed_ns", "deadline_error_ns", "c1_deadline_to_block_term_ns",
            "c2_block_term_to_release_ns", "host_pcap_gap_ns", "blocker_loops"]
    summary = {k: stats([w[k] for w in rows]) for k in keys}
    by_g = {}
    for w in rows:
        by_g.setdefault(w["g_ns"], []).append(w["deadline_error_ns"])
    out = {
        "campaign_dir": cdir, "reps": len(rows),
        "reps_all_deadline_released": sum(1 for w in rows if w["release_reason"] == "deadline"),
        "deadline_arithmetic_verified": sum(1 for w in rows if w["deadline_arith_ok"]),
        "total_blocker_escapes": sum(w["blocker_escapes"] for w in rows),
        "failures": failures,
        "summary_ns": summary,
        "deadline_error_by_G": {str(k): stats(v) for k, v in sorted(by_g.items())},
    }
    print("reps=%d  all-deadline-released=%d  deadline-arith-verified=%d  escapes=%d  FAILURES=%d"
          % (out["reps"], out["reps_all_deadline_released"], out["deadline_arithmetic_verified"],
             out["total_blocker_escapes"], len(failures)))
    for k in keys:
        s = summary[k]
        if s.get("count"):
            print("  %-32s n=%-4d min=%-10d med=%-10d p95=%-10d p99=%-10d max=%-10d mean=%-12s sd=%-8s range=%d"
                  % (k, s["count"], s["min"], s["median"], s["p95"], s["p99"], s["max"],
                     s["mean"], s["sd"], s["range"]))
    if len(by_g) > 1:
        print("  deadline_error_ns by G:")
        for g, s in sorted(out["deadline_error_by_G"].items(), key=lambda kv: int(kv[0])):
            print("    G=%-9s n=%-4d min=%d med=%d max=%d sd=%s"
                  % (int(g) // 1000000, s["count"], s["min"], s["median"], s["max"], s["sd"]))
    for f in failures[:10]:
        print("  FAIL %s: %s" % (f["rep"], f["why"]))
    if outp:
        json.dump(out, open(outp, "w"), indent=1)
        print("wrote", outp)


if __name__ == "__main__":
    main()
