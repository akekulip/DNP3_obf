#!/usr/bin/env python3
"""10_generate_figures.py — reproducible figures from the analyzer outputs (§16 D6, §23).

Reads the native and protected transactions.csv / summary.json produced by
09_analyze_clrt.py (evidence chain: raw PCAP -> transactions -> CLRT CSV ->
figures -> reported claim, directive §16 Diagram 6) and renders:

  fig_clrt_native_vs_protected.png   overlaid CLRT distributions (the headline)
  fig_clrt_timeline.png              per-transaction CLRT vs G
  fig_leakage_bits.png               timing leakage entropy vs bin resolution

Uses matplotlib (run with the research venv: $RESEARCH_PYTHON). Stdlib for parsing.
Every number is traceable to the committed CSV/JSON — no data is synthesized here.
"""
import argparse
import csv
import json
import os
import sys


def load_clrt(csv_path):
    xs = []
    if not os.path.exists(csv_path):
        return xs
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            if row.get("ambiguous", "True") == "False" and row.get("clrt_ms"):
                try:
                    xs.append(float(row["clrt_ms"]))
                except ValueError:
                    pass
    return xs


def main():
    ap = argparse.ArgumentParser(description="render CLRT figures from analyzer outputs")
    ap.add_argument("--native-prefix", help="prefix of native analyzer outputs (…/<runid>)")
    ap.add_argument("--protected-prefix", help="prefix of protected analyzer outputs")
    ap.add_argument("--g-ms", type=float, default=float(os.environ.get("G_MS", "25")))
    ap.add_argument("--figdir", default=os.environ.get("EVID_DIR", "research/timing_final/evidence/timing_final") + "/figures")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    print("RUN: generate figures -> %s (G=%s ms)" % (a.figdir, a.g_ms))
    if a.dry_run:
        print("DRYRUN: would load native/protected transactions.csv and render 3 PNGs into %s." % a.figdir)
        return 0

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        sys.exit("FATAL: matplotlib unavailable (%s) — run with the research venv ($RESEARCH_PYTHON)." % e)

    os.makedirs(a.figdir, exist_ok=True)
    nat = load_clrt((a.native_prefix or "") + ".transactions.csv") if a.native_prefix else []
    prot = load_clrt((a.protected_prefix or "") + ".transactions.csv") if a.protected_prefix else []
    if not nat and not prot:
        sys.exit("FATAL: no CLRT data — pass --native-prefix and/or --protected-prefix.")

    # Fig 1: overlaid distributions
    plt.figure(figsize=(7, 4))
    if nat:
        plt.hist(nat, bins=30, alpha=0.6, label="native (n=%d)" % len(nat))
    if prot:
        plt.hist(prot, bins=30, alpha=0.6, label="protected (n=%d)" % len(prot))
    plt.axvline(a.g_ms, color="k", ls="--", lw=1, label="G = %g ms" % a.g_ms)
    plt.xlabel("ACK→RESPONSE interval (ms)"); plt.ylabel("count")
    plt.title("DNP3 CLRT: native vs timing-normalized"); plt.legend()
    f1 = os.path.join(a.figdir, "fig_clrt_native_vs_protected.png")
    plt.tight_layout(); plt.savefig(f1, dpi=140); plt.close()
    print("  wrote %s" % f1)

    # Fig 2: per-transaction timeline vs G
    if prot:
        plt.figure(figsize=(7, 4))
        plt.plot(range(len(prot)), prot, "o-", ms=3, label="protected CLRT")
        plt.axhline(a.g_ms, color="k", ls="--", lw=1, label="G = %g ms" % a.g_ms)
        plt.xlabel("transaction #"); plt.ylabel("CLRT (ms)")
        plt.title("Protected CLRT per transaction"); plt.legend()
        f2 = os.path.join(a.figdir, "fig_clrt_timeline.png")
        plt.tight_layout(); plt.savefig(f2, dpi=140); plt.close()
        print("  wrote %s" % f2)

    # Fig 3: leakage entropy vs resolution (from summary.json if present)
    def leak(prefix):
        p = (prefix or "") + ".summary.json"
        if prefix and os.path.exists(p):
            return json.load(open(p)).get("clrt_leakage", {})
        return {}
    ln, lp = leak(a.native_prefix), leak(a.protected_prefix)
    labels = ["10us", "50us", "100us", "500us", "1ms"]
    if ln or lp:
        plt.figure(figsize=(7, 4))
        if ln:
            plt.plot(labels, [ln.get(x, {}).get("entropy_bits", 0) for x in labels], "o-", label="native")
        if lp:
            plt.plot(labels, [lp.get(x, {}).get("entropy_bits", 0) for x in labels], "s-", label="protected")
        plt.xlabel("bin resolution"); plt.ylabel("timing leakage (bits)")
        plt.title("Observer timing leakage vs resolution"); plt.legend()
        f3 = os.path.join(a.figdir, "fig_leakage_bits.png")
        plt.tight_layout(); plt.savefig(f3, dpi=140); plt.close()
        print("  wrote %s" % f3)

    print("figures: done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
