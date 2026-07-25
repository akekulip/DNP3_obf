#!/usr/bin/env python3
"""make_pub_figures.py — the 10 publication figures (directive §8).

Data-driven figures are reproduced from committed evidence (PCAPs + JSON); the two schematics
(architecture, timeline) are drawn from documented parameters. No truncated axes; IEEE-style labels
with units. Requires the research venv for matplotlib: ~/.venvs/research/bin/python.

Usage: make_pub_figures.py [--figdir <dir>]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EV = os.path.join(ROOT, "evidence")
sys.path.insert(0, HERE)
from analyze_clrt import read_pcap, classify, build_transactions  # noqa: E402


def clrt(pcap, ip):
    fr = [(i, t, classify(f)) for i, t, f in read_pcap(pcap)]
    fr = [(i, t, c) for i, t, c in fr if c]
    return [t["clrt_ms"] for t in build_transactions(fr) if not t["ambiguous"] and t["clrt_ms"] is not None]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--figdir", default=os.path.join(EV, "figures"))
    a = ap.parse_args()
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    os.makedirs(a.figdir, exist_ok=True)
    made = []

    nat = clrt(os.path.join(EV, "native", "native120.pcap"), "192.168.10.7")
    prot = clrt(os.path.join(EV, "protected", "final100_g25.pcap"), "192.168.10.7")

    def save(fig, name):
        p = os.path.join(a.figdir, name); fig.tight_layout(); fig.savefig(p, dpi=160)
        plt.close(fig); made.append(name)

    # Fig 1 — architecture (schematic)
    fig, ax = plt.subplots(figsize=(8, 3.6)); ax.axis("off")
    boxes = [(0.02, "Vision\nmaster\ndp9 (dir0)"), (0.30, "Tofino-1\nnormalizer\ndp8 loopback"),
             (0.62, "Hulk\noutstation\ndp11 (dir1)")]
    for x, t in boxes:
        ax.add_patch(plt.Rectangle((x, 0.35), 0.22, 0.3, fill=False, lw=1.5))
        ax.text(x + 0.11, 0.5, t, ha="center", va="center", fontsize=9)
    ax.annotate("", xy=(0.30, 0.5), xytext=(0.24, 0.5), arrowprops=dict(arrowstyle="->"))
    ax.annotate("", xy=(0.62, 0.5), xytext=(0.52, 0.5), arrowprops=dict(arrowstyle="<->"))
    ax.text(0.41, 0.72, "READ→ / ←ACK,RESPONSE", ha="center", fontsize=8)
    ax.text(0.41, 0.22, "response held in low-prio TM queue,\nblocker reservoir on dp8 loopback,\nreleased at t_ack+G",
            ha="center", fontsize=8)
    ax.set_title("Fig 1. In-network timing normalizer — lab topology"); save(fig, "fig01_architecture.png")

    # Fig 2 — transaction timeline (schematic)
    fig, ax = plt.subplots(figsize=(8, 3.2))
    ev = [(0, "READ\n(arm)"), (2, "ACK\n(t_ack)"), (2.1, "RESPONSE\narrives (native)"), (25, "RESPONSE\nreleased (t_ack+G)")]
    for t, lb in ev:
        ax.axvline(t, color="#888", lw=1); ax.text(t, 1.05, lb, ha="center", fontsize=8)
    ax.axvspan(2.1, 25, alpha=0.15, color="#2ca02c")
    ax.text(13.5, 0.5, "held in Q_RESP\n(blocker reservoir starves it)", ha="center", fontsize=9, color="#207520")
    ax.set_xlim(-1, 28); ax.set_ylim(0, 1.3); ax.set_yticks([]); ax.set_xlabel("time after READ, ms")
    ax.set_title("Fig 2. Transaction timeline (G = 25 ms)"); save(fig, "fig02_transaction_timeline.png")

    # Figs 3-10: data-driven
    # SHARED bins across both datasets — otherwise the protected spike (sd ~0.01 ms) gets its own
    # ultra-fine binning and renders sub-pixel-wide (invisible). Shared bins make it a real bar.
    lo = min(min(nat), min(prot)); hi = max(max(nat), max(prot))
    import numpy as np
    edges = np.linspace(lo, hi, 41)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.hist(nat, bins=edges, alpha=.6, label="native (n=%d)" % len(nat), color="#555")
    ax.hist(prot, bins=edges, alpha=.75, label="protected G=25 ms (n=%d)" % len(prot), color="#2ca02c")
    ax.axvline(25, ls="--", lw=1, color="#2ca02c", alpha=.6)
    ax.set_xlabel("CLRT, ms"); ax.set_ylabel("transactions"); ax.set_title("Fig 3. CLRT distribution: native vs protected")
    ax.legend(); ax.grid(alpha=.3); save(fig, "fig03_native_vs_protected_hist.png")

    fig, ax = plt.subplots(figsize=(7, 4.2))
    for xs, lb, c in ((nat, "native", "#555"), (prot, "protected G=25 ms", "#2ca02c")):
        xs = sorted(xs); ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax.step(xs, ys, where="post", label="%s (n=%d)" % (lb, len(xs)), color=c, lw=2)
    ax.set_xlabel("CLRT, ms"); ax.set_ylabel("empirical CDF"); ax.set_title("Fig 4. CLRT ECDF: native vs protected")
    ax.legend(); ax.grid(alpha=.3); save(fig, "fig04_native_vs_protected_ecdf.png")

    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(range(len(nat)), nat, ".", ms=5, label="native", color="#555")
    ax.plot(range(len(prot)), prot, ".", ms=5, label="protected G=25 ms", color="#2ca02c")
    ax.axhline(25, ls="--", lw=1, color="#2ca02c", alpha=.6)
    ax.set_xlabel("transaction #"); ax.set_ylabel("CLRT, ms"); ax.set_title("Fig 5. CLRT per transaction")
    ax.legend(); ax.grid(alpha=.3); save(fig, "fig05_clrt_by_txn.png")

    fe = json.load(open(os.path.join(EV, "fingerprinting", "fingerprint_eval.json")))
    res = ["1ms", "500us", "100us", "50us", "10us"]
    chans = {c["label"]: c for c in fe["clrt_magnitude_channel"]}
    natc = next(v for k, v in chans.items() if "corpus" in k); protc = next(v for k, v in chans.items() if "protected" in k)
    fig, ax = plt.subplots(figsize=(7, 4.2)); x = range(len(res))
    ax.bar([i - .2 for i in x], [natc["leakage"][r]["entropy_bits_MM"] for r in res], .4, label="native (n=300)", color="#555")
    ax.bar([i + .2 for i in x], [protc["leakage"][r]["entropy_bits_MM"] for r in res], .4, label="protected", color="#2ca02c")
    ax.set_xticks(list(x)); ax.set_xticklabels(res); ax.set_xlabel("observer bin resolution")
    ax.set_ylabel("CLRT entropy, bits (Miller-Madow)"); ax.set_title("Fig 6. Timing leakage before/after (>=500us reliable)")
    ax.legend(); ax.grid(alpha=.3, axis="y"); save(fig, "fig06_leakage_before_after.png")

    err = [(x - 25.0) * 1000.0 for x in prot]; m = sum(err) / len(err)
    fig, ax = plt.subplots(figsize=(7, 4.2)); ax.hist(err, bins=30, color="#1f77b4", alpha=.8)
    ax.set_xlabel("emitted interval − G, µs"); ax.set_ylabel("transactions")
    ax.set_title("Fig 7. Deadline error at G=25 ms (n=%d, sd=%.1f µs)" % (len(err), (sum((e-m)**2 for e in err)/len(err))**.5))
    ax.grid(alpha=.3); save(fig, "fig07_deadline_error.png")

    fig, ax = plt.subplots(figsize=(7, 4.2))
    comps = ["c1: deadline→\nfirst blocker term", "c2: term→\nresp egress", "total\nerror"]
    means = [14.4, 1720.1, 1734.5]; sds = [7.16, 1.14, 7.34]
    ax.bar(comps, means, yerr=sds, capsize=5, color=["#ff7f0e", "#1f77b4", "#2ca02c"])
    for i, (mm, s) in enumerate(zip(means, sds)):
        ax.text(i, mm + 30, "%.1f±%.2f ns" % (mm, s), ha="center", fontsize=9)
    ax.set_ylabel("nanoseconds"); ax.set_title("Fig 8. Release-tail decomposition (Part 12, n=100)")
    ax.grid(alpha=.3, axis="y"); save(fig, "fig08_release_tail_c1_c2.png")

    def guard(js):
        c = json.loads(open(js).read().split("P12READ ", 1)[1])["counters"]
        return c.get("ctr_response_actually_held", 0), c.get("ctr_response_zero_hold", 0)
    h1, z1 = guard(os.path.join(EV, "g_guard", "lowg_g1.read.json"))
    h25, z25 = guard(os.path.join(EV, "g_guard", "protnative_g25.read.json"))
    fig, ax = plt.subplots(figsize=(7, 4.2)); labels = ["G=1 ms\n(< native ~2 ms)", "G=25 ms\n(> native)"]
    ax.bar(labels, [h1, h25], label="protection applied", color="#2ca02c")
    ax.bar(labels, [z1, z25], bottom=[h1, h25], label="low-G warning (zero hold)", color="#d62728")
    ax.set_ylabel("transactions (n=30)"); ax.set_title("Fig 9. G-selection guard fires when G < native")
    ax.legend(); ax.grid(alpha=.3, axis="y"); save(fig, "fig09_g_guard.png")

    fig, ax = plt.subplots(figsize=(7, 4.2))
    progs = ["Part 12\n(synthetic)", "ibspg_dnp3\n(+classify)", "normalizer\n(+G-guard)"]; stages = [12, 11, 10]
    ax.bar(progs, stages, color="#1f77b4"); ax.axhline(12, ls="--", color="k", alpha=.5, label="12-stage budget")
    for i, s in enumerate(stages):
        ax.text(i, s + .1, "%d/12" % s, ha="center")
    ax.set_ylim(0, 13); ax.set_ylabel("ingress MAU stages"); ax.set_title("Fig 10. Ingress stage use (0 egress, 0 TCAM)")
    ax.legend(); ax.grid(alpha=.3, axis="y"); save(fig, "fig10_resource_use.png")

    print("generated %d figures in %s" % (len(made), a.figdir))
    for m in made:
        print("  ", m)


if __name__ == "__main__":
    main()
