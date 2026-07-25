#!/usr/bin/env python3
"""make_summary_figure.py — one publication figure for the in-network DNP3 normalizer.

Four panels, all from measured silicon captures:
  (a) CLRT ECDF, native vs three policy targets  — the timing result
  (b) CLRT spread per condition, log scale       — the collapse, quantified
  (c) on-wire size distribution, native vs defended — the size channel, still open
  (d) per-device channel inventory                — what is closed and what is not

Requires the research venv for matplotlib:
  ~/.venvs/research/bin/python make_summary_figure.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze_evidence import analyze, stats  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(HERE, "evidence")


def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    conds = [
        ("native (no defense)", os.path.join(EV, "e2e", "before30.pcap"), "#444444"),
        ("G = 17 ms", os.path.join(EV, "gsweep", "g17.pcap"), "#1f77b4"),
        ("G = 25 ms", os.path.join(EV, "e2e", "after30.pcap"), "#2ca02c"),
        ("G = 40 ms", os.path.join(EV, "gsweep", "g40.pcap"), "#d62728"),
    ]
    data = [(lb, analyze(p), c) for lb, p, c in conds if os.path.exists(p)]

    fig, axes = plt.subplots(2, 2, figsize=(12.5, 8))

    # (a) CLRT ECDF
    ax = axes[0][0]
    for lb, r, c in data:
        xs = sorted(r["clrt_ms"])
        if not xs:
            continue
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax.step(xs, ys, where="post", label="%s (n=%d)" % (lb, len(xs)), color=c, linewidth=2)
    ax.set_xlabel("ACK → response interval (CLRT), ms")
    ax.set_ylabel("empirical CDF")
    ax.set_title("(a) Timing channel: native spread vs policy-set constant")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)

    # (b) spread per condition, log scale
    ax = axes[0][1]
    labels = [lb for lb, _, _ in data]
    sds = [stats(r["clrt_ms"]).get("sd", 0) or 1e-4 for _, r, _ in data]
    ax.bar(range(len(labels)), sds, color=[c for _, _, c in data])
    ax.set_yscale("log")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=8)
    ax.set_ylabel("CLRT standard deviation, ms (log)")
    ax.set_title("(b) Spread collapses ~272× once G exceeds the native interval")
    for i, v in enumerate(sds):
        ax.text(i, v * 1.15, "%.4f" % v, ha="center", fontsize=8)
    ax.grid(alpha=0.3, axis="y")

    # (c) size distribution — the channel still open
    ax = axes[1][0]
    for lb, r, c in data[:1] + data[2:3]:
        xs = r["all_wire_sizes"]
        if xs:
            ax.hist(xs, bins=range(min(xs), max(xs) + 6, 2), alpha=0.6,
                    label="%s — %d distinct" % (lb, len(set(xs))), color=c)
    ax.set_xlabel("on-wire frame size, bytes")
    ax.set_ylabel("frames")
    ax.set_title("(c) Size channel: NOT yet closed (identical before and after)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)

    # (d) per-device channel inventory from the native corpus
    ax = axes[1][1]
    corpus = os.path.join(os.path.dirname(os.path.dirname(HERE)), "Traffic Trace")
    devs, clrts, sizes = [], [], []
    for d in ("SEL751", "AB1400", "ION7550"):
        p = os.path.join(corpus, d + ".pcap")
        if not os.path.exists(p):
            continue
        r = analyze(p)
        devs.append(d)
        clrts.append(len(r["clrt_ms"]))
        sizes.append(len(set(r["all_wire_sizes"])))
    x = range(len(devs))
    ax.bar([i - 0.2 for i in x], clrts, width=0.4, label="CLRT samples (separate-ACK only)")
    ax.bar([i + 0.2 for i in x], sizes, width=0.4, label="distinct wire sizes")
    ax.set_yscale("log")
    ax.set_xticks(list(x))
    ax.set_xticklabels(devs)
    ax.set_title("(d) Only SEL-751 has a CLRT at all — ACK mode remains a discriminator")
    ax.grid(alpha=0.3, axis="y")
    ax.legend(fontsize=8)

    fig.suptitle("In-network DNP3 timing normalization on Tofino-1 — real replayed traffic, "
                 "wire-measured", fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(EV, "SUMMARY_FIGURE.png")
    fig.savefig(out, dpi=160)
    print("wrote", out)

    # machine-readable twin of the panels
    summ = {lb: {"clrt": stats(r["clrt_ms"]),
                 "distinct_sizes": sorted(set(r["all_wire_sizes"])),
                 "roles": r["roles"]} for lb, r, _ in data}
    json.dump(summ, open(os.path.join(EV, "SUMMARY_FIGURE.json"), "w"), indent=1)
    print("wrote", os.path.join(EV, "SUMMARY_FIGURE.json"))


if __name__ == "__main__":
    main()
