#!/usr/bin/env python3
"""The release tail against the release deadline, on both lanes, with between-pass error bars.

The tail is the interval between the instant the schedule asks a packet to leave and the instant
it actually leaves. The switch does not timestamp its own departures, so the tail is read off the
two arms together: the Timing OFF blocks measure the outstation's own latency plus every
propagation term, the obfuscated blocks measure that same quantity plus the configured hold plus
the tail, and the difference leaves the tail. Each pass carries its own Timing OFF blocks, so the
baseline tracks the session rather than being measured once at the start.

What this adds over `audit_current/tools/release_tail.py`, which reads the same quantity out of
campaign_v1: eighteen deadlines on the read lane instead of four, the control lane's whole
feasible range instead of one point, and a spread taken across three independent installs of
each policy instead of a bootstrap inside a single install. The three passes are what make the
error bars mean something about the mechanism rather than about one configuration of it.

    python3 analyse_tail_sweep.py            measure, write tail_sweep.json
    python3 analyse_tail_sweep.py --figure   also draw fig_release_tail
    python3 analyse_tail_sweep.py --check    verify the published JSON, write nothing
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TXNS = ROOT / "transactions.csv"
TXNS_SEP = ROOT / "transactions_sep.csv"
OUT_JSON = ROOT / "tail_sweep.json"
FIGDIR = ROOT / "figures"

READ_LANE_CLASSES = ("READ", "SELECT")     # anchored on the outstation's acknowledgment
CONTROL_CLASSES = ("OPERATE",)             # anchored on the request


def _median(v) -> float:
    return float(np.median(v))


def load():
    if not TXNS.exists():
        sys.exit(f"{TXNS} not found; run extract_tail_sweep.py first")
    rows = list(csv.DictReader(TXNS.open()))
    if not rows:
        sys.exit(f"{TXNS} is empty")
    return rows


def baselines(rows):
    """One Timing OFF median per pass per class. The tail is a difference against this, so a
    baseline that drifted over the session would move every point that followed it."""
    b = defaultdict(list)
    for r in rows:
        if r["series"] == "baseline":
            b[(r["pass"], r["txn_class"])].append(float(r["ack_ms"]))
    return {k: _median(v) for k, v in b.items() if v}


def tails(rows, base):
    """tail per (series, deadline, class, pass).

    Read lane: the configured hold is D_A, and the outstation's acknowledgment latency sits in
    both arms and cancels. Control lane: the acknowledgment leaves at T_0 + A, timed from the
    request, so it never waits for the outstation at all and that latency has to be added back.
    """
    out = defaultdict(dict)
    per = defaultdict(list)
    for r in rows:
        if r["series"] == "baseline":
            continue
        # Both configured holds go in the key. Keying on one of them collapsed points that differ
        # only in the other: with D_A alone the read lane reported a single deadline holding all
        # eighteen, and with A alone every OPERATE in the read-lane series merged into one group,
        # since that series pins A at 20 and moves D_A.
        per[(r["series"], r["pass"], r["txn_class"], r["D_A_ms"], r["A_ms"])].append(r)

    for (series, pas, cls, _da, _a), rs in per.items():
        bl = base.get((pas, cls))
        if bl is None:
            continue
        ack = np.array([float(x["ack_ms"]) for x in rs])
        clrt = np.array([float(x["clrt_ms"]) for x in rs])
        d_a = float(rs[0]["D_A_ms"])
        a_ms = float(rs[0]["A_ms"])
        if cls in READ_LANE_CLASSES:
            emit = [("D_A", d_a, float(rs[0]["D_ms"]), _median(ack) - bl - d_a)]
        else:
            # OPERATE is measured against both candidate references rather than one, because the
            # campaign cannot say which governs it: campaign_v1 set D_A and A both to 20 ms, so
            # the read-lane hold and the control-lane offset coincide there and no difference
            # between them is observable. Reporting both lets the flat one identify itself.
            emit = [("A", a_ms, a_ms, _median(ack) - a_ms),
                    ("D_A", d_a, d_a, _median(ack) - d_a)]
        for ref, cfg, deadline, tail in emit:
            out[(series, cls, ref, deadline)][pas] = dict(
                tail_ms=tail, n=int(ack.size), ack_median_ms=_median(ack),
                clrt_median_ms=_median(clrt), baseline_ms=bl, configured_ms=cfg)
    return out


def summarise(t):
    res = []
    for (series, cls, ref, deadline), by_pass in sorted(t.items()):
        v = np.array([p["tail_ms"] for p in by_pass.values()])
        res.append(dict(
            series=series, txn_class=cls, reference=ref, deadline_ms=deadline,
            passes=len(v), n_total=int(sum(p["n"] for p in by_pass.values())),
            tail_ms=float(np.mean(v)),
            tail_min_ms=float(v.min()), tail_max_ms=float(v.max()),
            tail_sd_ms=float(v.std(ddof=1)) if v.size > 1 else 0.0,
            per_pass_ms=[float(x) for x in v],
            ack_median_ms=float(np.mean([p["ack_median_ms"] for p in by_pass.values()])),
            clrt_median_ms=float(np.mean([p["clrt_median_ms"] for p in by_pass.values()])),
            configured_ms=float(list(by_pass.values())[0]["configured_ms"]),
            saturated=bool(np.mean(v) < 0.0)))
    return res


def report(res, base):
    print("Release tail against the release deadline. Spread is across independent installs.\n")
    print("  baselines (Timing OFF request-to-acknowledgment median, ms):")
    for k in sorted(base):
        print(f"    pass {k[0]}  {k[1]:8s} {base[k]:.4f}")
    for series in ("readlane", "ctl_full", "ctl_reduced"):
        rs = [r for r in res if r["series"] == series]
        if not rs:
            continue
        print(f"\n  == {series} ==")
        print(f"    {'class':8s} {'vs':>4s} {'deadline':>9s} {'n':>6s} {'p':>2s} "
              f"{'tail us':>9s} {'min':>9s} {'max':>9s} {'sd':>7s}")
        for r in sorted(rs, key=lambda x: (x["txn_class"], x["reference"], x["deadline_ms"])):
            note = "  saturated" if r["saturated"] else ""
            print(f"    {r['txn_class']:8s} {r['reference']:>4s} {r['deadline_ms']:9.0f} "
                  f"{r['n_total']:6d} {r['passes']:2d} {r['tail_ms']*1000:9.1f} "
                  f"{r['tail_min_ms']*1000:9.1f} {r['tail_max_ms']*1000:9.1f} "
                  f"{r['tail_sd_ms']*1000:7.1f}{note}")


def separation():
    """Which configured quantity sets the master-visible OPERATE response-to-ACK interval.

    The design section gives it as O = R - A. The read lane's configured CLRT_new is a different
    quantity. Nothing measured before this could tell them apart, because every run so far set
    both to 4 ms. Two crossed series separate them: one walks R - A with CLRT_new pinned, the
    other walks CLRT_new with R - A pinned.
    """
    if not TXNS_SEP.exists():
        return []
    g = defaultdict(list)
    for r in csv.DictReader(TXNS_SEP.open()):
        if r["txn_class"] != "OPERATE" or r["series"] == "baseline":
            continue
        g[(r["series"], float(r["A_ms"]), float(r["R_ms"]), float(r["CLRT_new_ms"]))].append(
            float(r["clrt_ms"]))
    out = []
    for (series, a_ms, r_ms, clrt), v in sorted(g.items()):
        out.append(dict(series=series, A_ms=a_ms, R_ms=r_ms, O_ms=r_ms - a_ms,
                        CLRT_new_ms=clrt, n=len(v), measured_ms=_median(v),
                        err_vs_O_ms=_median(v) - (r_ms - a_ms),
                        err_vs_CLRT_ms=_median(v) - clrt))
    return out


def figure(res, rows, sep):
    """Two panels. What the tail costs, and which configured value the switch actually obeys.

    An earlier draft ran to three panels and carried a legend, a title and an annotation in each.
    Ditto's figures do the opposite: few panels, few marks, and nothing written on the plot that
    the caption can carry. The control-lane question needed two panels only because it was drawn
    as two questions; as one measured-against-configured panel it is one.
    """
    sys.path.insert(0, str(ROOT.parents[1] / "analysis"))
    import figstyle as fs                                  # noqa: E402
    import matplotlib.pyplot as plt                        # noqa: E402
    import collections                                     # noqa: E402
    fs.use_ieee()

    fig, ax = plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.25))

    # ---- (a) the tail itself, against the budget that was asked for
    rd = sorted([r for r in res if r["series"] == "readlane" and r["txn_class"] == "READ"],
                key=lambda r: r["deadline_ms"])
    live = [r for r in rd if not r["saturated"]]
    sat = [r for r in rd if r["saturated"]]
    # The split is in the measurement, not chosen: an order of magnitude separates the two
    # groups and nothing lies between them.
    lo = [r for r in live if r["tail_ms"] * 1000 < 120.0]
    hi = [r for r in live if r["tail_ms"] * 1000 >= 120.0]
    for rs, col, mk in ((hi, fs.TIMING_ON, "o"), (lo, fs.TIMING_OFF_ALT, "s")):
        x = [r["deadline_ms"] for r in rs]
        y = [r["tail_ms"] * 1000 for r in rs]
        e = [[y[i] - rs[i]["tail_min_ms"] * 1000 for i in range(len(rs))],
             [rs[i]["tail_max_ms"] * 1000 - y[i] for i in range(len(rs))]]
        ax[0].errorbar(x, y, yerr=e, marker=mk, ms=3.6, ls="none", elinewidth=0.9, capsize=2,
                       color=col, mec="black", mew=0.4)
    if sat:
        ax[0].axvspan(min(r["deadline_ms"] for r in sat) - 0.5,
                      max(r["deadline_ms"] for r in sat) + 1.0, color="#EDEDED", zorder=0)
    ax[0].set_xlabel("Release budget $D$ [ms]")
    ax[0].set_ylabel("Release tail $\\varepsilon$ [$\\mu$s]")
    ax[0].set_ylim(0, 1120)

    # ---- (b) measured against configured, for every quantity that could set the interval
    g = collections.defaultdict(list)
    for r in rows:
        if r["txn_class"] == "OPERATE" and r["series"].startswith("ctl"):
            g[("ack_vs_A", float(r["A_ms"]))].append(float(r["ack_ms"]))
    for d in sep or []:
        g[("resp_vs_O", d["O_ms"])].append(d["measured_ms"]) if d["series"] == "sep_O" else None
        g[("resp_vs_C", d["CLRT_new_ms"])].append(d["measured_ms"]) if d["series"] == "sep_C" else None
    series = (("resp_vs_C", "obeyed", fs.TIMING_ON, "o"),
              ("resp_vs_O", "ignored", fs.TIMING_OFF_ALT, "s"),
              ("ack_vs_A", "ignored", fs.TIMING_OFF_ALT, "s"))
    seen = set()
    for kind, lab, col, mk in series:
        pts = sorted((k[1], float(np.median(v))) for k, v in g.items() if k[0] == kind)
        if not pts:
            continue
        ax[1].plot([a for a, _ in pts], [b for _, b in pts], marker=mk, ms=4.2, ls="none",
                   color=col, mec="black", mew=0.4, zorder=3,
                   label=lab if lab not in seen else None)
        seen.add(lab)
    lim = [0, 27]
    ax[1].plot(lim, lim, ls=":", lw=1.0, color=fs.GREY, zorder=1)
    ax[1].set_xlim(*lim)
    ax[1].set_ylim(*lim)
    ax[1].set_xlabel("Configured value [ms]")
    ax[1].set_ylabel("Measured interval [ms]")
    fs.key(ax[1], loc="upper left")

    for a in ax:
        fs.grid(fig, a)
    fig.tight_layout(pad=0.3)

    data = [(r["series"], r["txn_class"], r["reference"], r["deadline_ms"], r["configured_ms"],
             r["passes"], r["n_total"], round(r["tail_ms"] * 1000, 2),
             round(r["tail_min_ms"] * 1000, 2), round(r["tail_max_ms"] * 1000, 2),
             round(r["tail_sd_ms"] * 1000, 2), int(r["saturated"])) for r in res]
    fs.save(fig, FIGDIR, "fig_release_tail", inputs=[TXNS, ROOT / "blocks.csv"],
            caption=("(a) The release tail $\\varepsilon$, the interval between a packet's "
                     "scheduled instant and its actual one, against the budget $D$ the operator "
                     "sets, over three independent installs of each policy. It falls on one of "
                     "two branches, near 25~$\\mu$s or growing with the hold to 0.96~ms; the "
                     "shaded region is where the reservoir spends its pass budget and releases "
                     "early. (b) Every configured quantity that could set a master-visible "
                     "OPERATE interval, measured against what was asked for. The configured "
                     "CLRT$_{\\mathrm{new}}$ is obeyed on the identity; the control-lane "
                     "offset $A$ and the difference $R-A$ are ignored."),
            stats_note=("(a) tail = median(request-to-acknowledgment | Obfuscated) - median(same "
                        "| Timing OFF blocks of the same pass) - configured hold; point is the "
                        "mean over three passes, whiskers the min and max. (b) per-setting "
                        "medians of the interval each quantity is supposed to govern"),
            data_rows=data,
            data_header=["series", "txn_class", "reference", "deadline_ms", "configured_ms",
                         "passes", "n", "tail_us", "tail_min_us", "tail_max_us", "tail_sd_us",
                         "saturated"])


def main(argv) -> int:
    rows = load()
    base = baselines(rows)
    res = summarise(tails(rows, base))
    if "--check" in argv:
        if not OUT_JSON.exists():
            print(f"{OUT_JSON} is not published", file=sys.stderr)
            return 1
        old = {(r["series"], r["txn_class"], r["reference"], r["deadline_ms"]): r
               for r in json.loads(OUT_JSON.read_text())["points"]}
        bad = [f"{k}: {old[k]['tail_ms']:.6f} against {r['tail_ms']:.6f}"
               for r in res
               for k in [(r["series"], r["txn_class"], r["reference"], r["deadline_ms"])]
               if k in old and abs(old[k]["tail_ms"] - r["tail_ms"]) > 1e-9]
        missing = [str(k) for r in res
                   for k in [(r["series"], r["txn_class"], r["reference"], r["deadline_ms"])]
                   if k not in old]
        if bad or missing:
            print(f"tail sweep: {len(bad) + len(missing)} problem(s)", file=sys.stderr)
            for b in (bad + missing)[:10]:
                print("  " + b, file=sys.stderr)
            return 1
        print("tail sweep: 0 problems")
        return 0
    report(res, base)
    OUT_JSON.write_text(json.dumps(
        {"baselines_ms": {f"{k[0]}/{k[1]}": v for k, v in base.items()}, "points": res},
        indent=1, sort_keys=True) + "\n")
    print(f"\n  -> {OUT_JSON}")
    if "--figure" in argv:
        figure(res, rows, separation())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
