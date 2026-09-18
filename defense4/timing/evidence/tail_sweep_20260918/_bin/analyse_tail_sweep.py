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
        # The deadline has to be in the key. Without it every point of a series collapsed into
        # one group and the read lane reported a single 6 ms "deadline" holding all eighteen.
        dl = r["D_ms"] if r["txn_class"] in READ_LANE_CLASSES else r["A_ms"]
        per[(r["series"], r["pass"], r["txn_class"], dl)].append(r)

    for (series, pas, cls, _dl), rs in per.items():
        bl = base.get((pas, cls))
        if bl is None:
            continue
        ack = np.array([float(x["ack_ms"]) for x in rs])
        clrt = np.array([float(x["clrt_ms"]) for x in rs])
        if cls in READ_LANE_CLASSES:
            cfg = float(rs[0]["D_A_ms"]); deadline = float(rs[0]["D_ms"])
            tail = _median(ack) - bl - cfg
        else:
            cfg = float(rs[0]["A_ms"]); deadline = cfg
            tail = _median(ack) - cfg          # the baseline is not subtracted on this lane
        key = (series, cls, deadline)
        out[key][pas] = dict(tail_ms=tail, n=int(ack.size), ack_median_ms=_median(ack),
                             clrt_median_ms=_median(clrt), baseline_ms=bl,
                             configured_ms=cfg)
    return out


def summarise(t):
    res = []
    for (series, cls, deadline), by_pass in sorted(t.items()):
        v = np.array([p["tail_ms"] for p in by_pass.values()])
        res.append(dict(
            series=series, txn_class=cls, deadline_ms=deadline,
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
        print(f"    {'class':8s} {'deadline':>9s} {'n':>6s} {'p':>2s} {'tail us':>8s} "
              f"{'min':>8s} {'max':>8s} {'sd':>7s}")
        for r in sorted(rs, key=lambda x: (x["txn_class"], x["deadline_ms"])):
            note = "  saturated" if r["saturated"] else ""
            print(f"    {r['txn_class']:8s} {r['deadline_ms']:9.0f} {r['n_total']:6d} "
                  f"{r['passes']:2d} {r['tail_ms']*1000:8.1f} {r['tail_min_ms']*1000:8.1f} "
                  f"{r['tail_max_ms']*1000:8.1f} {r['tail_sd_ms']*1000:7.1f}{note}")


def figure(res):
    sys.path.insert(0, str(ROOT.parents[1] / "analysis"))
    import figstyle as fs                                  # noqa: E402
    import matplotlib.pyplot as plt                        # noqa: E402
    fs.use_ieee()

    rd = [r for r in res if r["series"] == "readlane" and r["txn_class"] == "READ"]
    ctl = [r for r in res if r["series"] == "ctl_full" and r["txn_class"] == "OPERATE"]
    red = [r for r in res if r["series"] == "ctl_reduced" and r["txn_class"] == "OPERATE"]
    rd.sort(key=lambda r: r["deadline_ms"])
    ctl.sort(key=lambda r: r["deadline_ms"])
    red.sort(key=lambda r: r["deadline_ms"])

    fig, ax = plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.0))

    def bars(rs):
        x = [r["deadline_ms"] for r in rs]
        y = [r["tail_ms"] * 1000 for r in rs]
        lo = [y[i] - rs[i]["tail_min_ms"] * 1000 for i in range(len(rs))]
        hi = [rs[i]["tail_max_ms"] * 1000 - y[i] for i in range(len(rs))]
        return x, y, [lo, hi]

    live = [r for r in rd if not r["saturated"]]
    sat = [r for r in rd if r["saturated"]]
    x, y, e = bars(live)
    ax[0].errorbar(x, y, yerr=e, marker="o", ms=3.0, lw=1.0, capsize=2,
                   color=fs.TIMING_ON, mec="black", mew=0.4, label="READ")
    if sat:
        knee = min(r["deadline_ms"] for r in sat)
        ax[0].axvspan(knee - 1, max(r["deadline_ms"] for r in sat) + 1,
                      color="#EEEEEE", zorder=0)
        ax[0].text(knee + 0.5, 0.94, "released early", fontsize=8, color=fs.GREY,
                   transform=ax[0].get_xaxis_transform(), va="top")
    ax[0].set_xlabel("Release budget $D$ (ms)")
    ax[0].set_ylabel("Release tail ($\\mu$s)")
    ax[0].set_title("(a) read lane", loc="left", fontsize=8)

    for rs, lab, col, mk in ((ctl, "$J\\leq 12$ ms", fs.TIMING_ON, "s"),
                             (red, "$J\\leq 6$ ms", fs.SERIES_3, "^")):
        if not rs:
            continue
        x, y, e = bars(rs)
        ax[1].errorbar(x, y, yerr=e, marker=mk, ms=3.4, lw=1.0, capsize=2,
                       color=col, mec="black", mew=0.4, label=lab)
    ax[1].set_xlabel("Control-lane offset $A$ (ms)")
    ax[1].set_ylabel("Release tail ($\\mu$s)")
    ax[1].set_title("(b) control lane", loc="left", fontsize=8)
    ax[1].legend(loc="best", fontsize=8)

    for a in ax:
        fs.grid(fig, a)
    fig.tight_layout(pad=0.3)

    data = [(r["series"], r["txn_class"], r["deadline_ms"], r["configured_ms"], r["passes"],
             r["n_total"], round(r["tail_ms"] * 1000, 2), round(r["tail_min_ms"] * 1000, 2),
             round(r["tail_max_ms"] * 1000, 2), round(r["tail_sd_ms"] * 1000, 2),
             int(r["saturated"])) for r in res]
    fs.save(fig, FIGDIR, "fig_release_tail", inputs=[TXNS, ROOT / "blocks.csv"],
            caption=("The release tail, the interval between a packet's scheduled instant and its "
                     "actual one, against the deadline the operator sets. (a) Read lane, against "
                     "the release budget $D$; past the knee the reservoir spends its pass budget "
                     "and releases early, so no tail is defined. (b) Control lane, against the "
                     "acknowledgment offset $A$, over the whole range the control plane admits. "
                     "The lower end of that range is set by the jitter codebook: with $J$ drawn "
                     "from $\\{2,6,12\\}$ ms the smallest installable offset is 16 ms, and with "
                     "$\\{2,4,6\\}$ ms it is 12 ms. Whiskers span three independent installs of "
                     "each policy."),
            stats_note=("tail = median(request-to-acknowledgment | Obfuscated) - configured hold, "
                        "less the Timing OFF median of the same pass on the read lane, which is "
                        "anchored on the outstation's acknowledgment; the control lane is "
                        "anchored on the request and subtracts no baseline. Point is the mean "
                        "over three passes, whiskers the min and max"),
            data_rows=data,
            data_header=["series", "txn_class", "deadline_ms", "configured_ms", "passes",
                         "n", "tail_us", "tail_min_us", "tail_max_us", "tail_sd_us",
                         "saturated"])


def main(argv) -> int:
    rows = load()
    base = baselines(rows)
    res = summarise(tails(rows, base))
    if "--check" in argv:
        if not OUT_JSON.exists():
            print(f"{OUT_JSON} is not published", file=sys.stderr)
            return 1
        old = {(r["series"], r["txn_class"], r["deadline_ms"]): r
               for r in json.loads(OUT_JSON.read_text())["points"]}
        bad = [f"{k}: {old[k]['tail_ms']:.6f} against {r['tail_ms']:.6f}"
               for r in res
               for k in [(r["series"], r["txn_class"], r["deadline_ms"])]
               if k in old and abs(old[k]["tail_ms"] - r["tail_ms"]) > 1e-9]
        missing = [str(k) for r in res
                   for k in [(r["series"], r["txn_class"], r["deadline_ms"])] if k not in old]
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
        figure(res)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
