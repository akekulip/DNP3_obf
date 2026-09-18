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


def figure(res, rows):
    """Two panels, each drawn to the shape the data turned out to have.

    (a) The read-lane tail against the budget. It is not a curve: it splits into two regimes,
        one flat near 25 microseconds and one that grows with the hold, and which regime a
        setting lands in is reproducible across installs at most settings. Drawing a single
        line through them would invent a trend that is not there, so the two are marked apart
        and the saturated region, where the reservoir spends its budget and releases early, is
        shaded rather than plotted.

    (b) The control lane, drawn as the diagnostic it is. The design section places the
        master-facing OPERATE acknowledgment at T_0 + A, which is the dotted identity line.
        The measurement sits on the horizontal instead, at the read-lane hold, whatever A is.
    """
    sys.path.insert(0, str(ROOT.parents[1] / "analysis"))
    import figstyle as fs                                  # noqa: E402
    import matplotlib.pyplot as plt                        # noqa: E402
    fs.use_ieee()

    rd = sorted([r for r in res if r["series"] == "readlane" and r["txn_class"] == "READ"],
                key=lambda r: r["deadline_ms"])
    live = [r for r in rd if not r["saturated"]]
    sat = [r for r in rd if r["saturated"]]
    # The split is a property of the measurement, not a threshold chosen to make a picture:
    # the two groups are separated by an order of magnitude with nothing in between.
    SPLIT_US = 120.0
    lo = [r for r in live if r["tail_ms"] * 1000 < SPLIT_US]
    hi = [r for r in live if r["tail_ms"] * 1000 >= SPLIT_US]

    fig, ax = plt.subplots(1, 2, figsize=(fs.PAGE_WIDTH_IN, 2.05))

    def bars(rs):
        x = [r["deadline_ms"] for r in rs]
        y = [r["tail_ms"] * 1000 for r in rs]
        e = [[y[i] - rs[i]["tail_min_ms"] * 1000 for i in range(len(rs))],
             [rs[i]["tail_max_ms"] * 1000 - y[i] for i in range(len(rs))]]
        return x, y, e

    if sat:
        knee = min(r["deadline_ms"] for r in sat)
        ax[0].axvspan(knee - 0.5, max(r["deadline_ms"] for r in sat) + 1.0,
                      color="#EDEDED", zorder=0)
        ax[0].text(knee + 0.3, 0.96, "released\nearly", fontsize=8, color=fs.GREY,
                   transform=ax[0].get_xaxis_transform(), va="top")
    for rs, lab, col, mk in ((hi, "long branch", fs.TIMING_ON, "o"),
                             (lo, "short branch", fs.TIMING_OFF_ALT, "s")):
        if not rs:
            continue
        x, y, e = bars(rs)
        ax[0].errorbar(x, y, yerr=e, marker=mk, ms=3.2, ls="none", elinewidth=0.9, capsize=2,
                       color=col, mec="black", mew=0.4, label=lab)
    ax[0].set_xlabel("Release budget $D$ (ms)")
    ax[0].set_ylabel("Release tail ($\\mu$s)")
    ax[0].set_ylim(0, 1120)
    ax[0].set_title("(a) read lane", loc="left", fontsize=8)
    ax[0].legend(loc="upper left", fontsize=8, handletextpad=0.4, borderpad=0.3)

    # (b) the control lane, from the raw per-block medians so the identity line is comparable
    import collections
    g = collections.defaultdict(list)
    for r in rows:
        if r["txn_class"] == "OPERATE" and r["series"].startswith("ctl"):
            g[(r["series"], float(r["A_ms"]))].append(float(r["ack_ms"]))
    pts = {}
    for (series, a_ms), v in g.items():
        pts.setdefault(series, []).append((a_ms, float(np.median(v))))
    style = {"ctl_full": ("$J\\leq 12$ ms", fs.TIMING_ON, "o"),
             "ctl_reduced": ("$J\\leq 6$ ms", fs.SERIES_3, "^")}
    allA = sorted({a for v in pts.values() for a, _ in v})
    if allA:
        span = [min(allA) - 2, max(allA) + 2]
        ax[1].plot(span, span, ls=":", lw=1.0, color=fs.GREY, zorder=1)
        ax[1].text(span[0] + 0.4, span[0] + 1.2, "$e_{\\mathrm{ack}} = T_0 + A$",
                   fontsize=8, color=fs.GREY, rotation=38)
    for series, v in sorted(pts.items()):
        lab, col, mk = style.get(series, (series, fs.NEUTRAL, "x"))
        v.sort()
        ax[1].plot([a for a, _ in v], [m for _, m in v], marker=mk, ms=4.0, ls="none",
                   color=col, mec="black", mew=0.4, label=lab, zorder=3)
    ax[1].axhline(20.0, color=fs.TIMING_OFF_ALT, ls=(0, (5, 2)), lw=1.0, zorder=2)
    ax[1].text(12.4, 20.9, "$D_A = 20$ ms", fontsize=8, color=fs.TIMING_OFF_ALT)
    ax[1].set_xlabel("Configured control-lane offset $A$ (ms)")
    ax[1].set_ylabel("OPERATE request-to-ACK (ms)")
    ax[1].set_title("(b) control lane", loc="left", fontsize=8)
    ax[1].legend(loc="lower right", fontsize=8, handletextpad=0.4, borderpad=0.3)

    for a in ax:
        fs.grid(fig, a)
    fig.tight_layout(pad=0.3)

    data = [(r["series"], r["txn_class"], r["reference"], r["deadline_ms"], r["configured_ms"],
             r["passes"], r["n_total"], round(r["tail_ms"] * 1000, 2),
             round(r["tail_min_ms"] * 1000, 2), round(r["tail_max_ms"] * 1000, 2),
             round(r["tail_sd_ms"] * 1000, 2), int(r["saturated"])) for r in res]
    fs.save(fig, FIGDIR, "fig_release_tail", inputs=[TXNS, ROOT / "blocks.csv"],
            caption=("What the mechanism costs beyond the deadline it was given. (a) The read-lane "
                     "release tail against the budget $D$, over three independent installs of each "
                     "policy. The tail does not follow the budget smoothly: it falls on a short "
                     "branch near 25~$\\mu$s or a long branch that grows with the hold, reaching "
                     "0.96~ms. Past $D = 35$~ms the reservoir spends its pass budget and releases "
                     "early, so no tail is defined and the region is shaded. (b) The master-facing "
                     "OPERATE acknowledgment against the configured control-lane offset $A$. It "
                     "does not follow the dotted identity the design places it on; it sits at the "
                     "read-lane hold $D_A$, here 20~ms, for every admissible $A$ and for both "
                     "jitter codebooks."),
            stats_note=("tail = median(request-to-acknowledgment | Obfuscated) - median(same | "
                        "Timing OFF blocks of the same pass) - configured hold. Point is the mean "
                        "over three passes, whiskers the min and max across them. Panel (b) plots "
                        "per-offset medians directly, since the quantity in question is the "
                        "acknowledgment instant itself"),
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
        figure(res, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
