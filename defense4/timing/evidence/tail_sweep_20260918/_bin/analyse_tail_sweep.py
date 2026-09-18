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
# The manuscript copy. Published by this generator and nothing else, with a hash manifest that
# --check recomputes, the same contract the other figure families keep.
PUBDIR = ROOT.parents[3] / "paper" / "rewrite" / "figures" / "tail"
PUB_EXT = (".pdf", ".png", "_data.csv", ".caption.md", ".provenance.json")

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

    # One column, 2x2: the three classes' tails on a shared axis, then which value governs.
    # READ and SELECT sit on the read lane and are read against the Timing OFF baseline; OPERATE
    # is timed from the request, so its tail is its acknowledgment's arrival beyond T_0 + D_A.
    fig, grid = plt.subplots(2, 2, figsize=(fs.COL_WIDTH_IN, 3.05))
    tails_ax = [grid[0][0], grid[0][1], grid[1][0]]
    ax = [None, grid[1][1]]          # ax[1] keeps its old meaning below: the governing panel

    CLRT_PINNED = 4.0                # the read-lane series holds CLRT_new at 4 ms throughout
    for a_, cls, ref, title in ((tails_ax[0], "READ", "D_A", "READ"),
                                (tails_ax[1], "SELECT", "D_A", "SELECT"),
                                (tails_ax[2], "OPERATE", "D_A", "OPERATE")):
        pts = [r for r in res if r["series"] == "readlane" and r["txn_class"] == cls
               and r["reference"] == ref]
        # OPERATE rows are keyed on D_A; put them on the budget axis the other two use.
        for r in pts:
            r["_x"] = r["deadline_ms"] + (CLRT_PINNED if cls == "OPERATE" else 0.0)
        pts.sort(key=lambda r: r["_x"])
        live = [r for r in pts if not r["saturated"]]
        sat = [r for r in pts if r["saturated"]]
        # One neutral colour for every tail. Panel (d) spends blue and orange on obeyed and
        # ignored; reusing them for the two branches would read as that. Position shows the
        # branches, and the whiskers, spanning the three installs, show where they disagree.
        x = [r["_x"] for r in live]
        y = [r["tail_ms"] * 1000 for r in live]
        e = [[y[k] - live[k]["tail_min_ms"] * 1000 for k in range(len(live))],
             [live[k]["tail_max_ms"] * 1000 - y[k] for k in range(len(live))]]
        a_.errorbar(x, y, yerr=e, marker="o", ms=3.0, ls="none", elinewidth=0.8, capsize=1.6,
                    color=fs.NEUTRAL, mec="black", mew=0.4)
        if sat:
            a_.axvspan(min(r["_x"] for r in sat) - 0.5, max(r["_x"] for r in sat) + 1.0,
                       color="#EDEDED", zorder=0)
        a_.set_title(title, fontsize=8)
        a_.set_xlim(4, 38)
        a_.set_ylim(0, 1120)
        a_.set_xlabel("Release budget $D$ [ms]")
    tails_ax[0].set_ylabel("Release tail $\\varepsilon$ [$\\mu$s]")
    tails_ax[2].set_ylabel("Release tail $\\varepsilon$ [$\\mu$s]")
    tails_ax[1].set_yticklabels([])
    grid[1][1].set_title("Which value governs", fontsize=8)

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
                   )
        seen.add(lab)
    lim = [0, 27]
    ax[1].plot(lim, lim, ls=":", lw=1.0, color=fs.GREY, zorder=1)
    ax[1].set_xlim(*lim)
    ax[1].set_ylim(*lim)
    ax[1].set_xlabel("Configured value [ms]")
    ax[1].set_ylabel("Measured interval [ms]")
    # Labelled in place, not keyed. An opaque key has no safe corner at this size: in the upper
    # left it hid the ignored point at A = 12 ms, and in the lower right the one at R - A = 12.
    # A label set in clear space beside its own group cannot cover anything.
    ax[1].text(13.5, 9.5, "obeyed", fontsize=8, color=fs.TIMING_ON, ha="left", va="center")
    ax[1].text(14.0, 23.6, "ignored", fontsize=8, color=fs.TIMING_OFF_ALT, ha="left",
               va="center")

    for a in (grid[0][0], grid[0][1], grid[1][0], grid[1][1]):
        fs.grid(fig, a)
    fig.tight_layout(pad=0.3, h_pad=0.6, w_pad=0.5)

    data = [(r["series"], r["txn_class"], r["reference"], r["deadline_ms"], r["configured_ms"],
             r["passes"], r["n_total"], round(r["tail_ms"] * 1000, 2),
             round(r["tail_min_ms"] * 1000, 2), round(r["tail_max_ms"] * 1000, 2),
             round(r["tail_sd_ms"] * 1000, 2), int(r["saturated"])) for r in res]
    fs.save(fig, FIGDIR, "fig_release_tail", inputs=[TXNS, ROOT / "blocks.csv"],
            caption=("The release tail $\\varepsilon$ against the budget $D$ for READ, SELECT "
                     "and OPERATE, over three installs of each setting; whiskers span them, and "
                     "in the shaded region the reservoir spends its pass budget and releases "
                     "early. OPERATE is timed from the request, so its $\\varepsilon$ is the "
                     "acknowledgment's arrival beyond $T_0 + D_A$. Lower right, each configured "
                     "quantity that could set a master-visible OPERATE interval, against the "
                     "interval it would set: CLRT$_{\\mathrm{new}}$ is obeyed, $A$ and $R-A$ are "
                     "ignored."),
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
        pub = check_published()
        if pub:
            print(f"tail sweep: {len(pub)} problem(s)", file=sys.stderr)
            for b in pub:
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
        publish()
    return 0


def _sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publish():
    import shutil
    PUBDIR.mkdir(parents=True, exist_ok=True)
    lines = []
    for ext in PUB_EXT:
        src = FIGDIR / f"fig_release_tail{ext}"
        dst = PUBDIR / src.name
        shutil.copyfile(src, dst)
        lines.append(f"{_sha(dst)}  {dst.name}")
    (PUBDIR / "FIGURES.sha256").write_text("\n".join(lines) + "\n")
    print(f"  published -> {PUBDIR}")


def check_published():
    man = PUBDIR / "FIGURES.sha256"
    if not man.exists():
        return [f"{man} is missing"]
    bad = []
    for line in man.read_text().split("\n"):
        if not line.strip():
            continue
        h, name = line.split("  ", 1)
        pub, gen = PUBDIR / name, FIGDIR / name
        if not pub.exists() or _sha(pub) != h:
            bad.append(f"{name}: published copy does not match its manifest")
        elif not gen.exists() or _sha(gen) != h:
            bad.append(f"{name}: published copy does not match the generating tree")
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
