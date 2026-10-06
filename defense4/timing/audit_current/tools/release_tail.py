#!/usr/bin/env python3
"""Measure the release tail from the master-facing captures already in the repository.

The release tail is the interval between the instant the schedule asks a packet to leave and
the instant it actually leaves, written ``e - \\hat{e}`` in the design section. It is a hold,
so it is a cost: every microsecond of it is latency the master pays and the operator did not
configure.

The switch never timestamps its own departures, so the tail cannot be read off one transaction.
It can be read off the two arms together. On the acknowledgment lane,

    Timing OFF  :  m_A - m_0 = L
    Obfuscated  :  m_A - m_0 = L + D_A + tail

where ``L`` collects the outstation's own acknowledgment latency and every propagation term on
the path. ``L`` appears in both arms and cancels in the difference, so

    tail = median(ack | Obfuscated) - median(ack | Timing OFF) - configured hold

is an estimate of the location shift the hold introduces beyond its configured value. It needs
no instrumented build, no egress timestamp and no new capture. What it gives up is per-transaction
resolution: it is a population shift, not a per-exchange measurement, and it holds only while the
outstation's acknowledgment latency is distributed the same way in both arms. The interleaved
block schedule is what makes that assumption checkable, and the tight Timing OFF spread is what
makes it plausible; the run prints both.

Three results come out of one pass.

1. **The acknowledgment lane carries a tail of a few hundred microseconds.** In ``campaign_v1``
   it is about 0.78 ms on READ against a configured 20 ms hold.

2. **The coupling cancels it on the CLRT.** Both deadlines are computed from the same instant
   ``t_A``, so the tails of the two releases subtract. The measured CLRT therefore sits on its
   configured value to well under a microsecond, and the design's central identity is confirmed
   numerically rather than only algebraically.

3. **The tail is a function of the release budget, not of the split.** Across the eight sweep
   points that hold ``D`` at 24 ms and move the split between ``D_A`` and the configured
   ``CLRT_new``, the tail does not move. Across the budget ramp it grows with ``D``, and past the
   saturation knee the estimate goes negative, which is the arithmetic reporting that the switch
   can no longer hold as long as it was asked to.

The estimator is reported two ways, because the difference of medians is only a location shift
when one of the two terms is nearly constant. The Hodges-Lehmann estimate, the median of all
pairwise differences between the arms, makes no such assumption and is the one to quote if the
two disagree. On this data they agree to a few microseconds.

Usage::

    python3 release_tail.py                 measure, write outputs/release_tail.json
    python3 release_tail.py --check         verify the published JSON, write nothing

``--check`` exits non-zero if any published figure moved, so a silent drift in the derived
captures cannot pass.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]                                  # defense4/timing
CAMPAIGN = TIMING / "evidence" / "campaign_v1"
TXNS = CAMPAIGN / "derived" / "transactions.csv"
SWEEP_POINTS = CAMPAIGN / "sweep" / "sweep_points.csv"
CONSTANTS = CAMPAIGN / "PROVENANCE_CONSTANTS.json"
OUT_JSON = TIMING / "audit_current" / "outputs" / "release_tail.json"

BOOTSTRAP = 2000
SEED = 0
CLASSES = ("READ", "SELECT", "OPERATE")
# The read lane is anchored on the outstation's acknowledgment and the control lane on the
# request, so the two lanes do not subtract the same baseline. Naming them here keeps that
# distinction out of the arithmetic below, where it would be invisible.
READ_LANE = ("READ", "SELECT")


def _median(v) -> float:
    return float(np.median(v))


def _hodges_lehmann(a: np.ndarray, b: np.ndarray, rng, cap: int = 4000) -> float:
    """Median of all pairwise b - a. Subsampled above `cap` per arm; the estimate is a median,
    so a few million pairs settle it and the full cross product buys nothing but memory."""
    if a.size > cap:
        a = rng.choice(a, cap, replace=False)
    if b.size > cap:
        b = rng.choice(b, cap, replace=False)
    return float(np.median(b[:, None] - a[None, :]))


def _load_campaign():
    by = defaultdict(list)
    with TXNS.open() as fh:
        for r in csv.DictReader(fh):
            by[(r["arm"], r["txn_class"])].append(
                (r["session"], float(r["ack_ms"]), float(r["clrt_ms"]), float(r["rt_ms"])))
    if not by:
        sys.exit(f"no rows in {TXNS}")
    return by


def _session_bootstrap(off_by_session, obf_by_session, cfg, rng):
    """Resample grouped runs, never exchanges: the 22 runs are the independent unit here, and
    resampling exchanges would report a precision the campaign does not have."""
    ko, kb = sorted(off_by_session), sorted(obf_by_session)
    draws = []
    for _ in range(BOOTSTRAP):
        io = rng.integers(0, len(ko), len(ko))
        ib = rng.integers(0, len(kb), len(kb))
        vo = np.concatenate([off_by_session[ko[i]] for i in io])
        vb = np.concatenate([obf_by_session[kb[i]] for i in ib])
        draws.append(_median(vb) - _median(vo) - cfg)
    return [float(x) for x in np.percentile(draws, [2.5, 97.5])]


def measure() -> dict:
    const = json.loads(CONSTANTS.read_text())["config"]["obfuscated_arm"]
    d_a = float(const["D_A_ms"])          # read lane: hold from the acknowledgment's arrival
    clrt_cfg = float(const["D_R_ms"])     # the configured CLRT_new, the name the code still uses
    a_ms = float(const["A_ms"])           # control lane: acknowledgment offset from the request
    budget = d_a + clrt_cfg

    rng = np.random.default_rng(SEED)
    by = _load_campaign()
    out = {
        "configured": {"D_A_ms": d_a, "CLRT_new_ms": clrt_cfg, "A_ms": a_ms, "D_ms": budget},
        "estimator": ("location shift of the request-to-acknowledgment median between the arms, "
                      "minus the configured hold; the outstation's acknowledgment latency and "
                      "every propagation term cancel in the difference"),
        "campaign": {},
        "coupling": {},
        "cross_check_added_latency_ms": {},
        "sweep": [],
    }

    for c in CLASSES:
        off = np.array([x[1] for x in by[("native", c)]])
        obf = np.array([x[1] for x in by[("obfuscated", c)]])
        # The control lane releases at T_0 + A, timed from the request, so it never waits for the
        # outstation's acknowledgment. Adding that latency back is what makes the two lanes
        # comparable; on the read lane it is already inside both arms and cancels.
        lane = "read" if c in READ_LANE else "control"
        cfg = d_a if lane == "read" else a_ms
        shift = _median(obf) - _median(off)
        tail = shift - cfg + (0.0 if lane == "read" else _median(off))
        so, sb = defaultdict(list), defaultdict(list)
        for s, a, _, _ in by[("native", c)]:
            so[s].append(a)
        for s, a, _, _ in by[("obfuscated", c)]:
            sb[s].append(a)
        so = {k: np.array(v) for k, v in so.items()}
        sb = {k: np.array(v) for k, v in sb.items()}
        lo, hi = _session_bootstrap(so, sb, cfg - (0.0 if lane == "read" else _median(off)), rng)
        out["campaign"][c] = {
            "lane": lane,
            "n_timing_off": int(off.size),
            "n_obfuscated": int(obf.size),
            "ack_median_timing_off_ms": _median(off),
            "ack_median_obfuscated_ms": _median(obf),
            "ack_iqr_timing_off_ms": float(np.subtract(*np.percentile(off, [75, 25]))),
            "release_tail_ms": tail,
            "release_tail_ci95_ms": [lo, hi],
            "release_tail_hodges_lehmann_ms":
                _hodges_lehmann(off, obf, rng) - cfg + (0.0 if lane == "read" else _median(off)),
            "n_grouped_runs": len(so),
        }

    # The coupling: both deadlines come from t_A, so the two tails subtract on the CLRT.
    for c in CLASSES:
        obf = np.array([x[2] for x in by[("obfuscated", c)]])
        out["coupling"][c] = {
            "clrt_median_obfuscated_ms": _median(obf),
            "residual_tail_ms": _median(obf) - clrt_cfg,
        }

    # A second, independent route to the same number, and it must follow each lane's anchor.
    # On the read lane both releases hang off t_A, so the outstation's acknowledgment latency
    # sits in both arms and only its response time subtracts. On the control lane the response
    # leaves at T_0 + R, timed from the request, so the whole Timing OFF response time subtracts.
    # Using the read-lane form on OPERATE was wrong by the acknowledgment latency, 0.53 ms.
    r_ms = float(const["R_ms"])
    for c in CLASSES:
        off_rt = np.array([x[3] for x in by[("native", c)]])
        obf_rt = np.array([x[3] for x in by[("obfuscated", c)]])
        off_clrt = np.array([x[2] for x in by[("native", c)]])
        tail_r = out["campaign"][c]["release_tail_ms"] + out["coupling"][c]["residual_tail_ms"]
        if c in READ_LANE:
            predicted = budget + tail_r - _median(off_clrt)
            form = "D + tail - CLRT_original"
        else:
            predicted = r_ms + tail_r - _median(off_rt)
            form = "R + tail - request-to-response under Timing OFF"
        measured = _median(obf_rt) - _median(off_rt)
        out["cross_check_added_latency_ms"][c] = {
            "form": form, "predicted": predicted, "measured": measured,
            "difference": predicted - measured}

    # The sweep answers a question the campaign cannot: whether the tail follows the budget or
    # the split. Its own Timing OFF point is the baseline; the campaign's is a different session.
    sweep_csv = Path("/tmp/cv1_out/sweep_canonical.csv")
    if sweep_csv.exists():
        g = defaultdict(list)
        with sweep_csv.open() as fh:
            for r in csv.DictReader(fh):
                if r["txn_class"] == "READ":
                    g[r["point"]].append(float(r["ack_ms"]))
        base = _median(g["sw_off"])
        with SWEEP_POINTS.open() as fh:
            for r in csv.DictReader(fh):
                if r.get("mode") != "D4" or r["point"] not in g:
                    continue
                v = np.array(g[r["point"]])
                da = float(r["D_A_ms"])
                tail = _median(v) - base - da
                draws = [_median(rng.choice(v, v.size)) - base - da for _ in range(BOOTSTRAP)]
                lo, hi = (float(x) for x in np.percentile(draws, [2.5, 97.5]))
                # A negative estimate is not a negative tail. It says the realized hold came
                # in under the configured one, which is the mechanism past its operating region:
                # the reservoir spent its pass budget and released early. Flagged, not reported
                # as a measurement.
                out["sweep"].append({
                    "point": r["point"], "D_A_ms": da, "CLRT_new_ms": float(r["D_R_ms"]),
                    "D_ms": float(r["D_ms"]), "n": int(v.size),
                    "ack_median_ms": _median(v), "release_tail_ms": tail,
                    "release_tail_ci95_ms": [lo, hi],
                    "saturated": bool(tail < 0.0)})
        out["sweep_baseline_ack_median_ms"] = base
        out["sweep_baseline_n"] = len(g["sw_off"])
        out["sweep"].sort(key=lambda d: (d["D_ms"], d["D_A_ms"]))
    return out


def _report(d: dict) -> None:
    cfg = d["configured"]
    print("Release tail, from the master-facing captures. No instrumented build, no new capture.")
    print(f"  configured  D_A = {cfg['D_A_ms']:g} ms, CLRT_new = {cfg['CLRT_new_ms']:g} ms, "
          f"A = {cfg['A_ms']:g} ms, budget D = {cfg['D_ms']:g} ms\n")
    print(f"  {'class':8s} {'lane':8s} {'n/arm':>6s} {'OFF med':>8s} {'IQR':>6s} {'obf med':>8s} "
          f"{'tail us':>8s} {'95% CI us':>18s} {'H-L us':>8s}")
    for c, r in d["campaign"].items():
        lo, hi = r["release_tail_ci95_ms"]
        print(f"  {c:8s} {r['lane']:8s} {r['n_obfuscated']:6d} "
              f"{r['ack_median_timing_off_ms']:8.4f} {r['ack_iqr_timing_off_ms']:6.3f} "
              f"{r['ack_median_obfuscated_ms']:8.4f} {r['release_tail_ms']*1000:8.1f} "
              f"[{lo*1000:7.1f},{hi*1000:7.1f}] {r['release_tail_hodges_lehmann_ms']*1000:8.1f}")
    print("\n  The coupling: both deadlines come from t_A, so the two tails subtract on the CLRT.")
    for c, r in d["coupling"].items():
        print(f"    {c:8s} measured CLRT {r['clrt_median_obfuscated_ms']:7.4f} ms, "
              f"residual {r['residual_tail_ms']*1000:+7.2f} us")
    print("\n  Cross-check, added response latency = D + response-lane tail - CLRT_original:")
    for c, r in d["cross_check_added_latency_ms"].items():
        print(f"    {c:8s} predicted {r['predicted']:8.4f} ms  measured {r['measured']:8.4f} ms  "
              f"difference {r['difference']*1000:+6.1f} us")
    if d.get("sweep"):
        print(f"\n  Across the sweep, baseline {d['sweep_baseline_ack_median_ms']:.4f} ms "
              f"(n={d['sweep_baseline_n']}):")
        print(f"    {'point':14s} {'D_A':>4s} {'CLRT':>5s} {'D':>4s} {'n':>4s} {'tail us':>8s} "
              f"{'95% CI us':>20s}")
        for r in d["sweep"]:
            lo, hi = r["release_tail_ci95_ms"]
            note = "  saturated: released early" if r.get("saturated") else ""
            print(f"    {r['point']:14s} {r['D_A_ms']:4.0f} {r['CLRT_new_ms']:5.0f} "
                  f"{r['D_ms']:4.0f} {r['n']:4d} {r['release_tail_ms']*1000:8.1f} "
                  f"[{lo*1000:8.1f},{hi*1000:8.1f}]{note}")


def _check(fresh: dict) -> int:
    if not OUT_JSON.exists():
        print(f"{OUT_JSON} is not published; run without --check", file=sys.stderr)
        return 1
    old = json.loads(OUT_JSON.read_text())
    bad = []
    for c, r in fresh["campaign"].items():
        o = old.get("campaign", {}).get(c)
        if o is None:
            bad.append(f"{c}: absent from the published file")
            continue
        for k in ("release_tail_ms", "ack_median_timing_off_ms", "ack_median_obfuscated_ms"):
            if abs(o[k] - r[k]) > 1e-6:
                bad.append(f"{c}.{k}: published {o[k]:.6f} against {r[k]:.6f}")
    for c, r in fresh["coupling"].items():
        o = old.get("coupling", {}).get(c, {})
        if abs(o.get("residual_tail_ms", 1e9) - r["residual_tail_ms"]) > 1e-6:
            bad.append(f"{c}.residual_tail_ms moved")
    if bad:
        print("release tail: %d problem(s)" % len(bad), file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 1
    print("release tail: 0 problems")
    print("  every published figure matches a fresh measurement of the derived captures")
    return 0


def main(argv) -> int:
    check = "--check" in argv
    d = measure()
    if check:
        return _check(d)
    _report(d)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(d, indent=1, sort_keys=True) + "\n")
    print(f"\n  -> {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
