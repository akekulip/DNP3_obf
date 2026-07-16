#!/usr/bin/env python3
"""
trace_before_after.py -- before/after of the ACK/response timing manipulation,
applied to the REAL per-transaction native timings measured from the six device
PCAPs in ``Traffic Trace/``.

This does not re-derive the transform: it drives the shipped ``timing_policy``
module (the exact code the replay server runs) over the native per-transaction
timings reconstructed in ``reports/ack_trace_characterization.csv``. The "before"
is the measured device timing; the "after" is that same transaction pushed through
the real scheduler / ACK-response planner.

Two observables, matched to how each device actually behaves on the wire:

  * COMBINED-ACK devices (AB1400, ION7550) -- no separate ACK exists natively, so
    the manipulable observable is the request->response time. Phase-1 bounded
    response-time normalization (``ReleaseScheduler``) holds each response to a
    class-independent target. Before/after is on request->response.

  * SEPARATE-ACK device (SEL-751) -- a pure TCP ACK really precedes the DNP3
    response, so the observer-visible ACK->response gap is the fingerprint. The
    Phase-2 ``plan_ack_response_release`` reschedules the two existing packets
    (response-delay-only, ack-delay-only, gap-normalized). Before/after is on the
    ACK->response gap (and request->response).

Nothing here forges packets or edits bytes -- it only recomputes release times,
so it is a faithful projection of what the implemented defense does to these
devices' timing. Outputs (all overwritten each run):

    reports/trace_before_after.csv    one row per (device, observable, mode)
    reports/trace_before_after.json   full stats + config
    reports/trace_before_after.md     human-readable before/after tables
    reports/trace_before_after.png    distribution figure (if matplotlib present)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
from collections import defaultdict
from typing import Dict, List, Optional

import timing_policy as tp

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(HERE, "reports", "ack_trace_characterization.csv")
OUT_DIR = os.path.join(HERE, "reports")

MS = tp.MS_TO_NS  # ns per ms

# Device-specific outstation IPs (exclude the shared reference outstation 10.0.0.2).
DEVICE_IPS = {
    "SEL751": "10.0.0.1",
    "AB1400": "10.0.0.12",
    "ION7550": "10.0.0.11",
}
COMBINED_DEVICES = ("AB1400", "ION7550")
SEPARATE_DEVICES = ("SEL751",)


# ------------------------------------------------------------------ #
# Load the measured native timings from the characterization CSV
# ------------------------------------------------------------------ #

def load_native(csv_path: str) -> Dict[str, List[dict]]:
    """Return {device: [txn dicts]} for device-specific outstation transactions."""
    by_dev: Dict[str, List[dict]] = defaultdict(list)
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            dev = row["device_label"]
            ip = DEVICE_IPS.get(dev)
            if ip is None or row["outstation_ip"] != ip:
                continue  # skip reference outstation / unknown device
            try:
                req_to_resp = float(row["req_to_resp_ms"])
                req_to_ack = float(row["req_to_ack_ms"])
                ack_to_resp = float(row["ack_to_resp_ms"])
            except (ValueError, KeyError):
                continue
            by_dev[dev].append({
                "req_size": int(row["req_size"]),
                "resp_size": int(row["resp_size"]),
                "is_separate": row["first_rev_is_pure_ack"].strip().lower() == "true",
                "req_to_ack_ms": req_to_ack,
                "req_to_resp_ms": req_to_resp,
                "ack_to_resp_ms": ack_to_resp,
            })
    return by_dev


# ------------------------------------------------------------------ #
# Summary statistics
# ------------------------------------------------------------------ #

def pctl(vals: List[float], q: float) -> float:
    if not vals:
        return float("nan")
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    idx = q * (len(s) - 1)
    lo = int(idx)
    frac = idx - lo
    if lo + 1 >= len(s):
        return s[-1]
    return s[lo] * (1 - frac) + s[lo + 1] * frac


def summarize(vals: List[float]) -> dict:
    vals = [v for v in vals if v == v]  # drop NaN
    if not vals:
        return {"n": 0}
    return {
        "n": len(vals),
        "median": round(statistics.median(vals), 3),
        "p95": round(pctl(vals, 0.95), 3),
        "p99": round(pctl(vals, 0.99), 3),
        "max": round(max(vals), 3),
        "mean": round(statistics.fmean(vals), 3),
        "stdev": round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0,
        # coefficient of variation: how much structure/spread survives
        "cv": round(statistics.pstdev(vals) / statistics.fmean(vals), 4)
        if len(vals) > 1 and statistics.fmean(vals) else 0.0,
    }


# ------------------------------------------------------------------ #
# Phase-1: bounded/fixed response-time normalization on req->resp
# ------------------------------------------------------------------ #

def apply_phase1(txns: List[dict], profile: tp.TimingProfile,
                 rto_safe_ms: Optional[float]) -> List[float]:
    """Return the after request->response times (ms) under a Phase-1 profile.

    Each transaction is treated as its own flow so the marginal distribution is
    the transform of each native time (no cross-txn FIFO clamping artefacts). The
    native measured request->response is used as the response-ready time.
    """
    sched = tp.ReleaseScheduler(profile)
    out: List[float] = []
    for i, t in enumerate(txns):
        req_recv = 0
        resp_ready = int(round(t["req_to_resp_ms"] * MS))
        dec = sched.decide(
            flow_id="txn%d" % i,
            transaction_id=i,
            request_received_ns=req_recv,
            response_ready_ns=resp_ready,
            request_size=t["req_size"],
            response_size=t["resp_size"],
            packet_role=tp.COMBINED_RESPONSE,
            rto_safe_ms=rto_safe_ms,
        )
        out.append(dec.visible_delay_ns * tp.NS_TO_MS)
    return out


# ------------------------------------------------------------------ #
# Phase-2: reschedule the existing pure ACK + response (SEL-751)
# ------------------------------------------------------------------ #

def apply_phase2(txns: List[dict], ack_mode: str, ack_delay_ms: float,
                 response_delay_ms: float, gap_target_ms: float):
    """Return (after_gap_ms, after_req_to_resp_ms) lists under a Phase-2 ACK mode."""
    gaps: List[float] = []
    r2r: List[float] = []
    for t in txns:
        req_recv = 0
        ack_ready = int(round(t["req_to_ack_ms"] * MS))
        resp_ready = int(round(t["req_to_resp_ms"] * MS))
        plan = tp.plan_ack_response_release(
            request_received_ns=req_recv,
            ack_ready_ns=ack_ready,
            response_ready_ns=resp_ready,
            ack_mode=ack_mode,
            ack_delay_ns=int(round(ack_delay_ms * MS)),
            response_delay_ns=int(round(response_delay_ms * MS)),
            gap_target_ns=int(round(gap_target_ms * MS)) if gap_target_ms else None,
        )
        gaps.append(plan.gap_ns * tp.NS_TO_MS)
        r2r.append((plan.response_release_ns - req_recv) * tp.NS_TO_MS)
    return gaps, r2r


# ------------------------------------------------------------------ #
# Driver
# ------------------------------------------------------------------ #

def build(csv_path: str, seed: int, rto_safe_ms: float,
          fixed_ms: float, b_lo: float, b_hi: float,
          resp_delay_ms: float, ack_delay_ms: float, gap_ms: float) -> dict:
    native = load_native(csv_path)
    result = {
        "meta": {
            "source_csv": os.path.relpath(csv_path, HERE),
            "device_ips": DEVICE_IPS,
            "note": "Before = measured native device timing from the six PCAPs; "
                    "after = the same per-transaction times pushed through the "
                    "shipped timing_policy module (no byte edits, no forging).",
            "phase1_config": {
                "fixed_ms": fixed_ms, "bounded_ms": [b_lo, b_hi],
                "seed": seed, "rto_safe_ms": rto_safe_ms,
            },
            "phase2_config": {
                "response_delay_ms": resp_delay_ms, "ack_delay_ms": ack_delay_ms,
                "gap_target_ms": gap_ms,
            },
        },
        "devices": {},
    }

    for dev, txns in sorted(native.items()):
        entry = {"txns": len(txns), "ack_mode": "separate" if dev in SEPARATE_DEVICES
                 else "combined", "observables": {}}

        # ---- request->response (all devices; Phase-1 target for combined) ----
        native_r2r = [t["req_to_resp_ms"] for t in txns]
        r2r_block = {"native": summarize(native_r2r), "after": {}}
        prof_fixed = tp.TimingProfile(mode=tp.FIXED, target_delay_ms=fixed_ms,
                                      max_hold_ms=100.0)
        prof_bounded = tp.TimingProfile(mode=tp.BOUNDED, target_min_ms=b_lo,
                                        target_max_ms=b_hi, seed=seed,
                                        max_hold_ms=100.0)
        r2r_block["after"]["fixed_%gms" % fixed_ms] = summarize(
            apply_phase1(txns, prof_fixed, rto_safe_ms))
        r2r_block["after"]["bounded_%g_%gms" % (b_lo, b_hi)] = summarize(
            apply_phase1(txns, prof_bounded, rto_safe_ms))
        entry["observables"]["request_to_response_ms"] = r2r_block

        # ---- ACK->response gap (only meaningful for the separate-ACK device) ----
        if dev in SEPARATE_DEVICES:
            native_gap = [t["ack_to_resp_ms"] for t in txns]
            gap_block = {"native": summarize(native_gap), "after": {}}
            for mode, kw in (
                ("response-delay-only", {"response_delay_ms": resp_delay_ms}),
                ("ack-delay-only", {"ack_delay_ms": ack_delay_ms}),
                ("gap-normalized", {"gap_target_ms": gap_ms}),
            ):
                gaps, _ = apply_phase2(
                    txns, ack_mode=mode,
                    ack_delay_ms=kw.get("ack_delay_ms", 0.0),
                    response_delay_ms=kw.get("response_delay_ms", 0.0),
                    gap_target_ms=kw.get("gap_target_ms", 0.0))
                gap_block["after"][mode] = summarize(gaps)
            entry["observables"]["ack_to_response_gap_ms"] = gap_block

        result["devices"][dev] = entry
    return result, native


# ------------------------------------------------------------------ #
# Emit markdown + figure
# ------------------------------------------------------------------ #

def write_markdown(result: dict, path: str) -> None:
    m = result["meta"]
    L = []
    L.append("# Before / After of the ACK-Delay Timing Manipulation on the Real Device Traces\n")
    L.append("_Anchored to the six real-device PCAPs in `Traffic Trace/`. **Before** = "
             "the native per-transaction timing measured in "
             "`reports/ack_trace_characterization.csv`; **after** = each of those same "
             "transactions pushed through the shipped `timing_policy` module — the exact "
             "scheduler / ACK-response planner the replay server runs. No bytes are edited "
             "and no packet is forged; only release times are recomputed._\n")
    L.append("Phase-1 config: fixed **%g ms**, bounded **%s ms** (seed %s), RTO-safe "
             "**%g ms**. Phase-2 config: response-delay **+%g ms**, ack-delay **+%g ms**, "
             "gap-target **%g ms**.\n" % (
                 m["phase1_config"]["fixed_ms"],
                 m["phase1_config"]["bounded_ms"], m["phase1_config"]["seed"],
                 m["phase1_config"]["rto_safe_ms"],
                 m["phase2_config"]["response_delay_ms"],
                 m["phase2_config"]["ack_delay_ms"],
                 m["phase2_config"]["gap_target_ms"]))

    # Combined devices: request->response before/after
    L.append("## Combined-ACK devices — request→response normalization (Phase 1)\n")
    L.append("These devices piggyback the ACK on the response (no separate ACK to "
             "delay natively), so the manipulable observable is request→response time. "
             "Native ~16 ms is device-distinguishing in its tail; normalization pins it "
             "to a class-independent target.\n")
    L.append("| device | txns | native med | native p95 | native max | native CV | "
             "after (fixed) med/p95/max | after (bounded) med/p95/max | after CV |")
    L.append("|---|---:|---:|---:|---:|---:|---|---|---:|")
    for dev in COMBINED_DEVICES:
        e = result["devices"].get(dev)
        if not e:
            continue
        b = e["observables"]["request_to_response_ms"]
        nat = b["native"]
        fx = list(b["after"].values())[0]
        bd = list(b["after"].values())[1]
        L.append("| %s | %d | %.2f | %.2f | %.2f | %.4f | %.2f / %.2f / %.2f | "
                 "%.2f / %.2f / %.2f | %.4f |" % (
                     dev, e["txns"], nat["median"], nat["p95"], nat["max"], nat["cv"],
                     fx["median"], fx["p95"], fx["max"],
                     bd["median"], bd["p95"], bd["max"], bd["cv"]))
    L.append("")

    # Separate device: ACK->response gap before/after (the literal ACK delay)
    L.append("## Separate-ACK device (SEL-751) — observer-visible ACK→response gap (Phase 2)\n")
    L.append("The SEL-751 really emits a **pure TCP ACK before** the DNP3 response, so an "
             "attacker reads device processing time as the ACK→response gap. The Phase-2 "
             "planner reschedules the two existing packets (it never forges an ACK). "
             "`response-delay-only` grows the gap, `ack-delay-only` shrinks it, "
             "`gap-normalized` pins it to a bounded target.\n")
    for dev in SEPARATE_DEVICES:
        e = result["devices"].get(dev)
        if not e:
            continue
        gb = e["observables"]["ack_to_response_gap_ms"]
        nat = gb["native"]
        L.append("**%s** (%d transactions). Native ACK→response gap: median "
                 "**%.2f ms**, p95 %.2f, max %.2f, CV %.4f.\n" % (
                     dev, e["txns"], nat["median"], nat["p95"], nat["max"], nat["cv"]))
        L.append("| mode | gap median | gap p95 | gap max | gap CV | Δ median vs native |")
        L.append("|---|---:|---:|---:|---:|---:|")
        L.append("| native (before) | %.2f | %.2f | %.2f | %.4f | 0.00 |" % (
            nat["median"], nat["p95"], nat["max"], nat["cv"]))
        for mode, s in gb["after"].items():
            L.append("| %s | %.2f | %.2f | %.2f | %.4f | %+.2f |" % (
                mode, s["median"], s["p95"], s["max"], s["cv"],
                s["median"] - nat["median"]))
        L.append("")

    L.append("## Reading\n")
    L.append("- **Combined devices:** native request→response carries a device-specific "
             "tail (p95/max differ per device); after normalization every held transaction "
             "leaves at the same target, so the request→response CV collapses toward the "
             "target's own tiny spread — the timing channel is closed on the held path. "
             "The response **size** channel (37 vs 54 vs 61 B) is untouched by timing and "
             "still distinguishes devices (see `attacker_eval.md`).\n")
    L.append("- **SEL-751:** the native ~13 ms ACK→response gap is the cross-layer "
             "processing-time fingerprint. `response-delay-only` and `ack-delay-only` move "
             "the observer-visible gap in opposite directions without changing the true "
             "device processing time; `gap-normalized` replaces the device's native gap "
             "distribution with a bounded target, erasing the per-device gap signature. "
             "This is the literal ACK-delay manipulation applied to the real trace.\n")
    L.append("- **Honest scope:** this is a projection of the shipped policy onto measured "
             "native times (a distributional before/after), not a fresh live capture of a "
             "defended SEL-751. Live two-host validation of the mechanism/safety is in "
             "`reports/rig_timing_matrix_results.md` and `reports/ack_separation_rig_results.md`.\n")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


def write_figure(result: dict, native: Dict[str, List[dict]], path: str,
                 fixed_ms: float, b_lo: float, b_hi: float, seed: float,
                 rto_safe_ms: float, resp_delay_ms: float, ack_delay_ms: float,
                 gap_ms: float) -> Optional[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover
        print("[fig] matplotlib unavailable (%s); skipping figure" % exc)
        return None

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))

    def clip(vals, hi):
        return [min(v, hi) for v in vals if v == v]

    # Panel 1+2: combined devices req->resp native vs bounded-normalized
    for ax, dev in zip(axes[:2], COMBINED_DEVICES):
        txns = native.get(dev, [])
        if not txns:
            continue
        nat = [t["req_to_resp_ms"] for t in txns]
        prof = tp.TimingProfile(mode=tp.BOUNDED, target_min_ms=b_lo,
                                target_max_ms=b_hi, seed=seed, max_hold_ms=100.0)
        after = apply_phase1(txns, prof, rto_safe_ms)
        hi = max(30.0, pctl(nat, 0.99) * 1.1)
        bins = 40
        ax.hist(clip(nat, hi), bins=bins, alpha=0.6, label="native (before)",
                color="#c44", density=True)
        ax.hist(clip(after, hi), bins=bins, alpha=0.6,
                label="bounded[%g,%g] (after)" % (b_lo, b_hi),
                color="#268", density=True)
        ax.set_title("%s  request→response  (Phase 1)" % dev)
        ax.set_xlabel("ms")
        ax.set_ylabel("density")
        ax.legend(fontsize=8)

    # Panel 3: SEL-751 ACK->response gap native vs the three Phase-2 modes.
    # ECDF curves (not histograms): the gap-normalized mode is a near-delta at the
    # target, which a density histogram renders as an unreadable spike; a cumulative
    # curve shows a constant as a clean vertical step and keeps all four comparable.
    ax = axes[2]
    dev = "SEL751"
    txns = native.get(dev, [])
    if txns:
        def ecdf(vals, hi=45.0):
            s = sorted(v for v in vals if v == v and v <= hi)
            n = len(s)
            xs, ys = [], []
            for i, v in enumerate(s):
                xs.append(v)
                ys.append((i + 1) / n)
            return xs, ys
        series = [
            ("native gap (before)", [t["ack_to_resp_ms"] for t in txns], "#c44", "-"),
            ("ack-delay +%g (shrinks)" % ack_delay_ms,
             apply_phase2(txns, "ack-delay-only", ack_delay_ms, 0, 0)[0], "#2a8f2a", "-"),
            ("resp-delay +%g (grows)" % resp_delay_ms,
             apply_phase2(txns, "response-delay-only", 0, resp_delay_ms, 0)[0], "#8a2be2", "-"),
            ("gap-normalized %g" % gap_ms,
             apply_phase2(txns, "gap-normalized", 0, 0, gap_ms)[0], "#0e6ba8", "-"),
        ]
        for label, vals, color, ls in series:
            xs, ys = ecdf(vals)
            ax.plot(xs, ys, label=label, color=color, linestyle=ls, linewidth=2)
        ax.set_title("SEL-751  ACK→response gap  (Phase 2, ECDF)")
        ax.set_xlabel("observer-visible ACK→response gap (ms)")
        ax.set_ylabel("cumulative fraction")
        ax.set_xlim(0, 32)
        ax.grid(alpha=0.25)
        ax.legend(fontsize=7, loc="lower right")

    fig.suptitle("ACK-delay timing manipulation: before vs after on the real device traces",
                 fontsize=12)
    fig.tight_layout(rect=(0, 0, 1, 0.96))
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default=DEFAULT_CSV, help="characterization CSV (native before)")
    ap.add_argument("--seed", type=int, default=12345)
    ap.add_argument("--rto-safe-ms", type=float, default=105.0)
    ap.add_argument("--fixed-ms", type=float, default=25.0)
    ap.add_argument("--bounded-lo", type=float, default=20.0)
    ap.add_argument("--bounded-hi", type=float, default=30.0)
    ap.add_argument("--response-delay-ms", type=float, default=8.0)
    ap.add_argument("--ack-delay-ms", type=float, default=8.0)
    ap.add_argument("--gap-ms", type=float, default=20.0)
    ap.add_argument("--no-figure", action="store_true")
    args = ap.parse_args()

    result, native = build(
        args.csv, args.seed, args.rto_safe_ms, args.fixed_ms,
        args.bounded_lo, args.bounded_hi, args.response_delay_ms,
        args.ack_delay_ms, args.gap_ms)

    os.makedirs(OUT_DIR, exist_ok=True)
    json_path = os.path.join(OUT_DIR, "trace_before_after.json")
    md_path = os.path.join(OUT_DIR, "trace_before_after.md")
    csv_path = os.path.join(OUT_DIR, "trace_before_after.csv")
    png_path = os.path.join(OUT_DIR, "trace_before_after.png")

    with open(json_path, "w") as fh:
        json.dump(result, fh, indent=2)

    # flat CSV: one row per (device, observable, mode)
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["device", "ack_mode", "observable", "variant",
                    "n", "median_ms", "p95_ms", "p99_ms", "max_ms", "mean_ms",
                    "stdev_ms", "cv"])
        for dev, e in result["devices"].items():
            for obs, block in e["observables"].items():
                for variant, s in [("native", block["native"])] + \
                        list(block["after"].items()):
                    w.writerow([dev, e["ack_mode"], obs, variant, s.get("n", 0),
                                s.get("median", ""), s.get("p95", ""),
                                s.get("p99", ""), s.get("max", ""),
                                s.get("mean", ""), s.get("stdev", ""),
                                s.get("cv", "")])

    write_markdown(result, md_path)
    fig = None
    if not args.no_figure:
        fig = write_figure(result, native, png_path, args.fixed_ms,
                           args.bounded_lo, args.bounded_hi, args.seed,
                           args.rto_safe_ms, args.response_delay_ms,
                           args.ack_delay_ms, args.gap_ms)

    print("Wrote:")
    for p in (csv_path, json_path, md_path):
        print("  " + os.path.relpath(p, HERE))
    if fig:
        print("  " + os.path.relpath(fig, HERE))
    # quick console readout
    for dev, e in result["devices"].items():
        obs = e["observables"]
        if "ack_to_response_gap_ms" in obs:
            gb = obs["ack_to_response_gap_ms"]
            print("[%s] native gap med %.2f ms -> gap-normalized med %.2f ms" % (
                dev, gb["native"]["median"], gb["after"]["gap-normalized"]["median"]))
        r = obs["request_to_response_ms"]
        after_bounded = list(r["after"].values())[1]
        print("[%s] native r2r med %.2f (CV %.4f) -> bounded med %.2f (CV %.4f)" % (
            dev, r["native"]["median"], r["native"]["cv"],
            after_bounded["median"], after_bounded["cv"]))


if __name__ == "__main__":
    main()
