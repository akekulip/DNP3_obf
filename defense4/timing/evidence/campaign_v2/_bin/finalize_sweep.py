"""Build the campaign_v2 sweep's published tables from its captures.

Writes the three files `repro/validate_sweep.py` checks, in the schema campaign_v1 uses, so the
two sweeps are read by the same validator:

    sweep/sweep_points.csv    one row per point: the policy and the master-visible medians
    sweep/sweep_timing.json   per point, per class: n, CLRT median and spread, request-to-ACK median
    sweep/SWEEP.sha256        every capture and driver log, hashed, paths relative to the dataset root

The captures are the only trusted input. The driver logs are copied and hashed but are not read for
timing: wire timing comes from the master-facing capture through the repository's own extractor.

    python3 finalize_sweep.py
"""
from __future__ import annotations
import csv, hashlib, json, pathlib, re, statistics as st, sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent                                   # campaign_v2/
SWEEP = ROOT / "sweep"
sys.path.insert(0, str(ROOT / "repro"))
import pcap_dnp3 as P                                # noqa: E402

CLASSES = ["READ", "SELECT", "OPERATE"]
CONTROL_POINTS = {"sw_off", "sw_D2_0_24", "sw_D3_20_0"}
NON_POINT = {"sw_restore", "sw_restore2"}


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def policy_of(tag: str):
    """(mode, D_A, D_R) from the point name, which is how campaign_v1 encodes it."""
    if tag == "sw_off":
        return "OFF", None, None
    m = re.match(r"^sw_(D\d)_(\d+)_(\d+)b?$", tag)
    if not m:
        return None, None, None
    return m.group(1), float(m.group(2)), float(m.group(3))


def main() -> int:
    caps = sorted((SWEEP / "raw_pcaps").glob("sw_*.pcap"))
    if not caps:
        sys.exit("no captures under %s" % (SWEEP / "raw_pcaps"))
    timing, rows = {}, []
    for cap in caps:
        tag = cap.name[: -len(".pcap")]
        if tag in NON_POINT:
            continue
        mode, da, dr = policy_of(tag)
        if mode is None:
            print("  skipping %s: the name does not encode a policy" % tag)
            continue
        rep = P.extract(str(cap))
        by = {}
        for x in rep.exchanges:
            by.setdefault(P.FUNC_NAME.get(x.func, str(x.func)), []).append(x)
        per = {}
        for c in CLASSES:
            xs = by.get(c, [])
            if not xs:
                continue
            clrt = [x.clrt_ns / 1e6 for x in xs]
            ack = [x.ack_gap_ns / 1e6 for x in xs]
            per[c] = {"n": len(xs), "clrt_med": round(st.median(clrt), 3),
                      "clrt_sd": round(st.pstdev(clrt), 3) if len(clrt) > 1 else 0.0,
                      "ack_med": round(st.median(ack), 3)}
        timing[tag] = per
        rd = by.get("READ", [])
        rows.append({
            "point": tag, "mode": mode,
            "D_A_ms": "" if da is None else da, "D_R_ms": "" if dr is None else dr,
            "D_ms": "" if da is None else da + dr,
            "clrt_med_ms": per["READ"]["clrt_med"], "clrt_sd_ms": per["READ"]["clrt_sd"],
            "ack_med_ms": per["READ"]["ack_med"],
            # The sum of the two interval medians, not the median of the sum. They differ,
            # because a median is not additive, and campaign_v1's table publishes the sum -- so
            # repro/validate_sweep.py checks the three columns against each other on that
            # convention. Publishing the true median of rt here makes the table internally
            # inconsistent by about 0.01 ms and fails that check.
            "rt_med_ms": round(per["READ"]["clrt_med"] + per["READ"]["ack_med"], 3),
            "n_read": len(rd)})
        print("  %-14s %-4s D_A=%-4s D_R=%-4s  CLRT %7.3f  ACK %7.3f  n=%d"
              % (tag, mode, da, dr, rows[-1]["clrt_med_ms"], rows[-1]["ack_med_ms"], len(rd)))

    cols = ["point", "mode", "D_A_ms", "D_R_ms", "D_ms", "clrt_med_ms", "clrt_sd_ms",
            "ack_med_ms", "rt_med_ms", "n_read"]
    with open(SWEEP / "sweep_points.csv", "w", newline="") as f:
        w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(rows)
    json.dump(timing, open(SWEEP / "sweep_timing.json", "w"), indent=1)

    lines = []
    for p in sorted(list((SWEEP / "raw_pcaps").glob("*.pcap"))
                    + list((SWEEP / "app_jsonl").glob("*.jsonl"))):
        lines.append("%s  %s" % (sha256(p), p.relative_to(ROOT)))
    (SWEEP / "SWEEP.sha256").write_text("\n".join(lines) + "\n")

    print("\n%d points, %d control points, %d hashed files"
          % (len(rows), sum(1 for r in rows if r["point"] in CONTROL_POINTS), len(lines)))
    print("wrote sweep_points.csv, sweep_timing.json, SWEEP.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
