"""Validate the measured hardware sweep and emit its canonical tables.

The sweep is a real parameter sweep on the physical testbed: for each point the control plane
installed a release policy and the driver ran a fixed DNP3 workload through it. The raw captures
are the only trusted input. ``sweep_points.csv`` and ``sweep_timing.json`` are treated as claims
to be checked, never as sources.

Provenance boundary recorded here rather than inferred: the driver logs carry ``mode`` and the
``J`` codebook but not ``D_A``/``D_R``. The per-point offsets are read from ``sweep_points.csv``,
which is the archived configuration table; no per-point control-plane readback exists in this
tree. The point name encodes the same pair, and this script checks the table against the name so
a disagreement is reported instead of silently inheriting either one.

Two published columns are checked and one is corrected:

``clrt_med_ms``, ``clrt_sd_ms``, ``ack_med_ms``, ``n_read``
    recomputed from the captures and required to agree.

``rt_med_ms``
    published as ``ack_med_ms + clrt_med_ms``, which is a sum of two medians and not in general
    the median of the per-transaction response time. Both quantities are emitted under
    unambiguous names: ``rt_med_ms`` is now the true median of ``t_resp - t_req`` and
    ``sum_of_interval_medians_ms`` is the published quantity, retained so the correction is
    auditable.
"""
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from collections import Counter

import numpy as np

import pcap_dnp3 as P

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # campaign_v1/
SWEEP = os.path.join(ROOT, "sweep")
CLASSES = ["READ", "SELECT", "OPERATE"]
STATUS_OK = 0
# sweep_points.csv stores three decimals; agreement is required to that rounding.
TOL_MS = 0.0015
# Points that establish the operating envelope rather than a release policy.
CONTROL_POINTS = {"sw_off", "sw_D2_0_24", "sw_D3_20_0"}
# Not a sweep point: a capture taken after the sweep to restore the working policy.
NON_POINT_CAPTURES = {"sw_restore", "sw_restore2"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def verify_manifest(problems):
    """Every SWEEP.sha256 entry must exist and hash exactly."""
    man = os.path.join(SWEEP, "SWEEP.sha256")
    if not os.path.exists(man):
        problems.append("sweep: SWEEP.sha256 is missing")
        return 0
    n = 0
    for line in open(man):
        line = line.strip()
        if not line:
            continue
        want, rel = line.split(None, 1)
        # entries are recorded relative to the campaign_v1 root ("sweep/...")
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            problems.append(f"sweep manifest: {rel} is listed but missing")
            continue
        got = sha256(path)
        if got != want:
            problems.append(f"sweep manifest: {rel} hash {got[:12]} != recorded {want[:12]}")
        n += 1
    return n


def name_offsets(point):
    """(D_A, D_R) as encoded in the point name, or None. Used only to cross-check the table."""
    m = re.match(r"^sw_D\d_(\d+)_(\d+)b?$", point)
    if not m:
        return None
    return float(m.group(1)), float(m.group(2))


def read_points():
    with open(os.path.join(SWEEP, "sweep_points.csv")) as f:
        return list(csv.DictReader(f))


def extract_point(point, problems):
    """Parse one sweep capture and return its per-transaction rows."""
    pc = os.path.join(SWEEP, "raw_pcaps", point + ".pcap")
    if not os.path.exists(pc):
        problems.append(f"sweep: capture for {point} is missing")
        return []
    rep = P.extract(pc)
    for label, val in (("retransmissions", rep.retransmissions),
                       ("duplicate application frames", rep.duplicate_app_frames),
                       ("malformed frames", rep.malformed),
                       ("unpaired requests", rep.unpaired_requests),
                       ("out-of-order timestamps", rep.out_of_order_ts),
                       ("wrong-endpoint payloads", rep.wrong_endpoint)):
        if val:
            problems.append(f"{point}: {val} {label}")
    if rep.syn // 2 != 1:
        problems.append(f"{point}: {rep.syn // 2} TCP connections, expected 1")
    rows = []
    for i, e in enumerate(rep.exchanges):
        if not (e.t_req <= e.t_ack <= e.t_resp):
            problems.append(f"{point}: non-monotonic exchange at index {i}")
        if e.resp_func != P.RESP_FUNC:
            problems.append(f"{point}: response func 0x{e.resp_func:02x} != 0x81")
        if e.func in (3, 4) and e.status != STATUS_OK:
            problems.append(f"{point}: {P.FUNC_NAME[e.func]} status {e.status} != SUCCESS")
        rows.append(dict(point=point, idx=i, txn_class=P.FUNC_NAME.get(e.func, str(e.func)),
                         func=e.func, t_req=repr(e.t_req),
                         ack_ms=round((e.t_ack - e.t_req) * 1e3, 6),
                         clrt_ms=round((e.t_resp - e.t_ack) * 1e3, 6),
                         rt_ms=round((e.t_resp - e.t_req) * 1e3, 6),
                         status=("SUCCESS" if e.status == 0 else e.status)))
    return rows


def summarize(rows, cls=None):
    v = [r for r in rows if cls is None or r["txn_class"] == cls]
    if not v:
        return None
    clrt = np.array([r["clrt_ms"] for r in v])
    ack = np.array([r["ack_ms"] for r in v])
    rt = np.array([r["rt_ms"] for r in v])
    q1, q3 = np.percentile(clrt, [25, 75])
    return dict(
        n=len(v),
        clrt_med_ms=round(float(np.median(clrt)), 4),
        # sweep_points.csv was published with the POPULATION standard deviation (ddof=0); that
        # convention is undocumented in the table itself and is recorded here so the check is
        # against what was actually published. The sample standard deviation, which is the right
        # estimator when the points are treated as a sample, is emitted alongside it. The
        # campaign table (stats_campaign.py) uses the sample convention; the two differ by
        # sqrt((n-1)/n) and are never mixed in one reported quantity.
        clrt_sd_pop_ms=round(float(clrt.std(ddof=0)), 4),
        clrt_sd_samp_ms=round(float(clrt.std(ddof=1)), 4) if len(v) > 1 else 0.0,
        clrt_iqr_ms=round(float(q3 - q1), 4),
        clrt_q1_ms=round(float(q1), 4),
        clrt_q3_ms=round(float(q3), 4),
        clrt_min_ms=round(float(clrt.min()), 4),
        clrt_max_ms=round(float(clrt.max()), 4),
        ack_med_ms=round(float(np.median(ack)), 4),
        # the true median of the per-transaction response time
        rt_med_ms=round(float(np.median(rt)), 4),
        # the quantity sweep_points.csv published under the name rt_med_ms
        sum_of_interval_medians_ms=round(float(np.median(ack) + np.median(clrt)), 4),
    )


def main(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    problems = []
    n_manifest = verify_manifest(problems)

    published = read_points()
    points = [p["point"] for p in published]

    # every capture is either a declared point or a declared non-point
    on_disk = {os.path.basename(p)[:-5]
               for p in os.listdir(os.path.join(SWEEP, "raw_pcaps")) if p.endswith(".pcap")}
    unexpected = on_disk - set(points) - NON_POINT_CAPTURES
    if unexpected:
        problems.append(f"sweep: undeclared captures {sorted(unexpected)}")
    missing = set(points) - on_disk
    if missing:
        problems.append(f"sweep: declared points without a capture {sorted(missing)}")

    all_rows, summary = [], []
    for pub in published:
        point = pub["point"]
        rows = extract_point(point, problems)
        all_rows.extend(rows)
        s_read = summarize(rows, "READ")
        if s_read is None:
            problems.append(f"{point}: no READ transactions")
            continue

        # ---- the archived offsets, checked against the encoding in the point name
        D_A = float(pub["D_A_ms"]) if pub["D_A_ms"] else None
        D_R = float(pub["D_R_ms"]) if pub["D_R_ms"] else None
        enc = name_offsets(point)
        if enc is not None and D_A is not None and (enc[0] != D_A or enc[1] != D_R):
            problems.append(f"{point}: table offsets ({D_A}, {D_R}) disagree with the name {enc}")
        if D_A is not None and D_R is not None and pub["D_ms"]:
            if abs((D_A + D_R) - float(pub["D_ms"])) > 1e-9:
                problems.append(f"{point}: D_ms != D_A + D_R")

        # ---- published columns that must agree with the captures
        for col, got in (("clrt_med_ms", s_read["clrt_med_ms"]),
                         ("clrt_sd_ms", s_read["clrt_sd_pop_ms"]),
                         ("ack_med_ms", s_read["ack_med_ms"])):
            want = float(pub[col])
            if abs(got - want) > TOL_MS:
                problems.append(f"{point}: {col} recomputed {got} != published {want}")
        if int(pub["n_read"]) != s_read["n"]:
            problems.append(f"{point}: n_read recomputed {s_read['n']} != published {pub['n_read']}")

        # ---- the corrected column: the published rt_med_ms is the sum of the two medians
        pub_rt = float(pub["rt_med_ms"])
        if abs(pub_rt - s_read["sum_of_interval_medians_ms"]) > TOL_MS:
            problems.append(f"{point}: published rt_med_ms {pub_rt} is not the sum of the "
                            f"interval medians {s_read['sum_of_interval_medians_ms']}")

        rec = dict(point=point, mode=pub["mode"], D_A_ms=D_A, D_R_ms=D_R,
                   D_ms=(float(pub["D_ms"]) if pub["D_ms"] else None),
                   is_control_point=point in CONTROL_POINTS,
                   published_rt_med_ms=pub_rt,
                   rt_med_delta_ms=round(s_read["rt_med_ms"] - pub_rt, 4))
        rec.update({f"read_{k}": v for k, v in s_read.items()})
        for c in ("SELECT", "OPERATE"):
            s = summarize(rows, c)
            if s:
                rec.update({f"{c.lower()}_{k}": v for k, v in s.items()})
        summary.append(rec)

    # ---- write the canonical sweep tables
    with open(os.path.join(out_dir, "sweep_canonical.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys())); w.writeheader()
        w.writerows(all_rows)
    keys = sorted({k for r in summary for k in r})
    order = [k for k in ("point", "mode", "D_A_ms", "D_R_ms", "D_ms", "is_control_point") if k in keys]
    order += [k for k in keys if k not in order]
    with open(os.path.join(out_dir, "sweep_summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=order); w.writeheader()
        w.writerows(summary)
    report = dict(points=len(summary), transactions=len(all_rows),
                  manifest_entries_verified=n_manifest,
                  non_point_captures=sorted(NON_POINT_CAPTURES & on_disk),
                  offsets_provenance=("sweep_points.csv is the archived configuration table; the "
                                      "driver logs record mode and the J codebook but not D_A/D_R, "
                                      "and no per-point control-plane readback exists in this tree"),
                  rt_med_correction=("published rt_med_ms equals ack_med_ms + clrt_med_ms, a sum of "
                                     "medians; rt_med_ms here is the median of t_resp - t_req and "
                                     "sum_of_interval_medians_ms carries the published quantity"),
                  problems=problems)
    with open(os.path.join(out_dir, "sweep_report.json"), "w") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(out_dir, "sweep_summary.json"), "w") as f:
        json.dump(summary, f, indent=1)

    print(f"sweep points={len(summary)}  transactions={len(all_rows)}  "
          f"manifest entries verified={n_manifest}  problems={len(problems)}")
    print(f"{'point':14s} {'D_A':>5s} {'D_R':>5s} {'D':>5s} {'CLRT med':>9s} {'ACK med':>9s} "
          f"{'rt med':>8s} {'pub rt':>8s} {'delta':>7s}")
    for r in summary:
        print(f"{r['point']:14s} {str(r['D_A_ms'] or ''):>5s} {str(r['D_R_ms'] or ''):>5s} "
              f"{str(r['D_ms'] or ''):>5s} {r['read_clrt_med_ms']:9.3f} {r['read_ack_med_ms']:9.3f} "
              f"{r['read_rt_med_ms']:8.3f} {r['published_rt_med_ms']:8.3f} "
              f"{r['rt_med_delta_ms']:+7.3f}")
    for p in problems[:20]:
        print("  PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/campaign_v1_out"))
