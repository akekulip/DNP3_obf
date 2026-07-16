"""phase01_manual_validation.py -- Phase 01 §6 transaction validation.

Deterministically samples >=20 transactions per captured device and re-verifies each by
an INDEPENDENT, frame-targeted tshark re-read of that transaction's request / pure-ACK /
response frames, then re-derives the ACK-mode classification and checks the TCP
sequence/acknowledgement relationship. This is automated field-level re-extraction and
cross-derivation -- not human visual inspection -- and is labeled as such. Ambiguous
(OTHER_OR_AMBIGUOUS) transactions are added to the sample in full when few.

    python3 phase01_manual_validation.py --run-dir <phase01 run dir>
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from typing import Dict, List, Optional

import numpy as np

DEVICES = ["SEL751", "AB1400", "ION7550"]
SEED = 20250716
PER_DEVICE = 20
TIME_TOL_MS = 0.02
RE_FIELDS = ["frame.number", "frame.time_epoch", "tcp.len", "tcp.seq", "tcp.ack",
             "tcp.flags", "frame.len", "dnp3.al.func"]


def _load_rows(run_dir: str) -> List[dict]:
    path = os.path.join(run_dir, "tables", "ack_trace_characterization.csv")
    with open(path) as fh:
        return list(csv.DictReader(fh))


def _i(v) -> Optional[int]:
    v = (v or "").strip()
    return int(v) if v not in ("", "None") else None


def _f(v) -> Optional[float]:
    v = (v or "").strip()
    return float(v) if v not in ("", "None") else None


def _tshark_frames(pcap: str, frames: List[int]) -> Dict[int, dict]:
    """Independent, frame-targeted re-read of specific frames (one call per capture)."""
    if not frames:
        return {}
    filt = " || ".join("frame.number=={}".format(f) for f in sorted(set(frames)))
    cmd = ["tshark", "-r", pcap, "-Y", filt, "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for f in RE_FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    out: Dict[int, dict] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        c = line.split("\t")
        if len(c) < len(RE_FIELDS):
            c += [""] * (len(RE_FIELDS) - len(c))
        fn = _i(c[0])
        if fn is None:
            continue
        func = c[7].strip().split(",")[0]
        out[fn] = {"t": _f(c[1]) or 0.0, "tcp_len": _i(c[2]) or 0,
                   "seq": _i(c[3]) or 0, "ack": _i(c[4]) or 0, "flags": c[5].strip(),
                   "frame_len": _i(c[6]) or 0,
                   "func": int(func) if func.isdigit() else None}
    return out


def validate(run_dir: str, traffic_dir: str):
    rows = _load_rows(run_dir)
    dev_rows = [r for r in rows if r["is_reference"] == "False"]
    rng = np.random.default_rng(SEED)

    selected: List[dict] = []
    for dev in DEVICES:
        pool = [r for r in dev_rows if r["device_label"] == dev]
        if not pool:
            continue
        take = min(PER_DEVICE, len(pool))
        idx = rng.choice(len(pool), size=take, replace=False)
        selected += [pool[int(i)] for i in idx]
    # include every OTHER_OR_AMBIGUOUS device transaction (usually few)
    ambiguous = [r for r in dev_rows if r["classification"] == "OTHER_OR_AMBIGUOUS"]
    for r in ambiguous:
        if r not in selected:
            selected.append(r)

    # batch the frame re-reads per capture
    by_cap: Dict[str, List[int]] = {}
    for r in selected:
        cap = r["capture"]
        for key in ("req_frame", "pure_ack_frame", "resp_frame"):
            fn = _i(r[key])
            if fn is not None:
                by_cap.setdefault(cap, []).append(fn)
    reread = {cap: _tshark_frames(os.path.join(traffic_dir, cap), fns)
              for cap, fns in by_cap.items()}

    results = []
    for r in selected:
        cap = r["capture"]
        frames = reread.get(cap, {})
        req_fn, pa_fn, resp_fn = _i(r["req_frame"]), _i(r["pure_ack_frame"]), _i(r["resp_frame"])
        req = frames.get(req_fn)
        resp = frames.get(resp_fn) if resp_fn is not None else None
        pa = frames.get(pa_fn) if pa_fn is not None else None

        checks = {}
        # 1. re-read field agreement
        checks["req_len_ok"] = bool(req and req["tcp_len"] == (_i(r["req_tcp_len"]) or 0))
        checks["req_time_ok"] = bool(req and abs(req["t"] * 1000 - (_f(r["req_time_epoch"]) or 0) * 1000) <= TIME_TOL_MS)
        if resp_fn is not None:
            checks["resp_len_ok"] = bool(resp and resp["tcp_len"] == (_i(r["resp_tcp_len"]) or 0))
            checks["resp_time_ok"] = bool(resp and abs(resp["t"] * 1000 - (_f(r["resp_time_epoch"]) or 0) * 1000) <= TIME_TOL_MS)
        if pa_fn is not None:
            checks["pure_ack_zero_len"] = bool(pa and pa["tcp_len"] == 0)
        # 2. sequence/acknowledgement relationship: the ACKing packet acknowledges the request bytes
        expected_ack = (_i(r["req_seq"]) or 0) + (_i(r["req_tcp_len"]) or 0)
        if r["classification"] == "SEPARATE_ACK_RESPONSE" and pa is not None:
            checks["ack_relationship_ok"] = (pa["ack"] == expected_ack)
        elif r["classification"] == "COMBINED_ACK_RESPONSE" and resp is not None:
            checks["ack_relationship_ok"] = (resp["ack"] == expected_ack)
        # 3. re-derive ACK-mode classification from the re-read frames
        if resp_fn is None:
            manual_cls = "OTHER_OR_AMBIGUOUS"
        elif pa_fn is not None and pa is not None and pa["tcp_len"] == 0 and pa_fn < resp_fn:
            manual_cls = "SEPARATE_ACK_RESPONSE"
        else:
            manual_cls = "COMBINED_ACK_RESPONSE"
        checks["class_ok"] = (manual_cls == r["classification"])

        agree = all(v for v in checks.values())
        results.append({
            "capture": cap, "device": r["device_label"], "req_frame": req_fn,
            "pure_ack_frame": pa_fn, "resp_frame": resp_fn,
            "automated_class": r["classification"], "manual_class": manual_cls,
            "agree": agree,
            "failed_checks": ";".join(k for k, v in checks.items() if v is False) or "",
        })
    return selected, results


def write_outputs(selected, results, run_dir):
    vdir = os.path.join(run_dir, "validation")
    os.makedirs(vdir, exist_ok=True)
    csv_path = os.path.join(vdir, "manual_validation_sample.csv")
    cols = ["capture", "device", "req_frame", "pure_ack_frame", "resp_frame",
            "automated_class", "manual_class", "agree", "failed_checks"]
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow(r)

    n = len(results)
    n_ok = sum(1 for r in results if r["agree"])
    disag = [r for r in results if not r["agree"]]
    md = os.path.join(vdir, "manual_validation_report.md")
    from collections import Counter
    per_dev = Counter(r["device"] for r in results)
    L = ["# Phase 01 — Transaction Validation Report", "",
         "**Method:** automated, frame-targeted re-extraction and cross-derivation "
         "(an independent second tshark read of each transaction's request / pure-ACK / "
         "response frames), NOT human visual inspection. Sample seed: `{}` (numpy "
         "default_rng). Timestamp tolerance: {} ms.".format(SEED, TIME_TOL_MS), "",
         "Sample size: **{}** transactions ({} per device where available: {}).".format(
             n, PER_DEVICE, dict(per_dev)),
         "", "Agreement (re-read fields + ACK relationship + re-derived class): "
         "**{}/{}**.".format(n_ok, n), "",
         "Selected transaction frames are enumerated in `manual_validation_sample.csv` "
         "(capture, req/pure-ACK/resp frame numbers, automated vs re-derived class).", ""]
    if disag:
        L += ["## Disagreements", ""]
        for r in disag:
            L.append("- `{}` req_frame {}: failed {} (automated {} / re-derived {})".format(
                r["capture"], r["req_frame"], r["failed_checks"],
                r["automated_class"], r["manual_class"]))
        L += ["", "Each disagreement must be resolved by direct Wireshark inspection.", ""]
    else:
        L += ["## Result", "",
              "Every sampled transaction re-verified: the frame-targeted re-read reproduces "
              "the recorded sizes and timestamps, the TCP acknowledgement acknowledges the "
              "request bytes, and the re-derived ACK mode matches the automated "
              "classification.", ""]
    with open(md, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return csv_path, md, n_ok, n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traffic-dir", default="/home/philip/Projects/DNP3/Traffic Trace")
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: {}\n".format(args.run_dir))
        return 2
    selected, results = validate(args.run_dir, args.traffic_dir)
    csv_path, md, n_ok, n = write_outputs(selected, results, args.run_dir)
    print("manual validation: {}/{} sampled transactions re-verified (seed {})".format(
        n_ok, n, SEED))
    print("wrote", csv_path)
    print("wrote", md)
    return 0 if n_ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
