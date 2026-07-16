"""phase01_human_validation_prep.py -- prepare the GENUINE human packet-validation sheet.

Phase 01 §3 requires a genuine human review (Wireshark / direct packet-field inspection).
This script does ONLY the part a script is allowed to do: it selects the transactions to
review, re-reads their packet fields with tshark, and writes a validation sheet with the
software-derived fields populated and the **human verdict fields left BLANK**. A person
must open each transaction in Wireshark and fill `reviewer`, `date`, `reviewer_ack_mode`,
`agreement`, and `notes`. The script never writes a human verdict.

Selection (per §3): the 60 deterministic transactions (20/device, seed 20250716), the lone
ION7550 separate-ACK transaction, all reset-associated transactions, and >=10
retransmission/duplicate-ACK transactions spread across the affected captures.

    python3 phase01_human_validation_prep.py --run-dir <phase01 run dir>
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import Dict, List

import numpy as np

import phase01_manual_validation as MV  # reuse the tshark frame re-read + sampling seed

DEVICES = ["SEL751", "AB1400", "ION7550"]
SEED = MV.SEED          # 20250716 -- identical deterministic sample as the automated check
PER_DEVICE = MV.PER_DEVICE


def _load(run_dir: str) -> List[dict]:
    with open(os.path.join(run_dir, "tables", "ack_trace_characterization.csv")) as fh:
        return list(csv.DictReader(fh))


def _select(rows: List[dict]):
    dev_rows = [r for r in rows if r["is_reference"] == "False"]
    rng = np.random.default_rng(SEED)
    picked: Dict[tuple, dict] = {}       # key (capture, req_frame) -> row
    reason: Dict[tuple, str] = {}

    def add(r, why):
        k = (r["capture"], r["req_frame"])
        if k not in picked:
            picked[k] = r
            reason[k] = why
        elif why not in reason[k]:
            reason[k] = reason[k] + "+" + why

    # 60 deterministic (20/device) -- same draw as the automated re-extraction check
    for dev in DEVICES:
        pool = [r for r in dev_rows if r["device_label"] == dev]
        take = min(PER_DEVICE, len(pool))
        for i in rng.choice(len(pool), size=take, replace=False):
            add(pool[int(i)], "deterministic-sample")
    # lone ION7550 separate-ACK
    for r in dev_rows:
        if r["device_label"] == "ION7550" and r["classification"] == "SEPARATE_ACK_RESPONSE":
            add(r, "lone-ion7550-separate")
    # all reset-associated transactions
    for r in dev_rows:
        if r["reset"] == "True":
            add(r, "reset")
    # >=10 retransmission / duplicate-ACK, spread across affected captures
    anregion = [r for r in dev_rows
                if int(r["retransmission_count"]) > 0 or int(r["duplicate_ack_count"]) > 0]
    by_cap: Dict[str, List[dict]] = {}
    for r in anregion:
        by_cap.setdefault(r["capture"], []).append(r)
    added = 0
    # round-robin across captures until at least 10
    while added < 10 and any(by_cap.values()):
        for cap in list(by_cap):
            if by_cap[cap]:
                r = by_cap[cap].pop(0)
                why = "retransmission" if int(r["retransmission_count"]) > 0 else "duplicate-ack"
                add(r, why)
                added += 1
                if added >= 10:
                    break
    return picked, reason


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traffic-dir", default="/home/philip/Projects/DNP3/Traffic Trace")
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: {}\n".format(args.run_dir))
        return 2

    rows = _load(args.run_dir)
    picked, reason = _select(rows)

    # batch tshark re-reads per capture (req/pure-ack/resp frames)
    by_cap: Dict[str, List[int]] = {}
    for (cap, _), r in picked.items():
        for key in ("req_frame", "pure_ack_frame", "resp_frame"):
            fn = MV._i(r[key])
            if fn is not None:
                by_cap.setdefault(cap, []).append(fn)
    reread = {cap: MV._tshark_frames(os.path.join(args.traffic_dir, cap), fns)
              for cap, fns in by_cap.items()}

    vdir = os.path.join(args.run_dir, "validation")
    os.makedirs(vdir, exist_ok=True)
    csv_path = os.path.join(vdir, "human_packet_validation.csv")
    cols = ["reviewer", "date", "selection_reason", "capture", "transaction_id",
            "req_frame", "pure_ack_frame", "resp_frame", "req_payload_len",
            "resp_payload_len", "req_seq", "expected_ack", "observed_ack",
            "software_ack_mode", "reviewer_ack_mode", "agreement", "notes"]
    n = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for (cap, reqf), r in sorted(picked.items(), key=lambda kv: (kv[0][0], int(kv[0][1]))):
            frames = reread.get(cap, {})
            pa_fn = MV._i(r["pure_ack_frame"])
            resp_fn = MV._i(r["resp_frame"])
            # observed ack: pure-ACK's ack for SEPARATE, response's ack for COMBINED
            observed_ack = ""
            if r["classification"] == "SEPARATE_ACK_RESPONSE" and pa_fn in frames:
                observed_ack = frames[pa_fn]["ack"]
            elif resp_fn in frames:
                observed_ack = frames[resp_fn]["ack"]
            w.writerow({
                "reviewer": "", "date": "",                # BLANK -- human fills
                "selection_reason": reason[(cap, reqf)],
                "capture": cap, "transaction_id": "{}:{}".format(cap, reqf),
                "req_frame": reqf, "pure_ack_frame": r["pure_ack_frame"],
                "resp_frame": r["resp_frame"], "req_payload_len": r["req_tcp_len"],
                "resp_payload_len": r["resp_tcp_len"], "req_seq": r["req_seq"],
                "expected_ack": int(r["req_seq"]) + int(r["req_tcp_len"]),
                "observed_ack": observed_ack,
                "software_ack_mode": r["classification"],
                "reviewer_ack_mode": "", "agreement": "", "notes": "",  # BLANK -- human fills
            })
            n += 1

    md = os.path.join(vdir, "human_packet_validation.md")
    with open(md, "w") as fh:
        fh.write(_protocol_md(n, picked, reason))
    print("prepared human validation sheet: {} transactions".format(n))
    print("wrote", csv_path, "(verdict columns BLANK -- awaiting a human reviewer)")
    print("wrote", md)
    return 0


def _protocol_md(n, picked, reason) -> str:
    from collections import Counter
    reasons = Counter()
    for k in picked:
        for why in reason[k].split("+"):
            reasons[why] += 1
    L = ["# Phase 01 — Human Packet Validation (protocol + worksheet)", "",
         "**Status: PENDING HUMAN REVIEW.** This sheet was *prepared* by "
         "`phase01_human_validation_prep.py` — it selects the transactions and pre-reads "
         "their packet fields. The **verdict columns are intentionally blank**. A human "
         "must open each transaction in Wireshark (or inspect the packet fields directly) "
         "and complete `reviewer`, `date`, `reviewer_ack_mode`, `agreement`, and `notes` "
         "in `human_packet_validation.csv`. No software wrote any human verdict.", "",
         "This is distinct from the **AUTOMATED FRAME-TARGETED RE-EXTRACTION VALIDATION** "
         "(`manual_validation_report.md`, 60/60), which is an independent second tshark "
         "read — not human inspection.", "",
         "## Transactions to review ({} total)".format(n)]
    for why, c in sorted(reasons.items()):
        L.append("- {}: {}".format(why, c))
    L += ["", "## Procedure (per transaction)",
          "1. Open the `capture` in Wireshark; go to `req_frame`, `pure_ack_frame` (if any), "
          "`resp_frame`.",
          "2. Confirm the request payload length, response payload length, and request TCP "
          "sequence number against the sheet.",
          "3. Confirm the ACKing packet's acknowledgement number equals `expected_ack` "
          "(= req_seq + req_payload_len): for a SEPARATE transaction the pure TCP ACK, for a "
          "COMBINED transaction the DNP3 response.",
          "4. Decide the ACK mode yourself (COMBINED_ACK_RESPONSE / SEPARATE_ACK_RESPONSE / "
          "OTHER_OR_AMBIGUOUS) and record it in `reviewer_ack_mode`.",
          "5. Set `agreement` = yes/no vs `software_ack_mode`; add `notes` for any anomaly "
          "(retransmission, duplicate ACK, reset, delayed response).",
          "6. Fill `reviewer` and `date`.", "",
          "## Completion criterion",
          "Phase 01 human validation is complete only when every row has a human "
          "`reviewer_ack_mode` and `agreement`. Until then the Phase 01 gate records human "
          "validation as INCOMPLETE.", ""]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.exit(main())
