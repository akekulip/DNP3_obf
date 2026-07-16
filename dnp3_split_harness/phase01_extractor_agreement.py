"""phase01_extractor_agreement.py -- tshark vs Scapy extractor agreement (Phase 01 §5).

The canonical extractor is tshark (it feeds the downstream reports). This script builds
a small validated fixture (>=10 combined, >=10 separate, plus anomalous transactions
where available), reconstructs the same transactions INDEPENDENTLY with Scapy, and
compares frame selection, ACK mode, timestamps, and sizes field by field. Neither
extractor is retired; disagreements are reported, not hidden.

    python3 phase01_extractor_agreement.py --run-dir <phase01 run dir>
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import Dict, List, Optional

import characterize_ack_traces as C
import phase01_reconstruct as R

DNP3_PORT = 20000
BASE_CAPTURES = ["SEL751.pcap", "AB1400.pcap", "ION7550.pcap"]
L_CAPTURES = ["SEL751L.pcap", "AB1400L.pcap", "ION7550L.pcap"]
TIME_TOL_MS = 0.01  # 10 us tolerance for timestamp/delay agreement


# --------------------------------------------------------------------------- #
# Independent Scapy reconstruction (mirrors the tshark transaction logic)
# --------------------------------------------------------------------------- #

def _scapy_packets(pcap: str) -> List[dict]:
    from scapy.all import rdpcap, IP, TCP  # imported lazily
    pkts = rdpcap(pcap)
    out = []
    for i, p in enumerate(pkts):
        if IP not in p or TCP not in p:
            continue
        ip, tcp = p[IP], p[TCP]
        payload = bytes(tcp.payload)
        fl = str(tcp.flags)
        out.append({
            "frame": i + 1, "t": float(p.time),
            "src": ip.src, "dst": ip.dst, "sport": int(tcp.sport), "dport": int(tcp.dport),
            "seq": int(tcp.seq), "ack": int(tcp.ack), "tlen": len(payload),
            "syn": "S" in fl, "fin": "F" in fl, "rst": "R" in fl, "ackf": "A" in fl,
            "dnp3": payload[:2] == b"\x05\x64", "ip_len": len(p),
        })
    return out


def _scapy_transactions(pcap: str) -> Dict[int, dict]:
    """Reconstruct transactions with Scapy; key by request frame number."""
    pkts = _scapy_packets(pcap)
    flows: Dict[tuple, List[dict]] = {}
    for p in pkts:
        a = (p["src"], p["sport"]); b = (p["dst"], p["dport"])
        flows.setdefault(tuple(sorted([a, b])), []).append(p)

    txns: Dict[int, dict] = {}
    for _, fl in flows.items():
        fl.sort(key=lambda p: p["frame"])
        out_ip = out_port = None
        for p in fl:
            if p["dport"] == DNP3_PORT:
                out_ip, out_port = p["dst"], p["dport"]; break
            if p["sport"] == DNP3_PORT:
                out_ip, out_port = p["src"], p["sport"]; break
        if out_ip is None:
            continue

        def is_req(p):
            return p["dst"] == out_ip and p["dport"] == DNP3_PORT and p["tlen"] > 0 and p["dnp3"]

        def is_rev(p):
            return p["src"] == out_ip and p["sport"] == DNP3_PORT

        idx = [i for i, p in enumerate(fl) if is_req(p)]
        for k, i in enumerate(idx):
            req = fl[i]
            end = idx[k + 1] if k + 1 < len(idx) else len(fl)
            window = fl[i + 1:end]
            rev = [p for p in window if is_rev(p)]
            first_rev = rev[0] if rev else None
            first_resp = next((p for p in rev if p["tlen"] > 0 and p["dnp3"]), None)
            first_pure = next((p for p in rev
                               if p["tlen"] == 0 and p["ackf"] and not p["syn"]
                               and not p["fin"] and not p["rst"]), None)
            first_rev_pure = bool(first_rev and first_rev["tlen"] == 0 and first_rev["ackf"]
                                  and not first_rev["syn"] and not first_rev["fin"]
                                  and not first_rev["rst"])
            if first_resp is None:
                cls = C.CLS_OTHER
            elif first_rev is not None and (first_rev["syn"] or first_rev["fin"] or first_rev["rst"]):
                cls = C.CLS_OTHER
            elif first_rev_pure:
                cls = C.CLS_SEPARATE if first_resp is not first_rev else C.CLS_OTHER
            elif first_rev is not None and first_rev["tlen"] > 0 and first_rev["dnp3"]:
                cls = C.CLS_COMBINED if first_resp is first_rev else C.CLS_OTHER
            else:
                cls = C.CLS_OTHER
            pure = first_pure if cls == C.CLS_SEPARATE else None
            txns[req["frame"]] = {
                "req_frame": req["frame"], "req_t": req["t"], "req_len": req["tlen"],
                "resp_frame": first_resp["frame"] if first_resp else None,
                "resp_t": first_resp["t"] if first_resp else None,
                "resp_len": first_resp["tlen"] if first_resp else None,
                "pure_ack_frame": pure["frame"] if pure else None,
                "classification": cls,
                "req_to_resp_ms": (round((first_resp["t"] - req["t"]) * 1000.0, 6)
                                   if first_resp else None),
            }
    return txns


# --------------------------------------------------------------------------- #
# Fixture selection + comparison
# --------------------------------------------------------------------------- #

def _tshark_txns(pcap_path: str):
    device = C.device_from_pcap(pcap_path)
    return R.build_rich_transactions(C.run_tshark(pcap_path), pcap_path, device)


def _close(a: Optional[float], b: Optional[float], tol: float) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return abs(a - b) <= tol


def build_fixture(traffic_dir: str):
    """Return a list of (pcap_path, tshark_txn) fixture rows: >=10 combined, >=10 separate,
    plus anomalous (retransmission) transactions where available."""
    combined, separate, anomalous = [], [], []
    # base captures first (small); fall back to L for anomalies if base has none
    for name in BASE_CAPTURES + L_CAPTURES:
        path = os.path.join(traffic_dir, name)
        if not os.path.exists(path):
            continue
        need_more = len(combined) < 10 or len(separate) < 10 or len(anomalous) < 3
        if not need_more:
            break
        for t in _tshark_txns(path):
            if t.is_reference:
                continue
            if t.retransmission_count > 0 and len(anomalous) < 3:
                anomalous.append((path, t))
            elif t.classification == C.CLS_COMBINED and len(combined) < 10:
                combined.append((path, t))
            elif t.classification == C.CLS_SEPARATE and len(separate) < 10:
                separate.append((path, t))
    fixture = combined + separate + anomalous
    kinds = {"combined": len(combined), "separate": len(separate), "anomalous": len(anomalous)}
    return fixture, kinds


def compare(fixture, scapy_cache):
    rows = []
    for path, tt in fixture:
        name = os.path.basename(path)
        st = scapy_cache.setdefault(path, _scapy_transactions(path)).get(tt.req_frame)
        if st is None:
            rows.append({"capture": name, "req_frame": tt.req_frame,
                         "note": "scapy did not reconstruct this request frame",
                         "all_agree": False})
            continue
        checks = {
            "class_agree": tt.classification == st["classification"],
            "resp_frame_agree": tt.resp_frame == st["resp_frame"],
            "pure_ack_frame_agree": tt.pure_ack_frame == st["pure_ack_frame"],
            "req_len_agree": tt.req_tcp_len == st["req_len"],
            "resp_len_agree": tt.resp_tcp_len == st["resp_len"],
            "req_time_agree": _close(tt.req_time_epoch * 1000.0, st["req_t"] * 1000.0, TIME_TOL_MS),
            "resp_time_agree": _close(
                (tt.resp_time_epoch * 1000.0) if tt.resp_time_epoch is not None else None,
                (st["resp_t"] * 1000.0) if st["resp_t"] is not None else None, TIME_TOL_MS),
            "req_to_resp_agree": _close(tt.req_to_resp_ms, st["req_to_resp_ms"], TIME_TOL_MS),
        }
        rows.append({
            "capture": name, "req_frame": tt.req_frame,
            "tshark_class": tt.classification, "scapy_class": st["classification"],
            "tshark_resp_frame": tt.resp_frame, "scapy_resp_frame": st["resp_frame"],
            "tshark_pure_ack_frame": tt.pure_ack_frame, "scapy_pure_ack_frame": st["pure_ack_frame"],
            "tshark_req_len": tt.req_tcp_len, "scapy_req_len": st["req_len"],
            "tshark_resp_len": tt.resp_tcp_len, "scapy_resp_len": st["resp_len"],
            "tshark_req_to_resp_ms": tt.req_to_resp_ms, "scapy_req_to_resp_ms": st["req_to_resp_ms"],
            "all_agree": all(checks.values()), **checks})
    return rows


def write_outputs(rows, kinds, run_dir):
    vdir = os.path.join(run_dir, "validation")
    os.makedirs(vdir, exist_ok=True)
    csv_path = os.path.join(vdir, "extractor_agreement.csv")
    cols = ["capture", "req_frame", "tshark_class", "scapy_class", "class_agree",
            "tshark_resp_frame", "scapy_resp_frame", "resp_frame_agree",
            "tshark_pure_ack_frame", "scapy_pure_ack_frame", "pure_ack_frame_agree",
            "tshark_req_len", "scapy_req_len", "req_len_agree",
            "tshark_resp_len", "scapy_resp_len", "resp_len_agree",
            "req_time_agree", "resp_time_agree",
            "tshark_req_to_resp_ms", "scapy_req_to_resp_ms", "req_to_resp_agree",
            "all_agree", "note"]
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    n = len(rows)
    n_agree = sum(1 for r in rows if r.get("all_agree"))
    disagreements = [r for r in rows if not r.get("all_agree")]
    md = os.path.join(vdir, "extractor_agreement.md")
    L = ["# Phase 01 — Extractor Agreement (tshark vs Scapy)", "",
         "Canonical extractor: **tshark** (feeds the downstream reports). Scapy is an "
         "INDEPENDENT re-implementation used only to validate agreement on a fixture. "
         "Neither extractor is retired in Phase 01.", "",
         "Fixture composition: **{} combined, {} separate, {} anomalous** "
         "(total {}). Timestamp/delay tolerance: {} ms.".format(
             kinds["combined"], kinds["separate"], kinds["anomalous"], n, TIME_TOL_MS),
         "", "Full-agreement transactions: **{}/{}**.".format(n_agree, n), ""]
    if disagreements:
        L += ["## Disagreements", ""]
        for r in disagreements:
            if "note" in r and r.get("note"):
                L.append("- `{}` req_frame {}: {}".format(r["capture"], r["req_frame"], r["note"]))
            else:
                bad = [k for k in r if k.endswith("_agree") and r[k] is False]
                L.append("- `{}` req_frame {}: disagree on {} "
                         "(tshark class {} / scapy class {})".format(
                             r["capture"], r["req_frame"], ", ".join(bad),
                             r.get("tshark_class"), r.get("scapy_class")))
        L += ["", "Each disagreement above must be resolved by manual Wireshark/tshark "
              "inspection before either extractor's interpretation is trusted for that case.", ""]
    else:
        L += ["## Result", "",
              "The two extractors agree on frame selection, ACK mode, timestamps, and sizes "
              "for every fixture transaction. tshark remains the canonical extractor with an "
              "independent Scapy cross-check.", ""]
    with open(md, "w") as fh:
        fh.write("\n".join(L) + "\n")
    return csv_path, md, n_agree, n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--traffic-dir", default="/home/philip/Projects/DNP3/Traffic Trace")
    ap.add_argument("--run-dir", required=True, help="the Phase 01 run directory to write into")
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: {}\n".format(args.run_dir))
        return 2
    fixture, kinds = build_fixture(args.traffic_dir)
    rows = compare(fixture, {})
    csv_path, md, n_agree, n = write_outputs(rows, kinds, args.run_dir)
    print("extractor agreement: {}/{} fixture transactions fully agree".format(n_agree, n))
    print("fixture: {} combined, {} separate, {} anomalous".format(
        kinds["combined"], kinds["separate"], kinds["anomalous"]))
    print("wrote", csv_path)
    print("wrote", md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
