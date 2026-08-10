#!/usr/bin/env python3
"""Experiment 1, phases 1-3: corpus manifest, header attribution, baseline
header-only observer test. Read-only over the frozen corpus; writes JSON/CSV
into ../out/. Deterministic.

Usage: $RESEARCH_PYTHON run_attribution.py
"""
import csv
import json
import os
from collections import Counter, defaultdict

from scapy.all import IP, TCP, Ether

import exp1_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "out"))
os.makedirs(OUT, exist_ok=True)


def ts_rate_hz(session_pkts, outstation):
    """Estimate the outstation TSval clock rate (Hz) by least-squares slope of
    TSval vs capture time over outstation packets carrying a timestamp."""
    xs, ys = [], []
    for idx, pk in session_pkts:
        if L.direction(pk, outstation) != "outstation":
            continue
        ov = L.option_values(pk[TCP])
        if "tsval" in ov and ov["tsval"] is not None:
            xs.append(float(pk.time))
            ys.append(int(ov["tsval"]) & 0xFFFFFFFF)
    if len(xs) < 3:
        return None
    # unwrap tsval, fit slope
    t0 = xs[0]
    xs = [x - t0 for x in xs]
    y0 = ys[0]
    ys = [((y - y0) & 0xFFFFFFFF) for y in ys]
    n = len(xs)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return None
    slope = (n * sxy - sx * sy) / denom
    return round(slope, 1)


def main():
    manifest = []
    pkt_rows = []
    # per (device, capfile, session-index) signature
    session_sigs = []

    for device, caps in L.CORPUS.items():
        for cap in caps:
            path = os.path.join(L.TRAFFIC_TRACE, cap)
            sessions = L.load_sessions(path)
            # manifest counts
            ntcp = sum(len(s["packets"]) for s in sessions)
            func_cov = Counter()
            has_large = False
            for s in sessions:
                for idx, pk in s["packets"]:
                    if L.TCP in pk and len(bytes(pk[TCP].payload)) > 0:
                        fc = L.dnp3_funccode(pk[TCP].payload)
                        if fc is not None:
                            func_cov[L.DNP3_FUNC.get(fc, f"fc{fc}")] += 1
                        if len(bytes(pk[TCP].payload)) > 4000:
                            has_large = True
            manifest.append({
                "device": device,
                "file": cap,
                "path": os.path.join("Traffic Trace", cap),
                "sha256": L.sha256(path),
                "tcp_sessions": len(sessions),
                "tcp_packets": ntcp,
                "dnp3_funccodes": dict(func_cov),
                "large_response_present": has_large,
                "ttl_note": "checked in signatures",
            })
            # per session: extract signature + per-packet rows
            for si, s in enumerate(sessions):
                out = s["outstation"]
                syn_ack_layout = None
                est_doff = Counter()
                ttls = Counter()
                mss = set()
                wscale = set()
                sackok = set()
                windows = []
                ipid_seq = []
                for idx, pk in s["packets"]:
                    tcp = pk[TCP]
                    ip = pk[IP]
                    d = L.direction(pk, out)
                    pt = L.pkt_type(tcp)
                    lay = L.option_layout(tcp)
                    ov = L.option_values(tcp)
                    if d == "outstation":
                        if pt == "SYN-ACK":
                            syn_ack_layout = ",".join(lay)
                            if "mss" in ov: mss.add(ov["mss"])
                            if "wscale" in ov: wscale.add(ov["wscale"])
                            sackok.add(bool(ov.get("sackok")))
                        if pt in ("DATA", "ACK"):
                            est_doff[int(tcp.dataofs)] += 1
                        ttls[int(ip.ttl)] += 1
                        windows.append(int(tcp.window))
                        ipid_seq.append(int(ip.id))
                    pkt_rows.append({
                        "device": device, "file": cap, "session": si,
                        "direction": d, "pkt_type": pt,
                        "ip_ttl": int(ip.ttl), "ip_id": int(ip.id),
                        "ip_df": 1 if (int(ip.flags) & 0x2) else 0,
                        "ip_len": int(ip.len), "ip_ihl": int(ip.ihl),
                        "tcp_dataofs": int(tcp.dataofs),
                        "tcp_flags": int(tcp.flags),
                        "tcp_window": int(tcp.window),
                        "tcp_opt_layout": ",".join(lay),
                        "tcp_mss": ov.get("mss"),
                        "tcp_wscale": ov.get("wscale"),
                        "tcp_sackok": bool(ov.get("sackok")),
                        "tcp_tsval": ov.get("tsval"),
                        "tcp_payload_len": len(bytes(tcp.payload)),
                        "dnp3_func": L.DNP3_FUNC.get(
                            L.dnp3_funccode(tcp.payload) or -1, ""),
                    })
                # ip.id progression: sequential vs random/zero
                nz = [x for x in ipid_seq if x != 0]
                if not ipid_seq:
                    ipid_mode = "none"
                elif all(x == 0 for x in ipid_seq):
                    ipid_mode = "zero"
                else:
                    diffs = [(nz[i + 1] - nz[i]) & 0xFFFF for i in range(len(nz) - 1)]
                    small = sum(1 for dd in diffs if 0 < dd <= 8)
                    ipid_mode = ("sequential" if diffs and small / max(1, len(diffs)) > 0.6
                                 else "nonsequential")
                session_sigs.append({
                    "device": device, "file": cap, "session": si,
                    "outstation": (out[0] if out else None),
                    "syn_ack_layout": syn_ack_layout,
                    "established_data_offset": dict(est_doff),
                    "ttl": sorted(ttls),
                    "mss": sorted(x for x in mss if x is not None),
                    "wscale": sorted(x for x in wscale if x is not None),
                    "sackok": sorted(sackok),
                    "window_min": min(windows) if windows else None,
                    "window_max": max(windows) if windows else None,
                    "ipid_mode": ipid_mode,
                    "ts_rate_hz": ts_rate_hz(s["packets"], out),
                })

    # write manifest + features
    with open(os.path.join(OUT, "corpus_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(OUT, "packet_features.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(pkt_rows[0].keys()))
        w.writeheader()
        w.writerows(pkt_rows)
    with open(os.path.join(OUT, "session_signatures.json"), "w") as f:
        json.dump(session_sigs, f, indent=2)

    # ---- attribution: data_offset -> exact option layout, outstation dir ----
    attrib = defaultdict(lambda: defaultdict(Counter))
    for r in pkt_rows:
        if r["direction"] != "outstation":
            continue
        key = f"doff={r['tcp_dataofs']} opts=[{r['tcp_opt_layout']}]"
        attrib[r["device"]][r["pkt_type"]][key] += 1
    attrib_out = {d: {pt: dict(c) for pt, c in v.items()} for d, v in attrib.items()}
    with open(os.path.join(OUT, "attribution.json"), "w") as f:
        json.dump(attrib_out, f, indent=2)

    # ---- baseline header-only observer test (exploratory) ----
    # deterministic per-device signature = the set of outstation SYN-ACK layouts,
    # established data_offset set, ttl set. Report separability + a 1-NN LOSO.
    dev_sig = defaultdict(lambda: {"synack": set(), "est_doff": set(), "ttl": set()})
    for s in session_sigs:
        if s["syn_ack_layout"]:
            dev_sig[s["device"]]["synack"].add(s["syn_ack_layout"])
        for k in s["established_data_offset"]:
            dev_sig[s["device"]]["est_doff"].add(int(k))
        for t in s["ttl"]:
            dev_sig[s["device"]]["ttl"].add(int(t))

    groups = {
        "G1_tcp_option_layout_dataoffset": lambda s: (s["syn_ack_layout"],
                                                      tuple(sorted(int(k) for k in s["established_data_offset"]))),
        "G2_window_mss_wscale": lambda s: (tuple(s["mss"]), tuple(s["wscale"]),
                                           s["window_max"]),
        "G3_timestamp_rate": lambda s: (s["ts_rate_hz"],),
        "G4_ttl_ipid_df": lambda s: (tuple(s["ttl"]), s["ipid_mode"]),
        "G5_combined": lambda s: (s["syn_ack_layout"],
                                  tuple(sorted(int(k) for k in s["established_data_offset"])),
                                  tuple(s["ttl"]), s["ipid_mode"],
                                  tuple(s["mss"])),
    }
    # Detect the shared REFERENCE endpoint: an outstation IP whose sessions
    # appear under two or more different device labels (same physical host used
    # as a common control across captures). Tag device vs reference.
    ip_to_devs = defaultdict(set)
    for s in session_sigs:
        if s["outstation"]:
            ip_to_devs[s["outstation"]].add(s["device"])
    reference_ips = {ip for ip, devs in ip_to_devs.items() if len(devs) >= 2}
    for s in session_sigs:
        s["is_reference"] = s["outstation"] in reference_ips
    with open(os.path.join(OUT, "session_signatures.json"), "w") as f:
        json.dump(session_sigs, f, indent=2)

    # classification uses the REAL device sessions only (exclude the shared
    # reference endpoint, which is identical across devices by construction).
    sess = [s for s in session_sigs
            if (s["syn_ack_layout"] or s["established_data_offset"])
            and not s["is_reference"]]
    class_report = {}
    for gname, gfn in groups.items():
        # leave-one-session-out 1-NN by exact signature match
        correct = 0
        total = 0
        per_dev = Counter()
        confusion = defaultdict(Counter)
        for i, test in enumerate(sess):
            total += 1
            tsig = gfn(test)
            # candidates = other sessions
            votes = Counter()
            for j, train in enumerate(sess):
                if j == i:
                    continue
                if gfn(train) == tsig:
                    votes[train["device"]] += 1
            pred = votes.most_common(1)[0][0] if votes else "UNKNOWN"
            confusion[test["device"]][pred] += 1
            if pred == test["device"]:
                correct += 1
                per_dev[test["device"]] += 1
        # signatures unique per device?
        sig_by_dev = defaultdict(set)
        for s in sess:
            sig_by_dev[s["device"]].add(gfn(s))
        shared = False
        allsigs = defaultdict(set)
        for dev, sigs in sig_by_dev.items():
            for sg in sigs:
                allsigs[sg].add(dev)
        for sg, devs in allsigs.items():
            if len(devs) > 1:
                shared = True
        class_report[gname] = {
            "loso_accuracy": round(correct / total, 3) if total else None,
            "n_sessions": total,
            "per_device_correct": dict(per_dev),
            "confusion": {k: dict(v) for k, v in confusion.items()},
            "signature_uniquely_identifies_device": (not shared),
            "device_signatures": {d: sorted(str(x) for x in sigs)
                                  for d, sigs in sig_by_dev.items()},
        }

    baseline = {
        "note": ("EXPLORATORY: one physical unit per model, few real-device "
                 "sessions per device (see corpus_manifest). Deterministic-"
                 "signature separability is reported alongside a leave-one-"
                 "session-out 1-NN over REAL-DEVICE sessions only. This corpus "
                 "supports descriptive attribution, not a generalizable device-"
                 "family classification claim."),
        "corpus_structure": {
            "reference_endpoint_ips": sorted(f"{ip[0]}:{ip[1]}" for ip in reference_ips),
            "reference_note": ("A shared reference endpoint (same Linux-like TCP "
                               "stack) appears in every device capture and is "
                               "excluded from device classification; it is a "
                               "natural canonical target for T2 normalization."),
        },
        "n_devices": len(L.CORPUS),
        "real_device_sessions_per_device": dict(Counter(s["device"] for s in sess)),
        "feature_groups": class_report,
    }
    with open(os.path.join(OUT, "baseline_classification.json"), "w") as f:
        json.dump(baseline, f, indent=2)

    # console summary
    print("== manifest ==")
    for m in manifest:
        print(f"  {m['device']:8} {m['file']:14} sha={m['sha256'][:12]} "
              f"sessions={m['tcp_sessions']} pkts={m['tcp_packets']} "
              f"funcs={m['dnp3_funccodes']}")
    print("\n== outstation SYN-ACK attribution (the data_offset source) ==")
    for d, v in attrib_out.items():
        sa = v.get("SYN-ACK", {})
        print(f"  {d:8} SYN-ACK: {sa}")
    print("\n== baseline header-only separability (EXPLORATORY) ==")
    for g, r in class_report.items():
        print(f"  {g:34} LOSO={r['loso_accuracy']} unique={r['signature_uniquely_identifies_device']}")
    print(f"\nwrote: corpus_manifest.json, packet_features.csv, "
          f"session_signatures.json, attribution.json, baseline_classification.json")


if __name__ == "__main__":
    main()
