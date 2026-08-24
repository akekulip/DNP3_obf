#!/usr/bin/env python3
"""Paired ingress-vs-egress byte comparator for the transparent Defense 4 forwarding claim.

Run with $RESEARCH_PYTHON (needs scapy).

  pair_bytes.py --ingress <relay-facing.pcap> --egress <master-facing.pcap>
                --relay-ip 192.168.10.7 --master-ip 192.168.10.1 [--port 20000]
                [--intended <intended.jsonl>] [--offloads off|on] [--allow-mac-rewrite]
                [--min-protected 1] [--out report.json]

Topology: master <-> switch <-> relay. The relay-facing capture sees each relay->master ACK/RESPONSE
as it ARRIVES at the switch (before the hold); the master-facing capture sees the SAME frame as it
DEPARTS to the master (after the hold). Defense 4 changes only WHEN a frame leaves, never its bytes,
and the current P4 does NOT rewrite Ethernet MAC addresses, so for every relay->master frame the two
captures must carry byte-identical TCP payloads AND identical Ethernet/IP/TCP header fields.

Matching key: direction (relay->master), TCP 4-tuple, seq, ack, flags, DNP3 application sequence (when
a payload is present), payload length, and occurrence index (to separate a retransmission of the same
seq). The mapping records the occurrence index and BOTH pcap frame numbers.

Compared for every matched frame:
  - full TCP payload, exactly (pure ACKs included: a dropped/injected/changed ACK fails);
  - preserved headers: eth_src, eth_dst, vlan, ip_src, ip_dst, ip_id, ip_ttl, ip_flags, ip_len,
    sport, dport, seq, ack, tcp_flags, window. A MAC change FAILS unless --allow-mac-rewrite names a
    verified topology transform.
  - checksums: with --offloads off (default) a nonzero->changed or nonzero->zero checksum FAILS; with
    --offloads on a zeroed egress checksum is tolerated (transmit checksum offload) and only a nonzero
    mismatch fails.

Fail (exit 1) if any relay->master frame is unmatched, duplicated, reordered, or changed; if a
preserved header differs; if either capture has zero relay->master frames or fewer than --min-protected
RESPONSE (payload-bearing) frames; or if --intended bytes do not match ingress. Exit 2 on a usage/IO
error (missing/unreadable/malformed/wrong-link-type pcap, scapy unavailable, bad --intended).
"""
import argparse
import json
import os
import sys

try:
    from scapy.all import rdpcap, Ether, IP, TCP, Dot1Q
except Exception as e:
    print(json.dumps({"verdict": "IO_FAIL", "error": "scapy unavailable: %s" % e}))
    sys.exit(2)


class HardIO(Exception):
    pass


def app_seq(payload):
    if len(payload) >= 12 and payload[0] == 0x05 and payload[1] == 0x64:
        return "0x%02X" % payload[11]
    return None


def read_pcap(path):
    if not os.path.exists(path):
        raise HardIO("pcap missing: %s" % path)
    if os.path.getsize(path) == 0:
        raise HardIO("pcap empty: %s" % path)
    try:
        return rdpcap(path)
    except Exception as e:
        raise HardIO("pcap unreadable/malformed: %s (%s)" % (path, e))


def extract(pcap, relay_ip, master_ip, port):
    """relay->master frames (in capture order), plus diagnostics."""
    frames = []
    non_eth = other_flow = 0
    for i, p in enumerate(pcap, start=1):
        if Ether not in p:
            non_eth += 1
            continue
        vlan = int(p[Dot1Q].vlan) if Dot1Q in p else None
        if IP not in p or TCP not in p:
            other_flow += 1
            continue
        ip, tcp = p[IP], p[TCP]
        if not (ip.src == relay_ip and ip.dst == master_ip and int(tcp.sport) == port):
            other_flow += 1
            continue
        payload = bytes(tcp.payload)
        frames.append({
            "frameno": i, "eth_src": p[Ether].src, "eth_dst": p[Ether].dst, "vlan": vlan,
            "ip_src": ip.src, "ip_dst": ip.dst, "ip_id": int(ip.id), "ip_ttl": int(ip.ttl),
            "ip_flags": str(ip.flags), "ip_len": int(ip.len), "ip_chksum": int(ip.chksum or 0),
            "sport": int(tcp.sport), "dport": int(tcp.dport), "seq": int(tcp.seq), "ack": int(tcp.ack),
            "flags": str(tcp.flags), "window": int(tcp.window), "tcp_chksum": int(tcp.chksum or 0),
            "plen": len(payload), "payload": payload, "app_seq": app_seq(payload),
        })
    return frames, non_eth, other_flow


def key_of(f):
    return (f["ip_src"], f["sport"], f["ip_dst"], f["dport"], f["seq"], f["ack"],
            f["flags"], f["plen"], f["app_seq"])


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n if len(a) != len(b) else None


PRESERVED = ["eth_src", "eth_dst", "vlan", "ip_src", "ip_dst", "ip_id", "ip_ttl", "ip_flags",
             "ip_len", "sport", "dport", "seq", "ack", "flags", "window"]


def load_intended(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        raise HardIO("--intended file missing/empty: %s" % path)
    out = {}
    with open(path) as f:
        for ln, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                out[rec["app_seq"]] = bytes.fromhex(rec["hex"])
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                raise HardIO("--intended line %d bad: %s" % (ln, e))
    if not out:
        raise HardIO("--intended has no records: %s" % path)
    return out


def main(argv):
    ap = argparse.ArgumentParser(description="paired ingress-vs-egress byte comparator")
    ap.add_argument("--ingress", required=True)
    ap.add_argument("--egress", required=True)
    ap.add_argument("--relay-ip", required=True)
    ap.add_argument("--master-ip", required=True)
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--intended", default=None)
    ap.add_argument("--offloads", choices=["off", "on"], default="off")
    ap.add_argument("--allow-mac-rewrite", action="store_true",
                    help="only for a verified topology transform; the default P4 preserves MAC")
    ap.add_argument("--min-protected", type=int, default=1)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    ing_pk = read_pcap(args.ingress)
    egr_pk = read_pcap(args.egress)
    ing, ing_ne, ing_of = extract(ing_pk, args.relay_ip, args.master_ip, args.port)
    egr, egr_ne, egr_of = extract(egr_pk, args.relay_ip, args.master_ip, args.port)

    hard = []
    # zero-relevant-flow / zero-protected checks
    if len(ing) == 0:
        hard.append("ingress has zero relay->master frames (wrong flow / wrong IPs / empty)")
    if len(egr) == 0:
        hard.append("egress has zero relay->master frames (wrong flow / wrong IPs / empty)")
    ing_resp = [f for f in ing if f["plen"] > 0]
    egr_resp = [f for f in egr if f["plen"] > 0]
    if len(ing_resp) < args.min_protected:
        hard.append("ingress has %d RESPONSE frames < --min-protected %d" % (len(ing_resp), args.min_protected))

    # --intended: outstation intended bytes must match what arrived at ingress
    intended_checked = 0
    intended_mismatch = []
    if args.intended is not None:
        intended = load_intended(args.intended)
        for f in ing_resp:
            if f["app_seq"] in intended:
                intended_checked += 1
                if f["payload"] != intended[f["app_seq"]]:
                    off = first_diff(f["payload"], intended[f["app_seq"]])
                    intended_mismatch.append({"app_seq": f["app_seq"], "frameno": f["frameno"], "first_diff_offset": off})
        if intended_checked == 0:
            hard.append("--intended given but no ingress RESPONSE matched an intended app_seq")
        if intended_mismatch:
            hard.append("%d ingress frame(s) differ from intended bytes" % len(intended_mismatch))

    # pair ingress -> egress by key + occurrence
    egr_idx = {}
    for f in egr:
        egr_idx.setdefault(key_of(f), []).append(f)
    used = {}
    mapping, payload_mismatch, header_mismatch, checksum_fail, unmatched_ingress = [], [], [], [], []
    checksum_offload_notes = 0

    for f in ing:
        k = key_of(f)
        occ = used.get(k, 0)
        cands = egr_idx.get(k, [])
        if occ < len(cands):
            g = cands[occ]
            used[k] = occ + 1
            entry = {"seq": f["seq"], "plen": f["plen"], "app_seq": f["app_seq"], "occ": occ,
                     "ingress_frameno": f["frameno"], "egress_frameno": g["frameno"], "matched": True}
            off = first_diff(f["payload"], g["payload"])
            entry["payload_ok"] = off is None
            if off is not None:
                payload_mismatch.append({"seq": f["seq"], "app_seq": f["app_seq"], "first_diff_offset": off,
                                         "ingress_frameno": f["frameno"], "egress_frameno": g["frameno"]})
            for field in PRESERVED:
                if field in ("eth_src", "eth_dst") and args.allow_mac_rewrite:
                    continue
                if f[field] != g[field]:
                    header_mismatch.append({"seq": f["seq"], "field": field, "ingress": f[field], "egress": g[field],
                                            "ingress_frameno": f["frameno"], "egress_frameno": g["frameno"]})
            # checksums
            for cf in ("ip_chksum", "tcp_chksum"):
                a, b = f[cf], g[cf]
                if a != b:
                    if b == 0 and args.offloads == "on":
                        checksum_offload_notes += 1     # transmit checksum offload zeroed it
                    else:
                        checksum_fail.append({"seq": f["seq"], "field": cf, "ingress": a, "egress": b})
            mapping.append(entry)
        else:
            unmatched_ingress.append({"seq": f["seq"], "app_seq": f["app_seq"], "plen": f["plen"],
                                      "ingress_frameno": f["frameno"]})
            mapping.append({"seq": f["seq"], "plen": f["plen"], "app_seq": f["app_seq"],
                            "ingress_frameno": f["frameno"], "matched": False})

    unmatched_egress = []
    for k, cands in egr_idx.items():
        for g in cands[used.get(k, 0):]:
            unmatched_egress.append({"seq": g["seq"], "app_seq": g["app_seq"], "plen": g["plen"], "egress_frameno": g["frameno"]})

    # ordering: relay->master frames must appear in the same order at both points
    ing_order = [f["seq"] for f in ing]
    egr_order = [g["seq"] for g in egr]
    common = set(ing_order) & set(egr_order)
    reordered = [s for s in egr_order if s in common] != [s for s in ing_order if s in common]

    if payload_mismatch:
        hard.append("%d payload byte mismatch(es)" % len(payload_mismatch))
    if header_mismatch:
        macs = [h for h in header_mismatch if h["field"] in ("eth_src", "eth_dst")]
        if macs:
            hard.append("%d MAC field change(s) (P4 does not rewrite MAC)" % len(macs))
        others = [h for h in header_mismatch if h["field"] not in ("eth_src", "eth_dst")]
        if others:
            hard.append("%d preserved-header mismatch(es)" % len(others))
    if checksum_fail:
        hard.append("%d checksum mismatch(es) with offloads=%s" % (len(checksum_fail), args.offloads))
    if unmatched_ingress:
        hard.append("%d ingress frame(s) with no egress match (dropped/altered, ACKs included)" % len(unmatched_ingress))
    if unmatched_egress:
        hard.append("%d egress frame(s) with no ingress match (injected/duplicated)" % len(unmatched_egress))
    if reordered:
        hard.append("relay->master frames reordered between ingress and egress")

    report = {
        "ingress_pcap": args.ingress, "egress_pcap": args.egress,
        "relay_ip": args.relay_ip, "master_ip": args.master_ip, "port": args.port,
        "offloads": args.offloads, "allow_mac_rewrite": args.allow_mac_rewrite,
        "ingress_frames": len(ing), "egress_frames": len(egr),
        "ingress_responses": len(ing_resp), "egress_responses": len(egr_resp),
        "ingress_non_ether": ing_ne, "ingress_other_flow": ing_of,
        "egress_non_ether": egr_ne, "egress_other_flow": egr_of,
        "matched": sum(1 for m in mapping if m.get("matched")),
        "intended_checked": intended_checked, "intended_mismatch": intended_mismatch,
        "payload_mismatch": payload_mismatch, "header_mismatch": header_mismatch,
        "checksum_fail": checksum_fail, "checksum_offload_notes": checksum_offload_notes,
        "unmatched_ingress": unmatched_ingress, "unmatched_egress": unmatched_egress,
        "reordered": reordered, "mapping": mapping,
        "hard_anomalies": hard,
        "verdict": "BYTE-IDENTICAL" if not hard else "BYTE MISMATCH",
        "exit_code": 0 if not hard else 1,
    }
    if args.out:
        json.dump(report, open(args.out, "w"), indent=2, default=str)
    print(json.dumps({k: v for k, v in report.items() if k != "mapping"}, indent=2, default=str))
    return report["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except HardIO as e:
        print(json.dumps({"verdict": "IO_FAIL", "error": str(e), "exit_code": 2}))
        sys.exit(2)
