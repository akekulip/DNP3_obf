#!/usr/bin/env python3
"""Experiment 1, phases 5-6: validation of transformed pcaps + post-transform
header-only observer test. Read-only over originals; reads transformed copies
from ../pcaps/. Writes out/validation.json and out/post_transform_signatures.json.
"""
import json
import os
from collections import Counter, defaultdict

from scapy.all import rdpcap, Ether, IP, TCP, Padding

import exp1_lib as L

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "out"))
PCAPS = os.path.normpath(os.path.join(HERE, "..", "pcaps"))


def recompute_ok(pk):
    """Recompute IP + TCP checksum independently and compare to stored."""
    ip, tcp = pk[IP], pk[TCP]
    ipc, tcpc = int(ip.chksum), int(tcp.chksum)
    raw = bytes(pk)
    p2 = (Ether(raw) if Ether in pk else IP(raw))
    ip2, tcp2 = p2[IP], p2[TCP]
    del ip2.chksum
    del tcp2.chksum
    p3 = (Ether(bytes(p2)) if Ether in pk else IP(bytes(p2)))
    return int(p3[IP].chksum) == ipc, int(p3[TCP].chksum) == tcpc


def tcp_payload(pk):
    """Real TCP segment payload (DNP3 bytes), excluding L2 min-frame padding."""
    ip, tcp = pk[IP], pk[TCP]
    plen = int(ip.len) - ip.ihl * 4 - tcp.dataofs * 4
    return bytes(tcp.payload)[:max(0, plen)]


def validate_pair(orig_path, trans_path):
    o = rdpcap(orig_path)
    t = rdpcap(trans_path)
    res = {"orig_pkts": len(o), "trans_pkts": len(t)}
    # offload detection on ORIGINAL: how many stored checksums are already valid?
    orig_ip_ok = orig_tcp_ok = orig_tcp_n = 0
    for pk in o:
        if IP in pk and TCP in pk:
            orig_tcp_n += 1
            iok, tok = recompute_ok(pk)
            orig_ip_ok += int(iok)
            orig_tcp_ok += int(tok)
    res["orig_ip_checksum_valid_frac"] = round(orig_ip_ok / max(1, orig_tcp_n), 3)
    res["orig_tcp_checksum_valid_frac"] = round(orig_tcp_ok / max(1, orig_tcp_n), 3)
    res["offload_note"] = (
        "original TCP checksums appear offloaded/invalid in capture"
        if orig_tcp_ok / max(1, orig_tcp_n) < 0.9 else "original checksums valid")
    # alignment + payload preservation + transformed checksum validity
    n = min(len(o), len(t))
    payload_ok = True
    hdr_ok = True          # ip.len == ihl*4 + dataofs*4 + real payload
    minframe_ok = True     # >= 60-byte Ethernet frame
    trans_ip_ok = trans_tcp_ok = trans_n = 0
    first_bad = None
    for i in range(n):
        po, pt = o[i], t[i]
        if IP not in po or TCP not in po:
            continue
        # real DNP3 payload must be byte-identical
        if tcp_payload(po) != tcp_payload(pt):
            payload_ok = False
            if first_bad is None:
                first_bad = i
        # header self-consistency ties ip.len, data_offset, and payload together
        exp_iplen = pt[IP].ihl * 4 + pt[TCP].dataofs * 4 + len(tcp_payload(pt))
        if int(pt[IP].len) != exp_iplen:
            hdr_ok = False
        if len(bytes(pt[Ether])) < 60:
            minframe_ok = False
        trans_n += 1
        iok, tok = recompute_ok(pt)
        trans_ip_ok += int(iok)
        trans_tcp_ok += int(tok)
    res.update({
        "packet_count_preserved": len(o) == len(t),
        "payload_bytes_unchanged": payload_ok,
        "first_payload_mismatch_index": first_bad,
        "ip_len_dataoffset_payload_consistent": hdr_ok,
        "ethernet_min_frame_ok": minframe_ok,
        "trans_ip_checksum_valid_frac": round(trans_ip_ok / max(1, trans_n), 3),
        "trans_tcp_checksum_valid_frac": round(trans_tcp_ok / max(1, trans_n), 3),
    })
    res["PASS"] = bool(res["packet_count_preserved"] and payload_ok and hdr_ok
                       and minframe_ok and res["trans_ip_checksum_valid_frac"] == 1.0
                       and res["trans_tcp_checksum_valid_frac"] == 1.0)
    return res


def device_signature(path):
    """Real-device outstation signature after transformation (exclude the shared
    reference endpoint 10.0.0.2)."""
    sessions = L.load_sessions(path)
    sigs = []
    for s in sessions:
        out = s["outstation"]
        if out is None or out[0] == "10.0.0.2":
            continue
        sa = None
        est = Counter()
        ttls = set()
        mss = set()
        has_ts = False
        for idx, pk in s["packets"]:
            if L.direction(pk, out) != "outstation":
                continue
            tcp = pk[TCP]
            pt = L.pkt_type(tcp)
            if pt == "SYN-ACK":
                sa = ",".join(L.option_layout(tcp))
                ov = L.option_values(tcp)
                if "mss" in ov:
                    mss.add(ov["mss"])
            if pt in ("DATA", "ACK"):
                est[int(tcp.dataofs)] += 1
            ttls.add(int(pk[IP].ttl))
            if any((isinstance(o, (tuple, list)) and o[0] == "Timestamp")
                   for o in tcp.options):
                has_ts = True
        sigs.append({"outstation_ip": out[0], "syn_ack_layout": sa,
                     "established_data_offset": sorted(est),
                     "ttl": sorted(ttls), "mss": sorted(mss),
                     "carries_timestamp": has_ts})
    return sigs


def main():
    # Full per-packet validation on the short captures (representative and fast;
    # the per-packet checksum recompute is O(2 serializations)/packet). The large
    # "L" transforms are validated at the signature level via the collapse summary.
    validation = {}
    for cap in L.SHORT_CAPS:
        src = os.path.join(L.TRAFFIC_TRACE, cap)
        base = cap.replace(".pcap", "")
        for mode in ["T0", "T1", "T2", "T3"]:
            tp = os.path.join(PCAPS, f"{base}_{mode}.pcap")
            validation[f"{base}_{mode}"] = validate_pair(src, tp)
    with open(os.path.join(OUT, "validation.json"), "w") as f:
        json.dump(validation, f, indent=2)

    # post-transform signatures per capture per mode + originals
    post = {"original": {}, "T0": {}, "T1": {}, "T2": {}, "T3": {}}
    for cap in L.ALL_CAPS:
        dev = cap.replace(".pcap", "")
        post["original"][dev] = device_signature(os.path.join(L.TRAFFIC_TRACE, cap))
        for mode in ["T0", "T1", "T2", "T3"]:
            post[mode][dev] = device_signature(os.path.join(PCAPS, f"{dev}_{mode}.pcap"))
    with open(os.path.join(OUT, "post_transform_signatures.json"), "w") as f:
        json.dump(post, f, indent=2)

    # console summary
    print("== VALIDATION ==")
    allpass = True
    for k, r in validation.items():
        allpass &= r["PASS"]
        print(f"  {k:16} PASS={r['PASS']} payload_unchanged={r['payload_bytes_unchanged']} "
              f"hdr_ok={r['ip_len_dataoffset_payload_consistent']} minframe={r['ethernet_min_frame_ok']} "
              f"trans_tcp_cksum={r['trans_tcp_checksum_valid_frac']} (orig={r['orig_tcp_checksum_valid_frac']})")
    print(f"  ALL PASS: {allpass}")
    print("\n== POST-TRANSFORM device signatures (real device only) ==")
    for mode in ["original", "T0", "T2"]:
        print(f"  --- {mode} ---")
        for dev, sigs in post[mode].items():
            for s in sigs:
                print(f"    {dev:8} synack='{s['syn_ack_layout']}' est_doff={s['established_data_offset']} "
                      f"ttl={s['ttl']} mss={s['mss']} ts={s['carries_timestamp']}")
    # do devices collapse to one signature? Report the full signature and,
    # separately, the handshake-captured signature (sessions with a SYN-ACK) and
    # the established-only signature (present in every session).
    def full_sig(s):
        return (s["syn_ack_layout"], tuple(s["established_data_offset"]),
                tuple(s["ttl"]), tuple(s["mss"]), s["carries_timestamp"])

    def est_sig(s):
        return (tuple(s["established_data_offset"]), tuple(s["ttl"]),
                s["carries_timestamp"])

    collapse = {}
    for mode in ["original", "T0", "T1", "T2", "T3"]:
        full, hs, est = set(), set(), set()
        for dev, sigs in post[mode].items():
            for s in sigs:
                full.add(full_sig(s))
                est.add(est_sig(s))
                if s["syn_ack_layout"] is not None:
                    hs.add(full_sig(s))
        collapse[mode] = {
            "distinct_full_signatures": len(full),
            "distinct_handshake_captured_signatures": len(hs),
            "distinct_established_only_signatures": len(est),
        }
        print(f"  {mode:9} distinct: full={len(full)} handshake={len(hs)} established_only={len(est)}")
    with open(os.path.join(OUT, "collapse_summary.json"), "w") as f:
        json.dump(collapse, f, indent=2)


if __name__ == "__main__":
    main()
