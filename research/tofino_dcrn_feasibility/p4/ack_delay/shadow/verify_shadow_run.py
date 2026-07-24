#!/usr/bin/env python3
"""
verify_shadow_run.py — GATE-1 offline verifier for the B1 shadow-classifier silicon run.

Given the two injection halves, the two egress captures, and the on-switch counter JSON, it checks
every charter §G acceptance criterion and prints a PASS/FAIL report + JSON.

  dp8_inject.pcap  -> egresses dp9 -> hulk_cap.pcap    (master->outstation frames, dir 0)
  dp9_inject.pcap  -> egresses dp8 -> vision_cap.pcap   (outstation->master frames, dir 1)

Checks:
  * count identity     : each capture holds exactly as many flow frames as were injected (no loss)
  * order + byte identity: the i-th captured flow frame equals the i-th injected frame over the
                          meaningful span [Ethernet(14) + IP total_len], i.e. IP/TCP/DNP3 bytes,
                          TCP seq/ack, IP checksum all identical. (Trailing Ethernet padding on
                          sub-60B frames is a NIC/link artifact, not a shadow modification, so it
                          is excluded from the identity span.)
  * classification     : refmodel tally over the injected halves (with their physical dir) mapped
                          to silicon class indices == the on-switch class_ctr counts
  * no zero-payload ACK as DNP3, 300 READ, 300 RESP, 300 separate-ACK->response transaction triples
"""
import argparse, json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shadow_refmodel import classify
from scapy.all import PcapReader, IP, TCP, Ether, raw

DNP3 = 20000
# refmodel class name -> (silicon index, silicon name)
MAP = {"UNRELATED": (0, "NON_DNP3"), "DNP3_READ": (1, "DNP3_READ"), "PURE_ACK": (2, "PURE_ACK"),
       "DNP3_RESPONSE": (3, "DNP3_RESP"), "TCP_FIN": (4, "TCP_FIN"), "TCP_RST": (5, "TCP_RST"),
       "LINK_STATUS_OR_OTHER_DNP3": (6, "LINK_OTHER"), "MALFORMED": (7, "MALFORMED")}


def meaningful(pkt):
    """Ethernet header + IP datagram bytes (exclude trailing L2 padding). None if not IPv4."""
    if IP not in pkt:
        return None
    b = raw(pkt)
    iplen = pkt[IP].len
    return b[:14 + iplen]


def flow_frames(path):
    """Ordered list of (meaningful_bytes, scapy_pkt) for IPv4/TCP frames on the DNP3 flow."""
    out = []
    for p in PcapReader(path):
        if IP not in p or TCP not in p:
            continue
        if int(p[TCP].sport) != DNP3 and int(p[TCP].dport) != DNP3:
            continue
        out.append((meaningful(p), p))
    return out


def refmodel_tally(path):
    """Silicon-index tally by running the refmodel over a pcap half (dir implicit in TCP ports)."""
    tally = {}
    for p in PcapReader(path):
        if IP not in p or TCP not in p:
            continue
        c, _ = classify(p[IP].src, p[IP].dst, int(p[TCP].sport), int(p[TCP].dport),
                        int(p[TCP].flags), bytes(p[TCP].payload))
        idx, name = MAP.get(c, (0, "NON_DNP3"))
        tally[name] = tally.get(name, 0) + 1
    return tally


def compare_dir(inject, capture, label):
    inj = flow_frames(inject)
    cap = flow_frames(capture)
    r = {"label": label, "injected": len(inj), "captured_flow": len(cap)}
    r["count_identity"] = (len(inj) == len(cap))
    n = min(len(inj), len(cap))
    byte_ok = True; seqack_ok = True; first_bad = None
    for i in range(n):
        if inj[i][0] != cap[i][0]:
            byte_ok = False
            if first_bad is None:
                first_bad = i
        else:
            ti, tc = inj[i][1][TCP], cap[i][1][TCP]
            if int(ti.seq) != int(tc.seq) or int(ti.ack) != int(tc.ack):
                seqack_ok = False
    r["byte_identity"] = byte_ok and r["count_identity"]
    r["order_preserved"] = byte_ok and r["count_identity"]   # in-order byte match implies order kept
    r["tcp_seq_ack_identity"] = seqack_ok
    r["first_mismatch_index"] = first_bad
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dp8-inject", required=True)
    ap.add_argument("--dp9-inject", required=True)
    ap.add_argument("--hulk-cap", required=True)     # egress of dp8-injected frames
    ap.add_argument("--vision-cap", required=True)   # egress of dp9-injected frames
    ap.add_argument("--switch-counters", required=True)  # JSON from shadow_read_counters.py
    args = ap.parse_args()

    a = compare_dir(args.dp8_inject, args.hulk_cap, "dp8->dp9 (READs/master-ACK, dir0)")
    b = compare_dir(args.dp9_inject, args.vision_cap, "dp9->dp8 (RESP/CLRT-ACK, dir1)")

    # expected silicon classification = refmodel over both halves, mapped to silicon classes
    exp = {}
    for half in (args.dp8_inject, args.dp9_inject):
        for k, v in refmodel_tally(half).items():
            exp[k] = exp.get(k, 0) + v

    with open(args.switch_counters) as f:
        sw = json.load(f)
    sw_counts_raw = sw.get("class_counts", {})
    # normalize "1_DNP3_READ" -> "DNP3_READ": int
    sw_counts = {}
    for k, v in sw_counts_raw.items():
        name = k.split("_", 1)[1] if "_" in k and k.split("_", 1)[0].isdigit() else k
        sw_counts[name] = int(v)

    # Exact match on every DNP3-meaningful class; NON_DNP3 may only GROW vs the injected refmodel,
    # because a live inline link also carries background non-DNP3 frames (ARP/etc.) that are not part
    # of the injected session and can never be miscounted as a DNP3 class. (On a clean pcap with no
    # background this reduces to exact equality.)
    def _class_ok(k):
        if k == "NON_DNP3":
            return sw_counts.get(k, 0) >= exp.get(k, 0)
        return sw_counts.get(k, 0) == exp.get(k, 0)
    class_match = all(_class_ok(k) for k in set(exp) | set(sw_counts))

    checks = {
        "dir0_count_identity":        a["count_identity"],
        "dir0_byte_identity":         a["byte_identity"],
        "dir0_tcp_seq_ack_identity":  a["tcp_seq_ack_identity"],
        "dir1_count_identity":        b["count_identity"],
        "dir1_byte_identity":         b["byte_identity"],
        "dir1_tcp_seq_ack_identity":  b["tcp_seq_ack_identity"],
        "reads_classified_300":       sw_counts.get("DNP3_READ", 0) == 300,
        "responses_classified_300":   sw_counts.get("DNP3_RESP", 0) == 300,
        "pure_acks_ge_600":           sw_counts.get("PURE_ACK", 0) >= 600,
        "no_malformed":               sw_counts.get("MALFORMED", 0) == 0,
        "silicon_matches_refmodel":   class_match,
        "no_loss_or_reorder":         a["order_preserved"] and b["order_preserved"],
    }
    result = {
        "dir0": a, "dir1": b,
        "expected_class_counts": exp,
        "switch_class_counts": sw_counts,
        "checks": checks,
        "PASS": all(checks.values()),
    }
    print(json.dumps(result, indent=1))
    print("\n=== %s ===" % ("PASS" if result["PASS"] else "FAIL"))
    for k, v in checks.items():
        print("  [%s] %s" % ("OK" if v else "XX", k))
    sys.exit(0 if result["PASS"] else 1)


if __name__ == "__main__":
    main()
