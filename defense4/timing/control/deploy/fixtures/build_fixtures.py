#!/usr/bin/env python3
"""Deterministically synthesize fail-closed test fixtures for the Defense 4 evidence pipeline.

  $RESEARCH_PYTHON build_fixtures.py <out_dir>

Produces, under <out_dir>, one clean baseline plus a mutated negative for every hard-failure the
repaired tools must catch. Everything is synthesized from fixed constants (no timestamps, no
randomness), so the fixtures are reproducible byte-for-byte on every run.

Layout under <out_dir>:
  scorer/clean/            block + ev_pre + ev_post + blk.pcap for a valid D2 block  (scorer exit 0)
  scorer/bypass/           D2 with injected RESP_BYPASS                              (scorer exit 1)
  scorer/ordering/         a RESPONSE-before-ACK row (clrt<0)                        (scorer exit 1)
  scorer/stale/            nonzero reg_tag after the block                           (scorer exit 1)
  scorer/countermismatch/  RESP_HOLD_*+BYPASS != responded                          (scorer exit 1)
  scorer/tokenescape/      a 0x88C1 token seen on the wire                           (scorer exit 1)
  scorer/queuedrop/        a TM queue drop                                           (scorer exit 1)
  scorer/malformed.json    not JSON                                                  (scorer exit 2)
  scorer/empty.json        empty                                                     (scorer exit 2)
  pairs/ingress.pcap, egress_clean.pcap, egress_1byte.pcap, egress_drop.pcap, egress_inject.pcap
  dry/clean/ + dry/spec.txt          DRY_RUN fixtures for run_campaign.sh (clean)
  manifest/                a small dir to manifest then tamper
"""
import json
import os
import sys

RELAY = "192.168.10.7"
MASTER = "192.168.10.1"
MPORT = 51000
DNP3_PORT = 20000
N = 60   # polls per block

REQUIRED_CF = ["ARM_FRESH", "RESP_HOLD_EARLY", "RESP_HOLD_LATE", "RESP_BYPASS", "ACK_REJECT", "PKTGEN_ADMIT"]
REQUIRED_CD = ["RELEASE_DEADLINE", "RELEASE_FAILOPEN", "ACK_RELEASE", "ACK_REL_RETIRE", "BLOCK_TERM_TMO", "BLOCK_TERM_STALE"]


def zero_dump():
    d = {"cf": {k: 0 for k in REQUIRED_CF}, "cd": {k: 0 for k in REQUIRED_CD},
         "regs": {"reg_tag": 0},
         "queues": {q: {"drop_count_packets": 0} for q in ("qid7", "qid6", "qid5", "qid4")},
         "port_tm_drops": {"ig_port": 0, "eg_port": 0}}
    return d


def clean_d2_block():
    """A valid D2 block: N polls, one connection, each held ~10 ms, FIN only on the last poll."""
    rows = []
    for i in range(N):
        t_read = 100.0 + i * 0.4
        t_ack = t_read + 0.0018
        t_resp = t_ack + 0.0100           # CLRT ~ 10 ms
        rows.append({
            "poll": i, "app_seq_sent": "0x%02X" % (0xC0 + (i % 16)),
            "t_read": t_read, "read_seq": 1000 + i, "t_ack": t_ack, "t_resp": t_resp,
            "resp_len": 122, "resp_segments": 1,
            "dup_ack": 0, "dup_resp": 0, "retransmit": 0,
            "fin": (i == N - 1), "rst": False,
            "read_to_ack_ms": (t_ack - t_read) * 1e3, "read_to_resp_ms": (t_resp - t_read) * 1e3,
            "clrt_ms": (t_resp - t_ack) * 1e3, "ack_before_resp": True, "order_inconclusive": False,
        })
    block = {"label": "T_D2", "mode": "D2", "d_a_ms": "4", "d_r_ms": "10", "N": N, "gap_s": 0.4,
             "attempted": N, "sent": N, "responded": N, "errors": [], "capture_ok": True,
             "one_connection": True, "local_port": MPORT, "token_escapes_on_wire": 0,
             "rows": rows, "pcap": "blk_T_D2.pcap", "n_rows": N,
             "distinct_app_seqs": sorted({"0x%02X" % (0xC0 + (i % 16)) for i in range(N)})}
    pre = zero_dump()
    post = zero_dump()
    post["cf"]["ARM_FRESH"] = N
    post["cf"]["RESP_HOLD_LATE"] = N      # D2 holds every RESPONSE to the deadline
    post["cf"]["PKTGEN_ADMIT"] = N
    post["cd"]["RELEASE_DEADLINE"] = N
    post["cd"]["ACK_RELEASE"] = N
    return block, pre, post


def write_case(d, block, pre, post):
    os.makedirs(d, exist_ok=True)
    json.dump(block, open(os.path.join(d, "block.json"), "w"))
    json.dump(pre, open(os.path.join(d, "ev_pre.json"), "w"))
    json.dump(post, open(os.path.join(d, "ev_post.json"), "w"))


def craft_pcaps(pairs_dir):
    from scapy.all import Ether, IP, TCP, wrpcap
    os.makedirs(pairs_dir, exist_ok=True)
    relay_mac, sw_mac, master_mac = "00:11:22:33:44:77", "00:de:ad:be:ef:00", "00:aa:bb:cc:dd:01"

    def dnp3(appctrl, tail):
        return bytes([0x05, 0x64, 0x0b, 0x44, 0x00, 0x00, 0x01, 0x00, 0x2a, 0xec, 0xc0, appctrl]) + tail

    def frame(smac, dmac, seq, ack, payload=b"", flags="PA"):
        return Ether(src=smac, dst=dmac) / IP(src=RELAY, dst=MASTER, id=seq % 65536) / \
            TCP(sport=DNP3_PORT, dport=MPORT, seq=seq, ack=ack, flags=flags) / payload

    r0 = dnp3(0xC0, b"\x01\x02\x03\x04\x9a\x9b")
    r1 = dnp3(0xC1, b"\x05\x06\x07\x08\x1a\x2b")
    ing = [frame(relay_mac, sw_mac, 1000, 500, flags="A"),
           frame(relay_mac, sw_mac, 1000, 500, r0),
           frame(relay_mac, sw_mac, 1006, 500, r1)]
    egr = [frame(sw_mac, master_mac, 1000, 500, flags="A"),
           frame(sw_mac, master_mac, 1000, 500, r0),
           frame(sw_mac, master_mac, 1006, 500, r1)]
    r0m = bytearray(r0); r0m[12] ^= 0x01                       # single payload byte flipped
    egr_mut = [egr[0], frame(sw_mac, master_mac, 1000, 500, bytes(r0m)), egr[2]]
    r2 = dnp3(0xC2, b"\xde\xad\xbe\xef\x77\x88")
    egr_inj = egr + [frame(sw_mac, master_mac, 1012, 500, r2)]

    def w(name, pkts):
        wrpcap(os.path.join(pairs_dir, name), [Ether(bytes(p)) for p in pkts])
    w("ingress.pcap", ing)
    w("egress_clean.pcap", egr)
    w("egress_1byte.pcap", egr_mut)
    w("egress_drop.pcap", [egr[0], egr[1]])
    w("egress_inject.pcap", egr_inj)


def stub_pcap(path):
    with open(path, "wb") as f:
        f.write(b"DNP3-DRY-PCAP-STUB\n")   # non-empty; scorer/run_campaign only check size in dry mode


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    # ---- scorer clean baseline ----
    block, pre, post = clean_d2_block()
    sc = os.path.join(out, "scorer")
    write_case(os.path.join(sc, "clean"), block, pre, post)
    stub_pcap(os.path.join(sc, "clean", "blk.pcap"))

    # ---- bypass: 3 RESPONSEs skipped the hold ----
    b, pr, po = clean_d2_block()
    po["cf"]["RESP_BYPASS"] = 3
    write_case(os.path.join(sc, "bypass"), b, pr, po)

    # ---- ordering inversion: one row RESPONSE before ACK (clrt<0) ----
    b, pr, po = clean_d2_block()
    b["rows"][5]["clrt_ms"] = -0.5
    b["rows"][5]["ack_before_resp"] = False
    write_case(os.path.join(sc, "ordering"), b, pr, po)

    # ---- stale reg_tag after the block ----
    b, pr, po = clean_d2_block()
    po["regs"]["reg_tag"] = 0xC5
    write_case(os.path.join(sc, "stale"), b, pr, po)

    # ---- counter mismatch: HOLD_LATE short by 5, no bypass ----
    b, pr, po = clean_d2_block()
    po["cf"]["RESP_HOLD_LATE"] = N - 5
    write_case(os.path.join(sc, "countermismatch"), b, pr, po)

    # ---- token escape on the wire ----
    b, pr, po = clean_d2_block()
    b["token_escapes_on_wire"] = 2
    write_case(os.path.join(sc, "tokenescape"), b, pr, po)

    # ---- TM queue drop ----
    b, pr, po = clean_d2_block()
    po["queues"]["qid5"]["drop_count_packets"] = 3
    write_case(os.path.join(sc, "queuedrop"), b, pr, po)

    # ---- malformed / empty ----
    with open(os.path.join(sc, "malformed.json"), "w") as f:
        f.write("not json at all")
    open(os.path.join(sc, "empty.json"), "w").close()

    # ---- paired-byte pcaps ----
    craft_pcaps(os.path.join(out, "pairs"))

    # ---- DRY_RUN fixtures for run_campaign.sh (clean 3-block run) ----
    dry = os.path.join(out, "dry")
    os.makedirs(dry, exist_ok=True)
    spec = []
    for lbl, mode, holdlate, holdearly in (("T_OFF", "OFF", 0, 0), ("T_D2", "D2", N, 0), ("T_D4", "D4", 17, 43)):
        b, pr, po = clean_d2_block()
        b["label"] = lbl; b["mode"] = mode
        for r in b["rows"]:
            pass
        po = zero_dump()
        if mode == "OFF":
            po["cf"]["RESP_BYPASS"] = N          # OFF passes RESPONSEs through (not a must-hold mode)
            po["cf"]["ARM_FRESH"] = 0
        else:
            po["cf"]["ARM_FRESH"] = N
            po["cf"]["RESP_HOLD_LATE"] = holdlate
            po["cf"]["RESP_HOLD_EARLY"] = holdearly
            po["cf"]["RESP_BYPASS"] = N - holdlate - holdearly
            po["cf"]["PKTGEN_ADMIT"] = N
            po["cd"]["RELEASE_DEADLINE"] = N
            po["cd"]["ACK_RELEASE"] = N
        json.dump(b, open(os.path.join(dry, "block_%s.json" % lbl), "w"))
        json.dump(pr, open(os.path.join(dry, "ev_pre_%s.json" % lbl), "w"))
        json.dump(po, open(os.path.join(dry, "ev_post_%s.json" % lbl), "w"))
        stub_pcap(os.path.join(dry, "blk_%s.pcap" % lbl))
        spec.append("%s %s 4 10 %d 0.4 0 - normal" % (lbl, mode, N))
    with open(os.path.join(dry, "spec.txt"), "w") as f:
        f.write("\n".join(spec) + "\n")

    # ---- manifest tamper dir ----
    man = os.path.join(out, "manifest")
    os.makedirs(man, exist_ok=True)
    with open(os.path.join(man, "a.txt"), "w") as f:
        f.write("original evidence\n")
    with open(os.path.join(man, "b.json"), "w") as f:
        f.write('{"k": 1}\n')

    print("fixtures written to", out)


if __name__ == "__main__":
    main()
