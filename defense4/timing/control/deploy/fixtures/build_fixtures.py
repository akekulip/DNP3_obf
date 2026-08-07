#!/usr/bin/env python3
"""Deterministically synthesize fail-closed test fixtures with REAL pcaps (no text stubs).

  $RESEARCH_PYTHON build_fixtures.py <out_dir>

Everything is built from fixed constants and fixed packet timestamps, so the fixtures are reproducible
byte-for-byte. PCAPs are genuine libpcap captures crafted with scapy, so pcap-magic and structural
validation are actually exercised. Covers every failure named in the Phase 1 independent audit.
"""
import json
import os
import sys

from scapy.all import Ether, IP, TCP, wrpcap, Dot1Q

RELAY = "192.168.10.7"
MASTER = "192.168.10.1"
MPORT = 51000
PORT = 20000
MAC_R = "00:11:22:33:44:77"
MAC_M = "00:aa:bb:cc:dd:01"
N = 60
BASE_T = 1000.0

REQUIRED_CF = ["ARM_FRESH", "RESP_HOLD_EARLY", "RESP_HOLD_LATE", "RESP_BYPASS", "ACK_REJECT", "PKTGEN_ADMIT"]
REQUIRED_CD = ["RELEASE_DEADLINE", "RELEASE_FAILOPEN", "ACK_RELEASE", "ACK_REL_RETIRE", "BLOCK_TERM_TMO", "BLOCK_TERM_STALE"]


def dnp3(appctrl, tail):
    return bytes([0x05, 0x64, 0x0b, 0x44, 0x00, 0x00, 0x01, 0x00, 0x2a, 0xec, 0xc0, appctrl]) + tail


def zero_dump():
    return {"cf": {k: 0 for k in REQUIRED_CF}, "cd": {k: 0 for k in REQUIRED_CD},
            "regs": {"reg_tag": 0},
            "queues": {q: {"drop_count_packets": 0} for q in ("qid7", "qid6", "qid5", "qid4")},
            "port_tm_drops": {"ig_port": 0, "eg_port": 0}}


def clean_block(mode="D2", label="T_D2", n=N):
    rows = []
    for i in range(n):
        t_read = 100.0 + i * 0.4
        t_ack = t_read + 0.0018
        t_resp = t_ack + 0.0100
        rows.append({"poll": i, "app_seq_sent": "0x%02X" % (0xC0 + (i % 16)),
                     "t_read": t_read, "read_seq": 1000 + i, "t_ack": t_ack, "t_resp": t_resp,
                     "resp_len": 122, "resp_segments": 1, "dup_ack": 0, "dup_resp": 0,
                     "retransmit": 0, "fin": (i == n - 1), "rst": False,
                     "read_to_ack_ms": (t_ack - t_read) * 1e3, "read_to_resp_ms": (t_resp - t_read) * 1e3,
                     "clrt_ms": (t_resp - t_ack) * 1e3, "ack_before_resp": True, "order_inconclusive": False})
    block = {"label": label, "mode": mode, "d_a_ms": "4", "d_r_ms": "10", "N": n, "gap_s": 0.4,
             "attempted": n, "sent": n, "responded": n, "errors": [], "capture_ok": True,
             "one_connection": True, "local_port": MPORT, "token_escapes_on_wire": 0,
             "rows": rows, "pcap": "blk_%s.pcap" % label, "n_rows": n}
    pre = zero_dump()
    post = zero_dump()
    post["cf"]["ARM_FRESH"] = n
    post["cf"]["RESP_HOLD_LATE"] = n
    post["cf"]["PKTGEN_ADMIT"] = n
    post["cd"]["RELEASE_DEADLINE"] = n
    post["cd"]["ACK_RELEASE"] = n
    return block, pre, post


def write_case(d, block, pre, post):
    os.makedirs(d, exist_ok=True)
    json.dump(block, open(os.path.join(d, "block.json"), "w"))
    json.dump(pre, open(os.path.join(d, "ev_pre.json"), "w"))
    json.dump(post, open(os.path.join(d, "ev_post.json"), "w"))


def relay_master_frames(app_seqs, vlan=None, mac_src=MAC_R, mac_dst=MAC_M, master=MASTER, chksum=None):
    """One pure ACK + one RESPONSE per app_seq, relay->master, fixed timestamps. Returns (pkts, intended)."""
    pkts, intended = [], []
    seq = 1000
    t = BASE_T
    for a in app_seqs:
        payload = dnp3(a, bytes([a, a ^ 0x5A, 0x11, 0x22, (a * 3) & 0xFF, (a * 7) & 0xFF]))
        l2 = Ether(src=mac_src, dst=mac_dst)
        if vlan is not None:
            l2 = l2 / Dot1Q(vlan=vlan)
        ack = l2 / IP(src=RELAY, dst=master, id=seq % 65536) / TCP(sport=PORT, dport=MPORT, seq=seq, ack=500, flags="A")
        rsp = l2 / IP(src=RELAY, dst=master, id=(seq + 1) % 65536) / TCP(sport=PORT, dport=MPORT, seq=seq, ack=500, flags="PA") / payload
        for p in (ack, rsp):
            p.time = t
            t += 0.001
            if chksum is not None:
                p[TCP].chksum = chksum
            pkts.append(Ether(bytes(p)))          # serialize so checksums/lengths are concrete
        intended.append({"app_seq": "0x%02X" % a, "hex": payload.hex()})
        seq += len(payload) + 2
    return pkts, intended


def w(path, pkts):
    wrpcap(path, pkts)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    # one real pcap used wherever the scorer needs a valid --pcap
    realpk, _ = relay_master_frames([0xC0, 0xC1])
    w(os.path.join(out, "real.pcap"), realpk)

    # =================== scorer cases ===================
    sc = os.path.join(out, "scorer")
    b, pr, po = clean_block(); write_case(os.path.join(sc, "clean"), b, pr, po)

    def mut(name, bf=None, prf=None, pof=None, base=("D2", "T_D2")):
        b, pr, po = clean_block(base[0], base[1])
        if bf:
            bf(b)
        if prf:
            prf(pr)
        if pof:
            pof(po)
        write_case(os.path.join(sc, name), b, pr, po)

    mut("dupack", bf=lambda b: b["rows"][3].__setitem__("dup_ack", 1))
    mut("dupresp", bf=lambda b: b["rows"][3].__setitem__("dup_resp", 1))
    mut("retransmit", bf=lambda b: b["rows"][3].__setitem__("retransmit", 1))
    mut("ordering", bf=lambda b: (b["rows"][5].__setitem__("clrt_ms", -0.5), b["rows"][5].__setitem__("ack_before_resp", False)))
    mut("inconclusive", bf=lambda b: b["rows"][7].__setitem__("order_inconclusive", True))
    mut("multiseg", bf=lambda b: b["rows"][9].__setitem__("resp_segments", 2))
    mut("stale", pof=lambda p: p["regs"].__setitem__("reg_tag", 0xC5))
    mut("noregtag", pof=lambda p: p["regs"].pop("reg_tag", None))
    mut("noqueue", pof=lambda p: p.pop("queues", None))
    mut("noport", pof=lambda p: p.pop("port_tm_drops", None))
    mut("nocounter", pof=lambda p: p["cf"].pop("ARM_FRESH", None))
    mut("negdelta", prf=lambda p: p["cf"].__setitem__("ARM_FRESH", 5))  # pre>post -> negative delta
    mut("bypass", pof=lambda p: p["cf"].__setitem__("RESP_BYPASS", 3))
    mut("countermismatch", pof=lambda p: p["cf"].__setitem__("RESP_HOLD_LATE", N - 5))
    mut("tokenescape", bf=lambda b: b.__setitem__("token_escapes_on_wire", 2))
    mut("queuedrop", pof=lambda p: p["queues"]["qid5"].__setitem__("drop_count_packets", 3))
    mut("drivererr", bf=lambda b: b.__setitem__("errors", ["poll 3: boom"]))
    mut("respshort", bf=lambda b: b.__setitem__("responded", N - 1))
    mut("badmode_block", bf=lambda b: b.__setitem__("mode", "FOO"))  # block mode unknown, scored as D2 -> mismatch

    # declared-negative EXERCISED (should PASS) vs NOT exercised (clean block under a negative scenario -> FAIL)
    # missing_ack exercised: 4 rows lose their ACK
    b, pr, po = clean_block()
    for i in (10, 20, 30, 40):
        b["rows"][i]["t_ack"] = None
        b["rows"][i]["clrt_ms"] = None
        b["rows"][i]["ack_before_resp"] = None
        b["rows"][i]["order_inconclusive"] = None
    b["errors"] = ["poll 10: no ack"]
    write_case(os.path.join(sc, "missingack_ok"), b, pr, po)
    # missing_resp exercised: 3 rows lose their RESPONSE
    b, pr, po = clean_block()
    for i in (5, 15, 25):
        b["rows"][i]["t_resp"] = None
        b["rows"][i]["clrt_ms"] = None
    b["responded"] = N - 3
    b["errors"] = ["poll 5: no resp"]
    write_case(os.path.join(sc, "missingresp_ok"), b, pr, po)
    # late_response exercised: 6 rows flagged late
    b, pr, po = clean_block()
    for i in range(6):
        b["rows"][i]["late"] = True
    write_case(os.path.join(sc, "late_ok"), b, pr, po)
    # fail_open exercised
    b, pr, po = clean_block("FAIL_OPEN", "T_FO")
    po["cd"]["RELEASE_FAILOPEN"] = 4
    write_case(os.path.join(sc, "failopen_ok"), b, pr, po)

    # malformed / empty for HardIO
    open(os.path.join(sc, "malformed.json"), "w").write("not json at all")
    open(os.path.join(sc, "empty.json"), "w").close()
    # a nonempty TEXT file masquerading as a pcap
    open(os.path.join(sc, "text.pcap"), "w").write("this is not a pcap, just text, but nonempty\n")

    # =================== pair_bytes cases ===================
    pb = os.path.join(out, "pairs")
    os.makedirs(pb, exist_ok=True)
    ing, intended = relay_master_frames([0xC0, 0xC1, 0xC2])
    egr = [Ether(bytes(p)) for p in ing]  # byte-identical clean egress
    w(os.path.join(pb, "ingress.pcap"), ing)
    w(os.path.join(pb, "egress_clean.pcap"), egr)
    with open(os.path.join(pb, "intended.jsonl"), "w") as f:
        for r in intended:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(pb, "intended_wrong.jsonl"), "w") as f:
        for r in intended:
            bad = dict(r); bad["hex"] = ("00" + r["hex"][2:])  # flip first byte
            f.write(json.dumps(bad) + "\n")
    # one-byte mutation on the first RESPONSE (index 1)
    egr_1b = [Ether(bytes(p)) for p in ing]
    raw = bytearray(bytes(egr_1b[1])); raw[-3] ^= 0x01; egr_1b[1] = Ether(bytes(raw))
    w(os.path.join(pb, "egress_1byte.pcap"), egr_1b)
    # dropped ACK (index 0 removed)
    w(os.path.join(pb, "egress_dropack.pcap"), [Ether(bytes(p)) for p in ing[1:]])
    # dropped RESPONSE (index 1 removed)
    w(os.path.join(pb, "egress_dropresp.pcap"), [Ether(bytes(p)) for p in (ing[0],) + tuple(ing[2:])])
    # injected extra RESPONSE
    inj, _ = relay_master_frames([0xCF])
    w(os.path.join(pb, "egress_inject.pcap"), [Ether(bytes(p)) for p in ing] + [inj[1]])
    # MAC mutation (egress src MAC changed) -- P4 does NOT rewrite MAC
    macpk, _ = relay_master_frames([0xC0, 0xC1, 0xC2], mac_src="de:ad:be:ef:00:01")
    w(os.path.join(pb, "egress_macmut.pcap"), macpk)
    # nonzero checksum change on egress
    ckpk = [Ether(bytes(p)) for p in ing]
    r = ckpk[1].copy(); r[TCP].chksum = 0x1234; ckpk[1] = Ether(bytes(r))
    w(os.path.join(pb, "egress_cksum.pcap"), ckpk)
    # reordered (swap the two responses' order at egress)
    ing4, _ = relay_master_frames([0xC0, 0xC1])
    w(os.path.join(pb, "ingress2.pcap"), ing4)
    w(os.path.join(pb, "egress_reorder.pcap"), [ing4[0], ing4[3], ing4[2], ing4[1]])
    # wrong flow: relay -> a different host (zero relevant frames vs master 192.168.10.1)
    other, _ = relay_master_frames([0xC0, 0xC1], master="10.0.0.5")
    w(os.path.join(pb, "ingress_other.pcap"), other)
    w(os.path.join(pb, "egress_other.pcap"), [Ether(bytes(p)) for p in other])
    # ACK-only (zero protected/RESPONSE frames)
    ackonly = [Ether(src=MAC_R, dst=MAC_M) / IP(src=RELAY, dst=MASTER) / TCP(sport=PORT, dport=MPORT, seq=1, ack=1, flags="A")]
    ackonly[0].time = BASE_T
    w(os.path.join(pb, "ingress_ackonly.pcap"), [Ether(bytes(ackonly[0]))])
    w(os.path.join(pb, "egress_ackonly.pcap"), [Ether(bytes(ackonly[0]))])
    # malformed + truncated pcaps
    open(os.path.join(pb, "text.pcap"), "w").write("not a pcap\n")
    good = open(os.path.join(pb, "ingress.pcap"), "rb").read()
    open(os.path.join(pb, "truncated.pcap"), "wb").write(good[:18])  # < global header
    # VLAN-tagged clean pair
    vpk, _ = relay_master_frames([0xC0, 0xC1], vlan=100)
    w(os.path.join(pb, "ingress_vlan.pcap"), vpk)
    w(os.path.join(pb, "egress_vlan.pcap"), [Ether(bytes(p)) for p in vpk])

    # =================== DRY_RUN campaign fixtures (clean 3-block run) ===================
    dry = os.path.join(out, "dry")
    os.makedirs(dry, exist_ok=True)
    app = [0xC0, 0xC1, 0xC2]
    dpk, dintended = relay_master_frames(app)
    with open(os.path.join(dry, "intended.jsonl"), "w") as f:
        for r in dintended:
            f.write(json.dumps(r) + "\n")
    spec = []
    for lbl, mode, hl, he in (("T_OFF", "OFF", 0, 0), ("T_D2", "D2", N, 0), ("T_D4", "D4", 17, 43)):
        b, pr, po = clean_block(mode, lbl)
        po = zero_dump()
        if mode == "OFF":
            po["cf"]["RESP_BYPASS"] = N
        else:
            po["cf"]["ARM_FRESH"] = N
            po["cf"]["RESP_HOLD_LATE"] = hl
            po["cf"]["RESP_HOLD_EARLY"] = he
            po["cf"]["RESP_BYPASS"] = N - hl - he
            po["cf"]["PKTGEN_ADMIT"] = N
            po["cd"]["RELEASE_DEADLINE"] = N
            po["cd"]["ACK_RELEASE"] = N
        json.dump(b, open(os.path.join(dry, "block_%s.json" % lbl), "w"))
        json.dump(pr, open(os.path.join(dry, "ev_pre_%s.json" % lbl), "w"))
        json.dump(po, open(os.path.join(dry, "ev_post_%s.json" % lbl), "w"))
        w(os.path.join(dry, "blk_%s.pcap" % lbl), [Ether(bytes(p)) for p in dpk])          # master-facing
        w(os.path.join(dry, "blk_%s_relay.pcap" % lbl), [Ether(bytes(p)) for p in dpk])    # relay-facing (identical)
        spec.append("%s %s 4 10 %d 0.4 0 - normal -" % (lbl, mode, N))
    open(os.path.join(dry, "spec.txt"), "w").write("\n".join(spec) + "\n")

    # a variant DRY set whose D2 relay capture is byte-mutated (paired comparison must fail)
    drym = os.path.join(out, "dry_pairfail")
    os.makedirs(drym, exist_ok=True)
    for fn in os.listdir(dry):
        data = open(os.path.join(dry, fn), "rb").read()
        open(os.path.join(drym, fn), "wb").write(data)
    from scapy.all import rdpcap
    pk = list(rdpcap(os.path.join(drym, "blk_T_D2_relay.pcap")))
    raw = bytearray(bytes(pk[1])); raw[-3] ^= 0x02; pk[1] = Ether(bytes(raw))
    w(os.path.join(drym, "blk_T_D2_relay.pcap"), pk)

    # =================== manifest dir (mixed extensions) ===================
    man = os.path.join(out, "manifest")
    os.makedirs(man, exist_ok=True)
    open(os.path.join(man, "a.txt"), "w").write("original evidence\n")
    open(os.path.join(man, "b.json"), "w").write('{"k": 1}\n')
    open(os.path.join(man, "driver.err"), "w").write("stderr\n")
    open(os.path.join(man, "results.csv"), "w").write("a,b\n1,2\n")
    open(os.path.join(man, "environment.record"), "w").write("env\n")

    print("fixtures written to", out)


if __name__ == "__main__":
    main()
