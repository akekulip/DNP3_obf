#!/usr/bin/env python3
"""build_replay_frames.py — turn the Gate 13.1 replay spec into wire frames for Gate 13.3+.

Takes `replay_spec_sel751.json` (real DNP3 payloads lifted from the capture) and re-frames each
transaction onto lab Ethernet/IPv4/TCP addressing, preserving the DNP3 application bytes EXACTLY —
byte preservation is the invariant under test, so the payload is copied, never rebuilt.

TOPOLOGY CONSEQUENCE (load-bearing, and a change from Parts 9-12).
The silicon classifier derives direction from the INGRESS PORT: master = dp9 = direction 0,
outstation = dp11 = direction 1. Parts 9, 11 and 12 injected every synthetic role from Hulk alone,
because a synthetic role byte carried its own identity. Real DNP3 cannot do that: a READ arriving on
dp11 would be classified as coming from the outstation, which is wrong. Therefore Gate 13.3 onward
needs TWO-SIDED injection:

    READ  (master -> outstation, dir 0)  must be injected from VISION  -> lands on dp9
    pure ACK + RESPONSE (dir 1)          must be injected from HULK    -> lands on dp11

This script emits both sides, tagged with the host that must send each frame.

TCP fields are synthesized to be self-consistent per transaction so the classifier's
`expected_ack = req.seq + req.payload_len` rule has something real to match: the pure ACK's
acknowledgement number is computed from the READ actually emitted here, not copied from the capture
(capture sequence numbers belong to a different connection).

Offline. Builds bytes in memory, writes a JSON of hex frames, and injects NOTHING.
Python 3.8+, stdlib only.
"""
import argparse
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))

# lab addressing (Parts 9-12 conventions; neutral src MAC avoids i40e source-pruning dropping
# reflected frames, and the destination is the real NIC MAC of the receiving host)
MAC_NEUTRAL = "02:00:00:00:00:0a"
MAC_VISION = "3c:fd:fe:cc:5d:c0"
IP_MASTER = "10.0.1.10"
IP_OUTSTATION = "10.0.2.10"
PORT_DNP3 = 20000
PORT_MASTER = 40000


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def cksum16(b):
    if len(b) % 2:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_ip_frame(src_ip, dst_ip, sport, dport, seq, ack, flags, payload,
                 dst_mac, src_mac=MAC_NEUTRAL):
    """One Ethernet/IPv4/TCP frame with correct IP and TCP checksums."""
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    pseudo = ip4(src_ip) + ip4(dst_ip) + struct.pack(">BBH", 0, 6, len(tcp) + len(payload))
    csum = cksum16(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack(">H", csum) + tcp[18:]

    total = 20 + len(tcp) + len(payload)
    iph = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) + ip4(src_ip) + ip4(dst_ip)
    iph = iph[:10] + struct.pack(">H", cksum16(iph)) + iph[12:]

    frame = mac(dst_mac) + mac(src_mac) + b"\x08\x00" + iph + tcp + payload
    if len(frame) < 60:                      # pad to the Ethernet minimum
        frame += b"\x00" * (60 - len(frame))
    return frame


def parse_back(frame):
    """Round-trip check: recover direction-relevant fields and the DNP3 payload."""
    ihl = (frame[14] & 0x0F) * 4
    tcp = 14 + ihl
    doff = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    total_len = struct.unpack(">H", frame[16:18])[0]
    payload_len = total_len - ihl - doff          # from headers, as the P4 parser must do it
    return {
        "sport": struct.unpack(">H", frame[tcp:tcp + 2])[0],
        "dport": struct.unpack(">H", frame[tcp + 2:tcp + 4])[0],
        "seq": struct.unpack(">I", frame[tcp + 4:tcp + 8])[0],
        "ack": struct.unpack(">I", frame[tcp + 8:tcp + 12])[0],
        "flags": frame[tcp + 13],
        "payload_len": payload_len,
        "payload": frame[14 + ihl + doff:14 + ihl + doff + payload_len],
    }


def build(spec, base_seq=0x1000):
    out = []
    seq_m, seq_o = base_seq, base_seq + 0x500000
    for t in spec["transactions"]:
        req = bytes.fromhex(t["req"]["payload_hex"])
        resps = [bytes.fromhex(h) for h in t["resp"]["payload_hex"]]

        # READ: master -> outstation, must ingress dp9, so VISION sends it
        out.append({"host": "vision", "role": "READ", "txn": t["txn"],
                    "frame": tcp_ip_frame(IP_MASTER, IP_OUTSTATION, PORT_MASTER, PORT_DNP3,
                                          seq_m, seq_o, 0x18, req, MAC_VISION)})
        expected_ack = (seq_m + len(req)) & 0xFFFFFFFF

        # pure ACK: outstation -> master, zero payload, ACK only. HULK sends it (dp11).
        out.append({"host": "hulk", "role": "PURE_ACK", "txn": t["txn"],
                    "expected_ack": expected_ack,
                    "frame": tcp_ip_frame(IP_OUTSTATION, IP_MASTER, PORT_DNP3, PORT_MASTER,
                                          seq_o, expected_ack, 0x10, b"", MAC_VISION)})

        # RESPONSE(s): outstation -> master, real DNP3 bytes. HULK sends them (dp11).
        for r in resps:
            out.append({"host": "hulk", "role": "RESPONSE", "txn": t["txn"],
                        "frame": tcp_ip_frame(IP_OUTSTATION, IP_MASTER, PORT_DNP3, PORT_MASTER,
                                              seq_o, expected_ack, 0x18, r, MAC_VISION)})
            seq_o = (seq_o + len(r)) & 0xFFFFFFFF
        seq_m = expected_ack
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default=os.path.join(HERE, "replay_spec_sel751.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "replay_frames_sel751.json"))
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    spec = json.load(open(a.spec))
    frames = build(spec)

    if a.selftest:
        ok = fail = 0
        by_txn = {}
        for f in frames:
            by_txn.setdefault(f["txn"], []).append(f)
        for txn, fl in by_txn.items():
            t = next(x for x in spec["transactions"] if x["txn"] == txn)
            read = next(f for f in fl if f["role"] == "READ")
            ack = next(f for f in fl if f["role"] == "PURE_ACK")
            resps = [f for f in fl if f["role"] == "RESPONSE"]
            pr, pa = parse_back(read["frame"]), parse_back(ack["frame"])
            checks = [
                ("read payload byte-identical", pr["payload"] == bytes.fromhex(t["req"]["payload_hex"])),
                ("read dnp3 magic", pr["payload"][:2] == b"\x05\x64"),
                ("read is master->outstation", pr["dport"] == PORT_DNP3),
                ("pure ack has zero payload", pa["payload_len"] == 0),
                ("pure ack is ACK-only (no SYN/FIN/RST)", pa["flags"] == 0x10),
                ("expected_ack == read.seq + len", pa["ack"] == (pr["seq"] + pr["payload_len"]) & 0xFFFFFFFF),
                ("read injected from vision (dp9/dir0)", read["host"] == "vision"),
                ("ack injected from hulk (dp11/dir1)", ack["host"] == "hulk"),
            ]
            for i, r in enumerate(resps):
                p = parse_back(r["frame"])
                checks.append(("resp %d byte-identical" % i,
                               p["payload"] == bytes.fromhex(t["resp"]["payload_hex"][i])))
                checks.append(("resp %d dnp3 magic" % i, p["payload"][:2] == b"\x05\x64"))
                checks.append(("resp %d from hulk" % i, r["host"] == "hulk"))
            for name, good in checks:
                if good:
                    ok += 1
                else:
                    fail += 1
                    print("  FAIL txn=%s %s" % (txn, name))
        print("selftest: %d checks passed, %d failed, over %d transactions" % (ok, fail, len(by_txn)))
        if fail:
            raise SystemExit(1)

    json.dump({"source_spec": os.path.basename(a.spec),
               "addressing": {"master": IP_MASTER, "outstation": IP_OUTSTATION,
                              "dnp3_port": PORT_DNP3, "src_mac": MAC_NEUTRAL,
                              "dst_mac": MAC_VISION},
               "injection": {"vision_dp9_dir0": "READ", "hulk_dp11_dir1": "PURE_ACK + RESPONSE"},
               "frame_count": len(frames),
               "frames": [{"host": f["host"], "role": f["role"], "txn": f["txn"],
                           "hex": f["frame"].hex()} for f in frames]},
              open(a.out, "w"), indent=1)
    n = {}
    for f in frames:
        n[(f["host"], f["role"])] = n.get((f["host"], f["role"]), 0) + 1
    print("built %d frames: %s" % (len(frames), dict(("%s/%s" % k, v) for k, v in sorted(n.items()))))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
