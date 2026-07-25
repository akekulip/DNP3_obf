#!/usr/bin/env python3
"""build_relay_frames.py — two-sided Tofino injection frames from a LIVE SEL-751 capture.

Unlike build_replay_frames.py (which synthesized a data_offset=5 envelope around corpus payloads),
this preserves the physical relay's REAL framing byte-for-byte — including data_offset=8 / TCP
timestamps and the real response bytes — and only rewrites the Ethernet MACs so the frames traverse
the Tofino path. IP/TCP headers, checksums and DNP3 payloads are untouched, so what the switch sees
is exactly what the relay emitted.

  READ (master->relay, dst tcp 20000)         -> injected from VISION (dp9, dir 0)
  pure ACK + RESPONSE (relay->master, src 20000) -> injected from HULK (dp11, dir 1)

Offline. Reads the pcap read-only, writes hex frames, injects nothing.
"""
import argparse
import json
import os
import struct

MAC_NEUTRAL = bytes.fromhex("02000000000a")   # neutral src: avoids i40e source-pruning
MAC_VISION = bytes.fromhex("3cfdfecc5dc0")     # real dst NIC MAC (Vision)
DNP3_PORT = 20000


def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        end = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, tu, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield ts + tu / 1e6, data


def classify(fr):
    if len(fr) < 34 or struct.unpack(">H", fr[12:14])[0] != 0x0800:
        return None
    ihl = (fr[14] & 0x0F) * 4
    if fr[23] != 6:
        return None
    tcp = 14 + ihl
    doff = ((fr[tcp + 12] >> 4) & 0x0F) * 4
    total_len = struct.unpack(">H", fr[16:18])[0]
    paylen = total_len - ihl - doff
    sport = struct.unpack(">H", fr[tcp:tcp + 2])[0]
    dport = struct.unpack(">H", fr[tcp + 2:tcp + 4])[0]
    flags = fr[tcp + 13]
    payload = fr[14 + ihl + doff:14 + ihl + doff + max(0, paylen)]
    from_relay = (sport == DNP3_PORT)
    role = "BYPASS"
    if paylen == 0 and (flags & 0x10) and not (flags & 0x07):
        role = "PURE_ACK" if from_relay else "ACK_MASTER"
    elif payload[:2] == b"\x05\x64" and paylen >= 13:
        func = payload[12]
        if func == 1 and not from_relay:
            role = "READ"
        elif func == 129 and from_relay:
            role = "RESPONSE"
    return {"role": role, "doff": doff, "paylen": paylen, "wire": len(fr), "from_relay": from_relay}


def reframe(fr):
    """Rewrite only the Ethernet MACs; IP/TCP/DNP3 (incl. checksums, data_offset, options) untouched."""
    return (MAC_VISION + MAC_NEUTRAL + fr[12:]).hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   "relay_frames_live.json"))
    ap.add_argument("--count", type=int, default=30)
    a = ap.parse_args()

    frames = [(ts, fr, classify(fr)) for ts, fr in read_pcap(a.pcap)]
    frames = [(ts, fr, c) for ts, fr, c in frames if c]

    # walk transactions in wire order: READ opens one, its ACK then RESPONSE close it
    txns, cur = [], None
    for ts, fr, c in frames:
        if c["role"] == "READ":
            if cur:
                txns.append(cur)
            cur = {"read": None, "ack": None, "resp": None}
            cur["read"] = fr
        elif cur and c["role"] == "PURE_ACK" and cur["ack"] is None:
            cur["ack"] = fr
        elif cur and c["role"] == "RESPONSE" and cur["resp"] is None:
            cur["resp"] = fr
    if cur:
        txns.append(cur)
    txns = [t for t in txns if t["read"] and t["resp"]][:a.count]

    out = []
    for i, t in enumerate(txns):
        out.append({"host": "vision", "role": "READ", "txn": i, "hex": reframe(t["read"])})
        if t["ack"]:
            out.append({"host": "hulk", "role": "PURE_ACK", "txn": i, "hex": reframe(t["ack"])})
        out.append({"host": "hulk", "role": "RESPONSE", "txn": i, "hex": reframe(t["resp"])})

    # report the framing so the run is self-documenting
    doffs = sorted({classify(bytes.fromhex(f["hex"]))["doff"] for f in out})
    json.dump({"source_pcap": os.path.abspath(a.pcap), "txns": len(txns), "frames": len(out),
               "data_offsets_present": doffs, "note": "REAL relay framing preserved; only MACs rewritten",
               "frames_list": out}, open(a.out, "w"), indent=1)
    n = {}
    for f in out:
        n[(f["host"], f["role"])] = n.get((f["host"], f["role"]), 0) + 1
    print("built %d frames from %d live relay transactions: %s"
          % (len(out), len(txns), dict(("%s/%s" % k, v) for k, v in sorted(n.items()))))
    print("data_offset present in the reframed set:", doffs, "(8 = the real relay framing)")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
