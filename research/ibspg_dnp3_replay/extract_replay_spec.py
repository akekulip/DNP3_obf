#!/usr/bin/env python3
"""extract_replay_spec.py — build a replay spec of REAL DNP3 frames for Part 13 gates 13.3+.

Gate 13.1 established which transactions are clean; this pulls their actual payload BYTES out of
the capture (the audit json records indices and timings, not bytes) and emits a replay spec the
injection harness can consume directly.

Default selection: the SEL751 / 10.0.0.1 stream — the only separate-ACK device in the corpus
(CLRT median 12.898 ms), hence the right corpus for the first HOLD_ACK / HOLD_RESPONSE gates.

Emits, per transaction: the READ request payload, the pure-ACK fact (a pure ACK carries no payload —
it is reproduced by the harness as a zero-payload segment, not replayed as bytes), and the RESPONSE
payload(s), each as hex, with the DNP3 fields already decoded by the audit so the harness never has
to re-parse.

Offline. Reads the pcap read-only. Injects nothing. Python 3.8+, stdlib only.

Usage: extract_replay_spec.py [--capture SEL751] [--outstation 10.0.0.1] [--count 30]
                              [--out replay_spec_sel751.json]
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_DEFAULT = os.path.abspath(os.path.join(HERE, "..", "..", "Traffic Trace"))


def read_pcap_payloads(path):
    """Return a list of per-packet dicts in capture order: ts, ip src/dst, tcp ports, flags, payload."""
    out = []
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return out
        magic = gh[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, tu, incl, _orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            rec = {"ts": ts + tu / 1e6, "payload": b""}
            # Ethernet II -> IPv4 -> TCP only; anything else is recorded with no payload
            if len(data) >= 34 and struct.unpack(">H", data[12:14])[0] == 0x0800:
                ihl = (data[14] & 0x0F) * 4
                if data[23] == 6 and len(data) >= 14 + ihl + 20:
                    tcp = 14 + ihl
                    doff = ((data[tcp + 12] >> 4) & 0x0F) * 4
                    rec["src"] = ".".join(str(b) for b in data[26:30])
                    rec["dst"] = ".".join(str(b) for b in data[30:34])
                    rec["sport"] = struct.unpack(">H", data[tcp:tcp + 2])[0]
                    rec["dport"] = struct.unpack(">H", data[tcp + 2:tcp + 4])[0]
                    rec["flags"] = data[tcp + 13]
                    rec["payload"] = data[14 + ihl + doff:]
            out.append(rec)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default=os.path.join(HERE, "corpus_audit.json"))
    ap.add_argument("--corpus", default=CORPUS_DEFAULT)
    ap.add_argument("--capture", default="SEL751")
    ap.add_argument("--outstation", default="10.0.0.1")
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--out", default=os.path.join(HERE, "replay_spec_sel751.json"))
    a = ap.parse_args()

    audit = json.load(open(a.audit))
    cap = next((c for c in audit["captures"] if c["capture"] == a.capture), None)
    if cap is None:
        sys.exit("capture %s not found in audit" % a.capture)
    stream = next((s for s in cap["streams"] if s["outstation"].startswith(a.outstation)), None)
    if stream is None:
        sys.exit("outstation %s not found in %s" % (a.outstation, a.capture))

    pkts = read_pcap_payloads(cap["path"] if os.path.exists(cap["path"])
                              else os.path.join(a.corpus, a.capture + ".pcap"))

    txns, skipped = [], []
    for t in stream.get("transactions", []):
        if len(txns) >= a.count:
            break
        # only clean, unambiguous, separate-ACK transactions are useful for the first gates
        if t.get("ack_mode") != "separate" or t.get("flags"):
            skipped.append({"txn": t.get("txn"), "ack_mode": t.get("ack_mode"),
                            "flags": t.get("flags")})
            continue
        # NOTE: the audit numbers packets 1-based (Wireshark frame numbers); this reader is
        # 0-based. Getting this wrong silently yields empty payloads, so the DNP3 start magic is
        # asserted below as a self-check rather than trusting the offset.
        req = pkts[t["req_pkt"] - 1]["payload"] if t.get("req_pkt") else b""
        resps = [pkts[i - 1]["payload"] for i in (t.get("resp_pkts") or [])]
        if not req or not resps or not all(resps):
            skipped.append({"txn": t.get("txn"), "why": "empty payload at recorded index"})
            continue
        if req[:2] != b"\x05\x64" or any(r[:2] != b"\x05\x64" for r in resps):
            skipped.append({"txn": t.get("txn"),
                            "why": "DNP3 start magic 0x0564 absent — packet indexing is wrong"})
            continue
        txns.append({
            "txn": t["txn"],
            "req": {"role": "ARM_READ", "fc": t.get("req_fc"), "fc_name": t.get("req_fc_name"),
                    "app_seq": t.get("req_app_seq"), "link_src": t.get("req_link_src"),
                    "link_dst": t.get("req_link_dst"), "seq": t.get("req_seq"),
                    "payload_len": len(req), "payload_hex": req.hex()},
            # a pure ACK has NO payload by definition; the harness emits a zero-payload segment
            "ack": {"role": "ACK", "present": t.get("ack_pkt") is not None,
                    "expected_ack": t.get("expected_ack"), "payload_len": 0},
            "resp": {"role": "RESP", "fc": t.get("resp_fc"), "app_seq": t.get("resp_app_seq"),
                     "frames": len(resps), "payload_lens": [len(r) for r in resps],
                     "payload_hex": [r.hex() for r in resps]},
            "observed_ms": {"req_to_ack": t.get("req_to_ack_ms"),
                            "ack_to_resp_clrt": t.get("ack_to_resp_ms"),
                            "req_to_resp": t.get("req_to_resp_ms")},
        })

    spec = {
        "gate": "13.3+ replay input",
        "source_capture": a.capture, "source_path": cap.get("path"),
        "stream": {"master": stream["master"], "outstation": stream["outstation"],
                   "ack_mode_verdict": stream.get("ack_mode_verdict")},
        "selection": "clean separate-ACK transactions only, in capture order",
        "requested": a.count, "selected": len(txns), "skipped": len(skipped),
        "skipped_detail": skipped[:20],
        "note": ("Payloads are the REAL DNP3 application bytes from the capture. The harness must "
                 "re-frame them onto lab MAC/IP addressing; the DNP3 payload must be replayed "
                 "byte-for-byte, since byte preservation is the invariant under test."),
        "transactions": txns,
    }
    json.dump(spec, open(a.out, "w"), indent=1)
    print("capture=%s stream=%s -> selected %d/%d transactions (skipped %d)"
          % (a.capture, stream["outstation"], len(txns), a.count, len(skipped)))
    if txns:
        t0 = txns[0]
        print("  first txn: READ %dB (fc=%s app_seq=%s) -> pure ACK -> RESPONSE %s (fc=%s)"
              % (t0["req"]["payload_len"], t0["req"]["fc"], t0["req"]["app_seq"],
                 t0["resp"]["payload_lens"], t0["resp"]["fc"]))
        print("  observed CLRT (ack->resp): %.3f ms" % (t0["observed_ms"]["ack_to_resp_clrt"] or 0))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
