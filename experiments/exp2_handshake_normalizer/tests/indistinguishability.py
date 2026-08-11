#!/usr/bin/env python3
"""Device-indistinguishability analysis for the handshake normalizer.

The obfuscation goal: after normalization, the SEL-751, ION7550 and AB1400 must look IDENTICAL on
the wire — a passive observer must not be able to tell them apart. The device fingerprint lives in
the OUTSTATION's SYN-ACK option layout (Experiment 1). This script normalizes each device's real
SYN-ACK and SYN layouts and compares the outputs field-by-field, ignoring the 5-tuple / seq / ack
(which legitimately vary per connection). It reports exactly what is collapsed (obfuscated) and
what RESIDUAL still distinguishes the devices.

Run:  ~/.venvs/research/bin/python indistinguishability.py
"""
import os
import sys
from scapy.all import Ether, IP, TCP

sys.path.insert(0, os.path.dirname(__file__))
import oracle  # transform()

MSS = lambda v: ("MSS", v)
TS = ("Timestamp", (0, 0))
WS = ("WScale", 7)
SACK = ("SAckOK", b"")
NOP = ("NOP", None)
EOL = ("EOL", None)

# Real device layouts from Experiment 1 (outstation SYN-ACK is the fingerprint).
DEVICES = {
    "SEL751":  {"synack": [MSS(1460), NOP, WS, NOP, NOP, SACK, NOP, NOP, TS], "ttl": 64,  "win": 16384},
    "ION7550": {"synack": [MSS(1460)],                                        "ttl": 64,  "win": 4096},
    "AB1400":  {"synack": [MSS(1478), NOP, NOP, NOP, EOL],                    "ttl": 128, "win": 2048},
}


def synack(dev):
    d = DEVICES[dev]
    return (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=d["ttl"], flags="DF") /
            TCP(sport=20000, dport=44000, flags="SA", seq=5, ack=1001, window=d["win"],
                options=d["synack"]))


def sig(pkt):
    """Observable device signature = the fields an observer uses, minus the 5-tuple/seq/ack."""
    p = Ether(bytes(pkt))
    t, i = p[TCP], p[IP]
    opt_bytes = bytes(p[TCP])[20:t.dataofs * 4]      # raw option region
    return {
        "data_offset": t.dataofs,
        "opt_bytes": opt_bytes.hex(),
        "ttl": i.ttl,
        "ip_id": i.id,
        "window": t.window,
        "mss": dict(t.options).get("MSS"),
    }


def analyze(direction, mk):
    print(f"\n=== {direction} — normalized device signatures ===")
    outs = {}
    for dev in DEVICES:
        out, outcome, _l3 = oracle.transform(mk(dev))
        outs[dev] = (sig(out), outcome)
    fields = ["data_offset", "opt_bytes", "ttl", "ip_id", "window", "mss"]
    print(f"{'device':9s} {'outcome':26s} " + " ".join(f"{f}" for f in ["do", "ttl", "ipid", "win", "mss"]))
    for dev, (s, oc) in outs.items():
        print(f"{dev:9s} {oc:26s} do={s['data_offset']} ttl={s['ttl']} ipid={s['ip_id']} "
              f"win={s['window']} mss={s['mss']}  opt={s['opt_bytes'] or '(none)'}")
    # which fields are identical across all devices?
    ident, resid = [], []
    for f in fields:
        vals = {outs[d][0][f] for d in DEVICES}
        (ident if len(vals) == 1 else resid).append(f)
    print(f"  COLLAPSED (identical across devices): {ident}")
    print(f"  RESIDUAL  (still distinguishes):      {resid}")
    indistinguishable = not resid
    print(f"  -> devices indistinguishable on {direction}: {'YES' if indistinguishable else 'NO'}")
    return indistinguishable, resid


if __name__ == "__main__":
    print("Device-indistinguishability of the handshake normalizer (outstation SYN-ACK is the "
          "Experiment-1 fingerprint).")
    ok_sa, resid_sa = analyze("SYN-ACK", synack)
    print("\n" + "=" * 78)
    if ok_sa:
        print("RESULT: outstations are INDISTINGUISHABLE after normalization. Obfuscation achieved.")
    else:
        print("RESULT: NOT yet indistinguishable. The current SAFE normalizer only canonicalizes an "
              "ALREADY-minimal SYN-ACK; a full-option SYN-ACK (SEL751 do=11, AB1400 do=7) fails open,"
              " so its fingerprint SURVIVES. Residual fields: " + str(resid_sa) + ".")
        print("Two ways to close it: (a) rely on the endpoint fallback (strip the master SYN options "
              "so a compliant outstation emits a minimal SYN-ACK) — Experiment 3, endpoint-dependent; "
              "or (b) AGGRESSIVELY canonicalize the SYN-ACK too (strip TS/WScale/SACK on BOTH "
              "directions — consistent, so no window-scale desync — plus clamp the window to a public "
              "constant to remove the window residual).")
    sys.exit(0)
