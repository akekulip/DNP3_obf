#!/usr/bin/env python3
"""ACK-mode normalizer oracle (Experiment 3 / timing axis 2).

Distinguisher (Experiment-1 / taxonomy): a Case-A outstation (SEL-751, separate-ACK) emits TWO
packets in response to a master READ — a standalone pure-TCP ACK, then the DNP3 RESPONSE — while a
Case-B outstation (ION7550, combined-ACK) emits ONE packet (the response, which piggybacks the ACK).
An observer counts outstation packets and reads whether a standalone ACK appears.

Mechanism: SUPPRESS the outstation's standalone pure ACK (payload-less, ACK-only, not SYN/FIN/RST).
The DNP3 RESPONSE that follows within the CLRT (~1.4-1.9 ms) carries a cumulative ACK >= the dropped
one, so the master is still acknowledged well inside its RTO (~200 ms+). Result: the Case-A
outstation now emits ONE observable packet (the response), matching Case B on the ACK-mode axis.

SAFETY ENVELOPE (documented, not hidden): this is safe for the DNP3 request -> ACK -> response
pattern within the timing budget, because a response reliably follows and re-ACKs. It is NOT safe
for arbitrary TCP (window advancement, CONFIRM/keepalive ACKs with no following data): a fully
robust version needs light per-flow "response pending" state (the store-and-forward boundary). This
oracle proves the ACK-mode axis collapses for the request/response pattern; the state-dependent
safety is the analogue of the handshake normalizer's Experiment-3 endpoint question.

Run:  ~/.venvs/research/bin/python oracle_ackmode.py
"""
import sys
from scapy.all import Ether, IP, TCP, Raw

OUTSTATION_PORT = 20000


def is_from_outstation(p):
    return TCP in p and p[TCP].sport == OUTSTATION_PORT


def payload_len(p):
    ip = p[IP]
    return ip.len - ip.ihl * 4 - p[TCP].dataofs * 4


def is_pure_ack(p):
    """ACK set, no SYN/FIN/RST, zero payload."""
    if TCP not in p:
        return False
    f = p[TCP].flags
    return bool(f & 0x10) and not (f & 0x02) and not (f & 0x01) and not (f & 0x04) and payload_len(p) == 0


def transform(p):
    """Return (out_or_None, outcome). None == dropped/suppressed."""
    pp = Ether(bytes(p))
    if not is_from_outstation(pp):
        return pp, "fwd_to_outstation_or_other"
    if is_pure_ack(pp):
        return None, "ack_suppressed"          # standalone ACK removed
    return pp, "fwd_response"                    # data (response) forwarded unchanged


def outstation_side(seq_pkts):
    """Given a device's outstation-emitted packets for one transaction, return the observable
    signature after transform: (n_packets, has_standalone_ack)."""
    out = []
    for p in seq_pkts:
        r, oc = transform(p)
        if r is not None:
            out.append(r)
    has_standalone = any(is_pure_ack(p) for p in out)
    return len(out), has_standalone


def pure_ack(ackno, dof=5, opts=None):
    o = opts or []
    return (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=64, flags="DF") /
            TCP(sport=OUTSTATION_PORT, dport=44000, flags="A", seq=100, ack=ackno,
                window=8192, options=o))


def response(ackno, payload):
    return (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=64, flags="DF") /
            TCP(sport=OUTSTATION_PORT, dport=44000, flags="PA", seq=100, ack=ackno,
                window=8192) / Raw(payload))


def run():
    results = []

    def ok(name, cond, note=""):
        results.append((name, "PASS" if cond else "FAIL", note))

    resp_bytes = b"\x05\x64\x1f\x44" + b"\x00" * 40   # a DNP3 response fragment

    # Case A (SEL-751): standalone ACK, then response
    caseA = [pure_ack(1024), response(1024, resp_bytes)]
    nA, saA = outstation_side(caseA)

    # Case B (ION7550): single combined ACK+response
    caseB = [response(1024, resp_bytes)]
    nB, saB = outstation_side(caseB)

    ok("01 Case A: 2 pkts -> 1 pkt after suppression", nA == 1, f"n={nA}")
    ok("02 Case A: no standalone ACK remains", saA is False)
    ok("03 Case B: unchanged, 1 pkt", nB == 1, f"n={nB}")
    ok("04 Case B: no standalone ACK (already combined)", saB is False)
    ok("05 ACK-MODE COLLAPSE: A and B identical observable pattern",
       (nA, saA) == (nB, saB), f"A={(nA,saA)} B={(nB,saB)}")

    # the surviving Case-A packet is the response, and it still ACKs the request
    survivorA = [transform(p)[0] for p in caseA if transform(p)[0] is not None][0]
    ok("06 surviving Case-A packet is the response (has payload)", payload_len(survivorA) > 0)
    ok("07 response still ACKs the request (ack preserved)", survivorA[TCP].ack == 1024,
       f"ack={survivorA[TCP].ack}")
    ok("08 response bytes untouched", bytes(survivorA[Raw].load) == resp_bytes)

    # a pure ACK carrying options (TS) is still a pure ACK -> suppressed
    caseA_ts = [pure_ack(2048, dof=8, opts=[("NOP", None), ("NOP", None), ("Timestamp", (5, 0))]),
                response(2048, resp_bytes)]
    nA2, saA2 = outstation_side(caseA_ts)
    ok("09 Case A with TS-bearing ACK: still collapses to 1", nA2 == 1 and not saA2, f"n={nA2}")

    # traffic toward the outstation (master side) is never touched
    to_out = Ether() / IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=44000, dport=OUTSTATION_PORT, flags="A")
    _, oc = transform(to_out)
    ok("10 master->outstation ACK NOT suppressed", oc == "fwd_to_outstation_or_other")

    print(f"{'CHECK':52s} RES  NOTE")
    print("-" * 88)
    for n, r, nt in results:
        print(f"{n:52s} {r:4s} {nt}")
    print("-" * 88)
    npass = sum(1 for r in results if r[1] == "PASS")
    print(f"ACK-MODE ORACLE: {npass}/{len(results)} checks pass")
    print(f"\nObservable outstation-side pattern after normalization:")
    print(f"  SEL-751 (Case A): (packets={nA}, standalone_ack={saA})")
    print(f"  ION7550 (Case B): (packets={nB}, standalone_ack={saB})")
    print(f"  -> ACK-mode axis {'COLLAPSED (indistinguishable)' if (nA,saA)==(nB,saB) else 'still distinguishes'}")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(run())
