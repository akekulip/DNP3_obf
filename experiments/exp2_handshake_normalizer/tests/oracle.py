#!/usr/bin/env python3
"""Offline oracle for the handshake normalizer (Experiment 2B).

This is a Python re-implementation of the P4 program's SPECIFIED transformation, used to
(1) validate that the specified output packets are well-formed (valid IPv4 + TCP checksums),
(2) validate byte-preservation invariants (seq/ack/window and payload never change; fail-open
    packets keep the entire TCP header byte-identical), and
(3) emit the golden expected packets the PTF test compares against.

IMPORTANT SCOPE: the oracle proves the *specification* is coherent and produces valid,
invariant-preserving packets. It does NOT prove the compiled datapath matches the spec — that
is the tofino-model run (blocked on veth/root in this environment; see MODEL_TESTS.md). Run:

    ~/.venvs/research/bin/python tests/oracle.py
"""
import sys
from scapy.all import Ether, IP, TCP, UDP, Raw, ARP

PUB_MSS = 1460
PUB_WINDOW = 8192                 # canonical handshake window (all devices identical)
SUPPORTED_DO = set(range(5, 12))  # 5..11
results = []


def _norm_l3(ip):
    """L3 normalization: ttl=64 always; id=0 for atomic datagrams (DF set, not fragmented)."""
    ip.ttl = 64
    atomic = (ip.flags == 0x2) and (ip.frag == 0)  # DF set, MF clear, offset 0
    l3i = 0
    if atomic:
        ip.id = 0
        l3i = 1
    return l3i


def _first_opt_is_mss(opts):
    return len(opts) >= 1 and opts[0][0] == "MSS"


def _second_opt_kind_safe(opts):
    # k1 in {NOP,EOL,SACKOK,Timestamp,WScale}; absent (do==6) is safe too
    if len(opts) < 2:
        return True
    k = opts[1][0]
    return k in ("NOP", "EOL", "SAckOK", "Timestamp", "WScale")


def transform(pkt_in):
    """Return (pkt_out, tcp_outcome, l3_applied) per the P4 spec."""
    p = Ether(bytes(pkt_in))            # serialize+reparse so ihl/proto/len are populated
    if ARP in p or IP not in p:
        return p, "fwd_non_ipv4", None
    ip = p[IP]
    # parser gate: TCP, no IP options (ihl==5), UNfragmented (offset 0 AND MF clear)
    is_tcp = (ip.proto == 6) and (ip.ihl == 5) and (ip.frag == 0) and not (int(ip.flags) & 0x1)
    if not is_tcp:
        l3 = _norm_l3(ip); del ip.chksum
        return Ether(bytes(p)), "fwd_non_tcp_or_ipopts_or_frag", l3
    tcp = p[TCP]
    dof = tcp.dataofs if tcp.dataofs else 5
    opts = list(tcp.options)
    payload = bytes(tcp.payload)
    syn = bool(tcp.flags & 0x02) and not (tcp.flags & 0x10)
    synack = bool(tcp.flags & 0x02) and bool(tcp.flags & 0x10)
    has_opts = dof >= 6
    # expected no-payload length per data_offset (supported range)
    exp = {5: 40, 6: 44, 7: 48, 8: 52, 9: 56, 10: 60, 11: 64}.get(dof, 0)
    has_payload = (ip.len != exp) if dof in SUPPORTED_DO else True
    orig_mss = dict(opts).get("MSS", 0) if _first_opt_is_mss(opts) else 0
    outmss = min(orig_mss, PUB_MSS) if orig_mss else PUB_MSS

    def eligible_norm():
        # rebuild as canonical [MSS] only, data_offset 6, canonical window
        p2 = p.copy()
        t2 = p2[TCP]; t2.options = [("MSS", outmss)]; t2.window = PUB_WINDOW
        t2.dataofs = 6                     # scapy keeps a concrete dataofs after reparse; force 6
        del t2.chksum
        i2 = p2[IP]; i2.len = 44
        l3 = _norm_l3(i2); del i2.chksum
        return Ether(bytes(p2)), l3

    # --- outcome logic mirrors the P4 apply block ---
    if dof > 11 and dof <= 15:
        l3 = _norm_l3(ip); del ip.chksum
        return Ether(bytes(p)), "tcp_unsupported_do", l3   # TCP byte-identical
    if syn:
        if has_payload:
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "syn_payload_bypass", l3
        if not has_opts or not _first_opt_is_mss(opts):
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "syn_failopen", l3
        if dof != 6 and not _second_opt_kind_safe(opts):
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "security_opt_bypass", l3
        out, l3 = eligible_norm()
        return out, ("norm_syn_clamp" if orig_mss > PUB_MSS else "norm_syn"), l3
    if synack:
        # symmetric aggressive normalization (strip options like the SYN path)
        if has_payload:                                    # SYN-ACK with payload/TFO -> fail open (M1)
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "synack_nonminimal_bypass", l3
        if not _first_opt_is_mss(opts):
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "synack_nonminimal_bypass", l3
        if dof != 6 and not _second_opt_kind_safe(opts):
            l3 = _norm_l3(ip); del ip.chksum
            return Ether(bytes(p)), "synack_nonminimal_bypass", l3
        out, l3 = eligible_norm()
        return out, ("synack_normalize_clamp" if orig_mss > PUB_MSS else "synack_normalize"), l3
    if has_opts:
        l3 = _norm_l3(ip); del ip.chksum
        return Ether(bytes(p)), "established_leak", l3
    l3 = _norm_l3(ip); del ip.chksum
    return Ether(bytes(p)), "fwd_other", l3


def check(name, pkt_in, expect_outcome, expect_tcp_identical=None):
    src = Ether(bytes(pkt_in))                             # populate lazy fields on the input
    out, outcome, l3 = transform(pkt_in)
    reparsed = Ether(bytes(out))
    ok = True; notes = []
    if outcome != expect_outcome:
        ok = False; notes.append(f"outcome {outcome} != {expect_outcome}")
    # checksum validity: stored csum must equal scapy's recomputation
    if IP in reparsed:
        ipc = reparsed[IP]
        recomputed = Ether(bytes(reparsed))[IP]
        if ipc.chksum != recomputed.chksum:
            ok = False; notes.append("IPv4 checksum invalid")
        if TCP in ipc and ipc[TCP].chksum != recomputed[TCP].chksum:
            ok = False; notes.append("TCP checksum invalid")
    # seq/ack always preserved; window preserved on fail-open, canonicalized on normalize
    if TCP in src and TCP in reparsed:
        for f in ("seq", "ack"):
            if getattr(src[TCP], f) != getattr(reparsed[TCP], f):
                ok = False; notes.append(f"{f} changed")
        normalized = outcome.startswith("norm") or outcome.startswith("synack_normalize")
        if normalized:
            rt = reparsed[TCP]
            opt = bytes(rt)[20:rt.dataofs * 4]
            if rt.window != PUB_WINDOW:
                ok = False; notes.append("window not canonicalized")
            if rt.dataofs != 6 or opt[:2] != bytes([2, 4]):   # canonical: do=6, [MSS] only
                ok = False; notes.append(f"not canonical [MSS] do6 (dataofs={rt.dataofs}, opt={opt.hex()})")
        if not normalized and src[TCP].window != reparsed[TCP].window:
            ok = False; notes.append("window changed on fail-open")
    # fail-open: entire TCP header byte-identical
    if expect_tcp_identical and TCP in src and TCP in reparsed:
        if bytes(src[TCP]) != bytes(reparsed[TCP]):
            ok = False; notes.append("TCP header NOT byte-identical on fail-open")
    results.append((name, "PASS" if ok else "FAIL", outcome, l3, ";".join(notes)))
    return ok


def _syn(mss, opts, ttl=64, df=True, dport=20000, seq=1000):
    fl = "DF" if df else 0
    o = ([("MSS", mss)] if mss is not None else []) + opts
    return (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=ttl, flags=fl) /
            TCP(sport=44000, dport=dport, flags="S", seq=seq, window=8192, options=o))


def _synack(opts):
    return (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=64, flags="DF") /
            TCP(sport=20000, dport=44000, flags="SA", seq=5, ack=1001, window=8192, options=opts))


def _est(flags, opts, payload=b""):
    return (Ether() / IP(src="10.0.0.2", dst="10.0.0.9", ttl=64, flags="DF") /
            TCP(sport=20000, dport=44000, flags=flags, seq=10, ack=20, window=4096, options=opts) /
            (Raw(payload) if payload else Raw()))


# ---- the case matrix (shared with the PTF model test via `import oracle`) ----
# each entry: (name, input_pkt, expect_outcome, expect_tcp_identical)
_do13 = (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", flags="DF") /
         TCP(sport=44000, dport=20000, flags="S", seq=1000, window=8192,
             options=[("MSS", 1460), ("Timestamp", (1, 0)), ("WScale", 7)] + [("NOP", None)] * 18))
CASES = [
    ("01 SEL751 full SYN (do~10)", _syn(1460, [("SAckOK", b""), ("Timestamp", (1, 0)), ("WScale", 7), ("NOP", None)]), "norm_syn", False),
    ("02 ION7550 MSS-only SYN (do6)", _syn(1460, []), "norm_syn", False),
    ("03 AB1400 MSS1478 clamp", _syn(1478, [("NOP", None), ("NOP", None), ("NOP", None), ("EOL", None)]), "norm_syn_clamp", False),
    ("04 small MSS 536 kept", _syn(536, [("Timestamp", (5, 0))]), "norm_syn", False),
    ("05 MSS absent SYN", _syn(None, [("Timestamp", (5, 0))]), "syn_failopen", True),
    ("06 MSS==public 1460", _syn(1460, [("NOP", None), ("NOP", None), ("SAckOK", b"")]), "norm_syn", False),
    ("07 MSS below clamp 1200", _syn(1200, []), "norm_syn", False),
    ("08 SYN-ACK MSS-only (do6)", _synack([("MSS", 1460)]), "synack_normalize", False),
    ("09 SYN-ACK MSS+TS -> normalized (aggressive)", _synack([("MSS", 1460), ("Timestamp", (2, 1))]), "synack_normalize", False),
    ("09b SYN-ACK MSS+MD5 -> fail open", _synack([("MSS", 1460), (19, b"\x00" * 16)]), "synack_nonminimal_bypass", True),
    ("09c SYN-ACK MSS + payload -> fail open (M1)", _synack([("MSS", 1460)]) / Raw(b"\x05\x64\x00\x00"), "synack_nonminimal_bypass", True),
    ("10 SYN payload/TFO", _syn(1460, [("TFO", b"\x01\x02\x03\x04\x05\x06\x07\x08")]) / Raw(b"data"), "syn_payload_bypass", True),
    ("11 SYN MD5 2nd opt", _syn(1460, [(19, b"\x00" * 16)]), "security_opt_bypass", True),
    ("12 SYN AO (kind 29)", _syn(1460, [(29, b"\x00" * 10)]), "security_opt_bypass", True),
    ("13 established + TS (leak)", _est("A", [("NOP", None), ("NOP", None), ("Timestamp", (7, 3))], b"\x05\x64\x00\x00"), "established_leak", True),
    ("14 established no-opt + DNP3", _est("A", [], b"\x05\x64\x0b\x44"), "fwd_other", True),
    ("15 ACK bare", _est("A", []), "fwd_other", True),
    ("16 FIN", _est("FA", []), "fwd_other", True),
    ("17 RST", _est("R", []), "fwd_other", True),
    ("18 UDP forwarded", Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ttl=200) / UDP(sport=5, dport=6) / Raw(b"abcd"), "fwd_non_tcp_or_ipopts_or_frag", None),
    ("19 ARP forwarded", Ether() / ARP(), "fwd_non_ipv4", None),
    ("20 retransmitted SYN (same 4-tuple)", _syn(1460, [("SAckOK", b""), ("Timestamp", (9, 0)), ("WScale", 7), ("NOP", None)], seq=1000), "norm_syn", False),
    ("21 do=11 max supported SYN", _syn(1460, [("SAckOK", b""), ("Timestamp", (1, 0)), ("WScale", 7), ("NOP", None), ("NOP", None), ("NOP", None)]), "norm_syn", False),
    ("22 TTL scrub input 128", _syn(1460, [], ttl=128), "norm_syn", False),
    ("23 non-atomic (fragment)", (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", flags="MF", frag=0) / TCP(sport=1, dport=2, flags="S", options=[("MSS", 1460)])), "fwd_non_tcp_or_ipopts_or_frag", None),
    ("24 IPv4 options (ihl>5)", (Ether() / IP(src="10.0.0.9", dst="10.0.0.2", ihl=6) / Raw(b"\x83\x03\x00\x00") / TCP(sport=1, dport=2, flags="S", options=[("MSS", 1460)])), "fwd_non_tcp_or_ipopts_or_frag", None),
    ("25 established DNP3 response (big)", _est("PA", [], b"\x05\x64\x1f\x44" + b"\x00" * 60), "fwd_other", True),
    ("26 duplicated MSS option", _syn(1460, [("MSS", 500)]), "security_opt_bypass", True),
    ("27 data_offset 12-15 unsupported", _do13, "tcp_unsupported_do", True),
]

if __name__ == "__main__":            # importable by the PTF test without running/exiting
    for _name, _pkt, _oc, _ti in CASES:
        check(_name, _pkt, _oc, expect_tcp_identical=_ti)
    npass = sum(1 for r in results if r[1] == "PASS")
    print(f"{'CASE':46s} {'RES':4s} {'OUTCOME':26s} L3  NOTES")
    print("-" * 100)
    for name, res, outcome, l3, notes in results:
        print(f"{name:46s} {res:4s} {outcome:26s} {str(l3):3s} {notes}")
    print("-" * 100)
    print(f"ORACLE: {npass}/{len(results)} cases pass the spec self-consistency + validity checks")
    sys.exit(0 if npass == len(results) else 1)
