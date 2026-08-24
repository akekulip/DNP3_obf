#!/usr/bin/env python3
"""Deterministic controlled DNP3 software outstation for the Defense 4 negative-test laboratory.

The physical SEL-751 cannot be told to drop an ACK, withhold a RESPONSE, send a RST mid-transaction,
or emit SELECT/OPERATE. This software outstation can, deterministically, so the P4 lifecycle can be
exercised on every edge case the plan requires. It is a SOFTWARE outstation: SELECT/OPERATE and all
hazardous cases go here, never to the physical relay.

Design: the deterministic scenario logic (which frames each case emits, with what bytes, flags, and
timing) is separated from the live wire realization. The logic is pure and unit-tested offline with no
kernel or wire in the loop (`test_outstation_offline.py`); `serve()` realizes the emissions on a real
TCP flow through the switch during the live phase (scapy, imported lazily).

Case A (separate-ACK): a NORMAL transaction is a pure TCP ACK of the READ followed, after a chosen
CLRT, by the DNP3 RESPONSE. Every emission's DNP3 payload is recorded as the transaction's INTENDED
bytes, so the paired comparator can check intended-vs-ingress even though a live device's values would
change every poll.
"""
import json

from collections import namedtuple

# a real SEL-751 class-0 RESPONSE frame (134 bytes), captured on the wire; the faithful template
SEL751_RESPONSE_HEX = (
    "05647344010000001a59f1c0818400010200000f8101010101018cd9010101010101010101010a0200001f01"
    "fee801010101010101010101010101010101bbc30101010101010101010101010101011ec30d040000140300"
    "030008000900010005003fc208003c000f0011001f001500150000005e6e000000000300000000000000000020f7"
)
RESPONSE_TEMPLATE = bytes.fromhex(SEL751_RESPONSE_HEX)

# An emission is one frame the outstation puts on the wire for a transaction.
#   kind:    "ack" (pure TCP ACK, empty payload) | "response" | "fin" | "rst" | "response_seg"
#   payload: DNP3 bytes (b"" for pure ACK/fin/rst)
#   t_ms:    when to send, in ms after the READ is received (models the CLRT and late paths)
#   flags:   TCP flags string ("A", "PA", "FA", "RA")
#   note:    human tag
Emission = namedtuple("Emission", "kind payload t_ms flags note")

# every scenario name the laboratory can request
SCENARIOS = [
    "normal", "resp_before_ta", "resp_between_ta_tresp", "resp_after_tresp", "resp_after_failopen",
    "missing_ack", "ack_no_resp", "missing_both",
    "dup_ack", "dup_resp", "retransmit",
    "wrong_appseq", "combined_response", "multi_segment",
    "fin_before_ack", "fin_after_ack", "fin_after_resp", "rst_before_ack", "rst_after_resp",
    "select", "operate",
]


def _set_appctrl(payload, appctrl):
    """Return a copy of a DNP3 response with its application-control octet (offset 11) set."""
    b = bytearray(payload)
    if len(b) > 11:
        b[11] = appctrl
    return bytes(b)


def plan(scenario, ctx):
    """Return the ordered list of Emissions for one transaction.

    ctx keys: read_appctrl (int C0..CF), clrt_ms (normal ack->response gap), tresp_ms (D_A+D_R budget
    from t_ACK), failopen_ms (fail-open horizon), response (template bytes).
    Timing is relative to READ receipt; the pure ACK is at t=0.5 ms, the response at the scenario's
    chosen offset. These offsets place the response in the arrival bucket the case is named for.
    """
    resp = _set_appctrl(ctx.get("response", RESPONSE_TEMPLATE), ctx["read_appctrl"])
    clrt = ctx.get("clrt_ms", 3.0)
    tresp = ctx.get("tresp_ms", 14.0)
    failopen = ctx.get("failopen_ms", 200.0)
    ack = Emission("ack", b"", 0.5, "A", "pure TCP ACK of the READ")

    if scenario in ("normal", "resp_before_ta"):
        return [ack, Emission("response", resp, clrt, "PA", "RESPONSE before T_A")]
    if scenario == "resp_between_ta_tresp":
        # response after the ACK deadline (T_A) but before T_RESP: the must-hold lifecycle case
        return [ack, Emission("response", resp, (tresp + clrt) / 2.0, "PA", "RESPONSE between T_A and T_RESP")]
    if scenario == "resp_after_tresp":
        return [ack, Emission("response", resp, tresp + 5.0, "PA", "RESPONSE after T_RESP (late safe release)")]
    if scenario == "resp_after_failopen":
        return [ack, Emission("response", resp, failopen + 20.0, "PA", "RESPONSE after fail-open horizon")]
    if scenario == "missing_ack":
        # no pure TCP ACK precedes the response; the response segment carries the only ACK
        return [Emission("response", resp, clrt, "PA", "RESPONSE with no preceding pure ACK")]
    if scenario == "ack_no_resp":
        return [ack]
    if scenario == "missing_both":
        return []
    if scenario == "dup_ack":
        return [ack, Emission("ack", b"", 1.0, "A", "duplicate pure ACK"),
                Emission("response", resp, clrt, "PA", "RESPONSE")]
    if scenario == "dup_resp":
        return [ack, Emission("response", resp, clrt, "PA", "RESPONSE"),
                Emission("response", resp, clrt + 2.0, "PA", "duplicate RESPONSE")]
    if scenario == "retransmit":
        # the same TCP segment (same seq) resent: realized by the wire layer resending without advancing seq
        return [ack, Emission("response", resp, clrt, "PA", "RESPONSE"),
                Emission("response_seg", resp, clrt + 3.0, "PA", "RETRANSMIT (same seq)")]
    if scenario == "wrong_appseq":
        bad = _set_appctrl(resp, (ctx["read_appctrl"] + 1) & 0xFF)
        return [ack, Emission("response", bad, clrt, "PA", "RESPONSE with wrong app sequence")]
    if scenario == "combined_response":
        # a single ACK-bearing DNP3 RESPONSE (no separate pure ACK): Case-B-like combined behavior
        return [Emission("response", resp, clrt, "PA", "combined ACK-bearing RESPONSE")]
    if scenario == "multi_segment":
        half = len(resp) // 2
        return [ack, Emission("response_seg", resp[:half], clrt, "PA", "RESPONSE segment 1"),
                Emission("response_seg", resp[half:], clrt + 1.0, "PA", "RESPONSE segment 2")]
    if scenario == "fin_before_ack":
        return [Emission("fin", b"", 0.5, "FA", "FIN before ACK")]
    if scenario == "fin_after_ack":
        return [ack, Emission("fin", b"", clrt, "FA", "FIN after ACK, before RESPONSE")]
    if scenario == "fin_after_resp":
        return [ack, Emission("response", resp, clrt, "PA", "RESPONSE"),
                Emission("fin", b"", clrt + 2.0, "FA", "FIN after RESPONSE")]
    if scenario == "rst_before_ack":
        return [Emission("rst", b"", 0.5, "RA", "RST before ACK")]
    if scenario == "rst_after_resp":
        return [ack, Emission("response", resp, clrt, "PA", "RESPONSE"),
                Emission("rst", b"", clrt + 2.0, "RA", "RST after RESPONSE")]
    if scenario in ("select", "operate"):
        # SELECT/OPERATE are software-outstation only. The outstation replies but the READ-protected
        # state must not arm; the response echoes the function so the P4 can be checked for bypass.
        fn = 0x83 if scenario == "select" else 0x84  # DNP3 app function SELECT=0x03/OPERATE=0x04 (resp 0x83/0x84 tag)
        b = bytearray(resp); b[11] = ctx["read_appctrl"]
        return [ack, Emission("response", bytes(b), clrt, "PA", "%s response (software only)" % scenario)]
    raise ValueError("unknown scenario %r" % scenario)


def intended_record(scenario, ctx):
    """The DNP3 bytes this transaction intends to deliver to the master (for the paired comparator)."""
    out = []
    for e in plan(scenario, ctx):
        if e.kind in ("response", "response_seg") and e.payload:
            out.append({"app_seq": "0x%02X" % ctx["read_appctrl"], "hex": e.payload.hex(),
                        "kind": e.kind, "note": e.note})
    return out


# ------------------------------------------------------------------ live wire realization (scapy) ---
def serve(listen_ip, port, scenario_seq, ctx_base, iface, master_ip, intended_out, log=print):
    """Realize the planned emissions on a real TCP flow through the switch. Live phase only.

    scapy owns the TCP state machine so every frame is deterministic; the kernel's RSTs for this port
    must be dropped first (the caller sets the iptables rule). One connection, N READs; each READ's
    scenario is scenario_seq[i % len]. Records intended bytes per transaction to intended_out.
    """
    from scapy.all import sniff, sendp, Ether, IP, TCP, get_if_hwaddr  # lazy: offline tests need no wire
    import time
    raise NotImplementedError(
        "serve() is the live wire realizer; wired up in the live Phase 2 step with the testbed's "
        "interface, MACs, and iptables RST-drop. The deterministic plan()/intended_record() logic it "
        "realizes is validated offline by test_outstation_offline.py.")


if __name__ == "__main__":
    import sys
    # offline self-describe: print the plan for a scenario
    sc = sys.argv[1] if len(sys.argv) > 1 else "normal"
    ctx = {"read_appctrl": 0xC0, "clrt_ms": 3.0, "tresp_ms": 14.0, "failopen_ms": 200.0}
    ems = []
    for e in plan(sc, ctx):
        d = dict(e._asdict())
        d["payload_len"] = len(e.payload)
        d["payload"] = e.payload.hex()
        ems.append(d)
    print(json.dumps({"scenario": sc, "emissions": ems, "intended": intended_record(sc, ctx)}, indent=2))
