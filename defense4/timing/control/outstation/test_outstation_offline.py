#!/usr/bin/env python3
"""Offline validation of the controlled software outstation's scenario engine.

Deterministic, no kernel or wire: for every scenario, check that plan() emits the frames the case is
named for, that every RESPONSE payload is a valid DNP3 link frame (start octets + header CRC), that
the application sequence is echoed (or deliberately wrong for wrong_appseq), that the timing lands in
the named arrival bucket, and that intended_record() reports the delivered DNP3 bytes. Prints every
check with PASS/FAIL and exits nonzero on any failure.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "../../../../dnp3_split_harness")))

import software_outstation as so
import dnp3_crc

CTX = {"read_appctrl": 0xC0, "clrt_ms": 3.0, "tresp_ms": 14.0, "failopen_ms": 200.0}
PASS = [0]
FAIL = [0]


def check(name, cond):
    if cond:
        print("  ok   %s" % name); PASS[0] += 1
    else:
        print("  FAIL %s" % name); FAIL[0] += 1


def kinds(ems):
    return [e.kind for e in ems]


def valid_dnp3(payload):
    if len(payload) < 10 or payload[0] != 0x05 or payload[1] != 0x64:
        return False
    return dnp3_crc.verify_crc(payload[0:8], payload[8:10])


def responses(ems):
    return [e for e in ems if e.kind in ("response", "response_seg") and e.payload]


def main():
    # every declared scenario must plan without error
    for sc in so.SCENARIOS:
        try:
            so.plan(sc, CTX)
            check("plan(%s) ok" % sc, True)
        except Exception as e:
            check("plan(%s) ok (%s)" % (sc, e), False)

    # normal: ack then response, response valid + echoes app-seq + before T_A
    ems = so.plan("normal", CTX)
    check("normal: ack precedes response", kinds(ems) == ["ack", "response"])
    check("normal: response is valid DNP3", valid_dnp3(ems[1].payload))
    check("normal: response echoes app-seq C0", ems[1].payload[11] == 0xC0)
    check("normal: response before T_A (clrt<tresp)", ems[1].t_ms < CTX["tresp_ms"])

    # the mandatory lifecycle case: response after the ACK deadline, before T_RESP
    ems = so.plan("resp_between_ta_tresp", CTX)
    r = responses(ems)[0]
    check("between: ack present", "ack" in kinds(ems))
    check("between: response after ack gap, before T_RESP", CTX["clrt_ms"] < r.t_ms < CTX["tresp_ms"])

    # late safe release: after T_RESP
    r = responses(so.plan("resp_after_tresp", CTX))[0]
    check("after_tresp: response t_ms > T_RESP", r.t_ms > CTX["tresp_ms"])
    r = responses(so.plan("resp_after_failopen", CTX))[0]
    check("after_failopen: response t_ms > fail-open horizon", r.t_ms > CTX["failopen_ms"])

    # missing / negative cases
    check("missing_ack: no pure ACK emitted", "ack" not in kinds(so.plan("missing_ack", CTX)))
    check("missing_ack: still has a response", len(responses(so.plan("missing_ack", CTX))) == 1)
    check("ack_no_resp: ack, no response", kinds(so.plan("ack_no_resp", CTX)) == ["ack"])
    check("missing_both: no emissions", so.plan("missing_both", CTX) == [])

    # duplicates / retransmit
    check("dup_ack: two acks", kinds(so.plan("dup_ack", CTX)).count("ack") == 2)
    dr = so.plan("dup_resp", CTX)
    check("dup_resp: two identical responses", len(responses(dr)) == 2 and responses(dr)[0].payload == responses(dr)[1].payload)
    rt = so.plan("retransmit", CTX)
    check("retransmit: a same-seq resend segment", any(e.kind == "response_seg" for e in rt))

    # identity + protocol-shape cases
    ws = responses(so.plan("wrong_appseq", CTX))[0]
    check("wrong_appseq: app-ctrl != READ app-ctrl", ws.payload[11] != 0xC0)
    cr = so.plan("combined_response", CTX)
    check("combined_response: no separate pure ACK", "ack" not in kinds(cr) and len(responses(cr)) == 1)
    ms = so.plan("multi_segment", CTX)
    segs = responses(ms)
    check("multi_segment: two segments", len(segs) == 2)
    check("multi_segment: concat == full response", segs[0].payload + segs[1].payload == so._set_appctrl(so.RESPONSE_TEMPLATE, 0xC0))

    # teardown timing
    check("fin_before_ack: fin, no ack", "fin" in kinds(so.plan("fin_before_ack", CTX)) and "ack" not in kinds(so.plan("fin_before_ack", CTX)))
    check("fin_after_ack: ack then fin, no response", kinds(so.plan("fin_after_ack", CTX)) == ["ack", "fin"])
    check("fin_after_resp: ack,response,fin", kinds(so.plan("fin_after_resp", CTX)) == ["ack", "response", "fin"])
    check("rst_before_ack: rst, no ack", "rst" in kinds(so.plan("rst_before_ack", CTX)) and "ack" not in kinds(so.plan("rst_before_ack", CTX)))
    check("rst_after_resp: ends in rst", kinds(so.plan("rst_after_resp", CTX))[-1] == "rst")

    # SELECT/OPERATE are software-outstation only and still valid DNP3
    for sc in ("select", "operate"):
        r = responses(so.plan(sc, CTX))[0]
        check("%s: valid DNP3 response (software only)" % sc, valid_dnp3(r.payload))

    # intended records: every response-bearing scenario yields intended bytes matching its emissions
    for sc in ("normal", "resp_between_ta_tresp", "multi_segment", "combined_response"):
        rec = so.intended_record(sc, CTX)
        emresp = responses(so.plan(sc, CTX))
        check("intended(%s): one record per response payload" % sc, len(rec) == len(emresp))
        check("intended(%s): hex matches emitted payload" % sc,
              all(rec[i]["hex"] == emresp[i].payload.hex() for i in range(len(rec))))

    # every WHOLE-frame response (kind=="response") must be a valid DNP3 frame; fragments
    # (kind=="response_seg") are validated by concatenation, not individually.
    allok = True
    for sc in so.SCENARIOS:
        for e in so.plan(sc, CTX):
            if e.kind == "response" and e.payload and not valid_dnp3(e.payload):
                allok = False
    check("all whole-frame responses are valid DNP3", allok)
    # multi_segment: the concatenated fragments form a valid DNP3 frame
    segs = responses(so.plan("multi_segment", CTX))
    check("multi_segment: concatenation is a valid DNP3 frame", valid_dnp3(segs[0].payload + segs[1].payload))
    # retransmit: the resend segment is a full-frame copy of the response
    rt = so.plan("retransmit", CTX)
    rt_resp = [e for e in rt if e.kind == "response"][0]
    rt_seg = [e for e in rt if e.kind == "response_seg"][0]
    check("retransmit: resend equals the original response frame", rt_seg.payload == rt_resp.payload and valid_dnp3(rt_seg.payload))

    print("\n=== outstation offline: %d passed, %d failed ===" % (PASS[0], FAIL[0]))
    return 1 if FAIL[0] else 0


if __name__ == "__main__":
    sys.exit(main())
