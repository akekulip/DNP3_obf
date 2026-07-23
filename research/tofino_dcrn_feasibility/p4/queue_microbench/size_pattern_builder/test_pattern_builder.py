#!/usr/bin/env python3
"""
test_pattern_builder.py — Step 7 unit tests for the DNP3 size-pattern builder v1 (OFF-SWITCH).

Runs with:  $RESEARCH_PYTHON test_pattern_builder.py    (uses unittest; needs scapy)

Covers, per the spec, at least: one READ, one separate-ACK transaction, and one SBO sequence
(SELECT -> confirm -> OPERATE -> confirm). The SBO sequence is SYNTHETIC because the real captures
contain only READ + DIRECT_OPERATE (no SBO); the test exercises the tooling's SBO handling and is
labelled synthetic — no real-capture SBO role is inferred.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_inventory as EI
import generate_candidates as GC
import evaluate_candidates as EV

from scapy.all import Ether, IP, TCP, Raw, wrpcap

MASTER = "10.0.0.3"


def dnp3(fc, app_ctrl=0xC1):
    """Minimal DNP3-over-TCP payload: 0x0564 + link(8) + transport + app_ctrl + FC(at offset 12)."""
    return b"\x05\x64\x0a\xc4\x01\x00\x0a\x00\xff\xff" + bytes([0xC0, app_ctrl, fc]) + b"\x00" * 8


def req(fc, out_ip):
    return Ether() / IP(src=MASTER, dst=out_ip) / TCP(sport=40000, dport=20000, flags="PA") / Raw(dnp3(fc))


def resp(fc, out_ip):
    return Ether() / IP(src=out_ip, dst=MASTER) / TCP(sport=20000, dport=40000, flags="PA") / Raw(dnp3(fc))


def pure_ack(out_ip):
    return Ether() / IP(src=out_ip, dst=MASTER) / TCP(sport=20000, dport=40000, flags="A")


def records_for(packets, dev, mode):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    wrpcap(path, packets)
    recs = list(EI.extract_pcap(path, os.path.basename(path), dev, mode))
    os.unlink(path)
    return recs


class TestExtractor(unittest.TestCase):
    def test_dnp3_fc_parsing(self):
        self.assertEqual(EI.parse_dnp3(dnp3(1))[1], "READ")
        self.assertEqual(EI.parse_dnp3(dnp3(5))[1], "DIRECT_OPERATE")
        self.assertEqual(EI.parse_dnp3(dnp3(3))[1], "SELECT")
        self.assertEqual(EI.parse_dnp3(dnp3(4))[1], "OPERATE")
        self.assertEqual(EI.parse_dnp3(dnp3(129))[1], "RESPONSE")
        self.assertEqual(EI.parse_dnp3(b"no dnp3 here")[1], None)

    def test_read_request_and_response(self):
        recs = records_for([req(1, "10.0.0.1"), resp(129, "10.0.0.1")], "SEL751", "separate")
        r_req = [r for r in recs if r["role"] == "READ_REQUEST"]
        r_resp = [r for r in recs if r["is_response"]]
        self.assertEqual(len(r_req), 1)
        self.assertEqual(r_req[0]["direction"], "master_to_outstation")
        self.assertEqual(len(r_resp), 1)
        self.assertEqual(r_resp[0]["response_to"], "READ")
        self.assertEqual(r_resp[0]["is_read_response"], 1)
        self.assertEqual(r_resp[0]["direction"], "outstation_to_master")

    def test_separate_ack_transaction(self):
        # SEL-751 separate-ACK: request -> pure outstation ACK -> response (one transaction)
        pkts = [req(1, "10.0.0.1"), pure_ack("10.0.0.1"), resp(129, "10.0.0.1")]
        recs = records_for(pkts, "SEL751", "separate")
        acks = [r for r in recs if r["tcp_kind"] == "ack_only"]
        self.assertEqual(len(acks), 1)
        self.assertEqual(acks[0]["role"], "ACK")
        self.assertEqual(acks[0]["ack_mode"], "separate")
        self.assertEqual(acks[0]["direction"], "outstation_to_master")
        # all three share one transaction id (request opened it)
        self.assertEqual(len({r["transaction_id"] for r in recs}), 1)

    def test_sbo_sequence_synthetic(self):
        # SYNTHETIC SBO (not in the real captures): SELECT -> confirm -> OPERATE -> confirm
        pkts = [req(3, "10.0.0.1"), resp(129, "10.0.0.1"), req(4, "10.0.0.1"), resp(129, "10.0.0.1")]
        recs = records_for(pkts, "SEL751", "separate")
        roles = [r["role"] for r in recs]
        self.assertIn("SELECT", roles)
        self.assertIn("OPERATE", roles)
        sel_conf = [r for r in recs if r["is_select_confirm"]]
        op_conf = [r for r in recs if r["is_operate_confirm"]]
        self.assertEqual(len(sel_conf), 1, "SELECT response must be labelled select_confirm")
        self.assertEqual(len(op_conf), 1, "OPERATE response must be labelled operate_confirm")
        # SELECT and OPERATE open distinct transactions
        self.assertEqual(len({r["transaction_id"] for r in recs}), 2)


class TestGenerator(unittest.TestCase):
    def setUp(self):
        # a small mixed inventory (varied wire sizes) for state-set tests
        self.recs = []
        for w in [54, 66, 88, 100, 115, 127]:
            self.recs.append({"wire_size": w, "device": "SEL751", "direction": "outstation_to_master",
                              "role": "RESPONSE", "transaction_id": 1, "is_response": 1,
                              "response_fragment_index": 0})

    def test_states_cover_max_and_upward_only(self):
        ws = sorted(r["wire_size"] for r in self.recs)
        for cid, (states, _rule) in GC.state_sets(ws).items():
            self.assertGreaterEqual(states[-1], max(ws), "%s top state must cover the max frame" % cid)
            self.assertEqual(states, sorted(states), "states must be ascending")
            for r in self.recs:
                s = GC.map_state(states, r["wire_size"])
                self.assertIsNotNone(s, "every packet must map (upward-only, top>=max)")
                self.assertGreaterEqual(s - r["wire_size"], 0, "padding must be >= 0 (upward only)")

    def test_maxonly_zero_size_leak(self):
        ws = sorted(r["wire_size"] for r in self.recs)
        states = GC.state_sets(ws)["maxonly"][0]
        e = EV.evaluate({"candidate_id": "maxonly", "size_states": [{"state": "S1", "target_wire_bytes": states[0]}],
                         "covers_largest_frame": True,
                         "pct_packets_per_state": {}, "max_original_wire_per_state": {},
                         "cover_modes": {"transaction_window": {"window_len_slots": 1, "filler_slots_per_type": {}}}},
                        self.recs, [10], [17], 211.0, 1.0)
        self.assertEqual(e["residual_distinguishability"]["size_leak_bits_upper"], 0.0,
                         "single-state pattern must leak 0 size bits")


if __name__ == "__main__":
    unittest.main(verbosity=2)
