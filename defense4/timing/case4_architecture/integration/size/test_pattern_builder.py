#!/usr/bin/env python3
"""
test_pattern_builder.py — regression tests for the DNP3 size-pattern builder v1.1 (OFF-SWITCH).

Run:  $RESEARCH_PYTHON test_pattern_builder.py     (unittest; needs scapy + numpy)

Charter autunomous.md §6.12. Every listed regression is covered and MUST pass before Phase 2:
 - two flows with the same transaction ID do NOT merge;
 - timestamp-preserving post-response ACK ordering;
 - SYN/FIN/RST excluded from pure-ACK;
 - separate vs combined ACK transaction detection;
 - retransmission detection (data-only) and duplicate handling;
 - a 127-byte captured input maps to the 128-byte target;
 - larger Class-0 / multi-segment input behavior (maps to None -> needs split/fail-open/larger state);
 - per-direction overhead correctness;
 - canonical filler differs for combined vs separate ACK mode;
 - corpus-specific maximum handling;
 - candidate filename matches candidate_id;
 - dry-run schema validation of a candidate JSON.

Small pcaps are synthesized with scapy; functions are imported from the actual builder modules.
"""
import json
import logging
import os
import sys
import tempfile
import unittest
import warnings

logging.getLogger("scapy").setLevel(logging.ERROR)
# extract_inventory.py is frozen (read-only); its PcapReader loop leaks the file handle, which unittest
# surfaces as a ResourceWarning. Silence it here so it does not obscure real test output.
warnings.simplefilter("ignore", ResourceWarning)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_inventory as EI      # noqa: E402
import generate_candidates as GC    # noqa: E402
import evaluate_candidates as EV     # noqa: E402

from scapy.all import Ether, IP, TCP, Raw, wrpcap    # noqa: E402

SZ = "ethernet_frame_bytes_no_fcs_min_applied"
MASTER = "10.0.0.3"
EMAC, OMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"


# ------------------------------------------------------------------ scapy synthesis helpers
def dnp3(fc, app_ctrl=0xC1):
    """0x0564 + link(8) + transport(1) + app_ctrl(1) + FC(1) at offset 12, then filler."""
    return b"\x05\x64\x0a\xc4\x01\x00\x0a\x00\xff\xff" + bytes([0xC0, app_ctrl, fc]) + b"\x00" * 8


def _frame(src, dst, sport, dport, flags, seq, ack, payload, ts):
    p = (Ether(src=EMAC, dst=OMAC) / IP(src=src, dst=dst) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) / (Raw(payload) if payload else b""))
    if ts is not None:
        p.time = ts
    return p


def req(fc, out_ip="10.0.0.1", sport=40000, seq=1000, ack=1, ts=None, size=None):
    payload = dnp3(fc)
    if size:
        need = size - 54
        if need > len(payload):
            payload = payload + b"\x00" * (need - len(payload))
    return _frame(MASTER, out_ip, sport, 20000, "PA", seq, ack, payload, ts)


def resp(fc, out_ip="10.0.0.1", sport=40000, seq=2000, ack=1, ts=None, size=None):
    payload = dnp3(fc)
    if size:
        need = size - 54
        if need > len(payload):
            payload = payload + b"\x00" * (need - len(payload))
    return _frame(out_ip, MASTER, 20000, sport, "PA", seq, ack, payload, ts)


def pure_ack(frm="outstation", out_ip="10.0.0.1", sport=40000, seq=3000, ack=1, ts=None, flags="A"):
    if frm == "outstation":
        return _frame(out_ip, MASTER, 20000, sport, flags, seq, ack, b"", ts)
    return _frame(MASTER, out_ip, sport, 20000, flags, seq, ack, b"", ts)


def analyzed(packets, dev="SEL751", label="separate"):
    """Write a pcap, run the v1.1 extractor + analysis pass, return the RAW analyzed records."""
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False).name
    wrpcap(f, packets)
    recs = EI.extract_raw(f, os.path.basename(f), dev, label)
    EI.analyze(recs)
    os.unlink(f)
    return recs


def make_rec(**kw):
    """A minimal analysis-inventory record with all fields the builder touches."""
    r = {"capture_id": "t.pcap", "capture_index": kw.get("capture_index", 1), "ts": kw.get("ts", 0.0),
         "device": kw.get("device", "SEL751"), "device_ack_mode_label": "separate",
         "flow": kw.get("flow", "10.0.0.3:40000"), "direction": kw["direction"],
         "role": kw["role"], "response_to": kw.get("response_to", ""),
         "response_fragment_index": kw.get("response_fragment_index", -1),
         "transaction_id": kw.get("transaction_id", 1),
         "ack_mode_observed": kw.get("ack_mode_observed", "combined"),
         "is_retransmission": 0, "is_duplicate": 0, "is_pure_ack": kw.get("is_pure_ack", 0),
         SZ: kw["size"]}
    return r


# ------------------------------------------------------------------ extractor / analysis tests
class TestExtractor(unittest.TestCase):
    def test_dnp3_fc_parsing(self):
        self.assertEqual(EI.parse_dnp3(dnp3(1))[1], "READ")
        self.assertEqual(EI.parse_dnp3(dnp3(5))[1], "DIRECT_OPERATE")
        self.assertEqual(EI.parse_dnp3(dnp3(3))[1], "SELECT")
        self.assertEqual(EI.parse_dnp3(dnp3(4))[1], "OPERATE")
        self.assertEqual(EI.parse_dnp3(dnp3(129))[1], "RESPONSE")
        self.assertIsNone(EI.parse_dnp3(b"no dnp3 here")[1])

    def test_two_flows_same_txn_id_do_not_merge(self):
        # two DISTINCT master flows (different sport), each a single READ transaction.
        pkts = [req(1, sport=40000, ts=1.0), resp(129, sport=40000, ts=1.1),
                req(1, sport=41000, ts=2.0), resp(129, sport=41000, ts=2.1)]
        recs = analyzed(pkts)
        # both flows open transaction_id == 1 within their own flow
        tids = {(r["flow"], r["transaction_id"]) for r in recs if r["transaction_id"] > 0}
        self.assertEqual(len({r["flow"] for r in recs}), 2, "two distinct flows expected")
        self.assertIn(("10.0.0.3:40000", 1), tids)
        self.assertIn(("10.0.0.3:41000", 1), tids)
        # the builder groups by (device,capture,flow,txn) -> the two txn-1 groups stay SEPARATE
        groups = GC.transaction_groups(recs)
        txn1_groups = [k for k in groups if k[3] == 1]
        self.assertEqual(len(txn1_groups), 2, "same txn id in two flows must NOT merge")
        for k, pkts_in in groups.items():
            flows = {p["flow"] for p in pkts_in}
            self.assertEqual(len(flows), 1, "a transaction group must contain exactly one flow")

    def test_timestamp_preserving_post_response_ack_order(self):
        pkts = [req(1, ts=10.0), resp(129, ts=10.2),
                pure_ack(frm="master", seq=1500, ts=10.4)]   # master ACK AFTER the response
        recs = analyzed(pkts)
        by_role = {r["role"]: r for r in recs}
        self.assertIn("RESPONSE", by_role)
        mack = [r for r in recs if r["role"] == "ACK" and r["direction"] == "master_to_outstation"]
        self.assertEqual(len(mack), 1)
        self.assertEqual(mack[0]["ack_role"], "master_ack_of_response")
        # order preserved by timestamp: the master ACK is NOT reordered ahead of the response
        self.assertGreater(mack[0]["ts"], by_role["RESPONSE"]["ts"])
        ordered = sorted(recs, key=lambda r: (r["ts"], r["capture_index"]))
        self.assertEqual(ordered[-1]["ack_role"], "master_ack_of_response")

    def test_syn_fin_rst_excluded_from_pure_ack(self):
        pkts = [pure_ack(flags="SA", seq=1, ts=1.0),     # SYN+ACK
                pure_ack(flags="FA", seq=2, ts=2.0),     # FIN+ACK
                pure_ack(flags="R", seq=3, ts=3.0),      # RST
                pure_ack(flags="A", seq=4, ts=4.0)]      # clean ACK
        recs = analyzed(pkts)
        pure = [r for r in recs if r["is_pure_ack"] == 1]
        self.assertEqual(len(pure), 1, "only the clean zero-payload ACK is a pure ACK")
        self.assertEqual(pure[0]["tcp_ack"], 1)
        for r in recs:
            if r["tcp_syn"] or r["tcp_fin"] or r["tcp_rst"]:
                self.assertEqual(r["is_pure_ack"], 0)

    def test_separate_vs_combined_ack_detection(self):
        sep = analyzed([req(1, sport=40000, ts=1.0), pure_ack(frm="outstation", sport=40000, ts=1.1),
                        resp(129, sport=40000, ts=1.2)])
        self.assertTrue(any(r["ack_mode_observed"] == "separate" for r in sep),
                        "request -> outstation pure ACK -> response must be SEPARATE")
        oack = [r for r in sep if r["role"] == "ACK" and r["direction"] == "outstation_to_master"]
        self.assertEqual(oack[0]["ack_role"], "outstation_ack_of_request")
        comb = analyzed([req(1, sport=42000, ts=1.0), resp(129, sport=42000, ts=1.1)])
        self.assertTrue(any(r["ack_mode_observed"] == "combined" for r in comb),
                        "request -> response with no separate ACK must be COMBINED")

    def test_retransmission_detection_data_only(self):
        # two DATA segments, same (dir,seq), payload>0, but not byte-identical (different ack) -> retx
        pkts = [req(1, seq=5000, ack=1, ts=1.0), req(1, seq=5000, ack=99, ts=1.5)]
        recs = analyzed(pkts)
        data = [r for r in recs if r["tcp_payload_bytes"] > 0]
        self.assertEqual(data[0]["is_retransmission"], 0)
        self.assertEqual(data[1]["is_retransmission"], 1, "repeated data seq -> retransmission")
        self.assertEqual(data[1]["is_duplicate"], 0, "different ack -> not a byte-identical duplicate")
        # repeated PURE ACKs (payload 0) at the same seq are NOT retransmissions
        acks = analyzed([pure_ack(seq=7000, ack=1, ts=1.0), pure_ack(seq=7000, ack=50, ts=1.1)])
        for r in acks:
            self.assertEqual(r["is_retransmission"], 0, "pure ACKs never consume seq space")

    def test_duplicate_handling(self):
        p = resp(129, seq=8000, ack=7, ts=1.0)
        recs = analyzed([p, resp(129, seq=8000, ack=7, ts=1.0)])   # byte-identical repeat
        self.assertEqual(recs[0]["is_duplicate"], 0)
        self.assertEqual(recs[1]["is_duplicate"], 1)
        analysis, suppressed = EI.dedup_policy(recs)
        self.assertEqual(suppressed, 1, "the duplicate is suppressed from the analysis inventory")
        self.assertTrue(all(r["is_duplicate"] == 0 for r in analysis))


# ------------------------------------------------------------------ candidate / mapping tests
class TestGenerator(unittest.TestCase):
    def test_127_byte_input_maps_to_128(self):
        recs = analyzed([resp(129, size=127, ts=1.0)])
        r = [x for x in recs if x["role"] == "RESPONSE"][0]
        self.assertEqual(r[SZ], 127, "synthesized frame must be exactly 127 captured bytes")
        self.assertEqual(GC.map_state([128], r[SZ]), 128, "127 B must map UP to the 128 B target")
        self.assertEqual(GC.map_state([128], 128), 128)

    def test_larger_class0_multisegment_input_behavior(self):
        recs = analyzed([resp(129, size=300, ts=1.0)])
        r = [x for x in recs if x["role"] == "RESPONSE"][0]
        self.assertEqual(r[SZ], 300)
        # exceeds both P4 pad states -> unfit -> needs split / fail-open / larger state
        self.assertIsNone(GC.map_state([128, 256], 300))
        self.assertEqual(GC.map_state([128, 512], 300), 512, "a larger state covers it upward-only")
        self.assertEqual(GC.align_hw(300), 512)

    def test_canonical_filler_differs_combined_vs_separate(self):
        # corpus with BOTH a separate-ACK READ and a combined-ACK READ transaction
        pkts = [req(1, sport=40000, ts=1.0), pure_ack(frm="outstation", sport=40000, ts=1.1),
                resp(129, sport=40000, ts=1.2), pure_ack(frm="master", sport=40000, seq=15, ts=1.3),
                req(1, sport=41000, ts=2.0), resp(129, sport=41000, ts=2.1),
                pure_ack(frm="master", sport=41000, seq=16, ts=2.2)]
        recs = analyzed(pkts)
        sched = GC.build_schedules(recs, [128])
        read = sched["common_ackmode_hiding"]["READ"]
        self.assertTrue(read["observed"])
        out_ack = [s for s in read["slots"] if s["direction"] == "outstation_to_master" and s["role"] == "ACK"]
        self.assertEqual(len(out_ack), 1, "the canonical schedule carries an outstation-ACK slot")
        self.assertEqual(out_ack[0]["separate_ack"]["real_or_cover_eligibility"], "real")
        self.assertEqual(out_ack[0]["combined_ack"]["real_or_cover_eligibility"], "cover",
                         "combined-ACK must ADD the missing outstation ACK as a COVER slot")
        # combined per-mode schedule has FEWER real slots than separate -> filler IS required
        sep_slots = len(sched["per_mode_operation"]["separate_READ"]["slots"])
        comb_slots = len(sched["per_mode_operation"]["combined_READ"]["slots"])
        self.assertGreater(sep_slots, comb_slots)

    def test_corpus_specific_maximum_handling(self):
        small = [make_rec(direction="outstation_to_master", role="RESPONSE", size=s, capture_index=i)
                 for i, s in enumerate([66, 88, 100])]
        self.assertEqual(GC.corpus_max(small), 100)
        big = [make_rec(direction="outstation_to_master", role="RESPONSE", size=s, capture_index=i)
               for i, s in enumerate([66, 120, 200])]
        self.assertEqual(GC.corpus_max(big), 200)
        # a candidate's top state is derived from the corpus's OWN max, not a hardcoded 127
        self.assertEqual(GC.align_hw(GC.corpus_max(small)), 128)
        self.assertEqual(GC.align_hw(GC.corpus_max(big)), 256)

    def test_candidate_filename_matches_candidate_id(self):
        # a minimal but structurally complete base inventory in a temp dir
        recs = self._mini_corpus()
        with tempfile.TemporaryDirectory() as d:
            inv = os.path.join(d, "inv"); os.makedirs(inv)
            out = os.path.join(d, "cand")
            with open(os.path.join(inv, "base_analysis.json"), "w") as f:
                json.dump({"records": recs, "provenance": {}}, f)
            written = GC.run_scope("base", inv, out)
            self.assertTrue(written)
            for path in written:
                with open(path) as f:
                    cid = json.load(f)["candidate_id"]
                self.assertEqual(os.path.splitext(os.path.basename(path))[0], cid)

    def test_dry_run_schema_validation(self):
        recs = self._mini_corpus()
        cand = GC.build_candidate("single128_corpus_baseline", [128], "rule", "base corpus", recs, "base",
                                  tempfile.gettempdir())
        ok, problems = GC.validate_candidate_schema(cand)
        self.assertTrue(ok, "a well-formed candidate must validate: %s" % problems)
        bad = dict(cand); bad["unfit_packets"] = 3
        ok2, problems2 = GC.validate_candidate_schema(bad)
        self.assertFalse(ok2)
        self.assertTrue(any("unfit_packets" in p for p in problems2))

    @staticmethod
    def _mini_corpus():
        recs = []
        i = 0
        # separate-ACK READ + combined-ACK DIRECT_OPERATE across two flows
        seq = [("10.0.0.3:40000", "separate", [("master_to_outstation", "READ_REQUEST", 88, ""),
                                               ("outstation_to_master", "ACK", 66, ""),
                                               ("outstation_to_master", "RESPONSE", 120, "READ"),
                                               ("master_to_outstation", "ACK", 66, "")]),
               ("10.0.0.3:41000", "combined", [("master_to_outstation", "DIRECT_OPERATE_REQUEST", 101, ""),
                                               ("outstation_to_master", "RESPONSE", 103, "DIRECT_OPERATE"),
                                               ("master_to_outstation", "ACK", 66, "")])]
        for tid, (flow, am, slots) in enumerate(seq, start=1):
            for d, role, size, rt in slots:
                i += 1
                recs.append(make_rec(direction=d, role=role, size=size, response_to=rt,
                                     transaction_id=tid, flow=flow, ack_mode_observed=am,
                                     capture_index=i, ts=float(i),
                                     is_pure_ack=1 if role == "ACK" else 0))
        return recs


# ------------------------------------------------------------------ evaluation tests
class TestEvaluator(unittest.TestCase):
    def test_per_direction_overhead_correctness(self):
        # one combined READ transaction: req 88 (m->o), resp 120 (o->m), master ACK 66 (m->o)
        recs = [make_rec(direction="master_to_outstation", role="READ_REQUEST", size=88, capture_index=1, ts=1.0),
                make_rec(direction="outstation_to_master", role="RESPONSE", size=120, response_to="READ",
                         capture_index=2, ts=1.1),
                make_rec(direction="master_to_outstation", role="ACK", size=66, capture_index=3, ts=1.2,
                         is_pure_ack=1)]
        cand = {"size_states": [{"state": "S1", "target_frame_bytes": 128}]}
        ov = EV.overhead(cand, recs, txn_per_sec=1.0)
        co = ov["cover_off_padding_only"]
        # master padding = (128-88)+(128-66) = 102 ; outstation padding = 128-120 = 8
        self.assertEqual(co["master_to_outstation"]["bytes_per_txn"], 102)
        self.assertEqual(co["outstation_to_master"]["bytes_per_txn"], 8)
        # transaction-window adds a cover ACK frame (128 B) to the combined transaction's o->m side
        tw = ov["transaction_window_padding_plus_cover_ack"]
        self.assertEqual(tw["outstation_to_master"]["bytes_per_txn"], 8 + 128)
        self.assertEqual(ov["combined_fraction"], 1.0)

    def test_single_state_zero_mutual_information(self):
        recs = [make_rec(direction="master_to_outstation", role="READ_REQUEST", size=88,
                         device="SEL751", flow="f1", capture_index=1, ts=1.0),
                make_rec(direction="outstation_to_master", role="RESPONSE", size=120, response_to="READ",
                         device="SEL751", flow="f1", capture_index=2, ts=1.1),
                make_rec(direction="master_to_outstation", role="DIRECT_OPERATE_REQUEST", size=101,
                         device="AB1400", flow="f2", capture_index=3, ts=2.0),
                make_rec(direction="outstation_to_master", role="RESPONSE", size=103,
                         response_to="DIRECT_OPERATE", device="AB1400", flow="f2", capture_index=4, ts=2.1)]
        EV.annotate_operation(recs)
        states = [128]
        feat = [EV.map_state(states, r[SZ]) for r in recs]
        for target in ["device", "direction"]:
            labels = [r[target] for r in recs]
            self.assertEqual(EV.mutual_information_bits(feat, labels), 0.0,
                             "a constant size-state must leak 0 bits about %s" % target)

    def test_mutual_information_positive_when_size_separates(self):
        # two states that perfectly separate two labels -> MI == 1 bit
        feat = [64, 64, 128, 128]
        lab = ["A", "A", "B", "B"]
        self.assertAlmostEqual(EV.mutual_information_bits(feat, lab), 1.0, places=6)


if __name__ == "__main__":
    # warnings="ignore": the only warnings raised are ResourceWarnings from the frozen
    # extract_inventory.py PcapReader loop (unfixable here) — they carry no signal for these tests.
    unittest.main(verbosity=2, warnings="ignore")
