#!/usr/bin/env python3
"""test_trace_harness.py — OFFLINE tests for the trace size-normalization harness.

Run:  $RESEARCH_PYTHON test_trace_harness.py       (or: python3 test_trace_harness.py)

No switch, no SDE, no root, no network. Covers:
  1. framing: build_trace_frame / mb_trace_gen framing -> physical size == input + 19 B, with
     input_size_class at the documented offset (frame byte 23), for all 13 sizes; the unsupported
     oversize probe; campaign apportionment; smoke plan counts.
  2. analyzer: flags wrong-size / loss / reorder / missing, and reports MI ~ 0 when every output
     is 128 (vs non-zero native MI that normalization removed).
  3. collector: check_completeness VALID/invalid logic on synthetic digest lists.
"""
import os
import struct
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import mb_trace_gen as gen
import mb_trace_analyze as ana
from mb_trace_collector import check_completeness
from queue_microbench_trace_setup import build_trace_frame, INPUT_SIZES, ETHERTYPE_TRACE

IN_SIZE_OFFSET = 23   # 14 (eth) + 9 (run_id2+seq4+dev1+op1+dir1) — documented datapath-key offset


# ------------------------------------------------------------------ pcap helper (classic libpcap)
def _eth_frame(size, ethertype):
    """A frame of exactly `size` bytes: dst(6)+src(6)+ethertype(2)+body."""
    assert size >= 14
    body = b"\x00" * (size - 14)
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", ethertype) + body


def _write_pcap(path, frames):
    """frames: list of (size, ethertype). Writes a little-endian classic libpcap file."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))  # global header
        for i, (size, et) in enumerate(frames):
            pkt = _eth_frame(size, et)
            f.write(struct.pack("<IIII", i, 0, len(pkt), len(pkt)))
            f.write(pkt)


def _rec(seq, input_size, device=1, op=1, direction=1, run_id=1, t=None,
         target_size=128, selected_state=1):
    return {"run_id": run_id, "seq": seq, "input_size": input_size, "target_size": target_size,
            "selected_state": selected_state, "device_label": device, "operation_label": op,
            "direction": direction, "transaction_id": seq, "ingress_tstamp": (seq if t is None else t),
            "release_tstamp": (seq if t is None else t), "hold_ns": 0,
            "release_reason": "SIZE_NORM", "qid": 1}


# ------------------------------------------------------------------ 1. framing
class TestFraming(unittest.TestCase):
    def test_physical_size_and_offset_all_13(self):
        for s in INPUT_SIZES:
            f = build_trace_frame(s, seq=s, run_id=7, device_label=3, operation_label=2,
                                  direction=1, transaction_id=11, ack_mode=2)
            self.assertEqual(len(f), s + 19, "size mismatch for %d" % s)
            self.assertEqual(f[IN_SIZE_OFFSET], s, "input_size_class not at offset 23 for %d" % s)
            self.assertEqual(struct.unpack_from("!H", f, 12)[0], ETHERTYPE_TRACE)
        self.assertEqual(len(INPUT_SIZES), 13)

    def test_gen_framing_matches(self):
        for s in INPUT_SIZES:
            spec = {"size": s, "device": "SEL751", "op": "READ", "dir": "in",
                    "ack": "separate", "supported": True}
            f = gen._spec_to_frame(spec, seq=1, run_id=1, tx_tstamp=0)
            self.assertEqual(len(f), s + 19)
            self.assertEqual(f[IN_SIZE_OFFSET], s)

    def test_unsupported_oversize_frame(self):
        f = gen.build_unsupported_frame(200, seq=5, run_id=900)
        self.assertEqual(len(f), 200 + 19)
        self.assertEqual(f[IN_SIZE_OFFSET], 200)
        self.assertEqual(struct.unpack_from("!H", f, 12)[0], ETHERTYPE_TRACE)

    def test_build_trace_frame_rejects_unsupported(self):
        with self.assertRaises(ValueError):
            build_trace_frame(200)
        with self.assertRaises(ValueError):
            build_trace_frame(61)

    def test_smoke_plan_counts(self):
        args = gen.parse_args(["--smoke", "--dry-run", "--run-id", "900"])
        # replicate run_smoke's plan/send without printing noise
        plan = [dict(s) for s in gen.SMOKE_SPECS]
        sent, per_size, _ = gen.send_plan(plan, None, args.run_id, 0, True)
        self.assertEqual(sent, 6)
        self.assertEqual(dict(per_size), {60: 1, 66: 1, 89: 1, 120: 2, 200: 1})

    def test_campaign_apportion_and_plan(self):
        camp = gen.load_campaign(gen.DEFAULT_CAMPAIGN)
        alloc = gen.apportion([e["count"] for e in camp["distribution"]], 800)
        self.assertEqual(sum(alloc), 800)
        plan = gen.build_campaign_plan(camp, 800, seed=1234)
        self.assertEqual(len(plan), 800)
        for spec in plan:                       # every campaign frame is a supported size
            self.assertIn(spec["size"], INPUT_SIZES)
        # deterministic for a fixed seed
        plan2 = gen.build_campaign_plan(camp, 800, seed=1234)
        self.assertEqual([p["size"] for p in plan], [p["size"] for p in plan2])


# ------------------------------------------------------------------ 2. analyzer
class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mbtrace_")
        # device 1 -> sizes {60,76}; device 2 -> {115,120}  => input_size leaks device natively
        self.records = []
        seq = 0
        for dev, sizes in ((1, [60, 76]), (2, [115, 120])):
            for s in sizes:
                for _ in range(5):
                    self.records.append(_rec(seq, s, device=dev, op=(1 if dev == 1 else 4),
                                             direction=(1 if dev == 1 else 2), t=seq))
                    seq += 1
        self.n = len(self.records)

    def _pcap(self, frames):
        p = os.path.join(self.tmp, "c.pcap")
        _write_pcap(p, frames)
        return p

    def test_happy_pass_and_mi(self):
        pcap = self._pcap([(128, 0x0800)] * self.n)
        r = ana.analyze(ana.read_pcap(pcap), self.records, tx_expected=self.n)
        self.assertTrue(r["PASS"], r["checks"])
        self.assertTrue(r["checks"]["all_outputs_128B"])
        self.assertTrue(r["checks"]["loss_ok_rx_eq_tx"])
        self.assertTrue(r["checks"]["reorder_ok"])
        self.assertEqual(r["shaped_size_histogram"], {128: self.n})
        mi = r["mutual_information"]
        self.assertAlmostEqual(mi["shaped_MI_outputsize_device_bits"], 0.0, places=9)
        self.assertAlmostEqual(mi["shaped_MI_outputsize_operation_bits"], 0.0, places=9)
        self.assertGreater(mi["native_MI_inputsize_device_bits"], 0.0)   # leakage existed natively
        self.assertTrue(r["checks"]["leakage_removed"])

    def test_flag_wrong_size(self):
        frames = [(128, 0x0800)] * (self.n - 1) + [(130, 0x0800)]   # one 130 B output
        r = ana.analyze(ana.read_pcap(self._pcap(frames)), self.records, tx_expected=self.n)
        self.assertFalse(r["PASS"])
        self.assertFalse(r["checks"]["all_outputs_128B"])
        self.assertEqual(r["checks"]["unexpected_output_sizes"], [130])

    def test_flag_loss(self):
        frames = [(128, 0x0800)] * (self.n - 3)      # fewer outputs than records
        r = ana.analyze(ana.read_pcap(self._pcap(frames)), self.records, tx_expected=self.n)
        self.assertFalse(r["PASS"])
        self.assertFalse(r["checks"]["loss_ok_rx_eq_tx"])
        self.assertEqual(r["counts"]["normalized_outputs"], self.n - 3)

    def test_flag_reorder(self):
        recs = [_rec(0, 60, t=0), _rec(1, 76, t=1), _rec(3, 115, t=2), _rec(2, 120, t=3)]
        pcap = self._pcap([(128, 0x0800)] * 4)
        r = ana.analyze(ana.read_pcap(pcap), recs, tx_expected=4)
        self.assertFalse(r["PASS"])
        self.assertFalse(r["checks"]["reorder_ok"])

    def test_flag_missing_seq(self):
        recs = [_rec(0, 60, t=0), _rec(1, 76, t=1), _rec(3, 115, t=2)]   # seq 2 missing
        pcap = self._pcap([(128, 0x0800)] * 3)
        r = ana.analyze(ana.read_pcap(pcap), recs, tx_expected=3)
        self.assertFalse(r["PASS"])
        self.assertFalse(r["checks"]["reorder_ok"])
        self.assertEqual(r["per_run"][1]["missing_seq"], 1)

    def test_wrapping_tstamp_not_reorder(self):
        # ingress_tstamp is a 32-bit ns counter that wraps mid-run; in-order seq across a
        # wrap boundary must NOT be flagged as a reorder (regression: sorting on the raw
        # wrapped value used to scramble order and fail reorder_ok on clean HW runs).
        ts = [0xFFFFFF00, 0xFFFFFFF0, 0x00000010, 0x00000100, 0x00000200]  # increasing, wraps once
        recs = [_rec(i, 60, t=ts[i]) for i in range(5)]
        pcap = self._pcap([(128, 0x0800)] * 5)
        r = ana.analyze(ana.read_pcap(pcap), recs, tx_expected=5)
        self.assertTrue(r["checks"]["reorder_ok"])
        self.assertTrue(r["per_run"][1]["monotonic"])
        self.assertTrue(r["PASS"])

    def test_passthrough_not_counted_as_output(self):
        # a fail-open 0x88B7 frame must NOT count as a normalized output
        frames = [(128, 0x0800)] * self.n + [(219, ETHERTYPE_TRACE)]
        r = ana.analyze(ana.read_pcap(self._pcap(frames)), self.records, tx_expected=self.n)
        self.assertEqual(r["counts"]["normalized_outputs"], self.n)
        self.assertEqual(r["counts"]["failopen_passthrough"], 1)
        self.assertTrue(r["PASS"])

    def test_per_direction_overhead(self):
        pcap = self._pcap([(128, 0x0800)] * self.n)
        r = ana.analyze(ana.read_pcap(pcap), self.records, tx_expected=self.n)
        # direction 1 = device 1's frames {60,76}: pad = (128-60)+(128-76) per pair
        d1 = r["per_direction_overhead"][1]
        self.assertEqual(d1["sum_output"], 128 * d1["n"])
        self.assertEqual(d1["pad_bytes_total"], d1["sum_output"] - d1["sum_input"])


# ------------------------------------------------------------------ 3. collector completeness
class TestCompleteness(unittest.TestCase):
    def _recs(self, n):
        return [_rec(i, INPUT_SIZES[i % len(INPUT_SIZES)]) for i in range(n)]

    def test_valid(self):
        recs = self._recs(10)
        r = check_completeness(recs, released_delta=10, digest_emit_delta=10, expect=10)
        self.assertTrue(r["VALID"], r)

    def test_counter_mismatch_invalid(self):
        recs = self._recs(10)
        self.assertFalse(check_completeness(recs, 9, 10, expect=10)["VALID"])
        self.assertFalse(check_completeness(recs, 10, 11, expect=10)["VALID"])

    def test_expect_mismatch_invalid(self):
        recs = self._recs(10)
        self.assertFalse(check_completeness(recs, 10, 10, expect=11)["VALID"])

    def test_dup_seq_invalid(self):
        recs = self._recs(10)
        recs[5]["seq"] = 4                       # duplicate seq 4
        r = check_completeness(recs, 10, 10, expect=10)
        self.assertFalse(r["VALID"])
        self.assertEqual(r["dup_seq"], 1)

    def test_missing_seq_invalid(self):
        recs = self._recs(10)
        recs[5]["seq"] = 99                       # gap: 5 missing, 99 outside range
        r = check_completeness(recs, 10, 10, expect=10)
        self.assertFalse(r["VALID"])
        self.assertGreater(r["missing_seq"], 0)

    def test_bad_target_or_state_invalid(self):
        recs = self._recs(10)
        recs[3]["target_size"] = 64
        self.assertFalse(check_completeness(recs, 10, 10, expect=10)["VALID"])
        recs2 = self._recs(10)
        recs2[3]["selected_state"] = 2
        self.assertFalse(check_completeness(recs2, 10, 10, expect=10)["VALID"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
