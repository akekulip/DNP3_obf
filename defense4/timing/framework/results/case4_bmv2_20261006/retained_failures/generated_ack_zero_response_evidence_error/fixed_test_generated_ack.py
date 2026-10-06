"""Phase 7: a switch-generated ACK for a combined-ACK device, in software, against real kernel TCP stacks.

Software-only prototype on BMv2 (mode 3). Nothing here is sent to any physical relay and nothing here is a hardware
claim. The outstation is `--combined` (delayed ACK: its acknowledgment rides the response); the generated ACK is the
switch speaking for it. Skips when the BMv2 toolchain or user namespaces are unavailable.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_bmv2_artifact import available, lab, MS  # noqa: E402

GEN = dict(mode=3, da_us=0, budget=1000, loop_pps=20000, combined=True)


def per_request(run):
    """Group the master-port view by request: the request, the packets toward the master until the next request."""
    rows = run["master_view"]
    reqs = [i for i, r in enumerate(rows) if r["from"] == "M" and r["len"] > 0]
    out = []
    for n, i in enumerate(reqs):
        end = reqs[n + 1] if n + 1 < len(reqs) else len(rows)
        out.append((rows[i], [r for r in rows[i + 1:end] if r["from"] == "O"]))
    return out


@unittest.skipUnless(available(), "BMv2 toolchain or user namespaces unavailable")
class GeneratedAck(unittest.TestCase):
    def test_the_generated_ack_is_accepted_and_is_a_separate_packet(self):
        run = lab("step5", gap_us=2000, latency_ms=2.0, count=3, **GEN)
        self.assertTrue(all(o == "OK" for o in run["outcomes"]), run["outcomes"])
        self.assertTrue(all(r["csum_ok"] for r in run["master_view"]), "every packet, generated ones included, has valid checksums")
        for req, resp in per_request(run)[1:]:                  # the first transaction has Linux's connection-start quick-ack
            end = req["seq"] + req["len"]
            pure = [r for r in resp if r["len"] == 0 and r["ack"] == end]
            data = [r for r in resp if r["len"] > 0]
            self.assertEqual(len(pure), 1, "exactly one separate ACK, and it is the generated one")
            self.assertEqual(len(data), 1)
            self.assertLess(pure[0]["t"], data[0]["t"])
            self.assertLess(pure[0]["t"] - req["t"], 2.5 * MS, "the ACK follows the request almost at once")

    def test_loss_after_the_switch_cannot_be_repaired_once_the_switch_has_acknowledged(self):
        control = lab("step5", mode=0, dropreq=1, combined=True, latency_ms=2.0, count=1, budget_ms=3000)
        self.assertEqual(control["outcomes"], ["OK"], "without generation the master retransmits and the READ completes")
        self.assertGreater(control["elapsed_ms"][0], 150, "...after one retransmission timeout")
        gen = lab("step5", gap_us=2000, latency_ms=2.0, count=1, dropreq=1, budget_ms=3000, **GEN)
        self.assertEqual(gen["outcomes"], ["TIMEOUT"], "with generation nothing repairs the loss: bytes were acknowledged that were never delivered")
        self.assertEqual(gen["endpoint_responses"], [], "an acknowledged request lost downstream produces no endpoint response events")
        reqs = [r for r in gen["master_view"] if r["from"] == "M" and r["len"] > 0]
        self.assertEqual(len(reqs), 1, "the master never retransmits a request that was acknowledged")

    def test_a_new_clrt_channel_exposes_response_latency_unless_the_response_is_scheduled(self):
        def clrt(latency_ms, gap_us):
            run = lab("step5", gap_us=gap_us, latency_ms=latency_ms, count=3, **GEN)
            self.assertTrue(all(o == "OK" for o in run["outcomes"]))
            vals = []
            for req, resp in per_request(run)[1:]:
                end = req["seq"] + req["len"]
                ack = next(r for r in resp if r["len"] == 0 and r["ack"] == end)
                data = next(r for r in resp if r["len"] > 0)
                vals.append((data["t"] - ack["t"]) / MS)
            return sum(vals) / len(vals)
        raw = [clrt(l, 0) for l in (2.0, 6.0, 12.0)]
        held = [clrt(l, 15000) for l in (2.0, 6.0, 12.0)]
        # unscheduled: CLRT_new tracks the device's response latency one for one (slope ~1) -- a channel that did not exist
        self.assertGreater(raw[2] - raw[0], 8.0)
        # scheduled to an ACK-relative deadline longer than any latency: the spread collapses
        self.assertLess(max(held) - min(held), 1.5)
        self.assertGreater(min(held), 14.0)


if __name__ == "__main__":
    unittest.main()
