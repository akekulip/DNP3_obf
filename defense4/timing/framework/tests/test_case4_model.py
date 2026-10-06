"""Case 4 regressions; these establish model behavior, not switch behavior."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "model"))
from response_ready_model import Ev, ResponseReadyModel, due, to_tick

MS = 1_000_000


def request(t=0, **kw):
    return Ev(t, "REQ", **{**dict(epoch=1, seq=1000, length=22, app=5), **kw})


def ack(t=MS, **kw):
    return Ev(t, "ACK", **{**dict(epoch=1, ack=1022, app=5), **kw})


def response(t=2 * MS, **kw):
    return Ev(t, "RESP", **{**dict(epoch=1, ack=1022, app=5), **kw})


class Case4Recovery(unittest.TestCase):
    def run_model(self, events, gap=MS):
        return ResponseReadyModel(10 * MS, gap).run(events)

    def test_default_readiness_expiry_releases_ack_at_30_ms(self):
        result = self.run_model([request(), ack()])
        self.assertEqual([(o.t, o.reason) for o in result.find("ACK")],
                         [(30 * MS, "watchdog")])

    def test_wrong_epoch_fin_cannot_clear_an_active_owner(self):
        result = self.run_model([request(), ack(), Ev(2 * MS, "FIN", epoch=2), response(3 * MS)])
        self.assertEqual(result.counters, {"normal": 1})
        self.assertEqual([o.t for o in result.find("ACK")], [9_999_872])

    def test_fin_flushes_a_response_scheduled_after_ack_release(self):
        result = self.run_model([request(), ack(), response(), Ev(10_500_000, "FIN", epoch=1)])
        self.assertEqual([(o.t, o.reason) for o in result.find("RESP")],
                         [(10_500_000, "reset_flush")])
        self.assertEqual(result.counters, {"reset_flush": 1})

    def test_rst_flushes_held_traffic_and_allows_next_exchange(self):
        result = self.run_model([request(), ack(), response(), Ev(3 * MS, "RST", epoch=1),
                                 request(4 * MS, epoch=2), ack(5 * MS, epoch=2),
                                 response(6 * MS, epoch=2)])
        self.assertEqual(result.counters, {"reset_flush": 1, "normal": 1})
        self.assertEqual(result.state, "IDLE")

    def test_tcp_request_end_wraps_modulo_32_bits(self):
        result = self.run_model([request(seq=0xfffffff0), ack(ack=6), response(ack=6)])
        self.assertEqual(result.counters, {"normal": 1})

    def test_late_ready_response_keeps_full_8_ms_gap_after_ack(self):
        result = self.run_model([request(), ack(), response(29 * MS)], gap=8 * MS)
        self.assertEqual([(o.kind, o.t) for o in result.outs if o.kind != "REQ"],
                         [("ACK", 29 * MS), ("RESP", 37 * MS)])
        self.assertEqual(result.counters, {"normal": 1})

    def test_all_external_events_at_expiry_precede_watchdog(self):
        result = self.run_model([request(), ack(30 * MS), response(30 * MS)])
        self.assertEqual(result.counters, {"normal": 1})
        self.assertEqual([o.t for o in result.find("RESP")], [30_999_936])

    def test_reset_never_repeats_already_forwarded_legacy_ack(self):
        result = ResponseReadyModel(10 * MS, MS, policy="response_focused").run([
            request(), ack(), response(1_500_000), Ev(1_700_000, "FIN", epoch=1)])
        self.assertEqual([(o.t, o.reason) for o in result.find("ACK")], [(MS, "forwarded")])

    def test_time_comparison_uses_low32_masked_nanoseconds(self):
        self.assertEqual(to_tick((1 << 32) - 1), 0xffffff00)
        self.assertEqual(to_tick(1 << 32), 0)
        self.assertFalse(due(to_tick((1 << 32) - 256), to_tick(256)))
        self.assertTrue(due(to_tick((1 << 32) + 256), to_tick(256)))


class ExplicitDrain(unittest.TestCase):
    def test_reset_with_missing_original_prevents_rearm(self):
        events = [request(reset_seq=9000), ack(), response(),
                  Ev(3 * MS, "RST", epoch=1, seq=9000, reset_validated=True),
                  request(4 * MS, epoch=2),
                  Ev(5 * MS, "DRAIN_COMPLETE", epoch=1, owner_cookie=1),
                  request(6 * MS, epoch=2)]
        result = ResponseReadyModel(10 * MS, MS, deferred_returns=True).run(events)
        self.assertEqual(result.state, "QUARANTINED")
        self.assertEqual(result.counters["bypass_busy"], 2)
        self.assertEqual(result.counters["drain_incomplete"], 1)

    def test_terminal_originals_and_cookie_qualified_completion_enable_rearm(self):
        events = [request(), ack(), response(),
                  Ev(3 * MS, "RST", epoch=1),
                  Ev(4 * MS, "TERMINAL_ACK", epoch=1, owner_cookie=2),
                  Ev(5 * MS, "TERMINAL_ACK", epoch=1, owner_cookie=1),
                  Ev(6 * MS, "TERMINAL_ACK", epoch=1, owner_cookie=1),
                  Ev(7 * MS, "TERMINAL_RESP", epoch=1, owner_cookie=1),
                  Ev(8 * MS, "DRAIN_COMPLETE", epoch=1, owner_cookie=2),
                  Ev(9 * MS, "DRAIN_COMPLETE", epoch=1, owner_cookie=1),
                  request(10 * MS, epoch=2)]
        result = ResponseReadyModel(10 * MS, MS, deferred_returns=True).run(events)
        self.assertEqual(result.counters["drain_complete"], 1)
        self.assertEqual(result.find("REQ")[-1].reason, "forwarded")
        self.assertEqual(result.counters["drain_stale"], 2)

    def test_reset_requires_supported_validated_sequence_when_bound(self):
        for bad in (dict(seq=9001, reset_validated=True),
                    dict(seq=9000, reset_validated=False),
                    dict(seq=9000, reset_validated=True, supported=False)):
            with self.subTest(bad=bad):
                result = ResponseReadyModel(10 * MS, MS).run([
                    request(reset_seq=9000), ack(), response(),
                    Ev(3 * MS, "FIN", epoch=1, **bad)])
                self.assertEqual(result.counters, {"normal": 1})


class PacketAssociation(unittest.TestCase):
    def event(self, kind, t, **changes):
        values = dict(epoch=1, flow=("192.0.2.1", "192.0.2.2", 30001, 20000),
                      seq=1000 if kind == "REQ" else 4000, length=45,
                      ack=1061, app=15, operation="SELECT")
        if kind == "REQ":
            values.update(response_seq=4000, transformed_length=61)
        return Ev(t, kind, **{**values, **changes})

    def test_actual_packet_identity_rejects_each_wrong_input(self):
        for change in (dict(flow=("192.0.2.3", "192.0.2.2", 30001, 20000)),
                       dict(operation="OPERATE"), dict(seq=4001), dict(app=0),
                       dict(epoch=2), dict(ack=1045)):
            with self.subTest(change=change):
                result = ResponseReadyModel(10 * MS, MS).run([
                    self.event("REQ", 0), self.event("ACK", MS),
                    self.event("RESP", 2 * MS, **change), self.event("RESP", 3 * MS)])
                self.assertEqual(result.counters, {"stale_response": 1, "normal": 1})
                self.assertEqual(result.find("RESP")[0].reason, "stale_forwarded")

    def test_wrong_flow_ack_cannot_make_response_ready(self):
        result = ResponseReadyModel(10 * MS, MS).run([
            self.event("REQ", 0), self.event("ACK", MS, flow=("other", "flow", 1, 2)),
            self.event("RESP", 2 * MS)])
        self.assertEqual(result.counters, {"ack_unmatched": 1, "fallback_no_ack": 1})

    def test_wrong_flow_rst_cannot_retire_owner(self):
        result = ResponseReadyModel(10 * MS, MS).run([
            self.event("REQ", 0), self.event("ACK", MS),
            self.event("RST", 2 * MS, flow=("other", "flow", 1, 2)),
            self.event("RESP", 3 * MS)])
        self.assertEqual(result.counters, {"normal": 1})

    def test_unsupported_response_does_not_satisfy_readiness(self):
        result = ResponseReadyModel(10 * MS, MS).run([
            self.event("REQ", 0), self.event("ACK", MS),
            self.event("RESP", 2 * MS, supported=False)])
        self.assertEqual(result.counters, {"bypass_unsupported": 1, "fallback_no_response": 1})

    def test_app_wrap_is_new_association_after_prior_completion(self):
        result = ResponseReadyModel(10 * MS, MS).run([
            self.event("REQ", 0), self.event("ACK", MS), self.event("RESP", 2 * MS),
            self.event("REQ", 20 * MS, seq=1061, app=0),
            self.event("ACK", 21 * MS, ack=1122, app=0),
            self.event("RESP", 22 * MS, ack=1122, app=15),
            self.event("RESP", 23 * MS, ack=1122, app=0)])
        self.assertEqual(result.counters, {"normal": 2, "stale_response": 1})


if __name__ == "__main__":
    unittest.main()
