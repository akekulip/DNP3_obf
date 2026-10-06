"""Request anchoring requires switch and recovery bounds, entirely offline."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_delay_admission import inputs,b,check
from delay_admission import Provenance,evaluate


def request_inputs(**over):
    values=dict(anchor='request',
        switch_request_to_ack_min_ms=b('switch_request_to_ack_min_ms',2),
        switch_request_to_ack_max_ms=b('switch_request_to_ack_max_ms',3),
        switch_request_to_response_min_ms=b('switch_request_to_response_min_ms',4),
        switch_request_to_response_max_ms=b('switch_request_to_response_max_ms',29),
        readiness_expiry_ms=b('readiness_expiry_ms',30,Provenance.OPERATOR_SUPPLIED),
        completion_timeout_ms=b('completion_timeout_ms',35,Provenance.OPERATOR_SUPPLIED),
        heartbeat_interval_ms=b('heartbeat_interval_ms',0.15),
        physical_drain_ms=b('physical_drain_ms',2))
    values.update(over)
    return inputs(**values)


class RequestAnchor(unittest.TestCase):
    def test_legacy_formula_is_explicitly_native_ack(self):
        v=evaluate(inputs())
        self.assertEqual(v['policy']['anchor'],'native_ack')
        self.assertIn('ACK',v['response_hold_formula'])
        self.assertEqual(v['response_hold_ms'],23)

    def test_missing_switch_or_recovery_measurements_are_not_zero(self):
        v=evaluate(inputs(anchor='request'))
        self.assertEqual(v['verdict'],'provisional')
        self.assertIsNone(v['response_hold_ms'])
        self.assertIsNone(v['recovery_hold_bound_ms'])
        self.assertIn('switch_request_to_response_min_ms',v['unknown_inputs'])
        self.assertIn('physical_drain_ms',v['unknown_inputs'])
        self.assertIsNone(check(v,'outstation')['ok'])

    def test_ready_population_bound_contains_full_gap_and_late_response(self):
        v=evaluate(request_inputs())
        self.assertEqual(v['response_hold_ms'],20)
        self.assertEqual(v['ack_hold_ms'],27)
        self.assertAlmostEqual(v['recovery_hold_bound_ms'],37.1517)
        self.assertEqual(check(v,'master TCP')['terms_ms']['ack_hold_D_A'],27)

    def test_recovery_cap_includes_heartbeat_release_and_physical_drain(self):
        v=evaluate(request_inputs(physical_drain_ms=b('physical_drain_ms',6)))
        self.assertEqual(v['verdict'],'refused')
        self.assertFalse(v['policy_cap']['ok'])

    def test_recovery_must_fit_timers_even_when_ready_exchange_fits(self):
        v=evaluate(request_inputs(master_rto_ms=b('master_rto_ms',36)))
        self.assertTrue(check(v,'master TCP')['ok'])
        recovery=[c for c in v['checks'] if c['constraint']=='master TCP recovery'][0]
        self.assertFalse(recovery['ok'])
        self.assertEqual(v['verdict'],'refused')

    def test_unknown_native_interval_is_not_substituted_for_switch_response(self):
        v=evaluate(request_inputs(switch_request_to_response_min_ms=None))
        self.assertEqual(v['verdict'],'provisional')
        self.assertIsNone(v['response_hold_ms'])

    def test_invalid_anchor_and_inverted_intervals_rejected(self):
        self.assertEqual(evaluate(inputs(anchor='anything'))['verdict'],'rejected')
        v=evaluate(request_inputs(switch_request_to_response_min_ms=b('switch_request_to_response_min_ms',31)))
        self.assertEqual(v['verdict'],'rejected')

if __name__=='__main__':unittest.main()
