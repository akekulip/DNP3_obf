"""Main smoke identity, wrap and provenance regressions; no hardware access."""
import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'analysis'))
sys.path.insert(0,str(HERE))
import admission_record as ar
from test_case4_packet_parity import wire,FLOW,MS


class Cohort(unittest.TestCase):
    def test_committed_main_has_thirty_exchanges_excluding_precheck(self):
        c=ar.smoke_cohort()
        self.assertEqual(c['main_count'],30)
        self.assertEqual(c['precheck_count'],1)
        self.assertEqual(c['main_client_port'],38257)
        self.assertEqual(len(c['rows']),30)

    def test_full_flow_identity_and_tcp_end_wrap(self):
        flow=FLOW[:2]+(38257,20000)
        seq=0xfffffff0
        preflow=FLOW[:2]+(41461,20000)
        records=[(0,wire('REQ',flow=preflow)),(58*MS,wire('ACK',flow=preflow)),
          (59*MS,wire('RESP',flow=preflow)),
          (100*MS,wire('REQ',seq=seq,flow=flow)),
          (101*MS,wire('ACK',ack=4,flow=preflow)),
          (102*MS,wire('ACK',ack=4,flow=flow)),
          (103*MS,wire('RESP',ack=4,flow=flow))]
        c=ar.smoke_cohort(records=records,expected_count=1,main_client_port=38257)
        self.assertEqual(c['rows'],[(2.,3.,1.)])
        self.assertEqual(c['precheck_count'],1)

    def test_ambiguous_connection_cohort_is_refused(self):
        records=[]
        for client in (40000,40001):
            flow=FLOW[:2]+(client,20000)
            records.extend([(0,wire('REQ',flow=flow)),(MS,wire('ACK',flow=flow)),(2*MS,wire('RESP',flow=flow))])
        with self.assertRaises(ValueError):ar.smoke_cohort(records=records,expected_count=1)

    def test_current_candidate_does_not_inherit_baseline_timer_identity(self):
        inp=ar.build(10,target_build='case4-new-source')
        v=ar.da.evaluate(inp)
        self.assertEqual(inp.context.build_id,'case4-new-source')
        self.assertEqual(inp.anchor,'request')
        self.assertEqual(inp.master_rto_ms.provenance,ar.P.INHERITED_EARLIER_BUILD)
        self.assertEqual(inp.master_rto_ms.applies_to.build_id,ar.HISTORICAL_BUILD)
        self.assertEqual(inp.master_feedback_path_ms.provenance,ar.P.UNAVAILABLE)
        self.assertEqual(inp.switch_request_to_response_min_ms.provenance,ar.P.UNAVAILABLE)
        self.assertIsNone(v['recovery_hold_bound_ms'])
        self.assertEqual(v['verdict'],'provisional')

if __name__=='__main__':unittest.main()
