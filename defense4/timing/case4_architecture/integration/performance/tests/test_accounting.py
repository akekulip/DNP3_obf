import importlib
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
    api=importlib.import_module('accounting')
except ModuleNotFoundError:
    api=None


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api,'bounded workload/pass accounting is not implemented')

    def test_original_workload_counts_every_attempt_without_retries(self):
        w=api.load_workload()
        self.assertEqual((w['blocks'],w['attempts'],w['ceiling']),(44,16168,18360))
        self.assertEqual(w['counts'],{'READ':12868,'SELECT':3240,'OPERATE':60})
        self.assertEqual(w['trial_units'],16108)
        self.assertEqual(w['spacing_ms'],6443200)
        self.assertEqual(w['max_duration_ms'],14571200)
        self.assertTrue(all(r['interval_ms']==400 for r in w['rows']))

    def test_l1_wire_accounting_includes_padding_fcs_preamble_and_gap(self):
        self.assertEqual(api.wire_bytes(0),84)
        self.assertEqual(api.wire_bytes(35),113)
        self.assertEqual(api.normal_wire_bytes('SELECT',False),624)
        self.assertEqual(api.normal_wire_bytes('SELECT',True),762)
        self.assertEqual(api.normal_wire_bytes('READ',False),618)
        self.assertEqual(api.normal_wire_bytes('READ',True),696)
        for value in (-1,True,1.5):
            with self.assertRaises(ValueError):api.wire_bytes(value)

    def layout(self):
        return dict(name='bounded fixture',family='bounded_resubmit',authority_pipe=0,
            resubmit_bytes=8,paths={name:dict(passes=passes,internal_transfers=[])
                for name,passes in [('read_request',1),('control_request',3),('tcp_ack',2),
                    ('read_response',2),('control_response',3),('replay_request',2),('fragment_piece',2)]})

    def test_transform_replay_fragment_work_stays_separate_from_waiting(self):
        r=api.account(api.load_workload(),self.layout())
        self.assertEqual(r['path_passes']['control_request'],3)
        self.assertEqual(r['path_passes']['replay_request'],2)
        self.assertEqual(r['path_passes']['fragment_piece'],2)
        self.assertIsNone(r['holding']['internal_wire_bytes'])
        self.assertIsNone(r['worst_campaign_wire_bytes'])
        self.assertEqual(r['heartbeat']['requested_packets_per_second'],10000)
        self.assertFalse(r['complete_fit_verified'])

    def test_absent_transform_path_does_not_become_zero_internal_cost(self):
        result=api.account(api.load_workload(),dict(name='unknown',family='same_pipe',authority_pipe=0,paths={}))
        self.assertIsNone(result['normal_processing_passes'])
        self.assertIsNone(result['normal_internal_wire_bytes'])

    def test_measured_loop_inputs_expose_bandwidth_competition(self):
        r=api.account(api.load_workload(),self.layout(),holding=dict(
            frame_bytes=64,loop_period_us=2,token_copies=3,hold_ms=40,
            source='explicit engineering scenario, not measured target'),heartbeat_frame_bytes=64)
        self.assertEqual(r['holding']['packets_per_exchange'],60000)
        self.assertEqual(r['heartbeat']['requested_bits_per_second'],6720000)
        self.assertGreater(r['holding']['internal_wire_bytes'],0)
        self.assertEqual(r['holding']['evidence_kind'],'scenario')

    def test_cross_pipe_needs_actual_ports_and_return_authority(self):
        layout=self.layout();layout.update(family='cross_pipe',destination_pipe=1)
        r=api.account(api.load_workload(),layout)
        self.assertIn('physical_handoff_ports',r['capability_blockers'])
        self.assertIn('return_to_authority',r['capability_blockers'])
        self.assertFalse(r['complete_fit_verified'])
        layout['shared_state_assumed']=True
        with self.assertRaises(ValueError):api.account(api.load_workload(),layout)

    def test_additional_repair_and_fragment_packets_do_not_allocate_trials(self):
        self.assertIn('additional_packets', inspect.signature(api.account).parameters)
        events = dict(source='explicit additional-packet scenario', rows=[
            dict(path='replay_request', count=2, external_payload_bytes=[1,55]),
            dict(path='fragment_piece', count=3, external_payload_bytes=[12]),
        ])
        result = api.account(api.load_workload(), self.layout(), additional_packets=events)
        extra = result['additional_packets']
        self.assertEqual(extra['processing_passes'], 10)
        self.assertEqual(extra['external_wire_bytes'], 2*(84+133)+3*90)
        self.assertEqual(extra['internal_wire_bytes'], 0)
        self.assertEqual(result['workload']['attempts'], 16168)
        self.assertIsNone(result['worst_campaign_wire_bytes'])
        self.assertEqual(extra['evidence_kind'], 'scenario')

    def test_missing_repair_frequency_is_unavailable_and_invalid_extra_path_refuses(self):
        result = api.account(api.load_workload(), self.layout())
        self.assertIn('additional_packets', result)
        self.assertIsNone(result['additional_packets']['external_wire_bytes'])
        with self.assertRaises(ValueError):
            api.account(api.load_workload(), self.layout(), additional_packets=dict(
                source='scenario', rows=[dict(path='control_request', count=1, external_payload_bytes=[55])]))

    def test_pass_budget_and_workref_are_bounded(self):
        for key,value in [('resubmit_bytes',12),('authority_pipe',-1)]:
            bad=self.layout();bad[key]=value
            with self.assertRaises(ValueError):api.account(api.load_workload(),bad)
        bad=self.layout();bad['paths']['control_request']['passes']=0
        with self.assertRaises(ValueError):api.account(api.load_workload(),bad)

    def test_true_recirculation_counts_actual16_and48_byte_envelopes(self):
        self.assertIn('bounded_recirculation',api.FAMILIES)
        layout=dict(family='bounded_recirculation',authority_pipe=0,
            recirculation_envelope_bytes=16,paths={name:dict(passes=1,internal_transfers=[])
                for name in api.PATHS})
        layout['paths']['control_request']['internal_transfers']=[dict(
            link='private recirculation scenario',inner_frame_bytes=93,envelope_bytes=16,count=3)]
        result=api.account(api.load_workload(),layout)
        self.assertEqual(result['normal_internal_wire_bytes'],3300*3*(93+16+20))
        layout['paths']['control_request']['internal_transfers'][0]['envelope_bytes']=48
        result=api.account(api.load_workload(),layout)
        self.assertEqual(result['normal_internal_wire_bytes'],3300*3*(93+48+20))
        self.assertIsNone(result['authority']['workref_bytes'])
        self.assertFalse(result['complete_fit_verified'])

    def test_cross_pipe_does_not_implicitly_require_an8_byte_physical_handoff(self):
        try:
            result=api.account(api.load_workload(),dict(family='cross_pipe',authority_pipe=0,
                destination_pipe=1,recirculation_envelope_bytes=48,paths={}))
        except ValueError as exc:
            self.fail(str(exc))
        self.assertEqual(result['authority']['recirculation_envelope_bytes'],48)
        self.assertIsNone(result['normal_internal_wire_bytes'])

    def test_inband_header_must_not_double_count_a_pre_serialized_frame(self):
        layout=self.layout()
        layout['paths']['control_request']['internal_transfers']=[dict(
            link='ambiguous',frame_bytes=109,envelope_bytes=16,count=3)]
        with self.assertRaises(ValueError):api.account(api.load_workload(),layout)

    def test_report_output_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'result.json';api.write_report(p,{'kind':'fixture'})
            original=p.read_bytes()
            with self.assertRaises(FileExistsError):api.write_report(p,{})
            self.assertEqual(p.read_bytes(),original)

if __name__=='__main__':unittest.main()
