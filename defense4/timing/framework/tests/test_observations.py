"""Current internal timestamps never become physical departure or SBO acceptance."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis'))
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
IDENTITY = dict(source_sha256='a'*64, instrument_sha256='b'*64, schema_sha256='c'*64,
    build_id='instrument-build', connection_id='trial-1', operation_profile_sha256='d'*64)


def sample(event, timestamp, **over):
    result = dict(transaction_id='1', owner_cookie=0x80000001, operation='SELECT', app_seq=3,
        connection_cookie=5, src_ipv4=0x0a000001, dst_ipv4=0x0a000002, sport=50000,dport=20000,
        event=event, timestamp_ns=timestamp, clock_domain='switch_ingress', clock_width_bits=32,
        marker_mask=0xff, endpoint='ingress', evidence_kind='observed')
    result.update(over)
    return result


class Observations(unittest.TestCase):
    def load(self, samples, **over):
        import observations
        record = dict(version=1, identity=IDENTITY, observed_at='2026-10-06T00:00:00Z', samples=samples)
        record.update(over)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'observations.json'
            path.write_text(json.dumps(record))
            return observations.load_observations(path, IDENTITY)

    def test_masked_wrap_is_decoded_without_claiming_wire_departure(self):
        result = self.load([sample('ack_deadline', 0xffffff01), sample('ack_commit', 0x101)])
        interval = result.interval('1', 'ack_deadline', 'ack_commit')
        self.assertEqual(interval['value_ns'], 512)
        self.assertEqual(interval['quantity'], 'internal interval')
        self.assertIsNone(result.interval('1', 'ack_deadline', 'ack_wire_departure')['value_ns'])

    def test_missing_physical_drain_remains_unavailable(self):
        result = self.load([sample('ack_deadline', 1), sample('blocker_termination', 513)])
        self.assertIsNone(result.interval('1', 'ack_deadline', 'queue_drained')['value_ns'])
        self.assertEqual(result.interval('1', 'ack_deadline', 'blocker_termination')['value_ns'], 512)

    def test_different_clock_or_owner_cannot_be_subtracted(self):
        for field, value in [('clock_domain', 'capture_master'), ('owner_cookie', 0x80000002),
                             ('app_seq', 4), ('operation', 'OPERATE'),('connection_cookie',6),('sport',50001)]:
            result = self.load([sample('ack_deadline', 1), sample('ack_commit', 513, **{field:value})])
            self.assertIsNone(result.interval('1', 'ack_deadline', 'ack_commit')['value_ns'])

    def test_reverse_direction_preserves_same_full_socket(self):
        result=self.load([sample('request_ingress',1),sample('ack_ingress',513,
            src_ipv4=0x0a000002,dst_ipv4=0x0a000001,sport=20000,dport=50000)])
        self.assertEqual(result.interval('1','request_ingress','ack_ingress')['value_ns'],512)

    def test_full_association_fields_cannot_be_omitted(self):
        row=sample('ack_commit',1); del row['connection_cookie']
        with self.assertRaises(ValueError):self.load([row])

    def test_pulse_without_tuple_is_retained_but_interval_unavailable(self):
        result=self.load([sample('request_ingress',1),sample('readiness_expiry_service',513,
            src_ipv4=0,dst_ipv4=0,sport=0,dport=0)])
        self.assertEqual(len(result.samples),2)
        self.assertIsNone(result.interval('1','request_ingress','readiness_expiry_service')['value_ns'])

    def test_backward_or_ambiguous_wrap_is_not_a_huge_valid_interval(self):
        result = self.load([sample('ack_deadline', 513), sample('ack_commit', 1)])
        self.assertIsNone(result.interval('1', 'ack_deadline', 'ack_commit')['value_ns'])

    def test_marker_mask_cannot_erase_the_elapsed_clock(self):
        for mask in (0xffffffff,0x7fffffff):
            with self.assertRaises(ValueError):
                self.load([sample('ack_deadline',1_000_000,marker_mask=mask),
                           sample('ack_commit',100_000_000,marker_mask=mask)])

    def test_quantisation_coarser_than_horizon_is_unavailable(self):
        record=self.load([sample('ack_deadline',1,marker_mask=0xffff),
                          sample('ack_commit',100,marker_mask=0xffff)])
        self.assertIsNone(record.interval('1','ack_deadline','ack_commit',max_interval_ns=1000)['value_ns'])

    def test_physical_label_on_ingress_event_is_rejected(self):
        with self.assertRaises(ValueError):
            self.load([sample('ack_wire_departure', 1)])

    def test_new_source_or_profile_does_not_reuse_old_observations(self):
        for field in ('source_sha256','schema_sha256','connection_id','operation_profile_sha256'):
            identity = dict(IDENTITY, **{field: 'other'})
            with self.assertRaises(ValueError):
                self.load([], identity=identity)

    def test_duplicate_event_requires_explicit_distinct_transaction(self):
        with self.assertRaises(ValueError):
            self.load([sample('ack_commit', 1), sample('ack_commit', 257)])

    def test_configured_timestamp_cannot_become_observed_elapsed(self):
        result = self.load([sample('ack_deadline', 1, evidence_kind='configured'), sample('ack_commit', 257)])
        self.assertIsNone(result.interval('1','ack_deadline','ack_commit')['value_ns'])

    def test_explicit_sbo_pair_allows_different_app_sequence_and_owner(self):
        samples=[sample('select_accept',100,transaction_id='select-1',endpoint='outstation_application',
                    clock_domain='outstation_steady',clock_width_bits=64,marker_mask=0),
                 sample('operate_accept',440000100,transaction_id='operate-1',operation='OPERATE',app_seq=4,
                    owner_cookie=0x80000002,endpoint='outstation_application',clock_domain='outstation_steady',
                    clock_width_bits=64,marker_mask=0)]
        relation=dict(pair_id='pair-1',select_transaction_id='select-1',operate_transaction_id='operate-1',
            operation_profile_sha256=IDENTITY['operation_profile_sha256'],
            select_object_set_sha256='e'*64,operate_object_set_sha256='e'*64)
        result=self.load(samples,sbo_pairs=[relation])
        self.assertEqual(result.sbo_cycle('pair-1',max_interval_ns=500_000_000)['value_ns'],440_000_000)
        self.assertIsNone(self.load(samples).sbo_cycle('pair-1')['value_ns'])
        for field,value in [('operate_object_set_sha256','f'*64),('operation_profile_sha256','f'*64)]:
            invalid=dict(relation,**{field:value})
            self.assertIsNone(self.load(samples,sbo_pairs=[invalid]).sbo_cycle('pair-1')['value_ns'])

    def test_actual_bounded_digest_decoder_is_importable_without_field_aliases(self):
        from defense4.timing.response_ready import observation_digest as decoder
        def raw(event,timestamp):
            return dict(version=1,event=event,owner_cookie=0x80000001,connection_cookie=5,
                timestamp_ns32=timestamp,association_profile=(1 << 16)|(3 << 8)|3,
                src_ipv4=0x0a000001,dst_ipv4=0x0a000002,sport=50000,dport=20000,
                originals_pre_mask=3,outcome=0)
        result=self.load([decoder.decode(raw(1,1),clock_domain='switch_ingress'),
                          decoder.decode(raw(2,513),clock_domain='switch_ingress')])
        interval=result.interval('00000005:0001','request_ingress','ack_ingress')
        self.assertEqual(interval['value_ns'],512)
        self.assertEqual(interval['quantity'],'internal interval')


if __name__ == '__main__':
    unittest.main()
