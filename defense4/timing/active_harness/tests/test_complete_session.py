"""Real retained relay bytes through the session; offline, with scripted sockets only."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_active_harness import FakeSocket, make_session, _link_frame, build_response
import dnp3_codec as codec
import session
import read_requests
import frozen_builders
import sbo_driver
import relay_native_baseline as baseline

NATIVE = (Path(__file__).resolve().parents[2] / 'case4_architecture/integration/core/'
          'response_only_rearm/stage_experiments/read_complete_01/evidence/'
          'relay_native_20261024/native_20261024.json')


def samples():
    return json.loads(NATIVE.read_text())['transactions']


def padded(record, *, seq=None, transport_seq=63):
    """Independent selected prefix construction: original application bytes are unchanged."""
    app = bytes.fromhex(record['app_fragment_hex'])
    if seq is not None:
        app = bytes([(app[0] & 0xf0) | seq]) + app[1:]
    count = 26 if record['workload'] == 'mixed' else 4
    obj = bytes([1, 2, 1]) + (1024).to_bytes(2, 'little') + (1024+count-1).to_bytes(2, 'little') + bytes(count)
    head = _link_frame(bytes([0x40 | transport_seq]) + app[:4] + obj[:-4])
    tail = _link_frame(bytes([0x80 | ((transport_seq+1) & 63)]) + obj[-4:] + app[4:])
    return head, tail


def transact(script, record, **kwargs):
    s = make_session(script)
    builder = getattr(read_requests, record['workload'] + '_read_frame')
    return s, s.transaction(operation='READ', frame=builder(record['app_seq']),
        function=codec.FUNC_READ, app_seq=record['app_seq'], budget_ms=60,
        expect_read_groups=baseline.WORKLOADS[record['workload']][1], **kwargs)


class CompleteSession(unittest.TestCase):
    def test_actual_mixed_and_integrity_prefix_alone_never_complete(self):
        for record in samples()[:2]:
            head, tail = padded(record)
            self.assertEqual([len(head), len(tail)], [50,91] if record['workload']=='mixed' else [24,134])
            with self.subTest(workload=record['workload']):
                _, out = transact([head, 'timeout'], record)
                self.assertEqual(out.outcome, session.OUTCOME_TIMEOUT, out.as_dict())

    def test_actual_native_and_padded_all_six_complete(self):
        for record in samples():
            native = bytes.fromhex(record['response_wire_hex'])
            head, tail = padded(record)
            for chunks in ([native], [head, tail], [head+tail], [bytes([x]) for x in head+tail]):
                with self.subTest(workload=record['workload'], chunks=len(chunks)):
                    _, out = transact(chunks, record)
                    self.assertTrue(out.ok, out.as_dict())

    def test_crc_failure_before_valid_coalesced_response_is_not_hidden(self):
        record = samples()[0]
        raw = bytes.fromhex(record['response_wire_hex'])
        bad = bytearray(raw); bad[12] ^= 1
        _, out = transact([bytes(bad)+raw], record)
        self.assertEqual(out.outcome, session.OUTCOME_FRAME_ERROR, out.as_dict())

    def test_complete_response_missing_original_analog_is_invalid(self):
        record = samples()[0]
        app = bytes.fromhex(record['app_fragment_hex'])[:25]
        _, out = transact([_link_frame(b'\xc0'+app)], record)
        self.assertEqual(out.outcome, session.OUTCOME_INVALID)

    def test_baseline_integrity_verdict_validates_real_schema(self):
        record = samples()[1]
        out = baseline.one_transaction(FakeSocket([bytes.fromhex(record['response_wire_hex'])]),
                                       'integrity', record['app_seq'], 60)
        self.assertEqual(out['outcome'], 'OK', out)
        self.assertEqual(out['validation_problems'], [], out)

    def test_baseline_rejects_missing_analog(self):
        record = samples()[0]
        app = bytes.fromhex(record['app_fragment_hex'])[:25]
        out = baseline.one_transaction(FakeSocket([_link_frame(b'\xc0'+app)]), 'mixed', 0, 60)
        self.assertEqual(out['outcome'], 'INVALID', out)

    def test_baseline_parses_completed_fragment(self):
        record = samples()[0]
        head, tail = padded(record)
        out = baseline.one_transaction(FakeSocket([head, tail]), 'mixed', 0, 60)
        self.assertEqual(out['outcome'], 'OK', out)
        self.assertEqual(out['validation_problems'], [], out)

    def test_source_binding_failure_closes_socket_and_never_connects(self):
        class BindFailure(FakeSocket):
            connected = False
            closed = False
            def setsockopt(self, *args): pass
            def bind(self, addr): raise OSError('unavailable source')
            def connect(self, addr): self.connected = True
            def close(self): self.closed = True
        fake = BindFailure([])
        with patch.object(session.socket, 'socket', return_value=fake):
            with self.assertRaises(OSError):
                session.Session('192.168.10.7', source_address=('192.168.10.1', 0)).connect()
        self.assertFalse(fake.connected)
        self.assertTrue(fake.closed)



class CompleteValidationEdges(unittest.TestCase):
    def setUp(self):
        self.record = samples()[0]
        self.app = bytes.fromhex(self.record['app_fragment_hex'])

    def run_app(self, app):
        return transact([_link_frame(b'\xc0'+app)], self.record)[1]

    def test_every_truncated_application_object_is_rejected(self):
        for end in range(4, len(self.app)):
            with self.subTest(end=end):
                self.assertEqual(self.run_app(self.app[:end]).outcome, 'INVALID')

    def test_padding_wrong_range_duplicate_flags_and_unknown_object_rejected(self):
        pad = bytes([1,2,1,0,4,25,4])+bytes(26)
        variants = [pad[:-1], pad[:3]+bytes([1,4,26,4])+pad[7:],
                    pad[:-1]+b'\x80', pad+pad, bytes([99,1,0,0,0,0]),
                    bytes([1,2,1,25,4,0,4])]
        for obj in variants:
            with self.subTest(obj=obj.hex()):
                self.assertEqual(self.run_app(self.app[:4]+obj+self.app[4:]).outcome, 'INVALID')

    def test_preserves_every_original_value_flag_and_all_padding_objects(self):
        head, tail = padded(self.record)
        _, out = transact([head, tail], self.record)
        points = [point for obj in out.response_objects for point in obj['points']]
        self.assertEqual(len(points), 26+16+8)
        self.assertTrue(all(p['raw_hex']=='00' for p in points[:26]))
        self.assertEqual(points[26]['raw_hex'], '81')
        self.assertEqual(points[26]['flags'], 1)
        self.assertTrue(points[26]['value'])
        self.assertEqual(points[-1]['value'], 60)

    def test_iin_indications_allowed_and_each_error_bit_rejected(self):
        for low in (0, 0x80, 0x84, 0xff):
            app = self.app[:2]+bytes([low,0])+self.app[4:]
            self.assertTrue(self.run_app(app).ok)
        for high in (1,2,4,8,16,32):
            app = self.app[:2]+bytes([0x80,high])+self.app[4:]
            out = self.run_app(app)
            self.assertEqual(out.outcome, 'INVALID')
            self.assertTrue(any('IIN' in p for p in out.problems))

    def test_transport_gap_and_orphan_tail_and_restart_rejected(self):
        head, tail = padded(self.record)
        tail_user = codec.parse_frame(tail)[0].user_data
        gap = _link_frame(bytes([0x81])+tail_user[1:])  # head seq63 requires seq0
        for chunks in ([head,gap], [tail], [head,head,tail]):
            with self.subTest(chunks=len(chunks)):
                _, out = transact(chunks, self.record)
                self.assertEqual(out.outcome, 'INVALID')
                self.assertTrue(any('transport' in p for p in out.problems))

    def test_stale_two_frame_fragment_discarded_before_matching_fragment(self):
        stale = b''.join(padded(self.record, seq=9))
        good = b''.join(padded(self.record))
        _, out = transact([stale+good], self.record)
        self.assertTrue(out.ok, out.as_dict())
        self.assertEqual(out.stale_frames_discarded, 2)
        self.assertEqual(out.response_wire_hex, good.hex())
        self.assertEqual(out.received_wire_hex, (stale+good).hex())

    def test_sequence_wrap_15_to_zero_on_persistent_session(self):
        first = b''.join(padded(self.record, seq=15))
        second = b''.join(padded(self.record, seq=0))
        s = make_session([first,second])
        for seq in (15,0):
            out = s.transaction(operation='READ', frame=read_requests.mixed_read_frame(seq),
                function=1, app_seq=seq, budget_ms=60, expect_read_workload='mixed')
            self.assertTrue(out.ok, out.as_dict())

    def test_response_address_is_bound_to_request(self):
        wrong = _link_frame(b'\xc0'+self.app, dst=2)
        _, out = transact([wrong], self.record)
        self.assertEqual(out.outcome, 'INVALID')

    def test_exact_request_response_frames_apps_and_observed_socket_addresses(self):
        class Addressed(FakeSocket):
            def getsockname(self): return ('192.168.10.1', 45000)
            def getpeername(self): return ('192.168.10.7', 20000)
        head, tail = padded(self.record)
        s = session.Session('192.168.10.7')
        s.sock = Addressed([head,tail])
        request = read_requests.mixed_read_frame(0)
        out = s.transaction(operation='READ', frame=request, function=1, app_seq=0,
                            budget_ms=60, expect_read_workload='mixed')
        self.assertTrue(out.ok)
        self.assertEqual(out.request_wire_hex, request.hex())
        self.assertEqual(out.request_frames_hex, [request.hex()])
        self.assertEqual(out.request_app_hex, codec.parse_frame(request)[0].user_data[1:].hex())
        self.assertEqual(out.response_frames_hex, [head.hex(),tail.hex()])
        self.assertEqual(out.response_app_hex,
            codec.reassemble_application([codec.parse_frame(f)[0] for f in (head,tail)])[0].hex())
        self.assertEqual(out.local_address, ('192.168.10.1',45000))
        self.assertEqual(out.peer_address, ('192.168.10.7',20000))

    def test_partial_transport_state_does_not_survive_close_reconnect(self):
        head, tail = padded(self.record)
        s, out = transact([head, 'timeout'], self.record)
        self.assertEqual(out.outcome, 'TIMEOUT')
        s.close()
        class Connectable(FakeSocket):
            def setsockopt(self, *args): pass
            def connect(self, address): pass
            def getsockname(self): return ('192.168.10.1',45000)
            def getpeername(self): return ('192.168.10.7',20000)
        fake = Connectable([tail])
        with patch.object(session.socket, 'socket', return_value=fake): s.connect()
        out = s.transaction(operation='READ', frame=read_requests.mixed_read_frame(0),
                            function=1, app_seq=0, budget_ms=60)
        self.assertEqual(out.outcome, 'INVALID')

    def test_baseline_offline_readout_all_six_preserves_original_records(self):
        records = samples()
        before = json.dumps(records, sort_keys=True)
        for record in records:
            readout = baseline.reevaluate_record(record)
            self.assertEqual(readout['corrected_outcome'], 'OK', readout)
            self.assertEqual(readout['validation_problems'], [])
        self.assertEqual(json.dumps(records, sort_keys=True), before)

    def test_baseline_crc_and_incomplete_fragment_fail_closed(self):
        head, tail = padded(self.record)
        bad = bytearray(head); bad[12] ^= 1
        for raw in (head, bytes(bad)+tail, head+tail[:-1]):
            record = dict(self.record, response_wire_hex=raw.hex())
            self.assertEqual(baseline.reevaluate_record(record)['corrected_outcome'], 'INVALID')

    def test_control_both_crobs_and_parameters_required_before_operate(self):
        good = codec.parse_frame(build_response(0,[1,3],[0,0]))[0].user_data[1:]
        variants = [good[:-1], good[:7]+bytes([1])+good[8:20],  # truncation/second CROB absent
                    good[:9]+bytes([2])+good[10:],  # first code changed
                    good[:21]+bytes([2])+good[22:], # second code changed
                    good[:10]+bytes([2])+good[11:], # first count changed
                    good[:11]+bytes([201])+good[12:], # on-time changed
                    good[:15]+bytes([1])+good[16:], # off-time changed
                    good[:2]+bytes([0x80,1])+good[4:]]
        for application in variants:
            with self.subTest(application=application.hex()):
                s = make_session([_link_frame(b'\xc0'+application)])
                sel, op = sbo_driver.one_sbo(s,0,1,[1,3],60,False)
                self.assertFalse(sel.ok, sel.as_dict())
                self.assertEqual(op.outcome,'NOT_ATTEMPTED')
                self.assertEqual(len(s.sock.sent),1)

    def test_sbo_transport_fragment_does_not_open_operate_gate(self):
        good = codec.parse_frame(build_response(0,[1,3],[0,0]))[0].user_data[1:]
        first = _link_frame(b'\x40'+good[:16])
        s = make_session([first,'timeout'])
        sel, op = sbo_driver.one_sbo(s,0,1,[1,3],60,False)
        self.assertEqual(sel.outcome,'TIMEOUT')
        self.assertEqual(op.outcome,'NOT_ATTEMPTED')
        self.assertEqual(len(s.sock.sent),1)


class ExplicitReadWorkload(unittest.TestCase):
    def test_read_driver_builds_selected_mixed_integrity_or_legacy(self):
        import read_driver
        for workload, builder in [('legacy', frozen_builders.read_frame),
                                  ('mixed', read_requests.mixed_read_frame),
                                  ('integrity', read_requests.integrity_read_frame)]:
            self.assertEqual(read_driver.build(7, workload=workload), builder(7))
        with self.assertRaises(ValueError): read_driver.build(0, workload='unknown')

    def test_socket_garbage_cannot_be_hidden_by_valid_completion(self):
        record = samples()[0]
        _, out = transact([b'garbage'+bytes.fromhex(record['response_wire_hex'])],record)
        self.assertEqual(out.outcome, 'FRAME_ERROR')

    def test_explicit_groups_must_match_wire_request_schema(self):
        s = make_session([])
        with self.assertRaises(ValueError):
            s.transaction(operation='READ', frame=read_requests.mixed_read_frame(0), function=1,
                          app_seq=0, budget_ms=60, expect_read_groups={(10,2)})
        self.assertEqual(s.sock.sent, [])

    def test_crc_failure_after_valid_coalesced_response_is_not_hidden(self):
        record = samples()[0]
        raw = bytes.fromhex(record['response_wire_hex'])
        bad = bytearray(raw); bad[12] ^= 1
        _, out = transact([raw+bytes(bad)], record)
        self.assertEqual(out.outcome, 'FRAME_ERROR')


class BaselineCompleteness(unittest.TestCase):
    def test_offline_readout_rejects_completed_fragment_followed_by_unfinished_fragment(self):
        record = samples()[0]
        head, _ = padded(record)
        raw = bytes.fromhex(record['response_wire_hex']) + head
        readout = baseline.reevaluate_record(dict(record, response_wire_hex=raw.hex()))
        self.assertEqual(readout['corrected_outcome'], 'INVALID', readout)

    def test_baseline_empty_denominator_refused_before_connect(self):
        with patch.object(session.Session,'connect', side_effect=AssertionError('must not connect')):
            for args in (['--each','0'], ['--each','-1'], ['--budget-ms','0']):
                with self.subTest(args=args):
                    self.assertEqual(baseline.main(args), 2)


if __name__ == '__main__':
    unittest.main()
