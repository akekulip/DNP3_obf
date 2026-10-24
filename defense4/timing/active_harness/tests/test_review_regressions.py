"""Independent-review reproductions: matched metadata, trailing batches, finite budgets."""
import contextlib
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_active_harness import FakeSocket, make_session, _link_frame
from test_complete_session import samples, padded, transact
import session
import relay_native_baseline as baseline
import read_requests


class ReviewRegressions(unittest.TestCase):
    def test_baseline_records_matched_native_after_stale_padded_fragment(self):
        record=samples()[0]
        native=bytes.fromhex(record['response_wire_hex'])
        stale=b''.join(padded(record,seq=9))
        out=baseline.one_transaction(FakeSocket([stale+native]),'mixed',0,60)
        self.assertEqual(out['outcome'],'OK',out)
        self.assertEqual(out['decode']['app_seq'],0,out)
        self.assertEqual(out['wire_len'],91,out)
        self.assertEqual(out['response_wire_hex'],native.hex())
        self.assertEqual(out['received_wire_hex'],(stale+native).hex())
        self.assertEqual(baseline.reevaluate_record(out)['corrected_outcome'],'OK')

    def test_good_before_orphan_wrong_address_or_unfinished_prefix_is_invalid(self):
        record=samples()[0]
        native=bytes.fromhex(record['response_wire_hex'])
        head,tail=padded(record)
        app=bytes.fromhex(record['app_fragment_hex'])
        for name,extra in [('orphan',tail),('wrong_address',_link_frame(b'\xc0'+app,dst=2)),
                           ('unfinished',head),('duplicate',native)]:
            with self.subTest(extra=name):
                _,out=transact([native+extra],record)
                self.assertEqual(out.outcome,'INVALID',out.as_dict())
                self.assertTrue(out.problems)
                self.assertEqual(out.received_wire_hex,(native+extra).hex())
                self.assertEqual(out.response_wire_hex,native.hex())
                self.assertEqual(out.received_frames_hex,[native.hex(),extra.hex()])
                baseline_out=baseline.one_transaction(FakeSocket([native+extra]),'mixed',0,60)
                self.assertEqual(baseline_out['outcome'],'INVALID',baseline_out)
                self.assertTrue(baseline_out['validation_problems'])
                self.assertEqual(baseline.reevaluate_record(baseline_out)['corrected_outcome'],'INVALID')

    def test_complete_stale_after_current_is_counted_and_cannot_answer_next_request(self):
        record=samples()[0]
        native=bytes.fromhex(record['response_wire_hex'])
        stale=b''.join(padded(record,seq=1))
        s,out=transact([native+stale],record)
        self.assertTrue(out.ok,out.as_dict())
        self.assertEqual(out.stale_frames_discarded,2)
        self.assertEqual(out.response_wire_hex,native.hex())
        next_out=s.transaction(operation='READ',frame=read_requests.mixed_read_frame(1),
                               function=1,app_seq=1,budget_ms=60)
        self.assertEqual(next_out.outcome,'TIMEOUT')

    def test_current_padding_after_current_cannot_hide_in_transport_state(self):
        record=samples()[0]
        native=bytes.fromhex(record['response_wire_hex'])
        head,_=padded(record)
        s,out=transact([native+head],record)
        self.assertEqual(out.outcome,'INVALID')
        self.assertEqual(out.transport_bytes_buffered,len(head))

    def test_transaction_rejects_nonfinite_nonpositive_budget_before_socket_calls(self):
        for budget in (float('nan'),float('inf'),float('-inf'),0,-1):
            with self.subTest(budget=budget):
                s=make_session(['timeout'])
                with self.assertRaises(ValueError):
                    s.transaction(operation='READ',frame=read_requests.mixed_read_frame(0),
                                   function=1,app_seq=0,budget_ms=budget)
                self.assertEqual(s.sock.sent,[])
                self.assertEqual(s.sock.timeouts,[])

    def test_connect_timeout_rejected_before_socket_creation(self):
        for timeout in (float('nan'),float('inf'),float('-inf'),0,-1):
            with self.subTest(timeout=timeout):
                with patch.object(session.socket,'socket',side_effect=AssertionError('opened socket')):
                    with self.assertRaises(ValueError):
                        session.Session('192.168.10.7',connect_timeout_ms=timeout).connect()

    def test_baseline_cli_nonfinite_budget_gap_connect_timeout_rejected_before_connect(self):
        with patch.dict(os.environ,{'DEFENSE4_HW_AUTHORIZED':'1'}):
            with patch.object(session.Session,'connect',side_effect=AssertionError('opened socket')):
                for option in ('--budget-ms','--gap-ms','--connect-timeout-ms'):
                    for value in ('nan','inf','-inf'):
                        with self.subTest(option=option,value=value):
                            with contextlib.redirect_stderr(io.StringIO()):
                                self.assertEqual(baseline.main(['--live',option+'='+value]),2)


if __name__=='__main__': unittest.main()
