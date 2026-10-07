"""Packet-driven source checks for the new N candidate, not target execution."""
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'integration/core/harness'))
from driver import Pipeline
import vectors


class NativeHandoff(unittest.TestCase):
    def pipeline(self):
        return Pipeline.from_path(HERE.parent / 'n.p4', vectors.topology())

    def establish(self, pipe, client=100):
        for port, frame in (
            (1, vectors.packet(2, client, mss=1500)),
            (2, vectors.packet(18, 900, client + 1, reverse=True, mss=1500)),
            (1, vectors.packet(16, client + 1, 901)),
        ):
            out = pipe.inject(port, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.emitted, [(3-port, frame)])
        return (client + 1) & 0xffffffff

    def test_actual_handshake_select_hands_to_m_with_pin_and_no_endpoint_copy(self):
        for initial in (100, 0xffffffff, 0xfffffff0):
            with self.subTest(initial=initial):
                pipe = self.pipeline()
                start = self.establish(pipe, initial)
                raw = vectors.packet(24, start, 901, payload=vectors.native_select())
                out = pipe.inject(1, raw)
                self.assertFalse(out.dropped, out.drop_reason)
                self.assertEqual(len(out.emitted), 1)
                port, handoff = out.emitted[0]
                self.assertEqual(port, 196)
                self.assertEqual(handoff[12:16], bytes.fromhex('03050001'))
                self.assertEqual(handoff[28:], raw)
                state = pipe.state()
                self.assertEqual(state['work']['phase'], 5)
                self.assertEqual(int.from_bytes(handoff[0:4], 'big'), state['epoch'])
                self.assertEqual(int.from_bytes(handoff[4:8], 'big'), state['work']['generation'])
                self.assertEqual(int.from_bytes(handoff[8:12], 'big'), state['owner'])
                index,code,repeat,on,off = vectors.decoy_config()
                expected = index.to_bytes(2,'big')+bytes((code,repeat))+on.to_bytes(4,'big')+off.to_bytes(4,'big')
                self.assertEqual(handoff[16:28], expected)
                before = pipe.state()
                duplicate = pipe.inject(68, handoff)
                self.assertTrue(duplicate.dropped)
                self.assertEqual(duplicate.emitted, [])
                self.assertEqual(pipe.state(), before)

    def test_decoy_snapshot_survives_configuration_change_during_n_returns(self):
        pipe = self.pipeline()
        start = self.establish(pipe)
        raw = vectors.packet(24, start, 901, payload=vectors.native_select())
        original = vectors.decoy_config()
        _, result, reason = pipe.run_pass(1, 1, raw)
        self.assertIsNone(reason)
        self.assertEqual(result[0], 68)
        pipe.src.controls['Ingress'].tables['data_connection']['runtime'].clear()
        for *tuple4, _direction, _port in vectors.topology().flows:
            pipe.src.install('data_connection',tuple4,'configure',(202,2,2,77,88))
        out = pipe.inject(68,result[1])
        self.assertFalse(out.dropped,out.drop_reason)
        self.assertEqual(out.emitted[0][0],196)
        index,code,repeat,on,off = original
        expected=index.to_bytes(2,'big')+bytes((code,repeat))+on.to_bytes(4,'big')+off.to_bytes(4,'big')
        self.assertEqual(out.emitted[0][1][16:28],expected)

    def test_actual_close_after_handoff_quarantines_owner_and_keeps_pending_pin(self):
        pipe = self.pipeline()
        start = self.establish(pipe)
        pipe.inject(1, vectors.packet(24, start, 901, payload=vectors.native_select()))
        work = dict(pipe.state()['work'])
        close = vectors.packet(17, (start+35)&0xffffffff, 901)
        out = pipe.inject(1, close)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(pipe.state()['owner'] >> 16, 6)
        self.assertEqual(pipe.state()['work'], work)

    def test_captured_format_cannot_relabel_handshake_or_unknown_event(self):
        pipe = self.pipeline()
        start = self.establish(pipe)
        raw = vectors.packet(24,start,901,payload=vectors.native_select())
        _, result, reason = pipe.run_pass(1,1,raw)
        self.assertIsNone(reason)
        before = {key:repr(value) for key,value in pipe.src.cells.items()}
        for event,reserved in ((0x0101,1),(0x017e,1),(0x0105,2),(0x0105,0xffff)):
            with self.subTest(event=event,reserved=reserved):
                corrupt=bytearray(result[1])
                corrupt[12:16]=event.to_bytes(2,'big')+reserved.to_bytes(2,'big')
                out=pipe.inject(68,bytes(corrupt))
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted,[])
                self.assertEqual({key:repr(value) for key,value in pipe.src.cells.items()},before)

    def test_select_return_cannot_strip_captured_extension_and_mark_legacy_format(self):
        pipe=self.pipeline()
        start=self.establish(pipe)
        _,result,reason=pipe.run_pass(1,1,vectors.packet(24,start,901,payload=vectors.native_select()))
        self.assertIsNone(reason)
        before={key:repr(value) for key,value in pipe.src.cells.items()}
        stripped=bytearray(result[1][:16]+result[1][28:])
        stripped[14:16]=b'\x00\x00'
        out=pipe.inject(68,bytes(stripped))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted,[])
        self.assertEqual({key:repr(value) for key,value in pipe.src.cells.items()},before)

    def terminal_after_publish(self,pipe):
        start=self.establish(pipe)
        raw=vectors.packet(24,start,901,payload=vectors.native_select())
        for count,port in ((1,1),(2,68),(3,68)):
            _,result,reason=pipe.run_pass(count,port,raw)
            self.assertIsNone(reason)
            self.assertEqual(result[0],68)
            raw=result[1]
        self.assertEqual(pipe.state()['work']['phase'],3)
        return raw

    def test_fin_before_terminal_drains_local_pin_without_any_m_recipient(self):
        pipe=self.pipeline();terminal=self.terminal_after_publish(pipe)
        close=vectors.packet(17,136,901)
        pipe.inject(1,close)
        out=pipe.inject(68,terminal)
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted,[])
        self.assertEqual(pipe.state()['work']['phase'],9)
        self.assertEqual(pipe.state()['owner']>>16,6)

    def test_lost_local_abort_return_keeps_pin(self):
        pipe=self.pipeline();terminal=self.terminal_after_publish(pipe)
        pipe.inject(1,vectors.packet(17,136,901))
        _,result,reason=pipe.run_pass(4,68,terminal)
        self.assertIsNone(reason)
        self.assertEqual(result[0],68)
        self.assertEqual(result[1][12:16],bytes.fromhex('05ff0001'))
        self.assertEqual(pipe.state()['work']['phase'],5)
        # Deliberately do not deliver the genuine abort: no M received work,
        # yet loss must keep the pin rather than manufacturing completion.
        self.assertEqual(pipe.state()['owner']>>16,6)

    def test_raw_close_reads_each_live_work_phase_without_terminal_mutation(self):
        # Diagnostic bank-boundary fixtures, not packet-derived ready evidence.
        # Deliberately make generation equal the epoch-derived close parse token.
        for phase in (1,2,3,5,7):
            with self.subTest(phase=phase):
                pipe=self.pipeline();start=self.establish(pipe)
                pipe.inject(1,vectors.packet(24,start,901,payload=vectors.native_select()))
                fixture={'generation':pipe.state()['epoch'],'phase':phase}
                pipe.src.cells[('work','work')][0]=dict(fixture)
                out=pipe.inject(1,vectors.packet(17,136,901))
                self.assertFalse(out.dropped,out.drop_reason)
                self.assertEqual(pipe.state()['owner']>>16,6)
                self.assertEqual(pipe.state()['work'],fixture)

    def test_foreign_epoch_local_abort_same_generation_cannot_free_pin(self):
        pipe=self.pipeline();terminal=self.terminal_after_publish(pipe)
        pipe.inject(1,vectors.packet(17,136,901))
        _,result,reason=pipe.run_pass(4,68,terminal)
        self.assertIsNone(reason)
        abort=bytearray(result[1]);epoch=int.from_bytes(abort[:4],'big')
        abort[:4]=(epoch+1).to_bytes(4,'big')
        before={key:repr(value) for key,value in pipe.src.cells.items()}
        out=pipe.inject(68,bytes(abort))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted,[])
        self.assertEqual({key:repr(value) for key,value in pipe.src.cells.items()},before)


if __name__ == '__main__': unittest.main()
