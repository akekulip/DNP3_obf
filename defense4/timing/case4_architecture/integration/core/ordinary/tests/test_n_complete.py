"""Actual E completion is the sole normal downstream N terminal authority."""
import copy
import unittest
import test_e_emit as ee
import test_e_prepare as ep
import test_n_ready as nr
import test_m_prepare as mp


class NComplete(unittest.TestCase):
    def completion(self):
        pipe,e,raw=ee.EEmit().qualified()
        dropped,endpoint=ep.EPrepare().execute(e,raw,2);self.assertFalse(dropped)
        completion=e.mirror_headers[0][1]+endpoint
        out=ee.EEmit().retire_completion(pipe,e,completion)
        return pipe,out

    def test_genuine_completion_qualifies_owner_and_frees_only_on_next_actual_terminal(self):
        pipe,raw=self.completion()
        terminal,reason=nr.NativeReady().one(pipe,raw);self.assertIsNotNone(terminal,reason)
        self.assertEqual(pipe.state()['work']['phase'],7)
        self.assertEqual(pipe.state()['owner'],0x120001)
        self.assertEqual(terminal[0],68)
        self.assertEqual(terminal[1][12:16],bytes.fromhex('0f140003'))
        self.assertEqual(len(terminal[1]),137)
        result,_=nr.NativeReady().one(pipe,terminal[1]);self.assertIsNone(result)
        self.assertEqual(pipe.state()['work']['phase'],9)
        after=copy.deepcopy(pipe.src.cells)
        result,_=nr.NativeReady().one(pipe,raw);self.assertIsNone(result)
        result,_=nr.NativeReady().one(pipe,terminal[1]);self.assertIsNone(result)
        self.assertEqual(pipe.src.cells,after)

    def test_stale_full_generation_or_epoch_completion_cannot_borrow_live_work(self):
        for offset in (0,4,8,16,20):
            pipe,raw=self.completion();bad=bytearray(raw)
            bad[offset:offset+4]=(int.from_bytes(bad[offset:offset+4],'big')^0x80000000).to_bytes(4,'big')
            before=copy.deepcopy(pipe.src.cells)
            result,_=nr.NativeReady().one(pipe,bytes(bad));self.assertIsNone(result)
            self.assertEqual(pipe.src.cells,before)
        pipe,raw=self.completion()
        bad=bytearray(raw);bad[4:8]=(0x80000004).to_bytes(4,'big');bad[16:20]=(0x80000004).to_bytes(4,'big')
        before=copy.deepcopy(pipe.src.cells)
        result,_=nr.NativeReady().one(pipe,bytes(bad));self.assertIsNone(result)
        self.assertEqual(pipe.src.cells,before)

    def test_lost_terminal_retains_pin_and_foreign_stamp_does_not_free(self):
        pipe,raw=self.completion();terminal,reason=nr.NativeReady().one(pipe,raw);self.assertIsNotNone(terminal,reason)
        self.assertEqual(pipe.state()['work']['phase'],7)
        for offset in (0,24):
            bad=bytearray(terminal[1]);bad[offset:offset+4]=(int.from_bytes(bad[offset:offset+4],'big')^0x80000000).to_bytes(4,'big')
            before=copy.deepcopy(pipe.src.cells)
            result,_=nr.NativeReady().one(pipe,bytes(bad));self.assertIsNone(result)
            self.assertEqual(pipe.src.cells,before)

    def test_real_close_before_drain_cas_requires_genuine_cleanup_return(self):
        pipe,raw=self.completion()
        closed=pipe.inject(1,mp.vectors.packet(17,135,901));self.assertFalse(closed.dropped)
        self.assertEqual(pipe.state()['owner'],0x60001)
        cleanup,reason=nr.NativeReady().one(pipe,raw);self.assertIsNotNone(cleanup,reason)
        self.assertEqual(cleanup[1][12:16],bytes.fromhex('10140002'))
        self.assertEqual(pipe.state()['owner'],0x60001)
        self.assertEqual(pipe.state()['work']['phase'],7)
        before=copy.deepcopy(pipe.src.cells)
        bad=bytearray(cleanup[1]);bad[:4]=(0x80000001).to_bytes(4,'big')
        out,_=nr.NativeReady().one(pipe,bytes(bad));self.assertIsNone(out)
        self.assertEqual(pipe.src.cells,before)
        terminal,reason=nr.NativeReady().one(pipe,cleanup[1]);self.assertIsNotNone(terminal,reason)
        self.assertEqual(pipe.state()['owner'],0x70001)
        self.assertEqual(pipe.state()['work']['phase'],7)
        nr.NativeReady().one(pipe,terminal[1])
        self.assertEqual(pipe.state()['work']['phase'],9)

    def test_real_close_after_owner_drain_cas_retires_without_stranding_work(self):
        pipe,raw=self.completion();terminal,reason=nr.NativeReady().one(pipe,raw);self.assertIsNotNone(terminal,reason)
        closed=pipe.inject(1,mp.vectors.packet(17,135,901));self.assertFalse(closed.dropped)
        self.assertEqual(pipe.state()['owner'],0x70001)
        self.assertEqual(pipe.state()['work']['phase'],7)
        nr.NativeReady().one(pipe,terminal[1])
        self.assertEqual(pipe.state()['work']['phase'],9)


if __name__=='__main__':unittest.main()
