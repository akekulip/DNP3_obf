"""Actual packet N ready qualification/release CAS, not endpoint-emission proof."""
import copy
import unittest
import test_m_prepare as mp
import test_e_prepare as ep


class NativeReady(unittest.TestCase):
    def pending(self,start=100):
        pipe=mp.Pipeline.from_path(mp.HERE.parent/'n.p4',mp.vectors.topology())
        for port,frame in ((1,mp.vectors.packet(2,(start-1)&0xffffffff,mss=1500)),
                           (2,mp.vectors.packet(18,900,start,True,mss=1500)),
                           (1,mp.vectors.packet(16,start,901))):
            out=pipe.inject(port,frame);self.assertFalse(out.dropped)
        out=pipe.inject(1,mp.vectors.packet(24,start,901,payload=mp.vectors.native_select()))
        helper=mp.MPrepare();dropped,prepared=helper.execute(helper.receiver(),out.emitted[0][1]);self.assertFalse(dropped)
        e=ep.e_source();dropped,ready=ep.EPrepare().execute(e,prepared);self.assertFalse(dropped)
        return pipe,ready

    def one(self,pipe,raw):
        _,result,reason=pipe.run_pass(1,68,raw)
        return result,reason

    def test_actual_ready_then_atomic_owner_commit_preserves_both_refs(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                pipe,ready=self.pending(start);state=pipe.state()
                qualified,reason=self.one(pipe,ready);self.assertIsNotNone(qualified,reason)
                self.assertEqual(qualified[0],68)
                self.assertEqual(pipe.state()['work'],state['work'])
                self.assertEqual(pipe.state()['owner'],state['owner'])
                self.assertEqual(qualified[1][12:16],bytes.fromhex('06140002'))
                activated,reason=self.one(pipe,qualified[1]);self.assertIsNotNone(activated,reason)
                self.assertEqual(activated[0],196)
                self.assertEqual(pipe.state()['work']['phase'],7)
                self.assertEqual(pipe.state()['owner'],0x110001)
                self.assertEqual(activated[1][8:12],bytes.fromhex('00110001'))
                self.assertEqual(activated[1][20:24],ready[8:12])
                self.assertEqual(activated[1][12:16],bytes.fromhex('07140002'))
                before=copy.deepcopy(pipe.src.cells)
                duplicate,reason=self.one(pipe,qualified[1]);self.assertIsNone(duplicate)
                self.assertEqual(pipe.src.cells,before)

    def test_foreign_epoch_or_generation_ready_cannot_publish_or_change_banks(self):
        for offset,value in ((0,0x80000001),(4,0x80000004),(4,3),(20,0x90002)):
            pipe,ready=self.pending();bad=bytearray(ready);bad[offset:offset+4]=value.to_bytes(4,'big')
            before=copy.deepcopy(pipe.src.cells)
            result,_=self.one(pipe,bytes(bad));self.assertIsNone(result)
            self.assertEqual(pipe.src.cells,before)

    def test_real_close_before_owner_cas_prevents_activation_retains_pin(self):
        pipe,ready=self.pending();qualified,reason=self.one(pipe,ready);self.assertIsNotNone(qualified,reason)
        closed=pipe.inject(1,mp.vectors.packet(17,135,901));self.assertFalse(closed.dropped)
        self.assertEqual(pipe.state()['owner'],0x60001)
        result,_=self.one(pipe,qualified[1]);self.assertIsNone(result)
        self.assertEqual(pipe.state()['owner'],0x60001)
        self.assertEqual(pipe.state()['work']['phase'],7)


if __name__=='__main__':unittest.main()
