"""Actual N-committed SELECT activation, followed by a genuine M dirty-write return."""
import copy
import unittest
import test_n_ready as nr
import test_m_prepare as mp


class MActivation(unittest.TestCase):
    def committed(self,start=100):
        helper=nr.NativeReady();pipe,ready=helper.pending(start)
        qualified,reason=helper.one(pipe,ready);self.assertIsNotNone(qualified,reason)
        activated,reason=helper.one(pipe,qualified[1]);self.assertIsNotNone(activated,reason)
        return pipe,pipe.ordinary_m,activated[1]

    def test_geometry_and_ledger_publish_after_actual_n_commit_then_genuine_return_frees_m(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                pipe,m,raw=self.committed(start)
                dropped,out=mp.MPrepare().execute(m,raw);self.assertFalse(dropped)
                self.assertEqual(m.env.get('tm.ucast_egress_port'),198)
                self.assertEqual(m.env.get('tm.bypass_egress'),1)
                self.assertEqual(out[12:16],bytes.fromhex('08140003'))
                self.assertEqual(out[24:28],raw[:4])
                self.assertEqual(len(out),137)
                self.assertEqual(m.cells[('', 'geo_first')][0],(start+35)&0xffffffff)
                self.assertEqual(m.cells[('', 'ledger_position')][0],start)
                self.assertEqual(m.cells[('', 'ledger_tag')][0],{'epoch':int.from_bytes(raw[:4],'big'),'generation':int.from_bytes(raw[16:20],'big')})
                self.assertEqual(m.cells[('', 'reservation')][0]['phase'],1)
                before=copy.deepcopy(m.cells)
                dropped,_=mp.MPrepare().execute(m,raw);self.assertTrue(dropped);self.assertEqual(m.cells,before)
                dropped,emit=mp.MPrepare().execute(m,out,198);self.assertFalse(dropped)
                self.assertEqual(m.cells[('', 'reservation')][0]['phase'],4)
                self.assertEqual(m.env.get('tm.ucast_egress_port'),68)
                self.assertEqual(m.env.get('tm.bypass_egress'),0)
                self.assertEqual(emit[12:16],bytes.fromhex('09140002'))
                self.assertEqual(pipe.state()['work']['phase'],7)
                before=copy.deepcopy(m.cells)
                dropped,_=mp.MPrepare().execute(m,out,198);self.assertTrue(dropped);self.assertEqual(m.cells,before)

    def test_genuine_dirty_return_foreign_epoch_stamp_generation_and_loss(self):
        for offset,value in ((0,0x80000001),(24,0x80000001),(4,3),(16,3),(8,0x110002),(20,0x90002)):
            _,m,raw=self.committed();dropped,dirty=mp.MPrepare().execute(m,raw);self.assertFalse(dropped)
            self.assertEqual(m.cells[('','reservation')][0]['phase'],1)
            before=copy.deepcopy(m.cells);bad=bytearray(dirty)
            bad[offset:offset+4]=value.to_bytes(4,'big')
            dropped,_=mp.MPrepare().execute(m,bytes(bad),198)
            self.assertTrue(dropped);self.assertEqual(m.cells,before)
        # No returned packet means the current reservation stays pinned.
        self.assertEqual(m.cells[('','reservation')][0]['phase'],1)

    def test_foreign_full_identity_or_unknown_private_phase_cannot_publish_geometry(self):
        for event in (0x0714,0x0814):
            for offset,value in ((0,0x80000001),(4,0x80000004),(20,0x90002),(8,0x110002),(12,0x0f14)):
                _,m,raw=self.committed();bad=bytearray(raw)
                bad[12:14]=event.to_bytes(2,'big')
                width=2 if offset==12 else 4
                bad[offset:offset+width]=value.to_bytes(width,'big')
                before=copy.deepcopy(m.cells)
                dropped,_=mp.MPrepare().execute(m,bytes(bad),198 if event==0x0814 else 196)
                self.assertTrue(dropped);self.assertEqual(m.cells,before)


if __name__=='__main__':unittest.main()
