"""Actual E tag/owner/coordinate qualification after N commit and M final dirty return."""
import copy
import unittest
import test_n_ready as nr
import test_m_prepare as mp
import test_e_prepare as ep


class EQuery(unittest.TestCase):
    def activation(self,start=100):
        helper=nr.NativeReady();pipe,ready=helper.pending(start)
        qualified,reason=helper.one(pipe,ready);self.assertIsNotNone(qualified,reason)
        activated,reason=helper.one(pipe,qualified[1]);self.assertIsNotNone(activated,reason)
        dropped,dirty=mp.MPrepare().execute(pipe.ordinary_m,activated[1]);self.assertFalse(dropped)
        dropped,out=mp.MPrepare().execute(pipe.ordinary_m,dirty,198);self.assertFalse(dropped)
        return pipe,pipe.ordinary_e,out

    def test_actual_cache_full_identity_and_zero_wrap_position_before_emit_qualification(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                pipe,e,raw=self.activation(start)
                before=copy.deepcopy(e.cells)
                dropped,out=ep.EPrepare().execute(e,raw);self.assertFalse(dropped)
                self.assertEqual(pipe.ordinary_m.env.get('tm.ucast_egress_port'),68)
                self.assertEqual(out[:12],raw[:12]);self.assertEqual(out[16:],raw[16:])
                self.assertEqual(out[12:16],bytes.fromhex('0b140002'))
                self.assertEqual(e.cells,before)
                self.assertEqual(pipe.state()['work']['phase'],7)

    def test_valid_network_wrong_cache_epoch_owner_generation_or_coordinate_refused(self):
        for kind in ('epoch','owner','producer_generation','position'):
            pipe,e,raw=self.activation();bad=bytearray(raw)
            if kind=='position':
                bad=bytearray(raw[:24]+mp.vectors.packet(24,101,901,payload=raw[78:]))
            else:
                offset={'epoch':0,'owner':20,'producer_generation':16}[kind]
                bad[offset:offset+4]=(0x80000001).to_bytes(4,'big')
            before=copy.deepcopy(e.cells)
            dropped,_=ep.EPrepare().execute(e,bytes(bad));self.assertTrue(dropped)
            self.assertEqual(e.cells,before)


if __name__=='__main__':unittest.main()
