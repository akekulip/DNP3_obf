"""Real source E cache reads and typed completion; target mirroring remains a model gate."""
import copy
import unittest
import test_e_query as eq
import test_e_prepare as ep
import test_n_ready as nr


class EEmit(unittest.TestCase):
    def qualified(self,start=100):
        pipe,e,raw=eq.EQuery().activation(start)
        dropped,query=ep.EPrepare().execute(e,raw);self.assertFalse(dropped)
        out,reason=nr.NativeReady().one(pipe,query);self.assertIsNotNone(out,reason)
        self.assertEqual(out[0],2)
        self.assertEqual(pipe.state()['work']['phase'],7)
        return pipe,e,out[1]

    def test_genuine_query_rechecks_n_authority_before_endpoint_egress(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                pipe,e,raw=self.qualified(start)
                self.assertEqual(raw[12:16],bytes.fromhex('0b140002'))
                self.assertEqual(pipe.src.env['tm.bypass_egress'],0)
                before=copy.deepcopy(pipe.src.cells)
                for offset in (0,4,8):
                    bad=bytearray(raw);bad[offset:offset+4]=(int.from_bytes(bad[offset:offset+4],'big')^0x80000000).to_bytes(4,'big')
                    result,_=nr.NativeReady().one(pipe,bytes(bad));self.assertIsNone(result)
                    self.assertEqual(pipe.src.cells,before)

    def test_cached_image_loaded_before_exactly_one_endpoint_and_distinct_completion(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                pipe,e,raw=self.qualified(start)
                dropped,endpoint=ep.EPrepare().execute(e,raw,2);self.assertFalse(dropped)
                self.assertEqual(endpoint,raw[24:])
                self.assertEqual(e.mirror_headers,[(1,raw[:12]+bytes.fromhex('0e140002')+raw[16:24])])
                self.assertEqual(pipe.state()['work']['phase'],7)
                before=copy.deepcopy(e.cells)
                dropped,_=ep.EPrepare().execute(e,raw,2);self.assertTrue(dropped)
                self.assertEqual(e.cells,before)
                self.assertEqual(e.mirror_headers,[])

    def retire_completion(self,pipe,e,completion):
        dropped,qualified=ep.EPrepare().execute(e,completion,68);self.assertFalse(dropped)
        self.assertEqual(qualified[12:16],bytes.fromhex('12140003'))
        self.assertEqual(e.cells[('','reservation')][0]['phase'],2)
        routed,reason=nr.NativeReady().one(pipe,qualified);self.assertIsNotNone(routed,reason)
        self.assertEqual(routed[0],68);self.assertEqual(pipe.src.env['tm.bypass_egress'],0)
        dropped,out=ep.EPrepare().execute(e,routed[1],68);self.assertFalse(dropped)
        self.assertEqual(out,completion)
        return out

    def test_cached_read_overwrites_different_incoming_words_including_low24_tail(self):
        pipe,e,raw=self.qualified()
        altered=bytearray(raw[78:]);altered[4]^=1;altered[-1]^=0x80
        bad=raw[:24]+__import__('test_m_prepare').vectors.packet(24,100,901,payload=bytes(altered))
        dropped,out=ep.EPrepare().execute(e,bad,2);self.assertFalse(dropped)
        # Payload and incoming checksum can differ. Cache bytes must win.
        self.assertEqual(out,raw[24:])
        self.assertEqual(__import__('test_m_prepare').folded(out[14:34]),0xffff)
        pseudo=out[26:34]+bytes([0,6])+len(out[34:]).to_bytes(2,'big')
        self.assertEqual(__import__('test_m_prepare').folded(pseudo+out[34:]),0xffff)

    def test_missing_any_actual_read_completion_cannot_release_or_mirror(self):
        for missing in range(14):
            pipe,e,raw=self.qualified();e.begin_pass(0);e.env['eg.egress_port']=2
            accepted,_=e.packet_parser(raw);self.assertTrue(accepted)
            e.frame=__import__('interp_ext').Frame(e.controls['Ingress'],'')
            e.apply_table('pin_identity_t');e.apply_table('claim_endpoint_t')
            self.assertEqual(e.env['m.grant'],1)
            self.assertEqual(e.cells[('','reservation')][0]['phase'],2)
            for i in range(14):
                if i!=missing:e.apply_table('load_%d_t'%i)
            e.apply_table('endpoint_ready_t')
            self.assertTrue(e.env.get('md.drop_ctl',0)&1)
            e.render_wire();self.assertEqual(e.mirror_headers,[])
            self.assertEqual(e.cells[('','reservation')][0]['phase'],2)
            self.assertEqual(pipe.state()['work']['phase'],7)

    def test_foreign_epoch_completion_cannot_retire_e_pin(self):
        pipe,e,raw=self.qualified();dropped,endpoint=ep.EPrepare().execute(e,raw,2);self.assertFalse(dropped)
        completion=e.mirror_headers[0][1]+endpoint
        bad=bytearray(completion);bad[:4]=(0x80000001).to_bytes(4,'big')
        before=copy.deepcopy(e.cells)
        dropped,_=ep.EPrepare().execute(e,bytes(bad),68);self.assertTrue(dropped)
        self.assertEqual(e.cells,before)

    def test_real_completion_retires_e_pin_without_cache_access_or_endpoint_copy(self):
        pipe,e,raw=self.qualified();dropped,endpoint=ep.EPrepare().execute(e,raw,2);self.assertFalse(dropped)
        completion=e.mirror_headers[0][1]+endpoint
        before=copy.deepcopy(e.cells)
        out=self.retire_completion(pipe,e,completion)
        self.assertEqual(out,completion)
        self.assertEqual(e.cells[('','reservation')][0]['phase'],4)
        for key in before:
            if key!=('','reservation'):self.assertEqual(e.cells[key],before[key])
        self.assertEqual(e.mirror_headers,[])
        after=copy.deepcopy(e.cells)
        dropped,_=ep.EPrepare().execute(e,completion,68);self.assertTrue(dropped)
        self.assertEqual(e.cells,after)


if __name__=='__main__':unittest.main()
