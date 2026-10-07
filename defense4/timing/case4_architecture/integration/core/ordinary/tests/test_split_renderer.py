"""Actual-source loaded-leg admission, once-only final renderer and pipe3 routes."""
import copy
import unittest
import test_e_emit as ee
import test_e_prepare as ep
import test_m_prepare as mp
import test_n_ready as nr


class SplitRenderer(unittest.TestCase):
    def roles(self):
        self.assertTrue((mp.HERE.parent/'split.py').exists(),'split renderer generator missing')
        import split
        return split.generate_roles()

    def test_cache_load_keeps_full_reference_and_defers_endpoint_mirror(self):
        roles=self.roles();pipe,e,raw=ee.EEmit().qualified()
        cache=ep.e_source(roles['e3.p4'])
        cache.cells=copy.deepcopy(e.cells)
        dropped,loaded=ep.EPrepare().execute(cache,raw,452)
        self.assertFalse(dropped)
        self.assertEqual(loaded[:12],raw[:12]);self.assertEqual(loaded[16:],raw[16:])
        self.assertEqual(loaded[12:16],bytes.fromhex('0d140002'))
        self.assertEqual(cache.mirror_headers,[])
        self.assertEqual(cache.cells[('','reservation')][0]['phase'],2)
        before=copy.deepcopy(cache.cells)
        self.assertTrue(ep.EPrepare().execute(cache,raw,452)[0])
        self.assertEqual(cache.cells,before)

    def test_n_loaded_leg_requires_live_full_reference_before_final_renderer(self):
        roles=self.roles();pipe,e,raw=ee.EEmit().qualified()
        n=mp.Pipeline(roles['n3.p4'],mp.vectors.topology(),include_dir=mp.HERE.parent)
        n.src.cells=copy.deepcopy(pipe.src.cells)
        loaded=raw[:12]+bytes.fromhex('0d140002')+raw[16:]
        out,why=nr.NativeReady().one(n,loaded);self.assertIsNotNone(out,why)
        self.assertEqual(out[0],2);self.assertEqual(n.src.env['tm.bypass_egress'],0)
        before=copy.deepcopy(n.src.cells)
        for offset in (0,4,8):
            bad=bytearray(loaded);value=int.from_bytes(bad[offset:offset+4],'big')^0x80000000
            bad[offset:offset+4]=value.to_bytes(4,'big')
            if offset==4:bad[16:20]=value.to_bytes(4,'big')
            self.assertIsNone(nr.NativeReady().one(n,bytes(bad))[0])
            self.assertEqual(n.src.cells,before)
        n.src.cells[('work','work')][0]['phase']=9
        self.assertIsNone(nr.NativeReady().one(n,loaded)[0])

    def test_final_renderer_once_only_full_frame_and_defined24byte_mirror(self):
        roles=self.roles()
        for start in (0,100,0xfffffff0):
            pipe,e,raw=ee.EEmit().qualified(start)
            loaded=raw[:12]+bytes.fromhex('0d140002')+raw[16:]
            f=ep.e_source(roles['f.p4'])
            dropped,frame=ep.EPrepare().execute(f,loaded,2);self.assertFalse(dropped)
            self.assertEqual(frame,raw[24:])
            self.assertEqual(f.mirror_headers,[(1,raw[:12]+bytes.fromhex('0e140002')+raw[16:24])])
            self.assertEqual(mp.folded(frame[14:34]),65535)
            pseudo=frame[26:34]+bytes((0,6))+len(frame[34:]).to_bytes(2,'big')
            self.assertEqual(mp.folded(pseudo+frame[34:]),65535)
            before=copy.deepcopy(f.cells)
            self.assertTrue(ep.EPrepare().execute(f,loaded,2)[0]);self.assertEqual(f.cells,before)
            self.assertEqual(f.mirror_headers,[])

    def test_final_renderer_invalid_role_or_full_identity_cannot_consume_receipt(self):
        roles=self.roles();pipe,e,raw=ee.EEmit().qualified()
        loaded=raw[:12]+bytes.fromhex('0d140002')+raw[16:]
        for offset,value,size in ((0,0,4),(4,0,4),(4,0x80000004,4),(8,0x110002,4),(12,0x0b14,2),(14,3,2)):
            f=ep.e_source(roles['f.p4']);before=copy.deepcopy(f.cells)
            bad=bytearray(loaded);bad[offset:offset+size]=value.to_bytes(size,'big')
            self.assertTrue(ep.EPrepare().execute(f,bytes(bad),2)[0]);self.assertEqual(f.cells,before)
        f=ep.e_source(roles['f.p4']);before=copy.deepcopy(f.cells)
        bad=bytearray(loaded);bad[-1]^=1
        self.assertTrue(ep.EPrepare().execute(f,bytes(bad),2)[0]);self.assertEqual(f.cells,before)
        self.assertTrue(ep.EPrepare().execute(f,loaded,68)[0]);self.assertEqual(f.cells,before)

    def test_entire_source_path_uses_real_returns_until_all_pins_terminal(self):
        roles=self.roles()
        for start in (0,100,0xfffffff0):
            n=mp.Pipeline(roles['n3.p4'],mp.vectors.topology(),include_dir=mp.HERE.parent)
            for port,frame in ((1,mp.vectors.packet(2,(start-1)&0xffffffff,mss=1500)),
                               (2,mp.vectors.packet(18,900,start,True,mss=1500)),
                               (1,mp.vectors.packet(16,start,901))):
                self.assertFalse(n.inject(port,frame).dropped)
            selected=n.inject(1,mp.vectors.packet(24,start,901,payload=mp.vectors.native_select()))
            self.assertEqual(selected.emitted[0][0],196)
            m=mp.WireSource(roles['m3.p4'])
            m.install('forwarding',(196,),'route',(452,));m.install('forwarding',(198,),'route',(452,))
            m.install('connection',(mp.vectors.CLIENT,mp.vectors.SERVER,mp.vectors.CLIENT_PORT,mp.vectors.SERVER_PORT),'allow_connection',())
            cache=ep.e_source(roles['e3.p4']);bridge=mp.WireSource(roles['e3.p4']);f=ep.e_source(roles['f.p4'])
            def service(raw,port):
                dropped,out=ep.EPrepare().execute(cache,raw,port);self.assertFalse(dropped)
                dropped,routed=mp.MPrepare().execute(bridge,out,port);self.assertFalse(dropped)
                self.assertEqual(bridge.env['tm.ucast_egress_port'],68)
                return routed
            dropped,prepared=mp.MPrepare().execute(m,selected.emitted[0][1]);self.assertFalse(dropped)
            ready=service(prepared,452)
            qualified,_=nr.NativeReady().one(n,ready);self.assertIsNotNone(qualified)
            activate,_=nr.NativeReady().one(n,qualified[1]);self.assertEqual(activate[0],196)
            dropped,dirty=mp.MPrepare().execute(m,activate[1]);self.assertFalse(dropped)
            dropped,query=mp.MPrepare().execute(m,dirty,198);self.assertFalse(dropped)
            self.assertEqual(m.env['tm.ucast_egress_port'],452)
            authority,_=nr.NativeReady().one(n,service(query,452));self.assertEqual(authority[0],452)
            loaded=service(authority[1],452)
            final,_=nr.NativeReady().one(n,loaded);self.assertEqual(final[0],2)
            dropped,endpoint=ep.EPrepare().execute(f,final[1],2);self.assertFalse(dropped)
            self.assertEqual(endpoint,prepared[24:]);self.assertEqual(len(endpoint),109)
            completion=f.mirror_headers[0][1]+endpoint
            terminal,_=nr.NativeReady().one(n,service(completion,453));self.assertEqual(terminal[0],453)
            drained,_=nr.NativeReady().one(n,service(terminal[1],453));self.assertEqual(drained[0],68)
            out,_=nr.NativeReady().one(n,drained[1]);self.assertIsNone(out)
            self.assertEqual(n.state()['work']['phase'],9)
            self.assertEqual(cache.cells[('','reservation')][0]['phase'],4)
            self.assertEqual(m.cells[('','reservation')][0]['phase'],4)

    def test_service_role_port_mismatch_cannot_mutate_cache(self):
        roles=self.roles();cache=ep.e_source(roles['e3.p4'])
        prepared=ep.EPrepare().prepared()
        before=copy.deepcopy(cache.cells)
        self.assertTrue(ep.EPrepare().execute(cache,prepared,453)[0]);self.assertEqual(cache.cells,before)


if __name__=='__main__':unittest.main()
