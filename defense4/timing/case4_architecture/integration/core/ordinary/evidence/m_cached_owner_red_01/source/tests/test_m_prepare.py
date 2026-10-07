"""Actual P4 N receiver/constructor source tests. Checksums at wire remain model gates."""
from pathlib import Path
import copy
import sys
import unittest

HERE=Path(__file__).resolve().parent
ARCH=HERE.parents[3]
sys.path.insert(0,str(ARCH/'integration/core/harness'))
from interp_ext import ExtSource
from driver import Pipeline
import vectors
import case4_padding


class MPrepare(unittest.TestCase):
    def handoff(self,start=0):
        n=Pipeline.from_path(HERE.parent/'n.p4',vectors.topology())
        # Only configuration is installed; connection and Work derive from packets.
        for port,frame in ((1,vectors.packet(2,(start-1)&0xffffffff,mss=1500)),
                           (2,vectors.packet(18,900,start,True,mss=1500)),
                           (1,vectors.packet(16,start,901))):
            out=n.inject(port,frame);self.assertFalse(out.dropped,out.drop_reason)
        native=vectors.native_select()
        out=n.inject(1,vectors.packet(24,start,901,payload=native))
        self.assertEqual(out.emitted[0][0],196)
        return out.emitted[0][1],native

    def receiver(self):
        m=ExtSource((HERE.parent/'m.p4').read_text())
        m.install('forwarding',(196,),'route',(68,))
        m.install('connection',(vectors.CLIENT,vectors.SERVER,vectors.CLIENT_PORT,vectors.SERVER_PORT),'allow_connection',())
        return m

    def execute(self,m,raw,port=196):
        m.begin_pass(port);accepted,cursor=m.packet_parser(raw)
        if not accepted:return True,b''
        m.apply_control('Ingress')
        return bool(m.env.get('md.drop_ctl',0)&1),m.deparse()+raw[cursor:]

    def test_actual_n_handoff_constructs_exact55_from_captured_decoy_zero_and_wrap(self):
        for start in (0,100,0xfffffff0):
            with self.subTest(start=start):
                raw,native=self.handoff(start);m=self.receiver()
                dropped,out=self.execute(m,raw)
                self.assertFalse(dropped)
                self.assertEqual(m.env.get('m.changed'),1)
                self.assertEqual(out[28:32],raw[4:8])
                self.assertEqual(out[36:40],raw[8:12])
                self.assertEqual(out[36+54:],case4_padding.expand_control(native,vectors.DECOY)[0])
                self.assertEqual(int.from_bytes(out[36+16:36+18],'big'),95)
                self.assertEqual(out[4:12],raw[4:12])
                self.assertEqual(m.env.get('tm.ucast_egress_port'),68)
                self.assertEqual(m.env.get('tm.bypass_egress'),0)
                before=copy.deepcopy(m.cells)
                duplicate,_=self.execute(m,raw)
                self.assertTrue(duplicate)
                self.assertEqual(m.cells,before)

    def test_invalid_private_admission_never_mutates_m_banks(self):
        raw,_=self.handoff()
        cases=[]
        for begin,end,value in ((0,4,0),(4,8,0),(8,12,0x80001),(12,14,0x0307),(14,16,0)):
            bad=bytearray(raw);bad[begin:end]=value.to_bytes(end-begin,'big');cases.append(bytes(bad))
        bad=bytearray(raw);bad[28+24]^=1;cases.append(bytes(bad)) # IPv4 checksum
        bad=bytearray(raw);bad[-1]^=1;cases.append(bytes(bad)) # actual DNP3/TCP corruption
        for number,bad in enumerate(cases):
            with self.subTest(number=number):
                m=self.receiver();before=copy.deepcopy(m.cells)
                dropped,_=self.execute(m,bad)
                self.assertTrue(dropped)
                self.assertEqual(m.cells,before)
        m=self.receiver();before=copy.deepcopy(m.cells)
        dropped,_=self.execute(m,raw,197)
        self.assertTrue(dropped);self.assertEqual(m.cells,before)


if __name__=='__main__':unittest.main()
