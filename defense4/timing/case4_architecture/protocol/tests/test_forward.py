import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parents[1]/'framework/p4'));sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
from source_eval import Source,block
import fixed_layout
import case4_padding as padding
import primitives
import test_protocol as fixtures
class ActualForward(unittest.TestCase):
    def test_compiled_direction_sources_forward_modular_fields(self):
        for base in (1000,0xfffffff0):
            for direction,name in ((1,'mapping_forward.p4'),(2,'mapping_reverse.p4')):
                text=(HERE/name).read_text()
                for offset in (34,35,54,55,69,70,89,90,109,110):
                    for window in (0,1,20,65535):
                        seq=(base+offset)&0xffffffff
                        s=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'hdr.tcp.offset':5,'hdr.tcp.reserved':0,'hdr.tcp.flags':16,'hdr.tcp.urgent':0,'hdr.tcp.seq':seq,'hdr.tcp.ack':seq,'hdr.tcp.window':window},
                            {'forwarding':('route',(12,)),'connection':('configure',(base,(base+35)&0xffffffff,3,direction))})
                        s.run(block(block(text,'control Ingress'),'apply{'))
                        self.assertEqual(s.env['tm.ucast_egress_port'],12);self.assertEqual(s.env.get('md.drop_ctl',0),0)
                        if direction==1:self.assertEqual(s.env['hdr.tcp.seq'],fixed_layout.map_seq(seq,base,(base+35)&0xffffffff))
                        else:self.assertEqual((s.env['hdr.tcp.ack'],s.env['hdr.tcp.window']),fixed_layout.map_ack_window(seq,window,base,(base+35)&0xffffffff))
    def test_exact_replay_preserves_current_ack_window_flags_and_wire_image(self):
        native=fixtures.ExactImages().native(3);image=padding.expand_control(native,padding.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
        text=(HERE/'exact_replay.p4').read_text()
        for base in (1000,0xfffffff0):
            for bad in (False,True):
                fields={'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'hdr.native.data':native[-1]^int(bad),'hdr.tcp.seq':(base+34)&0xffffffff,'hdr.tcp.ack':0xaabbccdd,'hdr.tcp.window':1234,'hdr.tcp.flags':24,'hdr.ip.id':81}
                s=Source(text,fields,{'forwarding':('route',(12,)),'replay':('cached',(base,native[-1],0))},registers={(f'read_{i}',0):w for i,w in enumerate(primitives.ExactImage.capture(image).words())})
                s.run(block(block(text,'control Ingress'),'apply{'))
                if bad:self.assertEqual(s.env['md.drop_ctl'],1);continue
                self.assertEqual(s.render('image'),image);self.assertEqual(s.env['hdr.tcp.seq'],base)
                for field in ('hdr.tcp.ack','hdr.tcp.window','hdr.tcp.flags','hdr.ip.id'):self.assertEqual(s.env[field],fields[field])
