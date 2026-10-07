import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
import case4_padding as padding
from source_eval import Source,block
import test_protocol as fixtures

def parse_source(text,data):
    s=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb})
    start=0
    for header in ('dl','first','second','tail'):
        fields=[(f,w) for f,w in s.width.items() if f.startswith('hdr.'+header+'.')];count=sum(w for _,w in fields)//8
        bits=int.from_bytes(data[start:start+count],'big');left=count*8
        for field,width in fields:left-=width;s.env[field]=(bits>>left)&((1<<width)-1)
        start+=count
    return s

def response():
    image=padding.expand_control(fixtures.ExactImages().native(3),padding.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
    head,user=padding.decode_frame(image);head=bytearray(head);head[3]=0x44
    user=bytearray(user[:2]+b'\x81\0\0'+user[3:]);user[22]=3;user[40]=4
    return padding.build_frame(bytes(head),bytes(user))

class ResponseCarving(unittest.TestCase):
    def test_actual_four_crc_gate_preserves_statuses_then_exact_slices_wrap(self):
        text=(HERE/'carving.p4').read_text();frame=response();self.assertEqual(len(frame),57)
        for broken in (None,8,26,44,55):
            data=bytearray(frame)
            if broken is not None:data[broken]^=1
            s=parse_source(text,data);s.runtime={'forwarding':('route',(12,)),'connection':('split',(7,))}
            s.run(block(block(text,'control Ingress'),'apply'))
            self.assertEqual(s.env.get('tm.mcast_grp_a',0),7 if broken is None else 0)
        for base in (1000,0xfffffff0):
            outputs=[]
            for rid,action,expected,length,seq,flags in ((1,'render_first',frame[:28],68,base,16),(2,'render_second',frame[28:],69,(base+28)&0xffffffff,24)):
                s=parse_source(text,frame);s.env.update({'hdr.tcp.seq':base,'hdr.tcp.flags':24});s.action(action)
                payload=b''.join(s.render(h) for h in ('dl','first','second','tail') if s.valid.get(h,True));outputs.append(payload)
                self.assertEqual(payload,expected);self.assertEqual(s.env['hdr.ip.len'],length);self.assertEqual(s.env['hdr.tcp.seq'],seq);self.assertEqual(s.env['hdr.tcp.flags'],flags)
            self.assertEqual(b''.join(outputs),frame)
            self.assertNotEqual(b''.join(reversed(outputs)),frame)
        _,user=padding.decode_frame(frame);self.assertEqual((user[22],user[40]),(3,4))
    def test_valid_wrong_object_is_not_association_proof(self):
        text=(HERE/'carving.p4').read_text();head,user=padding.decode_frame(response());wrong=bytearray(user);wrong[10]^=1
        s=parse_source(text,padding.build_frame(head,wrong));s.runtime={'forwarding':('route',(12,)),'connection':('split',(7,))}
        s.run(block(block(text,'control Ingress'),'apply'))
        # Primitive validates shapes and bytes; external frozen-object association is still required.
        self.assertEqual(s.env['tm.mcast_grp_a'],7)

class SelectedResponse(unittest.TestCase):
    def test_selected_set_rejects_changed_valid_objects_preserves_status(self):
        from generate_selected_carving import SELECTED_KEYS
        text=(HERE/'selected_carving.p4').read_text();frame=response();original=parse_source(text,frame)
        frozen={key:original.expr(key) for key in SELECTED_KEYS}
        head,user=padding.decode_frame(frame)
        for position in (None,10,12,13,14,18,29,31,32,33,37,0,1):
            changed=bytearray(user)
            if position is not None:changed[position]^=1
            s=parse_source(text,padding.build_frame(head,changed))
            s.runtime={'forwarding':('route',(12,)),'connection':('split',(7,)),
                       'selected_objects':{'keys':frozen,'action':'selected','args':()}}
            s.run(block(block(text,'control Ingress'),'apply{'))
            self.assertEqual(s.env.get('tm.mcast_grp_a',0),7 if position is None else 0,position)
        for realstatus,decoystatus in ((0,0),(3,4),(255,254)):
            changed=bytearray(user);changed[22]=realstatus;changed[40]=decoystatus
            s=parse_source(text,padding.build_frame(head,changed));s.runtime={'forwarding':('route',(12,)),'connection':('split',(7,)),'selected_objects':{'keys':frozen,'action':'selected','args':()}}
            s.run(block(block(text,'control Ingress'),'apply{'));self.assertEqual(s.env['tm.mcast_grp_a'],7)
