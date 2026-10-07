import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
import case4_padding as padding
from source_eval import Source,block
from generate_selected import SELECTED_KEYS
import test_protocol as fixtures

def parsed(text,data):
    s=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb})
    start=0
    for header in ('dl','native','tail'):
        fields=[(f,w) for f,w in s.width.items() if f.startswith('hdr.'+header+'.')];count=sum(w for _,w in fields)//8
        bits=int.from_bytes(data[start:start+count],'big');left=count*8
        for field,width in fields:left-=width;s.env[field]=(bits>>left)&((1<<width)-1)
        start+=count
    return s
class SelectedObjects(unittest.TestCase):
    def test_exact_object_and_phase_match_not_shape_only(self):
        text=(HERE/'selected_padding.p4').read_text();native=fixtures.ExactImages().native(4);original=parsed(text,native)
        frozen={key:original.env[key] for key in SELECTED_KEYS}
        for changed in (None,*SELECTED_KEYS):
            s=parsed(text,native)
            if changed:s.env[changed]^=1
            # Recompute all native CRCs after the mutation: input is still well formed.
            s.action('input_head');s.env['hdr.dl.crc']=((s.env['m.hcrc']&255)<<8)|(s.env['m.hcrc']>>8)
            s.action('input_body');s.env['hdr.native.crc']=((s.env['m.bcrc']&255)<<8)|(s.env['m.bcrc']>>8)
            s.action('input_tail');s.env['hdr.tail.crc']=((s.env['m.tcrc']&255)<<8)|(s.env['m.tcrc']>>8)
            s.runtime={'forwarding':('route',(12,)),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000)),
                       'selected_objects':{'keys':frozen,'action':'selected','args':()}}
            s.run(block(block(text,'control Ingress'),'apply'))
            self.assertEqual(s.env.get('m.changed',0),changed is None,changed)
    def test_default_uninstalled_selected_set_never_transforms(self):
        text=(HERE/'selected_padding.p4').read_text();s=parsed(text,fixtures.ExactImages().native(3))
        s.runtime={'forwarding':('route',(12,)),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000))}
        s.run(block(block(text,'control Ingress'),'apply'));self.assertEqual(s.env.get('m.changed',0),0)
