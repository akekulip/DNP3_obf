import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(HERE));sys.path.insert(0,str(HERE.parent));sys.path.insert(0,str(HERE.parent.parents[1]/'framework/size'))
import case4_padding as codec
from assembly_eval import Source
from source_eval import block
class Producer(unittest.TestCase):
    def native(self):return codec.build_frame(bytes.fromhex('05641ac4ffff0100'),bytes.fromhex('ffcf040c01280100ffff8102ffffffff0102030400'))
    def fields(self,offset,data,base):
        return {'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'m.length':len(data),'m.full_length':len(data),'m.private':0,'hdr.tcp.seq':(base+offset)&0xffffffff,**{f'hdr.b{i}.data':v for i,v in enumerate(data)}}
    def advance(self,text,fields,banks,now,base):
        clear={name:0 for name in ('m.fault','m.foreign','m.publish','m.complete','m.profile','m.selected_match','m.badh','m.badb','m.badt','m.bad_offset','m.bad_end')}
        source=Source(text,{**fields,**clear,'p.global_tstamp':now},registers=banks)
        native=self.native();keys=(4,5,6,7,11,18,19,20,21,22,23,24,25,28,29,30,31,32)
        source.runtime={'connection':('context',(1,7,base)),'selected_objects':{'keys':{f'hdr.frame.b{i}':native[i] for i in keys},'action':'selected','args':()}}
        source.run(block(block(text,'control Ingress'),'apply{'));return source
    def fragment(self,text,offset,data,banks,now,base):
        fields=self.fields(offset,data,base)
        for hop in range(8):
            s=self.advance(text,fields,banks,now+hop*1024,base)
            if s.env.get('m.publish') or s.env.get('md.drop_ctl'):return s
            fields={k:v for k,v in s.env.items() if k.startswith('hdr.')};fields.update({'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,'m.private':1,'m.length':len(data),'m.full_length':len(data)})
        raise AssertionError('unbounded source loop')
    def test_actual_reordered_fragments_origin_zero_wrap_and_full_crc(self):
        text=(HERE/'producer.p4').read_text();native=self.native()
        for now,base in ((0,1000),(0xffffff00,0xfffffff0)):
            banks={('origin',0):{'generation':0,'observation':0}}
            first=self.fragment(text,17,native[17:],banks,now,base);self.assertFalse(first.env['m.publish'])
            self.assertEqual(banks[('origin',0)]['observation'],now)
            last=self.fragment(text,0,native[:17],banks,(now+20000)&0xffffffff,base)
            self.assertEqual(last.render('frame'),native);self.assertEqual(last.env['m.publish'],1)
            self.assertEqual(banks[('origin',0)]['observation'],now)
    def test_bad_complete_crc_sticky_and_expired_do_not_publish(self):
        text=(HERE/'producer.p4').read_text();native=bytearray(self.native());native[26]^=1
        banks={('origin',0):{'generation':0,'observation':0}}
        s=self.fragment(text,0,native,banks,0,1000);self.assertFalse(s.env['m.publish']);self.assertEqual(banks[('transport_fault',0)],1)
        old=dict(banks);fields=self.fields(0,b'x',1000);fields.update({'m.private':1,'hdr.ref.epoch':1,'hdr.ref.generation':7,'hdr.ref.event':2,'hdr.fragment.hops':1})
        for i in range(12):fields[f'hdr.expected.w{i}']=banks[(f'bucket_{i}',0)];fields[f'hdr.candidate.w{i}']=0
        self.advance(text,fields,banks,0,1000);self.assertEqual(banks,old)
        expired={('origin',0):{'generation':7,'observation':0}}
        s=self.fragment(text,0,self.native()[:1],expired,30_000_128,1000);self.assertFalse(s.env['m.publish']);self.assertEqual(expired[('transport_fault',0)],1)

    def test_foreign_private_cookie_cannot_poison_and_hops_are_bounded(self):
        text=(HERE/'producer.p4').read_text();banks={('origin',0):{'generation':7,'observation':0},('transport_fault',0):0}
        fields=self.fields(0,self.native()[:1],1000);fields.update({'m.private':1,'hdr.ref.epoch':1,'hdr.ref.generation':8,'hdr.ref.event':1,'hdr.fragment.hops':1})
        before={key:dict(value) if isinstance(value,dict) else value for key,value in banks.items()}
        s=self.advance(text,fields,banks,0,1000);self.assertEqual(banks,before);self.assertEqual(s.env['md.drop_ctl'],1)
        fields['hdr.ref.generation']=7;fields['hdr.fragment.hops']=17
        s=self.advance(text,fields,banks,0,1000);self.assertFalse(s.env['m.publish']);self.assertEqual(s.env['hdr.ref.event'],6)
