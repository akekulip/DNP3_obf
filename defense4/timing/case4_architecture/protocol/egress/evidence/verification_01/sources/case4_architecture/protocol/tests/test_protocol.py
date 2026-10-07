import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parents[1]/'framework/size'))
import case4_padding as padding
import rrc
import primitives

class ExactImages(unittest.TestCase):
    def native(self,fc,tp=0xff,app=0xcf):
        return padding.build_frame(bytes.fromhex('05641ac4ffff0100'), bytes([tp,app,fc])+bytes.fromhex('0c01280100ffff8102ffffffff0102030400'))
    def test_canonical_preserves_every_phase_byte(self):
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        images=[]
        for fc,tp,app in ((3,0xff,0xcf),(4,0xc0,0xc0)):
            native=self.native(fc,tp,app)
            expected,delta=padding.expand_control(native,decoy)
            self.assertEqual(delta,20)
            record=primitives.Canonical.capture(native,decoy)
            self.assertEqual(record.render(),expected)
            self.assertEqual(primitives.ExactImage.capture(expected).render(),expected)
            self.assertEqual(record.replay(34,1),expected[34:])
            images.append(expected)
        self.assertNotEqual(images[0],images[1])
    def test_bad_crc_every_block_and_profile_rejected(self):
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        native=self.native(3)
        for position in (8,26,33):
            bad=bytearray(native);bad[position]^=1
            with self.assertRaises(ValueError):primitives.Canonical.capture(bytes(bad),decoy)
        with self.assertRaises(ValueError):primitives.Canonical.capture(self.native(5),decoy)
    def test_exact_slice_resegmentation_and_wrap_is_offset_based(self):
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        image=padding.expand_control(self.native(3),decoy)[0]
        record=primitives.ExactImage.capture(image)
        for begin in range(35):
            self.assertEqual(record.replay(begin,35-begin),image[begin:])
        with self.assertRaises(ValueError):record.replay(35,1)
    def test_sources_are_executable_and_complete_forward(self):
        text=(HERE/'mapping.p4').read_text()
        self.assertIn('action complete()',text)
        self.assertIn('tm.ucast_egress_port=m.output_port',text)
        self.assertNotIn('MAX_PASSES',text)
        self.assertIn('m.right=hdr.tcp.ack+m.full_window',text)

class SourceBytes(unittest.TestCase):
    def test_grouped_mapping_actual_tables_wrap_both_edges(self):
        from source_eval import Source,block
        sys.path.insert(0,str(HERE.parents[1]/'framework/p4'))
        import fixed_layout
        text=(HERE/'mapping.p4').read_text()
        for base in (1000,0xfffffff0):
            for position in (-2,0,34,35,54,55,69,70,89,90,109,110,128,500):
                for window in (0,1,20,65535):
                    seq=(base+position)&0xffffffff
                    for direction in (1,2):
                        source=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb,
                            'hdr.tcp.offset':5,'hdr.tcp.reserved':0,'hdr.tcp.flags':16,'hdr.tcp.urgent':0,
                            'hdr.tcp.seq':seq,'hdr.tcp.ack':seq,'hdr.tcp.window':window},
                            {'forwarding':('route',(12,)),'connection':('configure',(base,(base+35)&0xffffffff,3,direction))})
                        source.run(block(block(text,'control Ingress'),'apply'))
                        self.assertFalse(source.env.get('md.drop_ctl',0))
                        if direction==1:self.assertEqual(source.env['hdr.tcp.seq'],fixed_layout.map_seq(seq,base,(base+35)&0xffffffff))
                        else:self.assertEqual((source.env['hdr.tcp.ack'],source.env['hdr.tcp.window']),fixed_layout.map_ack_window(seq,window,base,(base+35)&0xffffffff))
                        self.assertEqual(source.env['tm.ucast_egress_port'],12)
    def test_exact_and_canonical_actual_record_loads_render_all_bytes(self):
        from source_eval import Source
        native=ExactImages().native(3)
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        image=padding.expand_control(native,decoy)[0]
        for canonical,name in ((False,'exact_replay.p4'),(True,'canonical_replay.p4')):
            text=(HERE/name).read_text()
            if canonical:
                head,user=padding.decode_frame(image);raw=head+user;words=[int.from_bytes((raw+b'\0')[i:i+4],'big') for i in range(0,48,4)]
            else:words=primitives.ExactImage.capture(image).words()
            for slot in (0,1):
                source=Source(text,{'m.image_slot':slot},registers={(f'read_{i}',slot):w for i,w in enumerate(words)})
                for i in range(len(words)):source.action(f'load_{i}')
                source.action('last_slice')
                if canonical:
                    for hashname in ('head','block0','block1','tail'):source.action('crc_'+hashname)
                    source.action('crc_swap')
                self.assertEqual(source.render('image'),image)
    def test_native_validator_constructs_exact_image(self):
        from source_eval import Source,block
        text=(HERE/'padding.p4').read_text()
        decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
        for fc in (3,4):
            native=ExactImages().native(fc)
            for broken in (None,8,26,33):
                data=bytearray(native)
                if broken is not None:data[broken]^=1
                source=Source(text,{'m.parsed':1,'m.ip_error':False,'m.tcp_sum':0xffeb})
                start=0
                for header in ('dl','native','tail'):
                    fields=[(f,w) for f,w in source.width.items() if f.startswith('hdr.'+header+'.')]
                    count=sum(w for _,w in fields)//8;bits=int.from_bytes(data[start:start+count],'big');left=count*8
                    for field,width in fields:left-=width;source.env[field]=(bits>>left)&((1<<width)-1)
                    start+=count
                source.runtime={'forwarding':('route',(12,)),'connection':('configure',(0xc900,1,1,0x64000000,0x64000000))}
                source.run(block(block(text,'control Ingress'),'apply'))
                output=b''.join(source.render(h) for h in ('dl','native','tail','appended','last') if source.valid.get(h,h in ('dl','native','tail')))
                expected=padding.expand_control(bytes(data),decoy)[0]
                self.assertEqual(output,expected)
                self.assertEqual(source.env.get('m.changed',0),int(broken is None))

if __name__=='__main__':unittest.main()
