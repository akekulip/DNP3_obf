"""Fixed-layout oracle/source checks, not execution of a compiled Tofino pipeline."""
import sys
from pathlib import Path
import unittest
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'size'))
sys.path.insert(0,str(BASE/'p4'))
import case4_padding as padding
import rrc
try:
    import fixed_layout
except ImportError:
    fixed_layout=None

class Layout(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(fixed_layout,'fixed-layout P4 byte oracle is missing')
    def test_layout_matches_strict_codec_all_native_fields_and_crcs(self):
        for func in (3,4):
            for on,off,count in ((100,100,1),(0x12345678,0xabcdef01,3),(0,0xffffffff,7)):
                body=bytes([1,count])+on.to_bytes(4,'little')+off.to_bytes(4,'little')+bytes([0])
                user=bytes([0xc7,0xc5,func])+bytes.fromhex('0c012801000100')+body
                frame=padding.build_frame(bytes.fromhex('056400c40a000100'),user)
                decoy=padding.Decoy(201,bytes.fromhex('0101640000006400000000'))
                expected,_=padding.expand_control(frame,decoy)
                self.assertEqual(fixed_layout.expand(frame,decoy),expected)
    def test_carve_layout_matches_explicit_profile(self):
        from test_rrc_split import packet,dnp3_frame
        for n,name in ((33,'RRC_49_CUT28'),(41,'RRC_57_CUT28')):
            frame=dnp3_frame(bytes(range(n)));a,b=fixed_layout.carve(frame)
            actual=rrc.carve(packet(frame),profile=name)
            self.assertEqual((a,b),tuple(rrc.parse(p).payload for p in actual))
    def test_source_has_real_crc_and_size_operations(self):
        src=(BASE/'p4/case4_size_kernel.p4')
        self.assertTrue(src.exists(),'actual TNA size kernel source is missing')
        s=src.read_text()
        for fragment in ('CRCPolynomial<bit<16>>','h_native_tail','hdr.out1.setValid()',
                         'hdr.out2.setValid()','hdr.ip.total_len + 16w20',
                         'RRC_57','hdr.tcp.seq + 32w28','tcp_checksum.update'):
            self.assertIn(fragment,s)

    def test_two_boundary_maps_match_actual_image_transport_oracle(self):
        self.assertTrue(hasattr(fixed_layout,'map_ack_window'),'two-boundary mapping probe is missing')
        from case4_transport import RequestLedger
        for base in (1000,0xfffffff0):
            ledger=RequestLedger(base)
            frame=padding.build_frame(bytes.fromhex('056400c40a000100'),bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
            image=padding.expand_control(frame,padding.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
            ledger.forward(base,frame,replacement=image)
            ledger.forward((base+35)&0xffffffff,frame,replacement=image)
            for offset in range(0,151):
                ack=(base+offset)&0xffffffff
                self.assertEqual(fixed_layout.map_ack_window(ack,40,base,(base+35)&0xffffffff),ledger.reverse(ack,40))
                seq=(base+offset)&0xffffffff
                self.assertEqual(fixed_layout.map_seq(seq,base,(base+35)&0xffffffff),ledger.forward(seq,b'').seq)
    def test_wire_ablation_retains_input_checksum_guards(self):
        s=(BASE/'p4/case4_wire_only.p4').read_text()
        self.assertIn('NO TCP LEDGER',s)
        self.assertIn('Checksum() tcp_check;',s)
        self.assertIn('m.tcp_sum=tcp_check.get()',s)
        self.assertNotIn('tcp_check.verify()',s)
        self.assertNotIn('tcp_check.add(',s)
        self.assertIn('bool ip_error;',s)
        self.assertIn('m.ip_error=ip_check.verify()',s)
        self.assertIn('(m.ip_error==false)',s)
        self.assertNotIn('m.ip_valid=!m.ip_valid',s)
        self.assertIn('m.tcp_sum==16w0xFFEB',s)
        self.assertNotIn('Register<bit<32>,bit<8>>(1) first_base',s)

    def test_target_tail_clamps_leave_native_byte_outstanding(self):
        # Evaluate the actual source action expression, independently of the
        # layout oracle. This is source semantics, not silicon execution.
        import re
        source=(BASE/'p4/case4_size_kernel.p4').read_text()
        for action,field in (('ack_clamp_first','base'),('ack_clamp_second','op_base')):
            match=re.search(r'action '+action+r'\(\)\s*\{hdr.tcp.ack=m\.'+field+r'\+32w(\d+);\}',source)
            self.assertIsNotNone(match)
            for start in (1000,0xfffffff0):
                observed=(start+int(match[1]))&0xffffffff
                self.assertEqual(observed,(start+34)&0xffffffff)

    def test_partial_tail_windows_at_both_boundaries_do_not_overflow(self):
        from case4_transport import RequestLedger
        frame=padding.build_frame(bytes.fromhex('056400c40a000100'),bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
        image=padding.expand_control(frame,padding.Decoy(201,bytes.fromhex('0101640000006400000000')))[0]
        for base in (1000,0xfffffff0):
            ledger=RequestLedger(base)
            ledger.forward(base,frame,replacement=image)
            ledger.forward((base+35)&0xffffffff,frame,replacement=image)
            for offset in tuple(range(35,55))+tuple(range(90,110)):
                for window in (0,1,19,20,21,65535):
                    self.assertEqual(fixed_layout.map_ack_window((base+offset)&0xffffffff,window,base,(base+35)&0xffffffff),ledger.reverse((base+offset)&0xffffffff,window))

    def test_exclusive_subtract_checksum_residue_arithmetic(self):
        from test_rrc_split import packet,dnp3_frame
        self.assertTrue(hasattr(fixed_layout,'tcp_subtract_residual'))
        for payload in (b'',bytes(range(35)),dnp3_frame(bytes(range(33))),dnp3_frame(bytes(range(41)))):
            raw=packet(payload)
            self.assertEqual(fixed_layout.tcp_subtract_residual(raw),0xffeb)
            damaged=bytearray(raw);damaged[38]^=1
            self.assertNotEqual(fixed_layout.tcp_subtract_residual(damaged),0xffeb)

    def test_checksum_correct_non_ipv4_is_excluded_before_padding(self):
        from test_rrc_split import packet
        frame=padding.build_frame(bytes.fromhex('056400c40a000100'),bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
        raw=bytearray(packet(frame));raw[14]=0x65;raw[24:26]=b'\0\0'
        raw[24:26]=rrc._csum(bytes(raw[14:34])).to_bytes(2,'big')
        self.assertEqual(rrc._csum(bytes(raw[14:34])),0)
        pseudo=bytes(raw[26:34])+b'\0\x06'+(len(raw)-34).to_bytes(2,'big')
        self.assertEqual(rrc._csum(pseudo+bytes(raw[34:])),0)
        with self.assertRaises(ValueError):fixed_layout.tcp_subtract_residual(raw)
        for filename in ('case4_size_kernel.p4','case4_wire_only.p4'):
            source=(BASE/'p4'/filename).read_text()
            eg=source[source.index('parser EgParser'):]
            self.assertIn('select(hdr.ip.version,hdr.ip.ihl,hdr.ip.proto,hdr.ip.frag,hdr.ip.flags)',eg)
            self.assertIn('(4w4,4w5,8w6,13w0,3w0):tcp',eg)
            self.assertIn('(4w4,4w5,8w6,13w0,3w2):tcp',eg)
            self.assertIn('hdr.tcp.reserved!=4w0',source)
            self.assertIn('hdr.tcp.urgent!=16w0',source)
            self.assertIn('hdr.tcp.flags&8w0xF7',source)

    def test_resource_report_binds_source_and_assembler(self):
        import tempfile,json,hashlib
        import report_resources
        with tempfile.TemporaryDirectory() as temp:
            build=Path(temp);source=build/'probe.p4';source.write_text('probe')
            out=build/'out/pipe';out.mkdir(parents=True)
            bfa=out/'probe.bfa';bfa.write_text('stage 0 ingress:\nstage 11 egress:\n')
            manifest={'source':'probe.p4','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                'compiler':'test','exit_code':0,'artifact_sha256':{'out/pipe/probe.bfa':hashlib.sha256(bfa.read_bytes()).hexdigest()}}
            (build/'manifest.json').write_text(json.dumps(manifest))
            report=report_resources.summarize(build)
            self.assertTrue(report['within_stage_limits'])
            self.assertEqual(report['stage_span'],{'ingress':1,'egress':12})
            inputs=build/'inputs.json'
            inputs.write_text(json.dumps({'output_sha256':manifest['source_sha256']}))
            manifest['inputs_sha256']=hashlib.sha256(inputs.read_bytes()).hexdigest()
            (build/'manifest.json').write_text(json.dumps(manifest))
            self.assertTrue(report_resources.summarize(build)['inputs_identity_verified'])
            inputs.write_text('{}')
            with self.assertRaises(ValueError):report_resources.summarize(build)
            inputs.write_text(json.dumps({'output_sha256':manifest['source_sha256']}))
            bfa.write_text('stage 0 ingress:\nstage 12 egress:\n')
            with self.assertRaises(ValueError):report_resources.summarize(build)
            manifest['artifact_sha256']['out/pipe/probe.bfa']=hashlib.sha256(bfa.read_bytes()).hexdigest()
            (build/'manifest.json').write_text(json.dumps(manifest))
            self.assertFalse(report_resources.summarize(build)['within_stage_limits'])
            bfa.write_text('stage 0 ingress:\n')
            manifest['artifact_sha256']['out/pipe/probe.bfa']=hashlib.sha256(bfa.read_bytes()).hexdigest()
            (build/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):report_resources.summarize(build)


    def test_source_has_actual_two_boundaries_and_template_state(self):
        s=(BASE/'p4/case4_size_kernel.p4').read_text()
        for fragment in ('Register<bit<32>,bit<8>>(1) first_base','second_base',
                         'selected_on','selected_off','selected_identity','selected_tag',
                         'm.ack_delta','ack_clamp_first','hdr.tcp.ack=hdr.tcp.ack-32w20'):
            self.assertIn(fragment,s)

if __name__=='__main__':unittest.main()
