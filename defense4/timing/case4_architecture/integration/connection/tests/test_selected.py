import dataclasses
import importlib
import sys
import unittest
from pathlib import Path

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import test_connection as fixture
from test_connection import FLOW,packet,control
import case4_padding as codec
try:api=importlib.import_module('selected_reference')
except ModuleNotFoundError:api=None

class Selected(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api,'autonomous selected-object publisher missing')
        helper=fixture.Connection();helper.setUp();helper.established();self.c=helper.c
        self.decoy=codec.Decoy(201,bytes.fromhex("0101000000000000000000"))
        self.p=api.SelectedPublisher(self.c,self.decoy)

    def commit(self,raw):
        work=self.p.begin_select(raw,9);self.assertIsNotNone(work)
        for _ in range(3):work=self.p.advance(work)
        self.assertEqual(work.outcome,'forward')

    def response(self,frame=None,status=0):
        head,user=codec.decode_frame(codec.expand_control(frame or control(),self.decoy)[0])
        objects=bytearray(user[3:]);objects[17]=status
        response=codec.build_frame(bytes.fromhex('05642e4401000a00'),user[:2]+bytes((0x81,0,0))+objects)
        return packet(24,901,136,reverse=True,payload=response)

    def test_actual_cache_dispatch_never_overwrites_published_or_busy_record(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        text=(HERE/'selected.p4').read_text().replace(',_):',',32w0&&&32w0):')
        for response,stage,operation,phase,published,expected in (
                (0,0,1,4,0,1),(0,0,1,4,19,0),(0,0,1,1,0,0),
                (1,0,0,4,19,3),(0,0,0,4,19,2),(0,1,2,1,19,0)):
            source=Source(text,{'m.response':response,'m.stage':stage,'m.work_op':operation,
                'm.work_phase':phase,'m.context_generation':published,'m.cache_mode':0})
            source.table('cache_access')
            self.assertEqual(source.env['m.cache_mode'],expected)

    def test_actual_private_return_requires_retained_native_select(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        text=(HERE/'selected.p4').read_text()
        for response,function,expected in ((0,3,2),(0,4,0),(1,0x81,0)):
            source=Source(text,{'m.response':response,'hdr.first.w0':function<<8,
                'hdr.generation.generation':17,'m.work_op':0})
            source.table('return_packet')
            self.assertEqual(source.env['m.work_op'],expected)
            if not expected:self.assertEqual(source.env['md.drop_ctl'],1)

    def test_actual_response_operate_gate_requires_fresh_terminal_work(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        text=(HERE/'selected.p4').read_text()
        for stage,operation,phase,expected in ((0,0,4,1),(0,0,1,0),(1,2,4,0)):
            source=Source(text,{'m.stage':stage,'m.work_op':operation,'m.work_phase':phase,
                'm.association_allowed':0})
            source.table('association_admission')
            self.assertEqual(source.env['m.association_allowed'],expected)

    def test_actual_match_requires_next_operate_app_and_handles_nibble_wrap(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        from selected_association import FIELDS
        text=(HERE/'selected.p4').read_text()
        for response,difference,expected in ((1,0,1),(0,0xffffffff,1),(0,15,1),
                (0,0,0),(1,0xffffffff,0)):
            values={'m.diff_'+name:0 for name in FIELDS}
            values.update({'m.response':response,'m.diff_application':difference,'m.matched':0})
            source=Source(__import__('re').sub(r'\br\b','rv',text),values,registers={('accepted',0):{'generation':17,'phase':5}});source.table('object_match')
            self.assertEqual(source.env['m.matched'],expected)

    def test_actual_reader_compares_against_stored_real_object(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\br\b','rv',(HERE/'selected.p4').read_text())
        source=Source(text,{'m.compare_real_object':0x12340102,'m.compare_real_on':23},registers={('pair_real_object_real_on',0):{'first':0x12340101,'second':23}})
        source.action('compare_real_object')
        self.assertNotEqual(source.env['m.diff_real_object'],0)
        self.assertEqual(source.registers[('pair_real_object_real_on',0)],{'first':0x12340101,'second':23})

    def test_actual_source_saves_real_packet_object_and_separate_frozen_decoy(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\br\b','rv',(HERE/'selected.p4').read_text())
        source=Source(text,{'hdr.first.w2':0x12340101,'m.decoy_index':0x5678,'m.decoy_code':1,'m.decoy_repeat':2},
            registers={('pair_real_object_real_on',0):{'first':0,'second':0},('pair_frozen_decoy_object_frozen_decoy_on',0):{'first':0,'second':0}})
        source.action('compare_select_inputs');source.action('store_real_object');source.action('store_frozen_decoy_object')
        self.assertEqual(source.registers[('pair_real_object_real_on',0)]['first'],0x12340101)
        self.assertEqual(source.registers[('pair_frozen_decoy_object_frozen_decoy_on',0)]['first'],0x56780102)

    def test_paired_cell_mismatch_never_accepts_equal_other_word(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\br\b','rv',(HERE/'selected.p4').read_text())
        for left,right,expected in ((17,23,0),(18,23,1),(17,24,1)):
            source=Source(text,{'m.compare_real_object':left,'m.compare_real_on':right},
                registers={('pair_real_object_real_on',0):{'first':17,'second':23}})
            source.action('compare_real_object')
            self.assertEqual(source.env['m.diff_real_object'],expected)
            self.assertEqual(source.registers[('pair_real_object_real_on',0)],{'first':17,'second':23})

    def test_acceptance_salu_refuses_wrong_generation_and_uncommitted_phase(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        import re
        text=re.sub(r'\br\b','rv',(HERE/'selected.p4').read_text())
        for generation,phase,expected in ((17,5,0),(18,5,1),(17,4,1)):
            source=Source(text,{'m.context_generation':17},
                registers={('accepted',0):{'generation':generation,'phase':phase}})
            source.action('match_operate')
            self.assertEqual(source.env['m.accepted_diff'],expected)
            self.assertEqual(source.registers[('accepted',0)],{'generation':generation,'phase':6 if expected==0 else phase})

    def test_actual_byte_decoders_and_all_saved_cells_match_response_before_ack_mapping(self):
        sys.path.insert(0,str(HERE.parents[1]/'protocol'))
        from source_eval import Source
        from selected_compact import PAIRS, CHECK_FIELDS
        from selected_association import FIELDS
        import re
        text=re.sub(r'\br\b','rv',(HERE/'selected.p4').read_text())
        def fields(raw,response):
            p=fixture.api.parse_packet(raw);head,user=codec.decode_frame(p.payload)
            values={'hdr.ip.src':p.flow[0],'hdr.ip.dst':p.flow[1],
                'hdr.tcp.sport':p.flow[2],'hdr.tcp.dport':p.flow[3],
                'hdr.tcp.seq':p.seq,'hdr.tcp.ack':p.ack,
                'hdr.dl.dst':int.from_bytes(head[4:6],'big'),
                'hdr.dl.src':int.from_bytes(head[6:8],'big')}
            for index in range(4):values['hdr.first.w'+str(index)]=int.from_bytes(user[index*4:index*4+4],'big')
            if response:
                for index in range(4):values['hdr.second.w'+str(index)]=int.from_bytes(user[16+index*4:20+index*4],'big')
                values.update({'hdr.response_tail.w0':int.from_bytes(user[32:36],'big'),
                    'hdr.response_tail.w1':int.from_bytes(user[36:40],'big'),
                    'hdr.response_tail.w2':user[40]})
            else:values['hdr.tail.off']=int.from_bytes(user[16:20],'big')
            return values
        banks={('pair_'+a+'_'+b,0):{'first':0,'second':0} for a,b in PAIRS}
        banks.update({('application',0):0,('frozen_decoy_off',0):0})
        values=fields(packet(24,101,901,payload=control()),False)
        values.update({'m.decoy_index':0xc900,'m.decoy_code':1,'m.decoy_repeat':1,
            'm.decoy_on':0,'m.decoy_off':0})
        source=Source(text,values,registers=banks)
        source.action('calculate_native_end');source.action('compare_select_inputs')
        for a,b in PAIRS:source.action('store_'+a)
        for name in ('application','frozen_decoy_off'):source.action('store_'+name)
        head,user=codec.decode_frame(fixture.api.parse_packet(self.response()).payload)
        for corrupt in (False,True):
            changed=bytearray(user)
            if corrupt:changed[13]^=1
            # The response reaches this component before reverse ACK mapping:
            # wire end101+55=156, native end101+35=136.
            raw=packet(24,901,156,reverse=True,payload=codec.build_frame(head,changed))
            compared=Source(text,fields(raw,True),registers=source.registers.copy())
            compared.action('compare_response_inputs')
            for a,b in PAIRS:compared.action('compare_'+a)
            for name in ('application','frozen_decoy_off'):compared.action('compare_'+name)
            self.assertEqual(any(compared.env['m.diff_'+name] for name in CHECK_FIELDS),corrupt)

    def test_real_select_fields_frozen_then_all_status_response_and_operate(self):
        self.commit(packet(24,101,901,payload=control()))
        self.assertEqual(self.p.record.objects,codec.decode_frame(control())[1][3:])
        self.assertEqual(self.p.record.connection_epoch,self.c.epoch)
        self.assertTrue(self.p.accept_select_response(self.response(),12))
        self.assertTrue(self.p.admit_operate(packet(24,136,958,payload=control(4,1)),9))

    def test_real_packet_sequence_and_application_wrap_keep_exact_pair(self):
        helper=fixture.Connection();helper.setUp()
        helper.finish(packet(2,0xffffffef,mss=1460))
        helper.finish(packet(18,0xffffffdf,0xfffffff0,reverse=True,mss=1460),12)
        helper.finish(packet(16,0xfffffff0,0xffffffe0))
        self.c=helper.c;self.p=api.SelectedPublisher(self.c,self.decoy)
        self.commit(packet(24,0xfffffff0,0xffffffe0,payload=control(app=15)))
        payload=fixture.api.parse_packet(self.response(control(app=15))).payload
        self.assertTrue(self.p.accept_select_response(
            packet(24,0xffffffe0,19,reverse=True,payload=payload),12))
        self.assertTrue(self.p.admit_operate(packet(24,19,25,payload=control(4,0)),9))

    def test_bad_crc_or_wrong_sequence_never_claims_or_writes(self):
        frame=bytearray(control());frame[-1]^=1
        for raw in (packet(24,101,901,payload=bytes(frame)),packet(24,102,901,payload=control())):
            self.assertIsNone(self.p.begin_select(raw,9));self.assertIsNone(self.p.work)
            self.assertIsNone(self.p.record)

    def test_bad_status_wrong_objects_app_or_response_ack_does_not_authorize_operate(self):
        self.commit(packet(24,101,901,payload=control()))
        before=self.p.snapshot()
        self.assertFalse(self.p.accept_select_response(self.response(status=1),12))
        self.assertFalse(self.p.accept_select_response(self.response(control(app=1)),12))
        self.assertEqual(self.p.snapshot(),before)
        self.assertFalse(self.p.admit_operate(packet(24,136,958,payload=control(4,1)),9))

    def test_reset_mid_write_blocks_publication_until_actual_terminal(self):
        work=self.p.begin_select(packet(24,101,901,payload=control()),9)
        work=self.p.advance(work)
        self.c.cell=6<<16|self.c.generation
        for _ in range(2):work=self.p.advance(work)
        self.assertEqual(work.outcome,'refused');self.assertIsNone(self.p.record)
        self.assertIsNone(self.p.work)

    def test_stale_identity_cannot_write_publish_or_release_the_current_work(self):
        work=self.p.begin_select(packet(24,101,901,payload=control()),9)
        stale=dataclasses.replace(work,work_generation=work.work_generation+1)
        before=self.p.snapshot();self.assertEqual(self.p.advance(stale).outcome,'refused')
        self.assertEqual(self.p.snapshot(),before)
        self.assertIsNone(self.p.begin_select(packet(24,101,901,payload=control()),9))

    def test_operate_object_or_application_change_and_policyoff_do_not_mutate_context(self):
        self.commit(packet(24,101,901,payload=control()))
        self.assertTrue(self.p.accept_select_response(self.response(),12))
        self.assertFalse(self.p.admit_operate(packet(24,136,958,payload=control(4,0)),9))
        self.assertFalse(self.p.admit_operate(packet(24,136,958,payload=control(4,1)),9,policy_enabled=False))
        self.assertIsNotNone(self.p.record)

if __name__=='__main__':unittest.main()
