"""v2 emitted-P4 behavior; RESPONSE_READY_RED=1 retains frozen c62 counterexamples."""
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
INTEGRATION = HERE.parents[3]
sys.path[:0] = [str(HERE), str(INTEGRATION / 'read/tests'), str(HERE.parents[2] / 'response_only/hw')]
from t_config import t_units
from m12gen.build import build
from m12gen.common import combined
from queue_sim import QueueSim, ACK_FRAME, RSP_FRAME, REQ_FRAME, OP_FRAME, T0, RELAY, LADDER, OP_LADDER
import test_relay_ts as ts

C62 = HERE.parent / 'ctl_timing_01/evidence/m12p_c62_sdk9132/response_only.p4'


def role(text):
    text = re.sub(r'\bt_(\w+)', r'\1', combined.segment(text, 'T'))
    for name, old, new in (('T_IN',180,197),('HB_RETURN',181,198),('HELD_RETURN',182,199)):
        text = re.sub(r'(const PortId_t '+name+r'\s*=\s*)9w'+str(old)+';',r'\g<1>9w'+str(new)+';',text)
    return '#include <core.p4>\n#include <tna.p4>\n'+text


class SourceSim(QueueSim):
    def set_params(self, gap=5_000_000, budget=60000, enabled=1):
        unit=lambda ns:t_units({'gap':ns},unit_ns=256,grid_ns=512)['gap']
        vals=[unit(gap),unit(2_400_000),budget,enabled]
        if len(self.src.controls['Ingress'].actions['set_params'][0])==5:
            vals.insert(2,1953127)
        self.src.controls['Ingress'].tables['params']['runtime']=[]
        self.src.install('params',(),'set_params',vals)

    def emissions(self,frame,port=None):
        return [t for t,p,raw in self.emitted if (raw==frame or raw[16:]==frame) and(port is None or p==port)]

    def retry(self,time,epoch=1,operate=False):
        self.event(time,15 if operate else 16,OP_FRAME if operate else REQ_FRAME,epoch)


class ResponseReadyTiming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=C62.read_text() if os.environ.get('RESPONSE_READY_RED') else build(**ts.FLAGS,relay_ts=True,response_ready_timing=True)[0]
        cls.tmp=tempfile.TemporaryDirectory();cls.path=Path(cls.tmp.name)/'timing.p4';cls.path.write_text(role(cls.text))
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def sim(self,**kw):
        s=SourceSim(source=self.path,**kw);s.event(T0-10000,14,bytes(60));return s

    def test_waiting_for_response_retry_forwards_without_rearming(self):
        s=self.sim();s.request(T0);s.ack(T0+50000);s.retry(T0+1000000)
        s.response(T0+2000000);s.run(T0+12000000)
        self.assertEqual(len(s.emissions(REQ_FRAME,RELAY)),2)
        self.assertEqual(s.cell('gen_alloc_reg'),2)
        self.assertEqual(s.counter(9),1)
        self.assertEqual(len(s.emissions(ACK_FRAME)),1)
        self.assertGreaterEqual(s.emissions(RSP_FRAME)[0]-s.emissions(ACK_FRAME)[0],5000000)

    def test_queued_response_retry_drops_without_restarting_d(self):
        s=self.sim();s.request(T0);s.ack(T0+50000);s.response(T0+100000);s.retry(T0+2000000)
        s.run(T0+12000000)
        self.assertEqual(len(s.emissions(REQ_FRAME,RELAY)),1)
        self.assertEqual(s.counter(8),1)
        self.assertEqual(s.cell('gen_alloc_reg'),2)
        ack=s.emissions(ACK_FRAME)[0];rsp=s.emissions(RSP_FRAME)[0]
        self.assertGreaterEqual(rsp-ack,5000000);self.assertLess(rsp-ack,5200000)

    def test_response_waiting_for_ack_also_owns_original(self):
        s=self.sim();s.request(T0);s.response(T0+50000);s.retry(T0+1000000);s.ack(T0+2000000)
        s.run(T0+12000000)
        self.assertEqual(len(s.emissions(REQ_FRAME,RELAY)),1);self.assertEqual(s.counter(8),1)
        self.assertEqual(len(s.emissions(RSP_FRAME)),1)

    def test_after_release_retry_forwards_before_master_ack(self):
        s=self.sim();s.request(T0);s.ack(T0+50000);s.response(T0+100000);s.retry(T0+10000000)
        s.response(T0+11000000);s.run(T0+12000000)
        self.assertEqual(len(s.emissions(REQ_FRAME,RELAY)),2);self.assertEqual(s.counter(9),1)
        self.assertEqual(len(s.emissions(RSP_FRAME)),2);self.assertEqual(s.counter(3),1)
        self.assertEqual(s.cell('gen_alloc_reg'),2)

    def test_operate_retry_drops_during_j_and_response_d_then_forwards(self):
        s=self.sim();s.operate(T0);s.retry(T0+1000000,operate=True)
        s.retry(T0+3000000,operate=True)
        s.ack(T0+4000000);s.response(T0+4100000);s.retry(T0+6000000,operate=True)
        s.retry(T0+12000000,operate=True);s.run(T0+15000000)
        self.assertEqual(len(s.emissions(OP_FRAME,RELAY)),3)
        self.assertEqual(s.counter(16),1);self.assertEqual(s.counter(8),1);self.assertEqual(s.counter(9),2)
        self.assertEqual(s.cell('op_gen_alloc_reg'),2);self.assertEqual(s.cell('gen_alloc_reg'),2)
        self.assertGreaterEqual(s.emissions(OP_FRAME,RELAY)[0],T0+2400000)

    def test_timing_disabled_request_retries_forward_without_ownership(self):
        s=self.sim(enabled=0);s.request(T0);s.retry(T0+1000000)
        s.operate(T0+2000000);s.retry(T0+3000000,operate=True);s.run(T0+10000000)
        self.assertEqual(len(s.emissions(REQ_FRAME,RELAY)),2)
        self.assertEqual(len(s.emissions(OP_FRAME,RELAY)),2)
        self.assertEqual(s.counter(8),0);self.assertEqual(s.counter(16),0)
        self.assertEqual(s.counter(9),2)
        self.assertEqual(s.cell('gen_alloc_reg'),1);self.assertEqual(s.cell('op_gen_alloc_reg'),1)

    def test_no_exchange_timeout_and_blocker_budget_never_releases_data(self):
        s=self.sim(budget=1);s.request(T0);s.ack(T0+50000)
        s.response(T0+600000000);s.run(T0+612000000)
        self.assertEqual(len(s.emissions(ACK_FRAME)),1);self.assertEqual(len(s.emissions(RSP_FRAME)),1)
        self.assertGreaterEqual(s.emissions(ACK_FRAME)[0],T0+600000000)
        self.assertGreaterEqual(s.emissions(RSP_FRAME)[0]-s.emissions(ACK_FRAME)[0],5000000)
        self.assertGreater(s.counter(10),0)

    def test_reset_drops_held_originals_and_old_epoch_retries(self):
        s=self.sim();s.request(T0);s.ack(T0+50000);s.response(T0+100000)
        s.reset(T0+1000000);s.retry(T0+2000000)
        s.event(T0+3000000,14,REQ_FRAME,epoch=2);s.request(T0+4000000,epoch=2)
        s.retry(T0+4100000,epoch=2);s.ack(T0+4200000,epoch=2);s.response(T0+4300000,epoch=2)
        s.run(T0+16000000)
        self.assertEqual(len(s.emissions(RSP_FRAME)),1)
        self.assertEqual(s.cell('gen_alloc_reg'),5)
        self.assertEqual(s.counter(9),1)

    def test_all_d_and_arrival_orders(self):
        for d in (5000000,10000000,15000000,20000000):
            for a,r in ((50000,98000000),(98000000,50000)):
                s=self.sim(gap=d);s.request(T0);s.ack(T0+a);s.response(T0+r);s.run(T0+125000000)
                self.assertEqual(len(s.emissions(ACK_FRAME)),1);self.assertEqual(len(s.emissions(RSP_FRAME)),1)
                self.assertGreaterEqual(s.emissions(ACK_FRAME)[0],T0+max(a,r))
                self.assertGreaterEqual(s.emissions(RSP_FRAME)[0]-s.emissions(ACK_FRAME)[0],d)

    def test_one_global_response_access_and_no_timeout_state(self):
        text=role(self.text);code=re.sub(r'//[^\n]*|/\*.*?\*/','',text,flags=re.S)
        self.assertEqual(code.count('response_completion_access.apply();'),1)
        self.assertNotIn('response_wait_timeout',code);self.assertNotIn('t0_reg;',code.replace('op_t0_reg;',''))
        self.assertNotIn('EXPIRED',code)
        self.assertEqual(len(self.sim().src.controls['Ingress'].actions['set_params'][0]),4)

    @unittest.skipUnless(os.environ.get('RESPONSE_READY_CONTEXT'),'compiled context supplied by compiler gate')
    def test_compiled_completion_domains_each_have_one_physical_bank(self):
        context=json.loads(Path(os.environ['RESPONSE_READY_CONTEXT']).read_text())
        for name in ('ack_done_reg','resp_done_reg','op_done_reg'):
            regs=[t for t in context['tables'] if t.get('table_type')=='stateful' and t['name'].endswith('.'+name)]
            self.assertEqual(len(regs),1);self.assertEqual(len(regs[0]['stage_tables']),1)

    def test_n_duplicate_identity_binds_current_shape_function_app_and_range(self):
        import test_n_read_shapes as shared
        from m12gen import relay_sbo
        data=json.loads((HERE.parent/'read_complete_01/vectors/two_read_templates_relay.json').read_text())
        v=data['variants']['v0']['classes']
        mixed=bytes.fromhex(v['mixed']['request']);full=bytes.fromhex(v['integrity']['request'])
        select=bytes.fromhex('056424c4000001004a59cbcb030c011702010101c800000000008136000000030101c8000000000000000015ee')
        def edit(raw,app=None,func=None,bad_object=False):
            h,u=relay_sbo.deframe(raw);u=bytearray(u)
            if app is not None:u[1]=app
            if func is not None:u[2]=func
            if bad_object:u[3]^=1
            return relay_sbo.frame(h,bytes(u))
        def packet(raw,seq):
            out=bytearray(ts.packet(raw));out[38:42]=struct.pack('!I',seq)
            out[50:52]=bytes(2)
            out[50:52]=struct.pack('!H',shared._sum(bytes(out[26:34])+struct.pack('!BBH',0,6,len(out)-34)+bytes(out[34:])))
            return bytes(out)
        def inputs(n,raw,seq,stage,kind):
            n.begin_pass(9);n.packet_parser(packet(raw,seq))
            actual=n.env['m.packet_kind'];self.assertEqual(actual,kind)
            n.env.update({'m.stage':stage,'m.kind':kind,'m.work_phase':1 if stage else 4,'m.epoch_diff':0,'m.direction':1})
            n.table('read_input_t')
            if kind==5:n.action('compare_select_inputs')
            elif kind==7:n.action('compare_operate_inputs' if not stage else 'compare_operate_store_inputs')
            n.table('read_app_t');n.table('application_t')
        def tagged(original,candidate,original_kind,candidate_kind,seq=900,phase=5):
            n=shared.n_source(self.text)
            inputs(n,select if original_kind==9 else mixed,900,1,5 if original_kind==9 else 9)
            inputs(n,original,900,1,original_kind)
            inputs(n,candidate,seq,0,candidate_kind)
            if candidate_kind==9:
                n.table('read_request_full_profile' if n.valid.get('hdr.rd_req_full',n.valid.get('rd_req_full')) else 'read_request_mx_profile')
            else:n.table('profile')
            if n.env.get('m.profile')!=1:return False
            n.env.update({'m.client':900+len(original),'m.server':146,'m.observed':phase<<16|1,'m.new_seq':seq+len(candidate)})
            n.table('sequence_diff');n.table('sequence_guard');n.table('first_event')
            return n.env.get('hdr.event.event')==0x118
        op=edit(select,func=4)
        full=edit(full,app=relay_sbo.deframe(mixed)[1][1])
        for raw,kind in ((mixed,9),(full,9),(select,5),(op,7)):
            self.assertTrue(tagged(raw,raw,kind,kind),kind)
            h,u=relay_sbo.deframe(raw)
            self.assertFalse(tagged(raw,edit(raw,app=0xc0|((u[1]+1)&15)),kind,kind),kind)
            self.assertFalse(tagged(raw,raw,kind,kind,seq=901),kind)
            self.assertFalse(tagged(raw,edit(raw,bad_object=True),kind,kind),kind)
        self.assertFalse(tagged(mixed,full,9,9,seq=898))
        self.assertFalse(tagged(select,op,5,7))
        self.assertFalse(tagged(op,select,7,5))
        self.assertFalse(tagged(select,mixed,5,9,seq=920))
        self.assertFalse(tagged(mixed,select,9,5,seq=880))
        # The stronger function identity preserves successful SELECT/OPERATE
        # association, including application sequence wrap, and both responses.
        response=bytes.fromhex('05642644010000002f77d2cb8180000c011702010101c8000000e2170000000000030101c8000000000000008bf700ffff')
        for sel_app,op_app in ((0xcb,0xcc),(0xcf,0xc0)):
            n=shared.n_source(self.text)
            inputs(n,edit(select,app=sel_app),900,1,5)
            inputs(n,edit(op,app=op_app),945,0,7)
            n.env.update({'m.response':0,'m.diff_real_links':0,'m.diff_real_tcp_dst':0,'m.diff_real_off':0,'m.diff_native_end':0})
            n.table('object_match');self.assertEqual(n.env.get('m.matched'),1)
            for app,kind in ((sel_app,5),(op_app,7)):
                inputs(n,edit(select if kind==5 else op,app=app),900,1,kind)
                n.begin_pass(9);n.packet_parser(ts.packet(edit(response,app=app),reverse=True))
                n.env.update({'m.stage':0,'m.kind':6,'m.work_phase':4,'m.epoch_diff':0,'m.response':1,
                              'm.diff_real_links':0,'m.diff_real_tcp_dst':0,'m.diff_real_off':0,'m.diff_native_end':0})
                n.action('compare_response_inputs');n.table('application_t');n.table('object_match')
                self.assertEqual(n.env.get('m.matched'),1)

    def test_unselected_c52_is_exact(self):
        text,_=build(**ts.FLAGS,relay_ts=True)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),'8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4')

if __name__=='__main__':unittest.main()
