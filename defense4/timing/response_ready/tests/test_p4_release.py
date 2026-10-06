"""Source-driven response-ready table regressions; no hardware model claim."""
import sys
import os
import re
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'stage_reduction'))
import verify_stage_reduction_semantics as sem
SOURCE = Path(os.environ.get('P4_RESPONSE_READY_SOURCE', ROOT / 'response_ready/src/defense4_response_ready.p4'))

def table_effect(source, name, fields):
    result=sem.parse_const_table(source,name,sem.extract_consts(source)).apply(fields)
    if result and result.startswith('finish_'):
        body=sem.extract_named_block(source,result)
        match=re.search(r'meta.outcome\s*=\s*(OUT_\w+)\s*;',body)
        if match is None: raise AssertionError('terminal action has no outcome')
        return match.group(1)
    return result

class ReleaseTables(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text()
        self.c = sem.extract_consts(self.source)

    def select(self, name, **fields):
        return table_effect(self.source, name, dict(owner_valid=1, **fields))

    def test_live_blocker_waits_even_after_deadline(self):
        for age in (0, 256, 100000 << 8):
            self.assertEqual(self.select('tbl_decide_deq', read_release=1, role=self.c['ROLE_BLOCK'], verdict=self.c['V_BLOCK_LIVE'], age=age), 'OUT_AB_LOOP')

    def test_pending_requires_deadline(self):
        for age, outcome in ((0,'OUT_AB_DL'), (0xFFFFFF00,'OUT_AB_LOOP')):
            self.assertEqual(self.select('tbl_decide_deq', read_release=1, role=self.c['ROLE_BLOCK'], verdict=self.c['V_BLOCK_PENDING'], age=age), outcome)

    def test_watchdog_live_and_pending(self):
        for verdict in ('V_BLOCK_LIVE','V_BLOCK_PENDING'):
            self.assertEqual(self.select('tbl_decide_deq', read_release=1, role=self.c['ROLE_BLOCK'], verdict=self.c[verdict], age=0xFFFFFF00,budget_zero=1),'OUT_AB_TMO')

    def test_fresh_request_disarms(self):
        self.assertEqual(self.select('tbl_resp_deadline',read_release=1,anchor_req=1,pkt_class=self.c['CLASS_ARM'],tag_diff=0xC0),'resp_dl_disarm')

    def test_native_ack_does_not_arm(self):
        self.assertEqual(self.select('tbl_resp_deadline',read_release=1,anchor_req=1,pkt_class=self.c['CLASS_ACK'],tag_diff=0x3F),'resp_dl_read')

    def test_qualified_return_arms(self):
        self.assertEqual(self.select('tbl_resp_deadline',read_release=1,anchor_req=1,pkt_class=self.c['CLASS_ACK_REL']),'resp_dl_arm')
        for key in ('seq_diff','ack_diff','sport_diff'):
            self.assertEqual(self.select('tbl_resp_deadline',read_release=1,anchor_req=1,pkt_class=self.c['CLASS_ACK_REL'],**{key:1}),'resp_dl_read')

    def test_return_deadline_arms_once_across_wrap(self):
        body=sem.extract_register_action_block(self.source,'tresp_arm_once').replace('meta.dl_val_resp','meta.dl_val')
        for now in (0x100001,0xFFFFF001):
            deadline=(now+(3906 << 8)) & 0xFFFFFFFF
            _, stored=sem.eval_deadline_arm_once_body(body,self.c['UNARMED_WORD'],deadline,self.c)
            self.assertEqual(stored,deadline)
            _, duplicate=sem.eval_deadline_arm_once_body(body,stored,(deadline+4096)&0xFFFFFFFF,self.c)
            self.assertEqual(duplicate,deadline)
        mutated=body.replace('if (v == UNARMED_WORD)', 'if (v != UNARMED_WORD)')
        with self.assertRaises(AssertionError):
            sem.eval_deadline_arm_once_body(mutated,self.c['UNARMED_WORD'],123,self.c)

    def test_disabled_parity(self):
        baseline = (ROOT / 'latency_search/randomized/defense4_timing_randomized.p4').read_text()
        for table in ('tbl_decide_deq','tbl_resp_deadline'):
            original=sem.parse_const_table(baseline,table,self.c)
            candidate=sem.parse_const_table(self.source,table,self.c)
            for row in original.rows:
                fields=dict(zip(original.keys,(value for value,mask in row.matches)))
                fields['read_release']=0
                self.assertEqual(table_effect(self.source,table,fields),original.apply(fields))

    def test_release_mutations_are_detected(self):
        original=self.source
        mutations=(
            ('test_live_blocker_waits_even_after_deadline', 'dec_loop(OUT_AB_LOOP);', 'dec_o(OUT_AB_DL);'),
            ('test_fresh_request_disarms', ': resp_dl_disarm();', ': resp_dl_rmw();'),
            ('test_qualified_return_arms', ': resp_dl_arm();', ': resp_dl_read();'),
        )
        for check, old, new in mutations:
            with self.subTest(check=check):
                if old not in original and check=='test_live_blocker_waits_even_after_deadline':
                    rows=sem.parse_const_table(original,'tbl_decide_deq',self.c).rows
                    loop=next(row for row in rows if row.argument=='OUT_AB_LOOP')
                    drop=next(row for row in rows if row.argument=='OUT_AB_DL')
                    old,new=': '+loop.action+'(OUT_AB_LOOP);', ': '+drop.action+'(OUT_AB_DL);'
                self.source=original.replace(old,new,1)
                self.assertTrue(self.source != original, 'mutation did not change source')
                with self.assertRaises(AssertionError): getattr(self,check)()
        self.source=original

if __name__ == '__main__': unittest.main()
