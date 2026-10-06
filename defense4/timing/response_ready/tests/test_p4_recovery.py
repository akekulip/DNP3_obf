"""Executable source-bound admission tests; not a complete pipeline model."""
import re
import unittest
from test_p4_release import SOURCE, sem, table_effect


def execute(source,name,stored,**fields):
    """Interpret assignments/if blocks from the narrow 32-bit register-action subset."""
    block=sem.extract_register_action_block(source,name)
    body=sem._extract_block_after(block,block.index('void apply'))[1:-1]
    width=int(re.search(r'inout bit<(\d+)> v',block).group(1))
    mask=(1<<width)-1
    env={'v':stored,'rv':0,**sem.extract_consts(source)}
    env.update({'meta_'+k:v for k,v in fields.items()})
    def expression(expr):
        expr=re.sub(r'\(int<8>\)\s*v', '(v if v < 128 else v - 256)',expr)
        expr=re.sub(r'\(int<32>\)\s*v', '(v if v < 2147483648 else v - 4294967296)',expr)
        expr=re.sub(r'\b\d+[ws](0x[0-9a-fA-F]+|\d+)',r'\1',expr)
        expr=expr.replace('meta.','meta_').replace('||',' or ').replace('&&',' and ')
        if not re.fullmatch(r'[\w\s()+<>=!&|\-]+',expr): raise AssertionError('unsupported expression')
        return eval(expr,{'__builtins__':{}},env)
    def run(text):
        while text.strip():
            text=text.lstrip()
            if text.startswith('if '):
                opening=text.index('(');depth=1;end=opening+1
                while depth:
                    depth+=(text[end]=='(')-(text[end]==')');end+=1
                condition=text[opening+1:end-1]
                branch=sem._extract_block_after(text,end)
                matched=expression(condition)
                if matched: run(branch[1:-1])
                text=text[text.index('{',end)+len(branch):].lstrip()
                if text.startswith('else if'):
                    if matched:
                        skipped=sem._extract_block_after(text,text.index('if'))
                        text=text[text.index('{')+len(skipped):]
                    else: text=text[5:]
            else:
                match=re.match(r'(v|rv)\s*=\s*([^;]+);',text)
                if not match: raise AssertionError('unsupported statement: '+text[:80])
                env[match[1]]=expression(match[2]) & mask
                text=text[match.end():]
    run(body)
    return env['rv'],env['v']

class RecoveryGates(unittest.TestCase):
    def setUp(self): self.source=SOURCE.read_text(); self.c=sem.extract_consts(self.source)
    def table(self,name,**fields): return table_effect(self.source,name,fields)

    def test_pending_timeout_then_next_request(self):
        # Pending reg_tag may be 0x11; independent admission remains owner 0xC1.
        old,owner=execute(self.source,'owner_arm',0,cookie_in=0)
        self.assertEqual((old,owner),(0,0x80000001))
        self.assertEqual(self.table('tbl_owner_admission',read_release=1,mode=self.c['MODE_D4_DUAL'],pkt_class=self.c['CLASS_BLOCK_DEQ'],dequeued=1,role=self.c['ROLE_BLOCK'],budget_zero=1),'owner_release')
        _,owner=execute(self.source,'owner_retire',owner,cookie_in=0x80000001)
        self.assertEqual(owner,0x1)
        self.assertEqual(self.table('tbl_owner_valid',read_release=1,held_valid=1,owner=0x80000000),'owner_accept')
        old,owner=execute(self.source,'owner_arm',owner,cookie_in=0)
        self.assertEqual((old,owner),(0x1,0x80000002))

    def test_stale_returns_do_not_retire_new_owner(self):
        for old in range(1,18):
            for current in range(1,18):
                _,after=execute(self.source,'owner_retire',current|0x80000000,cookie_in=old|0x80000000)
                self.assertEqual(after,current if old==current else current|0x80000000)
                self.assertEqual(self.table('tbl_owner_valid',read_release=1,held_valid=1,owner=(current-old)&0xFFFFFFFF),'owner_accept' if old==current else 'owner_reject')

    def test_integrated_pending_release_and_duplicate_return(self):
        # Connect actual register bodies and table selections across one transaction.
        prior,owner=execute(self.source,'owner_arm',0,cookie_in=0)
        self.assertEqual(self.table('tbl_guarded_ack',read_release=1,owner=prior,
                         sess=self.c['SESS_MASTER'],role=self.c['ROLE_ARM']),'tracker_ack_write')
        _,tag=execute(self.source,'tag_rmw',0,gen_in=0xC1,tag_val=0xC1)
        _,deadline=execute(self.source,'tresp_disarm',123,now_word=0x10001)
        ack_diff,tag=execute(self.source,'tag_rmw',tag,gen_in=0,tag_val=self.c['TAG_NO_WRITE'])
        self.assertEqual(self.table('tbl_resp_deadline',read_release=1,anchor_req=1,
                         pkt_class=self.c['CLASS_ACK'],tag_diff=ack_diff),'resp_dl_read')
        _,tag=execute(self.source,'tag_read_or_mark',tag,tag_val=self.c['TAG_PENDING_DELTA'])
        token_owner,_=execute(self.source,'owner_read',owner,cookie_in=owner)
        pending=self.table('tbl_txn_active',read_release=1,cur_gen=tag,owner=token_owner)
        self.assertEqual(pending,'mark_txn_pending')
        for slot,outcome in ((1,'OUT_ADMIT_ACK'),(2,'OUT_ADMIT_RESP')):
            self.assertEqual(self.table('tbl_decide_fresh',read_release=1,owner_valid=1,
                             role=self.c['ROLE_BLOCK'],is_pktgen=1,pgen_slot=slot,txn_active=2),outcome)
        self.assertEqual(self.table('tbl_decide_deq',read_release=1,owner_valid=1,
                         role=self.c['ROLE_BLOCK'],verdict=self.c['V_BLOCK_PENDING'],age=0),'OUT_AB_DL')
        held_owner,_=execute(self.source,'owner_read',owner,cookie_in=owner)
        self.assertEqual(self.table('tbl_resp_deadline',read_release=1,anchor_req=1,owner=held_owner,
                         pkt_class=self.c['CLASS_ACK_REL']),'resp_dl_arm')
        now=0x02000001
        gap=3906<<8
        action=sem.extract_named_block(self.source,'build_read_release_cand')
        rhs=re.search(r'meta.tresp_cand\s*=\s*([^;]+)',action).group(1)
        candidate=eval(rhs.replace('meta.now_word',str(now)).replace('meta.read_gap_ticks',str(gap)),{'__builtins__':{}})&0xFFFFFFFF
        _,deadline=execute(self.source,'tresp_arm_once',deadline,dl_val_resp=candidate)
        _,duplicate=execute(self.source,'tresp_arm_once',deadline,dl_val_resp=candidate+4096)
        self.assertEqual(duplicate,deadline)
        for tick,outcome in ((deadline-256,'OUT_RB_LOOP'),(deadline,'OUT_RB_DL')):
            age,_=execute(self.source,'tresp_read',deadline,now_word=tick)
            self.assertEqual(self.table('tbl_decide_deq',read_release=1,owner_valid=1,
                             role=self.c['ROLE_BLOCK'],is_resp_blk=1,verdict=self.c['V_BLOCK_PENDING'],age_resp=age),outcome)
        _,owner=execute(self.source,'owner_retire',owner,cookie_in=owner)
        _,tag=execute(self.source,'tag_rmw',tag,gen_in=0,tag_val=self.c['TAG_INACTIVE'])
        self.assertEqual((owner,tag),(1,0))

    def test_watchdog_rearms_without_feedback_packet(self):
        _,owner=execute(self.source,'owner_arm',0,cookie_in=0)
        current=owner
        _,owner=execute(self.source,'owner_retire',owner,cookie_in=current)
        held,_=execute(self.source,'owner_read',owner,cookie_in=current)
        self.assertEqual(self.table('tbl_owner_valid',read_release=1,held_valid=1,owner=held),'owner_accept')
        previous,new_owner=execute(self.source,'owner_arm',owner,cookie_in=0)
        self.assertEqual((previous,new_owner),(1,0x80000002))
        stale,_=execute(self.source,'owner_read',new_owner,cookie_in=current)
        self.assertEqual(self.table('tbl_owner_valid',read_release=1,held_valid=1,owner=stale),'owner_reject')

    def test_busy_request_blocks_tracker_writes(self):
        for next_gen in range(1,18):
            old,after=execute(self.source,'owner_arm',0x80000003,cookie_in=next_gen|0x80000000)
            self.assertEqual(after,0x80000003)
            self.assertEqual(self.table('tbl_tracker_admission',read_release=1,owner=old),'block_trackers')
        for mode in ('MODE_OFF','MODE_FAIL_OPEN'):
            self.assertEqual(self.table('tbl_owner_admission',read_release=1,mode=self.c[mode],pkt_class=self.c['CLASS_ARM'],role=self.c['ROLE_ARM']),'owner_observe')

    def test_guarded_tracker_tables_use_admission_prestate(self):
        fields=dict(read_release=1,sess=self.c['SESS_MASTER'],role=self.c['ROLE_ARM'])
        for name in ('seq','sport','ack'):
            table='tbl_guarded_'+name
            self.assertEqual(self.table(table,owner=0x12,**fields),'tracker_'+name+'_write')
            for owner in (0x80000012,0xFFFF,0x8000FFFF):
                self.assertEqual(self.table(table,owner=owner,**fields),'tracker_'+name+'_read')
        source=sem.strip_comments(self.source)
        self.assertTrue('tbl_guarded_seq.apply();' in source)
        self.assertTrue('meta.cookie_in = 16w0x8000 ++ hdr.pgen.trigger_cookie;' in source)
        self.assertTrue('hdr.ib.cookie_word = meta.cookie_in;' in source)
        body=sem.extract_named_block(self.source,'cmt_fwd_clone_ready')
        self.assertTrue('meta.next_cookie' in body)

    def test_retirement_predicate_mutation_detected(self):
        mutant=self.source.replace('if (v == meta.cookie_in)', 'if (v != meta.cookie_in)',1)
        self.assertTrue(mutant != self.source, 'mutation did not change source')
        _,after=execute(mutant,'owner_retire',0x80000002,cookie_in=0x80000001)
        self.assertNotEqual(after,0x80000002)

    def test_enabled_watchdog_priority_and_domain(self):
        common=dict(read_release=1,mode=self.c['MODE_D4_DUAL'],dequeued=1,role=self.c['ROLE_BLOCK'])
        self.assertEqual(self.table('tbl_owner_admission',budget_zero=0,**common),'owner_observe')
        for slot in ('SLOT_ACK','SLOT_RESP'):
            self.assertEqual(self.table('tbl_owner_admission',budget_zero=1,token_slot=self.c[slot],**common),'owner_release')
        self.assertEqual(self.table('tbl_owner_admission',budget_zero=1,token_slot=self.c['SLOT_OP'],**common),'owner_observe')
        for isresp,outcome in ((0,'OUT_AB_TMO'),(1,'OUT_RB_TMO')):
            fields=dict(role=self.c['ROLE_BLOCK'],is_resp_blk=isresp,verdict=self.c['V_BLOCK_PENDING'],budget_zero=1,age=0,age_resp=0)
            self.assertEqual(self.table('tbl_decide_deq',read_release=1,owner_valid=1,**fields),outcome)
            self.assertEqual(self.table('tbl_decide_deq',read_release=1,owner_valid=0,**fields),'OUT_DEQ_DROP')
            self.assertEqual(self.table('tbl_decide_deq',read_release=0,owner_valid=1,**fields),'OUT_RB_DL' if isresp else 'OUT_AB_DL')

    def test_cookie_exhaustion_never_reuses_identity(self):
        old,active=execute(self.source,'owner_arm',0xFFFE,cookie_in=0)
        self.assertEqual(active,0x8000FFFF)
        _,idle=execute(self.source,'owner_retire',active,cookie_in=active)
        for _ in range(3):
            old,after=execute(self.source,'owner_arm',idle,cookie_in=0)
            self.assertEqual(after,idle)
            self.assertEqual(self.table('tbl_tracker_admission',read_release=1,owner=old),'block_trackers')

    def test_old_trigger_cookie_is_rejected_after_generation_alias(self):
        current=0x80000012
        old=0x020001
        self.assertEqual(self.table('tbl_owner_valid',read_release=1,held_valid=0,role=self.c['ROLE_BLOCK'],owner=(current-old)&0xFFFFFFFF),'owner_reject')
        self.assertEqual(self.table('tbl_decide_fresh',owner_valid=0),'OUT_PKTGEN_DROP')
        self.assertEqual(self.table('tbl_decide_deq',read_release=1,owner_valid=0),'OUT_DEQ_DROP')

    def test_pending_retransmission_after_watchdog_bypasses(self):
        self.assertEqual(self.table('tbl_txn_active',read_release=1,owner=0x2,cur_gen=0x12,pkt_class=self.c['CLASS_RESP']),'mark_txn_inactive')

    def test_shim_table_does_not_rewrite_blockers(self):
        self.assertEqual(self.table('tbl_held_owner',read_release=1,dequeued=1,held_valid=0,outcome=self.c['OUT_AB_LOOP']),'NoAction')
        self.assertEqual(self.table('tbl_held_owner',read_release=1,dequeued=1,held_valid=1),'strip_owner')

    @staticmethod
    def _action(table, fields):
        """The matched row's action name (table.apply returns only the outcome argument)."""
        for row in table.rows:
            if all((fields.get(k, 0) & m) == v for k, (v, m) in zip(table.keys, row.matches)):
                return row.action
        return table.default_action

    def test_timeout_note_terminates_in_every_mode(self):
        """A budget-zero token must leave the block queue for good, in every mode and both lanes.

        Multi-pass: the timeout pass, then each return of whatever it re-enqueued. The single-pass
        parity test cannot see a note that keeps coming back (reviewer finding, 2026-10-06)."""
        c = self.c
        owner_action = {'owner_release': 'owner_retire', 'owner_observe': 'owner_read', 'owner_admit': 'owner_arm'}
        for mode in ('MODE_D4_DUAL', 'MODE_FAIL_OPEN', 'MODE_OFF'):
            for slot, is_resp in (('SLOT_ACK', 0), ('SLOT_RESP', 1)):
                stored = cookie = 0x80000012
                trace = []
                for _ in range(8):
                    action = table_effect(SOURCE.read_text(), 'tbl_owner_admission', dict(
                        read_release=1, mode=c[mode], dequeued=1, role=c['ROLE_BLOCK'], budget_zero=1,
                        held_valid=0, token_slot=c[slot]))
                    returned, stored = execute(SOURCE.read_text(), owner_action[action], stored, cookie_in=cookie)
                    valid = table_effect(SOURCE.read_text(), 'tbl_owner_valid', dict(
                        read_release=1, held_valid=0, owner=returned, role=c['ROLE_BLOCK']))
                    action = self._action(sem.parse_const_table(SOURCE.read_text(), 'tbl_decide_deq', c), dict(
                        role=c['ROLE_BLOCK'], is_resp_blk=is_resp, verdict=c['V_BLOCK_PENDING'], budget_zero=1,
                        age=0, age_resp=0, read_release=1, owner_valid=1 if valid == 'owner_accept' else 0))
                    trace.append(action)
                    if action == 'finish_path_0':     # the drop path: the token is gone
                        break
                self.assertEqual(trace[-1], 'finish_path_0', (mode, slot, trace))
                self.assertLessEqual(len(trace), 2, (mode, slot, trace))

if __name__ == '__main__': unittest.main()
