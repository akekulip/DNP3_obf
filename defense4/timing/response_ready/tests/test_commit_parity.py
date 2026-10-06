"""Compare fused terminal effects with build 22; this is not a pipeline simulator."""
import os
import re
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'stage_reduction'))
import verify_stage_reduction_semantics as sem

REFERENCE = ROOT / 'response_ready/evidence/local_build_22/defense4_timing.p4'
SOURCE = Path(os.environ.get('P4_RESPONSE_READY_SOURCE', ROOT / 'response_ready/src/defense4_response_ready.p4'))


class Program:
    def __init__(self, source):
        self.source = re.sub(r'/\*.*?\*/|//[^\n]*', '', sem.preprocess_defines(source), flags=re.DOTALL).replace('\\\n', '')
        self.consts = sem.extract_consts(self.source)
        for name, value in re.findall(r'#define\s+(\w+)\s+(\d+w(?:0x[\da-fA-F]+|\d+))', self.source):
            self.consts[name] = sem.parse_p4_int(value)
        for name, alias in re.findall(r'const\s+[\w<>]+\s+(\w+)\s*=\s*(\w+);', self.source):
            if alias in self.consts:
                self.consts[name] = self.consts[alias]
        self.actions = {}
        for match in re.finditer(r'\baction\s+(\w+)\s*\(', self.source):
            self.actions[match[1]] = sem._extract_block_after(self.source, match.start())[1:-1]
        for match in re.finditer(r'#define\s+(\w+)\(\)\s*\{', self.source):
            self.actions[match[1]] = sem._extract_block_after(self.source, match.start())[1:-1]
        self.tables = {}

    def table(self, name):
        if name not in self.tables:
            self.tables[name] = sem.parse_const_table(self.source, name, self.consts)
        return self.tables[name]

    def select(self, name, fields):
        table = self.table(name)
        for row in table.rows:
            if all(fields.get(key, 0) & mask == value for key, (value, mask) in zip(table.keys, row.matches)):
                return row.action, row.argument
        return table.default_action, table.default_argument

    def effects(self, calls, fields):
        state = {'ig_dprsr_md.digest_type': 1, 'hdr.ib.seq': 13, 'hdr.ib.role': 1, 'hdr.ib.slot': 0,
                 'hdr.ib.cookie_word': 0x80000012, 'hdr.eth.etype': 0x800,
                 'hdr.held_owner.valid': fields.get('held_valid', 0),
                 'meta.fwd_port': 9, 'meta.owner': 0x80000012,
                 'meta.cur_gen': 0xC3, 'meta.epoch_stored': 0xC4,
                 'meta.budget_init': 18000, 'meta.cookie_in': 0x80000012,
                 'meta.next_cookie': 19}
        counts = []

        def value(expression):
            expression = re.sub(r'\(bit<\d+>\)', '', expression)
            expression = re.sub(r'\b\d+w(0x[\da-fA-F]+|\d+)', r'\1', expression)
            def replace(match):
                token = match[0]
                if token in state:
                    return str(state[token])
                if token in self.consts:
                    return str(self.consts[token])
                raise AssertionError('Unknown terminal operand: ' + token)
            expression = re.sub(r'\b[A-Za-z_]\w*(?:\.\w+)*\b', replace, expression)
            if not re.fullmatch(r'[\d\sxXa-fA-F()+|&\-]+', expression):
                raise AssertionError('Unsupported expression: ' + expression)
            return eval(expression, {'__builtins__': {}}) & 0xFFFFFFFF

        def execute(name, argument=None):
            if name == 'NoAction':
                return
            body = self.actions[name]
            if argument is not None:
                body = re.sub(r'\bo\b', str(value(argument)), body)
            while body.strip():
                body = body.lstrip()
                macro = re.match(r'(D3_\w+)\(\)', body)
                if macro:
                    execute(macro[1]); body = body[macro.end():]; continue
                statement, separator, body = body.partition(';')
                if not separator:
                    raise AssertionError('Unparsed terminal action: ' + statement)
                statement = statement.strip()
                if not statement:
                    continue
                assignment = re.fullmatch(r'([\w.]+)\s*=\s*(.+)', statement)
                validity = re.fullmatch(r'([\w.]+)\.set(Valid|Invalid)\(\)', statement)
                counter = re.fullmatch(r'ctr_outcome.count\((.*?)\)', statement)
                call = re.fullmatch(r'(\w+)\(\)', statement)
                if assignment:
                    state[assignment[1]] = value(assignment[2])
                elif validity:
                    state[validity[1] + '.valid'] = int(validity[2] == 'Valid')
                elif counter:
                    counts.append(value(counter[1]) if counter[1] else state['meta.outcome'])
                elif call:
                    execute(call[1])
                else:
                    raise AssertionError('Unsupported terminal statement: ' + statement)
        for name, argument in calls:
            execute(name, argument)
        # A dropped packet has no externally visible bytes or TM destination.
        if state.get('ig_dprsr_md.drop_ctl'):
            return {'drop': state['ig_dprsr_md.drop_ctl']}, counts
        return state, counts


class CommitParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = Program(REFERENCE.read_text())
        cls.new = Program(SOURCE.read_text())

    def compare(self, table_name, fields):
        old_action, old_arg = self.old.select(table_name, fields)
        new_action, new_arg = self.new.select(table_name, fields)
        # Pending-response blocker admission is a separate intentional repair.
        pending_admission = (table_name == 'tbl_decide_fresh' and fields.get('read_release') == 1
                             and fields.get('is_pktgen') == 1 and fields.get('txn_active') == 2
                             and old_arg == 'OUT_PKTGEN_DROP' and new_arg in ('OUT_ADMIT_ACK', 'OUT_ADMIT_RESP'))
        if pending_admission:
            old_action = 'dec_admit_ack' if new_arg == 'OUT_ADMIT_ACK' else 'dec_admit_resp'
            old_arg = new_arg
        # Enabled watchdog priority is a separate intentional repair (test_p4_recovery
        # test_enabled_watchdog_priority_and_domain): with read_release on and a valid owner, an
        # exhausted budget on a pending blocker reports the timeout instead of the deadline.
        # Effects are still compared against build 22's timeout path, so the note is checked.
        timeout_by_name = {'OUT_AB_DL': 'OUT_AB_TMO', 'OUT_RB_DL': 'OUT_RB_TMO'}
        watchdog_priority = (table_name == 'tbl_decide_deq' and fields.get('read_release') == 1
                             and fields.get('owner_valid') == 1 and fields.get('budget_zero') == 1
                             and fields.get('role') == self.old.consts['ROLE_BLOCK']
                             and fields.get('verdict') == self.old.consts['V_BLOCK_PENDING']
                             and timeout_by_name.get(old_arg) == new_arg)
        if watchdog_priority:
            old_action = 'dec_o'
            old_arg = new_arg
        # MODE_D2_RESP (response-focused, 2026-10-06) is a new feature with no counterpart in build 22:
        # arming a request and forwarding the fresh ACK while arming its response deadline. Build 22
        # selects ARM_BUSY / ACK_HOLD for mode 2, so there is nothing to compare against; the new
        # rows are checked directly (effects) and by test_p4_release.test_response_focused_*.
        if (table_name == 'tbl_decide_fresh' and fields.get('mode') == self.new.consts['MODE_D2_RESP']
                and new_arg in ('OUT_ARM_FRESH', 'OUT_ACK_FWD_ARM')):
            actual, new_counts = self.new.effects([(new_action, new_arg)], fields)
            self.assertEqual(new_counts, [self.new.consts[new_arg]])
            self.assertEqual(new_action, 'finish_path_10' if new_arg == 'OUT_ARM_FRESH' else 'finish_path_5')
            return new_action, new_arg
        # Timeout escape is reported by the outcome counter and the owner is released inline on the
        # timeout pass (tbl_owner_admission), so the note build 22 re-enqueued is not sent. Re-sending
        # it let the note loop forever in MODE_OFF / MODE_FAIL_OPEN (test_p4_recovery
        # test_timeout_note_terminates_in_every_mode). Exactly this case: new drops, old sent the note.
        if (table_name == 'tbl_decide_deq' and fields.get('read_release') == 1
                and old_arg in ('OUT_AB_TMO', 'OUT_RB_TMO') and new_arg == old_arg
                and new_action == 'finish_path_0' and old_action != 'finish_path_0'):
            actual, new_counts = self.new.effects([(new_action, new_arg)], fields)
            self.assertEqual(actual, {'drop': 1}, (table_name, fields))
            self.assertEqual(new_counts, [self.old.consts[old_arg]])
            for slot in ('SLOT_ACK', 'SLOT_RESP'):   # the inline release that replaces the note
                self.assertEqual(self.new.select('tbl_owner_admission', dict(
                    read_release=1, mode=self.new.consts['MODE_D4_DUAL'], dequeued=1,
                    role=self.new.consts['ROLE_BLOCK'], budget_zero=1, held_valid=0,
                    token_slot=self.new.consts[slot]))[0], 'owner_release')
            return new_action, old_arg
        # The historical spent-generation row dropped post-release transport
        # repair. The new released-domain verdict has a separate tested effect.
        if table_name == 'tbl_decide_fresh' and new_arg == 'OUT_OP_REPAIR':
            self.assertEqual(fields['bor_pc'], self.new.consts['BPC_OPERATE'])
            self.assertEqual(fields['verdict_bor'], self.new.consts['V_OP_REPAIR'])
            self.assertEqual(new_action, 'finish_path_14')
            actual, counts = self.new.effects([(new_action, new_arg)], fields)
            self.assertEqual(actual['ig_tm_md.ucast_egress_port'], self.new.consts['PORT_RELAY'])
            self.assertEqual(actual['ig_tm_md.qid'], self.new.consts['QID_FWD'])
            self.assertEqual(actual['ig_tm_md.bypass_egress'], 0)
            self.assertNotIn('drop', actual)
            self.assertEqual(counts, [self.new.consts['OUT_OP_REPAIR']])
            return new_action, new_arg
        self.assertEqual(new_arg, old_arg, (table_name, fields, old_arg, new_arg))
        outcome = self.old.consts[old_arg]
        context = dict(fields, outcome=outcome)
        calls = [(old_action, old_arg), self.old.select('tbl_commit', context), self.old.select('tbl_held_owner', context)]
        expected, old_counts = self.old.effects(calls, fields)
        if 'drop' not in expected and old_arg not in ('OUT_ARM_FRESH', 'OUT_OP_HOLD'):
            expected['ig_dprsr_md.digest_type'] = 0
        actual, new_counts = self.new.effects([(new_action, new_arg)], fields)
        self.assertEqual(actual, expected, (table_name, fields, new_action, old_arg))
        self.assertEqual(old_counts, [outcome])
        self.assertEqual(new_counts, [outcome])
        return new_action, old_arg

    def test_every_terminal_row_effect_and_count(self):
        reached = set()
        outcomes = set()
        expected_outcomes = set()
        for name, dequeued in (('tbl_decide_fresh', 0), ('tbl_decide_deq', 1)):
            for program in (self.old, self.new):
                table = program.table(name)
                expected_outcomes.update(row.argument for row in table.rows)
                expected_outcomes.add(table.default_argument)
                rng = random.Random(941)
                for row in table.rows:
                    for sample in range(12):
                        fields = {key: value | ((rng.getrandbits(32) if sample else 0) & ~mask)
                                  for key, (value, mask) in zip(table.keys, row.matches)}
                        owner_index = table.keys.index('owner_valid')
                        if row.matches[owner_index][1] == 0:
                            fields['owner_valid'] = 1
                        for enabled in (0, 1):
                            for held in ((0, 1) if dequeued and fields.get('role') in (self.old.consts['ROLE_ACK'], self.old.consts['ROLE_RESP']) else (0,)):
                                case = dict(fields, dequeued=dequeued, read_release=enabled, held_valid=held)
                                action, outcome = self.compare(name, case)
                                reached.add(action)
                                outcomes.add(outcome)
            for enabled in (0, 1):
                action, outcome = self.compare(name, dict(dequeued=dequeued, read_release=enabled, role=255, owner_valid=1))
                reached.add(action)
                outcomes.add(outcome)
        declared = set(re.findall(r'\baction\s+(finish_path_\d+)\(', self.new.source))
        self.assertEqual(reached, declared, 'Every fused action must have an exercised terminal effect')
        self.assertEqual(outcomes, expected_outcomes, 'Every decision outcome must be exercised')

    def test_bad_port_counts_once_and_drops(self):
        apply = sem.extract_named_block(self.new.source, 'apply')
        match = re.search(r'if\s*\(meta.port_ok\s*==\s*8w0\)\s*\{\s*(\w+)\(OUT_BADPORT\)', apply)
        self.assertIsNotNone(match)
        effect, counts = self.new.effects([(match[1], 'OUT_BADPORT')], {})
        self.assertEqual(effect, {'drop': 1})
        self.assertEqual(counts, [self.new.consts['OUT_BADPORT']])
        self.assertNotIn('tbl_commit.apply()', apply)
        self.assertNotIn('tbl_held_owner.apply()', apply)

    def test_indexed_counter_contract_is_explicit(self):
        self.assertTrue(re.search(r'Counter<bit<64>,\s*bit<16>>\(128,\s*CounterType_t.PACKETS\)\s+ctr_outcome', self.new.source), 'Indexed 128-outcome packet counter contract changed')
        self.assertNotRegex(self.new.source, r'DirectCounter[^;]+ctr_outcome')

    def test_wrong_queue_and_double_count_mutations_fail(self):
        original = self.new
        for old, replacement in (('to_resp_block();', 'to_block();'),
                                 ('ctr_outcome.count(o);', 'ctr_outcome.count(o); ctr_outcome.count(o);')):
            with self.subTest(mutation=old):
                start = original.source.index('action finish_path_')
                mutated = original.source[:start] + original.source[start:].replace(old, replacement, 1)
                self.assertNotEqual(mutated, original.source)
                self.new = Program(mutated)
                with self.assertRaises(AssertionError):
                    self.test_every_terminal_row_effect_and_count()
        self.new = original


if __name__ == '__main__':
    unittest.main()
