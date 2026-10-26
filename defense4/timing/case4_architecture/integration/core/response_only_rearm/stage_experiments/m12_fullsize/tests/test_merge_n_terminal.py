"""c71 trial (N experiment): next_stage folded into N's phase-1/2 terminal actions; decisions and fields unchanged."""
import hashlib
import itertools
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from m12gen import merge_n_terminal  # noqa: E402
from m12gen.common import combined  # noqa: E402

C69 = HERE.parent / 'ctl_timing_01/evidence/m12p_c69_sdk9132/response_only.p4'
C69_SHA = '5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59'
CLI = ['--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read', '--reduce', '--ack-retry',
       '--read-handshake', '--headroom', '--relay', '--relay-sbo', '--relay-ts', '--response-ready-timing',
       '--strip-telemetry', '--strip-operate-hold']


def generate(*extra):
    with tempfile.TemporaryDirectory() as out:
        result = subprocess.run([sys.executable, str(HERE / 'make_m12.py'), out, *CLI, *extra],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return (Path(out) / 'response_only.p4').read_text()


def action_body(text, name):
    line = next(l for l in text.splitlines() if l.startswith(' action %s(){' % name))
    return line[line.index('{') + 1:line.rindex('}')]


def run_branch(text, m):
    """Execute the phase-1/2 branch text (if/else and keyless applies only) for one metadata assignment."""
    def value(expr):
        expr = re.sub(r'\(bit<\d+>\)', '', expr)
        expr = re.sub(r'\b\d+w(0x[0-9a-fA-F]+|\d+)\b', lambda x: str(int(x[1], 0)), expr)
        expr = re.sub(r'\bm\.(\w+)', lambda x: 'm[%r]' % x[1], expr)
        return eval(expr.replace('||', ' or ').replace('&&', ' and '), {}, {'m': m})

    applied, pos = [], 0

    def block():
        nonlocal pos
        while pos < len(text) and text[pos] != '}':
            statement()

    def statement():
        nonlocal pos
        while text[pos] in ' \n':
            pos += 1
        if text.startswith('if(', pos):
            pos += 2
            depth, start = 0, pos
            while True:
                depth += (text[pos] == '(') - (text[pos] == ')')
                pos += 1
                if depth == 0:
                    break
            taken = value(text[start:pos])
            body(taken)
            rest = text[pos:]
            if rest.lstrip(' \n').startswith('else'):
                pos += len(rest) - len(rest.lstrip(' \n')) + 4
                if text[pos:].lstrip(' \n').startswith('if('):
                    if taken:
                        skip_statement()
                    else:
                        statement()
                else:
                    body(not taken)
        else:
            end = text.index(';', pos) + 1
            match = re.fullmatch(r'(\w+)\.apply\(\);', text[pos:end].strip())
            assert match, text[pos:end]
            applied.append(match[1])
            pos = end
        while pos < len(text) and text[pos] in ' \n':
            pos += 1

    def body(execute):
        nonlocal pos
        while text[pos] in ' \n':
            pos += 1
        assert text[pos] == '{', text[pos:pos + 20]
        pos += 1
        if execute:
            block()
        else:
            skip_to_close()
        assert text[pos] == '}'
        pos += 1

    def skip_to_close():
        nonlocal pos
        depth = 1
        while depth:
            depth += (text[pos] == '{') - (text[pos] == '}')
            pos += 1
        pos -= 1

    def skip_statement():
        nonlocal pos
        captured = list(applied)
        statement()
        applied[:] = captured

    while pos < len(text):
        statement()
    return applied


def effect(applied, actions):
    """The ordered list of actions executed by the applied keyless tables."""
    return [step for table in applied for step in actions[table]]


class MergeNTerminal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c69 = C69.read_text()
        cls.c71 = generate('--merge-n-terminal')

    def test_c69_identity_is_unchanged_without_the_flag(self):
        self.assertEqual(hashlib.sha256(generate().encode()).hexdigest(), C69_SHA)

    def test_only_n_changes(self):
        for name in ('E', 'T'):
            self.assertEqual(combined.segment(self.c71, name), combined.segment(self.c69, name), name)
        self.assertEqual(self.c71.replace(combined.segment(self.c71, 'N'), combined.segment(self.c69, 'N'), 1),
                         self.c69)

    def test_every_branch_executes_the_same_actions(self):
        old_actions = {'next_stage_t': ['next_stage'], 'abort_t': ['abort_work'], 'carry_t': ['carry_current']}
        new_actions = {'next_stage_t': ['next_stage'], 'abort_t': ['next_stage', 'abort_work'],
                       'carry_t': ['next_stage', 'carry_current']}
        self.assertIn(merge_n_terminal.BRANCH, self.c69)
        self.assertIn(merge_n_terminal.MERGED, self.c71)
        seen = set()
        for epoch, kind, stage, owner_op, owner in itertools.product(
                (0, 1, 0xffffffff), (0, 4, 8, 10, 12, 17, 24, 25, 255), range(4), (0, 1), (0, 1, 0x80000000)):
            m = dict(epoch_diff=epoch, kind=kind, stage=stage, owner_op=owner_op, owner_diff=owner)
            old = effect(run_branch(merge_n_terminal.BRANCH, m), old_actions)
            new = effect(run_branch(merge_n_terminal.MERGED, m), new_actions)
            self.assertEqual(sorted(old), sorted(new), m)
            self.assertEqual(new.count('next_stage'), 1, m)
            seen.add(tuple(sorted(new)))
        self.assertEqual(seen, {('abort_work', 'next_stage'), ('carry_current', 'next_stage'), ('next_stage',)})

    def test_folded_actions_touch_disjoint_fields_from_next_stage(self):
        """Folding is order-independent: next_stage accesses only event[15:8] and its own routing fields."""
        n69, n71 = combined.segment(self.c69, 'N'), combined.segment(self.c71, 'N')
        stage = action_body(n69, 'next_stage')
        stage_fields = set(re.findall(r'hdr\.event\.event\[15:8\]|m\.emit_loop|tm\.\w+', stage))
        self.assertEqual(stage_fields, {'hdr.event.event[15:8]', 'm.emit_loop', 'tm.ucast_egress_port',
                                        'tm.bypass_egress'})
        for name in ('abort_work', 'carry_current'):
            old_body = action_body(n69, name)
            self.assertEqual(action_body(n71, name), 'next_stage();' + old_body)
            self.assertNotIn('hdr.event.event[15:8]', old_body)
            self.assertFalse(re.search(r'hdr\.event\.event(?!\[7:0\])', old_body), old_body)
            self.assertFalse(re.search(r'm\.emit_loop|tm\.', old_body), old_body)
        self.assertEqual(action_body(n71, 'next_stage'), stage)

    def test_tables_keep_their_names_and_keyless_shape(self):
        n71 = combined.segment(self.c71, 'N')
        for table, action in (('next_stage_t', 'next_stage'), ('abort_t', 'abort_work'), ('carry_t', 'carry_current')):
            self.assertIn(' table %s{actions={%s;}size=1;const default_action=%s();}' % (table, action, action), n71)

    def test_composes_with_the_e_trial(self):
        both = generate('--strip-rbad', '--merge-n-terminal')
        self.assertEqual(combined.segment(both, 'N'), combined.segment(self.c71, 'N'))
        self.assertEqual(combined.segment(both, 'E'), combined.segment(generate('--strip-rbad'), 'E'))
        self.assertEqual(combined.segment(both, 'T'), combined.segment(self.c69, 'T'))

    def test_cli_requires_the_c69_dependency(self):
        with tempfile.TemporaryDirectory() as out:
            result = subprocess.run([sys.executable, str(HERE / 'make_m12.py'), out, *CLI[:-1], '--merge-n-terminal'],
                                    capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--merge-n-terminal requires --strip-operate-hold', result.stderr)


if __name__ == '__main__':
    unittest.main()
