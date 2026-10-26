"""c70 trial (E experiment): E's always-zero rbad0/rbad1/rbadt predicates removed; c69 and every other segment kept."""
import hashlib
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from m12gen import strip_rbad  # noqa: E402
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


def table(text, name):
    start = text.index('table %s {' % name)
    return text[start:strip_rbad._closing(text, text.index('{', start))]


def keys(body):
    inner = body[body.index('key = {') + len('key = {'):]
    return [k.split(':')[0].strip() for k in inner[:inner.index('}')].split(';') if k.strip()]


def entries(body):
    inner = body[body.index('const entries = {'):]
    inner = inner[inner.index('{') + 1:strip_rbad._closing(inner, inner.index('{')) - 1]
    rows = []
    for row in (r.strip() for r in strip_rbad._split_top(inner, ';') if r.strip()):
        end = strip_rbad._closing(row, 0, '()')
        rows.append(([v.strip() for v in strip_rbad._split_top(row[1:end - 1], ',')], row[end:].strip()))
    return rows


class StripRbad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c69 = C69.read_text()
        cls.c70 = generate('--strip-rbad')

    def test_c69_identity_is_unchanged_without_the_flag(self):
        self.assertEqual(hashlib.sha256(generate().encode()).hexdigest(), C69_SHA)
        self.assertEqual(hashlib.sha256(self.c69.encode()).hexdigest(), C69_SHA)

    def test_only_e_changes(self):
        for name in ('N', 'T'):
            self.assertEqual(combined.segment(self.c70, name), combined.segment(self.c69, name), name)
        old_e, new_e = combined.segment(self.c69, 'E'), combined.segment(self.c70, 'E')
        self.assertEqual(self.c70.replace(new_e, old_e, 1), self.c69)

    def test_predicates_and_their_unapplied_producers_are_gone(self):
        e = combined.segment(self.c70, 'E')
        for name in ('m.rbad0', 'm.rbad1', 'm.rbadt', 'in_rb0', 'in_rb1', 'hash_in_rt', 'in_rt_t', 'action in_rt('):
            self.assertNotIn(name, e, name)

    def test_working_crc_checks_are_kept(self):
        """Only E lines naming a removed predicate or producer change; that leaves the CRC producers (in_dl,
        in_cb0, in_ct, status_crc) and the badh/cbad0/cbadt checks byte-identical."""
        import difflib
        old_e, new_e = combined.segment(self.c69, 'E'), combined.segment(self.c70, 'E')
        touched = re.compile(r'rbad|in_rb[01]|hash_in_rt|in_rt_t|action in_rt\(')
        old_lines, new_lines = old_e.splitlines(), new_e.splitlines()
        # the two edited tables' const-entries lines are proven row for row by the equivalence test below
        entry_lines = {line for name in strip_rbad.TABLES for line in table(old_e, name).splitlines()
                       if 'const entries' in line}
        for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes():
            if tag != 'equal':
                self.assertTrue(all(touched.search(line) or line in entry_lines for line in old_lines[i1:i2]),
                                old_lines[i1:i2])
        for marker in ('table status_crc_t', 'table in_dl_t', 'table in_cb0_t', 'm.in_rt'):
            self.assertIn(marker, new_e)
        checks = re.findall(r'm\.(badh|cbad0|cbadt) = [^;]+;', old_e)
        self.assertEqual(re.findall(r'm\.(badh|cbad0|cbadt) = [^;]+;', new_e), checks)

    def test_entry_tables_are_equivalent_row_for_row(self):
        for name in strip_rbad.TABLES:
            old, new = table(self.c69, name), table(self.c70, name)
            old_keys = keys(old)
            drop = [i for i, k in enumerate(old_keys) if k in ('m.rbad0', 'm.rbad1', 'm.rbadt')]
            self.assertEqual(len(drop), 3)
            self.assertEqual(keys(new), [k for i, k in enumerate(old_keys) if i not in drop])
            old_rows, new_rows = entries(old), entries(new)
            self.assertEqual(len(new_rows), len(old_rows), name)
            for (old_values, old_action), (new_values, new_action) in zip(old_rows, new_rows):
                self.assertTrue(all(old_values[i] in ('0', '_') for i in drop), old_values)
                self.assertEqual(new_values, [v for i, v in enumerate(old_values) if i not in drop])
                self.assertEqual(new_action, old_action)

    def test_a_row_needing_a_nonzero_predicate_fails_closed(self):
        e = combined.segment(self.c69, 'E')
        row = '(_, 1, 3w4 &&& 3w7, 0, 1, 8w0 &&& 8w0x07, 91, 1, _, 0, 0, 0, 0, _, _): do_acct_try();'
        self.assertIn(row, e)
        bad = self.c69.replace(row, row.replace('91, 1, _, 0, 0, 0, 0,', '91, 1, _, 0, 1, 0, 0,'), 1)
        with self.assertRaises(ValueError):
            strip_rbad.transform(bad)

    def test_a_second_assignment_fails_closed(self):
        bad = self.c69.replace('m.badh = 0; m.rbad0 = 0;', 'm.badh = 0; m.rbad0 = 0; m.rbad0 = 1;', 1)
        with self.assertRaises(ValueError):
            strip_rbad.transform(bad)

    def test_cli_requires_the_c69_dependency(self):
        with tempfile.TemporaryDirectory() as out:
            result = subprocess.run([sys.executable, str(HERE / 'make_m12.py'), out, *CLI[:-1], '--strip-rbad'],
                                    capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--strip-rbad requires --strip-operate-hold', result.stderr)


if __name__ == '__main__':
    unittest.main()
