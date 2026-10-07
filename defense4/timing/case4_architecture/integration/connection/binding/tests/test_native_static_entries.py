"""A table whose const entries exceed its declared size compiles but the model/driver refuses to load
it ("Not enough space adding static entry N"). native_04 shipped sequence_diff size=8 with 9 entries.

Two gates: the generated source (every table, const entries <= size) and, when a compile of exactly
this source exists under binding/evidence or integration/evidence, the compiled context.json (the logic of
integration/core/scan_static_entries.py).
"""
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ARCH = HERE.parents[2]
sys.path.insert(0, str(ARCH / 'integration/core/harness'))
from interp_ext import ExtSource  # noqa: E402
from p4syntax import match_brace  # noqa: E402


def block(text, marker):
    at = text.index('{', text.index(marker))
    return text[at + 1:match_brace(text, at) - 1]

SOURCE = HERE / 'native_binding.p4'


def source_tables(text=None):
    """{table: (const entry count, declared size or None)} for the Ingress control."""
    src = ExtSource(text or SOURCE.read_text(), HERE)
    result = {}
    for name, table in src.controls['Ingress'].tables.items():
        body = block(src.text, 'table %s{' % name) if ('table %s{' % name) in src.text else block(src.text, 'table %s {' % name)
        size = re.search(r'\bsize\s*=\s*(\d+)\s*;', body)
        result[name] = (len(table['entries']), int(size[1]) if size else None)
    return result


class StaticEntries(unittest.TestCase):
    def test_no_generated_table_has_more_const_entries_than_its_size(self):
        tables = source_tables()
        self.assertGreater(len(tables), 40)
        over = {n: v for n, v in tables.items() if v[1] is not None and v[0] > v[1]}
        self.assertEqual(over, {}, 'const entries exceed the declared size (the model refuses to load)')

    def test_every_table_with_const_entries_declares_a_size(self):
        missing = [n for n, (entries, size) in source_tables().items() if entries and size is None]
        self.assertEqual(missing, [])

    def test_the_check_has_teeth_native_04_sequence_diff_overflow_is_detected(self):
        bad = SOURCE.read_text().replace('actions={diff_syn;diff_synack;diff_forward;diff_reverse;diff_reset_forward;diff_reset_reverse;diff_response;diff_read_response;NoAction;}size=20;',
                                         'actions={diff_syn;diff_synack;diff_forward;diff_reverse;diff_reset_forward;diff_reset_reverse;diff_response;diff_read_response;NoAction;}size=8;')
        self.assertNotEqual(bad, SOURCE.read_text())
        entries, size = source_tables(bad)['sequence_diff']
        self.assertGreater(entries, size)

    def test_sequence_diff_regression(self):
        entries, size = source_tables()['sequence_diff']
        self.assertGreaterEqual(size, entries)
        self.assertGreater(entries, 9)

    def test_compiled_context_of_this_exact_source_has_no_static_overflow(self):
        digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        checked = 0
        manifests = sorted((HERE / 'evidence').glob('*/manifest.json'))
        manifests += sorted((ARCH / 'integration/evidence').glob('native_*/manifest.json'))
        for manifest in manifests:
            report = json.loads(manifest.read_text())
            if report.get('source_sha256') != digest or report.get('exit_code') != 0:
                continue
            # A matching main source must not qualify a build with stale includes.
            if any(not (HERE / name).is_file() or
                   hashlib.sha256((HERE / name).read_bytes()).hexdigest() != expected
                   for name, expected in report.get('source_files', {}).items()):
                continue
            context = manifest.parent / 'out/pipe/context.json'
            if not context.is_file():
                continue
            for table in json.loads(context.read_text())['tables']:
                self.assertLessEqual(len(table.get('static_entries') or []), table['size'], (manifest.parent.name, table['name']))
            checked += 1
        if not checked:
            self.skipTest('no compiled evidence for the current source yet')


if __name__ == '__main__':
    unittest.main()
