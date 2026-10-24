"""The rearm installer reads E's provenance dispatch from the compiled candidate.

c48+ (relay_sbo) adds the physical relay departure port to E's provenance parser
(three entries); c30 has the original two. The third entry is accepted only when it
is the build's own compiled t_RELAY_PORT; the baseline reader still checks the rest.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parent / 'response_only' / 'hw' / 'tests'))
import fixture as fx  # noqa: E402,F401  (binds the baseline installer the candidate entrypoint wraps)

_spec = importlib.util.spec_from_file_location('rearm_bringup_ports', HERE / 'hw' / 'bringup_composite.py')
rbc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rbc)

EVIDENCE = HERE / 'stage_experiments/ctl_timing_01/evidence'
C30 = EVIDENCE / 'm12p_c30_sdk9132/compile_local/out'
C51 = EVIDENCE / 'm12p_c51_sdk9132/compile_local/out'
THREE = 'transition select(eg.egress_port) { 9w9: provenance; 9w64: provenance; 9w48: provenance; default: accept; }'


def edited(source, old, new):
    temporary = Path(tempfile.mkdtemp(prefix='candidate_ports_'))
    text = (source / 'response_only.p4pp').read_text()
    assert text.count(old) == 1, old
    (temporary / 'response_only.p4pp').write_text(text.replace(old, new))
    return temporary


class CandidatePorts(unittest.TestCase):
    def tearDown(self):
        for path in getattr(self, 'temporary', []):
            shutil.rmtree(path, ignore_errors=True)

    def read(self, path):
        self.temporary = getattr(self, 'temporary', []) + ([path] if path not in (C30, C51) else [])
        return rbc.candidate_ports(path)

    def test_two_entry_build_reads_as_before(self):
        ports, errors = self.read(C30)
        self.assertEqual(errors, [])
        self.assertEqual(ports['e_ports'], [9, 48])
        self.assertNotIn('e_relay_departure', ports)

    def test_relay_build_accepts_its_compiled_relay_departure(self):
        ports, errors = self.read(C51)
        self.assertEqual(errors, [])
        self.assertEqual(ports['e_ports'], [9, 48])
        self.assertEqual(ports['e_relay_departure'], 64)

    def test_third_entry_must_be_the_compiled_relay_port(self):
        path = edited(C51, THREE, THREE.replace('9w64: provenance', '9w65: provenance'))
        ports, errors = self.read(path)
        self.assertTrue(errors)

    def test_relay_entry_outside_the_middle_is_refused(self):
        for order in ('9w64: provenance; 9w9: provenance; 9w48: provenance;',
                      '9w9: provenance; 9w48: provenance; 9w64: provenance;'):
            with self.subTest(order=order):
                path = edited(C51, THREE, THREE.replace(
                    '9w9: provenance; 9w64: provenance; 9w48: provenance;', order))
                ports, errors = self.read(path)
                self.assertTrue(errors)
                self.assertNotIn('e_relay_departure', ports)

    def test_four_entries_are_refused(self):
        path = edited(C51, THREE, THREE.replace('9w48: provenance;', '9w48: provenance; 9w64: provenance;'))
        _ports, errors = self.read(path)
        self.assertTrue(errors)

    def test_missing_relay_constant_refuses_three_entries(self):
        path = edited(C51, 'const PortId_t t_RELAY_PORT = 9w64', 'const PortId_t t_RELAY_PORX = 9w64')
        _ports, errors = self.read(path)
        self.assertTrue(errors)


if __name__ == '__main__':
    unittest.main()
