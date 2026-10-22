"""READ-class schedule fork (build/case4_socket_gate_read_schedule), loopback only, software only.

Each run is the real outstation and master over 127.0.0.1 inside unshare -rn with dumpcap on lo
(../loopback_capture.py); the capture is decoded independently of the endpoints' JSON with read_complete_01's
capture.py and dnp3_std.py (every link CRC checked, transport reassembled).
  - unset: the fork's request and response streams and TCP segmentation equal the existing binary's
  - rotate4 on base and large DB: READ classes follow the fixed order over every READ slot, all commands succeed,
    the derived lengths in read_commands equal the captured ones, and the per-class sizes are the recorded ones
Build first with ../build_endpoint.py.
"""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
BINARY = BASE / 'build/case4_socket_gate_read_schedule'
EXISTING = BASE / 'build/case4_socket_gate_pad58b'
SPEC = importlib.util.spec_from_file_location('read_schedule_loopback', BASE / 'loopback_capture.py')
LOOP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(LOOP)
ORDER = ['range', 'analog', 'class0', 'integrity']
# (request octets, response link frames) per class, measured on loopback 2026-10-21 (README.md)
SIZES = {'base': {'range': (20, [49]), 'analog': (22, [141]), 'class0': (18, [247]), 'integrity': (27, [247])},
         'large': {'range': (20, [49]), 'analog': (22, [141]), 'class0': (18, [292, 85]),
                   'integrity': (27, [292, 85])}}
CAN_CAPTURE = bool(shutil.which('dumpcap')) and subprocess.run(['unshare', '-rn', 'true']).returncode == 0


def last_json(path):
    return json.loads([line for line in Path(path).read_text().splitlines() if line.startswith('{')][-1])


@unittest.skipUnless(BINARY.is_file() and EXISTING.is_file(), 'build both endpoints first (build_endpoint.py)')
class ReadSchedule(unittest.TestCase):
    def test_manifest_binds_the_schedule_binary(self):
        record = json.loads((BASE / 'build/build_manifest.json').read_text())['read_schedule_endpoint']
        for name, digest in record['source_hashes'].items():
            self.assertEqual(hashlib.sha256((BASE / 'sources' / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(hashlib.sha256(BINARY.read_bytes()).hexdigest(), record['binary_sha256'])
        self.assertEqual(hashlib.sha256((BASE / 'build/lib/libopendnp3.so').read_bytes()).hexdigest(),
                         record['library_sha256'])

    def test_invalid_schedule_controls_fail_before_any_traffic(self):
        with tempfile.TemporaryDirectory() as temp:
            stop = Path(temp) / 'stop'; stop.touch()
            for role, env, word in (('master', dict(CASE4_READ_SCHEDULE='rotate5', CASE4_DB='base'), 'CASE4_READ_SCHEDULE'),
                                    ('master', dict(CASE4_READ_SCHEDULE='rotate4'), 'CASE4_DB'),
                                    ('outstation', dict(CASE4_DB='huge'), 'CASE4_DB'),
                                    # two-READ-target controls (2026-10-22)
                                    ('master', dict(CASE4_READ_SCHEDULE='mixed_full', CASE4_DB='large'), 'requires CASE4_DB=base'),
                                    ('master', dict(CASE4_PAD_EXPECT='mixed=0'), 'CASE4_PAD_EXPECT'),
                                    ('master', dict(CASE4_PAD_EXPECT='mixed=26,mixed=26'), 'CASE4_PAD_EXPECT'),
                                    ('master', dict(CASE4_PAD_EXPECT='bogus=4'), 'CASE4_PAD_EXPECT'),
                                    ('master', dict(CASE4_PAD_EXPECT=''), 'CASE4_PAD_EXPECT'),
                                    ('outstation', dict(CASE4_PAD_EXPECT='mixed=26'), 'CASE4_PAD_EXPECT'),
                                    ('master', dict(CASE4_READ_SCHEDULE='mixed_full', CASE4_DB='base',
                                                    CASE4_PAD_EXPECT='range=5'), 'never issues'),
                                    ('master', dict(CASE4_PAD_EXPECT='mixed=26'), 'never issues'),
                                    ('master', dict(CASE4_FIXTURE_VARIANT='1'), 'CASE4_FIXTURE_VARIANT requires'),
                                    ('master', dict(CASE4_FIXTURE_VARIANT='10'), 'CASE4_FIXTURE_VARIANT')):
                with self.subTest(role=role, env=env):
                    run = subprocess.run([str(BINARY), role, '127.0.0.1', '1', str(stop), '1'],
                                         env=dict(CASE4_PAD58B_SOCKET_GATE='1', **env), capture_output=True,
                                         text=True, timeout=5)
                    self.assertEqual(run.returncode, 64, run.stdout + run.stderr)
                    self.assertIn(word, run.stderr)

    @unittest.skipUnless(CAN_CAPTURE, 'needs dumpcap and unprivileged user namespaces')
    def test_unset_schedule_is_the_existing_workload_on_the_wire(self):
        with tempfile.TemporaryDirectory() as temp:
            dirs = []
            for binary in (EXISTING, BINARY):
                out = Path(temp) / binary.name
                rc = LOOP.run(binary, out, 1, dict(CASE4_SBO_CYCLES='4', CASE4_READ_PAUSE_MS='0'))
                self.assertEqual(rc, 0, (out / 'master.log').read_text())
                LOOP.decode(out); dirs.append(out)
            self.assertEqual(LOOP.compare(*dirs), dict(request_stream_sha256=True, response_stream_sha256=True,
                                                       request_segments=True, response_segments=True, exchanges=True))

    @unittest.skipUnless(CAN_CAPTURE, 'needs dumpcap and unprivileged user namespaces')
    def test_rotate4_on_base_and_large_databases(self):
        cycles, reads = 8, 1
        slots = [ORDER[k % 4] for k in range(reads + cycles)]
        for db in ('base', 'large'):
            with self.subTest(db=db), tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / db
                rc = LOOP.run(BINARY, out, reads, dict(CASE4_SBO_CYCLES=str(cycles), CASE4_READ_PAUSE_MS='0',
                                                       CASE4_READ_SCHEDULE='rotate4', CASE4_DB=db))
                self.assertEqual(rc, 0, (out / 'master.log').read_text())
                master, station = last_json(out / 'master.log'), last_json(out / 'outstation.log')
                self.assertTrue(master['success'] and master['read_commands_ok'])
                self.assertEqual((master['read_schedule'], master['db'], station['db']), ('rotate4', db, db))
                self.assertEqual({c: v['issued'] for c, v in master['reads_per_class'].items()},
                                 {c: slots.count(c) for c in ORDER})
                self.assertEqual([r['class'] for r in master['read_commands']], slots)
                self.assertTrue(all(r['success'] for r in master['read_commands']))
                self.assertEqual([station[k] for k in ('select_real', 'operate_real', 'opens')], [cycles, cycles, 1])

                decoded = LOOP.decode(out)
                kinds = [e['kind'] for e in decoded['exchanges']]
                expected = ['READ:' + slots[0]]
                for c in range(cycles):
                    expected += ['SELECT', 'OPERATE', 'READ:' + slots[reads + c]]
                self.assertEqual(kinds, expected)
                read_rows = [e for e in decoded['exchanges'] if e['kind'].startswith('READ:')]
                for record, row in zip(master['read_commands'], read_rows):
                    self.assertEqual((row['request_octets'], row['response_frames']), SIZES[db][record['class']])
                    self.assertEqual(row['tcp_segments'], row['response_frames'])
                    self.assertEqual((record['response_link_octets'], record['response_apdu_octets']),
                                     (row['response_octets'], row['response_apdu_octets']))

    @unittest.skipUnless(CAN_CAPTURE, 'needs dumpcap and unprivileged user namespaces')
    def test_mixed_full_schedule_on_base(self):
        """Two-READ-target workload: the mixed READ is ONE request with g1v2 0-15 and g30v1 0-7 (25 octets) whose
        native response is one 91-octet link frame in one TCP segment; the full READ is the integrity poll (27 -> 247).
        Strict fixture check with no padding declared, on two fixture variants."""
        cycles, reads = 6, 1
        slots = [('mixed', 'integrity')[k % 2] for k in range(reads + cycles)]
        sizes = {'mixed': (25, [91]), 'integrity': (27, [247])}
        for variant in ('0', '1'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / ('v' + variant)
                rc = LOOP.run(BINARY, out, reads, dict(CASE4_SBO_CYCLES=str(cycles), CASE4_READ_PAUSE_MS='0',
                                                       CASE4_READ_SCHEDULE='mixed_full', CASE4_DB='base',
                                                       CASE4_FIXTURE_VARIANT=variant))
                self.assertEqual(rc, 0, (out / 'master.log').read_text())
                master = last_json(out / 'master.log')
                self.assertTrue(master['success'] and master['read_commands_ok'])
                self.assertEqual((master['read_schedule'], master['pad_expect']), ('mixed_full', 'none'))
                self.assertEqual([r['class'] for r in master['read_commands']], slots)
                self.assertTrue(all(r['padding_points'] == 0 for r in master['read_commands']))
                mixed = [r for r in master['read_commands'] if r['class'] == 'mixed'][0]
                self.assertEqual([(h['g'], h['v'], h['q'], h['count']) for h in mixed['response_headers']],
                                 [(1, 2, 0, 16), (30, 1, 0, 8)])
                decoded = LOOP.decode(out)
                rows = [e for e in decoded['exchanges'] if e['kind'].startswith('READ:')]
                self.assertEqual([e['kind'] for e in rows], ['READ:' + s for s in slots])
                for record, row in zip(master['read_commands'], rows):
                    self.assertEqual((row['request_octets'], row['response_frames']), sizes[record['class']])
                    self.assertEqual(row['tcp_segments'], row['response_frames'])
                    self.assertEqual(record['response_link_octets'], row['response_octets'])


if __name__ == '__main__':
    unittest.main()
