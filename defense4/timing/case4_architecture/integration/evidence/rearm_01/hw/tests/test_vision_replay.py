"""Replay evidence filtering and runner boundaries; no real processes or traffic."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW.parents[3] / 'protocol/hw_vepa/tests'))
import pcaptk as tk
SPEC = importlib.util.spec_from_file_location('vision_replay', HW / 'vision_replay.py')
vp = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(vp)
PORT = 59400


def packet(seq, ack, flags, payload=b'', reverse=False):
    return tk.frame(vp.vc.OUTSTATION if reverse else vp.vc.MASTER,
                    vp.vc.MASTER if reverse else vp.vc.OUTSTATION,
                    20000 if reverse else PORT, PORT if reverse else 20000, seq, ack, flags, payload)


def connection(client, server, close, size=49):
    user = bytes([0xc0, 0xc0, 0x81, 0, 0, 10, 2, 0, 0, 22]) + bytes(23 if size == 49 else 32)
    return [packet(client, 0, tk.SYN), packet(server, client + 1, tk.SYN | tk.ACK, reverse=True),
            packet(client + 1, server + 1, tk.ACK),
            packet(client + 1, server + 1, tk.PSH | tk.ACK, tk.read_request()),
            packet(server + 1, client + 21, tk.PSH | tk.ACK, tk.dnp3_frame(user), reverse=True),
            packet(client + 21, server + 1 + size, close | tk.ACK)]


def write_pcap(path, frames):
    tk.write_pcap(path, [(1000 + index, frame) for index, frame in enumerate(frames)])


def artifacts(dest):
    dest.mkdir(parents=True, exist_ok=True)
    old = [connection(1000, 2000, tk.FIN), connection(3000, 4000, tk.RST)]
    manifests = []
    for name, frames in zip(('graceful', 'rst'), old):
        path = dest / ('old_' + name + '.pcap'); write_pcap(path, frames)
        manifest, _ = vp.rp.collect([path], PORT)
        manifest.update(applied=True, interface=vp.vc.NIC, sent=len(frames), new_isns=dict(client=900000, server=800000))
        (dest / ('replay_' + name + '.json')).write_text(json.dumps(manifest))
        manifests.append(manifest)
    current = connection(900000, 800000, tk.RST)
    raw = current[:3] + old[0] + old[1] + current[3:]
    write_pcap(dest / 'out.pcap', raw); write_pcap(dest / 'in.pcap', current)
    for name in ('master.json', 'outstation.json', 'result.json', 'state.txt', 'pre_read_ready.json'):
        (dest / name).write_text('retained ' + name)
    return old, current, raw, manifests


class VisionReplay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dest = self.root / 'c2'
        self.old, self.current, self.raw, self.manifests = artifacts(self.dest)
        authority = patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'})
        authority.start(); self.addCleanup(authority.stop)

    def test_exact_declared_frames_only_removed_and_every_in_byte_retained(self):
        original = {name: (self.dest / name).read_bytes() for name in ('out.pcap', 'in.pcap')}
        result = vp.derive_current(self.dest)
        derived = self.dest / 'current'
        self.assertEqual([frame for _, frame in vp.rp.records(derived / 'out.pcap')], self.current)
        self.assertEqual((derived / 'out.pcap').read_bytes()[:24], original['out.pcap'][:24])
        self.assertEqual((derived / 'in.pcap').read_bytes(), original['in.pcap'])
        self.assertEqual(result['removed'], 12)
        self.assertEqual(set(result['classes']), set(vp.rp.CLASSES))
        self.assertEqual(result['new_isns'], dict(client=900000, server=800000))
        for name in ('out.pcap', 'in.pcap'):
            self.assertEqual((self.dest / name).read_bytes(), original[name])
        for name in ('master.json', 'outstation.json', 'result.json', 'state.txt', 'pre_read_ready.json'):
            self.assertEqual((derived / name).read_bytes(), (self.dest / name).read_bytes())
        self.assertEqual(len(result['manifest_hashes']['replay_rst.json']), 64)
        self.assertTrue(result['raw_hashes']); self.assertTrue(result['derived_hashes'])

    def test_duplicate_hash_counts_are_respected_without_deduplication(self):
        manifest = self.manifests[0]
        manifest['packets'].append(copy.deepcopy(manifest['packets'][2]))
        manifest['sent'] += 1; manifest['counts']['PURE_ACK'] += 1
        (self.dest / 'replay_graceful.json').write_text(json.dumps(manifest))
        write_pcap(self.dest / 'out.pcap', self.raw[:4] + [self.old[0][2]] + self.raw[4:])
        self.assertEqual(vp.derive_current(self.dest)['removed'], 13)

    def test_missing_excess_or_unknown_replay_bytes_refuse_before_derivation(self):
        for frames in (self.raw[:-4] + self.raw[-3:], self.raw[:4] + [self.old[0][0]] + self.raw[4:]):
            write_pcap(self.dest / 'out.pcap', frames)
            with self.assertRaises(ValueError): vp.derive_current(self.dest)
            self.assertFalse((self.dest / 'current').exists())

    def test_manifest_application_counts_tuple_and_native_lengths_must_match_actual_frames(self):
        mutations = [lambda m: m.update(applied=False), lambda m: m.update(sent=True),
                     lambda m: m.update(sent=m['sent'] - 1), lambda m: m.update(interface='unsafe'),
                     lambda m: m.update(tuple=['192.168.10.1', PORT, '192.168.10.7', 20000]),
                     lambda m: m['packets'][4].update(payload_bytes=58),
                     lambda m: m['packets'][4].update(sha256='0' * 64),
                     lambda m: m['counts'].update(FIN=0),
                     lambda m: m.update(new_isns=dict(client=1, server=2)),
                     lambda m: m.update(isns=self.manifests[1]['isns'])]
        for change in mutations:
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifests[0]); change(manifest)
                (self.dest / 'replay_graceful.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError): vp.derive_current(self.dest)
                self.assertFalse((self.dest / 'current').exists())
        (self.dest / 'replay_graceful.json').unlink()
        with self.assertRaises((ValueError, OSError)): vp.derive_current(self.dest)

    def test_private_or_checksum_bad_bytes_cannot_be_hidden_by_manifest_hashes(self):
        for bad in ('private', 'checksum'):
            frame = bytearray(self.old[0][0])
            if bad == 'private': frame[12:14] = b'\x88\xb5'
            else: frame[50] ^= 1
            frames = list(self.raw); frames[3] = bytes(frame)
            write_pcap(self.dest / 'out.pcap', frames)
            manifest = copy.deepcopy(self.manifests[0]); manifest['packets'][0]['sha256'] = hashlib.sha256(frame).hexdigest()
            (self.dest / 'replay_graceful.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): vp.derive_current(self.dest)
            self.assertFalse((self.dest / 'current').exists())

    def test_replays_outside_completed_handshake_and_first_read_window_refuse(self):
        for frames in (self.raw[3:15] + self.current, self.current + self.raw[3:15]):
            write_pcap(self.dest / 'out.pcap', frames)
            with self.assertRaises(ValueError): vp.derive_current(self.dest)

    def test_new_coordinates_require_independent_checksum_valid_current_handshake(self):
        for name, manifest in zip(vp.MANIFESTS, self.manifests):
            changed = copy.deepcopy(manifest)
            changed['new_isns'] = dict(client=900001, server=800001)
            (self.dest / name).write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'captured current handshake'):
            vp.derive_current(self.dest)
        for name, manifest in zip(vp.MANIFESTS, self.manifests):
            (self.dest / name).write_text(json.dumps(manifest))
        bad = bytearray(self.current[1]); bad[50] ^= 1
        write_pcap(self.dest / 'in.pcap', [self.current[0], bytes(bad)] + self.current[2:])
        with self.assertRaisesRegex(ValueError, 'checksum-valid current handshake'):
            vp.derive_current(self.dest)
        self.assertFalse((self.dest / 'current').exists())

    def test_old_forwarded_in_frame_remains_visible_as_wire_failure(self):
        write_pcap(self.dest / 'in.pcap', self.current + [self.old[0][4]])
        vp.derive_current(self.dest)
        evidence = vp.vc.wc.analyze(self.dest / 'current/out.pcap', self.dest / 'current/in.pcap')
        self.assertTrue(evidence['unmatched_returned'] or evidence['duplicate_returned'])
        self.assertEqual((self.dest / 'current/in.pcap').read_bytes(), (self.dest / 'in.pcap').read_bytes())

    def test_plan_is_offline_and_fixed_port_authorization_identity_are_guarded(self):
        with patch.object(vp.vc, 'preflight', side_effect=AssertionError('process')):
            plan = vp.scenario('offline')
        self.assertFalse(plan['applied']); self.assertEqual([row['pre_read_grace_ms'] for row in plan['plan']], [0, vp.vi.PRE_READ_GRACE_MS, 0])
        for port in (59399, True):
            with self.assertRaises(ValueError): vp.scenario('unsafe', port)
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
            vp.scenario('unsafe', apply=True)
        with patch.object(vp.vc.vr, 'IP_O', '192.168.10.7'), self.assertRaises(ValueError):
            vp.scenario('unsafe', apply=True)

    def test_three_leg_runner_uses_derived_c2_only_and_retains_sources(self):
        calls, gates = [], []
        def connect(dest, *args, **kwargs):
            dest = Path(dest); dest.mkdir()
            grace = int(os.environ['CASE4_PRE_READ_GRACE_MS'])
            if grace: artifacts(dest)
            master = dict(opens=1, pre_read_grace_ms=grace, pre_read_ready_ns=1_000_000_000,
                          first_read_issued_ns=1_000_000_000 + grace * 1_000_000)
            (dest / 'master.json').write_text(json.dumps(master))
            if grace:
                Path(os.environ['CASE4_PRE_READ_MARKER']).write_text(json.dumps(dict(tcp_open=True, opens=1,
                    pre_read_grace_ms=grace, pre_read_ready_ns=master['pre_read_ready_ns'], first_read_issued_ns=0)))
            calls.append((args, kwargs, grace)); return dict(ok=True)
        def evaluate(dest, *args, **kwargs):
            gates.append(Path(dest)); return []
        with patch.object(vp.vc.vr, 'RUNS', str(self.root)), patch.object(vp.vc, 'preflight', return_value=[]), \
             patch.object(vp.vc.vr, 'run_connection', side_effect=connect), patch.object(vp.vc, 'observe', return_value={'ok': True}), \
             patch.object(vp.vc, 'evaluate', side_effect=evaluate):
            result = vp.scenario('series', apply=True)
        self.assertTrue(result['ok']); self.assertEqual([row[2] for row in calls], [0, vp.vi.PRE_READ_GRACE_MS, 0])
        self.assertTrue(all(row[1] == dict(read_pause_ms=25, run_sbo=True, close_grace_ms=1000, capture_immediate=True) for row in calls))
        self.assertEqual(gates, [self.root / 'series/c1', self.root / 'series/c2/current', self.root / 'series/c3'])
        self.assertEqual(result['connections'][1]['replay_filter']['removed'], 12)
        self.assertEqual(set(result['source_sha256']), {str(Path(module.__file__)) for module in
            (vp, vp.vi, vp.vc, vp.rp, vp.vc.vr, vp.vc.wc, vp.vc.clrt, vp.vc.checks)} |
            {str(HW / 'token_window.py'), str(HW / 'snapshot_lifecycle.py')})
        verdict = json.loads((self.root / 'series/c2/verdict.json').read_text())
        self.assertEqual(verdict['replay_filter'], result['connections'][1]['replay_filter'])
        self.assertTrue(result['hashes'])

    def test_first_leg_observer_or_application_failure_stops_remaining_legs(self):
        def connect(dest, *args, **kwargs):
            Path(dest).mkdir(); return dict(ok=True)
        for index, (observed, failures) in enumerate(((False, []), (True, ['application failed']))):
            with patch.object(vp.vc.vr, 'RUNS', str(self.root)), patch.object(vp.vc, 'preflight', return_value=[]), \
                 patch.object(vp.vc.vr, 'run_connection', side_effect=connect) as run, \
                 patch.object(vp.vc, 'observe', return_value={'ok': observed}), \
                 patch.object(vp.vc, 'evaluate', return_value=failures), \
                 patch.dict(os.environ, {'CASE4_PRE_READ_GRACE_MS': 'caller', 'CASE4_PRE_READ_MARKER': 'caller-marker'}):
                result = vp.scenario('failed_%d' % index, apply=True)
                self.assertEqual(os.environ['CASE4_PRE_READ_GRACE_MS'], 'caller')
                self.assertEqual(os.environ['CASE4_PRE_READ_MARKER'], 'caller-marker')
            self.assertFalse(result['ok']); self.assertEqual(run.call_count, 1)

    def test_missing_replay_manifests_stop_before_c2_gate_and_c3(self):
        def connect(dest, *args, **kwargs):
            Path(dest).mkdir(); return dict(ok=True)
        with patch.object(vp.vc.vr, 'RUNS', str(self.root)), patch.object(vp.vc, 'preflight', return_value=[]), \
             patch.object(vp.vc.vr, 'run_connection', side_effect=connect) as run, patch.object(vp.vc, 'observe', return_value={'ok': True}), \
             patch.object(vp.vc, 'evaluate', return_value=[]) as evaluate:
            result = vp.scenario('missing_series', apply=True)
        self.assertFalse(result['ok']); self.assertEqual(run.call_count, 2); self.assertEqual(evaluate.call_count, 1)


if __name__ == '__main__':
    unittest.main()
