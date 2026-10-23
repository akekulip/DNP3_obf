"""Vision scenario boundary tests; no namespaces, traffic, or real socket kills."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vision_candidate', HW / 'vision_candidate.py')
vc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vc)


def frame(src, dst, sport, dport, flags=16, payload=b'', seq=100, ack=200):
    ipaddr = lambda value: bytes(map(int, value.split('.')))
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 80, flags, 65535, 0, 0) + payload)
    pseudo = ipaddr(src) + ipaddr(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp[16:18] = struct.pack('!H', vc.wc._sum16(pseudo + tcp))
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(tcp), 0, 0, 64, 6, 0, ipaddr(src), ipaddr(dst)))
    ip[10:12] = struct.pack('!H', vc.wc._sum16(ip))
    return b'\x00' * 12 + b'\x08\x00' + bytes(ip + tcp)


def dnp(function, app_seq=7):
    body = bytes((192, 192 | app_seq, function))
    head = b'\x05\x64' + bytes((len(body) + 5, 196)) + b'\x01\x00\x02\x00'
    return head + struct.pack('<H', vc.wc.dnp3_crc(head)) + body + struct.pack('<H', vc.wc.dnp3_crc(body))


def pcap(path, frames):
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for n, packet in enumerate(frames):
        data += struct.pack('<IIII', 1, n * 1000, len(packet), len(packet)) + packet
    Path(path).write_bytes(data)


class Stop:
    def __init__(self):
        self.waits = []

    def is_set(self):
        return False

    def wait(self, delay):
        self.waits.append(delay)
        return False


class VisionCandidate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.port = 59410
        authority = patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'})
        authority.start(); self.addCleanup(authority.stop)

    def captures(self, function=4, bad_checksum=False):
        req = dnp(function)
        out = frame(vc.MASTER, vc.OUTSTATION, self.port, 20000, payload=req)
        incoming = bytearray(frame(vc.OUTSTATION, vc.MASTER, 20000, self.port,
                                   payload=dnp(129), ack=100 + len(req)))
        if bad_checksum:
            incoming[50] ^= 1
        pcap(self.root / 'out.pcap', [out]); pcap(self.root / 'in.pcap', [bytes(incoming)])

    def test_offline_default_never_enters_process_boundary(self):
        with patch.object(vc.vr, 'run_connection', side_effect=AssertionError('traffic')), \
             patch.object(vc.vr, 'sh', side_effect=AssertionError('process')), patch('builtins.print'):
            self.assertEqual(vc.main(['test', '--master-port', str(self.port)]), 0)

    def test_apply_requires_authorization_and_refuses_unsafe_identity(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
            vc.scenario('test', self.port, 'graceful', 1, apply=True)
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), \
             patch.object(vc.vr, 'IP_O', '192.168.10.7'), self.assertRaisesRegex(ValueError, 'software'):
            vc.scenario('test', self.port, 'rst', 1, apply=True)
        for port in (0, 20000, 65536, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                vc.scenario('test', port, 'graceful', 1)

    def test_operate_match_requires_exact_tuple_function_crc_and_checksum(self):
        self.captures(); self.assertIsNotNone(vc.operate_response(self.root, self.port))
        self.assertIsNone(vc.operate_response(self.root, self.port + 1))
        self.captures(function=3); self.assertIsNone(vc.operate_response(self.root, self.port))
        self.captures(bad_checksum=True); self.assertIsNone(vc.operate_response(self.root, self.port))

    def test_ss_kill_is_exact_and_only_after_valid_response_and_unique_probe(self):
        self.captures(); stop = Stop(); calls = []
        def nsx(ns, *args, **kw):
            calls.append((ns, args, kw))
            return SimpleNamespace(returncode=0, stdout='0 0 %s:%d %s:20000\n' % (vc.MASTER, self.port, vc.OUTSTATION), stderr='')
        with patch.object(vc.vr, 'nsx', side_effect=nsx):
            record = vc.observe(self.root, self.port, stop, timeout=1)
        self.assertTrue(record['ok']); self.assertIn(0.2, stop.waits)
        self.assertEqual(len(calls), 2)
        for namespace, args, kw in calls:
            self.assertEqual(namespace, 'ns_vepa_a')
            self.assertIn('state', args); self.assertIn('established', args)
            self.assertIn('src 192.168.10.61', args[-1]); self.assertIn('dst 192.168.10.62', args[-1])
            self.assertIn('sport = :%d' % self.port, args[-1]); self.assertIn('dport = :20000', args[-1])
            self.assertEqual(kw['timeout'], 2)
        self.assertNotIn('-K', calls[0][1]); self.assertIn('-K', calls[1][1])
        self.assertTrue((self.root / 'ss_probe.log').is_file()); self.assertTrue((self.root / 'ss_kill.log').is_file())

    def test_ambiguous_probe_and_timeout_never_kill(self):
        self.captures()
        with patch.object(vc.vr, 'nsx', return_value=SimpleNamespace(returncode=0, stdout='wrong socket\n', stderr='')) as nsx:
            self.assertFalse(vc.observe(self.root, self.port, Stop(), timeout=1)['ok'])
            self.assertEqual(nsx.call_count, 1)
        (self.root / 'in.pcap').unlink()
        with patch.object(vc.time, 'monotonic', side_effect=[0, 0, 2]), patch.object(vc.vr, 'nsx') as nsx:
            self.assertFalse(vc.observe(self.root, self.port, Stop(), timeout=1)['ok'])
            nsx.assert_not_called()

    def test_observer_direct_api_requires_authority_before_socket_commands(self):
        self.captures()
        with patch.dict(os.environ, {}, clear=True), patch.object(vc.vr, 'nsx') as nsx:
            record = vc.observe(self.root, self.port, Stop(), timeout=1)
            self.assertFalse(record['ok']); self.assertIn('DEFENSE4_HW_AUTHORIZED', record['error'])
            nsx.assert_not_called()

    def test_preflight_refuses_physical_namespace_address(self):
        with patch.object(vc.vr, 'sh', return_value=SimpleNamespace(returncode=0,
                 stdout=json.dumps([{'ifname': vc.NIC}]), stderr='')), \
             patch.object(vc.vr, 'nsx', return_value=SimpleNamespace(returncode=0,
                 stdout=json.dumps([{'ifname': 'mvA', 'addr_info': [{'family': 'inet', 'local': '192.168.10.1'}]}]), stderr='')):
            with self.assertRaisesRegex(RuntimeError, 'software namespace address'):
                vc.preflight('rst')

    def test_application_success_and_captured_rst_are_both_mandatory(self):
        controls = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=5000)
        master = dict(success=True, all_reads_match_seed=True, reads_requested=20, reads_completed=20,
                      application_calls=1, opens=1, reads=[dict(points_received=23, matches_seed=True, completed=True)] * 20,
                      **controls)
        outstation = dict(select_real=1, operate_real=1, select_decoy=0, operate_decoy=0)
        wire = dict(returned_integrity=dict(dnp3_crc_bad=[], tcp_checksum_bad=[]),
                    unmatched_sent=[], unmatched_returned=[], duplicate_returned=[])
        timing = dict(summary={kind: dict(logical_requests=count, complete=count, incomplete=0,
                     req_crc_bad=0, resp_crc_bad=0, resp_len=[58], piggyback=0)
                     for kind, count in (('READ', 20), ('SELECT', 1), ('OPERATE', 1))})
        result = dict(ok=True, master_rc=0, endpoint_controls=controls,
                      tcpdump={direction: dict(captured=10, dropped_kernel=0) for direction in ('out', 'in')})
        for name, value in (('master.json', master), ('outstation.json', outstation), ('result.json', result)):
            (self.root / name).write_text(json.dumps(value))
        (self.root / 'state.txt').write_text('observed state')
        rst = frame(vc.MASTER, vc.OUTSTATION, self.port, 20000, flags=20)
        pcap(self.root / 'out.pcap', [rst]); pcap(self.root / 'in.pcap', [rst])
        with patch.object(vc.wc, 'analyze', return_value=wire), patch.object(vc.clrt, 'analyze', return_value=timing):
            self.assertEqual(vc.evaluate(self.root, self.port, 'rst', 1, result), [])
            pcap(self.root / 'in.pcap', [])
            self.assertIn('captured close proof missing: rst', vc.evaluate(self.root, self.port, 'rst', 1, result))
            pcap(self.root / 'in.pcap', [rst])
            master.pop('close_grace_ms'); (self.root / 'master.json').write_text(json.dumps(master))
            self.assertIn('missing or wrong master effective controls', vc.evaluate(self.root, self.port, 'rst', 1, result))
            master.update(controls); (self.root / 'master.json').write_text(json.dumps(master))
            outstation['operate_real'] = 0; (self.root / 'outstation.json').write_text(json.dumps(outstation))
            self.assertTrue(vc.evaluate(self.root, self.port, 'rst', 1, result))
            outstation['operate_real'] = 1; (self.root / 'outstation.json').write_text(json.dumps(outstation))
            master['opens'] = 2; (self.root / 'master.json').write_text(json.dumps(master))
            self.assertIn('master must report exactly one connection open', vc.evaluate(self.root, self.port, 'rst', 1, result))
            master['opens'] = 1; (self.root / 'master.json').write_text(json.dumps(master))
            result['tcpdump']['in']['dropped_kernel'] = 1
            self.assertIn('missing or lossy capture statistics: in', vc.evaluate(self.root, self.port, 'rst', 1, result))
            result['tcpdump']['in']['dropped_kernel'] = 0
            master.update(reads_requested=1, reads_completed=1, reads=master['reads'][:1], close_grace_ms=1000)
            (self.root / 'master.json').write_text(json.dumps(master))
            result['endpoint_controls'] = dict(controls, close_grace_ms=1000)
            timing['summary']['READ'].update(logical_requests=1, complete=1)
            self.assertEqual(vc.evaluate(self.root, self.port, 'rst', 1, result, rst_grace_ms=1000, reads=1), [])
            master['close_grace_ms'] = 5000; (self.root / 'master.json').write_text(json.dumps(master))
            self.assertIn('missing or wrong master effective controls',
                          vc.evaluate(self.root, self.port, 'rst', 1, result, rst_grace_ms=1000, reads=1))
            master.update(close_grace_ms=1000, pre_read_grace_ms=500,
                          pre_read_ready_ns=1_000_000_000, first_read_issued_ns=1_500_000_000)
            (self.root / 'master.json').write_text(json.dumps(master))
            (self.root / 'pre_read_ready.json').write_text(json.dumps(dict(pre_read_grace_ms=500,
                pre_read_ready_ns=1_000_000_000, first_read_issued_ns=0, tcp_open=True, opens=1)))
            self.assertEqual(vc.evaluate(self.root, self.port, 'rst', 1, result,
                             rst_grace_ms=1000, reads=1, pre_read_grace_ms=500), [])
            (self.root / 'pre_read_ready.json').unlink()
            self.assertIn('missing or malformed pre-READ marker', vc.evaluate(self.root, self.port, 'rst', 1, result,
                          rst_grace_ms=1000, reads=1, pre_read_grace_ms=500))

    def test_scenario_reuses_installed_tuple_three_times_without_setup(self):
        calls = []
        def connect(dest, label, port, *args, **kwargs):
            Path(dest).mkdir(); calls.append((port, args, kwargs))
            return {'ok': True}
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(vc.vr, 'RUNS', str(self.root)), \
             patch.object(vc, 'preflight', return_value=[]), patch.object(vc.vr, 'run_connection', side_effect=connect), \
             patch.object(vc, 'evaluate', return_value=[]), patch.object(vc.vr, 'profile', side_effect=AssertionError('setup')), \
             patch.object(vc.vr, 'casea', side_effect=AssertionError('fixture')):
            record = vc.scenario('test', self.port, 'graceful', 1, apply=True)
        self.assertTrue(record['ok']); self.assertEqual([row[0] for row in calls], [self.port] * 3)
        self.assertTrue(all(row[2]['close_grace_ms'] == 0 for row in calls))
        self.assertTrue(all(row[2]['capture_immediate'] is False for row in calls))
        self.assertEqual(len(record['connections']), 3)

    def test_custom_rst_grace_and_single_read_propagate_to_endpoint_and_gate(self):
        calls, gates = [], []
        def connect(dest, label, port, *args, **kwargs):
            Path(dest).mkdir(); calls.append((port, args, kwargs)); return {'ok': True}
        def evaluate(*args, **kwargs):
            gates.append(kwargs); return []
        with patch.object(vc.vr, 'RUNS', str(self.root)), patch.object(vc, 'preflight', return_value=[]), \
             patch.object(vc, 'observe', return_value={'ok': True}), patch.object(vc.vr, 'run_connection', side_effect=connect), \
             patch.object(vc, 'evaluate', side_effect=evaluate):
            record = vc.scenario('test', self.port, 'rst', 1, apply=True, rst_grace_ms=1000, reads=1)
        self.assertTrue(record['ok']); self.assertEqual(len(calls), 3)
        self.assertTrue(all(row[1][0] == 1 and row[2]['close_grace_ms'] == 1000 for row in calls))
        self.assertTrue(all(row[2]['capture_immediate'] is True for row in calls))
        self.assertTrue(all(row == dict(rst_grace_ms=1000, reads=1, pre_read_grace_ms=0, control_padding=1,
                                        expect_held_operate_dup=0, expect_overtaken_ack=0, image_len=58)
                            for row in gates))

    def test_qualify_capture_is_opt_in_and_reaches_each_connection(self):
        calls = []
        def connect(dest, label, port, *args, **kwargs):
            Path(dest).mkdir(); calls.append(kwargs); return {'ok': True}
        with patch.object(vc.vr, 'RUNS', str(self.root)), patch.object(vc, 'preflight', return_value=[]), \
             patch.object(vc.vr, 'run_connection', side_effect=connect), patch.object(vc, 'evaluate', return_value=[]):
            record = vc.scenario('test', self.port, 'graceful', 1, apply=True, qualify_capture=True)
        self.assertTrue(record['ok'])
        self.assertTrue(all(row['qualify_capture'] is True for row in calls))
        self.assertTrue(record['qualify_capture'])

    def test_strict_control_padding_propagates_to_gate(self):
        gates = []
        def connect(dest, label, port, *args, **kwargs):
            Path(dest).mkdir(); return {'ok': True}
        def evaluate(*args, **kwargs):
            gates.append(kwargs); return []
        with patch.object(vc.vr, 'RUNS', str(self.root)), patch.object(vc, 'preflight', return_value=[]), \
             patch.object(vc, 'observe', return_value={'ok': True}), patch.object(vc.vr, 'run_connection', side_effect=connect), \
             patch.object(vc, 'evaluate', side_effect=evaluate):
            vc.scenario('test', self.port, 'graceful', 1, apply=True, control_padding=0)
        self.assertEqual([g['control_padding'] for g in gates], [0, 0, 0])
        self.assertEqual(vc.EXPECT_STRICT['padding']['1'], {'read_resp_len': [58], 'sbo_resp_len': [37]})

    def test_rst_grace_and_read_bounds_are_enforced_offline(self):
        for value in (499, 5001, True, '1000'):
            with self.subTest(grace=value), self.assertRaises(ValueError):
                vc.scenario('test', self.port, 'rst', 1, rst_grace_ms=value)
        for value in (0, 21, True):
            with self.subTest(reads=value), self.assertRaises(ValueError):
                vc.scenario('test', self.port, 'rst', 1, reads=value)
        for value in (500, 1000, 5000):
            with self.subTest(grace=value):
                self.assertEqual(vc.scenario('test', self.port, 'rst', 1, rst_grace_ms=value)['close_grace_ms'], value)

    def test_pre_read_grace_bounds_are_enforced_offline(self):
        for value in (-1, vc.PRE_READ_GRACE_MS + 1, True, '500'):
            with self.subTest(grace=value), self.assertRaises(ValueError):
                vc.scenario('test', self.port, 'rst', 1, pre_read_grace_ms=value)
        for value in (0, vc.PRE_READ_GRACE_MS):
            self.assertEqual(vc.scenario('test', self.port, 'rst', 1, pre_read_grace_ms=value)['pre_read_grace_ms'], value)

    def test_pre_read_environment_uses_exact_marker_and_restores_caller_on_failure(self):
        old = {'CASE4_PRE_READ_GRACE_MS': '777', 'CASE4_PRE_READ_MARKER': '/caller/marker'}
        with patch.dict(os.environ, old):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                with vc.pre_read_controls(self.root, vc.PRE_READ_GRACE_MS):
                    self.assertEqual(os.environ['CASE4_PRE_READ_GRACE_MS'], str(vc.PRE_READ_GRACE_MS))
                    self.assertEqual(os.environ['CASE4_PRE_READ_MARKER'], str(self.root / 'pre_read_ready.json'))
                    raise RuntimeError('injected')
            self.assertEqual({key: os.environ[key] for key in old}, old)
            with vc.pre_read_controls(self.root, 0):
                self.assertEqual(os.environ['CASE4_PRE_READ_GRACE_MS'], '0')
                self.assertNotIn('CASE4_PRE_READ_MARKER', os.environ)
            self.assertEqual({key: os.environ[key] for key in old}, old)
        with patch.dict(os.environ):
            for key in old:
                os.environ.pop(key, None)
            with vc.pre_read_controls(self.root, 500):
                self.assertIn('CASE4_PRE_READ_MARKER', os.environ)
            self.assertTrue(all(key not in os.environ for key in old))

    def test_pre_read_hook_requires_marker_matching_master_and_full_elapsed_grace(self):
        master = dict(pre_read_grace_ms=500, pre_read_ready_ns=1_000_000_000, first_read_issued_ns=1_500_000_000)
        marker = dict(pre_read_grace_ms=500, pre_read_ready_ns=1_000_000_000, first_read_issued_ns=0, tcp_open=True, opens=1)
        (self.root/'master.json').write_text(json.dumps(master))
        (self.root/'pre_read_ready.json').write_text(json.dumps(marker))
        failures, observed = vc.pre_read_evidence(self.root, 500)
        self.assertEqual(failures, []); self.assertEqual(observed['elapsed_ns'], 500_000_000)
        self.assertEqual(len(observed['marker_sha256']), 64)
        for field, value in (('pre_read_grace_ms', 0), ('pre_read_ready_ns', '1000000000'),
                             ('first_read_issued_ns', 1_499_999_999)):
            with self.subTest(master_field=field):
                changed = dict(master); changed[field] = value
                (self.root/'master.json').write_text(json.dumps(changed))
                self.assertTrue(vc.pre_read_evidence(self.root, 500)[0])
        (self.root/'master.json').write_text(json.dumps(master))
        for field, value in (('pre_read_grace_ms', 0), ('pre_read_ready_ns', 999), ('first_read_issued_ns', 1),
                             ('tcp_open', False), ('opens', True)):
            with self.subTest(marker_field=field):
                changed = dict(marker); changed[field] = value
                (self.root/'pre_read_ready.json').write_text(json.dumps(changed))
                self.assertTrue(vc.pre_read_evidence(self.root, 500)[0])
        (self.root/'pre_read_ready.json').unlink()
        self.assertTrue(vc.pre_read_evidence(self.root, 500)[0])
        (self.root/'master.json').write_text('{}')
        self.assertTrue(vc.pre_read_evidence(self.root, 500)[0])

    def test_zero_pre_read_grace_accepts_legacy_missing_field_and_only_observed_zero(self):
        for value, accepted in ((None, True), (0, True), (False, False), (500, False), ('0', False)):
            with self.subTest(value=value):
                master = {} if value is None else {'pre_read_grace_ms': value}
                (self.root/'master.json').write_text(json.dumps(master))
                self.assertEqual(not vc.pre_read_evidence(self.root, 0)[0], accepted)

    def test_scenario_exports_hook_fields_hashes_and_per_connection_marker_paths(self):
        calls = []
        def connect(dest, *args, **kwargs):
            dest = Path(dest); dest.mkdir()
            marker_path = os.environ['CASE4_PRE_READ_MARKER']
            calls.append((os.environ['CASE4_PRE_READ_GRACE_MS'], marker_path))
            master = dict(pre_read_grace_ms=vc.PRE_READ_GRACE_MS, pre_read_ready_ns=1_000_000_000,
                          first_read_issued_ns=1_000_000_000 + vc.PRE_READ_GRACE_MS * 1_000_000)
            (dest/'master.json').write_text(json.dumps(master))
            Path(marker_path).write_text(json.dumps(dict(pre_read_grace_ms=vc.PRE_READ_GRACE_MS,
                 pre_read_ready_ns=1_000_000_000, first_read_issued_ns=0, tcp_open=True, opens=1)))
            return {'ok': True}
        with patch.object(vc.vr, 'RUNS', str(self.root)), patch.object(vc, 'preflight', return_value=[]), \
             patch.object(vc.vr, 'run_connection', side_effect=connect), patch.object(vc, 'evaluate', return_value=[]):
            record = vc.scenario('hook_test', self.port, 'graceful', 1, apply=True,
                                 pre_read_grace_ms=vc.PRE_READ_GRACE_MS)
        self.assertTrue(record['ok']); self.assertEqual(len(calls), 3)
        for index, (grace, path) in enumerate(calls, 1):
            self.assertEqual(grace, str(vc.PRE_READ_GRACE_MS)); self.assertEqual(path, str(self.root/'hook_test'/('c%d' % index)/'pre_read_ready.json'))
            hook = record['connections'][index-1]['pre_read_hook']
            self.assertEqual(hook['observed_pre_read_grace_ms'], vc.PRE_READ_GRACE_MS); self.assertEqual(len(hook['marker_sha256']), 64)

    def test_failed_connection_stops_observer_and_remaining_scenario(self):
        stopped = threading.Event()
        def watch(dest, port, done, **kwargs):
            done.wait(1); stopped.set(); return {'ok': False, 'error': 'stopped'}
        def fail(dest, *args, **kwargs):
            Path(dest).mkdir(); raise RuntimeError('injected failure')
        with patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'}), patch.object(vc.vr, 'RUNS', str(self.root)), \
             patch.object(vc, 'preflight', return_value=[]), patch.object(vc, 'observe', side_effect=watch), \
             patch.object(vc.vr, 'run_connection', side_effect=fail), patch.object(vc, 'evaluate', return_value=[]):
            record = vc.scenario('test', self.port, 'rst', 1, apply=True)
        self.assertFalse(record['ok']); self.assertTrue(stopped.is_set())
        self.assertEqual(len(record['connections']), 1)
        self.assertFalse(record['connections'][0]['ok'])

    def test_close_proof_requires_valid_incoming_kernel_rst_or_both_fins(self):
        rst = frame(vc.MASTER, vc.OUTSTATION, self.port, 20000, flags=20)
        pcap(self.root / 'out.pcap', [rst]); pcap(self.root / 'in.pcap', [])
        self.assertFalse(vc.close_proof(self.root, self.port, 'rst'))
        pcap(self.root / 'in.pcap', [rst]); self.assertTrue(vc.close_proof(self.root, self.port, 'rst'))
        invalid = bytearray(rst); invalid[50] ^= 1
        pcap(self.root / 'in.pcap', [bytes(invalid)]); self.assertFalse(vc.close_proof(self.root, self.port, 'rst'))
        pcap(self.root / 'in.pcap', [frame(vc.MASTER, vc.OUTSTATION, self.port, 20000, flags=17),
                                   frame(vc.OUTSTATION, vc.MASTER, 20000, self.port, flags=17)])
        self.assertTrue(vc.close_proof(self.root, self.port, 'graceful'))


if __name__ == '__main__':
    unittest.main()



import sys  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[5] / 'protocol/hw_vepa/tests'))


class HeldOperateDuplicates(unittest.TestCase):
    """Only a master 35-octet retransmission of an earlier sent segment is excused as a dropped held duplicate."""

    def write(self, tmp, frames):
        import pcaptk as tk
        tk.write_pcap(str(Path(tmp) / 'out.pcap'), frames)
        return Path(tmp) / 'out.pcap'

    def test_only_true_retransmissions_are_excused(self):
        import tempfile
        import pcaptk as tk
        with tempfile.TemporaryDirectory() as tmp:
            op = tk.frame(vc.MASTER, vc.OUTSTATION, 59420, 20000, 1000, 5000, tk.PSH | tk.ACK, b'\x05' * 35)
            other = tk.frame(vc.MASTER, vc.OUTSTATION, 59420, 20000, 1035, 5000, tk.PSH | tk.ACK, b'\x06' * 35)
            path = self.write(tmp, [(1000, op), (208000, op), (300000, other)])
            excused, remaining = vc.held_operate_duplicates(path, [{'sent_index': 1}, {'sent_index': 2},
                                                                  {'sent_index': 0}])
            self.assertEqual([e['sent_index'] for e in excused], [1])
            self.assertEqual([r['sent_index'] for r in remaining], [2, 0])


    def test_expect_defaults_reproduce_the_fixed_tables(self):
        self.assertEqual(vc.expect(1, 58), vc.EXPECT)
        self.assertEqual(vc.expect(0, 58), vc.EXPECT_STRICT)
        self.assertEqual(vc.expect(1, 61)['padding']['1'], {'read_resp_len': [61], 'sbo_resp_len': [61]})
