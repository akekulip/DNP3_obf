"""Host diagnostic: RX interrupt coalescing off for one campaign, baseline recorded and restored (Philip,
2026-10-22). Only RX moderation is touched; restore verifies by read-back and keeps the baseline on any mismatch."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import capture_observation as co  # noqa: E402

TEMPLATE = ('Coalesce parameters for enp59s0f0np0:\nAdaptive RX: %s  TX: on\nstats-block-usecs:\tn/a\n\n'
            'rx-usecs:\t%d\nrx-frames:\tn/a\n\ntx-usecs:\t50\n')


class FakeNic:
    def __init__(self, adaptive='on', usecs=50, refuse=False):
        self.adaptive, self.usecs, self.refuse, self.calls = adaptive, usecs, refuse, []

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:2] == ['ethtool', '-c']:
            return SimpleNamespace(returncode=0, stdout=TEMPLATE % (self.adaptive, self.usecs), stderr='')
        if cmd[:2] == ['ethtool', '-C']:
            if self.refuse:
                return SimpleNamespace(returncode=1, stdout='', stderr='Operation not supported')
            args = dict(zip(cmd[3::2], cmd[4::2]))
            if args.get('adaptive-rx') == 'on' and 'rx-usecs' in args:   # the i40e rejection seen on Vision
                return SimpleNamespace(returncode=1, stdout='', stderr='netlink error: Invalid argument')
            self.adaptive = args.get('adaptive-rx', self.adaptive)
            self.usecs = int(args.get('rx-usecs', self.usecs))
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(cmd)


class RxCoalesceDiagnostic(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'rx_coalesce_baseline.json'

    def tearDown(self):
        self.temp.cleanup()

    def test_apply_records_baseline_and_reads_back(self):
        nic = FakeNic()
        baseline, effective = co.rx_coalesce_diagnostic(self.path, run=nic)
        self.assertEqual((baseline['adaptive_rx'], baseline['rx_usecs']), ('on', 50))
        self.assertEqual((effective['adaptive_rx'], effective['rx_usecs']), ('off', 0))
        self.assertTrue(self.path.exists())
        # only RX moderation is written
        writes = [c for c in nic.calls if c[:2] == ['ethtool', '-C']]
        self.assertEqual(writes, [['ethtool', '-C', 'enp59s0f0np0', 'adaptive-rx', 'off', 'rx-usecs', '0']])

    def test_existing_baseline_is_never_overwritten(self):
        self.path.write_text(json.dumps({'interface': 'enp59s0f0np0', 'adaptive_rx': 'on', 'rx_usecs': 50}))
        baseline, _ = co.rx_coalesce_diagnostic(self.path, run=FakeNic(adaptive='off', usecs=0))
        self.assertEqual((baseline['adaptive_rx'], baseline['rx_usecs']), ('on', 50))

    def test_ineffective_setting_raises(self):
        with self.assertRaisesRegex(RuntimeError, 'not effective'):
            co.rx_coalesce_diagnostic(self.path, run=FakeNic(refuse=True))

    def test_restore_reapplies_verifies_and_removes_baseline(self):
        nic = FakeNic()
        co.rx_coalesce_diagnostic(self.path, run=nic)
        self.assertEqual(co.restore_rx_coalesce(self.path, run=nic), [])
        self.assertEqual((nic.adaptive, nic.usecs), ('on', 50))
        self.assertFalse(self.path.exists())

    def test_restore_mismatch_keeps_baseline_and_reports(self):
        nic = FakeNic()
        co.rx_coalesce_diagnostic(self.path, run=nic)
        nic.refuse = True
        errors = co.restore_rx_coalesce(self.path, run=nic)
        self.assertTrue(errors)
        self.assertTrue(self.path.exists())

    def test_restore_without_diagnostic_is_a_noop(self):
        nic = FakeNic()
        self.assertEqual(co.restore_rx_coalesce(self.path, run=nic), [])
        self.assertEqual(nic.calls, [])


class CampaignSetupCommand(unittest.TestCase):
    def setup_command(self, cfg):
        import campaign as cp
        steps = []
        stub = type('S', (), {'V': '/v', 'cfg': cfg, 'vision_touched': False, 'rn': SimpleNamespace(dry=True), 'root': '/nonexistent',
                              'step': lambda self, where, what, cmd, **k: steps.append(cmd)})()
        cp.Campaign.vision_setup(stub)
        return steps[0]

    def test_flag_only_with_the_diagnostic(self):
        self.assertEqual(self.setup_command({}), 'sudo python3 /v/vision_run.py setup')
        self.assertEqual(self.setup_command({'host_diagnostic': {'rx_coalescing': 'off'}}),
                         'sudo python3 /v/vision_run.py setup --rx-coalesce-diag')
        with self.assertRaises(ValueError):
            self.setup_command({'host_diagnostic': {'rx_coalescing': 'on'}})


class CpuLatencyHold(unittest.TestCase):
    """The supervised CPU-latency request, with the REAL helper code against a stand-in device file. The fake read
    models the kernel: the effective constraint is 0 while the recorded helper runs, the baseline otherwise."""
    BASE = 2000000000

    def setUp(self):
        import struct
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.state = self.dir / 'cpu_latency_state.json'
        self.device = self.dir / 'cpu_dma_latency'
        self.device.write_bytes(struct.pack('i', self.BASE))
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.kill_leftovers)

    def kill_leftovers(self):
        import os, signal
        try:
            st = json.loads(self.state.read_text())
            os.kill(st['pid'], signal.SIGKILL)
        except Exception:
            pass

    def kernel_read(self):
        try:
            st = json.loads(self.state.read_text())
        except Exception:
            return self.BASE
        return 0 if co._is_helper(st) else self.BASE

    def hold(self, **kw):
        kw.setdefault('read', self.kernel_read)
        kw.setdefault('held', lambda: False)
        return co.cpu_latency_hold(self.state, device=str(self.device), **kw)

    def test_real_helper_holds_then_release_closes_and_restores(self):
        held = self.hold()
        self.assertEqual((held['baseline'], held['effective']), (self.BASE, 0))
        self.assertIsNotNone(held['start_time'])
        self.assertEqual(self.device.read_bytes()[:4], b'\0\0\0\0')        # the helper wrote a signed 32-bit zero
        errors, evidence = co.cpu_latency_release(self.state, read=self.kernel_read)
        self.assertEqual(errors, [])
        self.assertTrue(evidence['held_at_release'] and evidence['diagnostic_valid'])
        self.assertIsNone(co.process_identity(held['pid']))                 # SIGTERM handler closed and exited
        self.assertFalse(self.state.exists())

    def test_refusals_before_any_spawn(self):
        spawned = []
        spawn = lambda: spawned.append(1)
        with self.assertRaisesRegex(RuntimeError, 'expected baseline'):
            self.hold(read=lambda: 0, spawn=spawn)
        with self.assertRaisesRegex(RuntimeError, 'already holds'):
            self.hold(held=lambda: True, spawn=spawn)
        self.state.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.hold(spawn=spawn)
        self.assertEqual(spawned, [])

    def test_ineffective_request_stops_helper_and_removes_state(self):
        pids = []
        real = lambda: __import__('subprocess').Popen(
            [sys.executable, '-c', co.CPU_LATENCY_HOLD, str(self.state) + '.helper', str(self.device)],
            start_new_session=True)
        spawn = lambda: pids.append(real()) or pids[-1]
        with self.assertRaisesRegex(RuntimeError, 'not effective'):
            self.hold(read=lambda: self.BASE, spawn=spawn, timeout=0.5)
        pids[-1].wait(timeout=5)
        self.assertIsNotNone(pids[-1].returncode)                 # helper stopped
        self.assertFalse(self.state.exists())

    def test_helper_gone_before_release_is_diagnostic_invalid_but_host_restored(self):
        import os, signal
        held = self.hold()
        os.kill(held['pid'], signal.SIGKILL)
        for _ in range(50):
            if co.process_identity(held['pid']) is None:
                break
            __import__('time').sleep(0.05)
        errors, evidence = co.cpu_latency_release(self.state, read=self.kernel_read)
        self.assertEqual(errors, [])
        self.assertFalse(evidence['held_at_release'])
        self.assertFalse(evidence['diagnostic_valid'])

    def test_reused_pid_is_never_signalled(self):
        import subprocess as sp
        other = sp.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            self.state.write_text(json.dumps({'baseline': self.BASE, 'pid': other.pid, 'start_time': -1,
                                              'helper_file': str(self.state) + '.helper', 'device': str(self.device)}))
            errors, evidence = co.cpu_latency_release(self.state, read=lambda: self.BASE)
            self.assertIsNone(other.poll())                          # still running: not signalled
            self.assertFalse(evidence['diagnostic_valid'])
            self.assertEqual(errors, [])
        finally:
            other.kill()

    def test_failed_read_before_release_still_stops_helper(self):
        held = self.hold()
        reads = iter([RuntimeError('device gone')])

        def flaky():
            item = next(reads, None)
            if isinstance(item, Exception):
                raise item
            return self.BASE
        errors, evidence = co.cpu_latency_release(self.state, read=flaky)
        self.assertIsNone(co.process_identity(held['pid']))
        self.assertFalse(evidence['held_at_release'])
        self.assertEqual(errors, [])

    def test_constraint_not_back_keeps_state(self):
        self.hold()
        errors, _ = co.cpu_latency_release(self.state, read=lambda: 0)
        self.assertTrue(any('baseline' in e for e in errors))
        self.assertTrue(self.state.exists())

    def test_corrupted_state_is_a_host_error(self):
        self.state.write_text('{not json')
        errors, _ = co.cpu_latency_release(self.state, read=lambda: self.BASE)
        self.assertTrue(errors)

    def test_release_without_state_checks_the_device(self):
        errors, evidence = co.cpu_latency_release(self.state, read=lambda: self.BASE, held=lambda: False)
        self.assertEqual(errors, [])
        self.assertFalse(evidence['applied'])
        # an orphaned helper (setup killed before writing its state): constraint 0 / device held -> host error
        self.assertTrue(co.cpu_latency_release(self.state, read=lambda: 0, held=lambda: False)[0])
        self.assertTrue(co.cpu_latency_release(self.state, read=lambda: self.BASE, held=lambda: True)[0])

    def test_read_cpu_latency_reads_a_signed_int(self):
        self.assertEqual(co.read_cpu_latency(str(self.device)), self.BASE)


class RestoreOrder(unittest.TestCase):
    """vision_run restore: the CPU release runs first and every step runs even when an earlier one raises or exits."""

    def test_raising_steps_do_not_skip_others(self):
        import vision_run as vr
        calls = []
        stubs = {
            'casea': lambda *a: (calls.append('casea'), sys.exit('ip route failed'))[1],
            'profile': lambda *a: (calls.append('profile'), (_ for _ in ()).throw(RuntimeError('sysctl')))[1],
            'state': lambda: 'source-pruning : off',
            'pruning': lambda *a: calls.append('pruning'),
        }
        co_stubs = {
            'cpu_latency_release': lambda p: (calls.append('cpu'), ([], {'applied': False}))[1],
            'restore_offload_baseline': lambda *a: (calls.append('offload'), [])[1],
            'restore_rx_coalesce': lambda *a: (calls.append('rx'), [])[1],
            'read_cpu_latency': lambda: 2000000000,
            'snapshot_rx_coalesce': lambda *a: {'adaptive_rx': 'on', 'rx_usecs': 50},
        }
        from unittest import mock
        with mock.patch.multiple(vr, **stubs), mock.patch.multiple(vr.capture_observation, **co_stubs), \
                mock.patch.object(sys, 'argv', ['vision_run.py', 'restore']):
            with self.assertRaises(SystemExit) as caught:
                vr.main()
        self.assertEqual(calls[0], 'cpu')
        self.assertEqual(set(calls), {'cpu', 'casea', 'profile', 'offload', 'rx'})
        self.assertIn('fixture off raised', str(caught.exception))
        self.assertIn('namespace profile raised', str(caught.exception))


class HostDiagnosticKeys(unittest.TestCase):
    def test_unknown_key_is_refused(self):
        import campaign as cp
        stub = type('S', (), {'V': '/v', 'cfg': {'host_diagnostic': {'cpu_latncy': 'zero'}}, 'vision_touched': False, 'rn': SimpleNamespace(dry=True), 'root': '/nonexistent',
                              'step': lambda self, *a, **k: None})()
        with self.assertRaisesRegex(ValueError, 'unknown keys'):
            cp.Campaign.vision_setup(stub)

    def test_cpu_flag(self):
        import campaign as cp
        steps = []
        stub = type('S', (), {'V': '/v', 'cfg': {'host_diagnostic': {'cpu_latency': 'zero', '_note': 'x'}},
                              'vision_touched': False, 'rn': SimpleNamespace(dry=True), 'root': '/nonexistent', 'step': lambda self, w, what, cmd, **k: steps.append(cmd)})()
        cp.Campaign.vision_setup(stub)
        self.assertEqual(steps, ['sudo python3 /v/vision_run.py setup --cpu-latency-diag'])


class CampaignEvidence(unittest.TestCase):
    """The release evidence is kept in the record; an invalid or missing CPU diagnostic fails the block."""

    def run_evidence(self, output, cfg):
        import campaign as cp
        stub = type('S', (), {'cfg': cfg, 'record': {}, 'soft_failures': []})()
        cp.Campaign.host_diagnostic_evidence(stub, output)
        return stub

    def test_valid_evidence_recorded(self):
        st = self.run_evidence('x\ncpu latency release evidence: {"applied": true, "diagnostic_valid": true}\n',
                               {'host_diagnostic': {'cpu_latency': 'zero'}})
        self.assertTrue(st.record['cpu_latency_diagnostic']['diagnostic_valid'])
        self.assertEqual(st.soft_failures, [])

    def test_invalid_or_missing_evidence_fails(self):
        st = self.run_evidence('cpu latency release evidence: {"applied": true, "diagnostic_valid": false}\n',
                               {'host_diagnostic': {'cpu_latency': 'zero'}})
        self.assertTrue(st.soft_failures)
        st = self.run_evidence('nothing printed\n', {'host_diagnostic': {'cpu_latency': 'zero'}})
        self.assertTrue(st.soft_failures)

    def test_no_diagnostic_no_effect(self):
        st = self.run_evidence('cpu latency release evidence: {"applied": false}\n', {})
        self.assertEqual(st.soft_failures, [])


class GateWithInvalidDiagnostic(unittest.TestCase):
    def test_non_object_evidence_is_invalid_not_a_crash(self):
        import campaign as cp
        stub = type('S', (), {'cfg': {'host_diagnostic': {'cpu_latency': 'zero'}}, 'record': {}, 'soft_failures': []})()
        cp.Campaign.host_diagnostic_evidence(stub, 'cpu latency release evidence: [1, 2]\n')
        self.assertTrue(stub.record['host_diagnostic_invalid'])
        self.assertTrue(stub.soft_failures)


class ReviewTwoFindings(unittest.TestCase):
    def test_restore_exits_nonzero_on_cpu_host_errors_and_still_runs_the_rest(self):
        import vision_run as vr
        from unittest import mock
        calls = []
        co_stubs = {
            'cpu_latency_release': lambda p: (calls.append('cpu'), (['helper 7 still running after SIGTERM'],
                                                                    {'applied': True, 'diagnostic_valid': True}))[1],
            'restore_offload_baseline': lambda *a: (calls.append('offload'), [])[1],
            'restore_rx_coalesce': lambda *a: (calls.append('rx'), [])[1],
            'read_cpu_latency': lambda: 0,
            'snapshot_rx_coalesce': lambda *a: {'adaptive_rx': 'on', 'rx_usecs': 50},
        }
        stubs = {'casea': lambda *a: calls.append('casea'), 'profile': lambda *a: calls.append('profile'),
                 'state': lambda: 'source-pruning : off', 'pruning': lambda *a: None}
        with mock.patch.multiple(vr, **stubs), mock.patch.multiple(vr.capture_observation, **co_stubs), \
                mock.patch.object(sys, 'argv', ['vision_run.py', 'restore']):
            with self.assertRaises(SystemExit) as caught:
                vr.main()
        self.assertIn('cpu latency restore failed', str(caught.exception))
        self.assertEqual(set(calls), {'cpu', 'casea', 'profile', 'offload', 'rx'})

    def test_setup_refuses_a_leftover_state_or_constraint_for_any_block(self):
        import vision_run as vr
        from unittest import mock
        base = {'device_held': lambda: False,
                'read_cpu_latency': lambda: 2000000000}
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / 'cpu_latency_state.json'
            for case, co_over, make_state in (('state file', {}, True), ('constraint', {'read_cpu_latency': lambda: 0}, False),
                                              ('held', {'device_held': lambda: True}, False)):
                if make_state:
                    state.write_text('{}')
                elif state.exists():
                    state.unlink()
                with mock.patch.object(vr, 'CPU_LATENCY_STATE', str(state)), \
                        mock.patch.multiple(vr.capture_observation, **dict(base, **co_over)), \
                        mock.patch.object(vr, 'profile', lambda *a: self.fail('setup went past the refusal')), \
                        mock.patch.object(vr.capture_observation, 'record_offload_baseline',
                                          lambda *a: self.fail('setup changed state before the refusal')), \
                        mock.patch.object(sys, 'argv', ['vision_run.py', 'setup']):
                    with self.assertRaisesRegex(SystemExit, 'setup refused', msg=case):
                        vr.main()

    def test_hold_on_a_block_that_did_not_request_it_fails(self):
        import campaign as cp
        stub = type('S', (), {'cfg': {}, 'record': {}, 'soft_failures': []})()
        cp.Campaign.host_diagnostic_evidence(stub, 'cpu latency release evidence: {"applied": true, "diagnostic_valid": true}\n')
        self.assertTrue(stub.record['host_diagnostic_invalid'])
        self.assertTrue(stub.soft_failures)

    def test_gate_never_excuses_an_invalid_diagnostic(self):
        import campaign as cp
        self.assertTrue(cp.gate_ok({'ok': True}, False))
        self.assertTrue(cp.gate_ok({'ok': False}, True))                     # precision-only reported path
        self.assertFalse(cp.gate_ok({'ok': False, 'host_diagnostic_invalid': True}, True))
        self.assertFalse(cp.gate_ok({'ok': True, 'host_diagnostic_invalid': True}, False))
        src = Path(cp.__file__).read_text()
        self.assertIn("self.record['gate_ok'] = gate_ok(self.record, precision_reported)", src)
