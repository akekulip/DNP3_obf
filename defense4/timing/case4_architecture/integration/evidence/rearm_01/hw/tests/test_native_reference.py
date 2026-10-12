"""Native-reference gates and restoration through a fake process boundary."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_reference', HW / 'native_reference.py')
nr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nr)


def artifacts(dest):
    master = dict(success=True, all_reads_match_seed=True, reads_completed=20, reads_requested=20,
                  application_calls=1, read_pause_ms=25, run_sbo=True, close_grace_ms=0,
                  reads=[dict(points_received=23, matches_seed=True, completed=True)] * 20)
    outstation = dict(select_real=1, operate_real=1, select_decoy=0, operate_decoy=0)
    summary = {kind: dict(logical_requests=count, complete=count, incomplete=0, req_crc_bad=0,
                         resp_crc_bad=0, resp_len=[length], piggyback=0)
               for kind, count, length in [('READ', 20, 49), ('SELECT', 1, 37), ('OPERATE', 1, 37)]}
    wire = dict(returned_integrity=dict(dnp3_crc_bad=[], tcp_checksum_bad=[]),
                unmatched_returned=[], unmatched_sent=[], duplicate_returned=[])
    result = dict(ok=True, master_rc=0, endpoint_controls=dict(read_pause_ms=25, run_sbo=True, close_grace_ms=0))
    for name, value in [('master.json', master), ('outstation.json', outstation), ('wire.json', wire),
                        ('timing.json', dict(summary=summary)), ('result.json', result)]:
        (dest / name).write_text(json.dumps(value))
    for name in ('out.pcap', 'in.pcap', 'state.txt'):
        (dest / name).write_bytes(b'captured fixture')


class FakeRunner:
    dry = False

    def __init__(self, cfg, fail_on=None, wrong_program=False):
        self.cfg, self.fail_on, self.wrong_program = cfg, fail_on, wrong_program
        self.calls = []

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        self.calls.append((where, cmd, label))
        if self.fail_on and self.fail_on in (label or ''):
            return nr.cp.Result(1, '', 'injected failure')
        if cmd.startswith('python3 ') and 'observe_program.py' in cmd:
            return nr.cp.Result(0, json.dumps({'program': 'response_only' if self.wrong_program else nr.PROGRAM}), '')
        if cmd.startswith('sha256sum '):
            lines = []
            for remote in shlex.split(cmd)[1:]:
                name = Path(remote).name
                if name == 'case4_socket_gate_pad58b':
                    value = self.cfg['endpoint']['binary_sha256']
                else:
                    local = nr.HW_VEPA / name if name in ('vision_run.py', 'loss.py') else dict(nr.tools())[name]
                    value = nr.cp.sha256_file(str(local))
                lines.append('%s  %s' % (value, remote))
            return nr.cp.Result(0, '\n'.join(lines), '')
        if 'xargs sha256sum | sha256sum' in cmd:
            return nr.cp.Result(0, self.cfg['endpoint']['lib_sha256'] + '  -', '')
        if 'switch_slot.py vepa' in cmd:
            port = int(shlex.split(cmd)[shlex.split(cmd).index('--master-port') + 1])
            data = dict(which='vepa', master_port=port, enable=0, no_forwarding=False)
            data['Ingress.forwarding'] = [{'key': {'ig.ingress_port': 9}, 'data': {'port': 9}}]
            data['Egress.conn'] = [{'key': {}, 'data': {'enable': 0}}]
            return nr.cp.Result(0, json.dumps(data), '')
        if 'switch_counters.py' in cmd:
            return nr.cp.Result(0, json.dumps(dict(outcome={}, ports={'9': {'rx': 100, 'tx': 100}},
                regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})), '')
        if 'vision_run.py run' in cmd:
            return nr.cp.Result(0, json.dumps({'ok': True, 'master_rc': 0}), '')
        if cmd.startswith('scp -qr '):
            dest = Path(shlex.split(cmd)[-1])
            artifacts(dest)
        elif cmd.startswith('scp -q ') and '_prerun.json' in cmd:
            destination = Path(shlex.split(cmd)[-1])
            (destination / 'native_test_prerun.json').write_text('{}')
        return nr.cp.Result(0, '', '')


class NativeReference(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = nr.native_config(nr.DEFAULT_CONFIG, self.root)

    def campaign(self, fake=None):
        return nr.NativeReference(self.cfg, fake or FakeRunner(self.cfg), 'native_test', config_path=str(nr.DEFAULT_CONFIG), out=lambda _: None)

    def test_exact_native_profile_and_no_composite_deployment(self):
        fake = FakeRunner(self.cfg)
        campaign = self.campaign(fake)
        self.assertEqual(campaign.execute(), 0)
        commands = '\n'.join(cmd for _, cmd, _ in fake.calls)
        for port in range(59400, 59403):
            self.assertIn('vepa --master-port %d --enable 0' % port, commands)
        self.assertIn('/pad58b_rearm_controls_20261012/vision_run.py run', commands)
        for flag in ('--reads 20', '--range 8', '--gap-ms 0', '--start-delay-ms 0', '--read-pause-ms 25', '--run-sbo 1'):
            self.assertIn(flag, commands)
        for seed in (12345, 12346, 12347):
            self.assertIn('--start-seed %d' % seed, commands)
        for forbidden in ('switch_swap.sh', 'bringup_composite.py', 'launch_composite.sh', 'set_enabled.py', 'tofino.bin'):
            self.assertNotIn(forbidden, commands)
        retained = json.loads((Path(campaign.root) / 'native_reference.json').read_text())
        self.assertTrue(retained['ok'])
        self.assertEqual(len(retained['blocks']), 3)
        self.assertTrue(retained['hashes'])

    def test_wrong_running_program_refuses_before_mutation(self):
        fake = FakeRunner(self.cfg, wrong_program=True)
        self.assertEqual(self.campaign(fake).execute(), 1)
        commands = '\n'.join(cmd for _, cmd, _ in fake.calls)
        for forbidden in ('switch_slot.py vepa', 'vision_run.py setup', 'vision_run.py run', 'switch_slot.py relay'):
            self.assertNotIn(forbidden, commands)

    def test_all_restore_actions_are_attempted_after_traffic_or_restore_failure(self):
        for failure in ('traffic + capture', 'restore relay slot', 'restore Vision'):
            with self.subTest(failure=failure):
                fake = FakeRunner(self.cfg, fail_on=failure)
                campaign = self.campaign(fake)
                campaign.root = str(self.root / failure.replace(' ', '_'))
                self.assertEqual(campaign.execute(), 1)
                restore = [label for _, _, label in fake.calls if label and label.startswith('restore')]
                self.assertEqual(restore, ['restore relay slot', 'restore Vision', 'restore ping'])

    def test_gate_refuses_corruption_wrong_lengths_bad_values_and_missing_evidence(self):
        dest = self.root / 'block'; dest.mkdir(); artifacts(dest)
        counters = dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})
        (dest / 'before.json').write_text(json.dumps(counters)); (dest / 'after.json').write_text(json.dumps(counters))
        self.assertEqual(nr.gate(self.cfg, dest, 0, 0, 0)[0], [])
        alterations = [('outstation.json', 'operate_real', 2), ('master.json', 'all_reads_match_seed', False),
                       ('wire.json', 'unmatched_returned', [1])]
        for name, key, value in alterations:
            original = (dest / name).read_text()
            changed = json.loads(original); changed[key] = value; (dest / name).write_text(json.dumps(changed))
            self.assertTrue(nr.gate(self.cfg, dest, 0, 0, 0)[0])
            (dest / name).write_text(original)
        timing = json.loads((dest / 'timing.json').read_text()); timing['summary']['SELECT']['resp_len'] = [49]
        (dest / 'timing.json').write_text(json.dumps(timing))
        self.assertTrue(nr.gate(self.cfg, dest, 0, 0, 0)[0]); artifacts(dest)
        for rcs in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
            self.assertTrue(nr.gate(self.cfg, dest, *rcs)[0])
        (dest / 'in.pcap').unlink()
        self.assertTrue(nr.gate(self.cfg, dest, 0, 0, 0)[0])

    def test_mapper_growth_unacked_and_missing_fields_fail(self):
        dest = self.root / 'mapper'; dest.mkdir(); artifacts(dest)
        good = dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})
        (dest / 'before.json').write_text(json.dumps(good))
        for bad in ({}, dict(regs={'acct': {'Egress.acct.lo': [1], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}}),
                    dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [1]}, 'front': {'Egress.front.f1': [0]}})):
            (dest / 'after.json').write_text(json.dumps(bad))
            self.assertTrue(nr.gate(self.cfg, dest, 0, 0, 0)[0])

    def test_master_effective_controls_missing_fields_fail(self):
        dest = self.root / 'controls_missing'; dest.mkdir(); artifacts(dest)
        counters = dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})
        for name in ('before.json', 'after.json'):
            (dest / name).write_text(json.dumps(counters))
        self.assertEqual(nr.gate(self.cfg, dest, 0, 0, 0)[0], [])
        original = json.loads((dest / 'master.json').read_text())
        for field in ('read_pause_ms', 'run_sbo', 'close_grace_ms'):
            with self.subTest(field=field):
                changed = dict(original); del changed[field]
                (dest / 'master.json').write_text(json.dumps(changed))
                self.assertIn('missing or wrong master effective endpoint controls', nr.gate(self.cfg, dest, 0, 0, 0)[0])

    def test_master_effective_controls_mismatches_fail(self):
        dest = self.root / 'controls_mismatch'; dest.mkdir(); artifacts(dest)
        counters = dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})
        for name in ('before.json', 'after.json'):
            (dest / name).write_text(json.dumps(counters))
        original = json.loads((dest / 'master.json').read_text())
        for field, value in (('read_pause_ms', 0), ('read_pause_ms', '25'), ('run_sbo', False),
                             ('run_sbo', 1), ('close_grace_ms', 250), ('close_grace_ms', False)):
            with self.subTest(field=field, value=value):
                changed = dict(original); changed[field] = value
                (dest / 'master.json').write_text(json.dumps(changed))
                self.assertIn('missing or wrong master effective endpoint controls', nr.gate(self.cfg, dest, 0, 0, 0)[0])

    def test_cli_is_dry_by_default_and_apply_requires_authorization(self):
        with patch.object(nr.cp, 'ShellRunner', side_effect=AssertionError('real runner constructed')):
            with patch('builtins.print'):
                self.assertEqual(nr.main(['--out', str(self.root)]), 0)
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
                nr.main(['--apply', '--out', str(self.root)])

    def test_real_runner_cannot_bypass_authorization_via_python_api(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(nr.cp.ShellRunner, 'run',
                                                                side_effect=AssertionError('unauthorized command')):
            campaign = self.campaign(nr.cp.ShellRunner(self.cfg['hosts']))
            with self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
                campaign.execute()

    def test_malformed_summary_fails_as_evidence_without_crashing_gate(self):
        dest = self.root / 'malformed'; dest.mkdir(); artifacts(dest)
        (dest / 'timing.json').write_text(json.dumps({'summary': ['malformed']}))
        self.assertTrue(nr.gate(self.cfg, dest, 0, 0, 0)[0])


if __name__ == '__main__':
    unittest.main()
