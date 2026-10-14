"""Native replay archive gates and restoration; mocked process boundary only."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import tempfile
import unittest
from unittest.mock import patch

HW = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_rst_capture', HW / 'native_rst_capture.py')
nc = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(nc)


def write(path, value):
    Path(path).write_text(json.dumps(value))


def rst_capture(path, rst=True):
    address = lambda ip: bytes(map(int, ip.split('.')))
    src, dst = address(nc.vc.MASTER), address(nc.vc.OUTSTATION)
    tcp = bytearray(struct.pack('!HHIIBBHHH', 59400, 20000, 100, 200, 80, 20 if rst else 16, 65535, 0, 0))
    tcp[16:18] = struct.pack('!H', nc.vc.wc._sum16(src + dst + struct.pack('!BBH', 0, 6, len(tcp)) + tcp))
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 0, 0, 64, 6, 0, src, dst))
    ip[10:12] = struct.pack('!H', nc.vc.wc._sum16(ip))
    frame = bytes(12) + b'\x08\x00' + ip + tcp
    Path(path).write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
                           struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)


def extracted():
    wire = dict(returned_integrity=dict(dnp3_crc_bad=[], tcp_checksum_bad=[]),
                unmatched_sent=[], unmatched_returned=[], duplicate_returned=[])
    timing = dict(summary={kind: dict(logical_requests=1, complete=1, incomplete=0,
                   req_crc_bad=0, resp_crc_bad=0, resp_len=[length], piggyback=0)
                   for kind, length in [('READ', 49), ('SELECT', 37), ('OPERATE', 37)]})
    return wire, timing


def artifacts(dest, vision_dir):
    dest.mkdir(parents=True, exist_ok=True)
    controls = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=1000)
    connections = []
    for index in range(1, 4):
        leg = dest / ('c%d' % index); leg.mkdir(exist_ok=True)
        result = dict(ok=True, master_rc=0, endpoint_controls=controls,
                      tcpdump={name: dict(captured=10, dropped_kernel=0) for name in ('out', 'in')})
        observer = dict(ok=True, response=dict(checksum_valid=True, dnp3_crc_valid=True),
                        commands=[dict(namespace=nc.vc.NAMESPACE_M, argv=nc.vc.ss_args(59400, kill), rc=0)
                                  for kill in (False, True)])
        connection = dict(name=leg.name, master_port=59400, ok=True, failures=[], result=result, observer=observer)
        master = dict(success=True, all_reads_match_seed=True, reads_requested=1, reads_completed=1,
                      application_calls=1, opens=1, reads=[dict(points_received=23, matches_seed=True, completed=True)], **controls)
        wire, timing = extracted()
        for name, value in [('master', master), ('outstation', dict(select_real=1, operate_real=1, select_decoy=0, operate_decoy=0)),
                            ('result', result), ('observer', observer), ('verdict', connection), ('wire', wire), ('timing', timing)]:
            write(leg / (name + '.json'), value)
        (leg / 'state.txt').write_text('observed state')
        for name in ('ss_probe.log', 'ss_kill.log'):
            (leg / name).write_text('retained exact kernel operation')
        for name in ('out.pcap', 'in.pcap'):
            rst_capture(leg / name)
        connections.append(connection)
    scenario = dict(ok=True, applied=True, master_port=59400, padding=0, reads=1, close_mode='rst',
                    close_grace_ms=1000, read_pause_ms=25, pre_read_grace_ms=0,
                    tuple=[nc.vc.MASTER, 59400, nc.vc.OUTSTATION, 20000],
                    namespaces=[nc.vc.NAMESPACE_M, nc.vc.NAMESPACE_O], nic=nc.vc.NIC,
                    source_sha256=nc.source_pins(vision_dir), connections=connections)
    write(dest / 'scenario.json', scenario)
    counters = dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]}, 'front': {'Egress.front.f1': [0]}})
    for name in ('before', 'after'):
        write(dest / (name + '.json'), counters)


class FakeRunner:
    dry = False

    def __init__(self, cfg, failure=None, wrong_program=False, bad_hash=False, bad_slot=False, raises=False):
        self.cfg, self.failure, self.wrong_program, self.bad_hash = cfg, failure, wrong_program, bad_hash
        self.bad_slot, self.raises = bad_slot, raises
        self.calls = []

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        self.calls.append((where, cmd, label))
        if self.failure and self.failure in (label or ''):
            if self.raises:
                raise OSError('injected boundary exception')
            return nc.nr.cp.Result(1, '', 'injected failure')
        if cmd.startswith('python3 ') and 'observe_program.py' in cmd:
            return nc.nr.cp.Result(0, json.dumps({'program': 'response_only' if self.wrong_program else nc.nr.PROGRAM}), '')
        if cmd.startswith('sha256sum '):
            local = dict(nc.nr.tools() + nc.vision_tools())
            local.update({name: nc.nr.HW_VEPA / name for name in ('vision_run.py', 'loss.py', 'capture_observation.py', 'wire_check.py')})
            lines = []
            for remote in shlex.split(cmd)[1:]:
                name = Path(remote).name
                digest = self.cfg['endpoint']['binary_sha256'] if name == 'case4_socket_gate_pad58b' else nc.nr.cp.sha256_file(str(local[name]))
                if self.bad_hash and name == 'checks.py':
                    digest = '0' * 64
                lines.append('%s  %s' % (digest, remote))
            return nc.nr.cp.Result(0, '\n'.join(lines), '')
        if 'xargs sha256sum | sha256sum' in cmd:
            return nc.nr.cp.Result(0, self.cfg['endpoint']['lib_sha256'] + '  -', '')
        if 'switch_slot.py vepa' in cmd:
            data = dict(which='vepa', master_port=59400, enable=0, no_forwarding=False,
                        **{'Ingress.forwarding': [{'key': {'ig.ingress_port': 9}, 'data': {'port': 9}}],
                           'Egress.conn': nc.slot_rows()})
            if self.bad_slot:
                data['Egress.conn'][0]['key']['hdr.ip.src'] = 0xc0a80a07
            return nc.nr.cp.Result(0, json.dumps(data), '')
        if 'switch_counters.py' in cmd:
            return nc.nr.cp.Result(0, json.dumps(dict(regs={'acct': {'Egress.acct.lo': [0], 'Egress.acct.hi': [0]},
                                                         'front': {'Egress.front.f1': [0]}})), '')
        if cmd.startswith('scp -qr '):
            artifacts(Path(shlex.split(cmd)[-1]), self.cfg['hosts']['vision_run_dir'])
        return nc.nr.cp.Result(0, '', '')


class NativeRstCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = nc.native_rst_config(nc.nr.DEFAULT_CONFIG, self.root)
        authority = patch.dict(os.environ, {'DEFENSE4_HW_AUTHORIZED': '1'})
        authority.start(); self.addCleanup(authority.stop)
        wire, timing = extracted()
        for target, value in ((nc.vc.wc, wire), (nc.vc.clrt, timing)):
            mock = patch.object(target, 'analyze', return_value=value)
            mock.start(); self.addCleanup(mock.stop)

    def campaign(self, fake):
        return nc.NativeRstCapture(self.cfg, fake, 'native_rst_test', config_path=str(nc.nr.DEFAULT_CONFIG), out=lambda _: None)

    def test_one_fixed_native_series_and_all_restores_without_composite(self):
        fake = FakeRunner(self.cfg); campaign = self.campaign(fake)
        self.assertEqual(campaign.execute(), 0)
        commands = '\n'.join(cmd for _, cmd, _ in fake.calls)
        self.assertEqual(sum('vision_candidate.py ' in cmd and '--apply' in cmd for _, cmd, _ in fake.calls), 1)
        for flag in ('--master-port 59400', '--padding 0', '--close-mode rst', '--rst-grace-ms 1000', '--reads 1', '--pre-read-grace-ms 0'):
            self.assertIn(flag, commands)
        self.assertIn('vepa --master-port 59400 --enable 0', commands)
        for forbidden in ('switch_swap.sh', 'bringup_composite.py', 'launch_composite.sh', 'tofino.bin', '--reads 20'):
            self.assertNotIn(forbidden, commands)
        self.assertEqual([entry['step'] for entry in campaign.record['restore']], ['restore relay slot', 'restore Vision', 'restore ping'])
        retained = json.loads((Path(campaign.root) / 'native_rst_capture.json').read_text())
        self.assertTrue(retained['ok']); self.assertEqual(len(retained['series']['connections']), 3)
        self.assertFalse(retained['effective_config']['evaluation']['read_precision'])
        self.assertTrue(retained['source_hashes']); self.assertTrue(retained['hashes'])

    def test_failed_traffic_or_restore_attempts_every_restore(self):
        for failure in ('native RST traffic', 'restore relay slot', 'restore Vision'):
            with self.subTest(failure=failure):
                fake = FakeRunner(self.cfg, failure=failure); campaign = self.campaign(fake)
                campaign.root = str(self.root / failure.replace(' ', '_'))
                self.assertEqual(campaign.execute(), 1)
                self.assertEqual([entry['step'] for entry in campaign.record['restore']], ['restore relay slot', 'restore Vision', 'restore ping'])

    def test_restore_exception_does_not_skip_remaining_actions(self):
        fake = FakeRunner(self.cfg, failure='restore relay slot', raises=True)
        campaign = self.campaign(fake)
        self.assertEqual(campaign.execute(), 1)
        self.assertEqual([entry['step'] for entry in campaign.record['restore']], ['restore relay slot', 'restore Vision', 'restore ping'])

    def test_wrong_software_slot_tuple_refuses_traffic_and_restores(self):
        fake = FakeRunner(self.cfg, bad_slot=True); campaign = self.campaign(fake)
        self.assertEqual(campaign.execute(), 1)
        self.assertFalse(any(label == 'native RST traffic + capture' for _, _, label in fake.calls))
        self.assertEqual(len(campaign.record['restore']), 3)

    def test_wrong_program_or_deployed_hash_refuses_before_slot(self):
        for key in ('wrong_program', 'bad_hash'):
            fake = FakeRunner(self.cfg, **{key: True}); campaign = self.campaign(fake)
            campaign.root = str(self.root / key)
            self.assertEqual(campaign.execute(), 1)
            commands = '\n'.join(cmd for _, cmd, _ in fake.calls)
            self.assertNotIn('switch_slot.py vepa', commands)
            self.assertNotIn('vision_run.py setup', commands)
            if key == 'wrong_program':
                self.assertFalse(campaign.record['restore'])

    def test_dry_default_and_direct_apply_authorization_and_freshness(self):
        with patch.object(nc.nr.cp, 'ShellRunner', side_effect=AssertionError('real boundary')), patch('builtins.print'):
            self.assertEqual(nc.main(['--out', str(self.root)]), 0)
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'DEFENSE4_HW_AUTHORIZED'):
            self.campaign(FakeRunner(self.cfg)).execute()
        campaign = self.campaign(FakeRunner(self.cfg)); Path(campaign.root).mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh run-id'):
            campaign.execute()

    def test_archive_gate_requires_native_lengths_real_rst_controls_opens_and_pins(self):
        dest = self.root / 'archive'; artifacts(dest, self.cfg['hosts']['vision_run_dir'])
        pins = nc.source_pins(self.cfg['hosts']['vision_run_dir'])
        self.assertEqual(nc.archive_gate(self.cfg, dest, 0, pins)[0], [])
        for field, bad in [('opens', 2), ('close_grace_ms', 5000), ('all_reads_match_seed', False)]:
            path = dest / 'c1/master.json'; original = path.read_text()
            value = json.loads(original); value[field] = bad; write(path, value)
            self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0]); path.write_text(original)
        rst_capture(dest / 'c1/in.pcap', rst=False)
        self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0]); rst_capture(dest / 'c1/in.pcap')
        wire, timing = extracted(); timing['summary']['READ']['resp_len'] = [58]
        with patch.object(nc.vc.clrt, 'analyze', return_value=timing):
            self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0])
        scenario = json.loads((dest / 'scenario.json').read_text()); scenario['source_sha256'][next(iter(pins))] = '0' * 64
        write(dest / 'scenario.json', scenario)
        self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0])

    def test_missing_evidence_bad_observer_and_mapper_growth_fail(self):
        dest = self.root / 'missing'; artifacts(dest, self.cfg['hosts']['vision_run_dir'])
        pins = nc.source_pins(self.cfg['hosts']['vision_run_dir'])
        self.assertTrue(nc.archive_gate(self.cfg, dest, 1, pins)[0])
        (dest / 'c2/ss_kill.log').unlink()
        self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0])
        artifacts(dest, self.cfg['hosts']['vision_run_dir'])
        observer = json.loads((dest / 'c2/observer.json').read_text()); observer['commands'][1]['argv'] = ['ss', '-K']
        write(dest / 'c2/observer.json', observer)
        self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0])
        artifacts(dest, self.cfg['hosts']['vision_run_dir'])
        counters = json.loads((dest / 'after.json').read_text()); counters['regs']['acct']['Egress.acct.hi'] = [1]
        write(dest / 'after.json', counters)
        self.assertTrue(nc.archive_gate(self.cfg, dest, 0, pins)[0])


if __name__ == '__main__':
    unittest.main()
