#!/usr/bin/env python3
"""Capture native READ49/SBO37 and actual kernel RSTs on the baseline program.

Offline plan by default; --apply requires DEFENSE4_HW_AUTHORIZED=1. One guarded
vision_candidate.py series uses three same-port59400 incarnations with one
READ plus SBO each, padding off, RST grace1000ms and no pre-READ hook. This is
a replay archive, not a 20-READ timing qualification. Baseline setup, identity,
fixture, counters and all three independent restores reuse NativeReference.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import native_reference as nr
import vision_candidate as vc
from privileged_python import authorized_python

PORT = 59400
LEG_FILES = ('out.pcap', 'in.pcap', 'master.json', 'outstation.json', 'result.json', 'state.txt',
             'wire.json', 'timing.json', 'observer.json', 'verdict.json', 'ss_probe.log', 'ss_kill.log')


def native_rst_config(path, out):
    cfg = nr.native_config(path, out)
    cfg['evaluation'] = dict(purpose='native-rst-replay-archive', read_precision=False)
    cfg['trials'] = dict(reads_per_trial=1, trials_per_arm=3)
    cfg['traffic'].update(master_port_range=dict(first=PORT, last=PORT), close_grace_ms=1000)
    return cfg


def vision_tools():
    return [(name, HERE / name) for name in ('vision_candidate.py', 'token_window.py', 'snapshot_lifecycle.py')] + [
        (name, nr.HW_VEPA / name) for name in ('wire_check.py', 'clrt_check.py', 'checks.py')]


def source_pins(vision_dir):
    return {vision_dir + '/' + name: nr.cp.sha256_file(str(path)) for name, path in
            vision_tools() + [('vision_run.py', nr.HW_VEPA / 'vision_run.py')]}


def slot_rows():
    m, o = (int(ipaddress.ip_address(ip)) for ip in (vc.MASTER, vc.OUTSTATION))
    return [dict(key={'hdr.ip.src': o, 'hdr.ip.dst': m, 'hdr.tcp.sport': 20000, 'hdr.tcp.dport': PORT},
                 data=dict(idx=0, enable=0)),
            dict(key={'hdr.ip.src': m, 'hdr.ip.dst': o, 'hdr.tcp.sport': PORT, 'hdr.tcp.dport': 20000}, data=dict(idx=0))]


def read_json(path):
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError('expected JSON object: ' + str(path))
    return value


def archive_gate(cfg, dest, vision_rc, pins):
    dest, failures, observed = Path(dest), [], dict(connections=[])
    if vision_rc:
        failures.append('Vision native RST series failed')
    try:
        scenario = read_json(dest / 'scenario.json')
        expected = dict(ok=True, applied=True, master_port=PORT, padding=0, reads=1,
                        close_mode='rst', close_grace_ms=1000, read_pause_ms=25, pre_read_grace_ms=0,
                        tuple=[vc.MASTER, PORT, vc.OUTSTATION, 20000],
                        namespaces=[vc.NAMESPACE_M, vc.NAMESPACE_O], nic=vc.NIC)
        if any(type(scenario.get(k)) is not type(v) or scenario.get(k) != v for k, v in expected.items()):
            failures.append('wrong or missing native RST scenario controls')
        if scenario.get('source_sha256') != pins:
            failures.append('Vision scenario source pins do not match deployed helpers')
        connections = scenario.get('connections')
        if not isinstance(connections, list) or len(connections) != 3:
            raise ValueError('exactly three captured incarnations are required')
        for index, connection in enumerate(connections, 1):
            leg = dest / ('c%d' % index)
            leg_failures = []
            for name in LEG_FILES:
                if not (leg / name).is_file() or not (leg / name).stat().st_size:
                    leg_failures.append('missing or empty evidence: ' + name)
            verdict, observer = read_json(leg / 'verdict.json'), read_json(leg / 'observer.json')
            if not isinstance(connection, dict) or connection.get('name') != leg.name or \
                    connection.get('master_port') != PORT or connection.get('ok') is not True or \
                    connection.get('failures') != [] or verdict != connection:
                leg_failures.append('Vision per-leg verdict failed or disagrees with scenario')
            commands = observer.get('commands')
            response = observer.get('response') or {}
            if observer.get('ok') is not True or observer != connection.get('observer') or \
                    response.get('checksum_valid') is not True or response.get('dnp3_crc_valid') is not True or \
                    not isinstance(commands, list) or len(commands) != 2 or any(
                        command.get('namespace') != vc.NAMESPACE_M or command.get('rc') != 0 or
                        command.get('argv') != vc.ss_args(PORT, bool(index)) for index, command in enumerate(commands)):
                leg_failures.append('exact kernel socket probe/kill evidence missing')
            result = read_json(leg / 'result.json')
            if result != connection.get('result'):
                leg_failures.append('connection result disagrees with Vision verdict')
            # Retain the remote analyses before the independent local extraction.
            for name in ('wire', 'timing'):
                original, backup = leg / (name + '.json'), leg / (name + '_vision.json')
                if original.is_file() and not backup.exists():
                    backup.write_bytes(original.read_bytes())
            leg_failures += vc.evaluate(leg, PORT, 'rst', 0, result, rst_grace_ms=1000, reads=1, pre_read_grace_ms=0)
            observed['connections'].append(dict(name=leg.name, ok=not leg_failures, failures=leg_failures))
            failures += [leg.name + ': ' + failure for failure in leg_failures]
        for name in ('before', 'after'):
            snapshot = read_json(dest / (name + '.json'))
            nr.cp.runner.reg(snapshot, 'acct', '.lo'); nr.cp.runner.reg(snapshot, 'acct', '.hi'); nr.cp.runner.reg(snapshot, 'front')
        observed['growth_bytes'] = (nr.cp.runner.reg(snapshot, 'acct', '.lo') - nr.cp.runner.reg(snapshot, 'front')) & 0xffffffff
        observed['unacked'] = nr.cp.runner.reg(snapshot, 'acct', '.hi')
        if observed['growth_bytes'] or observed['unacked']:
            failures.append('native mapper growth/unacked must both be zero')
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError) as error:
        failures.append('archive evidence extraction failed: ' + str(error))
    return failures, observed


class NativeRstCapture(nr.NativeReference):
    def deploy_vision_capture(self):
        self.step('local', 'deploy native RST helper and analyzers', 'scp -q %s %s:%s/' %
                  (' '.join(nr.cp.q(path) for _, path in vision_tools()), self.cfg['hosts']['vision'], nr.cp.q(self.V)))
        result = self.step('vision', 'verify native RST helper and analyzers', 'sha256sum ' +
                           ' '.join(nr.cp.q(self.V + '/' + name) for name, _ in vision_tools()))
        if not self.rn.dry:
            got = {line.split()[1]: line.split()[0] for line in result.out.splitlines() if len(line.split()) == 2}
            for name, path in vision_tools():
                if got.get(self.V + '/' + name) != nr.cp.sha256_file(str(path)):
                    raise nr.cp.StepFailed('deployed native RST helper hash mismatch: ' + name)
        self.record['vision_source_pins'] = source_pins(self.V)
        self.step('vision', 'require fresh native RST label', 'test ! -e %s' % nr.cp.q(self.V + '/runs/' + self.run_id + '_native_rst'))

    def capture(self):
        dest, label = Path(self.root) / 'series', self.run_id + '_native_rst'
        if not self.rn.dry:
            dest.mkdir()
        started, error, vision = False, None, nr.cp.Result(1, '', 'traffic not started')
        try:
            result = self.step('switch', 'native RST slot padding off', self.hw_env(
                'python3 %s/switch_slot.py vepa --master-port %d --enable 0' % (nr.cp.q(self.R + '/aux'), PORT)))
            self.save(str(dest), 'slot.log', result)
            if not self.rn.dry:
                slot = nr.cp.runner.last_json(result.out)
                vc.write_json(dest / 'slot.json', slot)
                forwarding, conn = slot.get('Ingress.forwarding'), slot.get('Egress.conn') or []
                if slot.get('which') != 'vepa' or slot.get('no_forwarding') is not False or \
                        slot.get('enable') != 0 or slot.get('master_port') != PORT or not forwarding or len(forwarding) != 1 or \
                        forwarding[0]['key'] != {'ig.ingress_port': 9} or forwarding[0]['data'].get('port') != 9 or len(conn) != 2 or any(
                            not any(row.get('key') == expected['key'] and all(row.get('data', {}).get(k) == v
                                    for k, v in expected['data'].items()) for row in conn) for expected in slot_rows()):
                    raise nr.cp.StepFailed('slot readback must prove exact software tuple/padding-off reflection on dev9')
            if self.counter_snapshot(dest, 'before').rc:
                raise nr.cp.StepFailed('before counter snapshot failed')
            started = True
            cmd = authorized_python(self.V + '/vision_candidate.py',
                [label,'--master-port',PORT,'--padding',0,'--close-mode','rst',
                 '--rst-grace-ms',1000,'--reads',1,'--pre-read-grace-ms',0,'--apply'])
            vision = self.step('vision', 'native RST traffic + capture', cmd, check=False, timeout=600)
            self.save(str(dest), 'vision_run.out', vision)
        except Exception as failure:
            error = str(failure)
        finally:
            after = self.counter_snapshot(dest, 'after')
            if started:
                self.collect(label, 'native RST series archive', 'local', 'scp -qr %s:%s/runs/%s/* %s/' %
                             (self.cfg['hosts']['vision'], nr.cp.q(self.V), label, nr.cp.q(dest)))
        failures, observed = ([], {}) if self.rn.dry else archive_gate(self.cfg, dest, vision.rc, self.record['vision_source_pins'])
        if error:
            failures.append(error)
        if after.rc:
            failures.append('after counter snapshot failed')
        failures += ['collection failed: ' + entry['what'] for entry in self.record['collections'] if entry['unit'] == label and not entry['ok']]
        self.record['series'] = dict(label=label, master_port=PORT, reads_per_incarnation=1,
                                    ok=not failures, failures=failures, **observed)
        if not self.rn.dry:
            vc.write_json(dest / 'archive_verdict.json', self.record['series'])

    def execute(self):
        dry = self.rn.dry
        if not dry and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('native RST capture requires DEFENSE4_HW_AUTHORIZED=1')
        if not dry and os.path.exists(self.root):
            raise ValueError('evidence directory exists; use a fresh run-id')
        if not dry:
            os.makedirs(self.root)
        failed = False
        try:
            self.deploy_switch()
            self.switch_toolkit()
            self.admitted = True
            self.vision_identity()
            self.deploy_vision_capture()
            self.vision_setup()
            self.set_fixture('separate_ack', 5)
            self.capture()
        except Exception as error:
            failed = True
            self.record['failure'] = str(error)
        finally:
            restore_ok = self.restore()
            self.record.update(ok=not failed and restore_ok and self.record.get('series', {}).get('ok') is True,
                               program=nr.PROGRAM, composite_installed=False, effective_config=self.cfg,
                               config_sha256=self.config_sha256, config_file_sha256=self.config_file_sha256)
            if not dry:
                root = Path(self.root)
                vc.write_json(root / 'effective_config.json', self.cfg)
                paths = [Path(__file__), Path(nr.__file__), nr.HW_VEPA / 'campaign.py'] + [path for _, path in
                         vision_tools() + [('vision_run.py', nr.HW_VEPA / 'vision_run.py'), ('loss.py', nr.HW_VEPA / 'loss.py')] + nr.tools()]
                self.record['source_hashes'] = {str(path): nr.cp.sha256_file(str(path)) for path in paths}
                self.record['hashes'] = {str(path.relative_to(root)): nr.cp.sha256_file(str(path)) for path in
                                        root.rglob('*') if path.is_file() and path.name != 'native_rst_capture.json'}
                vc.write_json(root / 'native_rst_capture.json', self.record)
        return 0 if self.record['ok'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=nr.DEFAULT_CONFIG)
    parser.add_argument('--out', type=Path, default=HERE / 'native_rst_runs')
    parser.add_argument('--run-id', default='native_rst_capture_01')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('--apply requires DEFENSE4_HW_AUTHORIZED=1')
    cfg = native_rst_config(args.config, args.out)
    runner = nr.cp.ShellRunner(cfg['hosts']) if args.apply else nr.cp.DryRunner()
    campaign = NativeRstCapture(cfg, runner, args.run_id, config_path=str(args.config))
    rc = campaign.execute()
    print(json.dumps(campaign.record, indent=2))
    return rc


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.stderr.write('native RST capture refused: %s\n' % error)
        sys.exit(2)
