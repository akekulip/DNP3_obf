#!/usr/bin/env python3
"""Plan/run three native software-endpoint references on existing case4_response_path.

Default: offline command plan. --apply also requires DEFENSE4_HW_AUTHORIZED=1.
The baseline program stays running; only connection/forwarding rows are changed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
HW_VEPA = HERE.parents[3] / 'protocol/hw_vepa'
sys.path.insert(0, str(HW_VEPA))
import campaign as cp

PROGRAM = 'case4_response_path'
VISION_DIR = '/home/decps/pad58b_rearm_controls_20261012'
DEFAULT_CONFIG = HW_VEPA / 'config/fourarm_separate_ack_14892.json'
REQUIRED = ('out.pcap', 'in.pcap', 'master.json', 'outstation.json', 'result.json', 'state.txt',
            'wire.json', 'timing.json', 'before.json', 'after.json')


def native_config(path, out):
    cfg = json.loads(Path(path).read_text())
    if cfg['production']['program'] != PROGRAM or cfg['hosts']['vision_run_dir'] != VISION_DIR:
        raise ValueError('native reference requires baseline program and pinned controls endpoint directory')
    ep = cfg['endpoints']
    if (ep['master_ip'], ep['outstation_ip'], ep['outstation_port']) != ('192.168.10.61', '192.168.10.62', 20000):
        raise ValueError('native reference accepts only the software endpoint pair')
    for field in ('binary_sha256', 'lib_sha256'):
        if not re.fullmatch('[0-9a-f]{64}', cfg['endpoint'].get(field, '')):
            raise ValueError('missing endpoint pin: %s' % field)
    exp = cfg['expectations']
    if exp['common']['read_points'] != 23 or exp['padding']['0']['read_resp_len'] != [49] or exp['padding']['0']['sbo_resp_len'] != [37]:
        raise ValueError('native reference requires 23 points and native READ49/SBO37 expectations')
    cfg['program'] = PROGRAM
    cfg['arms'] = [dict(name='native', T=0, padding=0, build=None)]
    cfg['builds'] = {}                         # no N/T composite is selected, copied, or installed
    cfg['evaluation'] = dict(purpose='native-reference')
    cfg['fixture'].update(modes=['separate_ack'], delay_ms=5, jitter_ms=0)
    cfg['trials'] = dict(reads_per_trial=20, trials_per_arm=3)
    cfg['traffic'].update(master_port_range=dict(first=59400, last=59402), range=8, gap_ms=0,
                          start_delay_ms=0, read_pause_ms=25, run_sbo=True, close_grace_ms=0)
    cfg['seeds']['rng_seed'] = 12345
    cfg['evidence_dir'] = str(Path(out).resolve())
    return cfg


def tools():
    names = ('observe_program.py', 'live_snapshot.py', 'switch_slot.py', 'response_path_cp.py')
    return [(name, Path(path)) for path, name in cp.switch_tools() if name in names] + [
        ('switch_counters.py', HW_VEPA / 'switch_counters.py')]


def gate(cfg, dest, vision_rc, wire_rc, timing_rc):
    dest = Path(dest)
    present = {name: (dest / name).is_file() and (dest / name).stat().st_size > 0 for name in REQUIRED}
    ev = {}
    for name in ('master', 'outstation', 'wire', 'timing', 'before', 'after'):
        try:
            data = json.loads((dest / (name + '.json')).read_text())
            ev[name] = data if isinstance(data, dict) else None
        except (OSError, ValueError):
            ev[name] = None
    try:
        result = json.loads((dest / 'result.json').read_text())
    except (OSError, ValueError):
        result = {}
    _, failures = cp.runner.evaluate(False, vision_rc, result, wire_rc, timing_rc, present)
    failures += cp.checks.application_checks(cfg['expectations'], 0, 20, ev, run_sbo=True)
    controls = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=0)
    if not isinstance(result, dict) or result.get('endpoint_controls') != controls:
        failures.append('missing or wrong observed endpoint controls')
    master = ev.get('master') or {}
    if any(type(master.get(key)) is not type(value) or master.get(key) != value for key, value in controls.items()):
        failures.append('missing or wrong master effective endpoint controls')
    if master.get('application_calls') != 1:
        failures.append('master application_calls must equal 1')
    wire = ev.get('wire') or {}
    for key in ('unmatched_returned', 'unmatched_sent', 'duplicate_returned'):
        if wire.get(key) != []:
            failures.append('wire %s is nonzero or missing' % key)
    summary = (ev.get('timing') or {}).get('summary')
    rd = summary.get('READ') if isinstance(summary, dict) else None
    rd = rd if isinstance(rd, dict) else {}
    piggyback = rd.get('piggyback')
    fraction = piggyback / 20 if isinstance(piggyback, int) and not isinstance(piggyback, bool) else 2
    if not 0 <= fraction <= 0.05:
        failures.append('separate ACK fixture piggyback fraction outside [0, 0.05]')
    observation = {'piggyback_fraction': fraction}
    try:
        for snapshot in (ev['before'], ev['after']):
            cp.runner.reg(snapshot, 'acct', '.lo'); cp.runner.reg(snapshot, 'acct', '.hi'); cp.runner.reg(snapshot, 'front')
        after = ev['after']
        observation['growth_bytes'] = (cp.runner.reg(after, 'acct', '.lo') - cp.runner.reg(after, 'front')) & 0xffffffff
        observation['unacked'] = cp.runner.reg(after, 'acct', '.hi')
        if observation['growth_bytes'] != 0 or observation['unacked'] != 0:
            failures.append('native mapper growth/unacked must both be zero')
    except (KeyError, IndexError, TypeError, ValueError):
        failures.append('missing or malformed mapper counter evidence')
    return failures, observation


class NativeReference(cp.Campaign):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not re.fullmatch('[A-Za-z0-9_]+', self.run_id):
            raise ValueError('run-id must contain only letters, numbers and underscores')
        self.admitted = False
        self.record['blocks'] = []

    def step(self, where, label, cmd, cwd=None, check=True, timeout=3600):
        result = super().step(where, label, cmd, cwd=cwd, check=False, timeout=timeout)
        steps = self.record.setdefault('steps', [])
        steps.append(dict(where=where, label=label, command=cmd, rc=result.rc))
        self.save(self.root, 'step_%03d.log' % (len(steps) - 1), result)
        if check and result.rc:
            raise cp.StepFailed('%s failed (rc %d): %s' % (label, result.rc, (result.err or result.out)[-400:]), result)
        return result

    def deploy_switch(self):
        aux, host = self.R + '/aux', self.cfg['hosts']['switch']
        self.step('switch', 'make baseline tool directories', 'mkdir -p %s %s/snap' % (cp.q(aux), cp.q(self.R)))
        self.step('local', 'copy baseline tools only', 'scp -q %s %s:%s/' %
                  (' '.join(cp.q(path) for _, path in tools()), host, cp.q(aux)))
        result = self.step('switch', 'verify deployed baseline tools', 'sha256sum ' +
                           ' '.join(cp.q(aux + '/' + name) for name, _ in tools()))
        if not self.rn.dry:
            got = {line.split()[1]: line.split()[0] for line in result.out.splitlines() if len(line.split()) == 2}
            for name, path in tools():
                if got.get(aux + '/' + name) != cp.sha256_file(str(path)):
                    raise cp.StepFailed('deployed baseline tool hash mismatch: %s' % name)

    def counter_snapshot(self, dest, name):
        result = self.step('switch', 'native mapper %s counters' % name,
                           'python3 %s/switch_counters.py' % cp.q(self.R + '/aux'), check=False)
        self.save(str(dest), name + '.log', result)
        if not self.rn.dry and result.rc == 0:
            try:
                (dest / (name + '.json')).write_text(json.dumps(cp.runner.last_json(result.out), indent=2) + '\n')
            except (ValueError, IndexError):
                pass
        return result

    def block(self, index, port):
        label = '%s_native_t%d' % (self.run_id, index)
        dest = Path(self.root) / label
        if not self.rn.dry:
            dest.mkdir()
        block = dict(label=label, master_port=port, reads=20, start_seed=12345 + index, ok=False, failures=[])
        self.record['blocks'].append(block)
        vision, error = cp.Result(1, '', 'traffic not started'), None
        started = False
        try:
            result = self.step('switch', 'native slot padding off', self.hw_env(
                'python3 %s/switch_slot.py vepa --master-port %d --enable 0' % (cp.q(self.R + '/aux'), port)))
            self.save(str(dest), 'slot.log', result)
            if not self.rn.dry:
                slot = cp.runner.last_json(result.out)
                (dest / 'slot.json').write_text(json.dumps(slot, indent=2) + '\n')
                forwarding = slot.get('Ingress.forwarding')
                conn = slot.get('Egress.conn') or []
                if slot.get('which') != 'vepa' or slot.get('no_forwarding') is not False or \
                        slot.get('enable') != 0 or slot.get('master_port') != port or not forwarding or len(forwarding) != 1 or \
                        forwarding[0]['key'].get('ig.ingress_port') != 9 or forwarding[0]['data'].get('port') != 9 or \
                        not any(row['data'].get('enable') == 0 for row in conn):
                    raise cp.StepFailed('slot readback does not prove padding-off reflection on dev 9')
            before = self.counter_snapshot(dest, 'before')
            if before.rc:
                raise cp.StepFailed('before counter snapshot failed')
            started = True
            cmd = ('sudo python3 %s run %s --master-port %d --reads 20 --range 8 --gap-ms 0 '
                   '--start-delay-ms 0 --start-seed %d' %
                   (cp.q(self.V + '/vision_run.py'), label, port, 12345 + index)) + self.endpoint_control_args()
            vision = self.step('vision', 'native traffic + capture', cmd, check=False)
            self.save(str(dest), 'vision_run.out', vision)
        except (cp.StepFailed, ValueError, OSError, KeyError, IndexError) as failure:
            error = str(failure)
        finally:
            after = self.counter_snapshot(dest, 'after')
            if started:
                self.collect(label, 'native endpoint evidence', 'local', 'scp -qr %s:%s/runs/%s/* %s/' %
                             (self.cfg['hosts']['vision'], cp.q(self.V), label, cp.q(dest)))
        results = []
        for script, filename in (('wire_check.py', 'wire.json'), ('clrt_check.py', 'timing.json')):
            result = self.step('local', 'native ' + script, '%s %s %s %s --json %s' %
                               (cp.runner.PY, cp.q(HW_VEPA / script), cp.q(dest / 'out.pcap'),
                                cp.q(dest / 'in.pcap'), cp.q(dest / filename)), check=False)
            self.save(str(dest), script + '.log', result)
            results.append(result)
        if not self.rn.dry:
            failures, observation = gate(self.cfg, dest, vision.rc, results[0].rc, results[1].rc)
            if error:
                failures.append(error)
            if after.rc:
                failures.append('after counter snapshot failed')
            failures += ['collection failed: ' + c['what'] for c in self.record['collections'] if c['unit'] == label and not c['ok']]
            block.update(ok=not failures, failures=failures, observed=observation)
            (dest / 'verdict.json').write_text(json.dumps(block, indent=2) + '\n')
        else:
            block['ok'] = True

    def restore(self):
        if not self.admitted:
            return True                         # wrong program: no row/profile mutation was authorized
        ping, aux = self.cfg['production']['ping'], self.R + '/aux'
        actions = [('switch', 'restore relay slot', self.hw_env('python3 %s/switch_slot.py relay' % cp.q(aux))),
                   ('vision', 'restore Vision', 'sudo python3 %s/vision_run.py restore' % cp.q(self.V)),
                   ('vision', 'restore ping', 'ping -c %d -I %s %s' % (ping['count'], cp.q(ping['src']), cp.q(ping['dst'])))]
        for where, label, cmd in actions:
            try:
                result = self.rn.run(where, cmd, timeout=1800, label=label)
            except Exception as error:
                result = cp.Result(1, '', str(error))
            self.save(self.root, label.replace(' ', '_') + '.log', result)
            self.record['restore'].append(dict(step=label, rc=result.rc, ok=result.rc == 0))
        return all(entry['ok'] for entry in self.record['restore'])

    def execute(self):
        dry = self.rn.dry
        if not dry and isinstance(self.rn, cp.ShellRunner) and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('native reference requires DEFENSE4_HW_AUTHORIZED=1')
        if not dry and os.path.exists(self.root):
            raise ValueError('evidence directory exists; use a fresh run-id')
        if not dry:
            os.makedirs(self.root)
        failed = False
        try:
            self.deploy_switch()
            self.switch_toolkit()                # refuses wrong program before row/profile changes
            self.admitted = True
            self.vision_identity()              # derives paths from the configured new endpoint directory
            self.vision_setup()
            self.set_fixture('separate_ack', 5)
            for index, port in enumerate(range(59400, 59403)):
                self.block(index, port)
        except Exception as error:
            failed = True
            self.record['failure'] = str(error)
        finally:
            restore_ok = self.restore()
            self.record['ok'] = not failed and restore_ok and len(self.record['blocks']) == 3 and all(
                block['ok'] for block in self.record['blocks'])
            self.record.update(program=PROGRAM, composite_installed=False, effective_config=self.cfg,
                               config_sha256=self.config_sha256, config_file_sha256=self.config_file_sha256)
            if not dry:
                root = Path(self.root)
                (root / 'effective_config.json').write_text(json.dumps(self.cfg, indent=2) + '\n')
                self.record['source_hashes'] = {str(path): cp.sha256_file(str(path)) for path in
                    [Path(__file__), HW_VEPA / 'campaign.py', HW_VEPA / 'checks.py', HW_VEPA / 'vision_run.py',
                     HW_VEPA / 'wire_check.py', HW_VEPA / 'clrt_check.py'] + [path for _, path in tools()]}
                self.record['hashes'] = {str(path.relative_to(root)): cp.sha256_file(str(path)) for path in
                                        root.rglob('*') if path.is_file() and path.name != 'native_reference.json'}
                (root / 'native_reference.json').write_text(json.dumps(self.record, indent=2) + '\n')
        return 0 if self.record['ok'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--out', type=Path, default=HERE / 'native_runs')
    parser.add_argument('--run-id', default='native_reference_01')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('--apply requires DEFENSE4_HW_AUTHORIZED=1')
    cfg = native_config(args.config, args.out)
    run = cp.ShellRunner(cfg['hosts']) if args.apply else cp.DryRunner()
    reference = NativeReference(cfg, run, args.run_id, config_path=str(args.config))
    rc = reference.execute()
    print(json.dumps(reference.record, indent=2))
    return rc


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.stderr.write('native reference refused: %s\n' % error)
        sys.exit(2)
