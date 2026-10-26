#!/usr/bin/env python3
"""Native SEL-751 capture through the existing production program and guarded wrapper."""
import argparse
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import campaign as cp
import endpoint_profiles


class RelayNative(cp.Campaign):
    def execute(self):
        endpoint_profiles.validate_baseline(self.cfg)
        if not self.rn.dry and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('native relay baseline requires hardware authorization')
        if not self.rn.dry:
            os.makedirs(self.root)  # exclusive, as required by guarded_block
        error = None
        try:
            self.deploy_switch()
            self.switch_toolkit()  # observe program and snapshot before writes
            prod = self.cfg['production']
            observed = self.step('switch', 'verify running production conf identity',
                                 'python3 %s/aux/observe_program.py' % cp.q(self.R))
            if not self.rn.dry and cp.runner.last_json(observed.out).get('conf') != prod['conf']:
                raise cp.StepFailed('running production conf path differs from frozen baseline')
            for key, path in (('launch_sha256', prod['launch_script']), ('conf_sha256', prod['conf'])):
                observed = self.step('switch', 'verify production ' + key, 'sha256sum ' + cp.q(path))
                self.check_hash(observed, prod[key], path)
            for path, digest in prod['artifact_sha256'].items():
                observed = self.step('switch', 'verify production artifact ' + path, 'sha256sum ' + cp.q(path))
                self.check_hash(observed, digest, path)
            self.vision_identity()
            self.vision_setup()
            self.switch_touched = True
            port = self.cfg['traffic']['master_port_range']['first']
            out = self.step('switch', 'native physical relay slot, padding disabled', self.hw_env(
                'python3 %s/aux/switch_slot.py relay --master-port %d --enable 0 --passthrough' % (cp.q(self.R), port)))
            if not self.rn.dry:
                slot = cp.runner.last_json(out.out)
                if slot.get('which') != 'relay' or slot.get('enable') != 0 or slot.get('master_port') != port:
                    raise cp.StepFailed('native physical relay slot identity mismatch')
                forwarding = slot.get('Ingress.forwarding') or []
                routes = {(row['key'].get('ig.ingress_port'), row['data'].get('port')) for row in forwarding}
                if routes != {(9, 64), (64, 9)} or slot.get('passthrough') is not True or \
                        slot.get('Egress.conn') != [] or slot.get('Egress.odd_ip_t') != []:
                    raise cp.StepFailed('slot does not prove dev9/dev64 pure forwarding without mapper/padding entries')
                (Path(self.root) / 'slot.json').write_text(json.dumps(slot, indent=2) + '\n')
            label = self.run_id + '_native'
            event_clear = self.cfg['traffic'].get('event_clear') is True
            cmd = cp.RELAY_PYTHON + (' %s/vision_run.py run %s --master-port %d '
                   '--reads %d --range 8 --gap-ms 0 --qualify-capture' %
                   (cp.q(self.V), label, port, self.cfg['trials']['reads_per_trial'])) + self.endpoint_control_args()
            if event_clear:   # one-time class-2 poll + CONFIRM (Philip, 2026-10-25); READ/CONFIRM only
                cmd += ' --event-clear'
            traffic = self.step('vision', 'physical relay native master and capture', cmd, check=False)
            self.record['traffic'] = dict(command=cmd, rc=traffic.rc, stdout=traffic.out, stderr=traffic.err)
            self.save(self.root, 'vision_run.out', traffic)
            if not self.rn.dry:
                (Path(self.root) / 'traffic_result.json').write_text(json.dumps(self.record['traffic'], indent=2) + '\n')
            self.collect(label, 'native master evidence', 'local', 'scp -qr %s:%s/runs/%s/* %s/' %
                         (self.cfg['hosts']['vision'], cp.q(self.V), label, cp.q(self.root)))
            if event_clear:
                if not self.rn.dry:
                    cleared = json.loads((Path(self.root) / 'event_clear.json').read_text())
                    if traffic.rc or cleared.get('ok') is not True or not set(cleared.get('functions_sent') or [9]) <= {0, 1}:
                        raise cp.StepFailed('relay class-2 event clear failed or sent a function other than READ/CONFIRM')
                return
            checked = self.step('local', 'native relay wire and complete-response evidence',
                                '%s %s %s --master-port %d --reads %d --sbo %d --read-schedule %s' % (cp.runner.PY,
                                cp.q(ARCH / 'protocol/hw_vepa/relay_check.py'), cp.q(self.root), port,
                                self.cfg['trials']['reads_per_trial'],
                                cp.checks.sbo_count(self.cfg['traffic']), self.cfg['traffic']['read_schedule']), check=False)
            if traffic.rc or checked.rc:
                raise cp.StepFailed('native master/capture evidence failed')
        except Exception as exc:
            error = str(exc)
        finally:
            restored = self.restore()
            self.record.update(ok=not error and restored, failure=error, endpoint_profile='sel751',
                               purpose='relay-native-baseline', candidate_loaded=False,
                               observation_scope='master NIC TX/RX; no two-sided switch timing claim')
            if not self.rn.dry:
                (Path(self.root) / 'campaign_run.json').write_text(json.dumps(self.record, indent=2) + '\n')
        return 0 if self.record['ok'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'run'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    cfg = json.loads(Path(args.config).read_text())
    endpoint_profiles.validate_baseline(cfg)
    if args.mode == 'run' and not (args.apply or args.dry_run):
        parser.error('run requires --apply or --dry-run')
    runner = cp.ShellRunner(cfg['hosts']) if args.mode == 'run' and args.apply and not args.dry_run else cp.DryRunner()
    run = RelayNative(cfg, runner, args.run_id, config_path=args.config)
    code = run.execute()
    print(json.dumps(run.record, indent=2))
    return code


if __name__ == '__main__':
    sys.exit(main())
