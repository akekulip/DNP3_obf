#!/usr/bin/env python3
"""Step 4b, the bounded reset-interleaving check: one guarded block on the frozen candidate (run_block TOOL).

  bash run_block_frozen.sh FREEZE.json candidate_interleave CONFIG RUN_ID --arms combined --fixtures separate_ack

The base campaign's flow is unchanged (cold swap, ports, install of the config's connection rows, T, snapshots,
teardown, collection; restore_verify by run_block.sh). Only three steps differ:
- deploy: generates the interleave plan (interleave_probe.build_interleave_plan) for the config's endpoints, keeps
  a copy in the run evidence, and puts it on Vision with a sha256 check, together with the injector and its
  libraries;
- traffic: vision_contention.py --plan --run-dir runs/<label> --apply, in place of the endpoint workload. It sends
  both probe sides from one raw socket on addresses no Vision interface owns and captures out/in;
- verdict: interleave_probe.judge_interleave over the collected captures and the before/after counter snapshots.

The config must name the probe tuple, so the installed rows cover it: endpoints.master_ip / outstation_ip outside
every Vision address (vision_contention refuses otherwise), with one master port. Delivery and reconnect are judged
at every point. PASS also needs count_busy[5] > 0; a block without a restart is NOT_EXERCISED, never a pass.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'protocol' / 'hw_vepa'))
sys.path.insert(0, str(HERE))
import candidate_campaign  # noqa: E402
import campaign as base  # noqa: E402
import contention_probe as cprobe  # noqa: E402
import interleave_probe  # noqa: E402
from privileged_python import authorized_python  # noqa: E402

INTERFACE = 'enp59s0f0np0'                     # vision_contention.INTERFACE: Vision parent NIC, switch dev 9
VISION_EXTRA = {
    'vision_contention.py': HERE / 'vision_contention.py',
    'contention_probe.py': HERE / 'contention_probe.py',
    'wire_check.py': ARCH / 'protocol' / 'hw_vepa' / 'wire_check.py',
}
PLAN_NAME = 'interleave_plan.json'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def plan_for(cfg):
    ep = cfg['endpoints']
    rng = cfg['traffic']['master_port_range']
    if rng['first'] != rng['last']:
        raise ValueError('the interleave block uses one master port (range %r)' % rng)
    probe = cfg.get('interleave') or {}
    endpoints = cprobe.Endpoints(ep['master_ip'], ep['outstation_ip'], rng['first'], ep['outstation_port'],
                                 probe.get('master_mac', '02:00:00:00:00:61'),
                                 probe.get('outstation_mac', '02:00:00:00:00:62'),
                                 probe.get('next_hop_mac', '02:00:00:00:00:09'))
    image_len = next(iter(cfg['builds'].values())).get('image_len', 61)
    return interleave_probe.build_interleave_plan(endpoints, image_len=image_len)


class CandidateInterleaveCampaign(candidate_campaign.CandidateCampaign):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.plan = plan_for(self.cfg)
        self.plan_bytes = (json.dumps(self.plan, indent=1) + '\n').encode()

    def vision_identity(self):
        super().vision_identity()
        host = self.cfg['hosts']['vision']
        local = Path(self.root) / PLAN_NAME
        if not self.rn.dry:
            os.makedirs(self.root, exist_ok=True)
            local.write_bytes(self.plan_bytes)
        files = dict(VISION_EXTRA, **{PLAN_NAME: local})
        identity = {name: (sha256(self.plan_bytes) if name == PLAN_NAME else base.sha256_file(path))
                    for name, path in files.items()}
        self.step('local', 'deploy the interleave injector, its libraries and the plan to Vision',
                  'scp -q %s %s:%s/' % (' '.join(base.q(str(p)) for p in files.values()), host, self.V))
        result = self.step('vision', 'verify interleave helper and plan identity',
                           'sha256sum ' + ' '.join('%s/%s' % (self.V, name) for name in files))
        if not self.rn.dry:
            got = {line.split()[1].rsplit('/', 1)[-1]: line.split()[0]
                   for line in result.out.splitlines() if len(line.split()) == 2}
            for name, want in identity.items():
                if got.get(name) != want:
                    raise base.StepFailed('interleave Vision helper identity mismatch: %s' % name)
        self.record['interleave_identity'] = identity

    def interleave_vision_cmd(self, label, *_args, **_kwargs):
        return authorized_python(base.runner.V_RUN + '/vision_contention.py',
                                 ['--plan', base.runner.V_RUN + '/' + PLAN_NAME,
                                  '--run-dir', base.runner.V_RUN + '/runs/' + label,
                                  '--interface', INTERFACE, '--apply'])

    def run_unit(self, unit, port):
        old = base.runner.vision_cmd
        base.runner.vision_cmd = self.interleave_vision_cmd
        try:
            return super().run_unit(unit, port)
        finally:
            base.runner.vision_cmd = old

    def endpoint_control_args(self):
        return ''

    def qualify_capture_arg(self, arm):
        return ''

    def verdict(self, trial, rec, label, dest, v, arm, fixture):
        """The gate. Any verdict other than PASS fails the block, as the base verdict does (StepFailed after
        trial.json). Code review: setting trial['ok'] alone left run_block's rc at 0."""
        if self.rn.dry:                       # plan mode: nothing was sent, so nothing is judged
            trial['interleave_verdict'], trial['ok'] = 'DRY', True
            return
        snaps = Path(dest) / 'snapshots'
        try:
            before = json.loads((snaps / ('%s_before.json' % label)).read_text())
            after = json.loads((snaps / ('%s_after.json' % label)).read_text())
            inject_path = Path(dest) / 'inject.json'
            inject = json.loads(inject_path.read_text()) if inject_path.is_file() else None
            result = interleave_probe.judge_interleave(self.plan, str(Path(dest) / 'out.pcap'),
                                                       str(Path(dest) / 'in.pcap'), before, after, inject=inject,
                                                       vision_rc=getattr(v, 'rc', None))
        except (OSError, ValueError, TypeError, AttributeError) as e:
            result = dict(verdict='INVALID', reason='%s: %s' % (type(e).__name__, e))
        (Path(dest) / 'interleave.json').write_text(json.dumps(result, indent=1) + '\n')
        trial['interleave_verdict'] = result['verdict']
        trial['restarts'] = result.get('restarts')
        trial['failures'] += result.get('failures', []) or ([result['reason']] if result.get('reason') else [])
        if result['verdict'] == 'NOT_EXERCISED':
            trial['failures'].append('restart path not exercised (count_busy[5] did not rise)')
        trial['ok'] = result['verdict'] == 'PASS'
        json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
        if not trial['ok']:
            raise base.StepFailed('%s interleave %s: %s' % (label, result['verdict'], '; '.join(trial['failures'])))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('mode', choices=('validate', 'plan', 'run'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--run-id', default='candidate_interleave_01')
    parser.add_argument('--arms', default='combined')
    parser.add_argument('--fixtures', default='separate_ack')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    cfg = base.load_config(args.config)
    arms = args.arms.split(',') if args.arms else None
    fixtures = args.fixtures.split(',') if args.fixtures else None
    runner = base.DryRunner() if args.mode == 'plan' or args.dry_run or not args.apply else base.ShellRunner(cfg['hosts'])
    campaign = CandidateInterleaveCampaign(cfg, runner, args.run_id, arms=arms, fixtures=fixtures,
                                           config_path=args.config)
    if args.mode == 'validate':
        errs = base.check_bindings(cfg, campaign.arms)
        if errs:
            sys.exit('refusing: ' + '; '.join(errs))
        print('candidate interleave config OK: %d points, %d frames' % (len(campaign.plan['points']),
                                                                        len(campaign.plan['schedule'])))
        return 0
    if args.mode == 'run' and not args.apply and not args.dry_run:
        sys.exit('run requires --apply or --dry-run')
    return campaign.execute()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.stderr.write('candidate interleave refused: %s\n' % error)
        sys.exit(2)
