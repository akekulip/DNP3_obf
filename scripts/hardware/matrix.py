#!/usr/bin/env python3
"""Prepare one current 10-block, 2,440-exchange matrix; run it through the existing supervisor."""
import argparse
import copy
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(HERE.parent / 'checks')]
import campaign_base
import evaluation_campaign
import freeze_gate
import relay_check


DEFINITIONS = {'qualification': dict(file='lab.json', blocks=10, exchanges=2440),
               'evaluation': dict(file='lab_eval.json', blocks=64, exchanges=49408)}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expand_evaluation(spec):
    """Repeat the reference block per D: D cycles block by block, arm order rotates per repetition."""
    base = json.loads((HERE / spec['base']).read_text())
    template = next(block for block in base['blocks'] if block['id'] == spec['template'])
    arms, d_values, blocks = template['arms'], spec['d_ms'], []
    for index in range(len(d_values) * spec['blocks_per_d']):
        d_ms, repetition = d_values[index % len(d_values)], index // len(d_values)
        block = copy.deepcopy(template)
        block['id'] = 'e%02d_d%d_r%02d' % (index + 1, d_ms, repetition + 1)
        block['config']['timing_params_ns']['gap'] = d_ms * 1000000
        shift = repetition % len(arms)
        block['arms'] = copy.deepcopy(arms[shift:] + arms[:shift])
        blocks.append(block)
    return dict(common=base['common'], blocks=blocks)


def load_definition(name):
    spec = DEFINITIONS[name]
    definition = json.loads((HERE / spec['file']).read_text())
    if name == 'evaluation':
        definition = expand_evaluation(definition)
    return definition, spec


def prepare(build, native, output, campaign_id, definition='qualification'):
    build, native, output = map(lambda p: Path(p).resolve(), (build, native, output))
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', campaign_id):
        raise ValueError('campaign ID must be a safe bounded path component')
    if output.exists():
        raise ValueError('matrix evidence directory already exists; use a new ID')
    definition, spec = load_definition(definition)
    manifest = json.loads((build / 'compile_local/manifest.json').read_text())
    source_hash = sha(build / 'response_only.p4')
    output.mkdir(parents=True)
    configs = output / 'configs'
    configs.mkdir()
    steps, count, paths = [], 0, []
    for block in definition['blocks']:
        if set(block['config']) & {'endpoints','endpoint','ports_map'}:
            raise ValueError('matrix blocks cannot override the fixed reciprocal IP/port binding')
        cfg = copy.deepcopy(definition['common'])
        cfg.update(block['config'])
        cfg['traffic'] = block['traffic']
        cfg['evidence_dir'] = 'results/hardware/blocks'
        cfg['arms'] = [dict(arm, build='current') for arm in block['arms']]
        cfg['builds'] = {'current': dict(
            profile='sel751_current', endpoint_profile='sel751', image_len=60,
            control_padding=True, control_timed=True, lifecycle_rearm=True, mirror_fix=True,
            switch_telemetry=False, piggyback_bound=False, timing_contract=cfg['timing_contract'],
            source_sha256=source_hash, read_images=dict(mixed=141, integrity=158),
            read_padding=dict(mixed=26, integrity=4), allowed_loop_octet_gap={},
            manifest=str((build / 'compile_local/manifest.json').relative_to(ROOT)),
            out_dir=str((build / 'compile_local/out').relative_to(ROOT)),
            hashes={name: manifest['artifact_sha256'][name] for name in campaign_base.BUILD_HASHED},
            sde='/home/decps/Downloads/bf-sde-9.13.2', pcie='0000:04:00.0')}
        cfg['wire_profile'] = dict(tcp_profile='sel751_ts', ipv4_header_octets=20, tcp_header_octets=32,
                                   native_observation=str(native.relative_to(ROOT)),
                                   native_observation_sha256=sha(native))
        cfg['ctl_timing_identity'] = dict(source_sha256=source_hash,
            switch_compile=dict(out_dir=cfg['builds']['current']['out_dir']))
        path = configs / (block['id'] + '.json')
        path.write_text(json.dumps(cfg, indent=2) + '\n')
        campaign_base.load_config(path)
        run_id = campaign_id + '_' + block['id']
        argv = ['bash', str(HERE / 'run_block_frozen.sh'), str(output / 'freeze.json'),
                block['tool'], str(path), run_id] + block['arguments']
        multiplier = 3 if block['tool'] == 'persistence' or '--scenario' in block['arguments'] else 1
        if '--loss' in block['arguments']:
            multiplier = len(cfg['loss']['presets'][block['arguments'][1]])
        exchanges = len(cfg['arms']) * multiplier * (cfg['trials']['reads_per_trial'] +
                                                     2 * cfg['traffic'].get('sbo_cycles', 1))
        count += exchanges
        steps.append(dict(id=block['id'], kind='block', argv=argv, expected_exchanges=exchanges,
                          run_root=str(ROOT / cfg['evidence_dir'] / run_id)))
        paths.append(path)
    if len(steps) != spec['blocks'] or count != spec['exchanges']:
        raise ValueError('fixed matrix denominator changed: %d blocks, %d exchanges' % (len(steps), count))
    record = dict(campaign_id=campaign_id, evidence_kind='hardware', expected_exchanges=count, steps=steps)
    evaluation_campaign.validate_manifest(record)
    target = output / 'manifest.json'
    target.write_text(json.dumps(record, indent=2) + '\n')
    return target


def native_probe(build, output, label, port, apply=False):
    """The existing native READ preflight, through the same deployed producer and offload restoration."""
    build, output = Path(build).resolve(), Path(output).resolve()
    if output.exists() or not re.fullmatch(r'[A-Za-z0-9_]+', label) or not 1024 <= port <= 65535:
        raise ValueError('native preflight needs a fresh output, safe label and fixed master port')
    if apply:
        if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('native hardware preflight requires DEFENSE4_HW_AUTHORIZED=1')
        problems = freeze_gate.compile_problems(build, sha(build / 'response_only.p4'))
        if freeze_gate.model_summary_module().summarize_v3(build)['qualification'] != 'model_gate_passed':
            problems.append('17-driver model gate has not passed')
        if problems:
            raise ValueError('native preflight prerequisites: ' + '; '.join(problems))
        output.mkdir(parents=True)
    cfg = json.loads((HERE / 'lab.json').read_text())['common']
    engine = campaign_base.Campaign.__new__(campaign_base.Campaign)
    engine.cfg, engine.R, engine.V = cfg, cfg['hosts']['switch_remote_dir'], cfg['hosts']['vision_run_dir']
    engine.root, engine.record, engine.out = str(output), {}, print
    engine.rn = campaign_base.ShellRunner(cfg['hosts']) if apply else campaign_base.DryRunner()
    guard = evaluation_campaign.testbed_guard(output, {'evidence_kind':'hardware'}, {'kind':'block'}) if apply else nullcontext(None)
    with guard as ownership:
        if ownership:
            evaluation_campaign.atomic_json(ownership, dict(active=True,unsafe_restoration=False,
                campaign_dir=str(output),step_id=label,operation='native_read_preflight'))
        try:
            return _native_probe_run(engine,output,label,port,apply)
        finally:
            if ownership:
                safe = not engine.record.get('traffic_attempted')
                if not safe:
                    try:
                        flags = json.loads((output/'capture_offloads.json').read_text())
                        after = engine.step('switch','verify unchanged production after native READs',
                            'python3 '+campaign_base.q(engine.R+'/aux/observe_program.py'),check=False)
                        engine.record['production_after'] = campaign_base.runner.last_json(after.out)
                        safe = flags.get('restore_ok') is True and after.rc == 0 and engine.record['production_after'].get('program') == cfg['production']['program']
                    except (OSError,ValueError,KeyError,IndexError,TypeError):
                        safe = False
                state = dict(active=False,unsafe_restoration=not safe,campaign_dir=str(output),
                             step_id=label,operation='native_read_preflight')
                evaluation_campaign.atomic_json(ownership,state)
                (output/'native_preflight.json').write_text(json.dumps(engine.record,indent=2)+'\n')
                (output/'native_ownership.json').write_text(json.dumps(state,indent=2)+'\n')
                if not safe:
                    raise evaluation_campaign.Refused('native preflight restoration is unverified; hardware remains blocked')


def _native_probe_run(engine,output,label,port,apply):
    cfg = engine.cfg
    q = campaign_base.q
    observer = engine.R + '/aux/observe_program.py'
    engine.step('switch', 'prepare read-only program observer', 'mkdir -p ' + q(engine.R + '/aux'))
    engine.step('local', 'copy read-only program observer', 'scp -q %s %s:%s' %
                (q(HERE / 'observe_program.py'), cfg['hosts']['switch'], q(observer)))
    observed = engine.step('switch', 'verify production program before native READs', 'python3 ' + q(observer))
    if apply:
        engine.record['production_before'] = campaign_base.runner.last_json(observed.out)
        if engine.record['production_before'].get('program') != cfg['production']['program']:
            raise ValueError('native preflight requires the restored production program')
    engine.relay_vision_identity()
    command = (campaign_base.RELAY_PYTHON + ' %s/vision_run.py run %s --master-port %d --reads 2 '
               '--range 8 --gap-ms 0 --start-delay-ms 0 --read-pause-ms 25 --read-schedule mixed_full '
               '--run-sbo 0 --endpoint-profile sel751 --apply') % (q(engine.V), label, port)
    engine.record['traffic_attempted'] = bool(apply)
    result = engine.step('vision', 'two native READs with capture; no SELECT/OPERATE', command, check=False)
    engine.step('local', 'retain native probe evidence', 'rsync -a %s:%s/ %s/' %
                (cfg['hosts']['vision'], q(engine.V + '/runs/' + label), q(output)))
    if not apply:
        return dict(status='dry-run', hardware_contact=False)
    report = relay_check.analyze(output, port, dict(READ=2, SELECT=0, OPERATE=0), 'mixed_full')
    if result.rc:
        report['failures'].append('native master did not complete both READs')
    report['ok'] = not report['failures']
    (output / 'relay_wire.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'native_preflight.json').write_text(json.dumps(engine.record, indent=2) + '\n')
    if not report['ok']:
        raise ValueError('native packet preflight failed: ' + '; '.join(report['failures']))
    return dict(status='native_profile_observed', observation=str(output / 'relay_wire.json'),
                hardware_contact=True, select_operate_issued=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('build', type=Path)
    prep.add_argument('--native-observation', type=Path, required=True)
    prep.add_argument('--output', type=Path, required=True)
    prep.add_argument('--campaign-id', required=True)
    prep.add_argument('--definition', choices=sorted(DEFINITIONS), default='qualification')
    native = sub.add_parser('native-probe')
    native.add_argument('build', type=Path)
    native.add_argument('--output', type=Path, required=True)
    native.add_argument('--label', required=True)
    native.add_argument('--master-port', type=int, required=True)
    native.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'native-probe':
        print(json.dumps(native_probe(args.build, args.output, args.label, args.master_port, args.apply), indent=2))
        return 0
    target = prepare(args.build, args.native_observation, args.output, args.campaign_id, args.definition)
    print(target)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
