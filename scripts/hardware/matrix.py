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
import checks
import diag_mirror_sessions
import evaluation_campaign
import freeze_gate
import relay_check


DEFINITIONS = {'qualification': dict(file='lab.json', blocks=10, exchanges=2440),
               'evaluation': dict(file='lab_eval.json', blocks=64, exchanges=49408),
               'recovery': dict(file='lab_recovery.json', blocks=3, exchanges=396)}
# One campaign per recovery condition: the controller stops a campaign at a failed block, and a reproduced CROB
# TIMEOUT in one condition must not leave the other predetermined conditions unexecuted.
RECOVERY_BLOCKS = {'recovery_r1': 'r1_d20_combined', 'recovery_r2': 'r2_d20_size_only', 'recovery_r3': 'r3_d5_combined'}
DEFINITIONS.update({name: dict(file='lab_recovery.json', blocks=1, exchanges=132) for name in RECOVERY_BLOCKS})
# One campaign per registered D3/E2 diagnostic-mirror block (results/analysis/diag_mirror_d3/DESIGN.json), for the same
# reason; only the declared c72_diag_mirror build may prepare them (diagnostic_contract).
DIAG_BLOCKS = {'diag_d3_on': 'd3_mirror_on_d20', 'diag_d3_off': 'd3_mirror_off_d20',
               'diag_e2_first': 'e2_first_request_d20'}
DEFINITIONS.update({name: dict(file='lab_diag.json', blocks=1, exchanges=exchanges, diagnostic=True)
                    for name, exchanges in (('diag_d3_on', 1544), ('diag_d3_off', 1544), ('diag_e2_first', 256))})


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


def expand_recovery(spec):
    """Repeat the reference loss block per condition: only D, the arm, the loss preset and the master ports change."""
    base = json.loads((HERE / spec['base']).read_text())
    template = next(block for block in base['blocks'] if block['id'] == spec['template'])
    blocks = []
    for condition in spec['blocks']:
        block = copy.deepcopy(template)
        block['id'] = condition['id']
        block['config']['timing_params_ns']['gap'] = condition['d_ms'] * 1000000
        block['config']['loss']['presets'] = {spec['preset']: copy.deepcopy(spec['entries'])}
        block['arms'] = [copy.deepcopy(condition['arm'])]
        block['traffic']['master_port_range'] = copy.deepcopy(condition['master_port_range'])
        block['arguments'] = ['--loss', spec['preset']]
        blocks.append(block)
    return dict(common=base['common'], blocks=blocks)


def expand_diag(spec):
    """The reference block at one D per registered diagnostic block: only the arms, the trial counts, the READ count
    and SBO, the master ports and the mirror state change."""
    base = json.loads((HERE / spec['base']).read_text())
    template = next(block for block in base['blocks'] if block['id'] == spec['template'])
    arms = {arm['name']: arm for arm in template['arms']}
    blocks = []
    for condition in spec['blocks']:
        if condition['diag_mirror'] not in ('on', 'off') or not set(condition['arms']) <= set(arms):
            raise ValueError('diagnostic block %s needs mirror state on/off and template arms' % condition['id'])
        block = copy.deepcopy(template)
        block['id'] = condition['id']
        block['diag_mirror'] = condition['diag_mirror']
        block['config']['timing_params_ns']['gap'] = spec['d_ms'] * 1000000
        block['config']['trials']['trials_per_arm'] = condition['trials_per_arm']
        if 'reads_per_trial' in condition:
            block['config']['trials']['reads_per_trial'] = condition['reads_per_trial']
        if condition.get('run_sbo') is False:
            block['traffic']['run_sbo'] = False
            block['traffic'].pop('sbo_cycles', None)
        block['arms'] = [copy.deepcopy(arms[name]) for name in condition['arms']]
        block['traffic']['master_port_range'] = copy.deepcopy(condition['master_port_range'])
        blocks.append(block)
    return dict(common=base['common'], blocks=blocks,
                diag=dict(capture_interface=spec['capture_interface'], build_label=spec['build_label']))


def diagnostic_contract(build, source_hash, declared):
    """The diag_mirror fields of every diagnostic block config, only from a build the freeze gate admits as the
    declared diagnostic build: its compiled copy port, the registered capture interface and label, its source."""
    if not freeze_gate.declared_diagnostic(build):
        raise ValueError('a diagnostic definition needs the declared diagnostic build %s; %s has no %s'
                         % (declared['build_label'], build, freeze_gate.DIAG_IDENTITY))
    problems = freeze_gate.diagnostic_problems(build, source_hash)
    if build.name != declared['build_label']:
        problems.append('build %s is not the registered diagnostic build %s' % (build.name, declared['build_label']))
    constants = {}
    if not problems:
        try:
            constants = diag_mirror_sessions.load(build)
            problems += diag_mirror_sessions.validate(constants)
        except (OSError, ValueError) as error:
            problems.append('diagnostic constants unreadable: %s' % error)
    if problems:
        raise ValueError('diagnostic build refused: ' + '; '.join(problems))
    return dict(copy_port=constants['copy_port'], capture_interface=declared['capture_interface'],
                build_label=declared['build_label'], source_sha256=source_hash)


def load_definition(name):
    spec = DEFINITIONS[name]
    definition = json.loads((HERE / spec['file']).read_text())
    if name == 'evaluation':
        definition = expand_evaluation(definition)
    elif name == 'recovery':
        definition = expand_recovery(definition)
    elif name in RECOVERY_BLOCKS:
        full = expand_recovery(definition)
        definition = dict(common=full['common'], blocks=[b for b in full['blocks'] if b['id'] == RECOVERY_BLOCKS[name]])
    elif name in DIAG_BLOCKS:
        full = expand_diag(definition)
        definition = dict(common=full['common'], diag=full['diag'],
                          blocks=[b for b in full['blocks'] if b['id'] == DIAG_BLOCKS[name]])
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
    diag = diagnostic_contract(build, source_hash, definition['diag']) if spec.get('diagnostic') else None
    output.mkdir(parents=True)
    configs = output / 'configs'
    configs.mkdir()
    steps, count, paths = [], 0, []
    for block in definition['blocks']:
        if set(block['config']) & {'endpoints','endpoint','ports_map'}:
            raise ValueError('matrix blocks cannot override the fixed reciprocal IP/port binding')
        if set(block['config']) & {'purpose', 'diag_mirror'} or ('diag_mirror' in block) != (diag is not None):
            raise ValueError('only a diagnostic definition, with the admitted diagnostic build, carries the '
                             'diagnostic contract')
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
        if diag is not None:
            cfg['purpose'] = 'diagnostic'
            cfg['diag_mirror'] = dict(state=block['diag_mirror'], **diag)
            cfg['ports_map']['stat_ports'] += ',%d' % diag['copy_port']
        path = configs / (block['id'] + '.json')
        path.write_text(json.dumps(cfg, indent=2) + '\n')
        campaign_base.load_config(path)
        run_id = campaign_id + '_' + block['id']
        argv = ['bash', str(HERE / 'run_block_frozen.sh'), str(output / 'freeze.json'),
                block['tool'], str(path), run_id] + block['arguments']
        multiplier = 3 if block['tool'] == 'persistence' or '--scenario' in block['arguments'] else 1
        if '--loss' in block['arguments']:
            multiplier = len(cfg['loss']['presets'][block['arguments'][1]])
        # a plain block runs trials_per_arm cold connections per arm; SBO pairs follow checks.sbo_count (0 without SBO)
        trials = cfg['trials']['trials_per_arm'] if block['tool'] == 'campaign' and not block['arguments'] else 1
        exchanges = len(cfg['arms']) * trials * multiplier * (cfg['trials']['reads_per_trial'] +
                                                              2 * checks.sbo_count(cfg['traffic']))
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
