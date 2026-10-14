import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path('defense4/timing/case4_architecture')
SRC = ROOT / 'integration/evidence/rearm_01/config'
DST = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config'
FULL = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04'
MODEL = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence'
STRICT = ROOT / 'integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict'
BUILD = 'rearm_61_full04'
STRICT_BUILD = 'strict_dup_hold_full02'
BUILD_HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
CANDIDATE_SOURCE_SHA = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'
STRICT_SOURCE_SHA = '2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def load_json(path):
    return json.load(open(path))


def compile_identity(root, rel_manifest='compile_switch_9132/manifest.json', rel_out='compile_switch_9132/out'):
    manifest_path = root / rel_manifest
    out = root / rel_out
    manifest = load_json(manifest_path)
    if manifest.get('exit_code') != 0:
        raise ValueError('compile manifest is not successful: %s' % manifest_path)
    artifact = {k: manifest['artifact_sha256'][k] for k in BUILD_HASHED}
    return {
        'sdk': '9.13.2',
        'status': 'compiled',
        'compiler': manifest.get('compiler'),
        'source_sha256': manifest.get('source_sha256'),
        'manifest_sha256': sha(manifest_path),
        'bfrt_json_sha256': sha(out / 'bfrt.json'),
        'p4pp_sha256': sha(out / 'response_only.p4pp'),
        'artifact_sha256': artifact,
        'manifest': str((root / rel_manifest).relative_to(ROOT)),
        'out_dir': str((root / rel_out).relative_to(ROOT)),
    }


def latest_model_reports():
    by_kind = {}
    failures = []
    for path in sorted(MODEL.glob('model_*_*/*results.json')):
        try:
            record = load_json(path)
        except (OSError, ValueError):
            continue
        summary = record.get('summary') or {}
        parts = path.parent.name.rsplit('_', 1)
        kind = parts[0] if len(parts) == 2 and parts[1].isdigit() else path.parent.name
        item = {
            'path': str(path.relative_to(ROOT)),
            'sha256': sha(path),
            'summary': summary,
        }
        ok = summary.get('failed') == [] and summary.get('passed') == summary.get('total')
        if ok:
            by_kind[kind] = item
        else:
            failures.append(item)
    return {'latest_successful': by_kind, 'retained_failed': failures}


# Compiler outputs are git-ignored (**/out/). The configs bind their hashes, so regeneration needs the real
# build trees; they are never synthesized. Exit 3 names what is missing and how to rebuild it.
BUILD_OUTPUTS = {
    FULL / 'compile_switch_9132/out': (
        'SDK 9.13.2 on the switch host: python3 %s (copies build.py and the source to decps@10.10.54.81, runs '
        'bf-p4c --target tofino --arch tna -g, rsyncs out/ back)' % (FULL / 'compile_switch_9132/orchestrator.py')),
    FULL / 'compile_local/out': (
        'SDK 9.13.1 locally: python3 %s %s %s --compiler /home/philip/bf-sde-9.13.1/install/bin/bf-p4c'
        % (ROOT / 'build.py', FULL / 'response_only.p4', FULL / 'compile_local')),
    STRICT / 'compile_switch_9132/out': (
        'SDK 9.13.2 on the switch host for the strict comparison source, the same orchestrator procedure '
        'under %s' % (STRICT / 'compile_switch_9132')),
}
BUILD_FILES = ('bfrt.json', 'response_only.p4pp')


def missing_build_outputs():
    return [(str(out / name), how) for out, how in BUILD_OUTPUTS.items() for name in BUILD_FILES
            if not (out / name).is_file()]


_missing = missing_build_outputs()
if '--check-build' in sys.argv[1:] or _missing:
    for path, how in _missing:
        sys.stderr.write('missing compiler output %s\n  rebuild: %s\n' % (path, how))
    sys.exit(3 if _missing else 0)

inputs = load_json(FULL / 'response_only.inputs.json')
local_manifest = load_json(FULL / 'compile_local/manifest.json')
local_out = FULL / 'compile_local/out'
candidate_switch = compile_identity(FULL)
strict_switch = compile_identity(STRICT)
if inputs['source_sha256'] != CANDIDATE_SOURCE_SHA or candidate_switch['source_sha256'] != CANDIDATE_SOURCE_SHA:
    raise ValueError('candidate61 source SHA mismatch')
if strict_switch['source_sha256'] != STRICT_SOURCE_SHA:
    raise ValueError('strict comparison source SHA mismatch')

identity = {
    'profile': 'candidate61',
    'candidate_source_sha256': CANDIDATE_SOURCE_SHA,
    'full04_source_sha256': sha(FULL / 'response_only.p4'),
    'response_only_inputs_sha256': sha(FULL / 'response_only.inputs.json'),
    'generator_sha256': inputs.get('generator_sha256'),
    'segment_sha256': inputs.get('segment_sha256'),
    'strict_source': inputs.get('strict_source'),
    'image_len': 61,
    'native_lengths': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
    'output_lengths': {'off': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
                       'timing_only': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
                       'size_only': {'READ': 61, 'SELECT': 61, 'OPERATE': 61},
                       'combined': {'READ': 61, 'SELECT': 61, 'OPERATE': 61}},
    'local_compile': {
        'sdk': local_manifest.get('compiler'),
        'manifest_sha256': sha(FULL / 'compile_local/manifest.json'),
        'bfrt_json_sha256': sha(local_out / 'bfrt.json'),
        'p4pp_sha256': sha(local_out / 'response_only.p4pp'),
        'artifact_sha256': {k: local_manifest['artifact_sha256'][k] for k in BUILD_HASHED},
        'resources': local_manifest.get('resources'),
    },
    'switch_compile': candidate_switch,
    'model_gates': latest_model_reports(),
}

strict_identity = {
    'profile': 'strict_comparison',
    'source_sha256': STRICT_SOURCE_SHA,
    'switch_compile': strict_switch,
    'output_lengths': {'off': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
                       'timing_only': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
                       'size_only': {'READ': 58, 'SELECT': 37, 'OPERATE': 37},
                       'combined': {'READ': 58, 'SELECT': 37, 'OPERATE': 37}},
}


def make_build(profile, source_sha256, compile_info, image_len, control_padding, note):
    return {
        'profile': profile,
        'source_sha256': source_sha256,
        'out_dir': compile_info['out_dir'],
        'manifest': compile_info['manifest'],
        'sde': '/home/decps/Downloads/bf-sde-9.13.2',
        'pcie': '0000:04:00.0',
        'allowed_loop_octet_gap': {},
        'mirror_fix': True,
        'max_token_stale': 0,
        'image_len': image_len,
        'control_padding': control_padding,
        'strict_controls_native': not control_padding,
        'lifecycle_rearm': True,
        'hashes': compile_info['artifact_sha256'],
        '_note': note,
    }


build = make_build(
    'candidate61', CANDIDATE_SOURCE_SHA, candidate_switch, 61, True,
    'candidate61 full_04; READ and SELECT/OPERATE padded image length 61 in size-enabled arms. Hardware remains gated on sealed_profile registration, model/review gates, capture-boundary qualification, generation-headroom precheck, and restore verification.'
)
strict_build = make_build(
    'strict_comparison', STRICT_SOURCE_SHA, strict_switch, 58, False,
    'Strict baseline comparison build: READ padding profile is 58 bytes, SELECT/OPERATE remain native 37 bytes with strict control semantics.'
)

notes = [
    'candidate61 full_04 hardware preparation only; no production defaults changed.',
    'All candidate61 configs carry build.profile=candidate61 and build.source_sha256=1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa.',
    'Expected candidate61 lengths: off/timing-only READ49 SELECT37 OPERATE37; size-only/combined READ61 SELECT61 OPERATE61.',
    'Hardware remains gated on extended compiled-model packets, code review, sealed_profile registration, packet-boundary qualification, generation-headroom precheck, and restore verification per block.',
]
strict_notes = [
    'Strict comparison configs are separately labelled and pinned to dup_hold_01 full_02_strict switch build.',
    'Expected strict lengths: off/timing-only READ49 SELECT37 OPERATE37; size-only/combined READ58 SELECT37 OPERATE37.',
    'Capture-boundary qualification is required for strict comparison fairness; current runner qualification is known to cover candidate61 only, so root must wire the strict path before execution.',
]


def load(name):
    return load_json(SRC / name)


def configure_lengths(d, profile):
    d['expectations']['native_len'] = {'READ': 49, 'SELECT': 37, 'OPERATE': 37}
    if profile == 'candidate61':
        d['expectations']['padding']['1']['read_resp_len'] = [61]
        d['expectations']['padding']['1']['sbo_resp_len'] = [61]
        d['expectations']['padding']['1']['growth'] = 'positive_12_read_24_per_control'
    elif profile == 'strict_comparison':
        d['expectations']['padding']['1']['read_resp_len'] = [58]
        d['expectations']['padding']['1']['sbo_resp_len'] = [37]
        d['expectations']['padding']['1']['growth'] = 'positive_read_only'
    else:
        raise ValueError('unknown profile ' + profile)
    d['expectations']['padding']['0']['read_resp_len'] = [49]
    d['expectations']['padding']['0']['sbo_resp_len'] = [37]
    return d




def configure_loss_presets(d, profile):
    presets = d.get('loss', {}).get('presets', {})
    if profile == 'candidate61':
        replacements = {
            'select_resp_padded': 'select_resp_padded',
            'operate_resp_padded': 'operate_resp_padded',
        }
    else:
        replacements = {
            'select_resp_padded': 'select_resp_native',
            'operate_resp_padded': 'operate_resp_native',
        }
    for preset in presets.values():
        for entry in preset:
            if entry.get('class') in replacements:
                entry['class'] = replacements[entry['class']]
            if profile == 'candidate61' and entry.get('class') == 'select_resp_native':
                entry['class'] = 'select_resp_padded'
            if profile == 'candidate61' and entry.get('class') == 'operate_resp_native':
                entry['class'] = 'operate_resp_padded'
    return d

def transform(data, *, purpose=None, preset=None, gap=950000, readiness=None, build_name=BUILD, build_spec=None,
              profile='candidate61', arms=None, reads=None, trials=None, port_first=None, port_last=None,
              run_sbo=None, held=False, start_delay_ms=None, fixtures=None, eval_extra=None, standards=None, loss_presets=None,
              sbo_cycles=None, endpoint=None, vision_run_dir=None):
    d = copy.deepcopy(data)
    d['_notes'] = (strict_notes if profile == 'strict_comparison' else notes) + d.get('_notes', [])
    d['evidence_dir'] = 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/hw_campaigns'
    d['candidate61_identity'] = identity
    if profile == 'strict_comparison':
        d['strict_comparison_identity'] = strict_identity
    d['builds'] = {build_name: copy.deepcopy(build_spec or build)}
    for arm in d['arms']:
        arm['build'] = build_name
    if arms is not None:
        arm_map = {a['name']: a for a in d['arms']}
        d['arms'] = [copy.deepcopy(arm_map[name]) for name in arms]
        for arm in d['arms']:
            arm['build'] = build_name
    configure_lengths(d, profile)
    configure_loss_presets(d, profile)
    d['timing_params_ns']['gap'] = gap
    if readiness is not None:
        d['timing_params_ns']['readiness'] = readiness
    if preset is not None:
        d['shaping']['preset'] = preset
    if purpose is not None:
        d['evaluation'] = purpose
    if reads is not None:
        d['trials']['reads_per_trial'] = reads
    if trials is not None:
        d['trials']['trials_per_arm'] = trials
    if port_first is not None:
        d['traffic']['master_port_range']['first'] = port_first
    if port_last is not None:
        d['traffic']['master_port_range']['last'] = port_last
    if run_sbo is not None:
        d['traffic']['run_sbo'] = run_sbo
    if held:
        d['traffic']['expect_held_operate_dup'] = True
    else:
        d['traffic'].pop('expect_held_operate_dup', None)
    if start_delay_ms is not None:
        d['traffic']['start_delay_ms'] = start_delay_ms
    if fixtures is not None:
        d['fixture']['modes'] = fixtures
    if eval_extra:
        d['evaluation'].update(eval_extra)
    if standards is not None:
        d['standards'] = standards
    if loss_presets is not None:
        d['loss']['presets'] = loss_presets
    if sbo_cycles is not None:
        d['traffic']['sbo_cycles'] = sbo_cycles
    if endpoint is not None:
        d['endpoint'] = copy.deepcopy(endpoint)
    if vision_run_dir is not None:
        d['hosts']['vision_run_dir'] = vision_run_dir
    return d


def write(name, data):
    (DST / name).write_text(json.dumps(data, indent=2) + '\n')


# Candidate61 smoke and bounded campaign gates.
write('candidate61_fourarm_smoke.json', transform(load('candidate57s_fourarm_smoke.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'fourarm_smoke'}, port_first=59530, port_last=59533))
write('candidate61_persistence_graceful_950.json', transform(load('candidate57s_graceful_800.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'persistence_graceful'}, gap=950000, port_first=59520, port_last=59520))
write('candidate61_persistence_rst_950.json', transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'persistence_rst'}, port_first=59521, port_last=59521))
write('candidate61_loss_core_950.json', transform(load('candidate57s_single_loss.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'loss_core'}, port_first=59540, port_last=59546))
write('candidate61_reconnect_950.json', transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'reconnect_protected'}, port_first=59550, port_last=59550))
write('candidate61_stale_tokens_950.json', transform(load('candidate57s_old_tokens.json'),
    purpose={'purpose': 'stale_source_characterization', 'read_precision': False}, reads=1, trials=1, port_first=59412, port_last=59412))
write('candidate61_old_external_950.json', transform(load('candidate57s_old_external.json'),
    purpose={'purpose': 'stale_source_characterization', 'read_precision': False}, reads=1, trials=1, port_first=59400, port_last=59400))
write('candidate61_held_operate_350.json', transform(load('candidate57s_dup_hold_350.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'held_operate'}, gap=800000, port_first=59522, port_last=59522, held=True))

orders = [
    ('candidate61_eval_59570_950_b1.json', 'candidate57s_eval_b1.json', ['off', 'timing_only', 'size_only', 'combined'], 1),
    ('candidate61_eval_59570_950_b2.json', 'candidate57s_eval_b2.json', ['combined', 'off', 'timing_only', 'size_only'], 2),
    ('candidate61_eval_59570_950_b3.json', 'candidate57s_eval_b3.json', ['size_only', 'combined', 'off', 'timing_only'], 3),
]
for filename, template, order, block in orders:
    write(filename, transform(load(template), purpose={'purpose': 'timing_precision_characterization', 'read_precision': True,
        'candidate61_label': 'repeated_fourarm_59570_950', 'block': block, 'arm_order': order}, arms=order, reads=500, trials=1,
        preset='shape_59570', gap=950000, port_first=59560, port_last=59563, start_delay_ms=50,
        loss_presets={}))

# Repeated SELECT/OPERATE on one persistent connection (Gate 2): the repeated-SBO endpoint fork, deployed to its
# own Vision directory. reads counts every READ: 1 before the first cycle, then 64 x (SELECT, OPERATE, READ).
REPEAT_ENDPOINT = {
    'opendnp3_commit': '4648fcb898456d1cb70b5baecc38cc256c859c2e',
    'binary_sha256': 'e8f7694d98d5aad8bcfd0a4423e634a5a740e945d296df053cac6aa386d8e793',
    'lib_sha256': 'a5f744c0ce17fa8674e46b9c9bd374c224e57900dfa5c3adafc08dd1c9123cba',
    '_pinned': 'repeat_sbo_endpoint fork (CASE4_SBO_CYCLES, append-only per-command records); software handler only.',
    '_pin_with': 'sha256sum case4_socket_gate_pad58b; sorted sha256sum listing hash under lib/ in the configured Vision directory',
    '_lib_note': 'lib_sha256 is the sha256 of the sorted `sha256sum` listing of every file under lib/',
    'source_sha256': 'dc3985033d00d3d38dec74a3bf71574f56ade7ea49fc5a0162da5d95fb39384e',
    'source_files': {
        'SocketGatePad58B.cpp': 'dc3985033d00d3d38dec74a3bf71574f56ade7ea49fc5a0162da5d95fb39384e',
        'DecoyGateCommandHandler.h': 'e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2',
    },
    'build_recipe': 'integration/evidence/rearm_01/repeat_sbo_endpoint/build_endpoint.py',
}
REPEAT_VISION_DIR = '/home/decps/pad58b_repeat_sbo_20261014b'   # _20261014 held a stale build
repeat_orders = [
    ('candidate61_repeat_sbo_950_b1.json', 'candidate57s_eval_b1.json', ['off', 'timing_only', 'size_only', 'combined'], 1),
    ('candidate61_repeat_sbo_950_b2.json', 'candidate57s_eval_b2.json', ['combined', 'off', 'timing_only', 'size_only'], 2),
    ('candidate61_repeat_sbo_950_b3.json', 'candidate57s_eval_b3.json', ['size_only', 'combined', 'off', 'timing_only'], 3),
]
for filename, template, order, block in repeat_orders:
    write(filename, transform(load(template), purpose={'purpose': 'timing_precision_characterization', 'read_precision': True,
        'candidate61_label': 'repeat_sbo_64_59570_950', 'block': block, 'arm_order': order}, arms=order, reads=65, trials=1,
        preset='shape_59570', gap=950000, port_first=59590, port_last=59593, start_delay_ms=50, loss_presets={},
        sbo_cycles=64, endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR))

strict_standards = {
    'packet_boundary_required': True,
    'capture_boundary_scope': 'strict_comparison_fairness',
    'runner_qualification_status': 'capture qualification enabled; silicon comparison pending',
}
strict_orders = [
    ('strict_comparison_59570_950_b1.json', 'candidate57s_eval_b1.json', ['off', 'timing_only', 'size_only', 'combined'], 1),
    ('strict_comparison_59570_950_b2.json', 'candidate57s_eval_b2.json', ['combined', 'off', 'timing_only', 'size_only'], 2),
    ('strict_comparison_59570_950_b3.json', 'candidate57s_eval_b3.json', ['size_only', 'combined', 'off', 'timing_only'], 3),
]
for filename, template, order, block in strict_orders:
    write(filename, transform(load(template), purpose={'purpose': 'timing_precision_characterization', 'read_precision': True,
        'candidate61_label': 'strict_baseline_comparison_59570_950', 'block': block, 'arm_order': order}, arms=order,
        build_name=STRICT_BUILD, build_spec=strict_build, profile='strict_comparison', reads=500, trials=1,
        preset='shape_59570', gap=950000, port_first=59660, port_last=59663, start_delay_ms=50,
        standards=strict_standards))

write('candidate61_piggyback_combined_59570_950.json', transform(load('fourarm_piggyback_combined_59570.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'piggyback_separate_59570_950'}, gap=950000,
    fixtures=['piggyback'], arms=['combined'], reads=20, trials=1, port_first=59510, port_last=59510))
write('candidate61_compare_59570_950.json', transform(load('precision_10_950_59570.json'),
    purpose={'purpose': 'timing_precision_characterization', 'read_precision': True, 'candidate61_label': 'rate_comparison_59570_950'}, preset='shape_59570',
    gap=950000, arms=['combined'], reads=50, trials=3, port_first=59570, port_last=59572))
write('candidate61_compare_14892_950.json', transform(load('precision_10_950_remaining_14892.json'),
    purpose={'purpose': 'timing_precision_characterization', 'read_precision': True, 'candidate61_label': 'rate_comparison_14892_950'}, preset='shape_14892',
    gap=950000, arms=['combined'], reads=50, trials=3, port_first=59580, port_last=59582))

print('wrote', len(list(DST.glob('candidate61_*.json'))) + len(list(DST.glob('strict_comparison_*.json'))), 'configs to', DST)
