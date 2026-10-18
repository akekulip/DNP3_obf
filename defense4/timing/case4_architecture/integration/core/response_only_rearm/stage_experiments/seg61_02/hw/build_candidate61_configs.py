import copy
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path('defense4/timing/case4_architecture')
SRC = ROOT / 'integration/evidence/rearm_01/config'
DST = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/hw/config'
FULL = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence/full_04'
MODEL = ROOT / 'integration/core/response_only_rearm/stage_experiments/seg61_02/evidence'
STRICT = ROOT / 'integration/core/response_only_rearm/stage_experiments/dup_hold_01/evidence/full_02_strict'
CTL = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m3_01'
CTL_BUILD = 'ctl_timing_m3_01'
CTL_SOURCE_SHA = 'c4819dbac643048c16a9a0534337a938ca2820add0aae5a5bcda43e8b43a9204'
M4 = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m4_01'
M4_BUILD = 'ctl_timing_m4_01'
M4_SOURCE_SHA = '35e896ebcd11f461ea947db3b0fa5198770c547d680ffb4bdec5d885465c79cf'
M5 = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m5_10'
M5_BUILD = 'ctl_timing_m5_10'
M5_SOURCE_SHA = 'b758c98199dddd36f8df4a90ce7a1e2301b63e95c2ac766aafa20b5b9f15e981'
M9 = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m9_01'
M9_BUILD = 'ctl_timing_m9_01'
M9_SOURCE_SHA = '6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f'
M10 = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m10_03'
M10_BUILD = 'ctl_timing_m10_03'
M10_SOURCE_SHA = 'd9b84fcc7ecb1dded4e7fddf47a1e74da568c9b4159c0065e4e780c38d49b5dc'
M9D = ROOT / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m9d_01'
M9D_BUILD = 'ctl_timing_m9d_01'
M9D_SOURCE_SHA = '74c9cdcddbffa89589f2ed656f732328d9cc263d32877a74bab9a19ef269854f'
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


def successor_configs(build, output):
    """Derive the existing prepared workloads against an explicitly selected verified build."""
    build, output = Path(build).resolve(), Path(output).resolve()
    here = Path(__file__).resolve().parent
    architecture = Path(__file__).resolve().parents[6]
    def reference(path):
        try:
            return str(path.relative_to(architecture))
        except ValueError:
            return str(path)
    spec = importlib.util.spec_from_file_location('successor_sealed_profile', here.parents[2] / 'hw/sealed_profile.py')
    schema = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(schema)
    for name in ('compile_local', 'compile_switch_9132'):
        schema.describe(build / name / 'out')
    inputs = load_json(build / 'response_only.inputs.json')
    profile_path = build / 'supported_profile.json'
    profile = load_json(profile_path)
    if profile != inputs.get('supported_profile'):
        raise ValueError('successor supported profile differs from build inputs')
    selected = build / 'compile_switch_9132'
    manifest = load_json(selected / 'manifest.json')
    identity_record = dict(sdk='9.13.2', status='compiled', compiler=manifest['compiler'],
        source_sha256=inputs['source_sha256'], manifest_sha256=sha(selected / 'manifest.json'),
        bfrt_json_sha256=sha(selected / 'out/bfrt.json'), p4pp_sha256=sha(selected / 'out/response_only.p4pp'),
        artifact_sha256={key: manifest['artifact_sha256'][key] for key in BUILD_HASHED},
        manifest=reference(selected / 'manifest.json'), out_dir=reference(selected / 'out'))
    templates = sorted((here / 'config').glob('part2_m10_*.json')) + [here / 'config' / ('ctl_m10_' + suffix + '.json')
        for suffix in ('persistence_graceful_950', 'persistence_rst_950', 'loss_core_950', 'reconnect_950',
                       'held_operate_350')]
    if len(templates) != 55:
        raise ValueError('successor preparation requires the existing 50 Part2 and five recovery templates')
    prepared, bindings = {}, {}
    name = 'ctl_timing_' + build.name
    for template in templates:
        data = load_json(template)
        if len(data['builds']) != 1:
            raise ValueError('prepared template must select one build: ' + str(template))
        selected_build = copy.deepcopy(next(iter(data['builds'].values())))
        selected_build.update(source_sha256=inputs['source_sha256'], manifest=identity_record['manifest'],
                              out_dir=identity_record['out_dir'], hashes=identity_record['artifact_sha256'],
                              _note='Prepared successor %s; exact-candidate model gates and freeze required.' % build.name)
        data['builds'] = {name: selected_build}
        for arm in data['arms']:
            arm['build'] = name
        label = data['evaluation'].get('candidate61_label')
        if isinstance(label, str) and label.startswith('m10'):
            data['evaluation']['candidate61_label'] = build.name + label[3:]
        data['ctl_timing_identity'] = dict(source_sha256=inputs['source_sha256'],
            switch_compile=identity_record, design=reference(here.parents[1] / 'ctl_timing_01/efficiency_candidates.py'),
            supported_profile=reference(profile_path), supported_profile_sha256=sha(profile_path))
        filename = template.name.replace('m10', build.name, 1)
        prepared[filename] = json.dumps(data, indent=2) + '\n'
        bindings[filename] = dict(template=template.name, template_sha256=sha(template),
                                 sha256=hashlib.sha256(prepared[filename].encode()).hexdigest())
    output.mkdir(parents=True, exist_ok=False)
    for filename, content in prepared.items():
        (output / filename).write_text(content)
    record = dict(build=reference(build), source_sha256=inputs['source_sha256'],
        supported_profile_sha256=sha(profile_path), inputs_sha256=sha(build / 'response_only.inputs.json'),
        compile_manifests={name: sha(build / name / 'manifest.json')
                           for name in ('compile_local', 'compile_switch_9132')},
        qualification='pending exact-candidate model gates and freeze', configs=bindings)
    (output / 'prepared_configs.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if any(argument.startswith('--successor-') for argument in sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Prepare unchanged Part2/recovery workloads for a selected successor.',
                                     allow_abbrev=False)
    parser.add_argument('--successor-build', required=True)
    parser.add_argument('--successor-output', required=True)
    arguments = parser.parse_args()
    result = successor_configs(arguments.successor_build, arguments.successor_output)
    print(json.dumps(dict(source_sha256=result['source_sha256'], configs=len(result['configs']))))
    sys.exit(0)


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
    CTL / 'compile_switch_9132/out': (
        'SDK 9.13.2 on the switch host: python3 %s' % (CTL.parent.parent / 'compile_switch_orchestrator.py')),
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
ctl_switch = compile_identity(CTL)
m4_switch = compile_identity(M4)
if m4_switch['source_sha256'] != M4_SOURCE_SHA:
    raise ValueError('ctl_timing m4 source SHA mismatch')
m5_switch = compile_identity(M5)
if m5_switch['source_sha256'] != M5_SOURCE_SHA:
    raise ValueError('ctl_timing m5 source SHA mismatch')
m9_switch = compile_identity(M9)
if m9_switch['source_sha256'] != M9_SOURCE_SHA:
    raise ValueError('ctl_timing m9 source SHA mismatch')
m10_switch = compile_identity(M10)
if m10_switch['source_sha256'] != M10_SOURCE_SHA:
    raise ValueError('ctl_timing m10 source SHA mismatch')
m9d_switch = compile_identity(M9D)
if m9d_switch['source_sha256'] != M9D_SOURCE_SHA:
    raise ValueError('ctl_timing m9d source SHA mismatch')
if ctl_switch['source_sha256'] != CTL_SOURCE_SHA:
    raise ValueError('ctl_timing m3 source SHA mismatch')
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
        # T outcome index declaring GEN_EXHAUSTED (t_OUT_GEN_EXHAUSTED = 15 in full_04, ctl_timing m3 and
        # dup_hold_01 full_02_strict); checks.evaluate fails any drop it counts and a missing counter
        'gen_exhausted_outcome': 15,
        'hashes': compile_info['artifact_sha256'],
        '_note': note,
    }


build = make_build(
    'candidate61', CANDIDATE_SOURCE_SHA, candidate_switch, 61, True,
    'candidate61 full_04; READ and SELECT/OPERATE padded image length 61 in size-enabled arms. Hardware remains gated on sealed_profile registration, model/review gates, capture-boundary qualification, generation-headroom precheck, and restore verification.'
)
ctl_build = dict(make_build(
    'candidate61', CTL_SOURCE_SHA, ctl_switch, 61, True,
    'ctl_timing_01 m3: candidate61 encoding (E byte-identical) with SELECT and OPERATE ACK->response timed by T '
    '(OPERATE J hold kept) and a per-response piggyback bound pb (timing_params_ns.pb).'),
    control_timed=True, piggyback_bound=True)
m4_build = dict(make_build(
    'candidate61', M4_SOURCE_SHA, m4_switch, 61, True,
    'ctl_timing_01 m4: m3 plus IEEE 1815 Table 4-9 selection cancellation/replacement in N and fail-closed '
    'OPERATE lane exhaustion in T (E byte-identical to candidate61).'),
    control_timed=True, piggyback_bound=True)
m5_build = dict(make_build(
    'candidate61', M5_SOURCE_SHA, m5_switch, 61, True,
    'ctl_timing_01 m5: m4 plus a bounded, validated busy-retry for responses in N (ACK/response work-cell '
    'contention); E and T byte-identical to m4.'),
    control_timed=True, piggyback_bound=True)
m9_build = dict(make_build(
    'candidate61', M9_SOURCE_SHA, m9_switch, 61, True,
    'ctl_timing_01 m9: m6 N lifecycle corrections, m7 T time base (256 ns units), m8 E reset at the frontier, and '
    'the m9 N reset wait (a master RST no longer lost to a busy work cell).'),
    control_timed=True, piggyback_bound=True)
m10_build = dict(make_build(
    'candidate61', M10_SOURCE_SHA, m10_switch, 61, True,
    'ctl_timing_01 m10: m9 plus the N stage-1 RST restart (a validated master RST survives a same-incarnation '
    'owner change; count_busy[5] counts restarts). E and T identical to m9.'),
    control_timed=True, piggyback_bound=True)
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
    'binary_sha256': '8d78cf2fe9adcd559c23c2c018834dc84110d83796f38ed4fdfc10e0874a0553',
    'lib_sha256': 'a5f744c0ce17fa8674e46b9c9bd374c224e57900dfa5c3adafc08dd1c9123cba',
    '_pinned': 'repeat_sbo_endpoint fork (CASE4_SBO_CYCLES, append-only per-command records); software handler only.',
    '_pin_with': 'sha256sum case4_socket_gate_pad58b; sorted sha256sum listing hash under lib/ in the configured Vision directory',
    '_lib_note': 'lib_sha256 is the sha256 of the sorted `sha256sum` listing of every file under lib/',
    'source_sha256': '84ff5bc978a4a21f6749177aee298b65275b59afa217e24bb6d5d9a300b68e22',
    'source_files': {
        'SocketGatePad58B.cpp': '84ff5bc978a4a21f6749177aee298b65275b59afa217e24bb6d5d9a300b68e22',
        'DecoyGateCommandHandler.h': 'e1070d8de2e60fac3eb6e4e640eeed9bf857531f819732ac680f54407923d2d2',
    },
    'build_recipe': 'integration/evidence/rearm_01/repeat_sbo_endpoint/build_endpoint.py',
}
# _20261014 held a stale build; _20261014b ran blocks b1_02..b3 (endpoint e8f7694d, source dc398503)
REPEAT_VISION_DIR = '/home/decps/pad58b_repeat_sbo_20261014c'
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

# Gate 3 silicon: the control-timing build on the repeated-SBO endpoint. pb = 4 ms bounds piggybacked
# request->response (previously the 30 ms readiness fallback); it must exceed op_j (2.4 ms), because an
# OPERATE's piggybacked response cannot arrive before its J hold ends.
CTL_PB_NS = 4000000
# Characterization blocks (run, Gate 3) and their qualification twins: the same build, endpoint, workload and
# shaping with evaluation purpose qualification, so every timing objective the build claims (READ/SELECT/OPERATE
# CLRT, piggyback latency, OPERATE hold J) is a hard gate. Each family has its own master port range.
ctl_specs = [('ctl_timing_repeat_sbo_950_b%d.json', 'separate_ack', 59600, 'timing_precision_characterization',
              'ctl_timing_m3_%s_64'),
             ('ctl_timing_piggyback_950_b%d.json', 'piggyback', 59610, 'timing_precision_characterization',
              'ctl_timing_m3_%s_64'),
             ('ctl_timing_qual_repeat_sbo_950_b%d.json', 'separate_ack', 59620, 'qualification',
              'ctl_timing_m3_qual_%s_64'),
             ('ctl_timing_qual_piggyback_950_b%d.json', 'piggyback', 59630, 'qualification',
              'ctl_timing_m3_qual_%s_64')]
for pattern, fixture, port, purpose, label in ctl_specs:
    for filename, template, order, block in repeat_orders:
        data = transform(load(template), purpose={'purpose': purpose, 'read_precision': True,
            'candidate61_label': label % fixture, 'block': block, 'arm_order': order}, arms=order,
            reads=65, trials=1, preset='shape_59570', gap=950000, port_first=port, port_last=port + 3, start_delay_ms=50,
            loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR,
            build_name=CTL_BUILD, build_spec=ctl_build, fixtures=[fixture])
        data['timing_params_ns']['pb'] = CTL_PB_NS
        data['ctl_timing_identity'] = {'source_sha256': CTL_SOURCE_SHA, 'switch_compile': ctl_switch,
                                       'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/DESIGN.md'}
        write(pattern % block, data)

# ctl_timing m4 (the correctness successor): its own silicon recovery gates, qualification blocks and the
# asymmetric-shaping pilot. Same workloads, endpoints and templates as candidate61's step-3 gates and the m3
# qualification twins; every timing objective the build claims is a hard gate under purpose qualification.
M4_IDENTITY = {'source_sha256': M4_SOURCE_SHA, 'switch_compile': m4_switch,
               'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/DESIGN.md (m4)'}


def m4(data, pb=CTL_PB_NS):
    data['timing_params_ns']['pb'] = pb
    data['ctl_timing_identity'] = M4_IDENTITY
    return data


M4B = dict(build_name=M4_BUILD, build_spec=m4_build)
write('ctl_m4_persistence_graceful_950.json', m4(transform(load('candidate57s_graceful_800.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm4_persistence_graceful'},
    gap=950000, port_first=59700, port_last=59700, **M4B)))
write('ctl_m4_persistence_rst_950.json', m4(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm4_persistence_rst'},
    port_first=59701, port_last=59701, **M4B)))
write('ctl_m4_loss_core_950.json', m4(transform(load('candidate57s_single_loss.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm4_loss_core'},
    port_first=59710, port_last=59716, **M4B)))
write('ctl_m4_reconnect_950.json', m4(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm4_reconnect_protected'},
    port_first=59720, port_last=59720, **M4B)))
write('ctl_m4_stale_tokens_950.json', m4(transform(load('candidate57s_old_tokens.json'),
    purpose={'purpose': 'stale_source_characterization', 'read_precision': False}, reads=1, trials=1,
    port_first=59721, port_last=59721, **M4B)))
# J = 350 ms here (duplicates arrive while the OPERATE is held), and m4 requires op_j < pb < readiness <= cap:
# readiness 380 ms, cap 400 ms, pb 360 ms. Only the no-ACK fallback deadline moves; gap stays 800 us.
held = m4(transform(load('candidate57s_dup_hold_350.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm4_held_operate'},
    gap=800000, port_first=59722, port_last=59722, held=True, **M4B), pb=360000000)
held['timing_params_ns'].update(readiness=380000000, cap=400000000)
write('ctl_m4_held_operate_350.json', held)
for pattern, fixture, port, purpose, label in (
        ('ctl_m4_qual_repeat_sbo_950_b%d.json', 'separate_ack', 59730, 'qualification', 'ctl_timing_m4_qual_%s_64'),
        ('ctl_m4_qual_piggyback_950_b%d.json', 'piggyback', 59740, 'qualification', 'ctl_timing_m4_qual_%s_64'),
        # characterization twins: the same blocks, continuing past a timing-objective miss (measurement_only), so
        # every arm's distribution is recorded even where qualification stops at the first failing arm
        ('ctl_m4_char_repeat_sbo_950_b%d.json', 'separate_ack', 59760, 'timing_precision_characterization',
         'ctl_timing_m4_char_%s_64')):
    for filename, template, order, block in repeat_orders:
        write(pattern % block, m4(transform(load(template), purpose={'purpose': purpose, 'read_precision': True,
            'candidate61_label': label % fixture, 'block': block, 'arm_order': order}, arms=order,
            reads=65, trials=1, preset='shape_59570', gap=950000, port_first=port, port_last=port + 3,
            start_delay_ms=50, loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT,
            vision_run_dir=REPEAT_VISION_DIR, fixtures=[fixture], **M4B)))
# Asymmetric shaping pilot (unchanged binary): only ACK_HOLD slows to 14,892 PPS; RESP_HOLD, OP_HOLD and every
# BLOCK queue stay at 59,570. Paired against the all-59,570 baseline on the combined arm, same workload and pacing.
SHAPE_PILOTS = {'shape_59570': None,
                'shape_ack14892': {'hold_pps': {'ack': 14892, 'resp': 59570, 'op': 59570},
                                   'block_pps': {'ack': 59570, 'resp': 59570, 'op': 59570}, 'block_burst': 64},
                'shape_ack3723': {'hold_pps': {'ack': 3723, 'resp': 59570, 'op': 59570},
                                  'block_pps': {'ack': 59570, 'resp': 59570, 'op': 59570}, 'block_burst': 64}}
for preset, spec in SHAPE_PILOTS.items():
    for filename, template, order, block in repeat_orders:
        data = m4(transform(load(template), purpose={'purpose': 'timing_precision_characterization', 'read_precision': True,
            'candidate61_label': 'm4_shaping_%s' % preset, 'block': block}, arms=['combined'],
            reads=65, trials=1, preset=preset if spec is None else 'shape_59570', gap=950000,
            port_first=59750, port_last=59753, start_delay_ms=50, loss_presets={}, sbo_cycles=64,
            endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR, fixtures=['separate_ack'], **M4B))
        if spec is not None:
            data['shaping']['presets'][preset] = dict(spec)
            data['shaping']['preset'] = preset
        write('ctl_m4_%s_b%d.json' % (preset, block), data)
# Zero-pause robustness block for the confirmed pilot: the endpoint issues the next request as soon as the previous
# response arrives (read_pause_ms 0), kept apart from the paired efficiency comparison (which keeps 25 ms).
zp = m4(transform(load('candidate57s_eval_b1.json'), purpose={'purpose': 'timing_precision_characterization',
    'read_precision': True, 'candidate61_label': 'm4_shaping_ack14892_pause0', 'block': 1}, arms=['combined'],
    reads=65, trials=1, preset='shape_59570', gap=950000, port_first=59770, port_last=59773, start_delay_ms=50,
    loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR,
    fixtures=['separate_ack'], **M4B))
zp['shaping']['presets']['shape_ack14892'] = dict(SHAPE_PILOTS['shape_ack14892'])
zp['shaping']['preset'] = 'shape_ack14892'
zp['traffic']['read_pause_ms'] = 0
write('ctl_m4_shape_ack14892_pause0.json', zp)

# ctl_timing m5 (PLAN_m5.md S4/S5): the exact compiled successor, same families, workloads and templates as m4,
# on its own port range. Shaping pairs (S5) run only after S4 correctness passes.
M5_IDENTITY = {'source_sha256': M5_SOURCE_SHA, 'switch_compile': m5_switch,
               'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/DESIGN.md (m5)'}


def m5(data, pb=CTL_PB_NS):
    data['timing_params_ns']['pb'] = pb
    data['ctl_timing_identity'] = M5_IDENTITY
    return data


M5B = dict(build_name=M5_BUILD, build_spec=m5_build)
write('ctl_m5_persistence_graceful_950.json', m5(transform(load('candidate57s_graceful_800.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm5_persistence_graceful'},
    gap=950000, port_first=59800, port_last=59800, **M5B)))
write('ctl_m5_persistence_rst_950.json', m5(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm5_persistence_rst'},
    port_first=59801, port_last=59801, **M5B)))
write('ctl_m5_loss_core_950.json', m5(transform(load('candidate57s_single_loss.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm5_loss_core'},
    port_first=59810, port_last=59816, **M5B)))
write('ctl_m5_reconnect_950.json', m5(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm5_reconnect_protected'},
    port_first=59820, port_last=59820, **M5B)))
write('ctl_m5_stale_tokens_950.json', m5(transform(load('candidate57s_old_tokens.json'),
    purpose={'purpose': 'stale_source_characterization', 'read_precision': False}, reads=1, trials=1,
    port_first=59821, port_last=59821, **M5B)))
held5 = m5(transform(load('candidate57s_dup_hold_350.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm5_held_operate'},
    gap=800000, port_first=59822, port_last=59822, held=True, **M5B), pb=360000000)
held5['timing_params_ns'].update(readiness=380000000, cap=400000000)
write('ctl_m5_held_operate_350.json', held5)
for pattern, fixture, port, purpose, label in (
        ('ctl_m5_qual_repeat_sbo_950_b%d.json', 'separate_ack', 59830, 'qualification', 'ctl_timing_m5_qual_%s_64'),
        ('ctl_m5_qual_piggyback_950_b%d.json', 'piggyback', 59840, 'qualification', 'ctl_timing_m5_qual_%s_64'),
        ('ctl_m5_char_repeat_sbo_950_b%d.json', 'separate_ack', 59860, 'timing_precision_characterization',
         'ctl_timing_m5_char_%s_64')):
    for filename, template, order, block in repeat_orders:
        write(pattern % block, m5(transform(load(template), purpose={'purpose': purpose, 'read_precision': True,
            'candidate61_label': label % fixture, 'block': block, 'arm_order': order}, arms=order,
            reads=65, trials=1, preset='shape_59570', gap=950000, port_first=port, port_last=port + 3,
            start_delay_ms=50, loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT,
            vision_run_dir=REPEAT_VISION_DIR, fixtures=[fixture], **M5B)))
for preset in ('shape_59570', 'shape_ack14892'):
    spec = SHAPE_PILOTS[preset]
    for filename, template, order, block in repeat_orders:
        data = m5(transform(load(template), purpose={'purpose': 'timing_precision_characterization', 'read_precision': True,
            'candidate61_label': 'm5_shaping_%s' % preset, 'block': block}, arms=['combined'],
            reads=65, trials=1, preset=preset if spec is None else 'shape_59570', gap=950000,
            port_first=59850, port_last=59853, start_delay_ms=50, loss_presets={}, sbo_cycles=64,
            endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR, fixtures=['separate_ack'], **M5B))
        if spec is not None:
            data['shaping']['presets'][preset] = dict(spec)
            data['shaping']['preset'] = preset
        write('ctl_m5_%s_b%d.json' % (preset, block), data)

# ctl_timing m9 (completion plan gate 4): the frozen candidate. The agreed recovery and repeated timing families
# only, same workloads, endpoints and templates as m5, on its own port range. No shaping or characterization twins.
M9_IDENTITY = {'source_sha256': M9_SOURCE_SHA, 'switch_compile': m9_switch,
               'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/DESIGN.md (m9)'}


def m9(data, pb=CTL_PB_NS):
    data['timing_params_ns']['pb'] = pb
    data['ctl_timing_identity'] = M9_IDENTITY
    return data


M9B = dict(build_name=M9_BUILD, build_spec=m9_build)
write('ctl_m9_persistence_graceful_950.json', m9(transform(load('candidate57s_graceful_800.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm9_persistence_graceful'},
    gap=950000, port_first=59880, port_last=59880, **M9B)))
write('ctl_m9_persistence_rst_950.json', m9(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm9_persistence_rst'},
    port_first=59881, port_last=59881, **M9B)))
write('ctl_m9_loss_core_950.json', m9(transform(load('candidate57s_single_loss.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm9_loss_core'},
    port_first=59882, port_last=59888, **M9B)))
write('ctl_m9_reconnect_950.json', m9(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm9_reconnect_protected'},
    port_first=59889, port_last=59889, **M9B)))
write('ctl_m9_stale_tokens_950.json', m9(transform(load('candidate57s_old_tokens.json'),
    purpose={'purpose': 'stale_source_characterization', 'read_precision': False}, reads=1, trials=1,
    port_first=59920, port_last=59920, **M9B)))
held9 = m9(transform(load('candidate57s_dup_hold_350.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm9_held_operate'},
    gap=800000, port_first=59890, port_last=59890, held=True, **M9B), pb=360000000)
held9['timing_params_ns'].update(readiness=380000000, cap=400000000)
write('ctl_m9_held_operate_350.json', held9)
for pattern, fixture, port, purpose, label in (
        ('ctl_m9_qual_repeat_sbo_950_b%d.json', 'separate_ack', 59900, 'qualification', 'ctl_timing_m9_qual_%s_64'),
        ('ctl_m9_qual_piggyback_950_b%d.json', 'piggyback', 59910, 'qualification', 'ctl_timing_m9_qual_%s_64')):
    for filename, template, order, block in repeat_orders:
        write(pattern % block, m9(transform(load(template), purpose={'purpose': purpose, 'read_precision': True,
            'candidate61_label': label % fixture, 'block': block, 'arm_order': order}, arms=order,
            reads=65, trials=1, preset='shape_59570', gap=950000, port_first=port, port_last=port + 3,
            start_delay_ms=50, loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT,
            vision_run_dir=REPEAT_VISION_DIR, fixtures=[fixture], **M9B)))

# m10 (review af7bd434, step 4): the recovery set on the exact m10_03 image, its own port range 59950-59960. The
# restart path (count_busy[5]) is judged from the snapshots: a block whose counter stays 0 did not exercise it.
M10_IDENTITY = {'source_sha256': M10_SOURCE_SHA, 'switch_compile': m10_switch,
                'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/generate.py (transform_n_m10)'}


def m10(data, pb=CTL_PB_NS):
    data['timing_params_ns']['pb'] = pb
    data['ctl_timing_identity'] = M10_IDENTITY
    return data


M10B = dict(build_name=M10_BUILD, build_spec=m10_build)
write('ctl_m10_persistence_graceful_950.json', m10(transform(load('candidate57s_graceful_800.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_persistence_graceful'},
    gap=950000, port_first=59950, port_last=59950, **M10B)))
write('ctl_m10_persistence_rst_950.json', m10(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_persistence_rst'},
    port_first=59951, port_last=59951, **M10B)))
write('ctl_m10_loss_core_950.json', m10(transform(load('candidate57s_single_loss.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_loss_core'},
    port_first=59952, port_last=59958, **M10B)))
write('ctl_m10_reconnect_950.json', m10(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_reconnect_protected'},
    port_first=59959, port_last=59959, **M10B)))
held10 = m10(transform(load('candidate57s_dup_hold_350.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_held_operate'},
    gap=800000, port_first=59960, port_last=59960, held=True, **M10B), pb=360000000)
held10['timing_params_ns'].update(readiness=380000000, cap=400000000)
write('ctl_m10_held_operate_350.json', held10)
# Step 4b, the bounded reset-interleaving block (rearm_01/hw/candidate_interleave.py): the probe tuple on addresses
# no Vision interface owns (TEST-NET-1, vision_contention.guard refuses otherwise), one master port, and the link
# addresses of the probe's own frames (contention_probe READ head 0x0000 <- 0x0100, the installer default), so the
# installed rows are exactly the probe's.
inter10 = m10(transform(load('candidate57s_rst_950.json'),
    purpose={'purpose': 'qualification', 'read_precision': True, 'candidate61_label': 'm10_reset_interleave'},
    reads=1, trials=1, port_first=59970, port_last=59970, **M10B))
inter10['endpoints'].update(master_ip='192.0.2.61', outstation_ip='192.0.2.62', outstation_port=20000,
                            read_dst=0x0000, read_src=0x0100,
                            link_note='read_dst 0x0000 <- read_src 0x0100: the link addresses of the probe frames '
                                      '(contention_probe READ head), not the OpenDNP3 outstation (10)')
inter10['interleave'] = {'master_mac': '02:00:00:00:00:61', 'outstation_mac': '02:00:00:00:00:62',
                         'next_hop_mac': '02:00:00:00:00:09',
                         '_note': 'plan from interleave_probe.build_interleave_plan; judged by judge_interleave'}
write('ctl_m10_interleave_950.json', inter10)

# Part 2 (ctl_timing_01/evidence/m10_03/PART2_DESIGN_20261018.md): the reconciled timing grid on the frozen m10_03
# build, PREPARED ONLY. Conditions and checks live in part2_grid.py. Per condition: three four-arm campaign blocks in
# the existing Latin rotation (repeat_orders; repeated-SBO workload, separate-ACK fixture) and two feasibility-gate
# blocks on the combined arm (a short persistent READ and a short repeated SBO). None of these configs is in
# freeze_v3's config set, so run_block_frozen.sh refuses them until a freeze names them. They are named part2_m10_*,
# not ctl_m10_*: ctl_m10_* are the supported-profile blocks (tests/test_supported_profile.py), and the grid departs
# from that profile on purpose.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import part2_grid  # noqa: E402
PART2_NOTE = ('Part 2 grid config (part2_grid.CONDITIONS; ctl_timing_01/evidence/m10_03/PART2_DESIGN_20261018.md): '
              'fixture delay 5 ms in every block; prepared only; not in freeze_v3, so run_block_frozen.sh refuses it.')
for i, (cond, da, gap, readiness) in enumerate(part2_grid.CONDITIONS):
    base = 60000 + 10 * i
    timing = part2_grid.params(da, gap, readiness)
    for filename, template, order, block in repeat_orders:
        data = m10(transform(load(template), purpose={'purpose': 'timing_precision_characterization',
            'read_precision': True, 'candidate61_label': 'm10_part2_%s' % cond, 'block': block, 'arm_order': order},
            arms=order, reads=65, trials=1, preset='shape_59570', gap=gap, readiness=readiness, port_first=base,
            port_last=base + 3, start_delay_ms=50, loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT,
            vision_run_dir=REPEAT_VISION_DIR, fixtures=['separate_ack'], **M10B), pb=timing['pb'])
        data['timing_params_ns'].update(timing)
        data['fixture']['delay_ms'] = part2_grid.FIXTURE_L_NS // part2_grid.MS   # one L for every block (review C1)
        data['_notes'] = notes + [PART2_NOTE]   # the template's block notes (3/8 ms, 500 READs) no longer apply
        data['part2'] = {'condition': cond, 'role': 'campaign', 'grid': 'part2_grid.CONDITIONS'}
        write('part2_m10_%s_b%d.json' % (cond, block), data)
    feas_read = m10(transform(load('candidate57s_graceful_800.json'), purpose={'purpose': 'timing_precision_characterization',
        'read_precision': True, 'candidate61_label': 'm10_part2_feas_read_%s' % cond}, arms=['combined'], reads=20,
        trials=1, gap=gap, readiness=readiness, port_first=base + 4, port_last=base + 4, run_sbo=False,
        **M10B), pb=timing['pb'])
    feas_read['timing_params_ns'].update(timing)
    feas_read['fixture']['delay_ms'] = part2_grid.FIXTURE_L_NS // part2_grid.MS
    feas_read['_notes'] = notes + [PART2_NOTE]   # the template's block notes (3/8 ms, 500 READs) no longer apply
    feas_read['part2'] = {'condition': cond, 'role': 'feasibility_read', 'grid': 'part2_grid.CONDITIONS'}
    write('part2_m10_feas_read_%s.json' % cond, feas_read)
    feas_sbo = m10(transform(load(repeat_orders[0][1]), purpose={'purpose': 'timing_precision_characterization',
        'read_precision': True, 'candidate61_label': 'm10_part2_feas_sbo_%s' % cond}, arms=['combined'], reads=21,
        trials=1, preset='shape_59570', gap=gap, readiness=readiness, port_first=base + 5, port_last=base + 5,
        start_delay_ms=50, loss_presets={}, sbo_cycles=20, endpoint=REPEAT_ENDPOINT, vision_run_dir=REPEAT_VISION_DIR,
        fixtures=['separate_ack'], **M10B), pb=timing['pb'])
    feas_sbo['timing_params_ns'].update(timing)
    feas_sbo['fixture']['delay_ms'] = part2_grid.FIXTURE_L_NS // part2_grid.MS
    feas_sbo['_notes'] = notes + [PART2_NOTE]   # the template's block notes (3/8 ms, 500 READs) no longer apply
    feas_sbo['part2'] = {'condition': cond, 'role': 'feasibility_sbo', 'grid': 'part2_grid.CONDITIONS'}
    write('part2_m10_feas_sbo_%s.json' % cond, feas_sbo)

# ACK-delay localization (ctl_timing_01/evidence/m9d_01/ACK_DIAG_PLAN_20261017.md): six predefined blocks, the
# qualification repeated-SBO workload and arm orders, purpose characterization so every arm runs. Three on m9_01 (the
# control) and three on the m9d diagnostic build (m9 + E egress timestamps), each pair on its own port range.
m9d_build = dict(make_build(
    'candidate61', M9D_SOURCE_SHA, m9d_switch, 61, True,
    'DIAGNOSTIC ctl_timing_01 m9d: m9 plus E egress-parser timestamps of master-bound ACKs and responses '
    '(generate.transform_e_diag); never a candidate.'),
    control_timed=True, piggyback_bound=True)
M9D_IDENTITY = {'source_sha256': M9D_SOURCE_SHA, 'switch_compile': m9d_switch,
                'design': 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/m9d_01/ACK_DIAG_PLAN_20261017.md'}


def m9d(data, pb=CTL_PB_NS):
    data['timing_params_ns']['pb'] = pb
    data['ctl_timing_identity'] = M9D_IDENTITY
    return data


for pattern, wrap, spec, port in (('ctl_m9_ackdiag_ctrl_b%d.json', m9, M9B, 59930),
                                  ('ctl_m9d_ackdiag_b%d.json', m9d, dict(build_name=M9D_BUILD, build_spec=m9d_build), 59940)):
    for filename, template, order, block in repeat_orders:
        write(pattern % block, wrap(transform(load(template), purpose={'purpose': 'timing_precision_characterization',
            'read_precision': True, 'candidate61_label': pattern[:-len('_b%d.json')],
            'block': block, 'arm_order': order}, arms=order,
            reads=65, trials=1, preset='shape_59570', gap=950000, port_first=port, port_last=port + 3,
            start_delay_ms=50, loss_presets={}, sbo_cycles=64, endpoint=REPEAT_ENDPOINT,
            vision_run_dir=REPEAT_VISION_DIR, fixtures=['separate_ack'], **spec)))

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

print('wrote', sum(len(list(DST.glob(g))) for g in ('candidate61_*.json', 'strict_comparison_*.json', 'ctl_timing_*.json', 'ctl_m4_*.json',
                                                 'ctl_m5_*.json', 'ctl_m9_*.json', 'ctl_m9d_*.json', 'ctl_m10_*.json', 'part2_m10_*.json')),
      'configs to', DST)
