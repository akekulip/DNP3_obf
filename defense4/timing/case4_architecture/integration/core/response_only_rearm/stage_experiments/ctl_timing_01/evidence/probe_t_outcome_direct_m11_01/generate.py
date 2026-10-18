"""Generate bounded, source-pinned successors of m10 without changing frozen evidence.

  python3 efficiency_candidates.py OUTPUT [--probe t_single_child] [--probe n_zero_timestamp]
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE / 'evidence/m10_03'
BASE_SHA = 'd9b84fcc7ecb1dded4e7fddf47a1e74da568c9b4159c0065e4e780c38d49b5dc'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


retained = load('retained_efficiency_probes', HERE / 'efficiency_probes_m9/probe_candidates.py')
combined = load('efficiency_segments', HERE.parent / 'combined_nt_01/generate.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixed_retry(source):
    """Response retries have no reset lap count; validate them before parsing state inputs."""
    source = retained.once(source, '16w0x0400:retry_input;', '16w0x0400:response_retry_reserved;')
    return retained.once(source, ' state retry_input{',
        ' state response_retry_reserved{transition select(hdr.event.reserved){16w0:retry_input;default:reject;}}\n'
        ' state retry_input{')


def t_outcome_direct(source):
    """Remove the late identity lookup; retain one guarded call to the same indexed 32-bit counter."""
    start = source.index('    action bump(bit<5> idx) { bump_outcome.execute(idx); }')
    end = source.index('    // ---- request admission', start)
    old = source[start:end]
    if 'table outcome_count {' not in old or '23 : bump(23); 24 : bump(24);' not in old:
        raise ValueError('unexpected outcome counter baseline')
    source = retained.once(source, old,
        '    action bump_current_outcome() { bump_outcome.execute((bit<5>)md.outcome_code); }\n\n')
    return retained.once(source, '        outcome_count.apply();',
        '        if (md.outcome_code <= 8w16 || md.outcome_code == 8w23 || md.outcome_code == 8w24) {\n'
        '            bump_current_outcome();\n'
        '        }')


def n_relax_crc_stage(source):
    """Release CRC-only stage pins; retain the compiler's data dependencies and every stateful statement."""
    for stage, table in ((1, 'crc_t'), (2, 'input_tail_t'), (2, 'response_crct_t'),
                         (2, 'rd_second_crc_t'), (2, 'rd_request_crc_t'), (2, 'rd_tail_crc_t')):
        source = retained.once(source, '@stage(%d) table %s' % (stage, table), 'table %s' % table)
    return source


PROBES = {'t_single_child': retained.t_single_child,
          'n_zero_timestamp': retained.n_zero_unused_timestamp,
          't_outcome_direct': t_outcome_direct,
          'n_relax_crc_stage': n_relax_crc_stage}


def source_for(probes=()):
    source = (BASE / 'response_only.p4').read_text()
    if digest(source.encode()) != BASE_SHA:
        raise ValueError('frozen m10 source differs from the reviewed identity')
    source = fixed_retry(source)
    for name in probes:
        source = PROBES[name](source)
    return source


def generate(output, probes=()):
    if len(set(probes)) != len(probes):
        raise ValueError('a transform must be applied exactly once')
    source = source_for(probes)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'response_only.p4').write_text(source)
    segments = {role: digest(combined.segment(source, role).encode()) for role in ('N', 'E', 'T')}
    inputs = json.loads((BASE / 'response_only.inputs.json').read_text())
    profile = copy.deepcopy(json.loads((HERE / 'supported_profile.json').read_text()))
    profile.update(reset_restart_required=True, t_child_count=1 if 't_single_child' in probes else 3)
    profile['candidate'] = dict(build=str(output), milestone='m11', source_sha256=digest(source.encode()),
                                segment_sha256=segments, artifact_sha256={})
    inputs.update(source_sha256=digest(source.encode()), segment_sha256=segments, milestone='m11',
                  changed_roles=[role for role in ('N', 'E', 'T')
                                 if segments[role] != json.loads((BASE / 'response_only.inputs.json').read_text())['segment_sha256'][role]],
                  generator_sha256=digest(Path(__file__).read_bytes()),
                  supported_profile=profile,
                  successor_of=dict(path=str(BASE), source_sha256=BASE_SHA),
                  transforms=['response_retry_reserved_zero'] + list(probes))
    (output / 'response_only.inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (output / 'supported_profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    (output / 'generate.py').write_bytes(Path(__file__).read_bytes())
    return inputs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--probe', action='append', choices=sorted(PROBES), default=[])
    args = parser.parse_args()
    result = generate(args.output, args.probe)
    print(json.dumps({key: result[key] for key in ('source_sha256', 'segment_sha256', 'transforms')}))
