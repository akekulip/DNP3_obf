"""Generate bounded, source-pinned successors of m10 without changing frozen evidence.

  python3 efficiency_candidates.py OUTPUT [--probe t_single_child] [--probe n_zero_timestamp]
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import re
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


def t_single_child(source):
    """Use one bank and reject unsupported response/event and recirculated ladder child IDs before control."""
    source = retained.t_single_child(source)
    source = retained.once(source,
        '        pkt.extract(hdr.ladder); md.packet_epoch = hdr.ladder.budget;\n'
        '        transition select(hdr.ladder.role) {',
        '        pkt.extract(hdr.ladder); md.packet_epoch = hdr.ladder.budget;\n'
        '        transition select(hdr.ladder.child) { 0: single_ladder_role; default: reject; }\n'
        '    }\n'
        '    state single_ladder_role {\n'
        '        transition select(hdr.ladder.role) {')
    # Explicit parser reject still executes ingress with parser_err=0 on the compiled target (m11_04).
    # Validate the extracted IDs directly before every register/counter operation.
    control = retained.block(source, 'control t_Ingress(')
    original = retained.block(control, '    apply {')
    body = original[len('    apply {'):-1]
    guarded = ('    apply {\n'
               '        if ((!hdr.ladder.isValid() || hdr.ladder.child == 0) &&\n'
               '            (!hdr.tev.isValid() || hdr.tev.kind != t_KIND_RESPONSE || hdr.tev.stage == 0)) {' + body + '\n'
               '        } else {\n'
               '            ig_tm_md.bypass_egress = 0;\n'
               '            ig_dprsr_md.drop_ctl = 1; ig_dprsr_md.mirror_type = t_MIRROR_TYPE_CLONE;\n'
               '            md.clone_ses = t_NO_MIRROR_SESSION;\n'
               '        }\n'
               '    }')
    return retained.once(source, control, retained.once(control, original, guarded))


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



def t_resp_done_fused(source):
    """Select the response register read/commit in the go table, avoiding a later go-flag consumer."""
    old_register = retained.block(source,
        '    RegisterAction<bit<32>, bit<1>, bit<32>>(resp_done_reg) resp_done_try = {')
    new_register = retained.once(old_register, 'resp_done_try = {', 'resp_done_commit = {')
    new_register = retained.once(new_register,
        '            if (md.resp_go == 1) { value = md.cur_gen; }',
        '            value = md.cur_gen;')
    source = retained.once(source, old_register, new_register)
    source = retained.once(source,
        '    action try_resp_done() { md.done_diff = resp_done_try.execute(0); }\n', '')
    source = retained.once(source,
        '    action set_resp_go(bit<8> v) { md.resp_go = v; }',
        '    action response_done_read() { md.resp_go = 0; md.done_diff = resp_done_read.execute(0); }\n'
        '    action response_done_commit() { md.resp_go = 1; md.done_diff = resp_done_commit.execute(0); }')
    old_table = retained.block(source, '    table resp_go_check {')
    new_table = retained.once(old_table, 'actions = { set_resp_go; }',
                              'actions = { response_done_read; response_done_commit; }')
    if new_table.count('set_resp_go(0)') != 3 or new_table.count('set_resp_go(1)') != 3:
        raise ValueError('unexpected response-go rows/default')
    new_table = new_table.replace('set_resp_go(0)', 'response_done_read()')
    new_table = new_table.replace('set_resp_go(1)', 'response_done_commit()')
    source = retained.once(source, old_table, new_table)
    return retained.once(source,
        '                resp_go_check.apply();\n                try_resp_done();',
        '                resp_go_check.apply();')


def n_relax_crc_stage(source):
    """Release only crc_t's stage-1 pin; retain all other CRC placement and state/data dependencies."""
    return retained.once(source, '@stage(1) table crc_t', 'table crc_t')


def n_tail_fused(source):
    """Count the two retried duplicate verdicts directly and advance only the independent event byte."""
    table = retained.block(source, ' table first_event{')
    pattern = re.compile(r'(\([^()]+\)):(\w+)\(([^()]*)\);')
    rows = pattern.findall(table)
    if len(rows) != 161:
        raise ValueError('unexpected first-event row set')
    retry_rows = [row for row in rows if row[1] == 'forward_original'
                  and row[0].startswith(('(8w6,', '(8w11,'))]
    if len(retry_rows) != 2:
        raise ValueError('expected exactly the two response retry verdicts')
    rewritten = retained.once(table, 'm.new_seq:ternary;m.same_syn:ternary;}',
                              'm.new_seq:ternary;m.same_syn:ternary;m.retry:ternary;}')
    rewritten = retained.once(rewritten, 'forward_original;first_operate_dup;',
                              'forward_original;forward_retry_duplicate;first_operate_dup;')
    rewritten = pattern.sub(lambda match: match[1][:-1] + ',_):' + match[2] + '(' + match[3] + ');', rewritten)
    overrides = ''.join(row[0][:-1] + ',2w1):forward_retry_duplicate();' for row in retry_rows)
    rewritten = retained.once(rewritten, 'const entries={', 'const entries={' + overrides)
    source = retained.once(source, table, rewritten)
    source = retained.once(source, ' action forward_original(){hdr.event.event=16w0x0108;}',
        ' action forward_original(){hdr.event.event=16w0x0108;}\n'
        ' action forward_retry_duplicate(){hdr.event.event=16w0x01ff;hdr.t0.setInvalid();count_retry_duplicate();}')
    source = retained.once(source,
        'table retry_dup_t{actions={count_retry_duplicate;}size=1;const default_action=count_retry_duplicate();}\n', '')
    source = retained.once(source,
        'if(m.retry==2w1&&hdr.event.event==16w0x0108){hdr.event.event[7:0]=8w255;hdr.t0.setInvalid();retry_dup_t.apply();}', '')
    source = retained.once(source, 'action next_stage(){hdr.event.event=hdr.event.event+16w0x100;',
                              'action next_stage(){hdr.event.event[15:8]=hdr.event.event[15:8]+8w1;')
    source = retained.once(source,
        'else if(m.work_phase==32w1||m.work_phase==32w2){\n     if(m.epoch_diff',
        'else if(m.work_phase==32w1||m.work_phase==32w2){\n     next_stage_t.apply();\n     if(m.epoch_diff')
    return retained.once(source, '\n     next_stage_t.apply();\n    }else if(m.work_phase==32w3)',
                                  '\n    }else if(m.work_phase==32w3)')


PROBES = {'t_single_child': t_single_child,
          'n_zero_timestamp': retained.n_zero_unused_timestamp,
          't_outcome_direct': t_outcome_direct,
          't_resp_done_fused': t_resp_done_fused,
          'n_relax_crc_stage': n_relax_crc_stage,
          'n_tail_fused': n_tail_fused}


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


def record_artifacts(output):
    """Pin both verified compiler outputs in this successor's existing supported profile."""
    from model_profile import resolve
    output = Path(output).resolve()
    inputs_path, profile_path = output / 'response_only.inputs.json', output / 'supported_profile.json'
    inputs = json.loads(inputs_path.read_text())
    profile = inputs.get('supported_profile')
    if not isinstance(profile, dict) or profile != json.loads(profile_path.read_text()):
        raise ValueError('inline and per-build supported profiles must agree')
    resolve(inputs, output / 'response_only.p4')
    source_sha = digest((output / 'response_only.p4').read_bytes())
    required = {'bfrt.json', 'p0/context.json', 'p0/response_only.bfa', 'p0/tofino.bin',
                'p1/context.json', 'p1/response_only.bfa', 'p1/tofino.bin', 'response_only.conf'}
    pins = {}
    for name, version in (('compile_local', '9.13.1'), ('compile_switch_9132', '9.13.2')):
        compiled = output / name
        manifest = json.loads((compiled / 'manifest.json').read_text())
        if manifest.get('exit_code') != 0 or manifest.get('source_sha256') != source_sha:
            raise ValueError('%s is not a successful compile of this source' % name)
        if not re.match(r'^p4c\s+' + re.escape(version) + r'(?:\s|$)', manifest.get('compiler', '')):
            raise ValueError('%s must use SDK %s' % (name, version))
        artifacts = manifest.get('artifact_sha256')
        if not isinstance(artifacts, dict) or not required <= set(artifacts):
            raise ValueError('%s lacks the required compiler artifact inventory' % name)
        out = (compiled / 'out').resolve()
        for artifact, expected in artifacts.items():
            path = (out / artifact).resolve()
            try:
                path.relative_to(out)
            except ValueError:
                raise ValueError('artifact path escapes compiler output: %s' % artifact)
            if digest(path.read_bytes()) != expected:
                raise ValueError('%s artifact mismatch: %s' % (name, artifact))
        pins[name] = dict(artifacts, **{'response_only.p4pp': digest((out / 'response_only.p4pp').read_bytes())})
    profile['candidate']['artifact_sha256'] = pins
    inputs_path.write_text(json.dumps(inputs, indent=2) + '\n')
    profile_path.write_text(json.dumps(profile, indent=2) + '\n')
    return inputs


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--probe', action='append', choices=sorted(PROBES), default=[])
    parser.add_argument('--record-artifacts', action='store_true',
                        help='verify both compiler results and refresh this existing build profile')
    args = parser.parse_args()
    if args.record_artifacts and args.probe:
        parser.error('--record-artifacts cannot be combined with --probe')
    result = record_artifacts(args.output) if args.record_artifacts else generate(args.output, args.probe)
    print(json.dumps({key: result[key] for key in ('source_sha256', 'segment_sha256', 'transforms')}))
