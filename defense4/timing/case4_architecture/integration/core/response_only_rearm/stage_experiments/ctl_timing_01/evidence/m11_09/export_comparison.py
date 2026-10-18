"""Export this bounded compiler comparison from retained SDK outputs; no hardware actions."""
import csv
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CT = HERE.parents[1]
sys.path.insert(0, str(CT))
import resource_review as review

BUILDS = ('m10_03', 'm11_corrected_01', 'probe_n_zero_timestamp_m11_01',
          'probe_t_single_child_m11_05', 'probe_t_outcome_direct_m11_01',
          'probe_n_relax_crc_stage_m11_02', 'm11_05',
          'probe_n_tail_parallel_m11_01', 'probe_t_resp_done_fused_m11_01',
          'probe_t_resp_reads_exclusive_m11_01', 'm11_08', 'm11_09')
BOTH_SDK_BUILDS = set(BUILDS[:7]) | {'m11_09'}
ROLES = {'N': ('p0', 'ingress'), 'E': ('p0', 'egress'), 'T': ('p1', 'ingress')}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    reports = {}
    output = HERE / 'compiler_reports'
    output.mkdir(exist_ok=True)
    rows = []
    for build in BUILDS:
        report = review.review(CT / 'evidence' / build)
        assert report['source_matches_compiles'], build
        for sdk, compiled in report['compiles'].items():
            if compiled.get('present') is False:
                assert build not in BOTH_SDK_BUILDS, (build, sdk, 'required compile missing')
                continue
            assert compiled['exit_code'] == 0 and compiled['mirror_guard'].startswith('PASS'), (build, sdk)
            for role, (pipe, direction) in ROLES.items():
                placement = compiled['placement'][role]
                pressure = compiled['resources'][pipe]['phv'][direction]
                rows.append(dict(build=build, sdk=sdk, role=role, pipeline=pipe, direction=direction,
                    occupied_indices=' '.join(map(str, placement['occupied_indices'])),
                    occupied_count=placement['occupied_count'], stage_span=placement['stage_span'],
                    maximum_stage=placement['maximum_occupied_stage'],
                    **compiled['resources'][pipe]['attributed'][direction], **pressure))
        reports[build] = report
        write_json(output / (build + '.json'), report)
    with (HERE / 'compiler_table.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    baseline, selected = reports['m10_03'], reports['m11_09']
    comparison = dict(baseline_build='m10_03', candidate_build='m11_09',
        baseline_source_sha256=baseline['candidate_sha256'], candidate_source_sha256=selected['candidate_sha256'],
        stage_reduction_demonstrated=False,
        independent_probe_sdk_note='T06/T07 retain local SDK evidence only; other probes include every actual finished successful SDK compile. Absent compiles produce no CSV rows.',
        table_note='Direction-attributed physical units; shared/unattributed pipeline units and mirror resources '
                   'remain separately reported in compiler_reports. PHV capacity is allocated container capacity.',
        generation_command='python3 ' + str(Path(__file__).resolve().relative_to(CT.parents[7])),
        exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), compiles={})
    for sdk, new in selected['compiles'].items():
        old = baseline['compiles'][sdk]
        comparison['stage_reduction_demonstrated'] |= any(new['stages'][role] < old['stages'][role]
                                                          for role in ROLES)
        deltas = {}
        for pipe, resources in new['resources'].items():
            before = old['resources'][pipe]
            deltas[pipe] = dict(
                pipeline_totals={k: v - before['pipeline_totals'][k]
                                 for k, v in resources['pipeline_totals'].items()},
                attributed={direction: {k: v - before['attributed'][direction][k] for k, v in values.items()}
                            for direction, values in resources['attributed'].items()},
                phv={direction: {k: v - before['phv'][direction][k] for k, v in values.items()}
                     for direction, values in resources['phv'].items()})
        comparison['compiles'][sdk] = dict(compiler=new['compiler'], stages=new['stages'],
            baseline_stages=old['stages'], mirror_guard=new['mirror_guard'], resource_delta=deltas)
    comparison['rejected_probes'] = [
        dict(probe='E reverse-window', status='stopped_before_compile',
             reason='Actual img_wend9 -> classify_rev10 -> window11 remains after early arithmetic reassociation.'),
        dict(build='probe_t_outcome_direct_m11_01', reason='T11 unchanged on both SDKs; SRAM -1, PHV capacity +16 bits, crossbar +1 byte.'),
        dict(build='probe_n_relax_crc_stage_m11_02', reason='N12 unchanged on both SDKs; crossbar +3 bytes.')]
    for build, label, reason in (
        ('probe_n_tail_fused_m11_01', 'N01', 'Rejected local compile: first_event attached count_first and count_term with incompatible indirect-extern address/call expressions; no placement result.'),
        ('probe_t_resp_done_fused_m11_01', 'T06', 'Rejected for stage-cut selection: fused response-go/resp_done access still occupies eleven T stages on the local SDK.'),
        ('probe_t_resp_reads_exclusive_m11_01', 'T07', 'Rejected for stage-cut selection: mutually exclusive done reads still occupy eleven T stages on the local SDK.'),
        ('m11_08', 'T08', 'Rejected for stage-cut selection: eleven T stages remain; stage-8 placement log records held_verdict instruction-memory failures after hb_verdict placement.')):
        root = CT / 'evidence' / build
        manifest = root / 'compile_local/manifest.json'
        recorded = json.loads(manifest.read_text())
        evidence = {'manifest': str(manifest.relative_to(CT)),
                    'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
                    'source_sha256': recorded['source_sha256'], 'exit_code': recorded['exit_code']}
        paths = [root / 'compile_local/compile.log']
        paths += [root / 'compile_local/out/p1/context.json', root / 'compile_local/out/p1/response_only.bfa']
        if label == 'T08':
            paths += sorted((root / 'compile_local/out/p1/logs').glob('table_placement_*.log'))
        evidence['files'] = {str(p.relative_to(CT)): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in paths if p.is_file()}
        if label == 'T08':
            evidence['local_isolation_source'] = 'evidence/probe_t_held_single_keys_m11_01/response_only.p4'
        if build in reports:
            evidence['stages'] = reports[build]['compiles']['compile_local']['stages']
        comparison['rejected_probes'].append(dict(build=build, label=label, reason=reason, evidence=evidence))
    comparison['selected_stage_cut_probe'] = dict(build='probe_n_tail_parallel_m11_01', label='N02',
        reason='Separate two-row input-keyed retry counter plus high-byte event increment remove the dependent N tail stage.',
        source_sha256=reports['probe_n_tail_parallel_m11_01']['candidate_sha256'],
        local_stages=reports['probe_n_tail_parallel_m11_01']['compiles']['compile_local']['stages'])
    comparison['superseded'] = [
        dict(build='probe_n_relax_crc_stage_m11_01', reason='Withdrawn uncompiled: removed multiple scheduling pins.'),
        dict(build='probe_t_single_child_m11_01 / m11_01', reason='Returned ladder IDs lacked explicit validation.'),
        dict(build='probe_t_single_child_m11_02 / m11_02', reason='Parser-only rejection still executes T control; m11_02 target model failed 20/211 cases.'),
        dict(build='probe_t_single_child_m11_04 / m11_04', reason='Parser-error gateway still permits the same twenty invalid-ID counter side effects; final05 uses direct header-ID control checks.'),
        dict(build='probe_t_single_child_m11_03 / m11_03', reason='Both SDKs reject comparison of bit16 parser_err with error.NoError; corrected to 16w0 in fresh04 sources.')]
    write_json(HERE / 'compiler_comparison.json', comparison)
    print('Exported %d build/SDK/role rows; final placement %s' % (len(rows), selected['compiles']['compile_local']['stages']))


if __name__ == '__main__':
    main()
