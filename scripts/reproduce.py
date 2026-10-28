#!/usr/bin/env python3
"""Recompile the selected current source and replay only its retained qualification evidence."""
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path, help='explicit results/builds candidate directory')
    parser.add_argument('--hardware-index', type=Path, help='explicit index of the new current hardware matrix')
    parser.add_argument('--output', type=Path, help='new reproduction report; existing reports are never overwritten')
    args = parser.parse_args()
    selected = args.build.resolve()
    selected.relative_to(ROOT / 'results/builds')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report_path = args.output or ROOT / 'results/analysis/reproduction' / (selected.name + '_' + stamp + '.json')
    if report_path.exists():
        raise SystemExit('reproduction evidence must not be overwritten: ' + str(report_path))
    package = load('current_source_package', ROOT / 'scripts/profile.py')
    compiler = load('current_compile_evidence', ROOT / 'scripts/build.py')
    report = dict(build=str(selected.relative_to(ROOT)), hardware_contact=False,
                  qualification='failed', hardware='not_requested')
    status = 1
    try:
        report['package'] = package.verify_package(selected)
        if not all(report['package'].values()):
            raise ValueError('selected source package does not verify')
        source_sha = package.sha(ROOT / 'p4/response_only.p4')
        if package.sha(selected / 'response_only.p4') != source_sha:
            raise ValueError('selected build is not the canonical current P4')
        report['source_sha256'] = source_sha
        report['original_compile'] = compiler.restore_evidence(selected / 'compile_local', source_root=selected)
        original = json.loads((selected / 'compile_local/manifest.json').read_text())
        fresh = ROOT / 'results/builds' / (selected.name + '_reproduce_' + stamp)
        package.package(fresh)
        command = original.get('command', [])
        result = compiler.compile_candidate(fresh / 'response_only.p4', fresh / 'compile_local',
            defines=[value[2:] for value in command if value.startswith('-D')],
            event_logger='-Xp4c=--enable-event-logger' in command,
            parser_debug='-Xp4c=-Tlower_parser:5' in command)
        report['fresh_build'] = str(fresh.relative_to(ROOT))
        report['compile_exit_code'] = result['exit_code']
        if result['exit_code'] != 0:
            raise ValueError('fresh canonical compilation failed')
        package.record_artifacts(fresh)
        resources = load('current_resource_compare', ROOT / 'scripts/analysis/resource_compare.py')
        before, after = resources.measure(selected), resources.measure(fresh)
        comparisons = {}
        for pipe, expected in before['pipes'].items():
            actual = after['pipes'][pipe]
            comparisons[pipe] = {field: actual[field] == expected[field] for field in
                ('stages', 'allocated_mau_totals', 'phv_usage', 'stateful_tables')}
        report['resource_comparison'] = comparisons
        report['stages'] = {pipe: values['stages'] for pipe, values in after['pipes'].items()}
        if not all(value for pipe in comparisons.values() for value in pipe.values()):
            raise ValueError('fresh compiler resource result differs from the selected candidate')
        sys.path.insert(0, str(ROOT / 'scripts/model'))
        import model_summary
        model = model_summary.summarize_v3(selected)
        report['model'] = dict(qualification=model['qualification'],
            latest_by_driver=model['latest_by_driver'], blocked_reasons=model['blocked_reasons'])
        if model['qualification'] != 'model_gate_passed':
            raise ValueError('selected current model gate did not reproduce')
        if args.hardware_index:
            index = args.hardware_index.resolve()
            index.relative_to(ROOT / 'results/hardware')
            replay = subprocess.run([sys.executable, str(ROOT / 'scripts/checks/replay.py'), str(index)],
                                    cwd=str(ROOT), capture_output=True, text=True)
            report['hardware_index'] = str(index.relative_to(ROOT))
            report['hardware_replay_exit_code'] = replay.returncode
            report['hardware_replay_output'] = replay.stdout
            report['hardware_replay_error'] = replay.stderr
            if replay.returncode != 0:
                raise ValueError('selected current hardware evidence did not reproduce')
            report['hardware'] = 'recorded_verdicts_reproduced'
        report['qualification'] = ('current_evidence_reproduced' if args.hardware_index
                                   else 'offline_evidence_reproduced')
        status = 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['error'] = str(error)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'report': str(report_path), 'qualification': report['qualification'],
                      'hardware': report['hardware'], 'error': report.get('error')}, indent=2))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
