#!/usr/bin/env python3
"""Replay an explicit current matrix index offline; retained inputs are never overwritten."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE.parent / 'hardware'), str(HERE)]
import campaign
import campaign_base as base
import evaluation_campaign
import persistence
import standards

SCHEMA = 'current-hardware-index-v1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def local(path, repository_root):
    value = Path(path)
    if value.is_absolute():
        value = value.relative_to(repository_root)
    if '..' in value.parts:
        raise ValueError('index path escapes the current checkout')
    return ROOT / value


def matrix(path, repository_root=ROOT):
    value = read(path)
    for step in value.get('steps', []):
        step['run_root'] = str(local(step['run_root'], repository_root))
        for index in (1, 2, 4):
            step['argv'][index] = str(local(step['argv'][index], repository_root))
    evaluation_campaign.validate_manifest(value)
    if value['evidence_kind'] != 'hardware' or len(value['steps']) != 10 or value.get('expected_exchanges') != 2440:
        raise ValueError('index requires the fixed current 10-block/2440 matrix')
    if sum(step.get('expected_exchanges', 0) for step in value['steps']) != 2440:
        raise ValueError('matrix exchange denominators differ')
    return value


def index_matrix(path, repository_root=ROOT):
    path = Path(path).resolve()
    value = matrix(path, repository_root)
    files = {str(path.relative_to(ROOT)): sha(path)}
    for step in value['steps']:
        config = Path(step['argv'][4]).resolve()
        files[str(config.relative_to(ROOT))] = sha(config)
        root = Path(step['run_root']).resolve()
        if not (root / 'campaign_run.json').is_file() or not (root / 'restore_verify.json').is_file():
            raise ValueError('incomplete current block: ' + str(root))
        for item in root.rglob('*'):
            if item.is_symlink():
                raise ValueError('indexed evidence must not contain symlinks')
            if item.is_file():
                files[str(item.relative_to(ROOT))] = sha(item)
    return dict(schema=SCHEMA, repository_root=str(repository_root),
                matrix_manifest=str(path.relative_to(ROOT)), files=files)


class OfflineRunner:
    dry = False

    def run(self, *args, **kwargs):
        raise AssertionError('hardware command attempted during offline replay')


def owner(step):
    argv = step['argv']
    if len(argv) < 6 or argv[3] not in ('campaign', 'persistence'):
        raise ValueError('unsupported current block entrypoint')
    config = argv[4]
    cfg = base.load_config(config)
    options, kwargs = argv[6:], {}
    for option, key in (('--loss', 'loss'), ('--scenario', 'scenario'), ('--close-mode', 'close_mode'), ('--rst-grace-ms','rst_grace_ms')):
        if option in options:
            kwargs[key] = int(options[options.index(option) + 1]) if key == 'rst_grace_ms' else options[options.index(option) + 1]
    cls = persistence.CandidateSeriesCampaign if argv[3] == 'persistence' else campaign.CandidateCampaign
    result = cls(cfg, base.DryRunner(), argv[5], config_path=config, **kwargs)
    result.rn = OfflineRunner()
    result.record = read(Path(step['run_root']) / 'campaign_run.json')
    result.bound = result.record['builds']
    if result.record['run_id'] != argv[5] or result.record.get('config_file_sha256') != sha(config):
        raise ValueError('recorded run/config identity differs from the matrix')
    return result


def replay_trial(engine, unit, source):
    source = Path(source)
    original = read(source / 'trial.json')
    arm, fixture = unit['arm'], unit['fixture']
    connections = ('c1', 'c2', 'c3') if engine.scenario or isinstance(
        engine, persistence.CandidateSeriesCampaign) else ('single',)
    for name in connections:
        directory = source if name == 'single' else source / name
        port = original['master_port'] + (engine.cfg['scenarios']['reconnect']['reconnect_port_offset']
                                          if name == 'c2' and engine.scenario else 0)
        context = engine.standards_context(original, arm, None if name == 'single' else name,
                                           name == 'c2' and engine.scenario == 'reconnect')
        context['master_port'] = port
        captures = engine.standards_captures(str(directory), {})
        derived = standards.validate_standards(directory / 'standards.json', context, captures)
        if derived != read(directory / 'standards_verdict.json'):
            raise ValueError(str(directory) + ': standards verdict does not reproduce exactly')
    with tempfile.TemporaryDirectory(prefix='dnp3_current_replay_') as temporary:
        dest = Path(temporary) / 'trial'
        shutil.copytree(source, dest)
        trial = copy.deepcopy(original)
        endpoint = read(dest / 'result.json')
        vision = base.Result(0 if endpoint.get('ok') is True else 1, json.dumps(endpoint), '')
        try:
            if engine.scenario:
                engine.verdict_scenario(trial, trial['label'], str(dest), vision, arm)
            elif engine.loss_preset:
                engine.verdict_loss(trial, {}, trial['label'], str(dest), vision, arm, fixture,
                                    unit, trial['master_port'])
            else:
                engine.verdict(trial, {}, trial['label'], str(dest), vision, arm, fixture)
        except base.StepFailed:
            pass  # A recorded FAIL is reproducible; its verdict still has to match.
        for key in ('ok', 'dimension_verdicts', 'observed'):
            if trial.get(key) != original.get(key):
                raise ValueError(str(source) + ': ' + key + ' does not reproduce exactly')
    return sum(standards.expected_counts(engine.standards_context(original, arm)).values()) * len(connections)


def replay_index(path):
    report = dict(ok=False, hardware_contact=False, status='not_reproduced', failures=[], exchanges=0)
    try:
        index = read(path)
        if index.get('schema') != SCHEMA or not index.get('files'):
            raise ValueError('missing or unsupported current hardware index')
        for filename, digest in index['files'].items():
            if sha(local(filename, ROOT)) != digest:
                raise ValueError('indexed input changed: ' + filename)
        manifest = local(index['matrix_manifest'], ROOT)
        if str(manifest.relative_to(ROOT)) not in index['files']:
            raise ValueError('matrix manifest is not bound by the index')
        repository_root = Path(index['repository_root'])
        value = matrix(manifest, repository_root)
        if index_matrix(manifest, repository_root)['files'] != index['files']:
            raise ValueError('current index does not bind the complete explicit matrix input set')
        for step in value['steps']:
            engine = owner(step)
            restoration = read(Path(step['run_root']) / 'restore_verify.json')
            if restoration.get('ok') is not True:
                raise ValueError('restoration was not verified for ' + step['id'])
            block_count = 0
            for unit in engine.units():
                label = engine.label(unit)
                source = Path(step['run_root']) / unit['fixture'] / unit['arm']['name'] / label
                if str((source / 'trial.json').relative_to(ROOT)) not in index['files']:
                    raise ValueError('planned trial missing from the index: ' + label)
                block_count += replay_trial(engine, unit, source)
            if block_count != step['expected_exchanges']:
                raise ValueError(step['id'] + ': replay exchange denominator differs')
            report['exchanges'] += block_count
        report.update(ok=report['exchanges'] == 2440, status='reproduced')
    except (OSError, ValueError, KeyError, TypeError, IndexError, AssertionError) as error:
        report['failures'].append(str(error))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index', nargs='?', type=Path)
    parser.add_argument('--index-matrix', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if args.index_matrix:
        if not args.output:
            parser.error('--index-matrix requires --output')
        result = index_matrix(args.index_matrix)
    elif args.index:
        result = replay_index(args.index)
    else:
        parser.error('provide one explicit current index')
    if args.output:
        with args.output.open('x') as output:
            output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if args.index_matrix or result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
