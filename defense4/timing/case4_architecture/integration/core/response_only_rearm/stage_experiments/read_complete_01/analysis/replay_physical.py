#!/usr/bin/env python3
"""Reproduce retained c67/c68 physical wire reports without modifying evidence.

Exit zero means the recorded reports, including failures, were reproduced exactly.
It is not a new qualification verdict. No CLRT precision criterion is evaluated.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ARCH = ROOT.parent.parents[3]
REPO = ARCH.parents[2]
EVIDENCE = ROOT / 'evidence/hw_blocks'
sys.path[:0] = [str(HERE), str(ARCH / 'protocol/hw_vepa')]
from historical_checker import load_checker  # noqa: E402
import checks  # noqa: E402
import relay_check  # noqa: E402


def read_json(path):
    if not path.is_file():
        raise ValueError('missing ' + str(path))
    try:
        value = json.loads(path.read_text())
    except (ValueError, OSError) as error:
        raise ValueError('malformed %s: %s' % (path, error)) from error
    if not isinstance(value, dict):
        raise ValueError('expected JSON object: ' + str(path))
    return value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def option(arguments, name):
    return arguments[arguments.index(name) + 1] if name in arguments else None


def frozen_config(block, run):
    frozen = read_json(block / 'freeze_check.json')
    path = REPO / frozen['config']
    cfg = read_json(path)
    digest = sha(path)
    canonical = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if frozen.get('ok') is not True or digest != frozen.get('config_sha256') or \
            digest != run.get('config_file_sha256') or canonical != run.get('config_sha256'):
        raise ValueError('%s: frozen config identity differs' % block)
    for key in ('traffic', 'trials', 'timing_params_ns'):
        if (run.get('effective') or {}).get(key) != cfg.get(key):
            raise ValueError('%s: effective %s differs from frozen config' % (block, key))
    if cfg.get('endpoint_profile') != 'sel751' or cfg['fixture']['modes'] != ['physical_relay']:
        raise ValueError('%s: not a physical relay config' % block)
    return cfg, frozen


def planned_trials(cfg, run_id):
    campaign = cfg['evaluation']['campaign_block']
    arguments = campaign['arguments']
    loss = option(arguments, '--loss')
    scenario = option(arguments, '--scenario')
    close = option(arguments, '--close-mode')
    count = (len(cfg['loss']['presets'][loss]) if loss else
             1 if scenario or close or cfg['trial_mode'] == 'one_connection' else cfg['trials']['trials_per_arm'])
    reads = cfg['trials']['reads_per_trial']
    if cfg['trial_mode'] == 'one_connection' and not (loss or scenario or close):
        reads *= cfg['trials']['trials_per_arm']
    wanted = campaign['arms']
    arms = [arm for arm in cfg['arms'] if arm['name'] in wanted]
    if {arm['name'] for arm in arms} != set(wanted):
        raise ValueError('frozen campaign arms are missing')
    result = {}
    for arm in arms:
        for index in range(count):
            label = '%s_physical_relay_%s_t%d' % (run_id, arm['name'], index)
            port = cfg['traffic']['master_port_range']['first'] + len(result)
            result[label] = dict(arm=arm, reads=reads, port=port, scenario=scenario,
                                 close=close or ('graceful' if scenario == 'reconnect' else None))
    return result


def selected_checker(retained, cache):
    schema = retained.get('schema')
    if schema == 'sel751-wire-v2':
        if relay_check.SCHEMA_VERSION != schema:
            raise ValueError('live checker does not implement ' + schema)
        return relay_check, 'working-tree'
    if schema != 'sel751-wire-v1' or not retained.get('exchanges'):
        raise ValueError('unsupported retained wire report contract: ' + str(schema))
    # v1 was retained on both sides of the historical field removal. Its exchange
    # contract distinguishes them, including the final failed c67 attempt.
    revision = 'a4ebbecbe' if 'first_clrt_us' in retained['exchanges'][0] else '789092c2d'
    if revision not in cache:
        cache[revision] = load_checker(revision)
    return cache[revision], revision


def campaign_wire_checks(report, master, padded, checker, close):
    """The physical header/image/close checks applied by campaign.relay_verdict."""
    for direction, packets in report['packets'].items():
        for packet in packets:
            header = 40 if direction == 'out' else 44
            if packet['flags'] & 2:
                if packet['tcp_header_bytes'] != header:
                    report['failures'].append('SYN header differs from selected physical TCP profile')
            elif packet['payload_len'] and (packet['tcp_header_bytes'] != 32 or
                    packet['ipv4_header_bytes'] != 20 or not packet['tcp_options_hex'].startswith('0101080a')):
                report['failures'].append('data header/options differ from selected physical TCP profile')
    for record in master['records']:
        operation, workload = record['operation'], record.get('workload')
        length = ({'mixed': 141, 'integrity': 158} if padded else {'mixed': 91, 'integrity': 134}).get(workload) \
            if operation == 'READ' else (60 if padded else 49)
        if len(bytes.fromhex(record.get('response_wire_hex', ''))) != length:
            report['failures'].append('response length differs from selected relay image: ' + operation)
    if close is not None:
        report['failures'] += checker.close_checks(report, close)
    report['ok'] = not report['failures']


def replay_trial(directory, recorded, plan, cfg, cache):
    trial = read_json(directory / 'trial.json')
    for key in ('label', 'master_port', 'reads', 'ok', 'failures'):
        if trial.get(key) != recorded.get(key):
            raise ValueError('%s: trial.json %s differs from campaign record' % (directory, key))
    expected = dict(READ=plan['reads'], SELECT=checks.sbo_count(cfg['traffic']), OPERATE=checks.sbo_count(cfg['traffic']))
    names = ('c1', 'c2', 'c3') if plan['scenario'] or plan['close'] else ('single',)
    actual_names = {p.name for p in directory.iterdir() if p.is_dir() and p.name.startswith('c') and p.name[1:].isdigit()}
    if actual_names != (set(names) if names != ('single',) else set()):
        raise ValueError('%s: connection directories differ from frozen plan' % directory)
    result = dict(label=trial['label'], arm=plan['arm']['name'], recorded_ok=trial['ok'], connections=[])
    for name in names:
        cdir = directory if name == 'single' else directory / name
        for filename in ('in.pcap', 'out.pcap', 'master.json', 'result.json', 'capture_offloads.json', 'relay_wire.json'):
            if not (cdir / filename).is_file():
                raise ValueError('missing ' + str(cdir / filename))
        retained = read_json(cdir / 'relay_wire.json')
        checker, revision = selected_checker(retained, cache)
        native = plan['scenario'] == 'reconnect' and name == 'c2'
        port = plan['port'] + (cfg['scenarios']['reconnect']['reconnect_port_offset'] if native else 0)
        master = read_json(cdir / 'master.json')
        report = checker.analyze(cdir, port, expected, cfg['traffic']['read_schedule'])
        campaign_wire_checks(report, master, bool(plan['arm']['padding'] and not native), checker, plan['close'])
        if report != retained:
            differing = [key for key in sorted(set(report) | set(retained)) if report.get(key) != retained.get(key)]
            raise ValueError('%s: replay differs from retained relay_wire.json (%s)' % (cdir, ', '.join(differing)))
        result['connections'].append(dict(connection=name, master_port=port, checker_revision=revision,
            report_schema=report['schema'], report_matches_retained=True, wire_ok=report['ok'],
            wire_failures=report['failures'], expected_counts=expected,
            observed_counts={op: sum(r.get('operation') == op and r.get('outcome') == 'OK'
                                    for r in master['records']) for op in expected},
            exchanges=len(report['exchanges']), input_sha256=report['artifacts'],
            retained_report_sha256=sha(cdir / 'relay_wire.json')))
    return result


def replay_block(block, candidate, cache=None):
    block = Path(block)
    if '_%s_' % candidate not in block.name:
        raise ValueError('block does not match candidate: ' + block.name)
    run = read_json(block / 'campaign_run.json')
    if run.get('run_id') != block.name or not isinstance(run.get('ok'), bool):
        raise ValueError('%s: missing completed campaign record' % block)
    cfg, frozen = frozen_config(block, run)
    plans = planned_trials(cfg, run['run_id'])
    attempted = []
    for arm in run['arms']:
        for trial in arm['trials']:
            label = trial['label']
            if label not in plans or arm['arm'] != plans[label]['arm']['name'] or \
                    trial.get('reads') != plans[label]['reads'] or trial.get('master_port') != plans[label]['port']:
                raise ValueError('%s: trial differs from frozen plan: %s' % (block, label))
            attempted.append((label, trial))
    labels = [label for label, _ in attempted]
    if labels != list(plans)[:len(labels)]:
        raise ValueError('%s: attempted trial sequence differs from frozen plan' % block)
    never = list(plans)[len(labels):]
    if never and not (run['ok'] is False and run.get('failure')):
        raise ValueError('%s: missing expected trials from frozen plan' % block)
    actual_dirs = {str(p.relative_to(block / 'physical_relay')) for p in block.glob('physical_relay/*/*') if p.is_dir()}
    expected_dirs = {'%s/%s' % (plans[label]['arm']['name'], label) for label in labels}
    if actual_dirs != expected_dirs:
        raise ValueError('%s: trial directories differ from recorded attempts' % block)
    result = dict(block=block.name, recorded_run_ok=run['ok'], recorded_gate_ok=run.get('gate_ok'),
        phase=cfg['evaluation']['campaign_block']['phase'], config=frozen['config'],
        config_file_sha256=frozen['config_sha256'], expected_trials=len(plans),
        never_attempted_trials=never, pre_traffic_refusals=[], trials=[])
    cache = {} if cache is None else cache
    for label, recorded in attempted:
        directory = block / 'physical_relay' / plans[label]['arm']['name'] / label
        if not (directory / 'trial.json').is_file():
            # This retained attempt stopped at the install dry-run. The failed step
            # and absence of all traffic artifacts distinguish it from lost evidence.
            failed_step = directory / 'failed_step.log'
            refusal = (run['ok'] is False and 'composite install dry-run' in (run.get('failure') or '') and
                       failed_step.is_file() and 'REFUSED:' in failed_step.read_text() and
                       not any(directory.rglob('*.pcap')) and not any(directory.rglob('master.json')) and
                       not any(directory.rglob('result.json')))
            if refusal:
                result['pre_traffic_refusals'].append(dict(label=label, reason=run['failure'],
                                                          failed_step_sha256=sha(failed_step)))
                continue
            raise ValueError('missing ' + str(directory / 'trial.json'))
        result['trials'].append(replay_trial(directory, recorded, plans[label], cfg, cache))
    result['completed'] = not never and not result['pre_traffic_refusals']
    return result


def replay(candidate, evidence_root=EVIDENCE):
    blocks = sorted(Path(evidence_root).glob('rc01_hw_%s_*' % candidate))
    if not blocks:
        raise ValueError('no physical campaign blocks found for ' + candidate)
    cache = {}
    results = [replay_block(block, candidate, cache) for block in blocks]
    complete = [block for block in results if block['completed'] and block['recorded_run_ok'] and block['phase'] == 'reference']
    return dict(schema='physical-report-replay-v1', candidate=candidate, ok=True,
        meaning='Recorded wire reports reproduced exactly, including failures; no new qualification verdict.',
        completed=dict(blocks=len(complete), trials=sum(len(b['trials']) for b in complete),
                       exchanges=sum(c['exchanges'] for b in complete for t in b['trials'] for c in t['connections'])),
        blocks=results)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', choices=('c67', 'c68'), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ValueError('output exists: ' + str(args.out))
        destination = args.out.resolve()
        if destination == ROOT / 'evidence' or ROOT / 'evidence' in destination.parents:
            raise ValueError('output must be outside retained evidence')
        result = replay(args.candidate)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print('REPLAY FAILED: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps(dict(candidate=args.candidate, replay_ok=True, completed=result['completed'], out=str(args.out))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
