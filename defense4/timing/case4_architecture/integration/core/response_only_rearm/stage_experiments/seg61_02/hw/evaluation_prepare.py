#!/usr/bin/env python3
"""Frozen collection order and offline preparation hooks for the m11_09 hardware campaign.

No command in this module deploys hardware. The detached evaluation_campaign
controller invokes run_block_frozen.sh for each hardware entry. A guard is an
experimental margin, not a proved latency bound; cap is not a hard deadline.
"""
import argparse
import copy
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SEG = HERE.parent
ARCH = HERE.parents[5]
REPO = ARCH.parents[2]
HW = ARCH / 'integration/evidence/rearm_01/hw'
BUILD = HERE.parents[1] / 'ctl_timing_01/evidence/m11_09'
ANALYSIS_PYTHON = REPO / 'defense4/timing/evidence/campaign_v2/repro/.venv/bin/python'
MS = 1_000_000
SOURCE = 'f1de2b30e9f00fb93b20df51c3ddfafd3fcfd18e9b6dfcaadd62146dddbe5af8'
ARMS = ('off', 'timing_only', 'size_only', 'combined')
CONDITIONS = (('D05_J2p4', 5*MS, 2_400_000), ('D10_J2p4', 10*MS, 2_400_000),
              ('D15_J2p4', 15*MS, 2_400_000), ('D20_J2p4', 20*MS, 2_400_000),
              ('D10_J5', 10*MS, 5*MS), ('D10_J10', 10*MS, 10*MS),
              ('D10_J15', 10*MS, 15*MS), ('D10_J20', 10*MS, 20*MS))
RECOVERY = (
    ('persistence_graceful_950', 'candidate_series', ['--close-mode', 'graceful']),
    ('persistence_rst_950', 'candidate_series', ['--close-mode', 'rst', '--rst-grace-ms', '1000']),
    ('loss_core_950', 'candidate_campaign', ['--loss', 'core']),
    ('reconnect_950', 'candidate_campaign', ['--scenario', 'reconnect', '--reconnect-policy', 'protected']),
    ('held_operate_350', 'candidate_series', ['--close-mode', 'graceful']))


def load(path):
    return json.loads(Path(path).read_text())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(path).parent))
    spec.loader.exec_module(result)
    return result


grid = module('evaluation_grid', HERE / 'part2_grid.py')


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def collection_order(campaign_id):
    if not isinstance(campaign_id, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}', campaign_id):
        raise ValueError('campaign ID must be an ordinary service/path component')
    out = []
    def append(phase, label, **fields):
        out.append(dict(id=campaign_id + '_' + label, phase=phase,
                        collection_index=len(out), **fields))
    for suffix, tool, extra in RECOVERY:
        append('recovery', suffix, template='ctl_m11_09_' + suffix + '.json',
               tool=tool, arguments=['--arms', 'combined', '--fixtures', 'separate_ack'] + extra,
               arms=['combined'], expected_exchanges=None)
    append('reference', 'reference', template='part2_m11_09_ref_r30_b1.json',
           tool='candidate_campaign', arguments=[], arms=list(ARMS), expected_exchanges=772)
    def add(phase, label, condition, number, arms, reads, sbo, split=None):
        append(phase, label, condition_id=condition[0], D_ns=condition[1], J_ns=condition[2],
               round=number, split=split, arms=list(arms), reads=reads, sbo=sbo,
               expected_exchanges=len(arms)*(reads+2*sbo), tool='candidate_campaign', arguments=[])
    for r in range(1, 5):
        k = (r-1) % 4
        arms = ARMS[-k:] + ARMS[:-k] if k else ARMS
        add('pilot', 'pilot_%02d' % r, CONDITIONS[1], r, arms, 65, 64)
    for condition in CONDITIONS:
        add('feasibility', condition[0] + '_read', condition, 0, ['combined'], 20, 0)
        add('feasibility', condition[0] + '_sbo', condition, 0, ['combined'], 21, 20)
    for r in range(1, 17):
        k, a = (r-1) % 8, (r-1) % 4
        conditions = CONDITIONS[k:] + CONDITIONS[:k]
        arms = ARMS[-a:] + ARMS[:-a] if a else ARMS
        for condition in conditions:
            add('main', 'r%02d_%s' % (r, condition[0]), condition, r, arms, 65, 64,
                'training' if r <= 8 else 'testing')
    return out


def derive_envelope(availability_ns, tcp_rto_ns):
    def positive(values):
        return values and all(type(x) is int and x > 0 for x in values)
    if not positive(availability_ns):
        raise ValueError('complete native pilot response availability is required')
    if not positive(tcp_rto_ns):
        raise ValueError('observed TCP RTO evidence is required')
    l, g, dmax, jmax = max(availability_ns), 5*MS, 20*MS, 20*MS
    ceil = lambda x: ((x + MS - 1) // MS) * MS
    da = ceil(l + jmax + g)
    pb = ceil(max(jmax + g, da + dmax + g))
    readiness = ceil(max(pb + g, max(da, l+jmax) + dmax + g))
    cap = ceil(readiness + g)
    # Conservative common headroom screen includes the command hold and guard, and cap, the configured release
    # time when a fallback happens (review R8).
    budget = max(cap, jmax + da + dmax + g)
    limit = min(500*MS, min(tcp_rto_ns))
    if budget >= limit:
        raise ValueError('endpoint/TCP timeout headroom fails: %dns >= %dns' % (budget, limit))
    requested = dict(da=da, pb=pb, readiness=readiness, cap=cap)
    for _, d, j in CONDITIONS:
        errors = grid.check(dict(requested, gap=d, op_j=j), fixture_l_ns=l)
        if errors:
            raise ValueError('; '.join(errors))
    return dict(schema_version=1, requested_ns=requested,
                effective_ns={k: grid.t_units(v)*256 for k, v in requested.items()},
                response_availability_max_ns=l, min_observed_tcp_rto_ns=min(tcp_rto_ns),
                endpoint_timeout_ns=500*MS, guarded_budget_ns=budget, margin_ns=g,
                guards_are_worst_case_bounds=False, cap_is_demonstrated_hard_deadline=False,
                rule='pilot maximum; common envelope; ceil to1ms; no accuracy input')


def evaluation_config(template, block, envelope, order_sha):
    cfg = copy.deepcopy(template)
    by_name = {a['name']: a for a in cfg['arms']}
    cfg['arms'] = [by_name[a] for a in block['arms']]
    cfg['timing_params_ns'] = dict(envelope['requested_ns'], gap=block['D_ns'], op_j=block['J_ns'])
    cfg['trials'] = dict(reads_per_trial=block['reads'], trials_per_arm=1)
    cfg['traffic'].update(run_sbo=bool(block['sbo']), sbo_cycles=block['sbo'])
    if not block['sbo']:
        cfg['traffic'].pop('sbo_cycles')
    cfg['fixture'].update(modes=['separate_ack'], delay_ms=5, jitter_ms=0)
    cfg['evaluation'].update(purpose='qualification', read_precision=True,
                             collection_order_sha256=order_sha, evaluation_protocol='69a9d24',
                             campaign_block=block, requested_common_envelope=envelope['requested_ns'],
                             effective_timing_ns={k: grid.t_units(v)*256
                                                  for k, v in cfg['timing_params_ns'].items()},
                             arm_order=block['arms'], block=block['round'])
    cfg['part2'] = dict(condition=block['condition_id'], role=block['phase'], grid='evaluation_69a9d24')
    errors = grid.check_config(cfg)
    if errors:
        raise ValueError('; '.join(errors))
    return cfg


def frozen_order(root):
    root = Path(root).resolve()
    record = load(root / 'definition.json')
    if sha(root / 'collection_order.json') != record['collection_order_sha256']:
        raise ValueError('collection order differs from immutable definition')
    return record, load(root / 'collection_order.json')


def config_path(root, block):
    return Path(root) / 'configs' / (block['id'] + '.json')


def run_root(root, block):
    return Path(root) / 'blocks' / block['id']


def freeze(root, name, configs):
    target = Path(root) / name
    if target.exists():
        raise FileExistsError(str(target))
    subprocess.run(['/usr/bin/python3', str(HW / 'freeze_gate.py'), 'write', str(BUILD),
                    '-o', str(target), '--configs'] + [str(p) for p in configs], check=True)
    subprocess.run(['/usr/bin/python3', str(HW / 'freeze_gate.py'), 'check', str(target)], check=True)


def prepare(root, campaign_id):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    if sha(BUILD / 'response_only.p4') != SOURCE:
        raise ValueError('selected source changed')
    order = collection_order(campaign_id)
    write_new(root / 'collection_order.json', order)
    order_sha = sha(root / 'collection_order.json')
    write_new(root / 'definition.json', dict(schema_version=1, campaign_id=campaign_id,
              collection_order_sha256=order_sha, hardware_blocks=154, main_blocks=128,
              main_exchanges=98816, duration_seconds=86400, evidence_kind='hardware',
              source_sha256=SOURCE, build=str(BUILD), no_replacement=True))
    template = load(BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    provisional = dict(requested_ns=dict(da=30*MS, pb=55*MS, readiness=70*MS, cap=80*MS))
    for block in order[:10]:
        cfg = (load(BUILD / 'configs' / block['template']) if 'template' in block else
               evaluation_config(template, block, provisional, order_sha))
        # Evidence roots may be absolute; the existing wrapper resolves them consistently.
        cfg['evidence_dir'] = str(root / 'blocks')
        cfg['evaluation'].update(collection_order_sha256=order_sha, campaign_block=block)
        write_new(config_path(root, block), cfg)
    steps = []
    def hook(name):
        steps.append(dict(id=name, kind='hook', argv=['/usr/bin/python3', str(Path(__file__).resolve()),
                                                    name, str(root)]))
    for i, block in enumerate(order):
        if i == 10:
            hook('derive')
        if i == 26:
            hook('qualify')
        if block['phase'] == 'main' and block['round'] == 9 and order[i-1]['round'] == 8:
            hook('fit')
        freeze_path = root / ('freeze_pilot.json' if i < 10 else 'freeze_main.json')
        step = dict(id=block['id'], kind='block', run_root=str(run_root(root, block)),
                    argv=['/bin/bash', str(HW / 'run_block_frozen.sh'), str(freeze_path),
                          block['tool'], str(config_path(root, block)), block['id']] + block['arguments'])
        if block['phase'] in ('pilot', 'feasibility', 'main'):
            step['postcheck_argv'] = ['/usr/bin/python3', str(Path(__file__).resolve()), 'postcheck',
                                      str(root), '--block', block['id']]
        steps.append(step)
    hook('export')
    write_new(root / 'controller_manifest.json', dict(campaign_id=campaign_id, evidence_kind='hardware', steps=steps))
    return root


def extract_ledger(root, block):
    extractor = module('evaluation_transactions', SEG / 'analysis/four_arm_transactions.py')
    return extractor.publication_ledger(run_root(root, block),
        dict(condition=block.get('condition_id'), round=block.get('round'), split=block.get('split')))


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def observed_rtos(document):
    values = []
    for endpoint in ('master', 'outstation'):
        observed = [round(v*MS) for sample in document.get('samples', [])
                    if sample.get('endpoint') == endpoint and sample.get('status') == 'ok'
                    and sample.get('units') == 'ms'
                    for v in sample.get('rto_ms', []) if number(v) and v > 0]
        if not observed or min(observed) <= 0:
            raise ValueError('both endpoint TCP RTO observations are required: missing ' + endpoint)
        values += observed
    return values


def check_observations(block, cfg, record, ledger):
    """Check actual observations, in addition to the wrapper's correctness gates."""
    errors = []
    captured = [r for r in ledger['records'] if r['record_type'] == 'captured_exchange']
    if record.get('ok') is not True:
        errors.append('hardware block did not pass')
    sources = record.get('source_identity', {}).get('build_sources', {})
    if not sources or any(v.get('source_sha256') != SOURCE for v in sources.values()):
        errors.append('actual hardware source identity is missing or differs from m11_09')
    if [a['arm'] for a in record.get('arms', [])] != block['arms']:
        errors.append('actual configured arm execution order differs from frozen schedule')
    if record.get('effective', {}).get('timing_params_ns') != cfg['timing_params_ns']:
        errors.append('actual timing settings differ from frozen configuration')
    by_arm = {a['name']: a for a in cfg['arms']}
    for name in block['arms']:
        rows = [r for r in captured if r['arm'] == ('baseline' if name == 'off' else name)]
        expected = dict(READ=block['reads'], SELECT=block['sbo'], OPERATE=block['sbo'])
        observed = {k: sum(r['txn_class'] == k for r in rows) for k in expected}
        if observed != expected:
            errors.append('%s capture/attempt class counts differ: %s != %s' % (name, observed, expected))
        if any(not r.get('complete') or r.get('retransmitted') or r.get('attempts') != 1 for r in rows):
            errors.append('%s has incomplete, retried or uncertain attempt outcomes' % name)
        if any(not all(number(r.get(k)) for k in ('request_timestamp_ns', 'response_timestamp_ns',
                         'response_availability_ns', 'request_delivery_ns', 'response_len')) for r in rows):
            errors.append('%s lacks required observed timing/length evidence' % name)
        if by_arm[name]['T']:
            for operation, n in expected.items():
                if not n:
                    continue
                values = [abs(r['clrt_ns'] - cfg['timing_params_ns']['gap']) for r in rows
                          if r['txn_class'] == operation and number(r.get('clrt_ns'))]
                if len(values) != n or sorted(values)[math.ceil(.99*len(values))-1] > 100_000:
                    errors.append('%s/%s actual CLRT p99 precision fails or is incomplete' % (name, operation))
            holds = [r.get('operate_hold_ns') for r in rows if r['txn_class'] == 'OPERATE']
            if any(not number(h) or h < cfg['timing_params_ns']['op_j'] for h in holds):
                errors.append('%s actual OPERATE J hold fails' % name)
        arm = next((a for a in record.get('arms', []) if a['arm'] == name), {})
        trials = arm.get('trials', [])
        if len(trials) != 1 or trials[0].get('ok') is not True:
            errors.append('%s trial gate missing or failed' % name)
            continue
        trial = trials[0]
        if trial.get('generation_headroom', {}).get('ok') is not True:
            errors.append('%s generation headroom not verified' % name)
        tcpdump = trial.get('vision', {}).get('tcpdump', {})
        if any(tcpdump.get(d, {}).get('dropped_kernel') != 0 for d in ('in', 'out')):
            errors.append('%s capture drop accounting missing or nonzero' % name)
        outcomes = trial.get('observed', {}).get('outcomes', {})
        if not outcomes or any(outcomes.get(k) != 0 for k in ('OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK')):
            errors.append('%s fallback outcomes missing or nonzero' % name)
        if by_arm[name]['T']:
            for key, count in dict(OUT_ACK_COMMIT=sum(expected.values()),
                                   OUT_RESP_RELEASE=sum(expected.values()), OUT_OP_RELEASE=block['sbo']).items():
                if outcomes.get(key) != count:
                    errors.append('%s %s observed%s expected%s' % (name, key, outcomes.get(key), count))
    return errors


def postcheck(root, block_id):
    _, order = frozen_order(root)
    block = next(b for b in order if b['id'] == block_id)
    ledger = extract_ledger(root, block)
    target = run_root(root, block)
    write_new(target / 'publication_ledger.json', ledger)
    cfg, record = load(config_path(root, block)), load(target / 'campaign_run.json')
    errors = check_observations(block, cfg, record, ledger)
    if record.get('config_file_sha256') != sha(config_path(root, block)):
        errors.append('actual config file identity differs from frozen input')
    rto_paths = sorted(target.glob('*/*/*/tcp_rto.json'))
    if len(rto_paths) != len(block['arms']):
        errors.append('endpoint TCP RTO evidence is missing for one or more arms')
    for path in rto_paths:
        try:
            rtos = observed_rtos(load(path))
            timing = cfg['timing_params_ns']
            # configured worst case (cap, or hold + da + D + guard) and the latency actually observed (review R8)
            observed = [r.get('response_latency_ns') for r in ledger.get('records', [])
                        if isinstance(r.get('response_latency_ns'), int)]
            budget = max([timing.get('cap', 0), timing['op_j'] + timing['da'] + timing['gap'] + 5*MS] + observed)
            if budget >= min(500*MS, min(rtos)):
                errors.append('observed endpoint/TCP timeout headroom fails: ' + str(path))
        except ValueError as error:
            errors.append(str(error))
    # derived, not stamped (review A6): the hardware runner observed the switch program before the run, and the
    # independent restoration verdict is ok
    restored = (target / 'restore_verify.json').is_file() and load(target / 'restore_verify.json').get('ok') is True
    hardware = bool(record.get('pre_run_program')) and restored
    if not hardware:
        errors.append('block evidence is not attested hardware (pre-run switch program or verified restore missing)')
    proof = dict(schema_version=1, block_id=block_id, ok=not errors, failures=errors,
                 ledger_sha256=sha(target / 'publication_ledger.json'),
                 campaign_record_sha256=sha(target / 'campaign_run.json'),
                 evidence_kind='hardware' if hardware else 'unattested')
    write_new(target / 'evaluation_postcheck.json', proof)
    if errors:
        raise ValueError('; '.join(errors))


def qualified(root, blocks):
    for block in blocks:
        directory = run_root(root, block)
        post = load(directory / 'evaluation_postcheck.json')
        if (post.get('ok') is not True or load(directory / 'restore_verify.json').get('ok') is not True
                or post['ledger_sha256'] != sha(directory / 'publication_ledger.json')
                or post['campaign_record_sha256'] != sha(directory / 'campaign_run.json')):
            raise ValueError('block qualification/restoration binding failed: ' + block['id'])


def derive(root):
    root = Path(root).resolve()
    definition, order = frozen_order(root)
    pilots = [b for b in order if b['phase'] == 'pilot']
    qualified(root, pilots)
    availability, rtos, sources = [], [], {}
    for block in pilots:
        directory = run_root(root, block)
        path = directory / 'publication_ledger.json'
        sources[str(path.relative_to(root))] = sha(path)
        ledger = load(path)
        native = [r for r in ledger['records'] if r['record_type'] == 'captured_exchange' and r['arm'] == 'baseline']
        if len(native) != 193 or any(not number(r.get('response_availability_ns')) for r in native):
            raise ValueError('pilot native response availability coverage is incomplete')
        availability += [r['response_availability_ns'] for r in native]
        paths = sorted(directory.glob('*/*/*/tcp_rto.json'))
        if len(paths) != 4:
            raise ValueError('pilot TCP timer evidence missing for one or more arms')
        for path in paths:
            values = observed_rtos(load(path))
            rtos += values
            sources[str(path.relative_to(root))] = sha(path)
    envelope = derive_envelope(availability, rtos)
    envelope.update(pilot_evidence_sha256=sources, collection_order_sha256=definition['collection_order_sha256'])
    write_new(root / 'common_envelope.json', envelope)
    # Envelope selection is already locked before any attacker accuracy is read.
    subprocess.run([str(ANALYSIS_PYTHON), str(Path(__file__).resolve()), 'pilot-competence', str(root)], check=True)
    template = load(BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    for block in order[10:]:
        cfg = evaluation_config(template, block, envelope, definition['collection_order_sha256'])
        cfg['evidence_dir'] = str(root / 'blocks')
        write_new(config_path(root, block), cfg)
    freeze(root, 'freeze_main.json', [config_path(root, b) for b in order[10:]])


def pilot_competence(root):
    import numpy as np
    root = Path(root).resolve()
    _, order = frozen_order(root)
    if not (root / 'common_envelope.json').is_file():
        raise ValueError('envelope must be locked before pilot competence is evaluated')
    legacy = module('evaluation_legacy', SEG / 'analysis/leakage_four_arm.py')
    rows, runs = [], []
    for block in order:
        if block['phase'] != 'pilot':
            continue
        for row in load(run_root(root, block) / 'publication_ledger.json')['records']:
            if row['record_type'] == 'captured_exchange' and row['arm'] == 'baseline':
                rows.append(row)
                runs.append(block['id'])
    X = np.asarray([[r['ack_latency_ns']/MS, r['clrt_ns']/MS, r['response_len']] for r in rows])
    scores, _, _, used = legacy.folds(np.asarray(runs), np.asarray(['baseline']*len(rows)),
        np.asarray([r['txn_class'] for r in rows]), X, [0, 1, 2], ['baseline'])
    values = scores['baseline']
    mean = float(np.mean(values))
    competent = mean > 1/3 + legacy.COMPETENCE_MARGIN
    write_new(root / 'pilot_competence.json', dict(competent=competent, feature='joint',
        baseline_only=True, scope='pilot go/no-go only; not confirmatory training or test',
        grouped_held_out_scores=values, blocks=used, mean_balanced_accuracy=mean,
        required_above=1/3 + legacy.COMPETENCE_MARGIN, envelope_sha256=sha(root / 'common_envelope.json')))
    if not competent:
        raise ValueError('pilot native joint baseline is uninformative; no main sweep')


def qualify(root):
    root = Path(root).resolve()
    definition, order = frozen_order(root)
    feasibility = [b for b in order if b['phase'] == 'feasibility']
    if load(root / 'pilot_competence.json').get('competent') is not True:
        raise ValueError('pilot baseline competence not qualified')
    qualified(root, feasibility)
    # No main starts until every point and both workloads passed actual hardware checks.
    if len(feasibility) != 16:
        raise ValueError('full feasibility cohort missing')
    if any(run_root(root, b).exists() for b in order if b['phase'] == 'main'):
        raise ValueError('main evidence predates complete feasibility qualification')
    write_new(root / 'feasibility_qualification.json', dict(ok=True, conditions=8, blocks=16,
              collection_order_sha256=definition['collection_order_sha256'],
              envelope_sha256=sha(root / 'common_envelope.json'),
              postchecks={b['id']: sha(run_root(root, b) / 'evaluation_postcheck.json') for b in feasibility}))


def analysis_environment():
    code = ('import importlib.metadata as m,json,platform,sys; '
            'names=("numpy","scipy","scikit-learn","joblib","threadpoolctl","matplotlib",'
            '"contourpy","cycler","fonttools","kiwisolver","packaging","pillow","pyparsing",'
            '"python-dateutil","six"); '
            'print(json.dumps(dict(python=sys.version,platform=platform.platform(),'
            'packages={name:m.version(name) for name in names})))')
    result = subprocess.run([str(ANALYSIS_PYTHON), '-c', code], check=True,
                            stdout=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def release(root, training):
    """Copy portable hardware evidence; the strict offline loader independently verifies it."""
    root = Path(root).resolve()
    definition, order = frozen_order(root)
    main = [b for b in order if b['phase'] == 'main']
    selected = [b for b in main if not training or b['split'] == 'training']
    qualified(root, selected)
    destination = root / ('release_training' if training else 'release')
    destination.mkdir(exist_ok=False)
    artifacts, rows, cohort = [], [], []
    def artifact(path, relative, kind, block_id=None, evidence_kind='hardware'):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        record = dict(path=relative, sha256=sha(target), kind=kind, evidence_kind=evidence_kind)
        if block_id:
            record['block_id'] = block_id
        artifacts.append(record)
    schedule = [dict(block_id=b['id'], round=b['round'], split=b['split'],
                     condition_id=b['condition_id'], arms=b['arms']) for b in main]
    for block in selected:
        directory = run_root(root, block)
        ledger = load(directory / 'publication_ledger.json')
        cost_module = module('evaluation_cost', SEG / 'analysis/cost_report.py')
        costs = {}
        for arm in load(directory / 'campaign_run.json')['arms']:
            for trial in arm['trials']:
                d = directory / arm['fixture'] / arm['arm'] / trial['label']
                # Missing counters stay explicit; never substitute zero cost.
                try:
                    costs[trial['label']] = cost_module.trial_cost(d, trial['label'])
                except (OSError, KeyError, ValueError, TypeError):
                    costs[trial['label']] = None
        counts = {a: 0 for a in ARMS}
        for record in ledger['records']:
            if record['record_type'] != 'captured_exchange':
                continue
            row = dict(record)
            row.update(arm='off' if row['arm'] == 'baseline' else row['arm'],
                       example_id=row['exchange_id'], condition_id=block['condition_id'], operation=row['txn_class'])
            cost = costs.get(row['trial'])
            row['internal_bytes'] = cost['per_exchange']['rx_octets'] if cost else None
            row['internal_bytes_scope'] = 'trial average RX octets per complete exchange; not operation-specific'
            for field, source in (('clrt_ms', 'clrt_ns'), ('ack_ms', 'ack_latency_ns'),
                                  ('rt_ms', 'response_latency_ns'), ('realized_j_ms', 'operate_hold_ns')):
                row[field] = row[source]/MS if number(row.get(source)) else None
            counts[row['arm']] += 1
            rows.append(row)
        cohort.append(dict(block_id=block['id'], expected_per_arm={a: 193 for a in ARMS},
                           observed_per_arm=counts, complete=all(v == 193 for v in counts.values())))
        for path in sorted(directory.rglob('*')):
            if not path.is_file():
                continue
            rel = 'hardware/' + block['id'] + '/' + str(path.relative_to(directory))
            if path.name in ('out.pcap', 'in.pcap'):
                kind = 'capture'
            elif path.parent.name == 'snapshots' and path.suffix == '.json':
                kind = 'counters'
            elif path.suffix in ('.json', '.out', '.txt', '.log', '.stdout', '.stderr', '.pcap'):
                kind = 'audit'
            else:
                continue
            artifact(path, rel, kind, block['id'])
    fieldnames = sorted(set(k for r in rows for k in r))
    with (destination / 'rows.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True, allow_nan=False) if isinstance(v, (list, dict)) else v
                             for k, v in row.items()})
    write_new(destination / 'schedule.json', schedule)
    write_new(destination / 'cohort.json', dict(schema_version=1, blocks=cohort))
    for filename, kind in (('rows.csv', 'rows'), ('schedule.json', 'schedule'), ('cohort.json', 'cohort')):
        artifacts.append(dict(path=filename, sha256=sha(destination / filename), kind=kind, evidence_kind='hardware'))
    environment = analysis_environment()
    write_new(destination / 'environment_lock.json', environment)
    requirements = destination / 'requirements-analysis.txt'
    with requirements.open('x') as stream:
        stream.write(''.join('%s==%s\n' % (name, version) for name, version in sorted(environment['packages'].items())))
    for path in (destination / 'environment_lock.json', requirements):
        artifacts.append(dict(path=path.name, sha256=sha(path), kind='validation', evidence_kind='profile_metadata'))
    for filename in ('definition.json', 'collection_order.json', 'common_envelope.json', 'pilot_competence.json',
                     'feasibility_qualification.json', 'freeze_pilot.json', 'freeze_main.json', 'controller_manifest.json'):
        artifact(root / filename, 'audit/' + filename, 'audit')
    # Pilot and feasibility qualify the common envelope but never become main
    # training/testing rows. Preserve the complete evidence chain offline.
    for block in order[:26]:
        directory = run_root(root, block)
        for path in sorted(directory.rglob('*')):
            if path.is_file() and path.suffix in ('.pcap', '.json', '.out', '.txt', '.log', '.stdout', '.stderr'):
                artifact(path, 'preliminary/' + block['id'] + '/' + str(path.relative_to(directory)),
                         'audit', block['id'])
    supervision = root / definition['campaign_id']
    for path in sorted(supervision.rglob('*')):
        if path.is_file() and path.suffix in ('.json', '.log'):
            artifact(path, 'supervision/' + str(path.relative_to(supervision)), 'audit')
    for filename in ('supported_profile.json', 'response_only.inputs.json', 'compiler_comparison.json',
                     'resource_review.json', 'model_summary_v3.json'):
        if (BUILD / filename).is_file():
            validation_kind = ('model_validation' if filename == 'model_summary_v3.json' else
                               'profile_metadata' if filename in ('supported_profile.json', 'response_only.inputs.json')
                               else 'compiler_validation')
            artifact(BUILD / filename, 'candidate/' + filename, 'validation', evidence_kind=validation_kind)
    for compiler in ('compile_local', 'compile_switch_9132'):
        artifact(BUILD / compiler / 'manifest.json', 'candidate/' + compiler + '/manifest.json', 'validation',
                 evidence_kind='compiler_validation')
    if not training:
        artifact(root / 'release_training/model_lock.json', 'model_lock.json', 'model_lock')
        artifact(root / 'fit_attestation.json', 'fit_attestation.json', 'fit_attestation')
    for filename in ('publication_analysis.py', 'publication_figures.py', 'reproduce_evaluation.py'):
        artifact(SEG / 'analysis' / filename, 'scripts/' + filename, 'script')
    legacy_tables = []
    if not training:
        extractor = module('evaluation_legacy_export', SEG / 'analysis/four_arm_transactions.py')
        for condition, _, _ in CONDITIONS:
            table = destination / 'legacy_tables' / (condition + '.csv')
            table.parent.mkdir(exist_ok=True)
            extractor.main(['four_arm_transactions.py', str(table)] +
                [str(run_root(root, b)) for b in main if b['condition_id'] == condition])
            for path in (table, Path(str(table) + '.counts.json')):
                artifacts.append(dict(path=str(path.relative_to(destination)), sha256=sha(path), kind='legacy',
                                      evidence_kind='hardware'))
            legacy_tables.append(dict(condition_id=condition, path=str(table.relative_to(destination))))
    legacy_script = 'legacy_repo/' + str((SEG / 'analysis/leakage_four_arm.py').relative_to(REPO))
    for path in (SEG / 'analysis/leakage_four_arm.py',
                 REPO / 'defense4/timing/evidence/campaign_v2/repro/leakage_campaign.py'):
        artifact(path, 'legacy_repo/' + str(path.relative_to(REPO)), 'script')
    manifest = dict(schema_version=1, campaign_id=definition['campaign_id'], evidence_kind='hardware',
        hardware_provenance=dict(platform='Tofino-1', target='m11_09', endpoint='OpenDNP3', source_sha256=SOURCE),
        conditions=[dict(condition_id=c, D_ms=d/MS, J_ms=j/MS) for c, d, j in CONDITIONS],
        rows_file='rows.csv', schedule_file='schedule.json', cohort_file='cohort.json',
        model_lock_file='model_lock.json', fit_attestation_file='fit_attestation.json', artifacts=artifacts,
        legacy_tables=legacy_tables, legacy_script_file=legacy_script, environment_lock_file='environment_lock.json')
    write_new(destination / 'release_manifest.json', manifest)
    return destination


def fit(root):
    root = Path(root).resolve()
    _, order = frozen_order(root)
    if any(run_root(root, b).exists() for b in order if b.get('split') == 'testing'):
        raise ValueError('test hardware already exists; refusing post-test training lock')
    destination = release(root, training=True)
    subprocess.run([str(ANALYSIS_PYTHON), str(SEG / 'analysis/reproduce_evaluation.py'), str(destination),
                    '--fit-lock', str(destination / 'model_lock.json')], check=True)
    write_new(root / 'fit_attestation.json', dict(campaign_id=load(root / 'definition.json')['campaign_id'],
        model_lock_sha256=sha(destination / 'model_lock.json'), fit_after_round=8, before_round=9, ok=True,
        training_manifest_sha256=sha(destination / 'release_manifest.json'),
        tests_present_at_fit=False, collection_order_sha256=sha(root / 'collection_order.json')))


def export(root):
    root = Path(root).resolve()
    destination = release(root, training=False)
    subprocess.run([str(ANALYSIS_PYTHON), str(destination / 'scripts/reproduce_evaluation.py'),
                    str(destination), '--output', str(root / 'results')], check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'freeze-initial', 'derive', 'pilot-competence', 'postcheck', 'qualify', 'fit', 'export'))
    parser.add_argument('root', type=Path)
    parser.add_argument('--campaign-id')
    parser.add_argument('--block')
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        print(prepare(args.root, args.campaign_id))
    elif args.command == 'freeze-initial':
        _, order = frozen_order(args.root)
        freeze(args.root, 'freeze_pilot.json', [config_path(args.root, b) for b in order[:10]])
    else:
        if args.command == 'postcheck':
            postcheck(args.root, args.block)
        elif args.command == 'pilot-competence':
            pilot_competence(args.root)
        else:
            globals()[args.command](args.root)


if __name__ == '__main__':
    main()
