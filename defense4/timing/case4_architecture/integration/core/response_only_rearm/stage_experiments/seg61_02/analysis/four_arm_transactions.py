"""Transactions table for leakage_four_arm.py from four-arm silicon blocks (Part 2, 2026-10-18).

  python3 four_arm_transactions.py OUT.csv BLOCK_DIR [BLOCK_DIR ...]

Each BLOCK_DIR is one run_block campaign directory (e.g. hw_campaigns/part2_m10_da10_g100_b1_01) whose fixture
directory holds one trial per arm, each with the per-exchange timing.json the block's own extraction wrote. The
grouped run is the block: every block runs all four arms in its rotation order, so leave-one-run-out holds every
arm of one block out together.

One row per exchange: run, block_dir, arm (off -> baseline), trial, txn_class (READ/SELECT/OPERATE), ack_ms, clrt_ms,
rt_ms, resp_len, retransmitted, piggyback. Only complete exchanges with both intervals are written. Every other
exchange is counted in OUT.csv.counts.json, per block and arm, so no tail is dropped silently. The intervals are
host-capture-point times (timing.json's own note): the host-observed measurement, not switch-side time.

Publication API (additive; legacy CSV and FIELDS are unchanged):
``publication_ledger(block_dir, labels=None)`` returns a JSON-serializable
``vision-publication-ledger-v1`` object with records/counts/sources/bindings. It replays retained
pcaps without changing timing.json. ``labels`` accepts condition/round/split and a ``trials``
mapping of trial name to those fields, supplied from the frozen schedule. Missing schedule fields
stay null. Records of type ``captured_exchange`` contain existing feature columns plus integer
request/ack/response timestamps and publication ns metrics, lengths and numerical metadata counts.
``endpoint_issued_task`` records retain actual issued_ns evidence in its separate endpoint clock;
they never fabricate per-READ identities or map a task to captured requests by ordering.
Identifiers, labels, packet refs, checksums, protocol identity, config and endpoint clock evidence
are audit fields, never features. ``legacy_feature_eligible`` binds the existing CSV subset to
the ledger by exchange_id. ``null_reasons`` qualifies absent publication observations. Export with
``export_publication_ledger(path, block_dirs, labels=None)``; no minimum block count is imposed
on this evidence-preservation API. A valid legacy comparison still uses main's existing checks.
Partial trials are discovered from either capture, timing, endpoint or collection-result evidence.
Their surviving capture hashes/OUT requests are retained. Unavailable request counts are null,
with ``retained_exchange_records`` reporting the observed lower bound. Session IDs include the
full fixture/arm/trial source path. Missing campaign condition evidence never creates a label.
Use ``publication_complete`` for publication ownership, not legacy ``complete``.
"""
import csv
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

ARM_NAMES = {'off': 'baseline', 'size_only': 'size_only', 'timing_only': 'timing_only', 'combined': 'combined'}
CLASSES = ('READ', 'SELECT', 'OPERATE')
FIELDS = ('run', 'block_dir', 'arm', 'trial', 'txn_class', 'ack_ms', 'clrt_ms', 'rt_ms', 'resp_len', 'retransmitted',
          'piggyback', 'condition', 'build_identity', 'capture_identity', 'exchange_id', 'extractor_sha256',
          'request_packet_index', 'response_packet_index', 'capture_out_sha256', 'capture_in_sha256')


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def block_rows(block_dir, counts=None):
    block_dir = Path(block_dir).resolve()
    rows, counts = [], {} if counts is None else counts
    timings = sorted(block_dir.glob('*/*/*/timing.json'))           # fixture / arm / trial / timing.json
    if not timings:
        raise ValueError('%s: no per-arm timing.json' % block_dir)
    record_path = block_dir / 'campaign_run.json'
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    effective = record.get('effective', {})
    condition_fields = ('timing_params_ns', 'fixture', 'k', 'shaping_requested', 'endpoint_identity')
    condition_data = {k: effective.get(k) for k in condition_fields}
    condition_data['traffic'] = {k: effective.get('traffic', {}).get(k) for k in
                                 ('run_sbo', 'sbo_cycles', 'range', 'gap_ms', 'read_pause_ms', 'close_grace_ms',
                                  'start_delay_ms')}
    condition_data['trials'] = effective.get('trials')
    condition = identity(condition_data)
    builds = record.get('builds')
    sources = record.get('source_identity', {}).get('build_sources')
    build_identity = identity({'builds': builds, 'sources': sources})
    counts['_metadata'] = dict(condition=condition, effective_condition=condition_data,
                               build_identity=build_identity, block_dir=str(block_dir))
    problems, captures, exchanges, seen_trials = [], set(), set(), set()
    if any(k not in effective for k in condition_fields + ('trials', 'traffic')) or not builds or not sources:
        problems.append('missing effective condition/build metadata in campaign_run.json')
    trials = {}
    for rec in record.get('arms', []):
        if len(rec.get('trials', [])) != effective.get('trials', {}).get('trials_per_arm'):
            problems.append('recorded arm %s lacks the declared trial count' % rec.get('arm'))
        for trial in rec.get('trials', []):
            key = (rec['fixture'], rec['arm'], trial['label'])
            if key in trials:
                problems.append('duplicate recorded trial %s' % (key,))
            trials[key] = trial
    for t in timings:
        arm_dir = t.parent.parent.name
        if arm_dir not in ARM_NAMES:
            raise ValueError('%s: unknown arm directory %r' % (t, arm_dir))
        arm = ARM_NAMES[arm_dir]
        c = counts.setdefault(arm, dict(written=0, incomplete=0, missing_interval=0, other_kind=0, invalid=0,
                                      classes={k: dict(written=0, incomplete=0, missing_interval=0, invalid=0,
                                                      observed=0, expected=0) for k in CLASSES}))
        key = (t.parent.parent.parent.name, arm_dir, t.parent.name)
        seen_trials.add(key)
        trial = trials.get(key)
        if trial is None:
            problems.append('%s: trial absent from campaign_run.json' % t)
        else:
            traffic = effective['traffic']
            actual = trial.get('conditions', {})
            if (actual.get('delay_ms') != effective['fixture']['delay_ms'] or
                    actual.get('gap_ms') != traffic.get('gap_ms', 0) or
                    actual.get('start_delay_ms') != traffic.get('start_delay_ms', 0)):
                problems.append('%s: trial condition differs from effective fixture/traffic' % t)
            declared_reads = effective['trials'].get('reads_per_trial')
            if type(declared_reads) is not int or declared_reads < 1 or trial.get('reads') != declared_reads:
                problems.append('%s: trial reads differ from declared workload' % t)
            sbo = traffic.get('sbo_cycles', 1) if traffic.get('run_sbo', True) else 0
            for k, expected in [('READ', declared_reads if type(declared_reads) is int else 0),
                                ('SELECT', sbo), ('OPERATE', sbo)]:
                c['classes'][k]['expected'] += expected
        report = json.loads(t.read_text())
        capture = report.get('capture_sha256', {})
        extractor = report.get('extractor_sha256')
        provenance_ok = (set(capture) == {'out', 'in'} and
                         all(isinstance(v, str) and len(v) == 64 for v in capture.values()) and
                         isinstance(extractor, str) and len(extractor) == 64)
        if not provenance_ok:
            problems.append('%s: extraction lacks capture/extractor provenance; re-extract retained captures' % t)
        for name in ('out', 'in'):
            raw = t.parent / (name + '.pcap')
            if raw.exists() and hashlib.sha256(raw.read_bytes()).hexdigest() != capture.get(name):
                problems.append('%s: capture digest mismatch' % raw)
        capture_id = identity(capture)
        if capture_id in captures:
            problems.append('%s: duplicated capture pair' % t)
        captures.add(capture_id)
        for e in report['exchanges']:
            kind = e.get('kind')
            if kind in CLASSES:
                c['classes'][kind]['observed'] += 1
            eid = identity([capture_id, e.get('exchange_id')])
            valid_id = bool(e.get('exchange_id') and e.get('request_key') and
                            isinstance(e.get('request_packet_index'), int) and
                            (not e.get('complete') or isinstance(e.get('response_packet_index'), int)))
            if not valid_id or eid in exchanges:
                problems.append('%s: missing or duplicate exchange identity' % t)
            exchanges.add(eid)
            if e.get('kind') not in CLASSES:
                c['other_kind'] += 1
            elif not e.get('complete'):
                c['incomplete'] += 1
                c['classes'][kind]['incomplete'] += 1
            elif e.get('ack_lat_us') is None or e.get('clrt_us') is None:
                c['missing_interval'] += 1
                c['classes'][kind]['missing_interval'] += 1
            else:
                values = (e['ack_lat_us'], e['clrt_us'])
                size = e.get('resp_len')
                valid = (all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
                             for v in values) and isinstance(size, int) and not isinstance(size, bool) and size > 0)
                if e.get('rt_us') is not None:
                    valid = valid and isinstance(e['rt_us'], (int, float)) and math.isfinite(e['rt_us'])
                if not valid or not valid_id or not provenance_ok:
                    c['invalid'] += 1; c['classes'][kind]['invalid'] += 1
                    problems.append('%s: invalid observed intervals/length/identity' % t)
                    continue
                c['written'] += 1
                c['classes'][kind]['written'] += 1
                rows.append(dict(run=block_dir.name, block_dir=str(block_dir), arm=arm, trial=t.parent.name,
                                 txn_class=e['kind'], ack_ms=e['ack_lat_us'] / 1000.0, clrt_ms=e['clrt_us'] / 1000.0,
                                 rt_ms=(e['rt_us'] / 1000.0) if e.get('rt_us') is not None else '',
                                 resp_len=e.get('resp_len', ''), retransmitted=bool(e.get('retransmitted')),
                                 piggyback=bool(e.get('piggyback')), condition=condition, build_identity=build_identity,
                                 capture_identity=capture_id, exchange_id=eid, extractor_sha256=extractor,
                                 request_packet_index=e['request_packet_index'],
                                 response_packet_index=e.get('response_packet_index'),
                                 capture_out_sha256=capture.get('out'), capture_in_sha256=capture.get('in')))
    if seen_trials != set(trials):
        problems.append('recorded trials and extracted timing files differ')
    if problems:
        counts['_problems'] = problems
        raise ValueError('; '.join(problems))
    return rows, counts


def _replay_capture(out_path, in_path, allow_missing=False):
    """Load the repo's extractor locally; callers need no PYTHONPATH configuration."""
    source = next(parent / 'protocol' / 'hw_vepa' / 'clrt_check.py' for parent in Path(__file__).resolve().parents
                  if (parent / 'protocol' / 'hw_vepa' / 'clrt_check.py').exists())
    spec = importlib.util.spec_from_file_location('publication_clrt_check', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.analyze(out_path, in_path, allow_missing=allow_missing)


def _json_evidence(path):
    if not path.exists():
        return None, dict(path=str(path), status='unavailable', reason='missing_file')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        value = json.loads(path.read_text())
        json.dumps(value, allow_nan=False)
        if not isinstance(value, dict):
            raise ValueError('expected JSON object')
        return value, dict(path=str(path), sha256=digest, status='ok')
    except (ValueError, UnicodeError) as error:
        return None, dict(path=str(path), sha256=digest, status='unavailable', reason='partial_or_invalid_json',
                          error=str(error))


def publication_ledger(block_dir, labels=None):
    """Export every capture exchange and actual endpoint task record, without inventing gaps."""
    block_dir = Path(block_dir).resolve()
    labels = {} if labels is None else labels
    if set(labels) - {'condition', 'round', 'split', 'trials'}:
        raise ValueError('labels accepts only condition/round/split/trials')
    legacy_counts = {}
    try:
        legacy, legacy_counts = block_rows(block_dir, legacy_counts)
        validation = dict(status='ok', problems=[])
    except (ValueError, KeyError, OSError) as error:
        legacy = []
        validation = dict(status='error', problems=[str(error)])
    legacy_by_id = {r['exchange_id']: r for r in legacy}
    records, sources, trial_counts = [], [], []
    campaign, campaign_source = _json_evidence(block_dir / 'campaign_run.json')
    sources.append(campaign_source)
    effective = (campaign or {}).get('effective', {})
    condition_evidenced = all(key in effective and effective[key] is not None for key in
                             ('timing_params_ns', 'fixture', 'k', 'shaping_requested', 'endpoint_identity', 'trials', 'traffic'))
    trial_dirs = {path.parent for pattern in ('*/*/*/timing.json', '*/*/*/master.json', '*/*/*/out.pcap',
                                             '*/*/*/in.pcap', '*/*/*/result.json', '*/*/*/outstation.json')
                  for path in block_dir.glob(pattern)}
    for trial_dir in sorted(trial_dirs):
        path = trial_dir / 'timing.json'
        arm_dir = trial_dir.parent.name
        if arm_dir not in ARM_NAMES:
            raise ValueError('unknown arm directory %s' % trial_dir.parent)
        report, timing_source = _json_evidence(path)
        sources.append(timing_source)
        capture_availability = {}
        for direction in ('out', 'in'):
            capture_path = trial_dir / (direction + '.pcap')
            info = dict(path=str(capture_path), status='unavailable', reason='capture_file_missing')
            if capture_path.exists():
                usable = capture_path.stat().st_size >= 24
                info.update(status='observed' if usable else 'unavailable',
                            reason=None if usable else 'truncated_capture_header',
                            sha256=hashlib.sha256(capture_path.read_bytes()).hexdigest())
            capture_availability[direction] = info
            sources.append(info)
        if any('sha256' in info for info in capture_availability.values()):
            report = _replay_capture(trial_dir / 'out.pcap', trial_dir / 'in.pcap', allow_missing=True)
        if report is None:
            report = {'exchanges': []}
        capture = report.get('capture_sha256', {})
        capture_id = identity(capture) if capture else None
        trial_labels = {k: labels.get(k) for k in ('condition', 'round', 'split')}
        overrides = labels.get('trials', {}).get(trial_dir.name, {})
        if set(overrides) - set(trial_labels):
            raise ValueError('trial labels accepts only condition/round/split')
        trial_labels.update(overrides)
        metadata = legacy_counts.get('_metadata', {})
        if trial_labels['condition'] is None and condition_evidenced:
            trial_labels['condition'] = metadata.get('condition')
        collection, collection_source = _json_evidence(trial_dir / 'result.json')
        sources.append(collection_source)
        common = dict(run=block_dir.name, block_dir=str(block_dir), block_id=block_dir.name,
                      arm=ARM_NAMES[arm_dir], trial=trial_dir.name,
                      session_id=identity([str(block_dir), str(trial_dir.relative_to(block_dir)), capture_id]),
                      capture_availability=capture_availability,
                      capture_identity=capture_id, capture_out_sha256=capture.get('out'),
                      capture_in_sha256=capture.get('in'), extractor_sha256=report.get('extractor_sha256'),
                      extractor_sources_sha256=report.get('extractor_sources_sha256'),
                      endpoint_collection=(collection or {}).get('endpoint_collection'),
                      master_timeout=(collection or {}).get('master_timeout'),
                      audit_null_reasons={field: 'frozen_schedule_label_not_supplied' for field in ('condition', 'round', 'split')
                                          if trial_labels[field] is None},
                      **trial_labels)
        captured = []
        for exchange in report.get('exchanges', []):
            eid = identity([capture_id, exchange['exchange_id']]) if capture_id and exchange.get('exchange_id') else None
            pub = exchange.get('publication', {})
            request_key = exchange.get('request_key')
            row = dict(common, record_type='captured_exchange', exchange_id=eid,
                       connection_id=identity([common['session_id'], request_key.get('flow'), request_key.get('inc')])
                       if common['session_id'] and request_key else None,
                       txn_class=exchange.get('kind'), complete=exchange.get('complete'),
                       retransmitted=exchange.get('retransmitted'), piggyback=exchange.get('piggyback'),
                       attempts=exchange.get('attempts'), request_key=request_key,
                       integrity_audit=dict(request_dnp3_crc_ok=exchange.get('req_crc_ok'),
                                            response_dnp3_crc_ok=exchange.get('resp_crc_ok')),
                       observation=exchange.get('observation'), publication_schema_version=report.get('schema_version'),
                       request_packet_index=exchange.get('request_packet_index'),
                       ack_packet_index=((exchange.get('observation') or {}).get('ack') or {}).get('packet_index'),
                       response_packet_index=exchange.get('response_packet_index'),
                       legacy_feature_eligible=eid in legacy_by_id,
                       ack_ms=exchange['ack_lat_us'] / 1000.0 if exchange.get('ack_lat_us') is not None else None,
                       clrt_ms=exchange['clrt_us'] / 1000.0 if exchange.get('clrt_us') is not None else None,
                       rt_ms=exchange['rt_us'] / 1000.0 if exchange.get('rt_us') is not None else None,
                       resp_len=exchange.get('resp_len'))
            row.update(pub)
            if not pub:
                row['null_reasons'] = dict(publication='raw_captures_unavailable_replay_required')
                row['publication_complete'] = False
                row['publication_response_packet_index'] = None
                for field in ('request_timestamp_ns', 'ack_timestamp_ns', 'response_timestamp_ns',
                              'response_availability_ns', 'request_delivery_ns', 'operate_hold_ns',
                              'ack_latency_ns', 'clrt_ns', 'response_latency_ns', 'request_len', 'response_len',
                              'sequence', 'observed_at_ms'):
                    row[field] = None
            reasons = []
            if not exchange.get('complete'):
                reasons.append('missing_covering_response')
            if pub and not pub.get('publication_complete'):
                reasons.append('publication_response_ownership_not_established')
            if exchange.get('retransmitted'):
                reasons.append('tcp_retransmission_observed')
            if exchange.get('piggyback'):
                reasons.append('piggyback_ack')
            if any(reason != 'not_operate' for reason in row['null_reasons'].values()):
                reasons.append('publication_metrics_have_explicit_nulls')
            row['status'] = 'incomplete' if not exchange.get('complete') else ('uncertain' if reasons else 'observed')
            row['status_reasons'] = reasons
            row['fallback'] = collection.get('fallback') if collection and type(collection.get('fallback')) is bool else None
            row['fallback_reason'] = 'explicit_result_evidence' if row['fallback'] is not None else 'not_inferable_from_capture_alone'
            if row['fallback']:
                row['status_reasons'].append('explicit_fallback_recorded')
                row['status'] = 'fallback'
            if eid in legacy_by_id:
                old = legacy_by_id[eid]
                for key in ('txn_class', 'ack_ms', 'clrt_ms', 'rt_ms', 'resp_len', 'retransmitted', 'piggyback',
                            'request_packet_index', 'response_packet_index'):
                    if old[key] != ('' if row[key] is None and old[key] == '' else row[key]):
                        raise ValueError('legacy feature subset disagrees with capture replay for %s/%s' % (eid, key))
            captured.append(row)
            records.append(row)
        master, master_source = _json_evidence(trial_dir / 'master.json')
        sources.append(master_source)
        issued = []
        if master is not None:
            has_cycles = isinstance(master.get('cycles'), list)
            candidates = master['cycles'] if has_cycles else [master]
            for index, task in enumerate(candidates):
                if not isinstance(task, dict) or type(task.get('issued_ns')) is not int:
                    continue
                task_id = identity([master_source['sha256'], 'cycles' if has_cycles else 'task', index])
                evidence = {k: task[k] for k in ('cycle', 'issued_ns', 'completed_ns', 'callbacks', 'summary', 'ok')
                            if k in task}
                record = dict(common, record_type='endpoint_issued_task', exchange_id=None, endpoint_task_id=task_id,
                              connection_id=None, txn_class=None, endpoint_evidence=evidence,
                              endpoint_clock='endpoint_steady_clock_ns', status='issued_task_observed',
                              status_reasons=['endpoint_task_does_not_identify_individual_READ_SELECT_OPERATE'],
                              captured_exchange_ids=None, null_reasons=dict(
                                  captured_exchange_ids='no_cross_clock_identity_binding_evidenced'))
                issued.append(record)
                records.append(record)
        read_rows = [r for r in captured if r['txn_class'] == 'READ']
        requested = master.get('reads_requested') if master else None
        read_evidence = master.get('reads') if master and isinstance(master.get('reads'), list) else None
        request_counts_observed = capture_availability['out']['status'] == 'observed' or bool(captured)
        trial_counts.append(dict(session_id=common['session_id'], trial=trial_dir.name, arm=common['arm'],
                                 capture_availability=capture_availability,
                                 captured_exchanges=len(captured) if request_counts_observed else None,
                                 captured_attempts=sum(r['attempts'] or 0 for r in captured) if request_counts_observed else None,
                                 captured_reads=len(read_rows) if request_counts_observed else None,
                                 incomplete=sum(not r['complete'] for r in captured) if request_counts_observed else None,
                                 publication_incomplete=sum(not r.get('publication_complete', False) for r in captured)
                                 if request_counts_observed else None,
                                 retransmitted=sum(bool(r['retransmitted']) for r in captured),
                                 endpoint_issued_tasks=len(issued), endpoint_reads_requested=requested,
                                 endpoint_read_records=len(read_evidence) if read_evidence is not None else None,
                                 endpoint_read_issue_identities=None,
                                 endpoint_read_identity_gap_reason='current_endpoint_does_not_log_per_READ_issue_identity',
                                 requested_read_capture_gap=requested - len(read_rows)
                                 if type(requested) is int and request_counts_observed else None,
                                 count_unavailability_reason=None if request_counts_observed else 'out_capture_unavailable',
                                 uncertainty=['READ issue identities/timestamps absent from current endpoint log',
                                              'reads_requested is workload evidence, not proof every READ was issued',
                                              'SBO task issue evidence is not an individual protocol-request identity']))
    exchange_records = [r for r in records if r['record_type'] == 'captured_exchange']
    eligible = [r['exchange_id'] for r in exchange_records if r['legacy_feature_eligible']]
    if len(eligible) != len(set(eligible)) or set(eligible) != set(legacy_by_id):
        raise ValueError('legacy feature subset fails ledger reconciliation')
    unknown_request_trials = sum(c['captured_exchanges'] is None for c in trial_counts)
    result = dict(schema_version='vision-publication-ledger-v1', records=records, sources=sources,
                  counts=dict(trials=trial_counts, captured_exchanges=len(exchange_records) if not unknown_request_trials else None,
                              retained_exchange_records=len(exchange_records), unavailable_request_count_trials=unknown_request_trials,
                              endpoint_issued_tasks=len(records) - len(exchange_records),
                              legacy_feature_rows=len(legacy)), legacy_validation=validation,
                  bindings=dict(legacy_exchange_ids_sha256=identity(sorted(eligible)),
                                captured_exchange_ids_sha256=identity(sorted(r['exchange_id'] for r in exchange_records
                                                                           if r['exchange_id']))))
    json.dumps(result, allow_nan=False)
    return result


def export_publication_ledger(path, block_dirs, labels=None):
    """Write a bound evidence sidecar. labels maps block directory name to schedule label arguments."""
    blocks = [publication_ledger(block, (labels or {}).get(Path(block).name)) for block in block_dirs]
    result = dict(schema_version='vision-publication-ledger-export-v1', blocks=blocks)
    result['content_sha256'] = identity(blocks)
    Path(path).write_text(json.dumps(result, indent=1, allow_nan=False) + '\n')
    return result


def main(argv):
    out, blocks = Path(argv[1]), argv[2:]
    rows, counts, problems, seen_paths, conditions, builds, captures, exchanges = [], {}, [], set(), set(), set(), {}, set()
    for b in blocks:
        path = Path(b).resolve()
        if path in seen_paths or path.name in counts:
            problems.append('duplicate input block %s' % path)
            continue
        seen_paths.add(path)
        c = counts.setdefault(path.name, {})
        try:
            r, c = block_rows(path, c)
        except (ValueError, KeyError, OSError) as error:
            problems.append('%s: %s' % (path, error))
            continue
        rows += r
        conditions.add(c['_metadata']['condition']); builds.add(c['_metadata']['build_identity'])
        for arm in ARM_NAMES.values():
            if arm not in c:
                problems.append('%s: missing arm %s' % (path, arm))
                continue
            for kind in CLASSES:
                stat = c[arm]['classes'][kind]
                if not stat['written'] or stat['observed'] != stat['expected']:
                    problems.append('%s/%s/%s: incomplete class/request coverage' % (path, arm, kind))
        for row in r:
            group = (row['run'], row['arm'], row['trial'])
            if captures.setdefault(row['capture_identity'], group) != group:
                problems.append('capture pair reused across input blocks/arms/trials')
            for key in ('capture_out_sha256', 'capture_in_sha256'):
                if captures.setdefault(row[key], group) != group:
                    problems.append('capture reused across input blocks/arms/trials')
            if row['exchange_id'] in exchanges:
                problems.append('duplicate exchange identity across inputs')
            exchanges.add(row['exchange_id'])
    if len(seen_paths) < 3 or len(conditions) != 1 or len(builds) != 1:
        problems.append('main comparison requires at least three independent blocks of one condition and build')
    if problems:
        counts['_problems'] = problems
    if problems:
        Path(str(out) + '.counts.json').write_text(json.dumps(counts, indent=1, allow_nan=False) + '\n')
        raise ValueError('; '.join(problems))
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    counts['_table'] = dict(sha256=hashlib.sha256(out.read_bytes()).hexdigest(), rows=len(rows),
                           exchange_ids_sha256=identity(sorted(r['exchange_id'] for r in rows)),
                           capture_ids_sha256=identity(sorted({r['capture_identity'] for r in rows})))
    Path(str(out) + '.counts.json').write_text(json.dumps(counts, indent=1, allow_nan=False) + '\n')
    print('%d exchanges from %d blocks -> %s' % (len(rows), len(blocks), out))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
