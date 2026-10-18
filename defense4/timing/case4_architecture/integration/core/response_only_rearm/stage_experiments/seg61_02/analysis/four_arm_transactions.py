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
"""
import csv
import hashlib
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
