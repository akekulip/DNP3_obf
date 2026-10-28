#!/usr/bin/env python3
"""Corrected-v3 TCP reassembly over the retained c72 captures, written beside (never over) the historical record.

For every retained connection of the named campaigns, re-run relay_check.analyze on the retained out.pcap, in.pcap,
master.json and result.json with the arguments campaign_base.relay_verdict used: the trial's master port (c2 of a
reconnect scenario adds reconnect_port_offset), READ = trial reads, SELECT = OPERATE = checks.sbo_count(traffic),
the config's read_schedule, the relay_verdict profile/image post-checks, and close_checks where the persistence or
reconnect scenario ran them.  Each result is diffed per field against the historical relay_wire.json, and the
eval_rows row extractor is run on both to count changed rows.  Nothing under results/hardware/ is written.

  python3 scripts/analysis/corrected_v3.py --output results/analysis/corrected_v3
  python3 scripts/analysis/corrected_v3.py --checker-root FROZEN_TREE --output OUT   # frozen-checker control
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'c72-corrected-v3-v1'
CAMPAIGNS = ('rc01_hw_c72_eval_20261027_01', 'rc01_hw_c72_20261027_02')
CHECKER_FILES = ('scripts/checks/relay_check.py', 'scripts/checks/wire_check.py',
                 'scripts/checks/endpoint_profiles.py', 'scripts/checks/checks.py', 'scripts/checks/standards.py',
                 'scripts/hardware/active_harness/dnp3_codec.py')
CONNECTION_FILES = ('out.pcap', 'in.pcap', 'master.json', 'result.json', 'capture_offloads.json', 'relay_wire.json')
SPAN_FIELDS = ('sequence_start', 'sequence_end', 'start_offset', 'end_offset', 'first_timestamp_ns',
               'complete_timestamp_ns', 'actual_payload_lengths', 'wire_hex')
NEW_SPAN_FIELDS = ('unique_bytes', 'packet_bytes', 'retransmitted_bytes', 'retransmitted_segments')
EXCHANGE_FIELDS = ('operation', 'workload', 'ack_timestamp_ns', 'complete_clrt_us', 'piggyback')
REPORT_FIELDS = ('ok', 'failures', 'retransmissions', 'capture_drops', 'artifacts')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def json_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_checker(checker_root):
    """relay_check, checks and standards from checker_root: the working tree, or a materialised frozen tree."""
    sys.path.insert(0, str(Path(checker_root) / 'scripts/checks'))
    sys.path.append(str(ROOT / 'scripts/analysis'))
    import relay_check
    import checks
    import standards
    import eval_rows
    return relay_check, checks, standards, eval_rows


def connections(campaign_dir, inputs):
    """Each retained connection with the analyze arguments its campaign step used."""
    manifest_path = campaign_dir / 'manifest.json'
    inputs[str(manifest_path)] = sha(manifest_path)
    for step in json.loads(manifest_path.read_text())['steps']:
        argv = step['argv']
        config_path, options = Path(argv[4]), argv[6:]
        inputs[str(config_path)] = sha(config_path)
        config = json.loads(config_path.read_text())
        scenario = options[options.index('--scenario') + 1] if '--scenario' in options else None
        terminal = campaign_dir / campaign_dir.name / 'steps' / step['id'] / 'terminal.json'
        status = json.loads(terminal.read_text()).get('status') if terminal.is_file() else None
        for trial_path in sorted(Path(step['run_root']).glob('*/*/*/trial.json')):
            inputs[str(trial_path)] = sha(trial_path)
            trial, directory = json.loads(trial_path.read_text()), trial_path.parent
            arm = next(a for a in config['arms'] if a['name'] == directory.parent.name)
            close_mode, names = None, {'single': directory}
            if argv[3] == 'persistence':
                close_mode = options[options.index('--close-mode') + 1]
                names = {name: directory / name for name in ('c1', 'c2', 'c3')}
            elif scenario == 'reconnect':
                close_mode = 'graceful'
                names = {name: directory / name for name in ('c1', 'c2', 'c3')}
            for name, path in names.items():
                port = trial['master_port']
                if scenario == 'reconnect' and name == 'c2':
                    port += config['scenarios']['reconnect']['reconnect_port_offset']
                yield dict(campaign=campaign_dir.name, block=step['id'], step_status=status, arm=arm,
                           trial=directory.name, connection=name, directory=path, master_port=port,
                           reads=trial['reads'], traffic=config['traffic'], close_mode=close_mode,
                           native=scenario == 'reconnect' and name == 'c2')


def analyse(modules, conn):
    """relay_check.analyze plus the relay_verdict post-checks, as campaign_base.relay_verdict applied them."""
    relay_check, checks, standards, _ = modules
    sbo = checks.sbo_count(conn['traffic'])
    expected = dict(READ=conn['reads'], SELECT=sbo, OPERATE=sbo)
    try:
        report = relay_check.analyze(conn['directory'], conn['master_port'], expected, conn['traffic']['read_schedule'])
        master = json.loads((conn['directory'] / 'master.json').read_text())
        for direction, packets in report['packets'].items():
            for packet in packets:
                header = 40 if direction == 'out' else 44
                if packet['flags'] & 2:
                    if packet['tcp_header_bytes'] != header:
                        report['failures'].append('SYN header differs from selected physical TCP profile')
                elif packet['payload_len'] and (packet['tcp_header_bytes'] != 32 or packet['ipv4_header_bytes'] != 20
                                                or not packet['tcp_options_hex'].startswith('0101080a')):
                    report['failures'].append('data header/options differ from selected physical TCP profile')
        padded = bool(conn['arm']['padding'] and not conn['native'])
        for record in master['records']:
            operation, workload = record['operation'], record.get('workload')
            image = standards.SEL751_IMAGES[padded].get(workload if operation == 'READ' else operation)
            if len(bytes.fromhex(record.get('response_wire_hex', ''))) != image:
                report['failures'].append('response length differs from selected relay image: ' + operation)
        if conn['close_mode'] is not None:
            report['failures'] += relay_check.close_checks(report, conn['close_mode'])
        report['ok'] = not report['failures']
        return report
    except (OSError, ValueError, KeyError, TypeError) as error:
        return dict(ok=False, failures=['missing/malformed physical relay evidence: ' + str(error)], exchanges=[])


def span_view(part):
    if not part:
        return part
    view = {field: part.get(field) for field in SPAN_FIELDS + NEW_SPAN_FIELDS if field != 'wire_hex'}
    view['packet_indices'] = [packet['index'] for packet in part.get('packets', [])]
    return view


def compact(report):
    """The v3 result without packet records (their SHA-256 is kept); reproducible from the hashed inputs."""
    view = {field: report.get(field) for field in ('schema',) + REPORT_FIELDS +
            ('retransmitted_bytes', 'unique_bytes', 'packet_bytes')}
    view['packets_sha256'] = json_sha(report.get('packets'))
    view['exchanges'] = [dict({field: e.get(field) for field in EXCHANGE_FIELDS},
                              request=span_view(e.get('request')), response=span_view(e.get('response')),
                              application_ok=(e.get('application') or {}).get('ok'))
                         for e in report.get('exchanges', [])]
    return view


def field_diff(historical, current):
    """(field, historical, v3) for every compared field that differs; fields new in v3 are not differences."""
    found = []

    def note(field, old, new):
        if old != new:
            found.append(dict(field=field, historical=old, v3=new))
    for field in REPORT_FIELDS:
        note(field, historical.get(field), current.get(field))
    note('packets_sha256', json_sha(historical.get('packets')), json_sha(current.get('packets')))
    old_exchanges, new_exchanges = historical.get('exchanges') or [], current.get('exchanges') or []
    note('exchange_count', len(old_exchanges), len(new_exchanges))
    for i, (old, new) in enumerate(zip(old_exchanges, new_exchanges)):
        for field in EXCHANGE_FIELDS:
            note('exchanges[%d].%s' % (i, field), old.get(field), new.get(field))
        old_app, new_app = old.get('application') or {}, new.get('application') or {}
        for field in ('ok', 'failures', 'points'):
            note('exchanges[%d].application.%s' % (i, field), old_app.get(field), new_app.get(field))
        for span in ('request', 'response'):
            old_span, new_span = old.get(span) or {}, new.get(span) or {}
            note('exchanges[%d].%s.located' % (i, span), bool(old_span), bool(new_span))
            if old_span and new_span:
                for field in SPAN_FIELDS:
                    note('exchanges[%d].%s.%s' % (i, span, field), old_span.get(field), new_span.get(field))
                note('exchanges[%d].%s.packet_indices' % (i, span), span_view(old_span)['packet_indices'],
                     span_view(new_span)['packet_indices'])
    return found


def row_diff(eval_rows, conn, current):
    """Rows eval_rows.trial_rows derives from the historical and the v3 relay_wire.json, compared field by field."""
    old_rows, _, _ = eval_rows.trial_rows(conn['directory'], {})
    with tempfile.TemporaryDirectory() as scratch:
        trial = Path(scratch) / conn['directory'].name
        trial.mkdir()
        for name in eval_rows.ARTIFACTS:
            os.symlink(conn['directory'] / name, trial / name)
        (trial / 'relay_wire.json').write_text(json.dumps(current))
        new_rows, _, _ = eval_rows.trial_rows(trial, {})
    changes = [dict(seq=old.get('seq'), field=field, historical=old.get(field), v3=new.get(field))
               for old, new in zip(old_rows, new_rows) for field in sorted(set(old) | set(new))
               if old.get(field) != new.get(field)]
    if len(old_rows) != len(new_rows):
        changes.append(dict(seq=None, field='row_count', historical=len(old_rows), v3=len(new_rows)))
    return len(old_rows), len(new_rows), changes


def run(checker_root, output, campaigns):
    modules = load_checker(checker_root)
    inputs, records, results = {}, [], []
    for campaign in campaigns:
        for conn in connections(ROOT / 'results/hardware/campaigns' / campaign, inputs):
            for name in CONNECTION_FILES:
                if (conn['directory'] / name).is_file():
                    inputs[str(conn['directory'] / name)] = sha(conn['directory'] / name)
            if not (conn['directory'] / 'relay_wire.json').is_file():
                results.append(dict(key(conn), retained=False))
                continue
            historical = json.loads((conn['directory'] / 'relay_wire.json').read_text())
            current = analyse(modules, conn)
            rows_before, rows_after, row_changes = row_diff(modules[3], conn, current)
            differences = field_diff(historical, current)
            results.append(dict(key(conn), retained=True, step_status=conn['step_status'],
                                historical_schema=historical.get('schema'), v3_schema=current.get('schema'),
                                historical_ok=historical.get('ok'), v3_ok=current.get('ok'),
                                historical_exchanges=len(historical.get('exchanges') or []),
                                v3_exchanges=len(current.get('exchanges') or []),
                                historical_retransmissions=historical.get('retransmissions'),
                                v3_retransmissions=current.get('retransmissions'),
                                v3_retransmitted_bytes=current.get('retransmitted_bytes'),
                                rows=[rows_before, rows_after], differences=differences, row_changes=row_changes))
            records.append(dict(key(conn), v3=compact(current)))
    checker = {path: dict(sha256=sha(Path(checker_root) / path), freeze_sha256={
        campaign: json.loads((ROOT / 'results/hardware/campaigns' / campaign / 'freeze.json').read_text())
        ['files'].get(path, {}).get('sha256') for campaign in campaigns}) for path in CHECKER_FILES}
    output.mkdir(parents=True, exist_ok=True)
    with (output / 'connections_v3.jsonl.gz').open('wb') as raw, \
            gzip.GzipFile('', 'wb', fileobj=raw, mtime=0) as stream:
        for record in records:
            stream.write((json.dumps(record, sort_keys=True) + '\n').encode())
    (output / 'diff.json').write_text(json.dumps(dict(schema=SCHEMA, checker_root=str(checker_root),
                                                       connections=results), indent=1) + '\n')
    manifest = dict(schema=SCHEMA, script=dict(path='scripts/analysis/corrected_v3.py', sha256=sha(__file__)),
                    eval_rows_sha256=sha(ROOT / 'scripts/analysis/eval_rows.py'), checker_root=str(checker_root),
                    checker_files=checker, python=platform.python_version(), inputs=inputs,
                    outputs={name: sha(output / name) for name in ('connections_v3.jsonl.gz', 'diff.json')})
    (output / 'input_manifest.json').write_text(json.dumps(manifest, indent=1) + '\n')
    return results, checker


def key(conn):
    return dict(campaign=conn['campaign'], block=conn['block'], arm=conn['arm']['name'], trial=conn['trial'],
                connection=conn['connection'], master_port=conn['master_port'], close_mode=conn['close_mode'],
                path=str(conn['directory'].relative_to(ROOT)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--checker-root', type=Path, default=ROOT)
    parser.add_argument('--campaign', action='append', choices=CAMPAIGNS)
    args = parser.parse_args(argv)
    output = args.output.resolve()
    if output == ROOT / 'results/hardware' or ROOT / 'results/hardware' in output.parents:
        parser.error('outputs never go under results/hardware/')
    results, _ = run(args.checker_root.resolve(), output, args.campaign or list(CAMPAIGNS))
    totals = {}
    for row in results:
        t = totals.setdefault(row['campaign'], dict(connections=0, exchanges=0, differing_connections=0,
                                                    differences=0, changed_rows=0))
        t['connections'] += 1
        t['exchanges'] += row.get('v3_exchanges', 0)
        t['differing_connections'] += bool(row.get('differences') or row.get('row_changes'))
        t['differences'] += len(row.get('differences') or [])
        t['changed_rows'] += len({c['seq'] for c in row.get('row_changes') or []})
    print(json.dumps(totals, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
