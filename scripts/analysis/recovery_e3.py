#!/usr/bin/env python3
"""E3 SELECT-loss recovery: per-trial SELECT/OPERATE timeline and CROB status from the captured bytes.

    python3 scripts/analysis/recovery_e3.py BLOCK_DIR [BLOCK_DIR ...] > results/analysis/recovery_e3/e3_trials.json

Reads each trial's relay_wire.json (exchange timestamps, CROB points decoded from the captured bytes), in.pcap
(every captured copy of the dropped SELECT response, including the relay's retransmission), result.json (the loss
rule that fired) and standards_verdict.json (the recorded verdict).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/checks'))
import wire_check  # noqa: E402


def first_ns(part):
    packets = (part or {}).get('packets') or []
    return packets[0]['timestamp_ns'] if packets else None


def ms(a, b):
    return None if a is None or b is None else round((b - a) / 1e6, 3)


def trial(path):
    wire = json.loads((path / 'relay_wire.json').read_text())
    result = json.loads((path / 'result.json').read_text())
    verdict = json.loads((path / 'standards_verdict.json').read_text())
    ops = {e['operation']: e for e in wire['exchanges'] if e['operation'] in ('SELECT', 'OPERATE')}
    sel, op = ops.get('SELECT'), ops.get('OPERATE')
    row = dict(trial=path.name, ok=result.get('ok'), verdict_ok=verdict.get('ok'),
               verdict_failures=verdict.get('failures'), loss=result.get('loss'))
    if sel is None:
        return dict(row, problem='no SELECT exchange')
    seq = sel['response']['sequence_start']
    copies = [s['t_us'] * 1000 for s in wire_check.parse(path / 'in.pcap')[0]
              if s['sport'] == 20000 and s['seq'] == seq and s['len']]
    t0 = first_ns(sel['request'])
    row.update(
        select_request_ns=t0, select_points=sel['application'].get('points'),
        select_response_copies=len(copies),
        ms_from_select_request=dict(
            relay_ack_of_select=ms(t0, sel.get('ack_timestamp_ns')),
            first_select_response_copy=ms(t0, copies[0] if copies else None),
            retransmitted_select_response_copy=ms(t0, copies[1] if len(copies) > 1 else None),
            operate_request=ms(t0, first_ns((op or {}).get('request'))),
            relay_ack_of_operate=ms(t0, (op or {}).get('ack_timestamp_ns')),
            operate_response=ms(t0, first_ns((op or {}).get('response')))),
        operate_points=(op or {}).get('application', {}).get('points'))
    return row


def main(blocks):
    rows = [trial(t) for b in blocks for t in sorted(Path(b).glob('physical_relay/*/*_t*')) if t.is_dir()]
    statuses = {}
    for r in rows:
        key = ','.join('%s:%s' % (p, s) for p, s in (r.get('operate_points') or []))
        statuses[key] = statuses.get(key, 0) + 1
    print(json.dumps(dict(trials=len(rows), operate_status_counts=statuses, rows=rows), indent=1, default=str))


if __name__ == '__main__':
    main(sys.argv[1:])
