#!/usr/bin/env python3
"""First request retransmitted by the master per fresh connection (exact-binary blocks), from relay_wire.json: the
first exchange's request retransmitted_segments; the delay between its first and last copy is taken from out.pcap
(master segments toward the relay carrying the request's sequence and payload).

    $RESEARCH_PYTHON first_request_retx.py TRIAL... --out OUT.json
"""
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, '/home/philip/Projects/DNP3/scripts/checks')
import wire_check  # noqa: E402


def row(path):
    w = json.loads((Path(path) / 'relay_wire.json').read_text())
    req = w['exchanges'][0]['request']
    copies = sorted(s['t_us'] for s in wire_check.parse(Path(path) / 'out.pcap')[0]
                    if s['dport'] == 20000 and s['len'] and s['seq'] == req['sequence_start'])
    return dict(trial=Path(path).name, retransmitted=req['retransmitted_segments'] > 0, copies=len(copies),
                delay_ms=round((copies[-1] - copies[0]) / 1e3, 1) if req['retransmitted_segments'] else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trials', nargs='+')
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    rows = [row(p) for p in a.trials]
    out = dict(first_request_retransmitted=dict(n=sum(r['retransmitted'] for r in rows), of=len(rows)),
               delays_ms=[r['delay_ms'] for r in rows if r['retransmitted']], per_trial=rows)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({k: v for k, v in out.items() if k != 'per_trial'}))


if __name__ == '__main__':
    sys.exit(main())
