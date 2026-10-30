#!/usr/bin/env python3
"""Master segments in retained hardware captures that N's inherited ACK limitation would not forward.

    $RESEARCH_PYTHON scripts/analysis/master_ack_scan.py results/hardware/blocks --out OUT.json

The model (results/analysis/ack_behaviour/summary.json) shows that on c72, c74 and c75 N does not forward a master
window update or zero-window advertisement while a request is outstanding, nor a keepalive. This counts, per retained
trial, how often the supported master sent such a segment toward the relay (out.pcap: frames the master sent; in.pcap:
frames it received; both on the master NIC):
- window_change_outstanding / window_change_idle: a pure ACK repeating the previous master segment's acknowledgment
  with a different window, while a request is outstanding (master data sent, no relay data since) or not;
- zero_window: a pure ACK advertising window 0;
- keepalive: a segment of 0 or 1 octet whose sequence is the master's next sequence minus 1.
It reads captures only; whether N forwarded a segment is not judged here.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1] / 'scripts/checks')]
import wire_check  # noqa: E402
from recovery_compare import tcp_fields  # noqa: E402

RELAY_PORT, M32 = 20000, 1 << 32
CLASSES = ('window_change_outstanding', 'window_change_idle', 'zero_window', 'keepalive')


def scan(trial):
    out = [dict(s, side='master', **tcp_fields(s['frame']))
           for s in wire_check.parse(Path(trial) / 'out.pcap')[0] if s['dport'] == RELAY_PORT]
    received = [dict(s, side='relay') for s in wire_check.parse(Path(trial) / 'in.pcap')[0] if s['sport'] == RELAY_PORT]
    events = sorted(out + received, key=lambda s: (s['t_us'], s['side'] == 'master', s['index']))
    result = dict(master_segments=len(out), pure_acks=0, examples=[], **{k: 0 for k in CLASSES})
    connections = {}

    def hit(klass, s, port, **extra):
        result[klass] += 1
        result['examples'].append(dict(klass=klass, port=port, t_us=s['t_us'], **extra))

    for s in events:
        port = s['sport'] if s['side'] == 'master' else s['dport']
        c = connections.setdefault(port, dict(nxt=None, prev=None, outstanding=False))
        if s['side'] == 'relay':
            if s['len']:
                c['outstanding'] = False
            continue
        if s['flags'] & 0x07:                                        # SYN, FIN or RST
            c['nxt'], c['prev'] = (s['seq'] + s['len'] + 1) % M32, s
            continue
        if c['nxt'] is not None and s['len'] <= 1 and s['seq'] == (c['nxt'] - 1) % M32:
            hit('keepalive', s, port, length=s['len'])
        if s['len'] == 0 and s['flags'] == 0x10:
            result['pure_acks'] += 1
            if s['window'] == 0:
                hit('zero_window', s, port)
            p = c['prev']
            if p is not None and p['ack'] == s['ack'] and p['window'] != s['window']:
                hit('window_change_outstanding' if c['outstanding'] else 'window_change_idle', s, port,
                    window=[p['window'], s['window']])
        if s['len']:
            c['outstanding'] = True
            end = (s['seq'] + s['len']) % M32
            if c['nxt'] is None or (end - c['nxt']) % M32 < M32 // 2:
                c['nxt'] = end
        c['prev'] = s
    return result


def scan_all(root):
    root = Path(root)
    trials = sorted(p.parent for p in root.rglob('out.pcap'))
    totals, errors, hits = dict(master_segments=0, pure_acks=0, **{k: 0 for k in CLASSES}), [], []
    for trial in trials:
        try:
            result = scan(trial)
        except (OSError, ValueError, KeyError, IndexError) as error:
            errors.append(dict(trial=str(trial.relative_to(root)), error=repr(error)))
            continue
        for key in totals:
            totals[key] += result[key]
        if result['examples']:
            hits.append(dict(trial=str(trial.relative_to(root)), examples=result['examples']))
    return dict(root=str(root), trials=len(trials), errors=errors, totals=totals, trials_with_hits=hits)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('root', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args(argv)
    out = scan_all(a.root)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps(dict(trials=out['trials'], errors=len(out['errors']), totals=out['totals'],
                          trials_with_hits=len(out['trials_with_hits'])), indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
