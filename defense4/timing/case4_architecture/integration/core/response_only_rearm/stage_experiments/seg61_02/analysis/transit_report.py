#!/usr/bin/env python3
"""Tap-to-tap transit of every packet between Vision's transmit and receive capture points (Gate 5, tails).

  python3 transit_report.py TRIAL_DIR [TRIAL_DIR ...] [--threshold-us 500] -o transit.json

For untimed, unpadded traffic (off arms, or the production program) the switch neither holds nor rewrites
sequence numbers, so a packet in out.pcap (Vision TX) is matched to the same packet in in.pcap (Vision RX) by
(source port, destination port, seq, ack, flags, payload length). Transit = RX time - TX time, per leg:
  request       master -> outstation, payload
  outstation_ack / response    outstation -> master, bare ACK / payload
  master_ack    master -> outstation, bare ACK
Every transit above the threshold is listed with its position (index of the request it follows), and the
spacing between consecutive events in exchanges, to test the ~128-exchange recurrence. Captures are read only.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'read_reencode_01'))
import capture  # noqa: E402

OUTSTATION_PORT = 20000


def leg(rec, master_port):
    to_outstation = rec['dst'][1] == OUTSTATION_PORT
    if to_outstation:
        return 'request' if rec['payload'] else 'master_ack'
    return 'response' if rec['payload'] else 'outstation_ack'


def key(rec):
    return (rec['src'][1], rec['dst'][1], rec['seq'], rec['ack'], rec['flags'], len(rec['payload']))


def trial_transit(d, threshold_us):
    master_port = json.load(open(d / 'result.json'))['master_port']
    def records(path):
        return [r for r in capture.tcp_records(path)
                if {r['src'][1], r['dst'][1]} == {master_port, OUTSTATION_PORT}]
    sent, received = records(d / 'out.pcap'), records(d / 'in.pcap')
    first_rx = {}
    for r in received:
        first_rx.setdefault(key(r), r['time'])
    legs, events, unmatched, request_index = {}, [], 0, -1
    for r in sorted(sent, key=lambda x: x['time']):
        name = leg(r, master_port)
        if name == 'request':
            request_index += 1
        rx = first_rx.get(key(r))
        if rx is None:
            unmatched += 1
            continue
        us = round((rx - r['time']) * 1e6, 1)
        legs.setdefault(name, []).append(us)
        if us > threshold_us:
            events.append({'leg': name, 'transit_us': us, 'after_request': request_index, 'tx_time': r['time']})
    spacing = [b['after_request'] - a['after_request'] for a, b in zip(events, events[1:])]
    return {'trial': str(d), 'unmatched_tx': unmatched, 'requests': request_index + 1,
            'legs': {k: {'n': len(v), 'p50': statistics.median(v), 'max': max(v),
                         'over_threshold': sum(1 for x in v if x > threshold_us)} for k, v in legs.items()},
            'events': events, 'event_spacing_requests': spacing}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('trials', nargs='+')
    ap.add_argument('--threshold-us', type=float, default=500.0)
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = [trial_transit(Path(t), a.threshold_us) for t in a.trials]
    Path(a.output).write_text(json.dumps(out, indent=1) + '\n')
    for t in out:
        print(Path(t['trial']).name, 'requests', t['requests'], 'unmatched', t['unmatched_tx'],
              {k: (v['p50'], v['max'], v['over_threshold']) for k, v in t['legs'].items()},
              'spacing', t['event_spacing_requests'][:12])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
