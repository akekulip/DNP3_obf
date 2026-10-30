#!/usr/bin/env python3
"""E3 SELECT-loss recovery: compare failed and successful OPERATE transactions across builds from retained captures.

    $RESEARCH_PYTHON scripts/analysis/recovery_compare.py --build c72 BLOCK... --build c74 BLOCK... --out OUT.json

Per trial, on top of recovery_e3.trial (master-side timeline and CROB status from the captured bytes):
- the relay's TCP timestamps: TSval of its ACK of the SELECT and of the OPERATE, and their difference in relay ticks
  (the relay TSval advances in 30 ms steps);
- a derived tick phase of the OPERATE departure: the block's relay clock fitted on the earliest arrival per TSval,
  grid placed by the smallest residual. It ignores one-way delay, so it carries about 1 ms of systematic error, more
  in timed arms where the switch holds responses;
- relay windows on those ACKs, relay IP-ID gaps, repeated relay pure ACKs, master OPERATE copies, application control
  bytes, IIN, and whether the OPERATE objects equal the SELECT objects.
A feature "separates" when the TIMEOUT and SUCCESS ranges are disjoint, pooled over the builds or within one build.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'scripts/checks')]
import recovery_e3  # noqa: E402
import wire_check  # noqa: E402

RELAY_PORT, TICK = 20000, 30
FEATURES = ('master_select_to_operate_ms', 'relay_ticks_select_to_operate', 'operate_tick_phase_ms_derived',
            'relay_ack_delay_select_ms', 'relay_ack_delay_operate_ms', 'first_select_response_copy_ms',
            'retransmission_gap_ms', 'retransmission_to_operate_ms', 'relay_window_select_ack',
            'relay_window_operate_ack', 'operate_copies', 'extra_relay_pure_acks')


def tcp_fields(frame):
    """IPv4 identification, TCP window and the timestamp option (None when absent) from an Ethernet frame."""
    ip = 14
    tcp = ip + (frame[ip] & 0x0f) * 4
    options, i, ts = frame[tcp + 20:tcp + (frame[tcp + 12] >> 4) * 4], 0, (None, None)
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        length = options[i + 1] if i + 1 < len(options) else 0
        if length < 2:
            break
        if kind == 8 and length == 10:
            ts = (int.from_bytes(options[i + 2:i + 6], 'big'), int.from_bytes(options[i + 6:i + 10], 'big'))
        i += length
    return dict(ip_id=int.from_bytes(frame[ip + 4:ip + 6], 'big'),
                window=int.from_bytes(frame[tcp + 14:tcp + 16], 'big'), tsval=ts[0], tsecr=ts[1])


def segments(path, name, relay_side):
    out = []
    for s in wire_check.parse(path / name)[0]:
        if (s['sport'] if relay_side else s['dport']) == RELAY_PORT:
            out.append(dict(s, **tcp_fields(s['frame'])))
    return sorted(out, key=lambda s: (s['timestamp_ns'], s['index']))


def at(segs, ns):
    return next((s for s in segs if s['timestamp_ns'] == ns), None)


def trial(path, build, condition):
    base = recovery_e3.trial(path)
    wire = json.loads((path / 'relay_wire.json').read_text())
    ex = {e['operation']: e for e in wire['exchanges'] if e['operation'] in ('SELECT', 'OPERATE')}
    sel, op = ex['SELECT'], ex['OPERATE']
    relay, master = segments(path, 'in.pcap', True), segments(path, 'out.pcap', False)
    ack_sel, ack_op = at(relay, sel['ack_timestamp_ns']), at(relay, op['ack_timestamp_ns'])
    pure = [s['ack'] for s in relay if not s['len'] and s['flags'] == 0x10]
    ids = [s['ip_id'] for s in relay]
    m = base['ms_from_select_request']
    req = [e['application']['request_app_hex'] for e in (sel, op)]
    rsp = [e['application']['response_app_hex'] for e in (sel, op)]
    statuses = [s for _, s in base.get('operate_points') or []]
    return dict(base, build=build, condition=condition,
                outcome='SUCCESS' if statuses and all(s == 'SUCCESS' for s in statuses) else '/'.join(sorted(set(statuses))) or 'none',
                relay_tsval_select_ack=ack_sel['tsval'], relay_tsval_operate_ack=ack_op['tsval'],
                relay_ticks_select_to_operate=(ack_op['tsval'] - ack_sel['tsval']) / TICK,
                relay_window_select_ack=ack_sel['window'], relay_window_operate_ack=ack_op['window'],
                relay_ip_id_gaps=sum((b - a) % 65536 != 1 for a, b in zip(ids, ids[1:])),
                extra_relay_pure_acks=len(pure) - len(set(pure)),
                operate_copies=sum(1 for s in master if s['len'] and s['seq'] == op['request']['sequence_start']),
                operate_departure_ns=op['request']['first_timestamp_ns'],
                app_control=[h[:2] for h in req], iin=[h[4:8] for h in rsp],
                operate_objects_equal_select=req[0][4:] == req[1][4:],
                master_select_to_operate_ms=m['operate_request'], relay_ack_delay_select_ms=m['relay_ack_of_select'],
                relay_ack_delay_operate_ms=None if m['relay_ack_of_operate'] is None or m['operate_request'] is None
                else round(m['relay_ack_of_operate'] - m['operate_request'], 3),
                first_select_response_copy_ms=m['first_select_response_copy'],
                retransmission_gap_ms=None if m['retransmitted_select_response_copy'] is None
                else round(m['retransmitted_select_response_copy'] - m['first_select_response_copy'], 3),
                retransmission_to_operate_ms=None if m['retransmitted_select_response_copy'] is None
                else round(m['operate_request'] - m['retransmitted_select_response_copy'], 3),
                _relay_points=[(s['tsval'], s['timestamp_ns']) for s in relay if s['tsval'] is not None])


def tick_phase(rows):
    """Derived: fit the block's relay clock (ns per TSval unit) on the earliest arrival per TSval, place the tick grid
    by the smallest residual, and give each OPERATE departure's offset (ms) into its tick."""
    points = [p for r in rows for p in r['_relay_points']]
    earliest = {}
    for tsval, ns in points:
        earliest[tsval] = min(ns, earliest.get(tsval, ns))
    xs, ys = list(earliest), [earliest[x] for x in earliest]
    n, mx, my = len(xs), sum(xs) / len(xs), sum(ys) / len(ys)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    intercept = my - slope * mx
    offset = min(ns - (intercept + slope * tsval) for tsval, ns in points)
    for r in rows:
        since = r['operate_departure_ns'] - (intercept + offset)
        r['operate_tick_phase_ms_derived'] = round((since % (slope * TICK)) / 1e6, 2)
    return dict(ns_per_unit=slope, points=n)


def separates(rows, feature):
    bad = [r[feature] for r in rows if r['outcome'] != 'SUCCESS' and r[feature] is not None]
    good = [r[feature] for r in rows if r['outcome'] == 'SUCCESS' and r[feature] is not None]
    return bool(bad and good) and (max(bad) < min(good) or min(bad) > max(good))


def compare(builds):
    rows, fits = [], {}
    for build, blocks in builds.items():
        for block in blocks:
            condition = Path(block).name.split('_recovery_')[1][:2]
            block_rows = [trial(t, build, condition) for t in sorted(Path(block).glob('physical_relay/*/*_t*'))]
            fits['%s %s' % (build, condition)] = tick_phase(block_rows)
            rows += block_rows
    tsvals = [ts for r in rows for ts, _ in r['_relay_points']]
    for r in rows:
        del r['_relay_points']
    split = [f for f in FEATURES if separates(rows, f) or any(separates([r for r in rows if r['build'] == b], f)
                                                              for b in builds)]
    return dict(builds={b: dict(success=dict(n=sum(r['outcome'] == 'SUCCESS' for r in rows if r['build'] == b),
                                             of=sum(r['build'] == b for r in rows))) for b in builds},
                relay_tsval=dict(segments=len(tsvals), all_multiples_of_30=all(t % TICK == 0 for t in tsvals)),
                clock_fits=fits, features_checked=list(FEATURES), separating_features=split, rows=rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--build', nargs='+', action='append', required=True, metavar=('LABEL', 'BLOCK'))
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args(argv)
    out = compare({group[0]: [Path(p) for p in group[1:]] for group in a.build})
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1, default=str) + '\n')
    print(json.dumps({k: out[k] for k in ('builds', 'relay_tsval', 'separating_features')}, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
