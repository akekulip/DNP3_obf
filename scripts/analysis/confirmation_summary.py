#!/usr/bin/env python3
"""Counts for the connection-start fix confirmation: strict-workload trials and fresh-connection starts.

    $RESEARCH_PYTHON scripts/analysis/confirmation_summary.py strict TRIAL... --out OUT.json
    $RESEARCH_PYTHON scripts/analysis/confirmation_summary.py starts TRIAL... \
        --build-label c72_diag_mirror --source-sha256 SHA --out OUT.json

strict: per trial, the recorded verdicts, the logical transaction order against [mixed READ, SELECT, OPERATE,
integrity READ] x N (relay_wire.json, after TCP reassembly), response sizes against the class images of
standards_verdict.json, CROB SUCCESS on points 1 and 3, master and relay TCP retransmissions, and CLRT by class
(piggybacked exchanges excluded). Percentiles interpolate linearly between order statistics.

starts: per mirror-on fresh connection, which of the master's first frames (SYN, final handshake ACK, first request)
has no egress copy toward the relay while the switch counters show it received and not emitted (dev9 RX - dev64 TX
covers it). A missing handshake-ACK copy is a suppressed obsolete ACK only when a later master segment that was forwarded
covers everything it carries (sequence, acknowledgment, the same window, no newer timestamp); otherwise it is a lost
valid ACK. A missing copy the counters do not cover is reported as unexplained, never as a switch loss. Also per
connection, for a relay reply to a late forwarded handshake ACK: whether the handshake ACK's egress copy left after the
first request's, the pure ACKs acknowledging the first request before the first response (relay side from the ingress
copies, master side from in.pcap), and the first exchange's CLRT. The mirror is used for packet presence and order
only. Every count carries its denominator.
"""
import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diag_mirror_capture as cap  # noqa: E402
import diag_mirror_d3 as d3  # noqa: E402
import preservation_check as pc  # noqa: E402
import recovery_compare  # noqa: E402
import relay_check as rc  # noqa: E402

SYN = cap.wc.SYN

CYCLE = (('READ', 'mixed'), ('SELECT', None), ('OPERATE', None), ('READ', 'integrity'))
CLASS = {('READ', 'mixed'): 'READ mixed', ('SELECT', None): 'SELECT', ('OPERATE', None): 'OPERATE',
         ('READ', 'integrity'): 'READ integrity'}
FRAMES = ('none', 'syn', 'suppressed_obsolete_ack', 'lost_valid_ack', 'first_request', 'unexplained_missing_copy')


def frac(n, of):
    return dict(n=n, of=of)


def spread(values):
    if not values:
        return dict(n=0)
    q = statistics.quantiles(values, n=100, method='inclusive') if len(values) > 1 else [values[0]] * 99
    return dict(n=len(values), median=statistics.median(values), p5=q[4], p95=q[94])


def strict_trial(path):
    path = Path(path)
    trial, verdict, wire = (json.loads((path / name).read_text())
                            for name in ('trial.json', 'standards_verdict.json', 'relay_wire.json'))
    expected = verdict['expected']
    images = {('READ', c): v['image'] for c, v in expected['read_classes'].items()}
    images.update({(op, None): expected['lengths'][op][0] for op in ('SELECT', 'OPERATE')})
    exchanges = wire['exchanges']
    keys = [(e['operation'], e.get('workload')) for e in exchanges]
    order_ok = (len(keys) == expected['planned_exchanges'] and len(keys) % 4 == 0
                and keys == list(CYCLE) * (len(keys) // 4))
    sized = [e['response']['end_offset'] - e['response']['start_offset'] == images.get(k)
             for e, k in zip(exchanges, keys)]
    sbo = [e for e, k in zip(exchanges, keys) if k[0] != 'READ']
    crob = [e['application']['ok'] and sorted(map(tuple, e['application']['points'])) == [(1, 'SUCCESS'),
                                                                                           (3, 'SUCCESS')]
            for e in sbo]
    clrt = {}
    for e, k in zip(exchanges, keys):
        if not e['piggyback'] and e.get('complete_clrt_us') is not None:
            clrt.setdefault(CLASS.get(k, str(k)), []).append(e['complete_clrt_us'])
    return dict(trial=path.name, ok=bool(trial['ok'] and verdict['ok'] and wire['ok']), order_ok=order_ok,
                exchanges=len(exchanges), sizes_equal_image=frac(sum(sized), len(sized)),
                crob_success=frac(sum(crob), len(crob)), retransmissions=wire['retransmissions'], clrt_us=clrt)


def strict(paths):
    rows = [strict_trial(p) for p in paths]
    clrt = {}
    for row in rows:
        for cls, values in row['clrt_us'].items():
            clrt.setdefault(cls, []).extend(values)
    return dict(trials=frac(sum(r['ok'] for r in rows), len(rows)),
                order_ok=frac(sum(r['order_ok'] for r in rows), len(rows)),
                sizes_equal_image=frac(*(sum(r['sizes_equal_image'][k] for r in rows) for k in ('n', 'of'))),
                crob_success=frac(*(sum(r['crob_success'][k] for r in rows) for k in ('n', 'of'))),
                retransmissions={d: sum(r['retransmissions'][d] for r in rows) for d in ('out', 'in')},
                clrt_us={cls: spread(v) for cls, v in clrt.items()},
                per_trial=[{k: v for k, v in r.items() if k != 'clrt_us'} for r in rows])


def at_or_after(a, b):
    """b is at or after a in 32-bit TCP sequence space."""
    return (b - a) % (1 << 32) < (1 << 31)


def obsolete(ack, later):
    """Pure. A pure ACK is obsolete when a later forwarded master segment carries everything it carries: a sequence and
    an acknowledgment at or beyond its own, the same window, and no older timestamp."""
    if later is None:
        return False
    newer_ts = ack.get('tsval') is not None and (later.get('tsval') is None or not at_or_after(ack['tsval'], later['tsval']))
    return (at_or_after(ack['seq'], later['seq']) and at_or_after(ack['ack'], later['ack'])
            and later['window'] == ack['window'] and not newer_ts)


def fields(seg):
    return dict(seg, **recovery_compare.tcp_fields(seg['frame']))


def start_row(trial):
    """The frame not forwarded at connection start, from the master's first three frames to the relay."""
    copies = {(s['seq'], s['ack'], s['flags'], s['frame'][18:20]) for s in trial['mirror']['to_relay']}
    missing = [s for s in trial['master']['to_relay'][:3]
               if (s['seq'], s['ack'], s['flags'], s['frame'][18:20]) not in copies]
    cnt, error = d3.counters(trial)
    not_forwarded = cnt['dev9']['rx'] - cnt['dev64']['tx'] if cnt else None
    if not missing:
        frame = 'none'
    elif cnt and not_forwarded >= len(missing):
        frame = 'first_request' if missing[0]['len'] else 'syn' if missing[0]['flags'] & SYN else None
        if frame is None:
            sent = trial['master']['to_relay']
            later = next((s for s in sent[sent.index(missing[0]) + 1:]
                          if (s['seq'], s['ack'], s['flags'], s['frame'][18:20]) in copies), None)
            frame = ('suppressed_obsolete_ack' if obsolete(fields(missing[0]), later and fields(later))
                     else 'lost_valid_ack')
    else:
        frame = 'unexplained_missing_copy'
    first = cap.first_request(trial)
    return dict(trial=trial['name'], frame=frame, missing_copies=len(missing), dev9_rx_minus_dev64_tx=not_forwarded,
                counter_error=error, first_request_retransmitted=first.get('retransmitted'),
                retransmission_delay_ms=first.get('retransmission_delay_ms'),
                capture_complete=d3.completeness(trial)['ok'], **reply_observable(trial))


def reply_observable(trial):
    """Late handshake-ACK forward and the pure ACKs that precede the first response (c72: one per side)."""
    sent = trial['master']['to_relay']
    isn = next(s['seq'] for s in sent if s['flags'] & SYN)
    first = next(s for s in sent if s['len'])
    end = rc.stream_offset(first['seq'], isn) + first['len']
    handshake = next((s for s in sent if not s['len'] and not s['flags'] & SYN), None)

    def egress_ns(seg):
        return min((c['timestamp_ns'] for c in trial['mirror']['to_relay'] if seg and c['seq'] == seg['seq']
                    and c['len'] == seg['len'] and c['flags'] == seg['flags']), default=None)

    def acks_before_response(segments):
        acked = [s for s in segments if rc.stream_offset(s['ack'], isn) >= end and not s['flags'] & SYN]
        response = min((s['timestamp_ns'] for s in acked if s['len']), default=None)
        return sum(1 for s in acked if not s['len'] and (response is None or s['timestamp_ns'] < response))
    ack_ns, request_ns = egress_ns(handshake), egress_ns(first)
    wire = cap.read_json(trial['dir'] / 'relay_wire.json') or {}
    return dict(late_handshake_ack_forwarded=bool(ack_ns and request_ns and ack_ns > request_ns),
                relay_pure_acks_before_first_response=acks_before_response(trial['mirror']['from_relay']),
                master_pure_acks_before_first_response=acks_before_response(trial['master']['from_relay']),
                first_clrt_us=(wire.get('exchanges') or [{}])[0].get('complete_clrt_us'))


def starts(paths, label, sha):
    rows = [start_row(cap.load(p)) for p in paths]
    return dict(build=dict(label=label, source_sha256=sha),
                evidence_label='diagnostic-build evidence (%s); mirror used for packet presence only' % label,
                connections=len(rows), not_forwarded={f: sum(r['frame'] == f for r in rows) for f in FRAMES},
                first_request_retransmitted=frac(sum(bool(r['first_request_retransmitted']) for r in rows),
                                                 len(rows)),
                capture_complete=frac(sum(r['capture_complete'] for r in rows), len(rows)),
                late_handshake_ack_forwarded=frac(sum(r['late_handshake_ack_forwarded'] for r in rows), len(rows)),
                pure_acks_before_first_response={
                    side: {str(k): v for k, v in sorted(Counter(r['%s_pure_acks_before_first_response' % side]
                                                                for r in rows).items())}
                    for side in ('relay', 'master')},
                per_trial=rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('kind', choices=('strict', 'starts'))
    parser.add_argument('trials', nargs='+', type=Path)
    parser.add_argument('--build-label')
    parser.add_argument('--source-sha256')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.kind == 'starts':
        _, reason = pc.load(SimpleNamespace(build_label=args.build_label, source_sha256=args.source_sha256,
                                            build_inputs=None))
        if reason:
            parser.error(reason)
        result = starts(args.trials, args.build_label, args.source_sha256)
    else:
        result = strict(args.trials)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'per_trial'}, indent=1, default=str))
    return 0


if __name__ == '__main__':
    sys.exit(main())
