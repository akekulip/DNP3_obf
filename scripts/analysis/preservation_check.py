#!/usr/bin/env python3
"""E1 same-transaction preservation: the relay-leg mirror against the master NIC, per connection.

Each TCP direction on each side is reassembled by byte offset with the relay_check v3 functions (one SYN per stream;
retransmissions counted by byte overlap and reported apart from differences), split into DNP3 link frames, transport
segments and application fragments (preservation_dnp3), and matched by order and wrapped application sequence. The
response sequence translation is derived from the data and checked against the declared growth of the earlier
responses; request ACKs are checked against that translation. Only the declared padding is removed before the
complete original application content and order are compared; every other change is a difference.

The output is labelled with the build identity given on the command line (--build-label, --source-sha256); the tool
refuses to run without it, or when it disagrees with the build inputs that declare the padding.
"""
import argparse
import bisect
from collections import Counter
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'scripts/checks')]
import preservation_dnp3 as pd  # noqa: E402
import relay_check as rc  # noqa: E402
from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT  # noqa: E402

SCHEMA = 'c72-preservation-e1-v1'
MASK = 0xffffffff
# Header fields the build declares it changes (p4/response_only.p4). Responses: seq 1138 finish_forward_sequence,
# IP length 2199/2210 (READ) and 1150 (control), IP checksum 2228/1296, TCP checksum 2233-2247/1298-1330.
# Requests: ack 1175-1177 rev_translate/rev_withhold_*, window 1176-1177 and 1212-1216 window_t, TCP checksum.
DECLARED_HEADER = {'from_relay': {'ip.len', 'ip.checksum', 'tcp.seq', 'tcp.checksum'},
                   'to_relay': {'tcp.ack', 'tcp.window', 'tcp.checksum'}}
IP_FIELDS = (('eth', 0, 14), ('ip.version_ihl', 14, 15), ('ip.tos', 15, 16), ('ip.len', 16, 18), ('ip.id', 18, 20),
             ('ip.flags_frag', 20, 22), ('ip.ttl', 22, 23), ('ip.proto', 23, 24), ('ip.checksum', 24, 26),
             ('ip.addresses', 26, 34))
TCP_FIELDS = (('tcp.ports', 0, 4), ('tcp.seq', 4, 8), ('tcp.ack', 8, 12), ('tcp.offset_flags', 12, 14),
              ('tcp.window', 14, 16), ('tcp.checksum', 16, 18), ('tcp.urgent', 18, 20))
ASSUMPTIONS = [
    'relay-side responses are the complete frames received on dev64 before any transformation (ingress mirror)',
    'relay-side requests are the frames as emitted on dev64, ACK already translated (egress mirror)',
    'the mirror neither truncates, coalesces nor duplicates frames; a lost copy shows as a gap or unmatched item',
    'both mirror directions share the master-side 4-tuple; the relay-to-master SYN-ACK sequence is not translated',
]


def frac(n, of):
    return dict(n=n, of=of)


def header_fields(frame):
    t = 14 + (frame[14] & 15) * 4
    fields = {name: frame[a:b].hex() for name, a, b in IP_FIELDS}
    fields['ip.options'] = frame[34:t].hex()
    fields.update((name, frame[t + a:t + b].hex()) for name, a, b in TCP_FIELDS)
    fields['tcp.options'] = frame[t + 20:t + (frame[t + 12] >> 4) * 4].hex()
    return fields


def header_changes(relay, master, direction):
    """Ethernet/IPv4/TCP header fields that differ beyond the build's declared changes."""
    a, b = header_fields(relay['frame']), header_fields(master['frame'])
    return [dict(field='header ' + k, relay=a[k], master=b[k]) for k in a
            if a[k] != b[k] and k not in DECLARED_HEADER[direction]]


def directions(to_pcap, from_pcap, master, relay):
    out = {}
    for name, path, key in (('to_relay', to_pcap, master + relay), ('from_relay', from_pcap, relay + master)):
        segments, _ = rc.wc.parse(path)
        out[name] = [s for s in segments if (s['src'], s['sport'], s['dst'], s['dport']) == key]
    return out


def side(segments):
    """One TCP direction: the single-incarnation stream, its DNP3 fragments, gaps and byte accounting."""
    report = dict(segments=len(segments), payload_segments=sum(1 for s in segments if s['len']),
                  incarnations=len({s['seq'] for s in segments if s['flags'] & rc.wc.SYN}))
    stream = rc.tcp_stream(segments)
    if stream is None:
        return report, None, []
    frames, errors, gaps, cursor = [], [], [], 1
    for start, data in stream['runs']:
        if start != cursor:
            gaps.append([cursor, start])
        found, bad = pd.link_frames(bytes(data), start)
        frames, errors, cursor = frames + found, errors + bad, start + len(data)
    frags, bad = pd.fragments(frames)
    contributed = Counter()
    for a, b, _, seg in stream['pieces']:
        contributed[seg['index']] += b - a
    retransmitted = [dict(pcap_index=seg['index'], offset=a, length=b - a, timestamp_ns=seg['timestamp_ns'])
                     for a, b, seg in stream['copies'] if contributed[seg['index']] < b - a]
    report.update(rc.byte_counts(segments), retransmitted=retransmitted[:50], gaps=gaps, frames=len(frames),
                  conflicting_offsets=sorted(stream['conflicts'])[:50], framing_errors=errors + bad,
                  fragments=len(frags))
    return report, stream, frags


def seq_of(fragment):
    return fragment['app'][0] & 15 if fragment['app'] else -1


def brief(fragment):
    app = fragment['app']
    return dict(app_seq=seq_of(fragment), function=app[1] if len(app) > 1 else None, offset=fragment['start'],
                length=len(fragment['wire']))


def match(relay, master):
    """Pairs by order and wrapped 4-bit application sequence; anything else is unmatched on its side."""
    pairs, lone_r, lone_m, i, j = [], [], [], 0, 0
    while i < len(relay) and j < len(master):
        d = (seq_of(master[j]) - seq_of(relay[i])) & 15
        if d == 0:
            pairs.append((relay[i], master[j]))
            i, j = i + 1, j + 1
        elif d < 8:
            lone_r, i = lone_r + [relay[i]], i + 1
        else:
            lone_m, j = lone_m + [master[j]], j + 1
    return pairs, lone_r + relay[i:], lone_m + master[j:]


def segment_at(stream, offset):
    """The first-arriving segment that carried the byte at this stream offset."""
    return stream['pieces'][bisect.bisect_right(stream['starts'], offset) - 1][3]


def compare_responses(pairs, declared, relay_stream, master_stream):
    rows = []
    for k, (r, m) in enumerate(pairs):
        form, expected, growth = pd.classify(r, m, declared)
        diffs = []
        wire = pd.byte_diff(expected, m['wire'])
        if wire:
            diffs.append(dict(field='wire_vs_declared_image', **wire))
        diffs += [dict(field='link_crc', side=name, offsets=[x['offset'] for x in f['frames'] if not x['crc_ok']])
                  for name, f in (('relay', r), ('master', m)) if not f['crc_ok']]
        native, prefix = pd.strip(m['app'], form, declared)
        if prefix is not None and prefix != declared['shapes'][form[5:]]['prefix']:
            diffs.append(dict(field='padding_prefix', **pd.byte_diff(declared['shapes'][form[5:]]['prefix'], prefix)))
        diffs += pd.compare_application(r['app'], native)
        diffs += header_changes(segment_at(relay_stream, r['start']), segment_at(master_stream, m['start']),
                                'from_relay')
        rows.append(dict(index=k, app_seq=seq_of(r), function=brief(r)['function'], form=form, growth=growth,
                         relay_offset=r['start'], master_offset=m['start'], relay_len=len(r['wire']),
                         master_len=len(m['wire']), identical=not diffs, differences=diffs))
    return rows


def compare_requests(pairs):
    rows = []
    for k, (r, m) in enumerate(pairs):
        diffs = []
        wire = pd.byte_diff(r['wire'], m['wire'])
        if wire:
            diffs.append(dict(field='wire', **wire))
        if r['start'] != m['start']:
            diffs.append(dict(field='tcp_offset', relay=r['start'], master=m['start']))
        diffs += pd.compare_application(r['app'], m['app'], request=True)
        rows.append(dict(index=k, app_seq=seq_of(r), function=brief(r)['function'], relay_offset=r['start'],
                         master_offset=m['start'], length=len(r['wire']), identical=not diffs, differences=diffs))
    return rows


def translation(pairs, rows, lone_r, lone_m, r0, m0):
    """Observed sequence translation (master minus relay) per matched response against the cumulative declared
    growth of the earlier responses; undetermined (declared None) once an unmatched response precedes it."""
    table, cumulative = [dict(at='syn', relay_seq=r0, master_seq=m0, observed=rc.stream_offset(m0, r0), declared=0)], 0
    for (r, m), row in zip(pairs, rows):
        known = not any(f['start'] < r['start'] for f in lone_r) and not any(f['start'] < m['start'] for f in lone_m)
        rs, ms = (r0 + r['start']) & MASK, (m0 + m['start']) & MASK
        table.append(dict(response=row['index'], app_seq=row['app_seq'], form=row['form'], relay_seq=rs, master_seq=ms,
                          observed=rc.stream_offset(ms, rs), declared=cumulative if known else None))
        cumulative += row['growth']
    for entry in table:
        entry['consistent'] = None if entry['declared'] is None else entry['observed'] == entry['declared']
    return table


def ack_translator(pairs, lone_r, lone_m, r0, m0):
    """Master ACK of the response stream -> the relay ACK the observed translation implies (None: undetermined,
    i.e. inside a delivered image or at/after an unmatched response)."""
    def translate(ack):
        o = rc.stream_offset(ack, m0)
        before = [(r, m) for r, m in pairs if m['end'] <= o]
        pos = o - (before[-1][1]['end'] - before[-1][0]['end']) if before else o
        if (any(m['start'] < o < m['end'] for _, m in pairs) or any(f['start'] < o for f in lone_m)
                or any(f['start'] <= pos for f in lone_r)):
            return None
        return (r0 + pos) & MASK
    return translate


def request_segments(relay_segs, master_segs, rq0, mq0, translate):
    """Each request segment leaving toward the relay against the master's copies of the same bytes: ACK translated
    as the response translation implies, no other undeclared header change, request sequence untranslated."""
    copies = {}
    for s in master_segs:
        if s['len']:
            copies.setdefault((rc.stream_offset(s['seq'], mq0), s['payload']), []).append(s)
    checked = consistent = undetermined = 0
    mismatches, headers = [], []
    for s in (s for s in relay_segs if s['len']):
        checked += 1
        offset = rc.stream_offset(s['seq'], rq0)
        found = copies.get((offset, s['payload']), [])
        expected = [translate(c['ack']) for c in found]
        if found:
            # the master transmission this copy is: same translated ACK, then the same IPv4 ID (the switch does not
            # rewrite it), so a first transmission the switch dropped is not compared with the retransmission
            same_ack = [c for c, e in zip(found, expected) if e == s['ack']] or found
            twin = next((c for c in same_ack if c['frame'][18:20] == s['frame'][18:20]), same_ack[0])
            headers += [dict(d, pcap_index=s['index'], offset=offset) for d in header_changes(s, twin, 'to_relay')]
        if s['ack'] in expected:
            consistent += 1
        elif found and None in expected:
            undetermined += 1
        else:
            mismatches.append(dict(pcap_index=s['index'], offset=offset, relay_ack=s['ack'], expected=expected,
                                   master_acks=[c['ack'] for c in found], reason='ACK differs from the translated '
                                   'master ACK' if found else 'no master copy of these request bytes'))
    return dict(checked=checked, ack_consistent=frac(consistent, checked), ack_undetermined=frac(undetermined, checked),
                mismatches=mismatches, header_differences=headers, syn_offset=rc.stream_offset(mq0, rq0))


def block(rows, lone_r, lone_m, n_relay, n_master):
    same = sum(row['identical'] for row in rows)
    return dict(compared=len(rows), identical=frac(same, len(rows)), different=frac(len(rows) - same, len(rows)),
                unmatched=dict(relay_side=frac(len(lone_r), n_relay), master_side=frac(len(lone_m), n_master)),
                unmatched_items=dict(relay_side=[brief(f) for f in lone_r], master_side=[brief(f) for f in lone_m]),
                transactions=[{k: v for k, v in row.items() if k != 'differences'} for row in rows],
                differences=[row for row in rows if not row['identical']])


def trial_metadata(trial, port, requests, responses):
    """master.json records (claims, not authority) against the master-side fragments; relay_wire.json summary."""
    out = {}
    if (trial / 'master.json').is_file():
        records = [r for r in json.loads((trial / 'master.json').read_text()).get('records') or []
                   if (r.get('local_address') or [None, None])[1] == port]
        bad = [k for k, r in enumerate(records) if k >= min(len(requests), len(responses)) or
               r.get('request_wire_hex') != requests[k]['wire'].hex() or
               r.get('response_wire_hex') != responses[k]['wire'].hex()]
        out['master_json'] = dict(records=len(records), agreeing=frac(len(records) - len(bad), len(records)),
                                  disagreeing_records=bad[:50])
    if (trial / 'relay_wire.json').is_file():
        wire = json.loads((trial / 'relay_wire.json').read_text())
        out['relay_wire_json'] = dict(schema=wire.get('schema'), ok=wire.get('ok'),
                                      exchanges=len(wire.get('exchanges') or []))
    return out


def connection(args, declared, port):
    master, relay = (args.master_ip, port), (args.relay_ip, args.relay_port)
    sides = dict(relay_side=directions(args.relay_pcap, args.relay_pcap, master, relay),
                 master_side=directions(args.trial_dir / 'out.pcap', args.trial_dir / 'in.pcap', master, relay))
    tcp, streams, frags = {}, {}, {}
    for name, dirs in sides.items():
        tcp[name] = {}
        for d, segments in dirs.items():
            tcp[name][d], streams[name, d], frags[name, d] = side(segments)
    report = dict(connection=dict(master=list(master), relay=list(relay)), tcp=tcp)
    if any(s is None for s in streams.values()):
        return dict(report, ok=False, counts=dict(connections_ok=frac(0, 1)),
                    failures=['every direction on both sides needs exactly one connection incarnation (one SYN)'])
    o = {key: s['origin'] for key, s in streams.items()}
    rr, rm = frags['relay_side', 'from_relay'], frags['master_side', 'from_relay']
    qr, qm = frags['relay_side', 'to_relay'], frags['master_side', 'to_relay']
    pairs, lone_r, lone_m = match(rr, rm)
    qpairs, qlone_r, qlone_m = match(qr, qm)
    rows = compare_responses(pairs, declared, streams['relay_side', 'from_relay'], streams['master_side', 'from_relay'])
    table = translation(pairs, rows, lone_r, lone_m, o['relay_side', 'from_relay'], o['master_side', 'from_relay'])
    translate = ack_translator(pairs, lone_r, lone_m, o['relay_side', 'from_relay'], o['master_side', 'from_relay'])
    segs = request_segments(sides['relay_side']['to_relay'], sides['master_side']['to_relay'],
                            o['relay_side', 'to_relay'], o['master_side', 'to_relay'], translate)
    responses = dict(block(rows, lone_r, lone_m, len(rr), len(rm)), forms=dict(Counter(r['form'] for r in rows)))
    requests = block(compare_requests(qpairs), qlone_r, qlone_m, len(qr), len(qm))
    verified = [t for t in table if t['declared'] is not None]
    streams_all = [(name, d, tcp[name][d]) for name in tcp for d in tcp[name]]
    failures = ['%s %s: %d/%d' % (kind, what, b[what]['n'], b[what]['of']) for kind, b in
                (('responses', responses), ('requests', requests)) for what in ('different',) if b[what]['n']]
    failures += ['%s unmatched on the %s: %d/%d' % (kind, s, v['n'], v['of']) for kind, b in
                 (('responses', responses), ('requests', requests)) for s, v in b['unmatched'].items() if v['n']]
    failures += ['translation inconsistent at response %s' % t.get('response', 'syn') for t in table
                 if t['consistent'] is False]
    failures += ['request %s: %d' % (key, len(segs[key])) for key in ('mismatches', 'header_differences') if segs[key]]
    failures += ['request sequence translated by %d' % segs['syn_offset']] if segs['syn_offset'] else []
    failures += ['%s %s: %s' % (name, d, key) for name, d, s in streams_all
                 for key in ('gaps', 'conflicting_offsets', 'framing_errors') if s[key]]
    counts = dict(responses_identical=responses['identical'], requests_identical=requests['identical'],
                  translation_verified=frac(len(verified), len(table)),
                  translation_consistent=frac(sum(t['consistent'] for t in verified), len(verified)),
                  request_ack_consistent=segs['ack_consistent'], connections_ok=frac(int(not failures), 1))
    for kind, b in (('responses', responses), ('requests', requests)):
        counts.update(('%s_unmatched_%s' % (kind, s), v) for s, v in b['unmatched'].items())
    for name in tcp:
        counts['retransmitted_segments_' + name] = frac(sum(s['retransmitted_segments'] for s in tcp[name].values()),
                                                        sum(s['payload_segments'] for s in tcp[name].values()))
        counts['retransmitted_bytes_' + name] = frac(sum(s['retransmitted_bytes'] for s in tcp[name].values()),
                                                     sum(s['packet_bytes'] for s in tcp[name].values()))
    return dict(report, ok=not failures, failures=failures, responses=responses, requests=requests, translation=table,
                request_segments=segs, trial=trial_metadata(args.trial_dir, port, qm, rm), counts=counts)


def load(args):
    """(declared padding, None) or (None, refusal reason): the evidence must carry an identity the build confirms."""
    if not args.build_label or not args.source_sha256:
        return None, 'evidence must carry the build identity: give --build-label and --source-sha256'
    if not re.fullmatch('[0-9a-f]{64}', args.source_sha256):
        return None, '--source-sha256 is not a lowercase SHA-256 hex digest'
    args.build_inputs = args.build_inputs or ROOT / 'results/builds' / args.build_label / 'response_only.inputs.json'
    try:
        declared = pd.load_declared(args.build_inputs)
    except (OSError, KeyError, TypeError, ValueError) as error:
        return None, 'declared padding cannot be loaded from %s: %s' % (args.build_inputs, error)
    if declared['source_sha256'] != args.source_sha256 or declared['build'] != args.build_label:
        return None, 'build label/source SHA-256 disagree with %s' % args.build_inputs
    return declared, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--relay-pcap', type=Path, required=True, help='relay-leg mirror capture (both directions)')
    parser.add_argument('--trial-dir', type=Path, required=True,
                        help='out.pcap and in.pcap from the master NIC; master.json, relay_wire.json when present')
    parser.add_argument('--master-port', type=int, action='append', help='repeat per connection (default: master.json)')
    parser.add_argument('--master-ip', default=MASTER_IP)
    parser.add_argument('--relay-ip', default=RELAY_IP)
    parser.add_argument('--relay-port', type=int, default=RELAY_PORT)
    parser.add_argument('--build-label')
    parser.add_argument('--source-sha256')
    parser.add_argument('--build-inputs', type=Path, help='default results/builds/<label>/response_only.inputs.json')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    declared, reason = load(args)
    master_json = args.trial_dir / 'master.json'
    ports = args.master_port or sorted({r['local_address'][1] for r in (json.loads(master_json.read_text()).get(
        'records') or [] if master_json.is_file() else []) if r.get('local_address')})
    if not reason and not ports:
        reason = 'no --master-port given and no master.json local address to take it from'
    if reason:
        print('REFUSED: ' + reason, file=sys.stderr)
        return 2
    connections = [connection(args, declared, port) for port in ports]
    totals = {}
    for c in connections:
        for key, value in c['counts'].items():
            totals.setdefault(key, frac(0, 0))
            totals[key] = frac(totals[key]['n'] + value['n'], totals[key]['of'] + value['of'])
    files = [args.relay_pcap] + [args.trial_dir / n for n in ('out.pcap', 'in.pcap', 'master.json', 'relay_wire.json')]
    result = dict(schema=SCHEMA, ok=all(c['ok'] for c in connections),
                  build=dict(label=args.build_label, source_sha256=args.source_sha256, inputs=str(args.build_inputs),
                             inputs_sha256=pd.sha256(args.build_inputs)),
                  inputs={str(p): pd.sha256(p) for p in files if p.is_file()}, declared_padding=pd.summary(declared),
                  mirror_assumptions=ASSUMPTIONS, totals=totals, connections=connections)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(ok=result['ok'], build=result['build']['label'], totals=totals), indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
