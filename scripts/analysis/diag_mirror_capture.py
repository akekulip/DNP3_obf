"""Per-trial capture layer of the diagnostic-mirror analysis (diag_mirror_d3.py).

One trial directory is one fresh connection: the master NIC captures (out.pcap toward the relay, in.pcap from it) and
the copies the switch sent to the capture interface (mirror.pcap: egress copies of frames leaving on dev64 toward the
relay, ingress copies of frames arriving on dev64 from it). This module loads them, pairs each master NIC frame with
its copy and compares complete frames (D3b), and locates the first request of the connection (E2).

TCP parsing, stream offsets and checksums are the wire_check / relay_check v3 functions; header field names are
preservation_check's.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / 'scripts/checks')]
import preservation_check as pc  # noqa: E402
import relay_check as rc  # noqa: E402
from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT  # noqa: E402

wc = rc.wc
DIRS = ('to_relay', 'from_relay')
INPUTS = ('trial.json', 'out.pcap', 'in.pcap', 'mirror.pcap')
# results/analysis/diag_mirror_d3/DESIGN.json experiments.E2_first_request.classification, verbatim, by short key.
E2_CLASSES = {
    'lost_before_or_inside_switch': 'no egress copy of the first request: lost before or inside the switch',
    'lost_after_switch_egress': 'egress copy present, no relay ACK or response in the ingress copies before the '
                                'retransmission: lost after switch egress (cable, relay NIC or relay), the narrowest '
                                'supported location; an egress copy does not prove the relay received it',
    'lost_between_switch_ingress_and_master': 'relay response in the ingress copies, not at the master NIC: lost '
                                              'between switch ingress and the master',
}
NO_RETRANSMISSION, UNCLASSIFIED = 'no_retransmission', 'unclassified'
OTHER_CLASSES = {NO_RETRANSMISSION: 'the first request was not retransmitted at the master NIC',
                 UNCLASSIFIED: 'retransmitted, but the evidence contradicts every registered class: no egress copy of '
                               'the first request although a relay reply acknowledging it is in the ingress copies '
                               '(the capture missed a copy), or a relay reply reached the master NIC before the '
                               'retransmission'}


def frac(n, of):
    return dict(n=n, of=of)


def read_json(path):
    path = Path(path)
    return json.loads(path.read_text()) if path.is_file() else None


def brief(seg):
    return dict(pcap_index=seg['index'], timestamp_ns=seg['timestamp_ns'], seq=seg['seq'], ack=seg['ack'],
                flags=seg['flags'], payload_len=seg['len'], caplen=seg['captured_len'], wirelen=seg['original_len'])


def load(path):
    """One trial directory: identity (arm = parent directory name, as eval_rows), the master NIC segments and the
    mirror copies of the trial's connection by direction, in capture order, and every mirror.pcap record.
    Missing inputs are listed in 'missing'; nothing is substituted for them."""
    path = Path(path)
    meta = read_json(path / 'trial.json') or {}
    port = meta.get('master_port')
    trial = dict(dir=path, name=path.name, arm=path.parent.name, label=meta.get('label') or path.name, port=port,
                 missing=[name for name in INPUTS if not (path / name).is_file()],
                 master={d: [] for d in DIRS}, mirror={d: [] for d in DIRS}, records=[])
    if port is None and 'trial.json' not in trial['missing']:
        trial['missing'].append('trial.json master_port')
    keys = dict(to_relay=(MASTER_IP, port, RELAY_IP, RELAY_PORT), from_relay=(RELAY_IP, RELAY_PORT, MASTER_IP, port))

    def pick(segments, d):
        return sorted((s for s in segments if (s['src'], s['sport'], s['dst'], s['dport']) == keys[d]),
                      key=lambda s: (s['timestamp_ns'], s['index']))
    for d, name in (('to_relay', 'out.pcap'), ('from_relay', 'in.pcap')):
        if (path / name).is_file():
            trial['master'][d] = pick(wc.parse(path / name)[0], d)
    if (path / 'mirror.pcap').is_file():
        segments = wc.parse(path / 'mirror.pcap')[0]
        trial['mirror'] = {d: pick(segments, d) for d in DIRS}
        trial['records'] = wc.read_pcap_records(path / 'mirror.pcap')[0]
    return trial


def record_direction(frame, relay_macs):
    """A copy is an ingress copy when its Ethernet source is the relay (MAC learned from the relay's TCP copies)."""
    if not relay_macs:
        return 'unattributed'
    return 'from_relay' if frame[6:12] in relay_macs else 'to_relay'


def field_at(frame, offset):
    """The Ethernet/IPv4/TCP field (preservation_check names), the TCP payload or the Ethernet trailer at an offset."""
    if offset < 14:
        return 'eth.dst' if offset < 6 else 'eth.src' if offset < 12 else 'eth.type'
    if frame[12:14] != b'\x08\x00' or len(frame) < 34:
        return 'frame'
    tcp, end = 14 + (frame[14] & 15) * 4, 14 + int.from_bytes(frame[16:18], 'big')
    if offset >= end:
        return 'eth.trailer'
    if offset < tcp:
        return next((name for name, a, b in pc.IP_FIELDS if a <= offset < b), 'ip.options')
    if frame[23] != 6 or len(frame) < tcp + 13:
        return 'ip.payload'
    if offset >= tcp + (frame[tcp + 12] >> 4) * 4:
        return 'tcp.payload'
    return next((name for name, a, b in pc.TCP_FIELDS if tcp + a <= offset < tcp + b), 'tcp.options')


def frame_diff(reference, copy):
    """None when byte-identical; else the differing offsets (first 32), their fields and both lengths."""
    offsets = [i for i in range(max(len(reference), len(copy)))
               if i >= len(reference) or i >= len(copy) or reference[i] != copy[i]]
    if not offsets:
        return None
    fields = sorted({field_at(reference if i < len(reference) else copy, i) for i in offsets})
    return dict(offsets=offsets[:32], differing=len(offsets), fields=fields, reference_len=len(reference),
                copy_len=len(copy))


def wire_reference(seg, direction):
    """(frame as it crossed the master NIC, placeholder replaced). tcpdump -Q out captures a master frame before the
    NIC fills in the TCP checksum; such a frame carries the TX-offload placeholder (wire_check.ip_tcp_checksum, which
    relay_check accepts for out.pcap). It is replaced by the checksum the NIC computes; every other byte is kept."""
    frame = seg['frame']
    if direction != 'to_relay' or wc.ip_tcp_checksum(seg)[1:] != (False, True):
        return frame, False
    tcp = 14 + (frame[14] & 15) * 4
    segment = bytearray(frame[tcp:14 + int.from_bytes(frame[16:18], 'big')])
    segment[16:18] = b'\0\0'
    pseudo = frame[26:34] + struct.pack('!BBH', 0, 6, len(segment))
    fixed = bytearray(frame)
    fixed[tcp + 16:tcp + 18] = wc._sum16(pseudo + bytes(segment)).to_bytes(2, 'big')
    return bytes(fixed), True


def pair(references, copies, direction):
    """Each reference with an unused copy of the same seq and flags: a byte-identical one first, then one with the
    same ack, then the first in capture order. Returns (pairs, references without a copy, copies without a reference).
    """
    used, pairs, missing = set(), [], []
    for ref in references:
        want = wire_reference(ref, direction)[0]
        pool = [c for c in copies if c['index'] not in used and (c['seq'], c['flags']) == (ref['seq'], ref['flags'])]
        pick = (next((c for c in pool if c['frame'] == want), None) or
                next((c for c in pool if c['ack'] == ref['ack']), None) or (pool[0] if pool else None))
        if pick is None:
            missing.append(ref)
            continue
        used.add(pick['index'])
        pairs.append((ref, pick))
    return pairs, missing, [c for c in copies if c['index'] not in used]


def direction_fidelity(trial, d):
    refs, copies = trial['master'][d], trial['mirror'][d]
    pairs, missing, extra = pair(refs, copies, d)
    rows, same, offloaded = [], [], 0
    for ref, copy in pairs:
        want, replaced = wire_reference(ref, d)
        offloaded += replaced
        diff = frame_diff(want, copy['frame'])
        short = copy['captured_len'] < ref['captured_len'] or copy['original_len'] < ref['original_len']
        same.append(not diff and not short)
        if diff or short:
            rows.append(dict(reference=brief(ref), copy=brief(copy), shorter=short, **(diff or dict(fields=[]))))
    data = [ok for (ref, _), ok in zip(pairs, same) if ref['len']]
    return dict(references=len(refs), copies=len(copies), paired=frac(len(pairs), len(refs)),
                identical=frac(sum(same), len(pairs)), data_frames_identical=frac(sum(data), len(data)),
                shorter=frac(sum(r['shorter'] for r in rows), len(pairs)),
                reference_checksum_offloaded=frac(offloaded, len(pairs)), missing=frac(len(missing), len(refs)),
                extra=frac(len(extra), len(copies)), differences=rows[:50],
                missing_items=[brief(s) for s in missing[:50]], extra_items=[brief(s) for s in extra[:50]])


def fidelity(trial, uncaptured):
    """D3b for one off-arm trial (T and padding off, so no field is declared changed): every master NIC frame of the
    connection against its copy, complete frames byte for byte; a copy shorter than its reference (caplen or wire
    length) fails. uncaptured = switch dev10 TX minus copies captured (D3c): the copies the counters show were sent
    but not captured. A missing copy beyond that number is not accounted for by the counters and fails."""
    report, failures = dict(trial=trial['name'], arm=trial['arm']), []
    if trial['missing']:
        failures.append('inputs missing: ' + ', '.join(trial['missing']))
    for d in DIRS:
        report[d] = row = direction_fidelity(trial, d)
        bad = row['paired']['n'] - row['identical']['n']
        if bad:
            failures.append('%s: %d of %d paired copies differ from the reference or are shorter'
                            % (d, bad, row['paired']['n']))
        if not row['references']:
            failures.append('%s: no frame of the connection at the master NIC' % d)
    missing = sum(report[d]['missing']['n'] for d in DIRS)
    accounted = min(missing, max(uncaptured or 0, 0))
    report.update(missing_accounted_by_counters=frac(accounted, missing),
                  missing_unaccounted=frac(missing - accounted, missing))
    if missing - accounted:
        failures.append('%d missing copies the switch counters do not account for' % (missing - accounted))
    return dict(report, ok=not failures, failures=failures)


def first_ns(segments):
    return segments[0]['timestamp_ns'] if segments else None


def first_request(trial, mirror=True):
    """E2 for one fresh connection: the first master request at the master NIC, its egress copy, relay ACKs/responses
    acknowledging it in the ingress copies and at the master NIC, and the master's retransmission (a later out.pcap
    segment overlapping its bytes). Copies and master NIC frames share the Vision clock. Mirror-off connections
    report the retransmission only; their location is not observable."""
    row = dict(trial=trial['name'], arm=trial['arm'], mirror=mirror)
    sent = trial['master']['to_relay']
    syns, data = {s['seq'] for s in sent if s['flags'] & wc.SYN}, [s for s in sent if s['len']]
    absent = [n for n in ('trial.json', 'out.pcap', 'in.pcap') + (('mirror.pcap',) if mirror else ())
              if n in trial['missing']]
    if absent or len(syns) != 1 or not data:
        reason = ('inputs missing: ' + ', '.join(absent) if absent else
                  'not exactly one master SYN' if len(syns) != 1 else 'no master request at the master NIC')
        return dict(row, evaluable=False, reason=reason, **{'class': None})
    isn, first = syns.pop(), data[0]
    start = rc.stream_offset(first['seq'], isn)
    end = start + first['len']

    def covers(s):
        offset = rc.stream_offset(s['seq'], isn)
        return bool(s['len']) and offset < end and offset + s['len'] > start

    def acknowledges(s):
        return bool(s['flags'] & wc.ACK) and rc.stream_offset(s['ack'], isn) >= end
    retx = [s for s in data[1:] if covers(s)]
    t_retx = retx[0]['timestamp_ns'] if retx else None

    def before(s):
        return t_retx is None or s['timestamp_ns'] < t_retx
    at_master = [s for s in trial['master']['from_relay'] if acknowledges(s)]
    row.update(evaluable=True, first_request_ns=first['timestamp_ns'], request_offset=start, request_len=first['len'],
               retransmitted=bool(retx), retransmissions=len(retx), retransmission_ns=t_retx,
               retransmission_delay_ms=(t_retx - first['timestamp_ns']) / 1e6 if retx else None,
               master_ack_ns=first_ns([s for s in at_master if not s['len']]),
               master_response_ns=first_ns([s for s in at_master if s['len']]))
    if not mirror:
        return dict(row, reason='mirror off: location not observable', **{'class': None})
    egress = [c for c in trial['mirror']['to_relay'] if covers(c)]
    ingress = [s for s in trial['mirror']['from_relay'] if acknowledges(s)]
    original = [c for c in egress if before(c)]
    replied, delivered = [s for s in ingress if before(s)], [s for s in at_master if before(s)]
    row.update(egress_copy_ns=first_ns(original), egress_copies=len(egress), second_egress_copy=len(egress) > 1,
               egress_copy_times_ns=[c['timestamp_ns'] for c in egress[:8]],
               ingress_ack_ns=first_ns([s for s in ingress if not s['len']]),
               ingress_response_ns=first_ns([s for s in ingress if s['len']]),
               ingress_replies_before_retransmission=len(replied) if retx else None,
               master_replies_before_retransmission=len(delivered) if retx else None)
    key = (NO_RETRANSMISSION if not retx else
           UNCLASSIFIED if not original and replied else          # the relay answered a copy the capture missed
           'lost_before_or_inside_switch' if not original else
           'lost_after_switch_egress' if not replied else
           'lost_between_switch_ingress_and_master' if not delivered else UNCLASSIFIED)
    return dict(row, class_text=E2_CLASSES.get(key) or OTHER_CLASSES[key], **{'class': key})
