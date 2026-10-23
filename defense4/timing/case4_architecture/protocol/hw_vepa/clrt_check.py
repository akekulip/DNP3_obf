#!/usr/bin/env python3
"""Per-exchange timing at the master's capture point, from a run's two captures.

  clrt_check.py OUT.pcap IN.pcap [--json FILE]

OUT = `tcpdump -Q out` on the parent NIC (frames as the master/outstation sent them); IN = `-Q in`
(frames as the switch returned them). Both carry the same parent-NIC clock, so every interval below is a
host-capture-point interval, not an isolated ASIC forwarding time, and timestamps are integer
microseconds at the capture resolution (not epoch floats, which could not justify sub-microsecond
precision).

A logical request is one application exchange: a DNP3-bearing master segment, keyed by (four-tuple,
connection incarnation, TCP sequence start, DNP3 function). A TCP retransmission resends the same bytes
at the same sequence, so it is retained as another ATTEMPT of the same logical request, never a new one.
Each logical request is associated with:

  t_ack   first returned frame whose ACK covers the end of the request (master sequence space)
  t_resp  first returned DNP3 response (same four-tuple and incarnation) whose application sequence
          echoes the request and whose ACK covers the request end -- the application-sequence match is
          what stops an unrelated covering response from being misattributed.

  clrt    = t_resp - t_ack    (the measured m_R - m_A of NOTATION_MAPPING.md; never D_R)
  rt      = t_resp - t_req    (complete request-to-response latency, from the first attempt)
  ack_lat = t_ack - t_req

`piggyback` marks an exchange whose covering ACK is the response segment itself; clrt is 0 by
construction there and carries no information. An exchange with no covering response is `incomplete`
(a failed exchange) and is reported in the completion counts, though latency statistics are taken only
from the declared eligible subset: complete, non-piggyback, single-attempt exchanges.

Standard deviation is reported under two explicit keys, `sd_population` (divide by n) and `sd_sample`
(divide by n-1); there is no bare `sd`. The convention is also written into every report as `sd_convention`.

DNP3 CRCs are verified on requests and responses. A checksum-offloaded master segment carries only a
TCP pseudo-header placeholder, which is not corruption and does not affect the DNP3 CRC; returned frames
are checksum-validated.

Additive schema ``vision-exchanges-v2``: every legacy exchange also has ``observation``
(packet references, integer timestamps, lengths and capture clock metadata) and ``publication``
(integer ns intervals, or null plus ``null_reasons``). All intervals use the Vision parent-NIC
capture clock. ``response_availability_ns`` is OUT response minus OUT request;
``request_delivery_ns`` is IN request minus OUT request; ``operate_hold_ns`` is that
request delivery interval for OPERATE. No endpoint steady_clock value enters these fields.
Paired-capture metrics require unique preserved transport/content correspondence: M->O
sequence/payload or O->M ACK plus application identity. Capture order is never proof of
identity. Responses additionally require complete captured TCP payloads and exact content
or the CRC-validated bounded native49/37-to-61 encoding described below. Ambiguous/lost/retransmitted groups remain null. Shared legacy response refs
or a response ACK not exactly matching the request end cannot establish publication
completion; ``publication_complete`` is independent of legacy ``complete``. DNP3 identity and
checksums are audit data. Publication CLRT is null for a piggyback/missing ACK, while
legacy clrt_us retains its historical zero for piggyback.
``analyze(..., allow_missing=True)`` retains surviving OUT requests and capture hashes
when its paired IN artifact is missing; unavailable capture metadata counts are null.

Per-class READ (``analyze(..., read_policy={'classes': {class: {'native', 'image', 'native_segments'}}})``,
``--read-policy JSON``; the READ-class schedule endpoint): every READ row carries ``read_class`` (classified
from its request bytes) and the READ summary gains ``by_class``. A READ response pairs only when it is exactly
the native, or the policy prefix construction of a declared padded class: any one-frame prefix whose total is
that class image, from a one-frame native of that class; and, when the build declares a segmented class padded,
the first TCP segment of that class (prefix plus the renumbered native first frame). Without read_policy every
behaviour is the legacy one.
"""
import argparse
import hashlib
import json
import os
import statistics
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire_check as wc  # noqa: E402

MASTER_IP = wc.MASTER_IP
FUNC = {0: 'CONFIRM', 1: 'READ', 2: 'WRITE', 3: 'SELECT', 4: 'OPERATE', 5: 'DIRECT_OPERATE',
        0x81: 'RESPONSE', 0x82: 'UNSOLICITED'}
RESPONSE_FUNCS = (0x81, 0x82)
SD_CONVENTION = ('sd_population divides by n (statistics.pstdev); sd_sample divides by n-1 (statistics.stdev). '
                 'Both are in the units of the statistic (microseconds); a single value reports 0.0 for both.')


def after(a, b):
    """a >= b in 32-bit sequence space."""
    return ((a - b) & 0xffffffff) < 0x80000000


def func_of(payload):
    return payload[12] if len(payload) > 12 else None


def app_seq(payload):
    return payload[11] & 0x0f if len(payload) > 11 else None


def stats(values):
    if not values:
        return None
    v = sorted(values)
    q = lambda p: v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
    return {'n': len(v), 'min': v[0], 'median': int(statistics.median(v)), 'iqr': q(0.75) - q(0.25),
            'p95': q(0.95), 'p99': q(0.99), 'max': v[-1],
            'sd_population': round(statistics.pstdev(v), 1) if len(v) > 1 else 0.0,
            'sd_sample': round(statistics.stdev(v), 1) if len(v) > 1 else 0.0}


def _master_requests(out_segs):
    reqs = [s for s in out_segs if s['src'] == MASTER_IP and s['len'] >= 13 and s['payload'][:2] == b'\x05\x64']
    logical = []
    by_key = {}
    for r in sorted(reqs, key=lambda s: (s['t_us'], s['index'])):
        key = (r['flow'], r['inc'], r['seq'], func_of(r['payload']))
        if key in by_key:
            by_key[key]['attempts'].append(r)
            continue
        crc_ok, _ = wc.dnp3_ok(r['payload'])
        lr = {'flow': r['flow'], 'inc': r['inc'], 'seq': r['seq'], 'func': func_of(r['payload']),
              'app_seq': app_seq(r['payload']), 'end': (r['seq'] + r['len']) & 0xffffffff,
              't_req': r['t_us'], 'dnp3_crc_ok': crc_ok, 'attempts': [r],
              'kind': FUNC.get(func_of(r['payload']), 'F%d' % func_of(r['payload']))}
        by_key[key] = lr
        logical.append(lr)
    return logical


def _packet_observation(packet, capture):
    if packet is None:
        return None
    return dict(capture=capture, packet_index=packet['index'], timestamp_ns=packet['timestamp_ns'],
                timestamp_seconds=packet['timestamp_seconds'], timestamp_fraction=packet['timestamp_fraction'],
                capture_resolution=packet['capture_resolution'], direction=packet['dir'],
                tcp_payload_len=packet['len'], tcp_payload_declared_len=packet['tcp_payload_declared_len'],
                ip_len=packet['ip_len'], captured_len=packet['captured_len'], original_len=packet['original_len'],
                frame_sha256=packet['frame_sha256'])


def _crc_stripped_frames(payload):
    """Validated (link header without LEN, transport/application user) pairs."""
    if not wc.dnp3_ok(payload)[0]:
        return None
    frames, base = [], 0
    while base < len(payload):
        header = payload[base:base + 8]
        remaining, position, user = header[2] - 5, base + 10, bytearray()
        while remaining:
            count = min(16, remaining)
            user.extend(payload[position:position + count])
            position += count + 2
            remaining -= count
        frames.append((header[:2] + header[3:], bytes(user)))
        base = position
    return frames


READ_POLICY_IMAGE = 141      # read_complete_01 frozen policy: range READ 49 -> 141 (the one hardware READ shape)


def _read_prefix_matches(native_frame, right):
    """read_complete_01 policy READ (49 -> 141): a FIR frame with the native transport sequence s, application
    header and IIN and a G1V2 q0x01 object from index 1024 whose first n-4 flags are zero, then the native frame
    as FIN, sequence s+1, its four application octets replaced by the last four zero flags. n follows from the
    first frame's length; every other octet is fixed or the native's own."""
    header, user = native_frame
    if not (len(user) == 33 and user[0] & 0xc0 == 0xc0 and user[1] & 0xf0 == 0xc0 and user[2] == 0x81 and
            user[5:10] == bytes.fromhex('0a02000016')):
        return False
    n = len(right[0][1]) - 8
    if n < 4:
        return False
    obj = bytes.fromhex('010201') + (1024).to_bytes(2, 'little') + (1024 + n - 1).to_bytes(2, 'little') + bytes(n)
    seq = user[0] & 0x3f
    expected = [(header, bytes([0x40 | seq]) + user[1:5] + obj[:-4]),
                (header, bytes([0x80 | ((seq + 1) & 0x3f)]) + obj[-4:] + user[5:])]
    return right == expected


def _policy_prefix_matches(left, right, read_policy):
    """right == the read_complete_01 prefix construction of left (CRC-stripped frames of one TCP payload each):
    a FIR frame with the native transport sequence s, application header and IIN and a G1V2 q0x01 object from
    index 1024 whose first n-4 flags are zero (n follows from the prefix frame's length), then every native frame
    renumbered s+1.. keeping only its FIN bit, the first one's four application octets replaced by the last four
    zero flags. The lengths must be a declared padded class: a one-frame FIR|FIN native at that class native,
    returned at its image; or the first segment of a declared segmented class."""
    header, user = left[0]
    if len(user) < 6 or not user[0] & 0x40 or user[2] != 0x81 or len(right) != len(left) + 1:
        return False
    native_len = sum(10 + len(u) + 2 * (-(-len(u) // 16)) for _h, u in left)
    returned_len = sum(10 + len(u) + 2 * (-(-len(u) // 16)) for _h, u in right)
    complete = len(left) == 1 and user[0] & 0x80
    allowed = False
    for e in (read_policy.get('classes') or {}).values():
        if e['image'] == e['native']:
            continue
        segments = e.get('native_segments') or [e['native']]
        if complete and len(segments) == 1 and native_len == e['native'] and returned_len == e['image']:
            allowed = True
        elif not complete and len(segments) > 1 and native_len == segments[0] and \
                returned_len - native_len == e['image'] - e['native']:
            allowed = True
    if not allowed:
        return False
    n = len(right[0][1]) - 8
    if n < 4:
        return False
    obj = bytes.fromhex('010201') + (1024).to_bytes(2, 'little') + (1024 + n - 1).to_bytes(2, 'little') + bytes(n)
    seq = user[0] & 0x3f
    expected = [(header, bytes([0x40 | seq]) + user[1:5] + obj[:-4])]
    for i, (h, u) in enumerate(left):
        th = (u[0] & 0x80) | (((u[0] & 0x3f) + 1) & 0x3f)
        expected.append((h, bytes([th]) + (obj[-4:] + u[5:] if i == 0 else u[1:])))
    return right == expected


def _response_content_matches(native, returned, read_policy=None):
    """Exact content or the bounded seg61_01/encode61.py wire transformation.

    READ49->61 preserves the five transport/app/IIN bytes and all 23 G10V2 point
    bytes while replacing the single range header with the three declared ranges.
    Control37->61 preserves all 22 application bytes in transport segments 15/6/1.
    Link control/addresses, FIR/FIN, transport sequence and every CRC must match.
    Arbitrary padding, semantic changes and incomplete frames are unsupported.
    This local matcher adds no runtime import of the encoder/oracle.
    """
    left, right = _crc_stripped_frames(native), _crc_stripped_frames(returned)
    if left is None or right is None:
        return False
    if native == returned:
        return True
    if read_policy is not None:
        if left and len(left[0][1]) > 2 and left[0][1][2] == 0x81 and left[0][1][5:10] != bytes.fromhex('0c01280100'):
            return _policy_prefix_matches(left, right, read_policy)       # a READ response: the policy only
    elif len(left) == 1 and len(right) == 2 and len(returned) == READ_POLICY_IMAGE:
        return _read_prefix_matches(left[0], right)
    if len(left) != 1 or len(returned) != 61:
        return False
    header, user = left[0]
    if (len(native) == 49 and len(user) == 33 and user[0] & 0xc0 == 0xc0 and
            user[1] & 0xf0 == 0xc0 and user[2] == 0x81 and user[5:10] == bytes.fromhex('0a02000016')):
        points = user[10:]
        expected = (user[:5] + bytes.fromhex('0a02000005') + points[:6] + bytes.fromhex('0a02000609') +
                    points[6:10] + bytes.fromhex('0a02010a001600') + points[10:])
        return right == [(header, expected)]
    if (len(native) == 37 and len(user) == 23 and user[0] & 0xc0 == 0xc0 and user[2] == 0x81 and
            user[5:10] == bytes.fromhex('0c01280100') and user[-1] == 0):
        seq, app = user[0] & 0x3f, user[1:]
        expected = [(header, bytes([0x40 | seq]) + app[:15]),
                    (header, bytes([(seq + 1) & 0x3f]) + app[15:21]),
                    (header, bytes([0x80 | ((seq + 2) & 0x3f)]) + app[21:])]
        return right == expected
    return False


def _capture_pairs(sent, returned, read_policy=None):
    """Unique transport/content correspondence; capture order alone never establishes identity.

    This deployment preserves M->O sequence/payload and O->M cumulative ACK values.
    Response sequence/payload may be translated/padded and are not correspondence keys.
    Repeated transport identities, including retransmissions, remain ambiguous.
    """
    groups = {}
    for role, packets in (('out', sent), ('in', returned)):
        for p in packets:
            if p['len'] >= 13 and p['payload'][:2] == b'\x05\x64':
                transport = (p['seq'], p['payload']) if p['src'] == MASTER_IP else (p['ack'],)
                key = (p['flow'], p['inc'], p['dir'], func_of(p['payload']), app_seq(p['payload']), transport)
                groups.setdefault(key, {'out': [], 'in': []})[role].append(p)
    out_to_in, in_to_out = {}, {}
    for group in groups.values():
        left, right = group['out'], group['in']
        if len(left) != 1 or len(right) != 1:
            continue
        a, b = left[0], right[0]
        if b['timestamp_ns'] < a['timestamp_ns']:
            continue
        if any(p['len'] != p['tcp_payload_declared_len'] for p in (a, b)):
            continue
        if a['src'] != MASTER_IP and not _response_content_matches(a['payload'], b['payload'], read_policy):
            continue
        out_to_in[a['index']] = b
        in_to_out[b['index']] = a
    return out_to_in, in_to_out


def _add_publication(rows, out_segs, in_segs, capture_availability=None, read_policy=None):
    capture_availability = capture_availability or {'out': True, 'in': True}
    sent = {p['index']: p for p in out_segs}
    returned = {p['index']: p for p in in_segs}
    request_pairs, response_pairs = _capture_pairs(out_segs, in_segs, read_policy)
    response_uses = {}
    for row in rows:
        index = row['response_packet_index']
        if index is not None:
            response_uses[index] = response_uses.get(index, 0) + 1
    first_ns = min((sent[r['request_packet_index']]['timestamp_ns'] for r in rows), default=None)
    for row in rows:
        req = sent[row['request_packet_index']]
        resp = returned.get(row['response_packet_index'])
        response_reason = 'missing_response'
        if resp is not None and response_uses[resp['index']] > 1:
            response_reason = 'ambiguous_shared_response'
            resp = None
        if resp is not None and resp['ack'] != (req['seq'] + req['len']) & 0xffffffff:
            response_reason = 'response_ack_not_exact_request_end'
            resp = None
        if resp is not None and resp['timestamp_ns'] < req['timestamp_ns']:
            # Legacy microsecond truncation can order sub-us packets as ties. Keep the
            # legacy row intact, but never turn a pre-request frame into publication latency.
            resp = None
            response_reason = 'response_precedes_request_at_ns_precision'
        candidates = sorted((p for p in in_segs if p['flow'] == req['flow'] and p['inc'] == req['inc']
                             and p['src'] != MASTER_IP and p['timestamp_ns'] >= req['timestamp_ns']
                             and p['flags'] & wc.ACK and after(p['ack'], (req['seq'] + req['len']) & 0xffffffff)),
                            key=lambda p: (p['timestamp_ns'], p['index']))
        ack = candidates[0] if candidates else None
        delivered = request_pairs.get(req['index']) if not row['retransmitted'] else None
        available = response_pairs.get(resp['index']) if resp is not None else None
        if available is not None and available['timestamp_ns'] < req['timestamp_ns']:
            available = None
        availability_reason = 'unpaired_or_missing_out_response'
        if resp is not None and available is None:
            counterparts = [p for p in out_segs if p['flow'] == resp['flow'] and p['inc'] == resp['inc'] and
                            p['src'] == resp['src'] and p['ack'] == resp['ack'] and
                            func_of(p['payload']) == func_of(resp['payload']) and
                            app_seq(p['payload']) == app_seq(resp['payload'])]
            if len(counterparts) == 1:
                if any(p['len'] != p['tcp_payload_declared_len'] for p in (counterparts[0], resp)):
                    availability_reason = 'response_capture_truncated'
                elif not _response_content_matches(counterparts[0]['payload'], resp['payload'], read_policy):
                    availability_reason = 'response_content_mismatch_or_unsupported_encoding'
        reasons = {}
        pub = dict(request_timestamp_ns=req['timestamp_ns'],
                   publication_complete=resp is not None,
                   publication_response_packet_index=resp['index'] if resp else None,
                   ack_timestamp_ns=ack['timestamp_ns'] if ack else None,
                   response_timestamp_ns=resp['timestamp_ns'] if resp else None,
                   response_available_timestamp_ns=available['timestamp_ns'] if available else None,
                   request_delivered_timestamp_ns=delivered['timestamp_ns'] if delivered else None,
                   sequence=req['index'], observed_at_ms=(req['timestamp_ns'] - first_ns) / 1_000_000.0,
                   request_len=req['len'], response_len=resp['len'] if resp else None)
        for key, end, start, reason in (
                ('ack_latency_ns', ack, req, 'missing_covering_ack'),
                ('response_latency_ns', resp, req, response_reason),
                ('clrt_ns', resp if ack and not ack['len'] else None, ack,
                 'piggyback_ack' if ack and ack['len'] else 'missing_ack_or_response'),
                ('response_availability_ns', available, req, availability_reason),
                ('request_delivery_ns', delivered, req, 'ambiguous_or_missing_request_reflection'),
                ('operate_hold_ns', delivered if row['kind'] == 'OPERATE' else None, req,
                 'not_operate' if row['kind'] != 'OPERATE' else 'ambiguous_or_missing_request_reflection')):
            pub[key] = end['timestamp_ns'] - start['timestamp_ns'] if end and start else None
            if pub[key] is None:
                reasons[key] = reason
        for key in ('ack_timestamp_ns', 'response_timestamp_ns', 'response_available_timestamp_ns',
                    'request_delivered_timestamp_ns', 'response_len'):
            if pub[key] is None:
                reasons[key] = 'packet_not_observed_or_not_certainly_paired'
        if resp is None and response_reason != 'missing_response':
            for key in ('response_latency_ns', 'clrt_ns', 'response_availability_ns', 'response_timestamp_ns',
                        'response_available_timestamp_ns', 'response_len', 'publication_response_packet_index'):
                pub[key] = None
                reasons[key] = response_reason
        window_end = resp['timestamp_ns'] if resp else None
        metadata = {}
        for capture, packets in (('out', out_segs), ('in', in_segs)):
            window = [p for p in packets if p['flow'] == req['flow'] and p['inc'] == req['inc'] and
                      p['timestamp_ns'] >= req['timestamp_ns'] and
                      (window_end is None or p['timestamp_ns'] <= window_end)]
            for direction, src in (('request', MASTER_IP), ('response', wc.OUTSTATION_IP)):
                key = capture + '_' + direction + '_packet_count'
                metadata[key] = sum(p['src'] == src for p in window) if capture_availability[capture] else None
                if metadata[key] is None:
                    reasons[key] = 'capture_unavailable'
            key = capture + '_payload_packet_count'
            metadata[key] = sum(p['len'] > 0 for p in window) if capture_availability[capture] else None
            if metadata[key] is None:
                reasons[key] = 'capture_unavailable'
        pub.update(metadata)
        pub['null_reasons'] = reasons
        row['observation'] = dict(schema_version='vision-exchanges-v2',
                                  clock=dict(clock_id='vision-parent-nic', domain='pcap_epoch', units='ns',
                                             source='paired tcpdump captures on the same Vision parent NIC',
                                             resolution_is_accuracy=False, accuracy_ns=None,
                                             timebase_verification='declared_capture_contract_not_calibrated'),
                                  request=_packet_observation(req, 'out'), ack=_packet_observation(ack, 'in'),
                                  response=_packet_observation(resp, 'in'),
                                  request_delivered=_packet_observation(delivered, 'in'),
                                  response_available=_packet_observation(available, 'out'),
                                  response_content_correspondence=('exact' if available and resp and
                                      available['payload'] == resp['payload'] else
                                      ('read_policy_construction' if read_policy is not None and row['kind'] == 'READ'
                                       else 'bounded_native_to_61') if available else None),
                                  attempts=[_packet_observation(p, 'out') for p in out_segs
                                            if p['flow'] == req['flow'] and p['inc'] == req['inc']
                                            and p['seq'] == req['seq']
                                            and func_of(p['payload']) == func_of(req['payload'])],
                                  metadata_window_end='response' if resp else 'capture_end_incomplete')
        row['publication'] = pub


def _capture_available(path):
    return bool(path is not None and Path(path).exists() and Path(path).stat().st_size >= 24)


def exchanges(out_path, in_path, allow_missing=False, read_policy=None):
    available = {name: _capture_available(path) for name, path in
                 (('out', out_path), ('in', in_path))}
    out_segs = wc.assign_incarnations(wc.parse(out_path)[0]) if not allow_missing or available['out'] else []
    in_segs = wc.assign_incarnations(wc.parse(in_path)[0]) if not allow_missing or available['in'] else []
    back = sorted([s for s in in_segs if s['src'] != MASTER_IP], key=lambda s: (s['t_us'], s['index']))
    rows = []
    for lr in _master_requests(out_segs):
        t_ack = t_resp = resp_len = response_index = None
        piggy = False
        resp_crc_ok = None
        for b in back:
            if b['flow'] != lr['flow'] or b['inc'] != lr['inc'] or b['t_us'] < lr['t_req']:
                continue
            covers = (b['flags'] & wc.ACK) and after(b['ack'], lr['end'])
            if t_ack is None and covers:
                t_ack, piggy = b['t_us'], b['len'] > 0
            is_resp = (b['len'] and b['payload'][:2] == b'\x05\x64' and
                       func_of(b['payload']) in RESPONSE_FUNCS and app_seq(b['payload']) == lr['app_seq'])
            if is_resp and covers:
                t_resp, resp_len = b['t_us'], b['len']
                response_index = b['index']
                resp_crc_ok = wc.dnp3_ok(b['payload'])[0]
                break
        request_key = {k: lr[k] for k in ('flow', 'inc', 'seq', 'func')}
        exchange_id = hashlib.sha256(json.dumps(request_key, sort_keys=True).encode()).hexdigest()
        row = {'kind': lr['kind'], 'app_seq': lr['app_seq'], 't_req': lr['t_req'],
               'request_key': request_key, 'exchange_id': exchange_id,
               'request_packet_index': lr['attempts'][0]['index'], 'response_packet_index': response_index,
               'attempts': len(lr['attempts']), 'retransmitted': len(lr['attempts']) > 1,
               'req_crc_ok': lr['dnp3_crc_ok'], 'complete': t_resp is not None, 'piggyback': piggy,
               'resp_crc_ok': resp_crc_ok, 'resp_len': resp_len}
        if t_ack is not None:
            row['ack_lat_us'] = t_ack - lr['t_req']
        if t_resp is not None:
            row['clrt_us'] = t_resp - t_ack if t_ack is not None else None
            row['rt_us'] = t_resp - lr['t_req']
        if read_policy is not None and lr['kind'] == 'READ':
            import read_classes                        # policy runs only (deployed beside this file for series runs)
            row['read_class'] = read_classes.classify_request_frames(lr['attempts'][0]['payload'])
        rows.append(row)
    _add_publication(rows, out_segs, in_segs, available, read_policy)
    return rows


def summarize(rows, by_class=False):
    """by_class (read_policy runs): the READ entry also carries the same counts per read_class."""
    out = {}
    for kind in sorted(set(r['kind'] for r in rows)):
        sel = [r for r in rows if r['kind'] == kind]
        done = [r for r in sel if r['complete']]
        eligible = [r for r in done if not r['piggyback'] and not r['retransmitted']]
        out[kind] = {
            'logical_requests': len(sel), 'attempts': sum(r['attempts'] for r in sel),
            'retransmitted': sum(r['retransmitted'] for r in sel),
            'complete': len(done), 'incomplete': len(sel) - len(done),
            'piggyback': sum(r['piggyback'] for r in done),
            'req_crc_bad': sum(not r['req_crc_ok'] for r in sel),
            'resp_crc_bad': sum(r['resp_crc_ok'] is False for r in done),
            'resp_len': sorted(set(r['resp_len'] for r in done if r['resp_len'] is not None)),
            'eligible_for_latency': len(eligible),
            'clrt_us': stats([r['clrt_us'] for r in eligible if r.get('clrt_us') is not None]),
            'rt_us': stats([r['rt_us'] for r in eligible]),
            'ack_lat_us': stats([r['ack_lat_us'] for r in eligible if r.get('ack_lat_us') is not None])}
        if by_class and kind == 'READ':
            out[kind]['by_class'] = {}
            for cls in sorted(set(str(r.get('read_class')) for r in sel)):
                part = [r for r in sel if str(r.get('read_class')) == cls]
                finished = [r for r in part if r['complete']]
                out[kind]['by_class'][cls] = {
                    'logical_requests': len(part), 'complete': len(finished),
                    'resp_len': sorted(set(r['resp_len'] for r in finished if r['resp_len'] is not None)),
                    'publication_paired': sum(1 for r in part
                                              if r['publication']['response_available_timestamp_ns'] is not None)}
    return out


def analyze(out_path, in_path, allow_missing=False, read_policy=None):
    rows = exchanges(out_path, in_path, allow_missing=allow_missing, read_policy=read_policy)
    return {'schema_version': 'vision-exchanges-v2', 'sd_convention': SD_CONVENTION,
            'capture_sha256': {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                               for name, path in (('out', out_path), ('in', in_path))
                               if path is not None and Path(path).exists()},
            'capture_availability': {name: dict(status='observed' if _capture_available(path) else 'unavailable',
                                                reason=None if _capture_available(path) else 'capture_missing_or_header_truncated')
                                     for name, path in (('out', out_path), ('in', in_path))},
            'extractor_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'extractor_sources_sha256': {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                                         for name, path in (('clrt_check.py', __file__), ('wire_check.py', wc.__file__))},
            'note': 'intervals are host-capture-point (same parent-NIC clock), not ASIC forwarding time; '
                    'timestamps are integer microseconds at the capture resolution',
            'summary': summarize(rows, by_class=read_policy is not None), 'exchanges': rows}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('--json')
    ap.add_argument('--read-policy', help='per-class READ declaration as JSON: {"classes": {class: {native, image, '
                                          'native_segments}}}')
    a = ap.parse_args()
    report = analyze(a.out_pcap, a.in_pcap, read_policy=json.loads(a.read_policy) if a.read_policy else None)
    if a.json:
        json.dump(report, open(a.json, 'w'), indent=1, default=str)
    json.dump(report['summary'], sys.stdout, indent=1, default=str)
    print()
    # a run whose requests or responses fail their DNP3 CRC is a corrupt extraction
    bad = any(k['req_crc_bad'] or k['resp_crc_bad'] for k in report['summary'].values())
    sys.exit(1 if bad else 0)
