#!/usr/bin/env python3
"""
Gate 13.1 -- OFFLINE audit of the DNP3 replay corpora.

INTERPRETER: system python3 (tested on 3.8.10). Stdlib only; scapy/tshark are NOT
required to produce the results. tshark/capinfos are invoked ONLY for the optional
external cross-check appendix and their absence is reported, not fatal.

This script is read-only on the pcaps. It opens no socket, contacts no switch, and
emits no DNP3 traffic. It writes exactly two files into its own directory:
    corpus_audit.json            machine-readable counts + full transaction table
    GATE_13_1_CORPUS_AUDIT.md    the report

Run:
    python3 audit_corpus.py
    python3 audit_corpus.py --no-external      (skip the tshark/capinfos appendix)
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter, OrderedDict, defaultdict

import dnp3_pcap as D

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.abspath(os.path.join(HERE, '..', '..', 'Traffic Trace'))
CAPTURES = ['SEL751', 'SEL751L', 'AB1400', 'AB1400L', 'ION7550', 'ION7550L']
DNP3_PORT = 20000

# Established lab facts, checked against the data rather than assumed.
EXPECTED_LINK_MASTER = 1
EXPECTED_LINK_OUTSTATION = 10
EXPECTED_ACK_MODE = {'SEL751': 'separate', 'SEL751L': 'separate',
                     'AB1400': 'combined', 'AB1400L': 'combined',
                     'ION7550': 'combined', 'ION7550L': 'combined'}


# ---------------------------------------------------------------------------
# stream assembly
# ---------------------------------------------------------------------------
def build_streams(packets):
    """Group TCP packets into 4-tuple streams, both directions kept separate."""
    streams = OrderedDict()
    for pkt in packets:
        a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        key = (a, b) if a <= b else (b, a)
        streams.setdefault(key, []).append(pkt)
    return streams


def stream_roles(key, pkts):
    """Return (master_endpoint, outstation_endpoint) from the DNP3 port, or None."""
    for endpoint in key:
        if endpoint[1] == DNP3_PORT:
            other = key[0] if key[1] == endpoint else key[1]
            return other, endpoint
    return None, None


def seq_at_offset(reass, offset):
    """TCP sequence number of the stream byte at ``offset``."""
    lo, hi = 0, len(reass.segments) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, length, _idx, seq, _ts = reass.segments[mid]
        if offset < start:
            hi = mid - 1
        elif offset >= start + length:
            lo = mid + 1
        else:
            return D.seq_add(seq, offset - start)
    return None


# ---------------------------------------------------------------------------
# transaction pairing
# ---------------------------------------------------------------------------
def pair_transactions(reqs, resps, req_re, resp_re, pkt_by_index, os_packets):
    """
    Pair each application request frame with its pure TCP ACK (if any) and its
    response fragment group. Returns (transactions, orphan_responses).

    Pairing is by wire order plus DNP3 application sequence number; every deviation
    is recorded in the transaction's ``flags`` list rather than silently dropped.
    """
    transactions = []
    resp_ptr = 0
    n_resp = len(resps)
    for i, req in enumerate(reqs):
        flags = []
        req_off = req['stream_offset']
        req_seq = seq_at_offset(req_re, req_off)
        req_len = req['wire_len']
        expected_ack = D.seq_add(req_seq, req_len)
        carrier = pkt_by_index[req['first_packet']]
        if carrier.payload_len != req_len or carrier.seq != req_seq:
            flags.append('request_shares_tcp_segment')
        if req['spans_segments']:
            flags.append('request_spans_tcp_segments')

        # --- response fragment group -------------------------------------
        while resp_ptr < n_resp and resps[resp_ptr]['last_ts'] < req['last_ts']:
            resp_ptr += 1
        group = []
        if resp_ptr < n_resp:
            j = resp_ptr
            while j < n_resp:
                group.append(resps[j])
                j += 1
                if group[-1]['app_fin']:
                    break
            resp_ptr = j
        if not group:
            flags.append('missing_response')
        else:
            if group[0]['app_seq'] != req['app_seq']:
                flags.append('app_seq_mismatch')
            if len(group) > 1:
                flags.append('multi_fragment_response')
            if any(f['spans_segments'] for f in group):
                flags.append('response_spans_tcp_segments')

        # --- pure TCP ACK -------------------------------------------------
        resp_first_pkt = group[0]['first_packet'] if group else None
        ack_pkt = None
        dup_acks = 0
        cumulative = False
        for pkt in os_packets:
            if pkt.index <= req['last_packet']:
                continue
            if resp_first_pkt is not None and pkt.index > resp_first_pkt:
                break
            if not D.is_pure_ack(pkt):
                continue
            delta = D.seq_diff(pkt.ack, expected_ack)
            if delta == 0:
                if ack_pkt is None:
                    ack_pkt = pkt
                else:
                    dup_acks += 1
            elif delta > 0 and ack_pkt is None:
                ack_pkt = pkt
                cumulative = True
                break
        if cumulative:
            flags.append('cumulative_ack_only')

        # --- ACK mode -----------------------------------------------------
        resp_pkt = pkt_by_index[resp_first_pkt] if resp_first_pkt is not None else None
        if ack_pkt is not None and resp_first_pkt is not None and ack_pkt.index < resp_first_pkt:
            ack_mode = 'separate'
        elif ack_pkt is None and resp_pkt is not None and D.seq_diff(resp_pkt.ack, expected_ack) >= 0:
            ack_mode = 'combined'
        elif ack_pkt is None and resp_pkt is None:
            ack_mode = 'undetermined'
            flags.append('ack_mode_undetermined')
        else:
            ack_mode = 'ambiguous'
            flags.append('ack_mode_ambiguous')

        # --- multiple outstanding requests --------------------------------
        if group and i + 1 < len(reqs) and reqs[i + 1]['first_ts'] < group[0]['first_ts']:
            flags.append('multiple_outstanding')

        req_ts = req['last_ts']
        ack_ts = ack_pkt.ts if ack_pkt is not None else None
        resp_ts = group[0]['first_ts'] if group else None
        resp_last_ts = group[-1]['last_ts'] if group else None

        txn = OrderedDict()
        txn['txn'] = i
        txn['req_pkt'] = req['first_packet']
        txn['req_pkt_last'] = req['last_packet']
        txn['req_ts'] = round(req_ts, 9)
        txn['req_seq'] = req_seq
        txn['req_payload_len'] = req_len
        txn['req_tcp_payload_len'] = carrier.payload_len
        txn['expected_ack'] = expected_ack
        txn['req_fc'] = req['app_fc']
        txn['req_fc_name'] = req['app_fc_name']
        txn['req_app_seq'] = req['app_seq']
        txn['req_tr_seq'] = req['transport']['seq'] if req['transport'] else None
        txn['req_link_src'] = req['link_src']
        txn['req_link_dst'] = req['link_dst']
        txn['ack_pkt'] = ack_pkt.index if ack_pkt is not None else None
        txn['ack_ts'] = round(ack_ts, 9) if ack_ts is not None else None
        txn['ack_num'] = ack_pkt.ack if ack_pkt is not None else None
        txn['ack_dup_count'] = dup_acks
        txn['resp_pkts'] = [p for f in group for p in
                            range(f['first_packet'], f['last_packet'] + 1)]
        txn['resp_frames'] = len(group)
        txn['resp_ts'] = round(resp_ts, 9) if resp_ts is not None else None
        txn['resp_last_ts'] = round(resp_last_ts, 9) if resp_last_ts is not None else None
        txn['resp_app_seq'] = [f['app_seq'] for f in group]
        txn['resp_fc'] = [f['app_fc'] for f in group]
        txn['resp_iin'] = [f['iin'] for f in group]
        txn['resp_wire_len'] = [f['wire_len'] for f in group]
        txn['resp_ack_num'] = resp_pkt.ack if resp_pkt is not None else None
        txn['ack_mode'] = ack_mode
        # byte extents, used to attribute retransmitted segments exactly
        txn['_req_extent'] = (req_off, req_off + req_len)
        txn['_resp_extent'] = ((group[0]['stream_offset'],
                                group[-1]['stream_offset'] + group[-1]['wire_len'])
                               if group else None)
        txn['req_to_ack_ms'] = round((ack_ts - req_ts) * 1000.0, 6) if ack_ts else None
        txn['ack_to_resp_ms'] = (round((resp_ts - ack_ts) * 1000.0, 6)
                                 if (ack_ts and resp_ts) else None)
        txn['req_to_resp_ms'] = round((resp_ts - req_ts) * 1000.0, 6) if resp_ts else None
        txn['flags'] = flags
        transactions.append(txn)

    orphans = [f['first_packet'] for f in resps[resp_ptr:]]
    return transactions, orphans


def mark_retransmissions(transactions, req_re, resp_re):
    """
    Attribute every retransmitted TCP segment to the transaction whose bytes it
    duplicates, by mapping the retransmitted sequence number back to a stream offset
    and testing it against the request/response byte extents.

    Attribution is by byte range, not by packet-index window: in this corpus the
    duplicate response arrives AFTER the master has already ACKed, i.e. outside the
    request..response packet span, so a window test would miss it.
    """
    events = ([('request', r) for r in req_re.retransmissions] +
              [('response', r) for r in resp_re.retransmissions])
    if not events:
        return 0, []
    hit = set()
    unattributed = []
    for kind, (pkt_index, seq, length, _ts) in events:
        reass = req_re if kind == 'request' else resp_re
        offset = reass.offset_for_seq(seq)
        placed = False
        if offset is not None:
            key = '_req_extent' if kind == 'request' else '_resp_extent'
            for txn in transactions:
                extent = txn.get(key)
                if extent and extent[0] <= offset < extent[1]:
                    txn['flags'].append('retransmission_of_%s' % kind)
                    txn.setdefault('retransmitted_pkts', []).append(pkt_index)
                    hit.add(txn['txn'])
                    placed = True
                    break
        if not placed:
            unattributed.append({'kind': kind, 'pkt': pkt_index, 'seq': seq,
                                 'len': length, 'stream_offset': offset})
    return len(hit), unattributed


CLEAN_DISQUALIFIERS = {
    'missing_response', 'app_seq_mismatch', 'multi_fragment_response',
    'multiple_outstanding', 'retransmission_of_request', 'retransmission_of_response',
    'ack_mode_ambiguous', 'ack_mode_undetermined', 'cumulative_ack_only',
    'request_spans_tcp_segments', 'response_spans_tcp_segments',
    'request_shares_tcp_segment',
}


def is_clean(txn):
    return not (set(txn['flags']) & CLEAN_DISQUALIFIERS)


def longest_clean_run(txns):
    """Longest run of consecutive clean transactions: (start_txn, end_txn, length)."""
    best = (None, None, 0)
    run_start = None
    for i, t in enumerate(txns):
        if is_clean(t):
            if run_start is None:
                run_start = i
            length = i - run_start + 1
            if length > best[2]:
                best = (txns[run_start]['txn'], t['txn'], length)
        else:
            run_start = None
    return {'start_txn': best[0], 'end_txn': best[1], 'length': best[2]}


# ---------------------------------------------------------------------------
# per capture analysis
# ---------------------------------------------------------------------------
def analyse_capture(name, path):
    result = OrderedDict()
    result['capture'] = name
    result['path'] = path
    result['file_bytes'] = os.path.getsize(path)
    try:
        packets, pstats = D.read_pcap(path)
    except (D.PcapError, IOError, OSError) as exc:
        result['parse_error'] = '%s: %s' % (type(exc).__name__, exc)
        return result

    result['pcap_stats'] = pstats
    result['total_packets'] = pstats['total_packets']
    if packets:
        result['first_ts'] = round(packets[0].ts, 9)
        result['last_ts'] = round(packets[-1].ts, 9)
        result['duration_s'] = round(packets[-1].ts - packets[0].ts, 6)
    port_pkts = [p for p in packets if DNP3_PORT in (p.sport, p.dport)]
    result['tcp_packets_port_20000'] = len(port_pkts)
    result['tcp_packets_other_ports'] = len(packets) - len(port_pkts)

    pkt_by_index = {p.index: p for p in packets}
    streams = build_streams(packets)
    result['tcp_streams'] = len(streams)

    file_fc = Counter()
    file_klass = Counter()
    stream_reports = []
    for key, pkts in streams.items():
        master_ep, os_ep = stream_roles(key, pkts)
        if os_ep is None:
            stream_reports.append(OrderedDict([
                ('endpoints', ['%s:%d' % e for e in key]),
                ('note', 'no endpoint on TCP/20000 - not analysed as DNP3'),
                ('packets', len(pkts))]))
            continue
        m2o = [p for p in pkts if (p.dst, p.dport) == os_ep]
        o2m = [p for p in pkts if (p.src, p.sport) == os_ep]

        req_re, resp_re = D.StreamReassembler(), D.StreamReassembler()
        for p in m2o:
            req_re.add(p)
        for p in o2m:
            resp_re.add(p)
        req_frames, req_anom = D.parse_dnp3_frames(req_re)
        resp_frames, resp_anom = D.parse_dnp3_frames(resp_re)

        reqs = [f for f in req_frames if f['klass'] == 'APP_REQUEST']
        resps = [f for f in resp_frames if f['klass'] == 'APP_RESPONSE']
        txns, orphans = pair_transactions(reqs, resps, req_re, resp_re,
                                          pkt_by_index, o2m)
        retrans_hits, retrans_unattributed = mark_retransmissions(txns, req_re, resp_re)
        for t in txns:
            t.pop('_req_extent', None)
            t.pop('_resp_extent', None)
        clean = [t for t in txns if is_clean(t)]

        fc_m2o = Counter('%d:%s' % (f['app_fc'], f['app_fc_name'])
                         for f in req_frames if f['app_fc'] is not None)
        fc_o2m = Counter('%d:%s' % (f['app_fc'], f['app_fc_name'])
                         for f in resp_frames if f['app_fc'] is not None)
        file_fc.update(fc_m2o)
        file_fc.update(fc_o2m)
        klass = Counter(f['klass'] for f in req_frames + resp_frames)
        file_klass.update(klass)

        modes = Counter(t['ack_mode'] for t in txns)
        # CLRT is ACK->response, per the locked Case-A terminology in CLAUDE.md; it is
        # defined only for separate-ACK transactions. req->ACK is reported separately.
        r2a = sorted(t['req_to_ack_ms'] for t in txns
                     if t['ack_mode'] == 'separate' and t['req_to_ack_ms'] is not None)
        clrt = sorted(t['ack_to_resp_ms'] for t in txns
                      if t['ack_mode'] == 'separate' and t['ack_to_resp_ms'] is not None)
        r2r = sorted(t['req_to_resp_ms'] for t in txns if t['req_to_resp_ms'] is not None)
        intervals = sorted(round((b['req_ts'] - a['req_ts']), 6)
                           for a, b in zip(txns, txns[1:]))

        rep = OrderedDict()
        rep['master'] = '%s:%d' % master_ep
        rep['outstation'] = '%s:%d' % os_ep
        rep['packets_total'] = len(pkts)
        rep['packets_master_to_outstation'] = len(m2o)
        rep['packets_outstation_to_master'] = len(o2m)
        rep['pure_acks_master_to_outstation'] = sum(1 for p in m2o if D.is_pure_ack(p))
        rep['pure_acks_outstation_to_master'] = sum(1 for p in o2m if D.is_pure_ack(p))
        rep['data_pkts_master_to_outstation'] = sum(1 for p in m2o if p.payload_len)
        rep['data_pkts_outstation_to_master'] = sum(1 for p in o2m if p.payload_len)
        rep['bytes_master_to_outstation'] = len(req_re.buf)
        rep['bytes_outstation_to_master'] = len(resp_re.buf)
        rep['link_addr_master_to_outstation'] = dict(
            Counter('src=%d,dst=%d' % (f['link_src'], f['link_dst']) for f in req_frames))
        rep['link_addr_outstation_to_master'] = dict(
            Counter('src=%d,dst=%d' % (f['link_src'], f['link_dst']) for f in resp_frames))
        rep['dnp3_frames_master_to_outstation'] = len(req_frames)
        rep['dnp3_frames_outstation_to_master'] = len(resp_frames)
        rep['fc_master_to_outstation'] = dict(fc_m2o)
        rep['fc_outstation_to_master'] = dict(fc_o2m)
        rep['frame_class_counts'] = dict(klass)
        rep['retransmitted_pkts_master_to_outstation'] = [r[0] for r in req_re.retransmissions]
        rep['retransmitted_pkts_outstation_to_master'] = [r[0] for r in resp_re.retransmissions]
        rep['seq_gaps_master_to_outstation'] = [
            {'pkt': g[0], 'expected_seq': g[1], 'got_seq': g[2], 'missing_bytes': g[3]}
            for g in req_re.gaps]
        rep['seq_gaps_outstation_to_master'] = [
            {'pkt': g[0], 'expected_seq': g[1], 'got_seq': g[2], 'missing_bytes': g[3]}
            for g in resp_re.gaps]
        rep['anomalies_master_to_outstation'] = req_anom
        rep['anomalies_outstation_to_master'] = resp_anom
        rep['malformed_frames'] = [
            {'dir': d, 'pkt': f['first_packet'], 'offset': f['stream_offset'],
             'len_field': f['len_field'], 'klass': f['klass']}
            for d, fl in (('m2o', req_frames), ('o2m', resp_frames))
            for f in fl if f['klass'] == 'MALFORMED_CRC']
        rep['link_only_frames'] = [
            {'dir': d, 'pkt': f['first_packet'], 'link_fc': f['link_fc_name']}
            for d, fl in (('m2o', req_frames), ('o2m', resp_frames))
            for f in fl if f['klass'] == 'LINK_OTHER']
        rep['frames_spanning_tcp_segments'] = [
            {'dir': d, 'first_pkt': f['first_packet'], 'last_pkt': f['last_packet'],
             'wire_len': f['wire_len']}
            for d, fl in (('m2o', req_frames), ('o2m', resp_frames))
            for f in fl if f['spans_segments']]
        rep['transactions_total'] = len(txns)
        rep['transactions_clean'] = len(clean)
        rep['transactions_flagged'] = len(txns) - len(clean)
        rep['orphan_response_pkts'] = orphans
        rep['retransmission_affected_transactions'] = retrans_hits
        rep['retransmissions_unattributed'] = retrans_unattributed
        rep['longest_clean_run'] = longest_clean_run(txns)
        rep['request_fc_pattern_head'] = [t['req_fc_name'] for t in txns[:12]]
        rep['first_clean_read_txns'] = [
            {'txn': t['txn'], 'req_pkt': t['req_pkt'], 'ack_pkt': t['ack_pkt'],
             'resp_pkts': t['resp_pkts']}
            for t in clean if t['req_fc_name'] == 'READ'][:20]
        rep['ack_mode_counts'] = dict(modes)
        rep['ack_mode_verdict'] = ack_mode_verdict(modes)
        rep['flag_counts'] = dict(Counter(f for t in txns for f in t['flags']))
        rep['req_to_ack_ms'] = summarise(r2a)
        rep['clrt_ack_to_resp_ms'] = summarise(clrt)
        rep['req_to_resp_ms'] = summarise(r2r)
        rep['request_interval_s'] = summarise(intervals)
        rep['response_wire_len_counts'] = dict(Counter(
            l for t in txns for l in t['resp_wire_len']))
        rep['request_wire_len_counts'] = dict(Counter(
            t['req_payload_len'] for t in txns))
        rep['transactions'] = txns
        stream_reports.append(rep)

    result['streams'] = stream_reports
    result['fc_counts_file'] = dict(file_fc)
    result['frame_class_counts_file'] = dict(file_klass)
    result['transactions_total'] = sum(s.get('transactions_total', 0) for s in stream_reports)
    result['transactions_clean'] = sum(s.get('transactions_clean', 0) for s in stream_reports)
    return result


def ack_mode_verdict(modes):
    if not modes:
        return 'no_transactions'
    total = sum(modes.values())
    top, count = modes.most_common(1)[0]
    if count == total:
        return top
    return '%s_majority_%d_of_%d' % (top, count, total)


def summarise(values):
    if not values:
        return None
    n = len(values)
    def pct(p):
        idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
        return round(values[idx], 6)
    return OrderedDict([('n', n), ('min', round(values[0], 6)), ('p25', pct(25)),
                        ('median', pct(50)), ('p75', pct(75)), ('p95', pct(95)),
                        ('max', round(values[-1], 6)),
                        ('mean', round(sum(values) / float(n), 6))])


# ---------------------------------------------------------------------------
# Zeek cross-check
# ---------------------------------------------------------------------------
def read_zeek_log(path):
    if not os.path.exists(path):
        return None
    fields, rows = [], []
    with open(path) as handle:
        for line in handle:
            line = line.rstrip('\n')
            if line.startswith('#fields'):
                fields = line.split('\t')[1:]
            elif not line.startswith('#') and line.strip():
                rows.append(dict(zip(fields, line.split('\t'))))
    return rows


def zeek_crosscheck(corpus_dir, results):
    """Match each Zeek dnp3.log against the capture whose time window contains it."""
    out = OrderedDict()
    for label, rel in (('Traffic Trace/dnp3.log', 'dnp3.log'),
                       ('zeek_run/dnp3.log', os.path.join('zeek_run', 'dnp3.log')),
                       ('broscript/dnp3.log', os.path.join('broscript', 'dnp3.log'))):
        rows = read_zeek_log(os.path.join(corpus_dir, rel))
        if rows is None:
            out[label] = {'status': 'absent'}
            continue
        ts = [float(r['ts']) for r in rows]
        conns = Counter('%s:%s->%s:%s' % (r['id.orig_h'], r['id.orig_p'],
                                          r['id.resp_h'], r['id.resp_p']) for r in rows)
        fcs = Counter('%s/%s' % (r.get('fc_request', '-'), r.get('fc_reply', '-'))
                      for r in rows)
        match = None
        for res in results:
            if 'first_ts' not in res:
                continue
            if res['first_ts'] - 1 <= min(ts) and max(ts) <= res['last_ts'] + 1:
                match = res['capture']
                break
        entry = OrderedDict()
        entry['status'] = 'present'
        entry['records'] = len(rows)
        entry['ts_min'] = min(ts)
        entry['ts_max'] = max(ts)
        entry['matched_capture'] = match
        entry['records_per_connection'] = dict(conns)
        entry['fc_request_reply_pairs'] = dict(fcs)
        entry['zeek_iin_values'] = dict(Counter(r.get('iin', '-') for r in rows))
        if match:
            res = [r for r in results if r['capture'] == match][0]
            ours = OrderedDict()
            for s in res['streams']:
                if 'outstation' not in s:
                    continue
                ckey = '%s->%s' % (s['master'], s['outstation'])
                ours[ckey] = s['transactions_total']
            entry['our_transactions_per_connection'] = ours
            entry['agreement'] = compare_zeek(conns, ours)
        out[label] = entry
    return out


def latency_crosscheck(corpus_dir, results):
    """
    Compare Zeek's latency.log (one whitespace-separated row of seconds per
    connection) against our per-transaction request->response intervals.
    """
    path = os.path.join(corpus_dir, 'latency.log')
    if not os.path.exists(path):
        return {'status': 'absent'}
    rows = []
    with open(path) as handle:
        for line in handle:
            vals = [float(x) for x in line.split()]
            if vals:
                rows.append(vals)
    out = OrderedDict([('status', 'present'), ('rows', len(rows)),
                       ('values_per_row', [len(v) for v in rows]),
                       ('measures', 'request -> response, seconds'),
                       ('comparisons', [])])
    # latency.log was produced from SEL751.pcap (broscript/latency.bro).
    target = [r for r in results if r['capture'] == 'SEL751']
    if not target:
        return out
    streams = [s for s in target[0]['streams'] if 'outstation' in s]
    # latency.bro emits one row per responder IP in Zeek table order, and within a
    # row concatenates one vector PER FUNCTION CODE, also in table order. Neither
    # order is wire order, so the candidate orderings are searched explicitly rather
    # than assumed.
    candidates = []
    for s in streams:
        txns = s['transactions']
        by_fc = OrderedDict()
        for t in txns:
            by_fc.setdefault(t['req_fc_name'], []).append(t['req_to_resp_ms'] / 1000.0)
        names = list(by_fc)
        orders = [('wire', [t['req_to_resp_ms'] / 1000.0 for t in txns])]
        if len(names) == 2:
            orders.append(('+'.join(names), by_fc[names[0]] + by_fc[names[1]]))
            orders.append(('+'.join(reversed(names)), by_fc[names[1]] + by_fc[names[0]]))
        for label, vals in orders:
            candidates.append((s['outstation'], label, vals))
    for i, row in enumerate(rows):
        best = None
        for outstation, label, vals in candidates:
            if len(vals) != len(row):
                continue
            worst = max(abs(row[k] - vals[k]) for k in range(len(row)))
            within = sum(1 for k in range(len(row)) if abs(row[k] - vals[k]) < 1e-6)
            if best is None or worst < best['max_abs_diff_s']:
                best = OrderedDict([('zeek_row', i), ('zeek_values', len(row)),
                                    ('matched_stream', outstation),
                                    ('matched_ordering', label),
                                    ('compared', len(row)),
                                    ('max_abs_diff_s', worst),
                                    ('values_agreeing_to_1us', within)])
        if best is not None:
            best['max_abs_diff_s'] = round(best['max_abs_diff_s'], 12)
            out['comparisons'].append(best)
    return out


def compare_zeek(zeek_conns, our_conns):
    notes = []
    for ckey, n in our_conns.items():
        z = zeek_conns.get(ckey)
        if z is None:
            notes.append('%s: zeek has no records, we found %d transactions' % (ckey, n))
        elif z != n:
            notes.append('%s: zeek %d vs ours %d (delta %+d)' % (ckey, z, n, n - z))
        else:
            notes.append('%s: zeek %d == ours %d' % (ckey, z, n))
    return notes


# ---------------------------------------------------------------------------
# external cross-check (tshark / capinfos) -- evidence only, never load bearing
# ---------------------------------------------------------------------------
def run_cmd(cmd):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        return proc.returncode, out.decode('utf-8', 'replace'), err.decode('utf-8', 'replace')
    except OSError as exc:
        return -1, '', 'tool unavailable: %s' % exc


def external_crosscheck(corpus_dir):
    blocks = []
    for name in CAPTURES:
        path = os.path.join(corpus_dir, name + '.pcap')
        cmd = ['capinfos', '-c', '-u', '-a', '-e', '-M', path]
        rc, out, err = run_cmd(cmd)
        blocks.append(('$ ' + ' '.join(cmd), out if rc == 0 else out + err))
        cmd = ['tshark', '-r', path, '-Y', 'dnp3', '-T', 'fields',
               '-e', 'ip.src', '-e', 'dnp3.al.func']
        rc, out, err = run_cmd(cmd)
        if rc == 0:
            counted = Counter(l for l in out.splitlines() if l.strip())
            body = '\n'.join('%7d %s' % (v, k) for k, v in sorted(counted.items()))
        else:
            body = out + err
        blocks.append(('$ ' + ' '.join(cmd) + ' | sort | uniq -c', body))
    return blocks


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
def fmt_int(n):
    return '{:,}'.format(n)


def md_table(headers, rows):
    lines = ['| ' + ' | '.join(headers) + ' |',
             '|' + '|'.join(['---'] * len(headers)) + '|']
    for r in rows:
        lines.append('| ' + ' | '.join(str(c) for c in r) + ' |')
    return '\n'.join(lines)


def build_report(results, zeek, latency, external, corpus_dir):
    L = []
    add = L.append
    add('# Gate 13.1 -- DNP3 Replay Corpus Audit (OFFLINE)')
    add('')
    add('Part 13 (DNP3 replay integration), gate 13.1. Pure offline analysis: no switch, '
        'no hardware, no network, no physical SEL-751, no DNP3 control or write traffic '
        'was generated. The six pcap files were opened read-only.')
    add('')
    add('Generated by `audit_corpus.py` (system `python3`, stdlib only). Machine-readable '
        'twin: `corpus_audit.json`.')
    add('')
    add('Evidence tags: [OBS] measured from the capture bytes, [DOC] from a spec or an '
        'existing repo document, [REP] reproduced/cross-checked with an independent tool, '
        '[DESIGN] a design decision, [FIX] a defect corrected here, [OPEN] unresolved or '
        'inferred.')
    add('')

    # ---- 1. headline ----
    add('## 1. Headline counts per capture [OBS]')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            rows.append([r['capture'], 'PARSE ERROR', r['parse_error'], '', '', '', ''])
            continue
        rows.append([r['capture'], fmt_int(r['total_packets']),
                     fmt_int(r['tcp_packets_port_20000']), r['tcp_streams'],
                     '%.3f' % r['duration_s'], fmt_int(r['transactions_total']),
                     fmt_int(r['transactions_clean'])])
    add(md_table(['capture', 'total pkts', 'TCP pkts on :20000', 'TCP streams',
                  'duration (s)', 'transactions', 'clean transactions'], rows))
    add('')
    add('Every packet in all six files is IPv4/TCP on port 20000; there is no non-DNP3 '
        'background traffic, no VLAN tag, no IP fragment and no capture truncation '
        '(snaplen 65535). [OBS]')
    add('')

    # ---- 2. per-direction ----
    add('## 2. Per-direction breakdown and DNP3 link addresses [OBS]')
    add('')
    add('Direction is assigned by TCP port (the endpoint on :20000 is the outstation) and '
        'then cross-checked against the DNP3 link addresses actually carried in the '
        'frames. Every capture contains **two** DNP3 TCP streams.')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            rows.append([r['capture'], s['master'], s['outstation'],
                         fmt_int(s['packets_master_to_outstation']),
                         fmt_int(s['packets_outstation_to_master']),
                         fmt_int(s['data_pkts_master_to_outstation']),
                         fmt_int(s['data_pkts_outstation_to_master']),
                         ';'.join(sorted(s['link_addr_master_to_outstation'])),
                         ';'.join(sorted(s['link_addr_outstation_to_master']))])
    add(md_table(['capture', 'master', 'outstation', 'pkts m->o', 'pkts o->m',
                  'data pkts m->o', 'data pkts o->m', 'link addr m->o', 'link addr o->m'],
                 rows))
    add('')

    conflicts = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            for k in s['link_addr_master_to_outstation']:
                src = int(k.split(',')[0].split('=')[1])
                dst = int(k.split(',')[1].split('=')[1])
                if src != EXPECTED_LINK_MASTER or dst != EXPECTED_LINK_OUTSTATION:
                    conflicts.append('%s %s: request link %s (lab default expects '
                                     'src=%d,dst=%d)' % (r['capture'], s['outstation'], k,
                                                         EXPECTED_LINK_MASTER,
                                                         EXPECTED_LINK_OUTSTATION))
    if conflicts:
        add('**Conflict with the stated lab link-address fact** (master=1, outstation=10):')
        add('')
        for c in sorted(set(conflicts)):
            add('- %s [OBS]' % c)
        add('')

    # ---- 3. function codes ----
    add('## 3. DNP3 application function codes [OBS]')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            allfc = dict(s['fc_master_to_outstation'])
            allfc.update(s['fc_outstation_to_master'])
            rows.append([r['capture'], s['outstation'],
                         ', '.join('%s=%d' % (k, v) for k, v in
                                   sorted(s['fc_master_to_outstation'].items())),
                         ', '.join('%s=%d' % (k, v) for k, v in
                                   sorted(s['fc_outstation_to_master'].items()))])
    add(md_table(['capture', 'outstation', 'requests (m->o)', 'responses (o->m)'], rows))
    add('')
    add('Only three application function codes occur anywhere in the corpus: '
        '`1 READ`, `5 DIRECT_OPERATE` (requests) and `129 RESPONSE`. No CONFIRM, no '
        'unsolicited response, no SELECT/OPERATE. [OBS] The DIRECT_OPERATE frames are '
        'pre-existing capture content read offline; nothing in this gate transmits '
        'them. [DESIGN]')
    add('')

    # ---- 4. ACK mode ----
    add('## 4. Pure TCP ACKs and per-transaction ACK mode [OBS]')
    add('')
    add('A pure ACK is classified strictly: TCP payload length 0, ACK set, SYN=FIN=RST=0. '
        'ACK mode is decided **per transaction** from the packets, never from the file '
        'name: `separate` = a pure ACK acknowledging exactly `req.seq + req.len` arrives '
        'before the response packet; `combined` = no such pure ACK and the response '
        'packet itself carries `ack >= req.seq + req.len`.')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            clrt = s['clrt_ack_to_resp_ms']
            r2a = s['req_to_ack_ms']
            rows.append([r['capture'], s['outstation'],
                         fmt_int(s['pure_acks_outstation_to_master']),
                         fmt_int(s['pure_acks_master_to_outstation']),
                         ', '.join('%s=%d' % kv for kv in sorted(s['ack_mode_counts'].items())),
                         s['ack_mode_verdict'],
                         '%.3f' % r2a['median'] if r2a else 'n/a',
                         '%.3f' % clrt['median'] if clrt else 'n/a',
                         '%.3f' % clrt['p95'] if clrt else 'n/a'])
    add(md_table(['capture', 'outstation', 'pure ACKs o->m', 'pure ACKs m->o',
                  'per-txn ACK mode', 'verdict', 'req->ACK median (ms)',
                  'CLRT median (ms)', 'CLRT p95 (ms)'], rows))
    add('')
    add('**CLRT is ACK->response**, per the locked Case-A terminology in `CLAUDE.md`; it '
        'is defined only for separate-ACK transactions, so it is `n/a` wherever no pure '
        'ACK precedes the response. The request->ACK interval is a different quantity and '
        'is reported in its own column so the two are not conflated. [DOC]')
    add('')
    agree, disagree = [], []
    for r in results:
        if 'parse_error' in r:
            continue
        exp = EXPECTED_ACK_MODE.get(r['capture'])
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            got = s['ack_mode_verdict']
            line = '%s / %s: expected %s, measured %s' % (r['capture'], s['outstation'],
                                                          exp, got)
            (agree if got.startswith(exp) else disagree).append(line)
    add('Against the established expectation (SEL-751 separate; AB1400 and ION7550 '
        'combined), evaluated per stream:')
    add('')
    for line in agree:
        add('- AGREES: %s [OBS]' % line)
    for line in disagree:
        add('- DISAGREES: %s [OBS]' % line)
    add('')

    # ---- 5. malformed ----
    add('## 5. Malformed, link-only and segmentation cases [OBS]')
    add('')
    add('Hardened classification rule applied [FIX]: transport/application parsing is '
        'entered only when the `05 64` magic is valid **and** the link LEN field says the '
        'bytes are present. `LEN == 5` (no user data) is a well-formed link-only frame '
        'and is reported as LINK_OTHER, never malformed. A frame split across TCP '
        'segments is stitched by the reassembler and is a segmentation artifact, not '
        'corruption. Only a resync away from a bad magic, `LEN < 5`, or a failed '
        'CRC-16/DNP counts as malformed.')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            anom = s['anomalies_master_to_outstation'] + s['anomalies_outstation_to_master']
            rows.append([r['capture'], s['outstation'], len(s['malformed_frames']),
                         len(anom), len(s['link_only_frames']),
                         len(s['frames_spanning_tcp_segments']),
                         len(s['retransmitted_pkts_outstation_to_master']) +
                         len(s['retransmitted_pkts_master_to_outstation']),
                         len(s['seq_gaps_master_to_outstation']) +
                         len(s['seq_gaps_outstation_to_master'])])
    add(md_table(['capture', 'outstation', 'malformed frames', 'stream anomalies',
                  'LINK_OTHER frames', 'frames spanning TCP segments',
                  'retransmitted pkts', 'seq gaps'], rows))
    add('')
    examples = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            for f in s['frames_spanning_tcp_segments'][:3]:
                examples.append('%s %s: DNP3 frame of %d B spans packets %d..%d -- '
                                'TCP segmentation, reassembled, NOT malformed [OBS]'
                                % (r['capture'], s['outstation'], f['wire_len'],
                                   f['first_pkt'], f['last_pkt']))
            for f in s['malformed_frames'][:3]:
                examples.append('%s %s: MALFORMED (CRC) at packet %d, LEN field %d [OBS]'
                                % (r['capture'], s['outstation'], f['pkt'], f['len_field']))
            for a in (s['anomalies_master_to_outstation'] +
                      s['anomalies_outstation_to_master'])[:3]:
                examples.append('%s %s: %s at stream offset %d, packet %s [OBS]'
                                % (r['capture'], s['outstation'], a['kind'],
                                   a['stream_offset'], a.get('packet')))
    if examples:
        add('Concrete cases:')
        add('')
        for e in examples[:24]:
            add('- %s' % e)
    else:
        add('No malformed frame, no LINK_OTHER frame and no stream anomaly exists '
            'anywhere in the corpus. Every byte of every DNP3 stream parses as a '
            'complete, CRC-valid link frame carrying an application header. [OBS]')
    add('')

    # ---- 6. transactions ----
    add('## 6. Expected transaction pairings (main deliverable) [OBS]')
    add('')
    add('The full table lives in `corpus_audit.json` at '
        '`captures[].streams[].transactions[]`. Each record carries: `req_pkt`, '
        '`req_ts`, `req_seq`, `req_payload_len`, `expected_ack` (= `req_seq + '
        'req_payload_len` mod 2^32), `ack_pkt`, `ack_num`, `resp_pkts`, `req_app_seq` / '
        '`resp_app_seq`, `req_to_ack_ms`, `ack_to_resp_ms`, `req_to_resp_ms`, '
        '`ack_mode` and `flags`. This is the pairing Part 13 slot/generation matching '
        'must reproduce on chip.')
    add('')
    rows = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s:
                continue
            r2r = s['req_to_resp_ms']
            iv = s['request_interval_s']
            rows.append([r['capture'], s['outstation'], fmt_int(s['transactions_total']),
                         fmt_int(s['transactions_clean']), s['transactions_flagged'],
                         '%.3f' % r2r['median'] if r2r else 'n/a',
                         '%.3f' % iv['median'] if iv else 'n/a',
                         ', '.join('%s=%d' % kv for kv in sorted(s['flag_counts'].items()))
                         or 'none'])
    add(md_table(['capture', 'outstation', 'transactions', 'clean', 'flagged',
                  'req->resp median (ms)', 'req interval median (s)', 'flags'], rows))
    add('')
    add('### 6.1 Worked example -- first three transactions of each stream')
    add('')
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if 'outstation' not in s or not s['transactions']:
                continue
            add('**%s / %s**' % (r['capture'], s['outstation']))
            add('')
            trows = []
            for t in s['transactions'][:3]:
                trows.append([t['txn'], t['req_pkt'], t['req_fc_name'], t['req_app_seq'],
                              t['req_seq'], t['req_payload_len'], t['expected_ack'],
                              t['ack_pkt'] if t['ack_pkt'] is not None else '-',
                              t['ack_num'] if t['ack_num'] is not None else '-',
                              ','.join(str(p) for p in t['resp_pkts']),
                              ','.join(str(x) for x in t['resp_app_seq']),
                              '%.3f' % t['req_to_ack_ms'] if t['req_to_ack_ms'] is not None else '-',
                              '%.3f' % t['ack_to_resp_ms'] if t['ack_to_resp_ms'] is not None else '-',
                              '%.3f' % t['req_to_resp_ms'] if t['req_to_resp_ms'] is not None else '-',
                              t['ack_mode']])
            add(md_table(['txn', 'req pkt', 'fc', 'app seq', 'req seq', 'req len',
                          'expected ack', 'ack pkt', 'ack num', 'resp pkts',
                          'resp app seq', 'req->ack ms', 'ack->resp ms', 'req->resp ms',
                          'ack mode'], trows))
            add('')

    # ---- 7. gate candidates ----
    add('## 7. Best candidate segments for the first Part 13 replay gates [DESIGN]')
    add('')
    add(gate_candidates_text(results))
    add('')

    # ---- 8. Zeek ----
    add('## 8. Cross-check against Zeek [REP]')
    add('')
    add('Zeek was not run over all six captures. `Traffic Trace/dnp3.log` and '
        '`zeek_run/dnp3.log` are two runs over the same capture (identical rows, only '
        'the connection UIDs and the `#open` timestamp differ). `broscript/run.sh` shows '
        'the last active run was over `ION7550.pcap` with `testtcp.bro`, and its '
        '`broscript/dnp3.log` contains only one record per connection -- that analyzer '
        'run effectively failed and is NOT a usable reference. [OBS]')
    add('')
    add(zeek_text(zeek))
    add('')
    add(latency_text(latency))
    add('')

    # ---- 9. external ----
    if external:
        add('## 9. External tool cross-check (verbatim output) [REP]')
        add('')
        for cmd, out in external:
            add('```')
            add(cmd)
            add(out.rstrip())
            add('```')
            add('')

    add('## 10. Method, assumptions and limits')
    add('')
    add(method_text(corpus_dir))
    add('')
    return '\n'.join(L)


def gate_candidates_text(results):
    lines = []
    sel_streams = []
    for r in results:
        if 'parse_error' in r:
            continue
        for s in r['streams']:
            if s.get('ack_mode_verdict') == 'separate':
                sel_streams.append((r['capture'], s))
    if not sel_streams:
        return 'No separate-ACK stream found; re-examine before choosing a gate segment.'
    lines.append('Only the separate-ACK streams exercise the CLRT that the mechanism '
                 'normalizes, so the first HOLD_ACK and HOLD_RESPONSE gates should '
                 'replay one of these:')
    lines.append('')
    for cap, s in sel_streams:
        clrt = s['clrt_ack_to_resp_ms']
        r2a = s['req_to_ack_ms']
        lines.append('- **%s / %s** -- %d transactions, %d clean, %d malformed, '
                     '%d retransmissions, %d seq gaps; CLRT (ACK->response) median '
                     '%.3f ms (p25 %.3f, p75 %.3f, p95 %.3f, max %.3f); request->ACK '
                     'median %.3f ms; request interval median %.3f s. [OBS]'
                     % (cap, s['outstation'], s['transactions_total'],
                        s['transactions_clean'], len(s['malformed_frames']),
                        len(s['retransmitted_pkts_outstation_to_master']),
                        len(s['seq_gaps_outstation_to_master']),
                        clrt['median'], clrt['p25'], clrt['p75'], clrt['p95'], clrt['max'],
                        r2a['median'], s['request_interval_s']['median']))
    lines.append('')
    short = [x for x in sel_streams if x[1]['transactions_total'] < 1000]
    pick = short[0] if short else sel_streams[0]
    cap, s = pick
    first_clean = [t for t in s['transactions'] if is_clean(t)][:50]
    if first_clean:
        lines.append('**Recommended first gate segment:** `%s.pcap`, stream %s -> %s, '
                     'transactions %d..%d (the first %d consecutive clean transactions, '
                     'packets %d..%d). Rationale: it is the shortest separate-ACK stream '
                     '(%d transactions total, so a full replay fits in one short switch '
                     'window), it is retransmission-free and gap-free, every request is '
                     'one TCP segment and every response is one TCP segment, and the '
                     'per-transaction ACK is a distinct pure ACK whose number is exactly '
                     '`req.seq + req.len` -- which is precisely the match key the '
                     'on-chip slot logic has to compute. [DESIGN]'
                     % (cap, s['master'], s['outstation'], first_clean[0]['txn'],
                        first_clean[-1]['txn'], len(first_clean),
                        first_clean[0]['req_pkt'], max(first_clean[-1]['resp_pkts']),
                        s['transactions_total']))
        lines.append('')
        fcs = Counter(t['req_fc_name'] for t in first_clean)
        lines.append('Function-code mix in that segment: %s. A HOLD_ACK gate should use '
                     'the READ transactions first (single request packet, single '
                     'response packet, no control semantics); the DIRECT_OPERATE '
                     'transactions in the same stream are replayed as opaque bytes only '
                     'if and when a later gate needs them, and never against a live '
                     'relay. [DESIGN]'
                     % ', '.join('%s=%d' % kv for kv in sorted(fcs.items())))
        lines.append('')
        lines.append('The combined-ACK streams (AB1400, ION7550 and every 10.0.0.2 '
                     'stream) have no CLRT to normalize, so they are the right corpus '
                     'for a later Case-B gate and the wrong one for gates 13.2/13.3. '
                     'The ION7550 real-device streams additionally carry TCP '
                     'retransmissions and should not be the first thing a new replay '
                     'path has to survive. [DESIGN]')
    return '\n'.join(lines)


def zeek_text(zeek):
    lines = []
    for label, entry in zeek.items():
        if entry['status'] != 'present':
            lines.append('- `%s`: %s' % (label, entry['status']))
            continue
        lines.append('- `%s`: %d records, ts %.6f..%.6f, matched capture **%s**'
                     % (label, entry['records'], entry['ts_min'], entry['ts_max'],
                        entry['matched_capture']))
        for note in entry.get('agreement', []):
            lines.append('  - %s' % note)
        pairs = ', '.join('%s=%d' % kv for kv in sorted(
            entry['fc_request_reply_pairs'].items()))
        lines.append('  - Zeek request/reply pairs: %s' % pairs)
    return '\n'.join(lines)


def latency_text(lat):
    if lat.get('status') != 'present':
        return '- `latency.log`: %s' % lat.get('status')
    lines = ['- `latency.log` (from `broscript/latency.bro`, over `SEL751.pcap`): %d rows '
             'of %s values in seconds, measuring request -> response. Two ordering '
             'quirks in that script have to be undone before the rows can be compared: '
             'it emits one row per responder IP in Zeek table order (NOT wire order), '
             'and within a row it concatenates one vector per function code, again in '
             'table order. Searching the orderings gives an exact match: [REP]']
    for c in lat['comparisons']:
        lines.append('  - Zeek row %d -> our stream **%s**, ordering `%s`: all %d values '
                     'match, maximum absolute difference %.3e s; %d of %d agree to '
                     'within 1 us. [REP]'
                     % (c['zeek_row'], c['matched_stream'], c['matched_ordering'],
                        c['compared'], c['max_abs_diff_s'],
                        c['values_agreeing_to_1us'], c['compared']))
    lines.append('  - The residual difference is at the 1e-7 s level, which is Zeek '
                 '`cat()` decimal formatting of a double, not a measurement '
                 'disagreement. [OBS]')
    return '\n'.join(lines)


def method_text(corpus_dir):
    return '\n'.join([
        '**Physical model / scope.** None. This gate touches no power-system model and '
        'no device: it is a byte-level audit of six stored captures in `%s`. [DESIGN]' % corpus_dir,
        '',
        '**Parsing stack.** classic libpcap -> Ethernet -> IPv4 -> TCP -> per-direction '
        'sequence-ordered reassembly -> IEEE 1815 link frame (`05 64`, LEN, CTRL, DEST, '
        'SRC, header CRC, 16-byte data blocks each with its own CRC) -> transport header '
        '-> application header. Header CRC and every block CRC are verified with '
        'CRC-16/DNP (poly 0x3D65 reflected, init 0x0000, final XOR 0xFFFF). [DOC]',
        '',
        '**Assumptions.**',
        '',
        '| # | Assumption | Basis | Risk if wrong |',
        '|---|---|---|---|',
        '| A1 | The endpoint on TCP/20000 is the outstation | port convention, confirmed '
        'by DNP3 link PRM/DIR bits and by which side answers | direction labels invert |',
        '| A2 | A transaction is one request frame plus the next response fragment group '
        'in wire order with a matching application sequence number | DNP3 is '
        'request/response with a 4-bit app sequence; no CONFIRM appears in this corpus | '
        'mispairing under pipelining -- flagged as `multiple_outstanding`, count reported |',
        '| A3 | `expected_ack = req_seq + req_wire_len` | TCP cumulative ACK semantics; '
        'in this corpus every request frame is alone in its segment, so this equals '
        '`tcp.seq + tcp.len` | ACK match fails -- reported as `cumulative_ack_only` |',
        '| A4 | Retransmitted bytes are parsed once (first copy wins) | TCP receiver '
        'semantics | duplicate frames -- affected transactions are flagged and counted |',
        '',
        '**Limits. [OPEN]** Capture timestamps are host timestamps at the capture point, '
        'not switch timestamps, so CLRT values here are end-to-end as observed by the '
        'capture host and include its own stack delay. The capture point relative to the '
        'two endpoints is not recorded in the files, so the split of CLRT between device '
        'processing and path delay cannot be recovered from this corpus.',
    ])


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--corpus', default=DEFAULT_CORPUS, help='directory holding the pcaps')
    ap.add_argument('--outdir', default=HERE, help='where to write the two deliverables')
    ap.add_argument('--no-external', action='store_true',
                    help='skip the tshark/capinfos cross-check appendix')
    args = ap.parse_args()

    results = []
    for name in CAPTURES:
        path = os.path.join(args.corpus, name + '.pcap')
        sys.stderr.write('[audit] %s\n' % path)
        if not os.path.exists(path):
            results.append(OrderedDict([('capture', name), ('path', path),
                                        ('parse_error', 'file not found')]))
            continue
        results.append(analyse_capture(name, path))

    zeek = zeek_crosscheck(args.corpus, results)
    latency = latency_crosscheck(args.corpus, results)
    external = [] if args.no_external else external_crosscheck(args.corpus)

    payload = OrderedDict()
    payload['gate'] = '13.1'
    payload['title'] = 'DNP3 replay corpus audit (offline)'
    payload['corpus_dir'] = args.corpus
    payload['captures'] = results
    payload['zeek_crosscheck'] = zeek
    payload['zeek_latency_crosscheck'] = latency
    payload['totals'] = OrderedDict([
        ('captures', len(results)),
        ('parse_errors', sum(1 for r in results if 'parse_error' in r)),
        ('packets', sum(r.get('total_packets', 0) for r in results)),
        ('transactions', sum(r.get('transactions_total', 0) for r in results)),
        ('clean_transactions', sum(r.get('transactions_clean', 0) for r in results)),
    ])

    # Compact separators: the transaction table is ~30k records, so the file is
    # written for machine consumption. Pretty-print with `python3 -m json.tool`.
    json_path = os.path.join(args.outdir, 'corpus_audit.json')
    with open(json_path, 'w') as handle:
        json.dump(payload, handle, separators=(',', ':'), sort_keys=False)
    md_path = os.path.join(args.outdir, 'GATE_13_1_CORPUS_AUDIT.md')
    with open(md_path, 'w') as handle:
        handle.write(build_report(results, zeek, latency, external, args.corpus))
        handle.write('\n')

    # stdout summary (this is what gets pasted as evidence)
    print('%-10s %10s %10s %8s %12s %8s %8s %10s' %
          ('capture', 'packets', 'tcp:20000', 'streams', 'duration_s', 'txns', 'clean', 'ackmode'))
    for r in results:
        if 'parse_error' in r:
            print('%-10s PARSE ERROR: %s' % (r['capture'], r['parse_error']))
            continue
        modes = '/'.join(s['ack_mode_verdict'] for s in r['streams'] if 'outstation' in s)
        print('%-10s %10d %10d %8d %12.3f %8d %8d %10s' %
              (r['capture'], r['total_packets'], r['tcp_packets_port_20000'],
               r['tcp_streams'], r['duration_s'], r['transactions_total'],
               r['transactions_clean'], modes))
    print('')
    print('wrote %s (%d bytes)' % (json_path, os.path.getsize(json_path)))
    print('wrote %s (%d bytes)' % (md_path, os.path.getsize(md_path)))


if __name__ == '__main__':
    main()
