#!/usr/bin/env python3
"""
Independent DNP3 analyzer for a multi-CROB Select-Before-Operate capture.

Given a PCAP/PCAPNG file and the expected CROB count N, this reassembles the TCP
byte streams, parses the DNP3 link/transport/application layers from raw bytes
(validating the link-header CRC and every data-block CRC via ``dnp3_crc``), finds
the G12V1 SELECT, SELECT response, OPERATE, and OPERATE response, and verifies:

  * Group 12, Variation 1, qualifier 0x28, Count == N in SELECT and OPERATE;
  * N distinct CROB indexes;
  * identical SELECT and OPERATE CROB lists (index + control code);
  * N success (0x00) statuses in both responses.

It emits one JSON pass/fail report that includes, for the SELECT and OPERATE, the
logical (application) fragment count and the DNP3 data-link frame count -- so a
transaction that spans several link frames is still recognised as one logical SBO.
TCP packet count is never used as a correctness metric.

Reads packets with scapy (handles pcapng); no tshark dependency.
"""
import argparse
import json
import logging
import os
import sys

# Silence scapy's import-time IPv6 route warning (harmless here; we only read files).
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)

import lab_config as cfg
from dnp3_crc import verify_crc

_log = logging.getLogger(__name__)

LINK_START = b'\x05\x64'
FUNC_SELECT = 0x03
FUNC_OPERATE = 0x04
FUNC_RESPONSE = 0x81
GROUP_CROB, VAR_CROB = 12, 1
QUALIFIER_2OCTET_INDEX_2OCTET_COUNT = 0x28
CONTROL_CODE_NAMES = {0x03: 'LATCH_ON', 0x04: 'LATCH_OFF'}

# DNP3 CommandStatus values we care about for the boundary-index experiment. Only
# these are named; any other non-zero status is reported verbatim as UNKNOWN_0xNN
# (do not invent mappings).
STATUS_NAMES = {0: 'SUCCESS', 2: 'NO_SELECT', 4: 'NOT_SUPPORTED',
                8: 'TOO_MANY_OPS', 12: 'OUT_OF_RANGE'}
STATUS_TOO_MANY_OPS = 8


def status_name(status):
    """Name a DNP3 CommandStatus; unknown non-zero values become UNKNOWN_0xNN."""
    return STATUS_NAMES.get(status, 'UNKNOWN_0x%02X' % status)


# --------------------------------------------------------------------------- #
# TCP reassembly (scapy only extracts ordered payload bytes per direction)
# --------------------------------------------------------------------------- #
MAX_GAP = 1 << 20  # guard: never zero-fill more than 1 MiB within one connection


def read_streams(pcap_path, outstation_port):
    """Return (request_bytes, response_bytes): master->outstation and outstation->master.

    Segments are grouped per TCP connection (4-tuple) and reassembled with that
    connection's own ISN, so multiple connections to the outstation port (channel
    retry/reconnect) never collapse into one sequence space. Each direction's
    per-connection streams are then concatenated (the DNP3 frame parser resyncs on
    the 0x0564 start bytes across a connection boundary).
    """
    from scapy.all import rdpcap
    from scapy.layers.inet import TCP
    packets = rdpcap(pcap_path)
    # (src,sport,dst,dport) -> list of (seq, payload)
    conns = {}
    order = []
    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            continue
        src = pkt.src if hasattr(pkt, 'src') else ''
        dst = pkt.dst if hasattr(pkt, 'dst') else ''
        key = (src, int(tcp.sport), dst, int(tcp.dport))
        if key not in conns:
            conns[key] = []
            order.append(key)
        conns[key].append((int(tcp.seq), payload))

    def reassemble(seglist):
        if not seglist:
            return b''
        base = min(s for s, _ in seglist)
        buf = bytearray()
        for seq, payload in sorted(seglist, key=lambda x: x[0]):
            off = seq - base
            if off < 0 or off - len(buf) > MAX_GAP:
                continue  # pre-base retransmit, or an implausible gap (different flow)
            if off > len(buf):
                buf.extend(b'\x00' * (off - len(buf)))
            end = off + len(payload)
            if end <= len(buf):
                continue  # pure retransmit already covered
            buf[off:end] = payload
        return bytes(buf)

    req, resp = bytearray(), bytearray()
    for key in order:
        (_src, sport, _dst, dport) = key
        stream = reassemble(conns[key])
        if dport == outstation_port:
            req.extend(stream)
        elif sport == outstation_port:
            resp.extend(stream)
    return bytes(req), bytes(resp)


# --------------------------------------------------------------------------- #
# DNP3 link layer -> transport segments (with CRC validation)
# --------------------------------------------------------------------------- #
class CrcError(Exception):
    pass


def parse_link_frames(stream):
    """Yield dict(transport_payload, header_crc_ok, blocks_crc_ok) for each link frame."""
    i = 0
    n = len(stream)
    while True:
        j = stream.find(LINK_START, i)
        if j < 0 or j + 10 > n:
            return
        header = stream[j:j + 8]
        header_crc = stream[j + 8:j + 10]
        header_crc_ok = verify_crc(header, header_crc)
        length = stream[j + 2]                    # CTRL..end-of-userdata octet count
        user_len = length - 5
        if user_len < 0:
            i = j + 2
            continue
        pos = j + 10
        data = bytearray()
        blocks_ok = True
        remaining = user_len
        while remaining > 0:
            blk_len = min(16, remaining)
            block = stream[pos:pos + blk_len]
            crc = stream[pos + blk_len:pos + blk_len + 2]
            if len(block) < blk_len or len(crc) < 2:
                blocks_ok = False
                break
            if not verify_crc(bytes(block), crc):
                blocks_ok = False
            data.extend(block)
            pos += blk_len + 2
            remaining -= blk_len
        yield {'transport_payload': bytes(data),
               'header_crc_ok': header_crc_ok,
               'blocks_crc_ok': blocks_ok,
               'dest': int.from_bytes(stream[j + 4:j + 6], 'little'),
               'src': int.from_bytes(stream[j + 6:j + 8], 'little')}
        i = pos


def reassemble_app_fragments(frames):
    """Reassemble transport segments (FIR/FIN) into application fragments.

    Returns list of dict(app_bytes, link_frame_count, all_crc_ok). Each frame's
    transport payload begins with a 1-byte transport header (FIN/FIR/SEQ).
    """
    fragments = []
    cur = bytearray()
    cur_frames = 0
    cur_crc_ok = True
    started = False
    for fr in frames:
        tp = fr['transport_payload']
        if not tp:
            continue
        th = tp[0]
        fir = bool(th & 0x40)
        fin = bool(th & 0x80)
        app_chunk = tp[1:]
        if fir:
            cur = bytearray(app_chunk)
            cur_frames = 1
            cur_crc_ok = fr['header_crc_ok'] and fr['blocks_crc_ok']
            started = True
        elif started:
            cur.extend(app_chunk)
            cur_frames += 1
            cur_crc_ok = cur_crc_ok and fr['header_crc_ok'] and fr['blocks_crc_ok']
        else:
            continue  # continuation without a FIR start; ignore
        if fin and started:
            fragments.append({'app_bytes': bytes(cur), 'link_frame_count': cur_frames,
                              'all_crc_ok': cur_crc_ok})
            started = False
    return fragments


# --------------------------------------------------------------------------- #
# DNP3 application layer -> G12V1 CROB list
# --------------------------------------------------------------------------- #
def parse_app_header(app_bytes):
    """Return (func_code, app_seq, objects_offset). Responses carry a 2-byte IIN."""
    if len(app_bytes) < 2:
        return None, None, None
    app_ctrl = app_bytes[0]
    func = app_bytes[1]
    app_seq = app_ctrl & 0x0F
    offset = 2
    if func == FUNC_RESPONSE:
        offset += 2  # IIN
    return func, app_seq, offset


def parse_g12v1(app_bytes, offset):
    """Parse a G12V1 object block at ``offset``.

    Returns dict(qualifier, count, items=[(index, control_code, status)]) or None if
    the object header at offset is not Group 12 Var 1.
    """
    b = app_bytes
    if offset + 3 > len(b):
        return None
    group, var, qualifier = b[offset], b[offset + 1], b[offset + 2]
    if group != GROUP_CROB or var != VAR_CROB:
        return None
    pos = offset + 3
    if qualifier != QUALIFIER_2OCTET_INDEX_2OCTET_COUNT:
        # Still report what we saw; caller flags the qualifier mismatch.
        return {'group': group, 'variation': var, 'qualifier': qualifier,
                'count': None, 'items': []}
    count = int.from_bytes(b[pos:pos + 2], 'little')
    pos += 2
    items = []
    for _ in range(count):
        if pos + 2 + 11 > len(b):
            break
        index = int.from_bytes(b[pos:pos + 2], 'little')
        pos += 2
        control_code = b[pos]
        status = b[pos + 10]      # last byte of the 11-byte G12V1 body
        pos += 11
        items.append((index, control_code, status))
    return {'group': group, 'variation': var, 'qualifier': qualifier,
            'count': count, 'items': items}


def find_croby_fragments(stream, outstation_port_side):
    """Parse a byte stream into app fragments and attach any G12V1 parse."""
    frames = list(parse_link_frames(stream))
    frags = reassemble_app_fragments(frames)
    out = []
    for fr in frags:
        func, app_seq, off = parse_app_header(fr['app_bytes'])
        crob = parse_g12v1(fr['app_bytes'], off) if off is not None else None
        out.append({'func': func, 'app_seq': app_seq, 'crob': crob,
                    'link_frame_count': fr['link_frame_count'], 'all_crc_ok': fr['all_crc_ok'],
                    'app_len': len(fr['app_bytes'])})
    return out


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _locate_transaction(pcap_path, outstation_port):
    """Find the G12V1 SELECT/OPERATE requests and their responses in a capture.

    Returns (select, operate, select_resp, operate_resp); any element may be None.
    Responses are paired to requests by the echoed application sequence (robust to
    order), falling back to arrival order when the sequence is unavailable.
    """
    req_stream, resp_stream = read_streams(pcap_path, outstation_port)
    req_frags = find_croby_fragments(req_stream, outstation_port)
    resp_frags = find_croby_fragments(resp_stream, outstation_port)

    select = next((f for f in req_frags if f['func'] == FUNC_SELECT and f['crob']), None)
    operate = next((f for f in req_frags if f['func'] == FUNC_OPERATE and f['crob']), None)
    resp_croby = [f for f in resp_frags if f['func'] == FUNC_RESPONSE and f['crob'] and f['crob']['items']]

    def match_resp(req_frag, used):
        if req_frag is None:
            return None
        return next((f for f in resp_croby if f is not used and f['app_seq'] == req_frag['app_seq']), None)
    select_resp = match_resp(select, None)
    operate_resp = match_resp(operate, select_resp)
    remaining = [f for f in resp_croby if f not in (select_resp, operate_resp)]
    if select_resp is None and remaining:
        select_resp = remaining.pop(0)
    if operate_resp is None and remaining:
        operate_resp = remaining.pop(0)
    return select, operate, select_resp, operate_resp


def analyze(pcap_path, expected_n, outstation_port):
    select, operate, select_resp, operate_resp = _locate_transaction(pcap_path, outstation_port)

    failures = []

    def croby_list(frag):
        return [(i, c) for (i, c, _s) in frag['crob']['items']] if frag and frag['crob'] else []

    sel_items = croby_list(select)
    op_items = croby_list(operate)

    def check(cond, msg):
        if not cond:
            failures.append(msg)
        return cond

    check(select is not None, 'SELECT (G12V1) not found in request stream')
    check(operate is not None, 'OPERATE (G12V1) not found in request stream')
    check(select_resp is not None, 'SELECT response (G12V1) not found in response stream')
    check(operate_resp is not None, 'OPERATE response (G12V1) not found in response stream')

    for name, frag in (('SELECT', select), ('OPERATE', operate)):
        if frag and frag['crob']:
            c = frag['crob']
            check(c['group'] == GROUP_CROB and c['variation'] == VAR_CROB,
                  '%s object is not Group 12 Var 1' % name)
            check(c['qualifier'] == QUALIFIER_2OCTET_INDEX_2OCTET_COUNT,
                  '%s qualifier is 0x%02x, expected 0x28' % (name, c['qualifier']))
            check(c['count'] == expected_n,
                  '%s Count=%s, expected %s' % (name, c['count'], expected_n))
            check(len(c['items']) == expected_n,
                  '%s parsed %s items, expected %s' % (name, len(c['items']), expected_n))

    if sel_items:
        indexes = [i for i, _ in sel_items]
        check(len(set(indexes)) == len(indexes) == expected_n,
              'SELECT indexes not %s distinct: %s' % (expected_n, indexes))
    check(sel_items == op_items and bool(sel_items),
          'SELECT and OPERATE CROB lists differ')

    for name, frag in (('SELECT response', select_resp), ('OPERATE response', operate_resp)):
        if frag and frag['crob']:
            statuses = [s for (_i, _c, s) in frag['crob']['items']]
            check(len(statuses) == expected_n and all(s == 0 for s in statuses),
                  '%s does not carry %s success (0x00) statuses: %s' % (name, expected_n, statuses))

    present = [f for f in (select, operate, select_resp, operate_resp) if f]
    all_crc_ok = bool(present) and all(f['all_crc_ok'] for f in present)
    check(all_crc_ok, 'one or more link/data-block CRCs failed to validate')

    report = {
        'pcap': os.path.basename(pcap_path),
        'expected_n': expected_n,
        'outstation_port': outstation_port,
        'pass': not failures,
        'select': _frag_report(select),
        'operate': _frag_report(operate),
        'select_response': _frag_report(select_resp),
        'operate_response': _frag_report(operate_resp),
        'select_operate_identical': sel_items == op_items and bool(sel_items),
        'distinct_indexes': bool(sel_items) and len(set(i for i, _ in sel_items)) == len(sel_items),
        'all_crc_valid': all_crc_ok,
        'failures': failures,
    }
    return report


def _frag_report(frag):
    if not frag:
        return None
    c = frag['crob'] or {}
    items = c.get('items', [])
    return {
        'func': frag['func'],
        'app_seq': frag['app_seq'],
        'data_link_frames': frag['link_frame_count'],   # link frames making up this message
        'logical_fragments': 1,                          # one reassembled application fragment
        'app_byte_length': frag.get('app_len'),          # application-fragment byte length
        'qualifier': ('0x%02x' % c['qualifier']) if c.get('qualifier') is not None else None,
        'count': c.get('count'),
        'indexes': [i for (i, _c, _s) in items],
        'codes': [CONTROL_CODE_NAMES.get(cc, '0x%02x' % cc) for (_i, cc, _s) in items],
        'statuses': [s for (_i, _c, s) in items],
        'crc_valid': frag['all_crc_ok'],
    }


def analyze_boundary_index(pcap_path, expected_n, configured_points, outstation_port,
                           expect_operate='either'):
    """Characterise a K-valid-points / N-CROB SBO where N may exceed K.

    Reads the SELECT response's per-index CommandStatus values from the wire and
    reports them as observed -- it does NOT assume any particular status for an
    invalid index. It classifies by the OBSERVED first non-success status, so a
    per-request operation-count limit (TOO_MANY_OPS) is told apart from a
    nonexistent-output-index rejection (OUT_OF_RANGE) from the bytes, not from a
    prior expectation. A test is never failed merely because the returned status is
    not OUT_OF_RANGE. Does NOT require an OPERATE (a partial SELECT failure may
    suppress it); ``expect_operate`` may enforce 'absent'/'present', default 'either'
    leaves it unconstrained.
    """
    select, operate, select_resp, operate_resp = _locate_transaction(pcap_path, outstation_port)
    failures = []
    notes = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)
        return cond

    check(select is not None, 'SELECT (G12V1) not found in request stream')
    check(select_resp is not None, 'SELECT response (G12V1) not found in response stream')

    # SELECT request shape. Indexes may be in ANY transmitted order and may include
    # nonexistent indexes (>= K) -- do NOT assume 0..N-1 (that only holds for the
    # generated --crob-count path; --crob-plan places invalid indexes anywhere).
    sel_indexes = []
    sel_crob = select['crob'] if select else None
    if sel_crob:
        check(sel_crob['group'] == GROUP_CROB and sel_crob['variation'] == VAR_CROB,
              'SELECT object is not Group 12 Var 1')
        check(sel_crob['qualifier'] == QUALIFIER_2OCTET_INDEX_2OCTET_COUNT,
              'SELECT qualifier is 0x%02x, expected 0x28' % sel_crob['qualifier'])
        check(sel_crob['count'] == expected_n,
              'SELECT Count=%s, expected %s' % (sel_crob['count'], expected_n))
        sel_indexes = [i for (i, _c, _s) in sel_crob['items']]
        check(len(set(sel_indexes)) == len(sel_indexes),
              'SELECT indexes not distinct: %s' % sel_indexes)

    # Requested indexes that do not exist on the outstation (supported set is 0..K-1).
    invalid_indexes_in_select = [i for i in sel_indexes if i < 0 or i >= configured_points]

    # SELECT response: per-index CommandStatus values are the correctness evidence.
    statuses, status_names = [], []
    select_statuses_by_index = {}
    rejected_indexes = []
    status_counts = {}
    first_rejected_index = first_rejected_status = first_rejected_status_name = None
    if select_resp and select_resp['crob']:
        items = select_resp['crob']['items']
        statuses = [s for (_i, _c, s) in items]
        status_names = [status_name(s) for s in statuses]
        select_statuses_by_index = {str(i): s for (i, _c, s) in items}
        rejected_indexes = [i for (i, _c, s) in items if s != 0]
        for nm in status_names:
            status_counts[nm] = status_counts.get(nm, 0) + 1
        for (idx, _c, st) in items:
            if st != 0:
                first_rejected_index, first_rejected_status = idx, st
                first_rejected_status_name = status_name(st)
                break
        if len(statuses) != expected_n:
            notes.append('SELECT response carried %d statuses, expected %d '
                         '(possible whole-request rejection or early stop)' % (len(statuses), expected_n))

    too_many_ops_present = STATUS_TOO_MANY_OPS in statuses
    if too_many_ops_present and first_rejected_status != STATUS_TOO_MANY_OPS:
        notes.append('TOO_MANY_OPS also present in the SELECT response '
                     '(operation-count limit reached alongside invalid-index rejections)')

    operate_sent = operate is not None
    operate_response_seen = operate_resp is not None

    present = [f for f in (select, operate, select_resp, operate_resp) if f]
    all_crc_ok = bool(present) and all(f['all_crc_ok'] for f in present)
    check(all_crc_ok, 'one or more link/data-block CRCs failed to validate')

    # Classification. Precedence: parse/CRC -> all-success -> count-limit-first
    # (first rejection is TOO_MANY_OPS) -> decoy-only (every requested index invalid,
    # all rejected) -> multiple invalid rejected -> single invalid rejected.
    n_rejected = len(rejected_indexes)
    all_invalid_and_rejected = (bool(sel_indexes)
                                and len(invalid_indexes_in_select) == len(sel_indexes)
                                and n_rejected >= 1
                                and set(rejected_indexes) == set(sel_indexes))
    invalid_op = ('invalid_index_rejected_during_select_operate_still_sent' if operate_sent
                  else 'invalid_index_rejected_during_select_no_operate')

    if not select or not select_resp or not all_crc_ok:
        failure_stage, classification = 'parse', 'parser_or_crc_failure'
    elif not statuses:
        failure_stage, classification = 'select', 'unexpected_behavior'
    elif first_rejected_status is None:
        failure_stage, classification = 'none', 'all_success'
    elif first_rejected_status == STATUS_TOO_MANY_OPS:
        failure_stage, classification = 'select', 'too_many_ops_during_select'
    elif all_invalid_and_rejected:
        failure_stage, classification = 'select', 'decoy_only_invalid_rejected'
    elif n_rejected >= 2:
        failure_stage, classification = 'select', 'multiple_invalid_indexes_rejected'
    elif n_rejected == 1:
        failure_stage, classification = 'select', invalid_op
    else:
        failure_stage, classification = 'unknown', 'unexpected_behavior'

    if expect_operate == 'absent':
        check(not operate_sent, 'OPERATE was sent but --expect-operate absent')
    elif expect_operate == 'present':
        check(operate_sent, 'OPERATE expected (--expect-operate present) but not sent')

    clear = classification in ('all_success',
                               'invalid_index_rejected_during_select_no_operate',
                               'invalid_index_rejected_during_select_operate_still_sent',
                               'too_many_ops_during_select',
                               'multiple_invalid_indexes_rejected',
                               'decoy_only_invalid_rejected')
    passed = bool(select) and bool(select_resp) and all_crc_ok and clear and not failures

    sel_report = _frag_report(select)
    sel_resp_report = None
    if select_resp:
        sel_resp_report = dict(_frag_report(select_resp) or {})
        sel_resp_report.update({
            'statuses': statuses,
            'status_names': status_names,
            'first_rejected_index': first_rejected_index,
            'first_rejected_status': first_rejected_status,
            'first_rejected_status_name': first_rejected_status_name,
        })

    return {
        'pcap': os.path.basename(pcap_path),
        'mode': 'boundary-index',
        'configured_points': configured_points,
        'expected_n': expected_n,
        'pass': passed,
        'classification': classification,
        'failure_stage': failure_stage,
        'select': sel_report,
        'select_response': sel_resp_report,
        'select_statuses_by_index': select_statuses_by_index,
        # Observe-and-report aliases: the returned CommandStatus is read from the wire
        # and reported verbatim; it is never assumed. 'observed_status_by_index' names
        # each per-index status; 'first_non_success_status' is the first non-zero one.
        'observed_status_by_index': {idx: status_name(st)
                                     for idx, st in select_statuses_by_index.items()},
        'first_non_success_status': first_rejected_status_name,
        'first_non_success_index': first_rejected_index,
        'status_counts': status_counts,
        'invalid_indexes_in_select': invalid_indexes_in_select,
        'rejected_indexes': rejected_indexes,
        'first_rejected_index': first_rejected_index,
        'first_rejected_status': first_rejected_status,
        'first_rejected_status_name': first_rejected_status_name,
        'select_request_byte_length': (sel_report or {}).get('app_byte_length'),
        'select_response_byte_length': (sel_resp_report or {}).get('app_byte_length'),
        'select_data_link_frames': (sel_report or {}).get('data_link_frames'),
        'select_response_data_link_frames': (sel_resp_report or {}).get('data_link_frames'),
        'operate_sent': operate_sent,
        'operate_response_seen': operate_response_seen,
        'all_crc_valid': all_crc_ok,
        'notes': notes,
        'failures': failures,
    }


def build_parser():
    p = argparse.ArgumentParser(description='Independent DNP3 analyzer for a multi-CROB SBO capture.')
    p.add_argument('--pcap', required=True, help='PCAP/PCAPNG capture of one multi-CROB SBO run.')
    p.add_argument('--expected-n', type=int, required=True, help='Expected CROB count N.')
    p.add_argument('--mode', choices=['all-success', 'boundary-index'], default='all-success',
                   help='all-success (default): every CROB must succeed. boundary-index: '
                        'characterise how a nonexistent/over-limit index is rejected.')
    p.add_argument('--configured-points', type=int, default=None,
                   help='K = valid simulated output points on the outstation. '
                        'Required for --mode boundary-index.')
    p.add_argument('--expect-operate', choices=['absent', 'present', 'either'], default='either',
                   help='boundary-index only: require OPERATE to be absent/present, or leave '
                        'unconstrained (default either).')
    p.add_argument('--port', type=int, default=cfg.DNP3_PORT, help='Outstation TCP port.')
    p.add_argument('--json', default=None, help='Write the JSON report to this path (also prints it).')
    return p


def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    parser = build_parser()
    args = parser.parse_args()
    if args.mode == 'boundary-index' and args.configured_points is None:
        parser.error('--configured-points K is required for --mode boundary-index')
    try:
        if args.mode == 'boundary-index':
            report = analyze_boundary_index(args.pcap, args.expected_n, args.configured_points,
                                            args.port, args.expect_operate)
        else:
            report = analyze(args.pcap, args.expected_n, args.port)
    except Exception as exc:  # parsing/read errors are a failed analysis, not a crash
        report = {'pcap': os.path.basename(args.pcap), 'expected_n': args.expected_n,
                  'mode': args.mode, 'pass': False, 'failures': ['analyzer error: %r' % exc]}
    text = json.dumps(report, indent=2)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, 'w') as fh:
            fh.write(text + '\n')
    print(text)
    return 0 if report.get('pass') else 1


if __name__ == '__main__':
    sys.exit(main())
