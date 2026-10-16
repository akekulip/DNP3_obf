#!/usr/bin/env python3
"""Plan, build and judge a software-tuple ACK/response packet-pair contention probe (offline only).

Goal (directive 2026-10-16): cause N's single work-cell contention on silicon by injecting, from one
raw socket, both the master side and the outstation side of a configured protected connection, with the
outstation's standalone ACK and its native response spaced a few microseconds apart -- the scale of N's
lap on the ASIC -- so the response finds the cell still held and N retries the lap (count_busy[2]),
delivers once through T's committed path, and busy-drops nothing (count_busy[0]/[3]).

This module is pure stdlib and does no I/O to any host. It builds the exact frames (handshake, READ /
SELECT / OPERATE-after-SELECT request+ACK+response pairs, a duplicate response, and a noncontended
control with large spacing), emits the injection schedule, and judges a completed run from its two
direction captures plus the before/after N counter snapshots. `vision_contention.py` is the Vision-side
injector/capture that executes a plan; it is never run from here.

The independent variable is the ACK->response spacing MEASURED in the capture (in nanoseconds, at the host
transmit hook), not the sleep the injector requested. The padded image the master sees is produced by the
switch; the judge reads it from the capture and compares it to the matching noncontended control, so no
padded length is invented here.

The judge returns one of four verdicts, and their limits are stated on `judge`:
  INVALID  the run cannot be judged -- a missing/short counter or outcome snapshot, a point with no measured
           spacing, or an empty egress capture. INVALID is neither PASS nor PENDING.
  FAIL     a measured defect (busy drop, exhaustion, stale retry, aborted duplicate, a control not delivered
           exactly once, a wrong image, a duplicate reaching the master, a master-side ordering violation, a
           T outcome disagreeing with the delivered points, or an untimed escape outside delay tolerance).
  PENDING  no defect but no retry lap induced; silicon retry coverage stays open.
  PASS     a retry lap was induced and nothing failed.
Limits: all times are host-hook timestamps, not switch ingress; the N/T counters are run-wide, so a retry
lap is attributable to the contended points only when controls ran in a separate snapshot interval.
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBRARY = HERE if (HERE / 'wire_check.py').is_file() else HERE.parents[3] / 'protocol' / 'hw_vepa'
sys.path.insert(0, str(LIBRARY))
import wire_check as wc  # noqa: E402  (dnp3_crc, _sum16, flag constants, pcap reader/parser)

FIN, SYN, RST, PSH, ACK = wc.FIN, wc.SYN, wc.RST, wc.PSH, wc.ACK
MASK = 0xffffffff

# DNP3 link headers exactly as seg61_02/model_repeat.py uses them (build_frame rewrites LEN and every CRC).
READ_REQ_HEAD = bytes.fromhex('05640bc400000100')
CTL_REQ_HEAD = bytes.fromhex('05641ac40a000100')
READ_RSP_HEAD = bytes.fromhex('0564004401000000')
CTL_RSP_HEAD = bytes.fromhex('05641c4401000a00')
READ_OBJECTS = bytes.fromhex('0a02000016')
READ_BODY = bytes((0x80, 0x00)) + READ_OBJECTS + bytes(range(23))

# Proposed ACK->response spacings. Small values target one or two N laps (~1 us each on silicon); the
# control is far larger than the cell hold so its response never contends. Judge uses the measured value.
CONTENDED_SPACING_US = (0, 1, 2, 3, 5)
CONTROL_SPACING_US = 60_000


def crob(on_ms):
    return bytes.fromhex('0c012801000100') + bytes((0x01, 0x01)) + on_ms.to_bytes(4, 'little') + \
        (100).to_bytes(4, 'little') + b'\x00'


def dnp3_frame(head, user):
    """One bounded DNP3 link frame: case4_padding.build_frame, replicated on wire_check's CRC."""
    if len(head) != 8 or not 0 <= len(user) <= 250:
        raise ValueError('one bounded DNP3 link frame required')
    h = bytearray(head)
    h[2] = len(user) + 5
    out = bytes(h) + struct.pack('<H', wc.dnp3_crc(bytes(h)))
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        out += block + struct.pack('<H', wc.dnp3_crc(block))
    return out


def _mac(text):
    parts = text.split(':')
    if len(parts) != 6:
        raise ValueError('malformed MAC: ' + text)
    return bytes(int(p, 16) for p in parts)


def _ip(text):
    parts = text.split('.')
    if len(parts) != 4 or any(not 0 <= int(p) <= 255 for p in parts):
        raise ValueError('malformed IPv4: ' + text)
    return bytes(int(p) for p in parts)


def frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b'', window=64240, mss=None):
    """A complete Ethernet/IPv4/TCP frame with correct IP and TCP checksums (no NIC offload placeholder)."""
    options = b''
    if mss is not None:
        options = struct.pack('!BBH', 2, 4, mss)
        options += b'\x00' * (-len(options) % 4)
    data_offset = (20 + len(options)) // 4
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & MASK, ack & MASK, data_offset << 4,
                      flags, window, 0, 0) + options + payload
    total = 20 + len(tcp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0x4000, 64, 6, 0, _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack('!H', wc._sum16(ip)) + ip[12:]
    eth = _mac(dst_mac) + _mac(src_mac) + b'\x08\x00'
    pseudo = _ip(src_ip) + _ip(dst_ip) + struct.pack('!BBH', 0, 6, len(tcp))
    checksum = wc._sum16(pseudo + tcp)
    tcp = tcp[:16] + struct.pack('!H', checksum) + tcp[18:]
    return eth + ip + tcp


class Link:
    """Native DNP3 transport/application sequence state of one master/outstation pair (seg61 Sequences)."""

    def __init__(self):
        self.master_transport, self.app, self.outstation_transport = 0, 0, 0

    def request(self, fc, objects):
        app = self.app
        user = bytes((0xc0 | self.master_transport, 0xc0 | app, fc)) + objects
        self.master_transport = (self.master_transport + 1) % 64
        return dnp3_frame(READ_REQ_HEAD if fc == 1 else CTL_REQ_HEAD, user), app

    def response(self, app, body, kind):
        user = bytes((0xc0 | self.outstation_transport, 0xc0 | app, 0x81)) + body
        self.outstation_transport = (self.outstation_transport + 1) % 64
        return dnp3_frame(READ_RSP_HEAD if kind == 'READ' else CTL_RSP_HEAD, user)

    def next_app(self):
        self.app = (self.app + 1) % 16


class Endpoints:
    """The two tuples and MACs of the probe connection (a synthetic tuple no Vision kernel owns)."""

    def __init__(self, master_ip, outstation_ip, master_port, outstation_port,
                 master_mac, outstation_mac, next_hop_mac):
        self.master_ip, self.outstation_ip = master_ip, outstation_ip
        self.master_port, self.outstation_port = master_port, outstation_port
        self.master_mac, self.outstation_mac, self.next_hop = master_mac, outstation_mac, next_hop_mac

    def m_to_o(self, seq, ack, flags, payload=b'', mss=None):
        return frame(self.master_mac, self.next_hop, self.master_ip, self.outstation_ip,
                     self.master_port, self.outstation_port, seq, ack, flags, payload, mss=mss)

    def o_to_m(self, seq, ack, flags, payload=b'', mss=None):
        return frame(self.outstation_mac, self.next_hop, self.outstation_ip, self.master_ip,
                     self.outstation_port, self.master_port, seq, ack, flags, payload, mss=mss)


def _point(ep, tag, kind, role, spacing_us, client_isn, server_isn, image_len, duplicate=False):
    """Build one contended (or control) point on its own fresh connection and return its frames + metadata.

    OPERATE first runs a completed SELECT on the same connection; its request acknowledges the padded
    SELECT image, whose length (image_len) comes from the switch build config, not from this module -- the
    only point where the open-loop injector must predict the switch's sequence rewriting. Confirm image_len
    against a captured control run before trusting OPERATE coverage (see the report's blockers)."""
    link = Link()
    c, s = client_isn, server_isn
    frames = {}
    frames['syn'] = ep.m_to_o(c, 0, SYN, mss=1460)
    frames['synack'] = ep.o_to_m(s, c + 1, SYN | ACK, mss=1460)
    frames['ack'] = ep.m_to_o(c + 1, s + 1, ACK)
    c += 1
    s += 1
    master_s = s                             # the outstation sequence as the master sees it (after padding)
    if kind == 'OPERATE':
        sel_req, sel_app = link.request(3, crob(200))
        frames['select_req'] = ep.m_to_o(c, s, PSH | ACK, sel_req)
        frames['select_ack'] = ep.o_to_m(s, c + len(sel_req), ACK)
        sel_rsp = link.response(sel_app, bytes(2) + crob(200), 'SELECT')
        frames['select_rsp'] = ep.o_to_m(s, c + len(sel_req), PSH | ACK, sel_rsp)
        link.next_app()
        c += len(sel_req)
        s += len(sel_rsp)                    # outstation side advances by the native response (37)
        master_s += image_len                # master side advances by the padded image (61); config-supplied
        fc, objects, body = 4, crob(200), bytes(2) + crob(200)
    elif kind == 'SELECT':
        fc, objects, body = 3, crob(200), bytes(2) + crob(200)
    else:
        fc, objects, body = 1, READ_OBJECTS, READ_BODY
    req, app = link.request(fc, objects)
    native = link.response(app, body, kind)
    frames['request'] = ep.m_to_o(c, master_s, PSH | ACK, req)
    frames['bare_ack'] = ep.o_to_m(s, c + len(req), ACK)
    frames['response'] = ep.o_to_m(s, c + len(req), PSH | ACK, native)
    if duplicate:
        frames['duplicate'] = frames['response']
    frames['rst'] = ep.m_to_o(c + len(req), master_s, RST)
    # response_seq: outstation-side (egress capture); master_response_seq: as rewritten toward the master.
    return dict(tag=tag, kind=kind, role=role, spacing_us=spacing_us, client_isn=client_isn,
                server_isn=server_isn, response_seq=s, master_response_seq=master_s, request_len=len(req),
                native_response=native, image_len=image_len, duplicate=duplicate, frames=frames)


def build_plan(ep, image_len=61, contended_spacings=CONTENDED_SPACING_US, control_spacing_us=CONTROL_SPACING_US,
               kinds=('READ', 'SELECT', 'OPERATE'), isn_stride=0x200000, start_ns=1_000_000):
    """The full probe: for each kind a noncontended control, the contended spacings, and a contended
    duplicate point; each point on its own ISN-disjoint connection. Returns the points and a flat,
    time-ordered injection schedule (every frame with a target send time in ns)."""
    points, client, server = [], 0x10000000, 0x50000000
    for kind in kinds:
        points.append(('control_%s' % kind, kind, 'control', control_spacing_us, False))
        for d in contended_spacings:
            points.append(('contended_%s_%03dus' % (kind, d), kind, 'contended', d, False))
        points.append(('dup_%s' % kind, kind, 'contended', contended_spacings[0], True))
    built = []
    for i, (tag, kind, role, spacing, dup) in enumerate(points):
        built.append(_point(ep, tag, kind, role, spacing, client + i * isn_stride,
                            server + i * isn_stride, image_len, duplicate=dup))
    schedule = _schedule(built, start_ns)
    points = [_jsonable(p) for p in built]
    return dict(image_len=image_len, points=points, schedule=schedule,
                tuple=[ep.master_ip, ep.outstation_ip, ep.master_port, ep.outstation_port],
                next_hop_mac=ep.next_hop)


def _jsonable(point):
    """Drop raw frame bytes (the schedule carries them as hex); keep every scalar the judge reads."""
    out = {k: v for k, v in point.items() if k not in ('frames', 'native_response')}
    out['frames'] = {name: buf.hex() for name, buf in point['frames'].items()}
    out['native_response'] = point['native_response'].hex()
    return out


def _schedule(points, start_ns, settle_us=200_000, step_us=50):
    """One event list for the whole probe. Within a point the handshake and request are spaced by step_us;
    the bare ACK then the response are spaced by the point's spacing; points are separated by settle_us so
    N's cell and T's hold drain between them."""
    schedule, t = [], start_ns

    def emit(name, p, dt_us):
        nonlocal t
        t += int(dt_us * 1000)
        if name in p['frames']:
            schedule.append(dict(t_ns=t, tag=p['tag'], frame=name, bytes=p['frames'][name].hex()))

    for p in points:
        for name in ('syn', 'synack', 'ack'):
            emit(name, p, step_us)
        if p['kind'] == 'OPERATE':
            for name in ('select_req', 'select_ack'):
                emit(name, p, step_us)
            emit('select_rsp', p, p['spacing_us'])
            t += CONTROL_SPACING_US * 1000       # wait out T's J hold before the OPERATE
        emit('request', p, step_us)
        emit('bare_ack', p, step_us)
        emit('response', p, p['spacing_us'])
        if p['duplicate']:
            emit('duplicate', p, step_us)
        emit('rst', p, settle_us)
        t += settle_us * 1000
    return schedule


# ----- pcap I/O (schedule -> injectable pcap; captures -> judge) ---------------------------------------
def write_pcap(path, records, nanos=True):
    """records: iterable of (t_ns, frame bytes). Classic Ethernet pcap, ns resolution by default."""
    magic = b'\x4d\x3c\xb2\xa1' if nanos else b'\xd4\xc3\xb2\xa1'
    out = bytearray(struct.pack('<IHHiIII', int.from_bytes(magic, 'little'), 2, 4, 0, 0, 262144, 1))
    for t_ns, buf in records:
        out += struct.pack('<IIII', t_ns // 1_000_000_000, (t_ns % 1_000_000_000) if nanos else (t_ns % 1_000_000_000) // 1000,
                           len(buf), len(buf))
        out += buf
    Path(path).write_bytes(bytes(out))


def schedule_pcap(path, schedule):
    write_pcap(path, [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in schedule])


# ----- the offline judge ------------------------------------------------------------------------------
# count_busy cells (snapshot_counters.py N_COUNTERS): 0 busy drop, 1 busy pass, 2 retry lap, 3 retry
# exhaustion, 4 stale retry; count_term[0] retried duplicate aborted. T outcome keys as snapshot_counters.py
# records them (core/response_only/hw/snapshot_counters.py T_OUTCOMES).
BUSY_DROP, BUSY_PASS, RETRY_LAP, EXHAUSTION, STALE = 0, 1, 2, 3, 4
MIN_BUSY_CELLS = 8
TERM_RETRIED_DUP = 0
OUT_ACK_COMMIT, OUT_RESP_RELEASE = 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE'
OUT_ACK_FALLBACK, OUT_RESP_FALLBACK = 'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK'
IMAGE_LEN = 61
DEFAULT_DELAY_TOLERANCE_US = 100.0
# The egress spacing and every delay are measured at the host transmit hook (tcpdump -Q out on the Vision
# parent NIC), NOT at switch ingress; the host-stack/NIC queueing between this hook and the ASIC is not
# subtracted. Named in the report so no reader mistakes it for an on-chip timestamp.
MEASUREMENT_POINT = 'host transmit hook (tcpdump -Q out on the Vision parent NIC), not switch ingress'


def _read_pcap_ns(path):
    """Classic pcap reader that preserves nanoseconds (wire_check.read_pcap truncates ns to us; the probe's
    spacings are microsecond-scale, so that truncation would erase the independent variable). Returns a list
    of (t_ns, frame) and the file resolution."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return [], 'us'
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian, res = '<', 'us'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian, res = '>', 'us'
    elif magic == b'\x4d\x3c\xb2\xa1':
        endian, res = '<', 'ns'
    elif magic == b'\xa1\xb2\x3c\x4d':
        endian, res = '>', 'ns'
    else:
        raise ValueError('not a classic pcap: %r' % magic)
    off, out = 24, []
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(endian + 'IIII', data[off:off + 16])
        frame = data[off + 16:off + 16 + incl]
        if len(frame) < incl:
            break
        t_ns = ts_s * 1_000_000_000 + (ts_f if res == 'ns' else ts_f * 1000)
        out.append((t_ns, frame))
        off += 16 + incl
    return out, res


def _segs(path, master_ip, outstation_ip, master_port, outstation_port):
    """Parsed IPv4/TCP segments of one capture, timestamped in nanoseconds and tagged with direction against
    the probe tuple (not wire_check's hardcoded endpoints), so a synthetic tuple classifies correctly."""
    out = []
    for idx, (t_ns, frame) in enumerate(_read_pcap_ns(path)[0]):
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        ihl = (frame[14] & 0x0f) * 4
        if frame[14 + 9] != 6:
            continue
        total_len = int.from_bytes(frame[16:18], 'big')
        tcp_off = 14 + ihl
        dataofs = (frame[tcp_off + 12] >> 4) * 4
        src = '.'.join(str(b) for b in frame[26:30])
        dst = '.'.join(str(b) for b in frame[30:34])
        sport = int.from_bytes(frame[tcp_off:tcp_off + 2], 'big')
        dport = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
        seg = {'index': idx, 't_ns': t_ns, 't_us': t_ns / 1000.0, 'src': src, 'dst': dst,
               'sport': sport, 'dport': dport,
               'seq': int.from_bytes(frame[tcp_off + 4:tcp_off + 8], 'big'),
               'ack': int.from_bytes(frame[tcp_off + 8:tcp_off + 12], 'big'),
               'flags': frame[tcp_off + 13],
               'payload': frame[14 + ihl + dataofs:14 + total_len],
               'len': len(frame[14 + ihl + dataofs:14 + total_len]), 'frame': frame}
        tup = (src, dst, sport, dport)
        if tup == (master_ip, outstation_ip, master_port, outstation_port):
            seg['probe_dir'] = 'M->O'
        elif tup == (outstation_ip, master_ip, outstation_port, master_port):
            seg['probe_dir'] = 'O->M'
        else:
            continue
        out.append(seg)
    return out


def _counter_delta(before, after, name, cells):
    """Per-cell (after - before) for an N counter, or None if either snapshot lacks that cell."""
    b = (before.get('n_counters') or {}).get(name) or []
    a = (after.get('n_counters') or {}).get(name) or []
    out = []
    for i in range(cells):
        if i >= len(a) or i >= len(b) or a[i] is None or b[i] is None:
            out.append(None)
        else:
            out.append(a[i] - b[i])
    return out


def _outcomes(snapshot):
    return snapshot.get('outcomes') or {}


def _varying_octets(frame_len):
    """DNP3 link-frame octet positions whose bytes may legitimately differ between two responses of the same
    kind: the transport-control sequence (user byte 0) and application-control sequence (user byte 1), which
    sit right after the 8-byte link header + 2-byte header CRC, and the 2-byte CRC trailing every block (the
    header's CRC plus each 16-byte data block's CRC). Everything else -- function code, objects, E padding --
    must be byte-identical. Positions at/after frame_len are ignored by the caller."""
    varying = {10, 11}                     # transport-ctl seq, app-ctl seq (first two user octets)
    varying |= {8, 9}                      # header CRC (covers the length byte that encodes the seq region)
    pos = 10                               # first data block starts after the 10-byte header+header-CRC
    while pos < frame_len:
        block = min(16, frame_len - pos)
        varying |= {pos + block, pos + block + 1}      # this block's trailing 2-byte CRC
        pos += block + 2
    return varying


def _payload_matches_control(contended, control):
    """True if the contended response payload equals the control payload except at the documented DNP3
    sequence/CRC octets (see _varying_octets). Length must match first."""
    if len(contended) != len(control):
        return False
    varying = _varying_octets(len(contended))
    return all(i in varying or contended[i] == control[i] for i in range(len(contended)))


def judge(plan, egress_pcap, master_pcap, counters_before, counters_after,
          delay_tolerance_us=DEFAULT_DELAY_TOLERANCE_US, image_len=IMAGE_LEN):
    """Judge a completed probe from the two captures and the N/T counter snapshots.

    egress_pcap: frames as injected toward the switch (the ACK/response spacing is measured here, in ns, at
    the host transmit hook -- the independent variable). master_pcap: frames the switch returned toward the
    master (delivery is read here, at the host receive hook). Verdicts and their limits:

      INVALID  the run cannot be judged: a snapshot is missing/short (fewer than 8 count_busy cells, no
               count_term, absent T outcomes, or a negative delta), a point has no measured egress spacing,
               or the egress capture is empty. INVALID is NOT a pass and NOT pending.
      FAIL     a measured defect: a busy drop, retry exhaustion, a stale retry (count_busy[4]), a retried
               duplicate aborted (count_term[0]), a control not delivered exactly once, a wrong-length or
               wrong-bytes image, a duplicate reaching the master, a master-side ordering violation, a
               T-outcome count that disagrees with the delivered points, or an untimed escape (a contended
               master-side delay outside tolerance of its kind's control).
      PENDING  no defect, but no retry lap was induced (count_busy[2]==0): silicon retry coverage stays open.
      PASS     a retry lap was induced and nothing failed.

    The delay/spacing numbers are host-transmit-hook timestamps, not switch ingress; the N/T counters are
    run-wide, so a per-point attribution of a retry lap to a single contended point is not available from the
    counters alone (see H2 in the report)."""
    t = plan['tuple']
    eg = _segs(egress_pcap, *t)
    rx = _segs(master_pcap, *t)
    controls = {p['kind']: p for p in plan['points'] if p['role'] == 'control'}
    report = {'points': [], 'verdict': None, 'failures': [], 'invalid': [],
              'measurement_point': MEASUREMENT_POINT, 'delay_tolerance_us': delay_tolerance_us}

    # ---- snapshot validity (C1 / H3) ----------------------------------------------------------------
    count_busy = _counter_delta(counters_before, counters_after, 'count_busy', MIN_BUSY_CELLS)
    count_term = _counter_delta(counters_before, counters_after, 'count_term', 1)
    before_out, after_out = _outcomes(counters_before), _outcomes(counters_after)
    if any(v is None for v in count_busy):
        report['invalid'].append('count_busy snapshot missing or shorter than %d cells' % MIN_BUSY_CELLS)
    elif any(v < 0 for v in count_busy):
        report['invalid'].append('count_busy has a negative delta %s' % count_busy)
    if count_term[0] is None:
        report['invalid'].append('count_term snapshot missing')
    elif count_term[0] < 0:
        report['invalid'].append('count_term has a negative delta %s' % count_term)
    if not after_out or not before_out:
        report['invalid'].append('T outcome snapshot missing; the judge requires T outcome deltas')
    report['count_busy_delta'] = count_busy
    report['count_term_delta'] = count_term

    def out_delta(key):
        return (after_out.get(key, 0) or 0) - (before_out.get(key, 0) or 0)

    # ---- per-point capture checks -------------------------------------------------------------------
    control_delay = {}
    for p in plan['points']:
        oseq = p['response_seq'] & MASK                       # outstation-side (egress)
        mseq = (p.get('master_response_seq', p['response_seq'])) & MASK   # rewritten toward the master (C4)
        inj = sorted([s for s in eg if s['probe_dir'] == 'O->M' and s['seq'] == oseq], key=lambda s: s['t_ns'])
        inj_ack = [s for s in inj if s['len'] == 0 and s['flags'] & ACK]
        inj_rsp = [s for s in inj if s['len'] > 0]
        spacing_us = ((inj_rsp[0]['t_ns'] - inj_ack[0]['t_ns']) / 1000.0) if (inj_ack and inj_rsp) else None
        seen = sorted([s for s in rx if s['probe_dir'] == 'O->M' and s['seq'] == mseq], key=lambda s: s['t_ns'])
        rx_ack = [s for s in seen if s['len'] == 0 and s['flags'] & ACK]
        rx_rsp = [s for s in seen if s['len'] > 0]
        master_delay_us = ((rx_rsp[0]['t_ns'] - rx_ack[0]['t_ns']) / 1000.0) if (rx_ack and rx_rsp) else None
        row = dict(tag=p['tag'], kind=p['kind'], role=p['role'], requested_spacing_us=p['spacing_us'],
                   measured_ingress_spacing_us=spacing_us, master_delay_us=master_delay_us,
                   master_bare_acks=len(rx_ack), master_responses=len(rx_rsp),
                   master_response_len=rx_rsp[0]['len'] if rx_rsp else None)
        # H2: a point without a measured egress spacing cannot be judged
        if spacing_us is None:
            report['invalid'].append('%s: no measured egress spacing (ack/response not both captured)' % p['tag'])
        # H1: the master-side sequence of this point must be exactly [bare ACK, response], one each, in time
        # order. Extra response copies are a defect on the master side regardless of bytes -- the dup point's
        # second copy is legitimate only on the EGRESS capture (checked below), never at the master.
        order = [('ack' if s['len'] == 0 else 'rsp') for s in seen]
        timed_order_ok = order == ['ack', 'rsp']
        row['master_order'] = order
        delivered_once = len(rx_ack) == 1 and len(rx_rsp) == 1 and timed_order_ok
        control_len = image_len
        correct_image = bool(rx_rsp) and rx_rsp[0]['len'] == control_len
        if p['role'] == 'control':
            control_delay[p['kind']] = master_delay_us
            if rx_rsp:
                controls[p['kind']]['_payload'] = rx_rsp[0]['payload']
        row['delivered_once'] = delivered_once
        row['correct_image'] = correct_image
        row['duplicate_escaped'] = len(rx_rsp) > 1
        report['points'].append(row)

        if len(rx_rsp) > 1:
            report['failures'].append('%s: double accounting / duplicate reached the master (%d copies)'
                                      % (p['tag'], len(rx_rsp)))
        elif not delivered_once:
            report['failures'].append('%s: not delivered exactly once in order [bare ACK, response] '
                                      '(acks=%d responses=%d order=%s)'
                                      % (p['tag'], len(rx_ack), len(rx_rsp), order))
        if rx_rsp and not correct_image:
            report['failures'].append('%s: wrong image (len %d != image_len %d)'
                                      % (p['tag'], rx_rsp[0]['len'], control_len))
        # H1 (egress): the dup point's injection may carry one extra response, identical and after the first
        if p['duplicate'] and len(inj_rsp) > 1:
            if not all(s['frame'] == inj_rsp[0]['frame'] and s['t_ns'] >= inj_rsp[0]['t_ns'] for s in inj_rsp[1:]):
                report['failures'].append('%s: injected duplicate is not identical bytes after the original' % p['tag'])

    # ---- C3: contended payload bytes equal the control's except documented seq/CRC octets -----------
    for row, p in zip(report['points'], plan['points']):
        if p['role'] != 'contended' or row['master_response_len'] is None:
            continue
        ctl = controls.get(p['kind'], {})
        ref, mseq = ctl.get('_payload'), (p.get('master_response_seq', p['response_seq'])) & MASK
        got = next((s['payload'] for s in rx if s['probe_dir'] == 'O->M' and s['seq'] == mseq and s['len'] > 0), None)
        if ref is not None and got is not None and not _payload_matches_control(got, ref):
            report['failures'].append('%s: payload differs from its control outside DNP3 seq/CRC octets' % p['tag'])

    # ---- C2: contended master-side delay must match its kind's control within tolerance -------------
    for row in report['points']:
        if row['role'] != 'contended':
            continue
        ctl_delay = control_delay.get(row['kind'])
        md = row['master_delay_us']
        if md is None or ctl_delay is None:
            continue
        if abs(md - ctl_delay) > delay_tolerance_us:
            report['failures'].append('%s: master-side delay %.3f us escapes control %.3f us by more than %.1f us'
                                      % (row['tag'], md, ctl_delay, delay_tolerance_us))

    # ---- N counter verdicts -------------------------------------------------------------------------
    retry = count_busy[RETRY_LAP] if count_busy[RETRY_LAP] is not None else 0
    busy_drop = count_busy[BUSY_DROP] if count_busy[BUSY_DROP] is not None else 0
    exhaustion = count_busy[EXHAUSTION] if count_busy[EXHAUSTION] is not None else 0
    stale = count_busy[STALE] if count_busy[STALE] is not None else 0
    report['retry_laps'], report['busy_drops'], report['exhaustion'], report['stale'] = retry, busy_drop, exhaustion, stale
    if busy_drop:
        report['failures'].append('busy-dropped a response (count_busy[0]=%d)' % busy_drop)
    if exhaustion:
        report['failures'].append('retry exhaustion (count_busy[3]=%d)' % exhaustion)
    if stale:
        report['failures'].append('stale retry (count_busy[4]=%d)' % stale)
    if count_term[0]:
        report['failures'].append('retried duplicate aborted (count_term[0]=%d)' % count_term[0])

    # ---- C2: T outcomes must equal the delivered points, both fallbacks zero -------------------------
    delivered = sum(1 for r in report['points'] if r['delivered_once'])
    if after_out and before_out:
        ack_commit, resp_release = out_delta(OUT_ACK_COMMIT), out_delta(OUT_RESP_RELEASE)
        ack_fb, resp_fb = out_delta(OUT_ACK_FALLBACK), out_delta(OUT_RESP_FALLBACK)
        report['outcomes'] = dict(ACK_COMMIT=ack_commit, RESP_RELEASE=resp_release,
                                  ACK_FALLBACK=ack_fb, RESP_FALLBACK=resp_fb, delivered=delivered)
        if ack_commit != delivered:
            report['failures'].append('OUT_ACK_COMMIT delta %d != delivered points %d' % (ack_commit, delivered))
        if resp_release != delivered:
            report['failures'].append('OUT_RESP_RELEASE delta %d != delivered points %d' % (resp_release, delivered))
        if ack_fb or resp_fb:
            report['failures'].append('T fell back (ACK_FALLBACK=%d RESP_FALLBACK=%d)' % (ack_fb, resp_fb))

    # ---- H2: the retry delta is run-wide, so attribute it only against clean controls ---------------
    report['retry_attribution'] = ('count_busy is run-wide, not per point; a nonzero retry delta is '
                                   'attributable to the contended points only if the controls were injected '
                                   'in a separate snapshot interval with a zero retry delta. Per-point '
                                   'snapshots are not implemented here.')
    report['control_clean'] = all(r['delivered_once'] for r in report['points'] if r['role'] == 'control')

    if report['invalid']:
        report['verdict'] = 'INVALID'
    elif report['failures']:
        report['verdict'] = 'FAIL'
    elif retry < 1:
        report['verdict'] = 'PENDING'
        report['pending_reason'] = 'no retry lap recorded; contention not induced, silicon retry coverage open'
    else:
        report['verdict'] = 'PASS'
    return report


def main(argv=None):
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Offline contention-probe planner / judge.')
    sub = parser.add_subparsers(dest='cmd', required=True)
    pl = sub.add_parser('plan', help='print the plan JSON (and optionally write an injection pcap)')
    for name, default in (('master-ip', '192.0.2.61'), ('outstation-ip', '192.0.2.62'),
                          ('master-mac', '02:00:00:00:00:61'), ('outstation-mac', '02:00:00:00:00:62'),
                          ('next-hop-mac', '02:00:00:00:00:09')):
        pl.add_argument('--' + name, default=default)
    pl.add_argument('--master-port', type=int, default=59400)
    pl.add_argument('--outstation-port', type=int, default=20000)
    pl.add_argument('--image-len', type=int, default=61)
    pl.add_argument('--pcap')
    jd = sub.add_parser('judge', help='judge a completed run')
    jd.add_argument('--plan', required=True)
    jd.add_argument('--egress-pcap', required=True)
    jd.add_argument('--master-pcap', required=True)
    jd.add_argument('--before', required=True)
    jd.add_argument('--after', required=True)
    jd.add_argument('--delay-tolerance-us', type=float, default=DEFAULT_DELAY_TOLERANCE_US)
    args = parser.parse_args(argv)
    if args.cmd == 'plan':
        ep = Endpoints(args.master_ip, args.outstation_ip, args.master_port, args.outstation_port,
                       args.master_mac, args.outstation_mac, args.next_hop_mac)
        plan = build_plan(ep, image_len=args.image_len)
        if args.pcap:
            schedule_pcap(args.pcap, plan['schedule'])
        print(json.dumps({k: v for k, v in plan.items() if k != 'points'}, indent=2))
        return 0
    plan = json.loads(Path(args.plan).read_text())
    report = judge(plan, args.egress_pcap, args.master_pcap,
                   json.loads(Path(args.before).read_text()), json.loads(Path(args.after).read_text()),
                   delay_tolerance_us=args.delay_tolerance_us)
    print(json.dumps(report, indent=2))
    return 0 if report['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
