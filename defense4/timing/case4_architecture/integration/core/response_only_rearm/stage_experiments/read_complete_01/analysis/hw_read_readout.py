"""Independent physical-switch READ readout (Python >= 3.10): sizes, preservation, bandwidth, latency, throughput.

For every connection directory under a block's evidence (one with out.pcap and in.pcap), cut the DNP3 frames of
each TCP direction from both captures and pair the transactions in order:
  * outstation-side capture (in.pcap): the NATIVE responses the outstation sent;
  * master-side capture (out.pcap): the responses the master received through the switch.
Each READ response the master received is checked against the REFERENCE ENCODER, independently of the switch
and its model: general_read_padding.pad_read(request, native, policy targets, reserved range) must reproduce the
received bytes exactly when the connection was padded (and the native bytes exactly when it was not). Every CRC,
one reassembled fragment, original points as the suffix and the reserved synthetic prefix are checked by that
encoder's own decoder. Reported per connection: aggregate response sizes, TCP payload sizes per packet, wire
octets (Ethernet frames) native vs master-side, request-to-response latency at the master, transactions/s.

  python3 hw_read_readout.py BLOCK_EVIDENCE_DIR [--out readout.json]
"""
import argparse
import collections
import json
import statistics
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'software/source/full_read_01'))
sys.path.insert(0, str(ROOT / 'software/source/read_reencode_01'))
import general_read_padding as gp  # noqa: E402
import capture  # noqa: E402

std = gp.std
POLICY = json.loads((ROOT / 'policy/policy.json').read_text())
TARGETS = POLICY['selected']['targets']
PAD_START, PAD_STOP = POLICY['profile']['reserved_padding_range']
MASTER, OUTSTATION = '192.168.10.61', '192.168.10.62'


def as_micro(path):
    """capture.packets reads microsecond pcaps; convert a nanosecond pcap to a temporary microsecond copy."""
    data = path.read_bytes()
    if data[:4] == b'\xd4\xc3\xb2\xa1':
        return path
    if data[:4] != b'\x4d\x3c\xb2\xa1':
        raise ValueError('unsupported pcap magic in %s' % path)
    out, p = bytearray(b'\xd4\xc3\xb2\xa1' + data[4:24]), 24
    while p + 16 <= len(data):
        sec, nsec, incl, orig = struct.unpack('<IIII', data[p:p + 16])
        out += struct.pack('<IIII', sec, nsec // 1000, incl, orig) + data[p + 16:p + 16 + incl]
        p += 16 + incl
    tmp = path.with_suffix('.us.pcap.tmp')
    tmp.write_bytes(bytes(out))
    return tmp


def ip(b):
    return '.'.join(str(x) for x in b)


def direction_packets(pcap):
    """[(t, src, dst, payload_len, frame_len)] for TCP packets with payload, both directions."""
    out = []
    for t, f in capture.packets(pcap):
        if len(f) < 54 or f[12:14] != b'\x08\x00' or f[23] != 6:
            continue
        ihl = (f[14] & 15) * 4
        tot = int.from_bytes(f[16:18], 'big')
        off = 14 + ihl
        doff = (f[off + 12] >> 4) * 4
        plen = tot - ihl - doff
        if plen > 0:
            out.append((t, ip(f[26:30]), ip(f[30:34]), plen, len(f)))
    return out


def transactions(pcap):
    """[(kind, request_bytes, response_bytes, t_request, t_response_first_seg)] in stream order."""
    recs = list(capture.tcp_records(pcap))
    by_dir = collections.defaultdict(list)
    for r in recs:
        if r['payload']:
            by_dir[(ip(r['src'][0]) if isinstance(r['src'][0], (bytes, bytearray)) else r['src'][0],
                    ip(r['dst'][0]) if isinstance(r['dst'][0], (bytes, bytearray)) else r['dst'][0])].append(r)
    def cut(rs):
        # byte stream in sequence order (drop exact retransmissions), then link frames with first-byte time
        seen, data, times = set(), bytearray(), []
        for r in sorted(rs, key=lambda r: (r['seq'], r['time'])):
            if r['seq'] in seen:
                continue
            seen.add(r['seq'])
            data += r['payload']
            times += [r['time']] * len(r['payload'])
        frames, p = [], 0
        while p + 10 <= len(data) and data[p:p + 2] == b'\x05\x64':
            n = std.frame_length(data[p + 2] - 5)
            frames.append((bytes(data[p:p + n]), times[p]))
            p += n
        return frames
    req = cut(by_dir[(MASTER, OUTSTATION)])
    rsp = cut(by_dir[(OUTSTATION, MASTER)])
    def group(frames):
        out, cur, t0 = [], [], None
        for f, t in frames:
            u = std.deframe(f)[1]
            if u[0] & std.FIR:
                cur, t0 = [], t
            cur.append(f)
            if u[0] & std.FIN:
                out.append((b''.join(cur), t0))
                cur = []
        return out
    return group(req), group(rsp)


def kind_of(response):
    _, app = gp.one_fragment(response)
    if app[1] != 0x81:
        return 'other'
    obj = app[4:7]
    return 'SBO' if obj[:2] == b'\x0c\x01' else 'READ'


def analyse_connection(cdir, padded_expected):
    out_p, in_p = as_micro(cdir / 'out.pcap'), as_micro(cdir / 'in.pcap')
    m_req, m_rsp = transactions(out_p)
    o_req, o_rsp = transactions(in_p)
    rows, fails = [], []
    for i, ((mq, tq), (mr, tr)) in enumerate(zip(m_req, m_rsp)):
        if i >= len(o_rsp):
            fails.append('master response %d has no outstation-side native' % i)
            break
        native, tn = o_rsp[i]
        k = kind_of(native)
        row = dict(index=i, kind=k, native_len=len(native), master_len=len(mr), latency_us=round((tr - tq) * 1e6, 1),
                   native_frames=[len(f) for f in gp.split_frames(native)], master_frames=[len(f) for f in gp.split_frames(mr)])
        if k == 'READ':
            oq = o_req[i][0] if i < len(o_req) else mq
            if padded_expected:
                r = gp.pad_read(oq, native, TARGETS, pad_start=PAD_START, pad_stop=PAD_STOP)
                exp = r.output
                row.update(status=r.status, target=r.target, padding_points=r.padding_points)
            else:
                exp = native
            row['exact'] = (mr == exp)
            if not row['exact']:
                fails.append('READ %d: master-side bytes differ from the reference encoder' % i)
        rows.append(row)
    pk_m, pk_o = direction_packets(out_p), direction_packets(in_p)
    o2m_m = [p for p in pk_m if p[1] == OUTSTATION and p[2] == MASTER]
    o2m_o = [p for p in pk_o if p[1] == OUTSTATION and p[2] == MASTER]
    reads = [r for r in rows if r['kind'] == 'READ']
    dur = (max(p[0] for p in pk_m) - min(p[0] for p in pk_m)) if pk_m else 0
    summary = dict(
        transactions=len(rows), reads=len(reads), reads_exact=sum(1 for r in reads if r.get('exact')),
        read_native_lens=sorted(collections.Counter(r['native_len'] for r in reads).items()),
        read_master_lens=sorted(collections.Counter(r['master_len'] for r in reads).items()),
        read_master_frames=sorted(collections.Counter(tuple(r['master_frames']) for r in reads).items()),
        sbo_master_lens=sorted(collections.Counter(r['master_len'] for r in rows if r['kind'] == 'SBO').items()),
        o2m_tcp_payload_native=sorted(collections.Counter(p[3] for p in o2m_o).items()),
        o2m_tcp_payload_master=sorted(collections.Counter(p[3] for p in o2m_m).items()),
        o2m_wire_octets_native=sum(p[4] for p in o2m_o), o2m_wire_octets_master=sum(p[4] for p in o2m_m),
        read_latency_us=dict(median=statistics.median([r['latency_us'] for r in reads]) if reads else None,
                             p99=sorted(r['latency_us'] for r in reads)[int(0.99 * (len(reads) - 1))] if reads else None),
        transactions_per_s=round(len(rows) / dur, 2) if dur else None, duration_s=round(dur, 3))
    if summary['o2m_wire_octets_native']:
        summary['o2m_wire_overhead_percent'] = round(100 * (summary['o2m_wire_octets_master'] /
                                                           summary['o2m_wire_octets_native'] - 1), 2)
    for p in (out_p, in_p):
        if p.name.endswith('.tmp'):
            p.unlink()
    return dict(connection=str(cdir), padded_expected=padded_expected, summary=summary, failures=fails, rows=rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('block')
    ap.add_argument('--out')
    ap.add_argument('--native', action='store_true', help='connections were size-off (expect native bytes)')
    a = ap.parse_args()
    root = Path(a.block)
    conns = sorted({p.parent for p in root.rglob('out.pcap') if (p.parent / 'in.pcap').is_file()})
    results = []
    for c in conns:
        rec = {}
        for name in ('result.json', 'connection.json'):
            if (c / name).is_file():
                rec = json.loads((c / name).read_text())
        padded = not a.native and rec.get('padding', 1) != 0
        try:
            results.append(analyse_connection(c, padded))
        except Exception as error:  # a malformed capture is a recorded failure
            results.append(dict(connection=str(c), failures=['analysis error: %r' % error]))
    report = dict(block=str(root), policy_targets=TARGETS, connections=results,
                  ok=bool(results) and all(not r['failures'] for r in results))
    text = json.dumps(report, indent=1)
    if a.out:
        Path(a.out).write_text(text + '\n')
    print(json.dumps([dict(connection=r['connection'], summary=r.get('summary'), failures=r['failures'][:5])
                      for r in results], indent=1)[:6000])
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
