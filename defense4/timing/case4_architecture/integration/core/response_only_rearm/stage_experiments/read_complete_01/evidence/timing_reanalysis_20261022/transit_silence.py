"""Transit through the switch path versus prior RECEIVE silence on Vision, with a non-circular silence definition.

Both captures are tcpdump on the same Vision parent NIC (enp59s0f0np0): out.pcap = -Q out (what Vision sent: the
master's requests, the outstation's native responses and ACKs), in.pcap = -Q in (what came back through the switch).
One host, one software clock, microsecond pcap records. Transit of a packet = t(in) - t(out).

Silence definitions (both reported, labelled):
  silence_tx  (CORRECTED): t_tx(packet) - last in.pcap record strictly before t_tx. Measured before the packet
              entered the path, so it excludes the packet's own transit.
  silence_rx  (OLD, localize.py): t_rx(packet) - last in.pcap record strictly before t_rx. Includes the transit
              being explained whenever nothing else arrived during it (circular).
  idle_tx     time since the previous out.pcap record before t_tx (transmit-side idleness, for comparison).

Matching:
  exchange level  the readout's own reassembly (hw_read_readout.stream/fragments): requests and responses are DNP3
                  application fragments paired by order; request transit = outstation-side in minus master-side out,
                  response transit = master-side in minus outstation-side out (native), first frame and complete.
                  Padded responses pair by fragment, never by bytes.
  packet level    every out.pcap TCP packet keyed by (src, sport, dst, dport, seq, ack, flags, payload); the k-th
                  occurrence of a key pairs with the k-th in.pcap occurrence. Switch-rewritten packets (padding) do
                  not match and are counted as unmatched.

  python3 transit_silence.py BLOCK_DIR [BLOCK_DIR ...] --out results.json
"""
import argparse
import collections
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[1] / 'analysis'
sys.path.insert(0, str(ANALYSIS))
import hw_read_readout as rd  # noqa: E402

BUCKETS = (('<0.5ms', 0, 500), ('0.5-2ms', 500, 2000), ('>=2ms', 2000, float('inf')))
MASTER_IP, OUTSTATION = '192.168.10.61', ('192.168.10.62', 20000)


def records(path):
    """[(t_ns, frame)], plus the file's timestamp resolution."""
    recs, res = rd.wire_check.read_pcap_records(path)
    return [(r['timestamp_ns'], r['frame']) for r in recs], res


def tcp_key(frame):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
        return None
    ihl = (frame[14] & 15) * 4
    o = 14 + ihl
    doff = (frame[o + 12] >> 4) * 4
    total = int.from_bytes(frame[16:18], 'big')
    payload = bytes(frame[o + doff:14 + total])
    src = ('.'.join(map(str, frame[26:30])), int.from_bytes(frame[o:o + 2], 'big'))
    dst = ('.'.join(map(str, frame[30:34])), int.from_bytes(frame[o + 2:o + 4], 'big'))
    return (src, dst, int.from_bytes(frame[o + 4:o + 8], 'big'), int.from_bytes(frame[o + 8:o + 12], 'big'),
            frame[o + 13], payload)


def before(sorted_ts, t):
    """Last timestamp strictly before t, or None."""
    lo, hi = 0, len(sorted_ts)
    while lo < hi:
        mid = (lo + hi) // 2
        if sorted_ts[mid] < t:
            lo = mid + 1
        else:
            hi = mid
    return sorted_ts[lo - 1] if lo else None


def silences(rx_ts, tx_ts, t_tx, t_rx):
    p_tx, p_rx, p_out = before(rx_ts, t_tx), before(rx_ts, t_rx), before(tx_ts, t_tx)
    us = lambda a, b: None if b is None else (a - b) / 1e3
    return dict(silence_tx_us=us(t_tx, p_tx), silence_rx_us=us(t_rx, p_rx), idle_tx_us=us(t_tx, p_out))


def packet_class(key):
    src, dst, _seq, _ack, _flags, payload = key
    if src == OUTSTATION:
        direction = 'O2M'
    elif dst == OUTSTATION:
        direction = 'M2O'
    else:
        return 'other'
    if not payload:
        return direction + '_ack'
    if len(payload) > 12 and payload[:2] == b'\x05\x64':
        func = payload[12]
        return '%s_func%d' % (direction, func)
    return direction + '_data'


def analyse_trial(tdir):
    out_recs, res_out = records(tdir / 'out.pcap')
    in_recs, res_in = records(tdir / 'in.pcap')
    tx_ts = sorted(t for t, _ in out_recs)
    rx_ts = sorted(t for t, _ in in_recs)
    rows = []

    # packet level
    pending = collections.defaultdict(list)
    for t, f in in_recs:
        k = tcp_key(f)
        if k is not None:
            pending[k].append(t)
    used = collections.Counter()
    unmatched = collections.Counter()
    out_tcp = 0
    for t, f in out_recs:
        k = tcp_key(f)
        if k is None:
            continue
        out_tcp += 1
        i = used[k]
        if i >= len(pending.get(k, ())):
            unmatched[packet_class(k)] += 1
            continue
        used[k] += 1
        t_rx = pending[k][i]
        rows.append(dict(level='packet', measure=packet_class(k), cls=None, transit_us=(t_rx - t) / 1e3,
                         **silences(rx_ts, tx_ts, t, t_rx)))
    in_unmatched = sum(len(v) - used[k] for k, v in pending.items())

    # exchange level (readout reassembly)
    sent, recv = rd.tcp_packets(tdir / 'out.pcap'), rd.tcp_packets(tdir / 'in.pcap')
    port = json.loads((tdir / 'result.json').read_text())['master_port']
    master = (MASTER_IP, port)
    m_req, o_rsp = rd.stream(sent, master, OUTSTATION), rd.stream(sent, OUTSTATION, master)
    o_req, m_rsp = rd.stream(recv, master, OUTSTATION), rd.stream(recv, OUTSTATION, master)
    req_m = [f for f in rd.fragments(*m_req[:3]) if f['app'][1] != 0]
    req_o = [f for f in rd.fragments(*o_req[:3]) if f['app'][1] != 0]
    nat, got = rd.fragments(*o_rsp[:3]), rd.fragments(*m_rsp[:3])
    n = min(len(req_m), len(req_o), len(nat), len(got))
    for i in range(n):
        q, qo, nr, g = req_m[i], req_o[i], nat[i], got[i]
        kind = rd.KINDS.get(q['app'][1], 'func%d' % q['app'][1])
        cls = 'READ-' + rd.read_class(bytes(qo['app'])) if kind == 'READ' else kind
        for measure, a, b in (('req_first', q['t_first_ns'], qo['t_first_ns']),
                              ('req_complete', q['t_complete_ns'], qo['t_complete_ns']),
                              ('resp_first', nr['t_first_ns'], g['t_first_ns']),
                              ('resp_complete', nr['t_complete_ns'], g['t_complete_ns'])):
            rows.append(dict(level='exchange', measure=measure, cls=cls, transit_us=(b - a) / 1e3,
                             native_len=len(nr['bytes']), master_len=len(g['bytes']),
                             **silences(rx_ts, tx_ts, a, b)))
    meta = dict(trial=tdir.name, resolution=sorted({res_out, res_in}), out_records=len(out_recs),
                in_records=len(in_recs), out_tcp=out_tcp, packet_matched=sum(used.values()),
                packet_unmatched_out=dict(unmatched), packet_unmatched_in=in_unmatched,
                exchanges=dict(master_requests=len(req_m), outstation_requests=len(req_o), native_responses=len(nat),
                               master_responses=len(got), paired=n))
    return meta, rows


def nearest_rank(v, q):
    v = sorted(v)
    return v[max(0, -(-q * len(v) // 100) - 1)] if v else None


def stats(v):
    return dict(n=len(v), median=nearest_rank(v, 50), p90=nearest_rank(v, 90), p99=nearest_rank(v, 99)) if v else \
        dict(n=0)


def bucket(s):
    for name, lo, hi in BUCKETS:
        if lo <= s < hi:
            return name


def tabulate(rows):
    """{definition: {measure: {cls: {bucket: stats}}}} plus an 'ALL' class."""
    out = {}
    for definition in ('silence_tx_us', 'silence_rx_us'):
        cells = collections.defaultdict(list)
        for r in rows:
            s = r[definition]
            if s is None:
                continue
            for cls in ({r['cls'] or 'ALL', 'ALL'}):
                cells[(r['measure'], cls, bucket(s))].append(r['transit_us'])
        tab = {}
        for (m, c, b), v in sorted(cells.items()):
            tab.setdefault(m, {}).setdefault(c, {})[b] = stats(v)
        out[definition] = tab
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('blocks', nargs='+', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args(argv)
    result = {}
    for block in a.blocks:
        for tdir in sorted(block.glob('separate_ack/*/*/')):
            if not (tdir / 'out.pcap').is_file():
                continue
            arm = tdir.parent.name
            meta, rows = analyse_trial(tdir)
            result.setdefault(block.name, {})[arm] = dict(meta=meta, tables=tabulate(rows), rows=rows)
            ex = tabulate([r for r in rows if r['level'] == 'exchange'])
            print('== %s %s  res %s  pkt matched %d unmatched out %s in %d  exchanges %s' % (
                block.name, arm, meta['resolution'], meta['packet_matched'], meta['packet_unmatched_out'],
                meta['packet_unmatched_in'], meta['exchanges']['paired']))
            for definition in ('silence_tx_us', 'silence_rx_us'):
                for m in ('resp_first', 'resp_complete', 'req_first'):
                    cell = ex[definition].get(m, {}).get('ALL', {})
                    print('  %-13s %-13s ' % (definition[:-3], m) + '  '.join(
                        '%s n%3d med %6s p90 %6s p99 %6s' % (b, cell[b]['n'], cell[b]['median'], cell[b]['p90'],
                                                             cell[b]['p99']) if b in cell else '%s n  0' % b
                        for b, _, _ in BUCKETS))
    a.out.write_text(json.dumps(result, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
