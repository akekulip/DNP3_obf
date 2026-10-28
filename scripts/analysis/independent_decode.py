#!/usr/bin/env python3
"""Independent decode of retained DNP3 responses (audit 2026-10-28, section 4.2).

The custom master and the capture checker share one codec (scripts/hardware/active_harness/dnp3_codec.py). This
tool decodes the same retained response bytes a second way, with the Wireshark/tshark DNP3 dissector, and compares
the two views field by field: function code, IIN, application sequence, object headers and qualifiers, point
indices, binary and analog point values, CROB indices and statuses. tshark's expert warnings are counted.

It is a second parser over bytes captured at the master NIC. It is not a test of a deployed master, and it says
nothing about whether the bytes equal what the relay emitted before the switch (that needs a relay-side capture).

Two tshark behaviours are handled explicitly:
- tshark 4.4.9 does not reassemble an application fragment whose transport sequence wraps from 63 to 0 inside the
  fragment, although modulo-64 numbering makes that valid. The failed reassembly also corrupts its decode of the
  following responses (separate TCP conversations do not isolate it). The capture is therefore decoded from a
  control copy in which only those wrap responses have their transport sequence numbers renumbered (link CRCs
  recomputed); every other response is byte-identical to the retained capture. Wrap responses are counted
  separately.

  python3 scripts/analysis/independent_decode.py --campaign-prefix PREFIX --output OUT.json
"""
import argparse
from collections import Counter
import json
from multiprocessing import Pool
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts/hardware/active_harness'))
import dnp3_codec  # noqa: E402

SCHEMA = 'c72-independent-decode-v1'
FIELDS = (('func', 'dnp3.al.func'), ('iin', 'dnp3.al.iin'), ('seq', 'dnp3.al.seq'), ('obj', 'dnp3.al.obj'),
          ('prefix', 'dnp3.al.objq.prefix'), ('range', 'dnp3.al.objq.range'), ('point_index', 'dnp3.al.point_index'),
          ('index', 'dnp3.al.index'), ('ana', 'dnp3.al.ana.int'), ('bi', 'dnp3.al.biq.b7'),
          ('bo', 'dnp3.al.boq.b7'), ('ctrlstatus', 'dnp3.al.ctrlstatus'), ('expert', '_ws.expert.message'))
COMPARED = ('function', 'iin', 'app_seq', 'objects', 'indices', 'analog', 'binary_in', 'binary_out', 'crob_index',
            'crob_status')


def iin_word(codec_iin):
    """The codec stores IIN bytes little-endian; tshark shows IIN1 << 8 | IIN2."""
    return ((codec_iin & 0xff) << 8) | (codec_iin >> 8)


def split(value, cast=int):
    return [cast(v) for v in value.split('|')] if value else []


def boolean(value):
    return value.strip().lower() in ('1', 'true')


def tshark_view(row):
    groups = [(int(o, 16) >> 8, int(o, 16) & 0xff) for o in split(row['obj'], str)]
    qualifiers = [(p << 4) | r for p, r in zip(split(row['prefix']), split(row['range']))]
    view = dict(function=int(row['func']), iin=int(row['iin'], 16), app_seq=int(row['seq']),
                objects=[(g, v, q) for (g, v), q in zip(groups, qualifiers)], indices=split(row['point_index']),
                analog=split(row['ana']), crob_status=split(row['ctrlstatus']), crob_index=split(row['index']),
                expert=split(row['expert'], str))
    if row.get('bi'):
        view['binary_in'] = split(row['bi'], boolean)
    if row.get('bo'):
        view['binary_out'] = split(row['bo'], boolean)
    return view


def codec_view(app_hex):
    r = dnp3_codec.parse_application_response(bytes.fromhex(app_hex))
    view = dict(function=r.function, iin=iin_word(r.iin), app_seq=r.app_seq, objects=[], indices=[], analog=[],
                crob_status=[], crob_index=[], problems=list(r.problems))
    binary_in, binary_out = [], []
    for obj in r.objects:
        view['objects'].append((obj['group'], obj['variation'], obj['qualifier']))
        for point in obj['points']:
            if obj['group'] == 12:
                view['crob_index'].append(point['index'])
                view['crob_status'].append(point['status'])
                continue
            view['indices'].append(point['index'])
            if obj['group'] == 30:
                view['analog'].append(point['value'])
            elif obj['group'] == 1:
                binary_in.append(point['value'])
            elif obj['group'] == 10:
                binary_out.append(point['value'])
    if binary_in:
        view['binary_in'] = binary_in
    if binary_out:
        view['binary_out'] = binary_out
    return view


def differences(codec, tshark):
    return [dict(field=f, codec=codec.get(f), tshark=tshark.get(f)) for f in COMPARED
            if (codec.get(f) or []) != (tshark.get(f) or []) and codec.get(f) != tshark.get(f)]


def link_frames(wire):
    """(offset, length) of each DNP3 link frame in a TCP payload."""
    frames, p = [], 0
    while p + 10 <= len(wire) and wire[p:p + 2] == b'\x05\x64':
        length = dnp3_codec.frame_total_length(wire[p + 2])
        frames.append((p, length))
        p += length
    return frames


def wraps(wire):
    """True when a non-final transport segment carries sequence 63, so the fragment wraps 63 -> 0."""
    frames = link_frames(wire)
    return any(wire[p + 10] & 0x3f == 63 for p, _ in frames[:-1])


def renumber(wire):
    """Control copy: transport sequences renumbered 0, 1, ... (FIR/FIN kept), first data-block CRC recomputed."""
    out = bytearray(wire)
    for k, (p, length) in enumerate(link_frames(wire)):
        out[p + 10] = (out[p + 10] & 0xc0) | k
        block = bytes(out[p + 10:p + 10 + min(16, length - 12)])
        out[p + 10 + len(block):p + 12 + len(block)] = dnp3_codec.crc_le(block)
    return bytes(out)


def isolated_copy(pcap, dest, replace=None):
    """Copy of the capture with each relay-to-master segment on its own conversation (unique master port)."""
    from scapy.all import IP, TCP, rdpcap, wrpcap
    packets = rdpcap(str(pcap))
    for i, pkt in enumerate(packets):
        if TCP in pkt and pkt[TCP].sport == 20000:
            pkt[TCP].dport = 30000 + i
            if replace and pkt[TCP].seq in replace:
                pkt[TCP].remove_payload()
                pkt[TCP].add_payload(replace[pkt[TCP].seq])
                pkt[IP].len = None
            del pkt[TCP].chksum
            del pkt[IP].chksum
    wrpcap(str(dest), packets)
    return dest


def tshark_rows(pcap):
    command = ['tshark', '-r', str(pcap), '-o', 'tcp.relative_sequence_numbers:FALSE', '-d', 'tcp.port==20000,dnp3',
               '-Y', 'dnp3.al.func == 129',
               '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=|', '-e', 'tcp.seq']
    for _, field in FIELDS:
        command += ['-e', field]
    out = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        values = line.split('\t')
        row = dict(zip(['tcp_seq'] + [name for name, _ in FIELDS], values + [''] * (len(FIELDS) + 1 - len(values))))
        rows.setdefault(int(row['tcp_seq']), row)           # first copy of a retransmitted segment
    return rows


def compare_connection(directory):
    directory = Path(directory).resolve()
    wire = json.loads((directory / 'relay_wire.json').read_text())
    exchanges = [e for e in wire.get('exchanges', []) if (e.get('application') or {}).get('response_app_hex')]
    wrapped = {e['response']['sequence_start']: renumber(bytes.fromhex(e['response']['wire_hex']))
               for e in exchanges if wraps(bytes.fromhex(e['response']['wire_hex']))}
    with tempfile.TemporaryDirectory(prefix='dnp3_idec_') as tmp:
        rows = tshark_rows(isolated_copy(directory / 'in.pcap', Path(tmp) / 'control.pcap', wrapped))
    report = dict(connection=str(directory.relative_to(REPO)), responses=0, matched=0, matched_after_renumber=0,
                  wrap_responses=len(wrapped), differences=[], codec_problems=[], unmatched=[], expert=Counter())
    for exchange in exchanges:
        response, application = exchange['response'], exchange['application']
        report['responses'] += 1
        seq = response.get('sequence_start')
        row = rows.get(seq)
        if row is not None and seq in wrapped:
            report['matched_after_renumber'] += 1
        if row is None:
            report['unmatched'].append(seq)
            continue
        report['matched'] += 1
        codec, tshark = codec_view(application['response_app_hex']), tshark_view(row)
        report['expert'].update(tshark['expert'])
        if codec['problems']:
            report['codec_problems'].append(dict(seq=response['sequence_start'], problems=codec['problems']))
        for d in differences(codec, tshark):
            report['differences'].append(dict(d, seq=response['sequence_start']))
    report['expert'] = dict(report['expert'])
    return report


def connections(prefix):
    return sorted(p.parent for p in (REPO / 'results/hardware/blocks').glob(prefix + '_*/**/relay_wire.json')
                  if (p.parent / 'in.pcap').is_file())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--campaign-prefix', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    args = parser.parse_args(argv)
    version = subprocess.run(['tshark', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
    with Pool(args.workers) as pool:
        reports = pool.map(compare_connection, connections(args.campaign_prefix))
    expert = Counter()
    for r in reports:
        expert.update(r['expert'])
    total = dict(connections=len(reports), responses=sum(r['responses'] for r in reports),
                 matched=sum(r['matched'] for r in reports),
                 matched_after_renumber=sum(r['matched_after_renumber'] for r in reports),
                 wrap_responses=sum(r['wrap_responses'] for r in reports),
                 differences=sum(len(r['differences']) for r in reports),
                 codec_problems=sum(len(r['codec_problems']) for r in reports),
                 unmatched=sum(len(r['unmatched']) for r in reports), expert=dict(expert))
    out = dict(schema=SCHEMA, campaign_prefix=args.campaign_prefix, tshark=version, compared_fields=list(COMPARED),
               scope='second parser over master-NIC captures; not a deployed-master test; not relay-side preservation',
               totals=total, connections=[r for r in reports if r['differences'] or r['unmatched']
                                          or r['codec_problems'] or r['expert']])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
    print(json.dumps(total))
    return 0 if not (total['differences'] or total['unmatched']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
