#!/usr/bin/env python3
"""Reproduce new campaign measurements without changing any frozen campaign."""
import argparse
import csv
import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path

import numpy as np

import analysis
import configure

HERE = Path(__file__).resolve().parent


def validate_provenance(block, policy):
    """Check capture loss and actual configuration before admitting measurements."""
    capture_log = (block/'logs/capture.log').read_text()
    counts = re.findall(r"Packets received/dropped on interface .*?:\s*(\d+)/(\d+)", capture_log)
    if len(counts) != 1 or int(counts[0][0]) == 0 or int(counts[0][1]) != 0:
        raise ValueError('Missing capture statistics or reported packet loss')
    readback = json.loads((block/'configuration_readback.json').read_text())
    entries = tuple(configure.CodebookEntry(**entry) for entry in readback['codebook'])
    if not configure.audit_entries(entries).valid_policy:
        raise ValueError('Invalid codebook readback')
    p = configure.policy.make_policy(policy['name'], policy['kind'], policy['mode'],
        policy['requested_da_ms'], policy['requested_gap_ms'], policy['j_set_ms'])
    expected = configure.build_policy_plan(p)
    if sorted(entries, key=lambda e: e.priority) != sorted(expected.codebook_entries, key=lambda e: e.priority):
        raise ValueError('Codebook readback differs from requested policy')
    for key, wanted in [('tbl_params', expected.params_default), ('tbl_bor_params', expected.bor_params_default)]:
        for field, value in asdict(wanted).items():
            if readback[key].get(field) != value:
                raise ValueError('Configuration readback mismatch: '+key+'.'+field)
    return {'received_packets': int(counts[0][0]), 'dropped_packets': int(counts[0][1])}


def validate_packet_pairs(block):
    """Independently bind extracted timing endpoints to one TCP/DNP3 exchange."""
    path = analysis._find_one(block, ('traffic.pcap*', 'raw_pcaps/*.pcap*'), 'traffic capture')
    packets = analysis._tcp_packets(path)
    by_time = {packet.t_ns: packet for packet in packets}
    extracted = analysis.extract_transactions(path)
    validated = analysis._validated_transactions(path, extracted)
    for txn in validated:
        request, ack, response = (by_time[t] for t in (txn.t_req_ns, txn.t_ack_ns, txn.t_resp_ns))
        expected = (request.dst, request.src, request.dport, request.sport)
        for packet in (ack, response):
            if (packet.src, packet.dst, packet.sport, packet.dport) != expected:
                raise ValueError('Timing endpoint belongs to another TCP flow')
        if response.dnp3_func != 0x81 or response.app_seq != request.app_seq:
            raise ValueError('DNP3 response does not match request application sequence')
    return len(validated)


def summarize(root, phase='screen', allow_partial=False, campaign=None):
    blocks = []
    errors = []
    rows = []
    inputs = {}
    capture_audits = {}
    for block in sorted((root / 'evidence/blocks').iterdir()):
        if campaign and not block.name.startswith(campaign + '_r'):
            continue
        metadata = block / 'policy.json'
        if not metadata.exists():
            continue
        policy = json.loads(metadata.read_text())
        if policy.get('phase') != phase:
            continue
        try:
            capture_audits[block.name] = validate_provenance(block, policy)
            capture_audits[block.name]['matched_tcp_dnp3_exchanges_including_safety_polls'] = validate_packet_pairs(block)
            data = analysis.load_block(block)
            for row in data:
                row['policy_name'] = policy['name']
            rows.extend(data)
            blocks.append(block.name)
        except Exception as exc:
            errors.append({'block': block.name, 'error': str(exc)})
        for path in sorted(block.rglob('*')):
            if path.is_file():
                inputs[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    policies = {}
    for row in rows:
        policies.setdefault(row['policy_name'], []).append(row)
    counts = {name: len({r['block'] for r in data}) for name,data in policies.items()}
    complete = phase == 'screen' and len(blocks) == 125 and len(policies) == 25 and all(n == 5 for n in counts.values()) and not errors
    if not complete and not allow_partial:
        raise ValueError('Incomplete screen: %d blocks, %d policies, %d errors' % (len(blocks),len(policies),len(errors)))
    summary = {'phase': phase, 'campaign': campaign, 'complete_screen': complete, 'n_blocks': len(blocks),
               'n_exchanges': len(rows), 'errors': errors, 'policies': {}, 'input_sha256': inputs,
               'capture_audits': capture_audits}
    for name,data in sorted(policies.items()):
        p = json.loads((root / 'evidence/blocks' / data[0]['block'] / 'policy.json').read_text())
        result = {'policy': p, 'n_blocks': counts[name], 'n_exchanges': len(data), 'operations': {}}
        for op in analysis.CLASSES:
            obs = [r for r in data if r['txn_class'] == op]
            stat = {'n': len(obs)}
            for metric in ('ack_ms','clrt_ms','rt_ms','request_gap_ms'):
                values = [r[metric] for r in obs if r.get(metric) is not None and np.isfinite(r[metric])]
                if values:
                    q = np.quantile(values,[0,.25,.5,.75,.95,.99,1])
                    stat[metric] = dict(zip(('min','q1','median','q3','p95','p99','max'),map(float,q)))
                    stat[metric]['iqr'] = float(q[3]-q[1])
                    stat[metric]['sd'] = float(np.std(values, ddof=1)) if len(values)>1 else None
            result['operations'][op] = stat
        summary['policies'][name] = result
    return summary,rows


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--phase',default='screen')
    parser.add_argument('--allow-partial',action='store_true')
    parser.add_argument('--campaign', help='Exact acquisition schedule name; excludes diagnostics and older attempts')
    parser.add_argument('--out',type=Path,default=HERE/'results')
    args=parser.parse_args()
    summary,rows=summarize(HERE,args.phase,args.allow_partial,args.campaign)
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'measurements.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    if rows:
        keys=sorted(set().union(*(r.keys() for r in rows)))
        with (args.out/'transactions.csv').open('w') as fh:
            w=csv.DictWriter(fh,fieldnames=keys,lineterminator='\n');w.writeheader();w.writerows(rows)
    print(json.dumps({k:summary[k] for k in ('complete_screen','n_blocks','n_exchanges','errors')},indent=2))


if __name__=='__main__':
    main()
