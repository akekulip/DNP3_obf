#!/usr/bin/env python3
"""Separate cohort tables from retained captures; no acquisition or admission."""
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import admission_record
import stats

FRAMEWORK = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main(output):
    output.mkdir(parents=True, exist_ok=True)
    cohort = admission_record.smoke_cohort()
    rows = [dict(index=i, request_to_ack_ms=a, request_to_response_ms=r, clrt_ms=c)
            for i, (a, r, c) in enumerate(cohort['rows'])]
    write_csv(output / 'historical_off_main30.csv', rows)
    smoke_stats = stats.summarize([r['clrt_ms'] for r in rows], attempted=cohort['main_count'])
    capture = FRAMEWORK / 'results/case4_bmv2_transport_repair_20261006/final_captures/sbo_12'
    source = capture / 'result.json'
    run = json.loads(source.read_text())
    size_rows = []
    for i, (tx, pad, split, endpoint) in enumerate(zip(run['txns'], run['request_padding'],
                                                       run['split'], run['endpoint_responses'])):
        size_rows.append(dict(index=i, operation=tx['operation'], outcome=run['outcomes'][i],
            native_request_bytes=pad['native_length'], wire_request_bytes=pad['wire_length'],
            response_bytes=split['orig_len'], prefix_bytes=split['seq_order'][0],
            suffix_bytes=split['seq_order'][1],
            gap_ms=(tx['e_R']-tx['e_A'])/1e6,
            oracle_equal=pad['equals_software_oracle'], reassembled_equal=split['reassembled_equal'],
            contiguous=split['contiguous'], checksums_ok=pad['checksums_ok'] and split['checksums_ok'],
            endpoint_statuses=';'.join(str(s) for s in endpoint['statuses'])))
    if len(size_rows) != len(run['txns']):
        raise ValueError('size record denominator differs from transaction count')
    write_csv(output / 'case4_software_sbo.csv', size_rows)
    distributions = {key: dict(sorted(Counter(str(r[key]) for r in size_rows).items()))
        for key in ('native_request_bytes', 'wire_request_bytes', 'response_bytes', 'prefix_bytes', 'suffix_bytes')}
    summary = {
        'historical_off': {**{k: v for k, v in cohort.items() if k != 'rows'},
            'clrt_ms': smoke_stats, 'limit': 'OFF path on df599; master-facing times are not switch/admission bounds'},
        'case4_software_sbo': {'attempted': len(run['txns']), 'eligible': len(run['request_padding']),
            'bypassed': len(run['txns'])-len(run['request_padding']),
            'eligible_fraction': len(run['request_padding'])/len(run['txns']),
            'outcomes': dict(Counter(run['outcomes'])), 'payload_distributions_bytes': distributions,
            'endpoint': run['artifact']['endpoint'], 'source_sha256': run['artifact']['source_sha256'],
            'limit': 'one SELECT/OPERATE pair; selected supported profile, not traffic-wide eligibility or independent repetitions; no physical OPERATE; full D_R unmeasured'},
        'classifier': 'No device labels; no device-identity classifier score inferred from transaction classes'}
    (output / 'cohort_summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    inputs = [source, capture / 'master_side.pcap', capture / 'outstation_side.pcap',
        FRAMEWORK / 'results/hw_smoke_20261006/cand_off_30/traffic.pcapng',
        FRAMEWORK / 'results/hw_smoke_20261006/cand_off_30/read.jsonl',
        FRAMEWORK / 'results/hw_smoke_20261006/cand_off_30/status.json']
    provenance = {'generator_sha256': sha(Path(__file__)), 'statistics_sha256': sha(Path(stats.__file__)),
        'inputs_sha256': {str(p.relative_to(FRAMEWORK)): sha(p) for p in inputs},
        'outputs_sha256': {p.name: sha(p) for p in output.iterdir() if p.suffix in ('.csv', '.json')
                           and p.name != 'provenance.json'},
        'methods': 'Main READ cohort by full reverse flow/TCP end/app sequence; type-7 quantiles, sample variance n-1; SBO size rows from independently captured packet/oracle checks'}
    (output / 'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    return summary


if __name__ == '__main__':
    print(json.dumps(main(Path(sys.argv[1])), indent=2))
