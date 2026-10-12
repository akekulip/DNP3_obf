#!/usr/bin/env python3
"""Independently verify the unchanged reconnect characterization; do not use its campaign verdict."""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[2]
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import clrt_check
import wire_check


def verify():
    run = HERE.parent / 'campaign_hw_vepa/same_tuple_failure_01'
    trial = run / 'separate_ack/combined/same_tuple_failure_01_separate_ack_combined_t0'
    result = {'claim': 'unchanged protected same-tuple reconnect is refused', 'connections': {}}
    for cn, expected in [('c1', {'READ': 58, 'SELECT': 58, 'OPERATE': 58}),
                         ('c2', {'READ': 49, 'SELECT': 37, 'OPERATE': 37})]:
        directory = trial / cn
        master = json.loads((directory / 'master.json').read_text())
        outstation = json.loads((directory / 'outstation.json').read_text())
        wire = json.loads((directory / 'wire.json').read_text())
        rows = clrt_check.exchanges(str(directory / 'out.pcap'), str(directory / 'in.pcap'))
        assert master['success'] and master['all_reads_match_seed']
        assert master['reads_requested'] == master['reads_completed'] == len(master['reads']) == 20
        assert all(r['completed'] and r['matches_seed'] and r['points_received'] == 23 for r in master['reads'])
        assert outstation['select_real'] == outstation['operate_real'] == 1
        assert outstation['select_decoy'] == outstation['operate_decoy'] == 0
        assert not wire['returned_integrity']['dnp3_crc_bad']
        assert not wire['returned_integrity']['tcp_checksum_bad']
        assert not wire['unmatched_sent'] and not wire['unmatched_returned'] and not wire['duplicate_returned']
        for kind, length in expected.items():
            exchanges = [r for r in rows if r['kind'] == kind]
            assert len(exchanges) == (20 if kind == 'READ' else 1)
            assert all(r['complete'] and r['req_crc_ok'] and r['resp_crc_ok']
                       and r['resp_len'] == length and r['attempts'] == 1 for r in exchanges)
        errors = [abs(r['clrt_us'] - 800) for r in rows
                  if r['kind'] == 'READ' and r['complete'] and not r['piggyback'] and r['attempts'] == 1]
        if cn == 'c1':
            assert len(errors) == 20 and clrt_check.stats(errors)['p99'] <= 100
        result['connections'][cn] = {'verified': True, 'reads': 20, 'real_select': 1, 'real_operate': 1,
                                     'response_lengths': expected,
                                     'read_absolute_error_us': clrt_check.stats(errors)}
    directory = trial / 'c3'
    c3 = json.loads((directory / 'result.json').read_text())
    sent, _ = wire_check.parse(str(directory / 'out.pcap'))
    returned, _ = wire_check.parse(str(directory / 'in.pcap'))
    assert c3['master_rc'] == 2 and not c3['ok']
    assert len(sent) == 5 and not returned
    assert all(s['flags'] == wire_check.SYN and s['len'] == 0 for s in sent)
    outstation = json.loads((directory / 'outstation.json').read_text())
    assert outstation['opens'] == outstation['select_real'] == outstation['operate_real'] == 0
    result['connections']['c3'] = {'verified_refusal': True, 'syn_sent': len(sent), 'returned': 0,
                                 'master_rc': c3['master_rc'], 'master_wall_s': c3['master_wall_s'],
                                 'master_json': 'empty: endpoint never connected'}
    campaign = json.loads((run / 'campaign_run.json').read_text())
    assert campaign['restore'] and all(s['ok'] and s['rc'] == 0 for s in campaign['restore'])
    result['restoration_verified'] = True
    result['campaign_verdict_authoritative'] = False
    result['original_gate_defect'] = 'native SBO lengths were collapsed with READ lengths'
    result['verified'] = True
    return result


if __name__ == '__main__':
    data = verify()
    (HERE / 'failure_verification.json').write_text(json.dumps(data, indent=2) + '\n')
    print(json.dumps(data, indent=2))
