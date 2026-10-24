import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import relay_loss


@pytest.mark.parametrize('selector,schedule,ip_len,chain,occurrence', [
    ('request_mixed:3', 'mixed', 77, 'OUTPUT', 3), ('request_full:3', 'full', 79, 'OUTPUT', 3),
    ('operate_req:1', 'mixed', 97, 'OUTPUT', 2), ('read_resp_padded:3', 'mixed', 193, 'INPUT', 3),
    ('read_resp_padded:3', 'full', 210, 'INPUT', 3), ('select_resp_padded:1', 'mixed', 112, 'INPUT', 1),
    ('operate_resp_padded:1', 'full', 112, 'INPUT', 2), ('ack_sep:3', 'mixed', 52, 'INPUT', 3),
    ('master_ack_of_padded_data:1', 'mixed', 52, 'OUTPUT', 2)])
def test_actual_timestamp_profile_selectors(selector, schedule, ip_len, chain, occurrence):
    spec = relay_loss.parse_drop(selector, schedule, 1)
    assert (spec['ip_len'], spec['chain'], spec['occurrence']) == (ip_len, chain, occurrence)


def test_loss_rejects_ambiguous_multiclass_and_legacy_destination_shapes():
    with pytest.raises(ValueError):
        relay_loss.parse_drop('read_resp_padded:3', 'mixed_full', 1)
    with pytest.raises(ValueError):
        relay_loss.parse_drop('request:1', 'mixed', 1)


def test_persistent_owned_cleanup_removes_only_owned_rules_and_detects_failure(tmp_path):
    from types import SimpleNamespace
    rules = [['-p', 'udp', '-j', 'ACCEPT']]
    original = list(rules)
    fail_delete = [False]
    def run(command):
        assert command[:2] == ['iptables', '-w']
        operation, chain = command[2:4]
        arguments = command[4:]
        if operation == '-S':
            return SimpleNamespace(returncode=0, stdout='-P INPUT ACCEPT\n' +
                ''.join('-A INPUT ' + ' '.join(rule) + '\n' for rule in rules), stderr='')
        if operation == '-C':
            return SimpleNamespace(returncode=0 if arguments in rules else 1, stdout='', stderr='')
        if operation == '-I':
            rules.insert(int(arguments[0]) - 1, arguments[1:])
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if operation == '-D':
            if fail_delete[0]:
                return SimpleNamespace(returncode=1, stdout='', stderr='delete rejected')
            rules.remove(arguments)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(command)
    path = tmp_path / 'owned.json'
    obj = relay_loss.RelayLoss(relay_loss.parse_drop('read_resp_padded:3', 'mixed', 1), 59410, 'scoped_loss', path, run=run)
    obj.install()
    assert path.exists() and len(rules) > len(original)
    fail_delete[0] = True
    refused = relay_loss.restore_owned(path, run=run)
    assert not refused['restored'] and path.exists()
    fail_delete[0] = False
    assert relay_loss.restore_owned(path, run=run)['restored']
    assert rules == original and not path.exists()


def test_exact_counter_alone_cannot_qualify_wrong_dropped_tcp_frontier():
    spec = relay_loss.parse_drop('read_resp_padded:3', 'mixed', 1)
    wire = dict(exchanges=[dict(operation='READ', request=dict(sequence_start=100 + i, sequence_end=101 + i),
                              response=dict(sequence_start=200 + i, sequence_end=393 + i)) for i in range(3)])
    report = dict(exact=True, restoration=dict(restored=True), spec=spec,
                  kernel_packet=dict(SRC='192.168.10.7', DST='192.168.10.1', SPT=20000, DPT=59410,
                                     LEN=193, SEQ=202, ACK=103))
    assert relay_loss.target_checks(report, wire, 59410) == []
    report['kernel_packet']['SEQ'] = 201
    assert relay_loss.target_checks(report, wire, 59410)
    report['kernel_packet']['SEQ'] = 202
    report['kernel_packet']['DPT'] = 59411
    assert relay_loss.target_checks(report, wire, 59410)
