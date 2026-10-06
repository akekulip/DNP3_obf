"""Admission checks must reject incomplete capture and stale hardware settings."""
from dataclasses import asdict
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import configure
import policy
import summarize
from types import SimpleNamespace


@pytest.fixture
def evidence(tmp_path):
    selected = policy.make_policy('small', 'fixed', 'D4', 5, 1)
    plan = configure.build_policy_plan(selected)
    (tmp_path/'logs').mkdir()
    (tmp_path/'logs/capture.log').write_text(
        "Packets received/dropped on interface 'eth0': 1200/0 (pcap:0)\n")
    readback = {'codebook': [asdict(e) for e in plan.codebook_entries],
                'tbl_params': asdict(plan.params_default),
                'tbl_bor_params': asdict(plan.bor_params_default)}
    (tmp_path/'configuration_readback.json').write_text(json.dumps(readback))
    return tmp_path, asdict(selected), readback


def test_admits_complete_capture_and_matching_realized_policy(evidence):
    block, selected, _ = evidence
    assert summarize.validate_provenance(block, selected)['dropped_packets'] == 0


@pytest.mark.parametrize('log', ['', "Packets received/dropped on interface 'eth0': 1200/1\n"])
def test_rejects_missing_or_lossy_capture_statistics(evidence, log):
    block, selected, _ = evidence
    (block/'logs/capture.log').write_text(log)
    with pytest.raises(ValueError, match='capture statistics|packet loss'):
        summarize.validate_provenance(block, selected)


def test_rejects_stale_deadline_even_with_clean_codebook(evidence):
    block, selected, readback = evidence
    readback['tbl_params']['d_ticks'] += 256
    (block/'configuration_readback.json').write_text(json.dumps(readback))
    with pytest.raises(ValueError, match='Configuration readback mismatch'):
        summarize.validate_provenance(block, selected)


def test_rejects_overlapping_codebook_even_if_saved_audit_claims_valid(evidence):
    block, selected, readback = evidence
    readback['codebook'].append(readback['codebook'][0])
    readback['audit'] = {'valid_policy': True}
    (block/'configuration_readback.json').write_text(json.dumps(readback))
    with pytest.raises(ValueError, match='Invalid codebook'):
        summarize.validate_provenance(block, selected)


@pytest.mark.parametrize('wrong_flow,wrong_sequence', [(True, False), (False, True)])
def test_pair_audit_rejects_other_flow_or_application_sequence(monkeypatch, tmp_path, wrong_flow, wrong_sequence):
    a = summarize.analysis
    req_payload = b'\x05\x64'+b'\x00'*9+bytes([7, a.FUNC_READ])
    resp_payload = b'\x05\x64'+b'\x00'*9+bytes([8 if wrong_sequence else 7, 0x81])
    packets = [a.TcpPacket(1, a.MASTER, a.RELAY, 1234, a.DNP3_PORT, 100, 0, a.TCP_ACK, req_payload),
               a.TcpPacket(2, a.RELAY, a.MASTER, a.DNP3_PORT, 9999 if wrong_flow else 1234,
                           200, 113, a.TCP_ACK, resp_payload)]
    txn = SimpleNamespace(t_req_ns=1, t_ack_ns=2, t_resp_ns=2)
    monkeypatch.setattr(a, '_find_one', lambda *_: tmp_path/'dummy.pcap')
    monkeypatch.setattr(a, '_tcp_packets', lambda _: packets)
    monkeypatch.setattr(a, 'extract_transactions', lambda _: [txn])
    monkeypatch.setattr(a, '_validated_transactions', lambda *_: [txn])
    with pytest.raises(ValueError, match='TCP flow|application sequence'):
        summarize.validate_packet_pairs(tmp_path)
