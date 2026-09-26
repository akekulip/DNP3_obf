from dataclasses import dataclass
import json
from pathlib import Path
import struct
import sys
from typing import Optional

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defense4.timing.latency_search import analysis


@dataclass
class FakeTxn:
    req_func: int
    ack_ms: Optional[float]
    clrt_ms: Optional[float]
    resp_ms: Optional[float]


def test_rows_from_capture_and_outcomes_account_for_every_transaction(tmp_path):
    """A missing ACK/response or invalid app outcome must fail instead of being dropped."""
    outcomes = tmp_path / "block.jsonl"
    outcomes.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "operation": "READ",
                        "valid": True,
                        "outcome": "OK",
                        "session_id": "s01",
                        "block_id": "b1",
                        "condition": "native",
                        "mode": "OFF",
                        "txn_id": 0,
                    }
                ),
                json.dumps(
                    {
                        "operation": "SELECT",
                        "valid": True,
                        "outcome": "OK",
                        "session_id": "s01",
                        "block_id": "b1",
                        "condition": "native",
                        "mode": "OFF",
                        "txn_id": 1,
                    }
                ),
            ]
        )
        + "\n"
    )
    txns = [
        FakeTxn(analysis.FUNC_READ, 1.0, 2.0, 3.0),
        FakeTxn(analysis.FUNC_SELECT, 1.5, None, None),
    ]

    with pytest.raises(analysis.AnalysisError, match="unpaired"):
        analysis.rows_from_transactions(txns, analysis.load_outcomes(outcomes))


def test_load_outcomes_rejects_non_ok_status_and_buffering(tmp_path):
    """Training data with errors, stale frames, or buffered bytes must fail closed."""
    outcomes = tmp_path / "bad.jsonl"
    outcomes.write_text(
        json.dumps(
            {
                "operation": "READ",
                "function": 1,
                "app_seq": 0,
                "outcome": "OK",
                "ok": True,
                "stale_frames_discarded": 1,
                "bytes_left_buffered": 0,
            }
        )
        + "\n"
    )

    with pytest.raises(analysis.AnalysisError, match="unsuccessful"):
        analysis.load_outcomes(outcomes)


def test_rows_from_capture_and_outcomes_expose_only_timing_features(tmp_path):
    """Changing the implementation to include packet size should alter the row contract."""
    outcome = tmp_path / "block.jsonl"
    outcome.write_text(
        json.dumps(
            {
                "operation": "OPERATE",
                "valid": True,
                "outcome": "OK",
                "session_id": "s09",
                "block_id": "b4",
                "condition": "obfuscated",
                "mode": "D4",
                "txn_id": 7,
                "rtt_ms": 6.25,
            }
        )
        + "\n"
    )

    rows = analysis.rows_from_transactions(
        [FakeTxn(analysis.FUNC_OPERATE, 2.0, 4.0, 6.0)],
        analysis.load_outcomes(outcome),
        policy={"da_ms": 2, "new_clrt_ms": 4},
    )

    assert rows == [
        {
            "session": "s09",
            "block": "b4",
            "arm": "obfuscated",
            "mode": "D4",
            "txn_index": 0,
            "txn_class": "OPERATE",
            "func": 4,
            "ack_ms": 2.0,
            "clrt_ms": 4.0,
            "rt_ms": 6.0,
            "app_rtt_ms": 6.25,
            "policy_da_ms": 2.0,
            "policy_new_clrt_ms": 4.0,
        }
    ]
    assert not (set(rows[0]) & {"req_len", "payload_len", "wire_bytes", "packet_size"})
    np.testing.assert_allclose(analysis.feature_matrix(rows), [[2.0, 4.0]])


def test_pooling_windows_do_not_cross_blocks_or_classes():
    """Pooled attackers must use non-overlapping same-class windows inside one capture block."""
    rows = []
    for block in ("b1", "b2"):
        for cls in ("READ", "SELECT"):
            for i in range(6):
                rows.append(
                    {
                        "session": "s1",
                        "block": block,
                        "arm": "obfuscated",
                        "txn_class": cls,
                        "ack_ms": i + (100 if block == "b2" else 0),
                        "clrt_ms": 10 + i,
                        "rt_ms": 10 + 2 * i,
                    }
                )

    pooled = analysis.pooled_rows(rows, pool_size=5)

    assert len(pooled) == 4
    assert {(r["block"], r["txn_class"], r["pool_size"], r["pool_start"]) for r in pooled} == {
        ("b1", "READ", 5, 0),
        ("b1", "SELECT", 5, 0),
        ("b2", "READ", 5, 0),
        ("b2", "SELECT", 5, 0),
    }
    first = next(r for r in pooled if r["block"] == "b1" and r["txn_class"] == "READ")
    assert first["ack_ms_mean"] == pytest.approx(2.0)
    assert first["clrt_ms_max"] == pytest.approx(14.0)


def test_request_gap_is_a_separate_feature_family():
    """Request spacing can leak harness behavior and must not be hidden in ACK/CLRT results."""
    rows = [
        {
            "session": "s1",
            "block": "b1",
            "arm": "native",
            "txn_class": "READ",
            "ack_ms": 1.0,
            "clrt_ms": 2.0,
            "rt_ms": 3.0,
            "request_gap_ms": None,
        },
        {
            "session": "s1",
            "block": "b1",
            "arm": "native",
            "txn_class": "OPERATE",
            "ack_ms": 1.5,
            "clrt_ms": 2.5,
            "rt_ms": 4.0,
            "request_gap_ms": 0.2,
        },
    ]

    assert analysis.feature_matrix(rows, "ack_clrt").tolist() == [[1.0, 2.0], [1.5, 2.5]]
    gap = analysis.feature_matrix(rows, "request_gap")
    assert np.isnan(gap[0, 0])
    assert gap[1, 0] == pytest.approx(0.2)
    combined = analysis.feature_matrix(rows, "ack_clrt_gap")
    np.testing.assert_allclose(combined[:, :2], [[1.0, 2.0], [1.5, 2.5]])
    assert np.isnan(combined[0, 2])
    assert combined[1, 2] == pytest.approx(0.2)


def _eval_rows():
    rows = []
    for session_no in range(1, 5):
        session = f"s{session_no:02}"
        for arm in ("native", "obfuscated"):
            for cls_no, cls in enumerate(analysis.CLASSES):
                base = cls_no * 20.0 if arm == "native" else 0.0
                for i in range(6):
                    rows.append(
                        {
                            "session": session,
                            "block": f"b{session_no}",
                            "arm": arm,
                            "txn_class": cls,
                            "ack_ms": base + i * 0.05,
                            "clrt_ms": base + i * 0.05 + 0.5,
                            "rt_ms": 2 * base + i * 0.1 + 0.5,
                        }
                    )
    return rows


def test_grouped_evaluation_keeps_train_and_test_sessions_disjoint():
    """Leaving one session out must not train on that held-out session."""
    result = analysis.evaluate_attackers(
        _eval_rows(),
        pools=(1,),
        classifiers=("logistic",),
        min_train_per_class=3,
    )

    folds = result["classifiers"]["logistic"]["ack_clrt"]["pool1"]["folds"]
    assert {fold["test_session"] for fold in folds} == {"s01", "s02", "s03", "s04"}
    assert all(fold["test_session"] not in fold["train_sessions_fixed"] for fold in folds)
    assert all(fold["test_session"] not in fold["train_sessions_adaptive"] for fold in folds)
    summary = result["classifiers"]["logistic"]["ack_clrt"]["pool1"]["summary"]
    assert summary["fixed_on_native"]["mean_balanced_accuracy"] > 0.95
    assert summary["fixed_on_obfuscated"]["mean_balanced_accuracy"] == pytest.approx(1 / 3)
    assert summary["adaptive_on_obfuscated"]["mean_balanced_accuracy"] == pytest.approx(1 / 3)


def test_completeness_requires_each_session_arm_class_before_evaluation():
    """A missing class in one arm should stop the grouped evaluation before fitting models."""
    rows = [r for r in _eval_rows() if not (
        r["session"] == "s03" and r["arm"] == "obfuscated" and r["txn_class"] == "OPERATE"
    )]

    with pytest.raises(analysis.AnalysisError, match="missing"):
        analysis.evaluate_attackers(rows, pools=(1,), classifiers=("logistic",))


def test_evaluation_can_leave_out_blocks_when_session_is_replicate_schema():
    """Fresh runner blocks use session as replicate id, so development folds leave blocks out."""
    rows = _eval_rows()
    for r in rows:
        r["session"] = "replicate_1"
        r["block"] = r["block"] + "_" + r["arm"]

    result = analysis.evaluate_attackers(
        rows,
        group_field="block",
        pools=(1,),
        classifiers=("logistic",),
        feature_sets=("clrt", "ack_clrt"),
        min_train_per_class=3,
    )

    folds = result["classifiers"]["logistic"]["ack_clrt"]["pool1"]["folds"]
    assert {fold["test_group"] for fold in folds} == {r["block"] for r in rows}
    assert all(fold["test_group"] not in fold["train_groups_fixed"] for fold in folds)
    assert result["feature_sets"]["clrt"] == ["clrt_ms"]


def test_binary_read_select_screening_reports_binary_chance():
    """READ/SELECT screening should be separate from the three-class task."""
    result = analysis.evaluate_attackers(
        _eval_rows(),
        pools=(1,),
        classifiers=("logistic",),
        tasks=("three_class", "read_select"),
        min_train_per_class=3,
    )

    task = result["tasks"]["read_select"]
    assert task["classes"] == ["READ", "SELECT"]
    assert task["chance_balanced_accuracy"] == 0.5
    assert "logistic" in task["classifiers"]


def test_simultaneous_upper_bound_uses_block_bootstrap():
    """Bootstrap screening should bound protected attacks, not the native diagnostic."""
    result = analysis.evaluate_attackers(
        _eval_rows(),
        pools=(1,),
        classifiers=("logistic",),
        feature_sets=("ack_clrt",),
        bootstrap_iterations=25,
        bootstrap_seed=12,
        min_train_per_class=3,
    )

    screening = result["tasks"]["three_class"]["simultaneous_screening"]
    assert screening["unit"] == "block"
    assert screening["confidence"] == 0.95
    assert screening["n_units"] == 4
    assert screening["n_bootstrap"] == 25
    assert screening["max_upper_bound_balanced_accuracy"] >= screening["max_observed_balanced_accuracy"]
    assert screening["included_scenarios"] == ["adaptive_on_obfuscated", "fixed_on_obfuscated"]
    native = result["classifiers"]["logistic"]["ack_clrt"]["pool1"]["summary"]["fixed_on_native"]
    assert native["mean_balanced_accuracy"] > screening["max_observed_balanced_accuracy"]
    assert result["classifiers"]["logistic"]["ack_clrt"]["pool1"]["available"] is True


def test_screening_bootstrap_uses_common_indices_and_centered_max_deviation():
    """UCB must preserve fold correlation and avoid an unsupported raw max-percentile claim."""
    task = {
        "classifiers": {
            "m": {
                "f": {
                    "pool1": {
                        "available": True,
                        "folds": [
                            {
                                "test_group": "g1",
                                "fixed_on_native": 0.99,
                                "fixed_on_obfuscated": 0.2,
                                "adaptive_on_obfuscated": 0.8,
                            },
                            {
                                "test_group": "g2",
                                "fixed_on_native": 0.99,
                                "fixed_on_obfuscated": 0.8,
                                "adaptive_on_obfuscated": 0.2,
                            },
                        ],
                    }
                }
            }
        }
    }

    screening = analysis._screening_bounds(task, "block", iterations=1, seed=0, confidence=0.95)

    assert screening["method"] == "centered_group_bootstrap_max_deviation"
    assert screening["max_observed_balanced_accuracy"] == pytest.approx(0.5)
    assert screening["max_upper_bound_balanced_accuracy"] == pytest.approx(0.8)


def test_analyse_rows_reports_each_policy_separately():
    """Campaign summaries should preserve per-policy results instead of pooling policies."""
    rows = []
    for policy, da in (("da4_gap4", 4.0), ("da5_gap1", 5.0)):
        for r in _eval_rows():
            row = dict(r)
            row["policy_name"] = policy
            row["policy_da_ms"] = da
            rows.append(row)

    result = analysis.analyse_rows(
        rows,
        pools=(1,),
        classifiers=("logistic",),
        feature_sets=("ack_clrt",),
        min_train_per_class=3,
        bootstrap_iterations=10,
    )

    assert set(result["per_policy"]) == {"da4_gap4", "da5_gap1"}
    assert result["per_policy"]["da4_gap4"]["n_rows"] == len(_eval_rows())
    assert result["per_policy"]["da4_gap4"]["attackers"]["tasks"]["three_class"]["group_field"] == "block"


def test_policy_name_metadata_is_preserved_in_rows():
    rows = analysis.rows_from_transactions(
        [FakeTxn(analysis.FUNC_READ, 1.0, 2.0, 3.0)],
        [
            analysis.Outcome(
                operation="READ",
                session="r00",
                block="b0",
                arm="obfuscated",
                mode="D4",
                txn_id=0,
                app_rtt_ms=3.0,
                raw={},
            )
        ],
        policy={"name": "da4_gap4", "da_ms": 4},
    )

    assert rows[0]["policy_name"] == "da4_gap4"
    assert rows[0]["policy_da_ms"] == 4.0


def test_per_policy_analysis_pairs_candidate_with_shared_off_by_replicate():
    """Each protected policy should be evaluated with matching OFF rows for the same replicate."""
    rows = []
    for replicate in range(5):
        for arm, policy in (("native", "ref_off"), ("obfuscated", "da4_gap4"), ("obfuscated", "da5_gap1")):
            for cls_no, cls in enumerate(analysis.CLASSES):
                for i in range(4):
                    rows.append(
                        {
                            "session": f"r{replicate:02}",
                            "block": f"r{replicate:02}_{policy}",
                            "arm": arm,
                            "policy_name": policy,
                            "txn_class": cls,
                            "ack_ms": cls_no + i * 0.01,
                            "clrt_ms": cls_no + i * 0.01 + (0 if arm == "native" else 0.5),
                            "rt_ms": 2 * cls_no + i * 0.02 + 0.5,
                        }
                    )

    result = analysis.analyse_rows(
        rows,
        pools=(1,),
        classifiers=("logistic",),
        feature_sets=("ack_clrt",),
        min_train_per_class=3,
        bootstrap_iterations=10,
    )

    assert set(result["per_policy"]) == {"da4_gap4", "da5_gap1"}
    da4 = result["per_policy"]["da4_gap4"]["attackers"]
    assert da4["tasks"]["three_class"]["group_field"] == "session"
    folds = da4["classifiers"]["logistic"]["ack_clrt"]["pool1"]["folds"]
    assert len(folds) == 5
    assert all(fold["n_test_native"] > 0 and fold["n_test_obfuscated"] > 0 for fold in folds)


def _tcp_frame(seq=100, ack=0, flags=analysis.TCP_ACK, payload=b"", src=analysis.MASTER,
               dst=analysis.RELAY, sport=12345, dport=analysis.DNP3_PORT, doff_words=5,
               truncate=0, total_len_extra=0, total_len_override=None):
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ihl_ver = 0x45
    tcp_header_len = doff_words * 4
    total_len = total_len_override or (20 + tcp_header_len + len(payload) + total_len_extra)
    ip = struct.pack(
        "!BBHHHBBH4B4B",
        ihl_ver, 0, total_len, 0, 0, 64, 6, 0,
        *(int(x) for x in src.split(".")),
        *(int(x) for x in dst.split(".")),
    )
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (doff_words << 12) | flags, 8192, 0, 0)
    frame = eth + ip + tcp + payload
    return frame[:-truncate] if truncate else frame


def test_decode_tcp_rejects_invalid_tcp_headers_and_truncated_ip():
    """Malformed TCP/IP packets in the endpoint flow must be rejected, not skipped."""
    with pytest.raises(analysis.AnalysisError, match="TCP data offset"):
        analysis._decode_tcp_packet(1, _tcp_frame(doff_words=4))
    with pytest.raises(analysis.AnalysisError, match="truncated IPv4"):
        analysis._decode_tcp_packet(1, _tcp_frame(total_len_extra=10))
    with pytest.raises(analysis.AnalysisError, match="truncated TCP"):
        analysis._decode_tcp_packet(1, _tcp_frame(doff_words=6, total_len_override=40))


def test_validated_transactions_accepts_cumulative_and_response_acks(monkeypatch):
    """A cumulative ACK, including on the response packet, is valid if it covers request bytes."""
    txn = type("Txn", (), {"req_func": analysis.FUNC_READ, "t_req_ns": 1000, "t_resp_ns": 5000})()
    req_payload = b"\x05\x64" + b"\x00" * 9 + bytes([7, analysis.FUNC_READ])
    resp_payload = b"\x05\x64" + b"\x00" * 9 + bytes([7, 0x81])
    packets = [
        analysis.TcpPacket(1000, analysis.MASTER, analysis.RELAY, 1111, analysis.DNP3_PORT,
                           100, 0, analysis.TCP_ACK, req_payload),
        analysis.TcpPacket(5000, analysis.RELAY, analysis.MASTER, analysis.DNP3_PORT, 1111,
                           200, 100 + len(req_payload), analysis.TCP_ACK, resp_payload),
    ]
    monkeypatch.setattr(analysis, "_tcp_packets", lambda _path: packets)

    rows = analysis._validated_transactions(Path("dummy.pcap"), [txn])

    assert rows[0].t_ack_ns == 5000
    assert rows[0].app_seq == 7


def test_validated_transactions_rejects_missing_ack_and_duplicate_payload(monkeypatch, tmp_path):
    txn = type("Txn", (), {"req_func": analysis.FUNC_READ, "t_req_ns": 1000, "t_resp_ns": 5000})()
    req_payload = b"\x05\x64" + b"\x00" * 9 + bytes([7, analysis.FUNC_READ])
    packets = [
        analysis.TcpPacket(1000, analysis.MASTER, analysis.RELAY, 1111, analysis.DNP3_PORT,
                           100, 0, analysis.TCP_ACK, req_payload),
        analysis.TcpPacket(5000, analysis.RELAY, analysis.MASTER, analysis.DNP3_PORT, 1111,
                           200, 100, analysis.TCP_ACK, b""),
    ]
    monkeypatch.setattr(analysis, "_tcp_packets", lambda _path: packets)

    with pytest.raises(analysis.AnalysisError, match="no relay TCP ACK covers"):
        analysis._validated_transactions(Path("dummy.pcap"), [txn])


def test_tcp_packets_rejects_duplicate_payload_and_out_of_order_timestamps(monkeypatch):
    """Capture-level packet validation catches retransmissions and timestamp disorder."""
    payload = b"\x05\x64" + b"\x00" * 10 + bytes([analysis.FUNC_READ])
    frame = _tcp_frame(payload=payload)
    monkeypatch.setattr(analysis, "iter_frames", lambda _path: [(1, frame), (2, frame)])
    with pytest.raises(analysis.AnalysisError, match="retransmitted payload"):
        analysis._tcp_packets(Path("dummy.pcap"))

    monkeypatch.setattr(analysis, "iter_frames", lambda _path: [(2, frame), (1, frame)])
    with pytest.raises(analysis.AnalysisError, match="non-monotonic"):
        analysis._tcp_packets(Path("dummy.pcap"))


def test_safety_filter_excludes_only_output_status_read():
    """Only the known 0..31 G10 output-status poll is excluded, not normal 0..22 READ."""
    status_payload = b"\x05\x64" + b"\x00" * 10 + bytes([analysis.FUNC_READ]) + b"\x00" * 4 + bytes([31])
    normal_payload = b"\x05\x64" + b"\x00" * 10 + bytes([analysis.FUNC_READ]) + b"\x00" * 4 + bytes([22])
    packets = [
        type("Pkt", (), {"from_master": True, "dnp3_func": analysis.FUNC_READ, "payload": status_payload, "t_ns": 1})(),
        type("Pkt", (), {"from_master": True, "dnp3_func": analysis.FUNC_READ, "payload": normal_payload, "t_ns": 2})(),
    ]

    assert analysis._output_status_poll_times_from_packets(packets) == {1}


def test_load_block_rejects_status_errors_and_failed_readbacks(tmp_path):
    block = tmp_path / "block"
    block.mkdir()
    (block / "status.json").write_text(json.dumps({"error": "capture failed", "capture_exit": 0}))

    with pytest.raises(analysis.AnalysisError, match="status.json reports failure"):
        analysis.load_block(block)

    (block / "status.json").write_text(json.dumps({"outputs_before": 0, "outputs_after": 1, "capture_exit": 0}))
    with pytest.raises(analysis.AnalysisError, match="output readback"):
        analysis.load_block(block)


def test_status_counts_require_planned_read_and_sbo_completion(tmp_path):
    """A reset after READs but before SBO is incomplete even if READ outcomes exist."""
    status = {"read_count": 100, "sbo_count": 100, "read_completed": 100, "sbo_completed": 0}
    outcomes = [
        analysis.Outcome("READ", "r0", "b0", "obfuscated", "D4", i, 1.0, {})
        for i in range(100)
    ]

    with pytest.raises(analysis.AnalysisError, match="completed"):
        analysis._validate_status_counts(tmp_path, status, outcomes)
