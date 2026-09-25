"""Reject sweep policies that disagree with the archived hardware readback."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import validate_sweep as sweep


def test_sweep_intervals_use_exact_capture_timestamp_differences():
    problems = []
    rows = sweep.extract_point("sw_D4_04_24", problems)
    assert problems == []
    report = sweep.P.extract(Path(sweep.SWEEP) / "raw_pcaps/sw_D4_04_24.pcap")
    for row, exchange in zip(rows, report.exchanges, strict=True):
        assert row["ack_ms"] == (exchange.t_ack_ns - exchange.t_req_ns) / 1e6
        assert row["clrt_ms"] == (exchange.t_resp_ns - exchange.t_ack_ns) / 1e6
        assert row["rt_ms"] == (exchange.t_resp_ns - exchange.t_req_ns) / 1e6


@pytest.mark.parametrize("field,value", [("d_ticks", 19000000), ("da_dr", 24000000),
                                         ("mode", 0), ("shape_enable", 1)])
def test_rejects_readback_disagreement(tmp_path, monkeypatch, field, value):
    params = dict(d_ticks=20000000, da_dr=28000000, mode=4, shape_enable=0)
    params[field] = value
    provenance = tmp_path / "provenance"
    provenance.mkdir()
    (provenance / "sw_D4_20_8.params.txt").write_text(
        f"anchor_req - got=1\ntbl_params={params!r}\n")
    monkeypatch.setattr(sweep, "SWEEP", str(tmp_path))
    problems = []
    sweep.validate_readback(dict(point="sw_D4_20_8", mode="D4", D_A_ms="20", D_R_ms="8"),
                            problems)
    assert any(field in problem for problem in problems)


def test_rejects_wrong_request_anchor(tmp_path, monkeypatch):
    provenance = tmp_path / "provenance"
    provenance.mkdir()
    (provenance / "sw_D4_20_8.params.txt").write_text(
        "anchor_req - got=0\ntbl_params={'d_ticks': 20000000, 'da_dr': 28000000, "
        "'mode': 4, 'shape_enable': 0}\n")
    monkeypatch.setattr(sweep, "SWEEP", str(tmp_path))
    problems = []
    sweep.validate_readback(dict(point="sw_D4_20_8", mode="D4", D_A_ms="20", D_R_ms="8"),
                            problems)
    assert any("anchor_req" in problem for problem in problems)


def test_accepts_independently_quantised_deadline_addends(tmp_path, monkeypatch):
    provenance = tmp_path / "provenance"
    provenance.mkdir()
    (provenance / "sw_D4_02_26.params.txt").write_text(
        "anchor_req - got=1\ntbl_params={'d_ticks': 1999872, 'da_dr': 27999744, "
        "'mode': 4, 'shape_enable': 0}\n")
    monkeypatch.setattr(sweep, "SWEEP", str(tmp_path))
    problems = []
    digest = sweep.validate_readback(dict(point="sw_D4_02_26", mode="D4", D_A_ms="2", D_R_ms="26"),
                                     problems)
    assert problems == []
    assert len(digest) == 64
