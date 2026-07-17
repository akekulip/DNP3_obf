"""Unit tests for the Phase 05 ACK feature-family decomposition (ack_fingerprint_eval.FEATURES /
supervised). Verifies the families are named/composed correctly and that a constant (zero-variance)
mode_only feature after coalescing is flagged non-discriminating rather than scored as learned.

    python3 -m pytest tests/test_phase05_features.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ack_fingerprint_eval as AF


def test_feature_families_named_and_composed():
    F = AF.FEATURES
    assert F["mode_only"] == ["is_separate"]
    assert F["ack_timing"] == ["req_to_ack_ms", "ack_to_resp_ms"]
    assert F["ack_combined"] == ["is_separate", "req_to_ack_ms", "ack_to_resp_ms"]  # was ack_only
    assert F["timing"] == ["req_to_resp_ms"]
    assert F["size"] == ["req_size", "resp_size"]
    assert "ack_only" not in F                        # renamed with provenance
    assert set(F["all"]) == {"is_separate", "req_to_ack_ms", "ack_to_resp_ms",
                             "req_to_resp_ms", "req_size", "resp_size"}


def _frame(is_separate):
    import pandas as pd
    rows = []
    for base in (True, False):                        # base pcap = train, L pcap = test
        for dev in ("AB1400", "ION7550"):
            for i in range(25):
                rows.append({
                    "device_label": dev, "is_L": not base,
                    "is_separate": is_separate,
                    "req_to_ack_ms": 10.0, "ack_to_resp_ms": 0.0,
                    "req_to_resp_ms": 10.0 if dev == "AB1400" else 15.0,
                    "req_size": 20, "resp_size": 50 if dev == "AB1400" else 61,
                })
    return pd.DataFrame(rows)


def test_mode_only_constant_flagged_after_coalescing():
    if not AF._HAVE_SKLEARN:
        try:
            import pytest
            pytest.skip("scikit-learn not installed")
        except ImportError:
            return
    df = _frame(is_separate=0)                         # coalesced: is_separate constant 0 everywhere
    out = AF.supervised(df, "native")
    assert out["mode_only"]["constant_non_discriminating"] is True
    assert out["mode_only"]["train_variance"]["is_separate"] == 0.0
    # size is NOT constant (AB1400 50 vs ION7550 61) -> not flagged
    assert out["size"]["constant_non_discriminating"] is False
    # provenance recorded
    assert out["seed"] == AF.SEED and out["rf_params"]["n_estimators"] == 200
    for m in ("accuracy", "balanced_accuracy", "macro_f1"):
        assert m in out["mode_only"]["rf"]


def test_mode_only_not_constant_when_separate_varies():
    if not AF._HAVE_SKLEARN:
        return
    import pandas as pd
    df = _frame(is_separate=0)
    df.loc[df["device_label"] == "AB1400", "is_separate"] = 1   # AB separate, ION combined
    out = AF.supervised(df, "native")
    assert out["mode_only"]["constant_non_discriminating"] is False


if __name__ == "__main__":
    for _n, _f in sorted(globals().items()):
        if _n.startswith("test_") and callable(_f):
            _f()
            print("ok", _n)
