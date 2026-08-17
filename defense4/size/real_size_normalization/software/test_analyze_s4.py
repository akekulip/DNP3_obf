from __future__ import annotations

import struct

from defense4.size.real_size_normalization.software import analyze_s4


def _epoch(total: int, fwd: int = 6, rev: int = 16) -> dict:
    sizes = [256] * (fwd + rev)
    return {
        "fwd_count": fwd,
        "rev_count": rev,
        "cell_count": fwd + rev,
        "total_outer_bytes": total,
        "size_signature": "|".join(str(s) for s in sorted(sizes)),
        "direction_signature": "%d:%d" % (fwd, rev),
    }


def test_structural_leakage_passes_on_constant_features() -> None:
    # Every epoch is structurally identical; labels vary. No size/count signal.
    epochs, labels = [], []
    for i in range(60):
        epochs.append(_epoch(total=5632))
        labels.append(str(i % 3))
    result = analyze_s4._structural_leakage(epochs, labels, permutations=200, bootstraps=200)

    assert result["passed"]
    assert all(v["observed_bits"] == 0.0 for v in result["mutual_information_bits"].values())
    rf = result["classifier"]["random_forest"]
    assert abs(rf["balanced_accuracy"] - result["classifier"]["chance_ba"]) < 1e-6


def test_structural_leakage_detects_a_planted_size_leak() -> None:
    # total_outer_bytes is perfectly separable by label -> the gate MUST fail.
    epochs, labels = [], []
    for i in range(60):
        lab = i % 3
        epochs.append(_epoch(total=5000 + 1000 * lab))
        labels.append(str(lab))
    result = analyze_s4._structural_leakage(epochs, labels, permutations=200, bootstraps=200)

    assert not result["passed"]
    assert result["mutual_information_bits"]["total_outer_bytes"]["observed_bits"] > 0.5
    assert not result["mutual_information_bits"]["total_outer_bytes"]["passed"]
    assert result["classifier"]["random_forest"]["balanced_accuracy"] > 0.9


def test_epoch_features_group_by_capture_epoch_and_direction() -> None:
    cells = []
    for counter in range(6):
        cells.append({"capture_epoch_index": "0", "direction": "forward", "wire_len": "256", "cell_counter": str(counter)})
    for counter in range(16):
        cells.append({"capture_epoch_index": "0", "direction": "reverse", "wire_len": "256", "cell_counter": str(counter)})
    feats = analyze_s4._epoch_features(cells)

    assert set(feats) == {0}
    assert feats[0]["fwd_count"] == 6
    assert feats[0]["rev_count"] == 16
    assert feats[0]["cell_count"] == 22
    assert feats[0]["total_outer_bytes"] == 22 * 256
    assert feats[0]["direction_signature"] == "6:16"


def test_is_tcp_and_looks_dnp3_classifiers() -> None:
    tcp = _tcp_frame(b"\x05\x64\x0b\x44payload")
    assert analyze_s4._is_tcp(tcp)
    assert analyze_s4._looks_dnp3(tcp)
    arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 40
    assert not analyze_s4._is_tcp(arp)
    assert not analyze_s4._looks_dnp3(arp)


def _tcp_frame(payload: bytes) -> bytes:
    src_mac = b"\x02\x44\x00\x00\x00\x02"
    dst_mac = b"\x02\x44\x00\x00\x00\x01"
    src_ip = bytes([10, 44, 0, 2])
    dst_ip = bytes([10, 44, 0, 1])
    tcp = struct.pack(">HHIIBBHHH", 20000, 40000, 1, 1, 5 << 4, 0x18, 8192, 0, 0)
    total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0x4000, 64, 6, 0, src_ip, dst_ip)
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload
