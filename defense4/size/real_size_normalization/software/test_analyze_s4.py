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


def test_time_bins_group_cells_by_wall_clock_epoch() -> None:
    cells = []
    for i in range(6):
        cells.append({"ts": i * 100, "wire_len": 256, "direction": "forward"})
    for i in range(16):
        cells.append({"ts": 1000 + i * 100, "wire_len": 256, "direction": "reverse"})
    for i in range(6):
        cells.append({"ts": 210_000 + i * 100, "wire_len": 256, "direction": "forward"})
    bins = analyze_s4._time_bins(cells, bin_us=210_000)

    assert [b["bin"] for b in bins] == [0, 1]
    assert bins[0]["fwd_count"] == 6 and bins[0]["rev_count"] == 16
    assert bins[0]["cell_count"] == 22
    assert bins[0]["total_outer_bytes"] == 22 * 256
    assert bins[0]["direction_signature"] == "6:16"


def _write_observer_csv(path, bins_cells) -> None:
    import csv as _csv
    with open(path, "w", newline="", encoding="utf-8") as h:
        w = _csv.DictWriter(h, fieldnames=["timestamp_us", "wire_len", "direction", "cell_counter"], lineterminator="\n")
        w.writeheader()
        t = 0
        for n_fwd, n_rev in bins_cells:
            for i in range(n_fwd):
                w.writerow({"timestamp_us": t, "wire_len": 256, "direction": "forward", "cell_counter": i}); t += 100
            for i in range(n_rev):
                w.writerow({"timestamp_us": t, "wire_len": 256, "direction": "reverse", "cell_counter": i}); t += 100
            t = ((t // 210_000) + 1) * 210_000  # advance to the next wall-clock epoch bin


def test_observer_gate_passes_on_fixed_volume(tmp_path) -> None:
    out = tmp_path / "run"; out.mkdir()
    _write_observer_csv(out / "observer_l_left.csv", [(6, 16)] * 15)
    report = analyze_s4.observer_size_report(out, tmp_path / "ana")

    assert report["invariants"]["all_cells_256B"]
    assert report["invariants"]["modal_bin_cell_count"] == 22
    assert report["invariants"]["max_abs_deviation_from_modal"] == 0
    assert report["invariants"]["passed"]


def test_observer_gate_fails_on_content_dependent_cell_count(tmp_path) -> None:
    # Three interior bins emit a large content-dependent excess of cells; the
    # wall-clock size gate MUST catch it (a counter-window gate could not).
    bins = [(6, 16)] * 15
    for i in (5, 7, 9):
        bins[i] = (6, 30)
    out = tmp_path / "run"; out.mkdir()
    _write_observer_csv(out / "observer_l_left.csv", bins)
    report = analyze_s4.observer_size_report(out, tmp_path / "ana")

    assert report["invariants"]["all_cells_256B"]  # sizes are still all 256B
    assert report["invariants"]["max_abs_deviation_from_modal"] >= 8
    assert not report["invariants"]["passed"]  # the count leak fails the gate


def test_is_tcp_and_looks_dnp3_classifiers() -> None:
    tcp = _tcp_frame(b"\x05\x64\x0b\x44payload")
    assert analyze_s4._is_tcp(tcp)
    assert analyze_s4._looks_dnp3(tcp)
    arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 40
    assert not analyze_s4._is_tcp(arp)
    assert not analyze_s4._looks_dnp3(arp)


def test_observer_gate_catches_small_correlated_count_leak_via_mi(tmp_path) -> None:
    # A per-bin count leak that is SMALL (within the max_dev bound) but
    # CORRELATED with the delivered response length must be caught by the
    # MI/classifier gate through the wired observer_size_report, not by max_dev.
    from defense4.size.real_size_normalization.offline.pcapio import PcapPacket, write_pcap
    import csv as _csv

    bin_us = 210_000
    payload_sizes = [10, 20, 30, 40, 50]  # 5 distinct response-frame length classes
    n_bins = 72
    cells = []
    responses = []
    for i in range(n_bins):
        base = i * bin_us + 1000
        edge = i == 0 or i == n_bins - 1
        k = 0 if edge else (i - 1) % 5      # class for this interior bin
        extra = 0 if edge else k            # count = 22 + k  (max deviation 4, <= 8)
        t = base
        for _ in range(6):
            cells.append((t, "forward")); t += 100
        for _ in range(16 + extra):
            cells.append((t, "reverse")); t += 100
        if not edge:
            payload = b"\x05\x64" + b"\x00" * payload_sizes[k]  # DNP3-looking, distinct length
            responses.append(PcapPacket(base + 50, _tcp_frame(payload)))

    out = tmp_path / "run"; out.mkdir()
    with open(out / "observer_l_left.csv", "w", newline="", encoding="utf-8") as h:
        w = _csv.DictWriter(h, fieldnames=["timestamp_us", "wire_len", "direction", "cell_counter"], lineterminator="\n")
        w.writeheader()
        for idx, (ts, d) in enumerate(cells):
            w.writerow({"timestamp_us": ts, "wire_len": 256, "direction": d, "cell_counter": idx})
    write_pcap(out / "vision_trusted_output.pcap", responses)

    report = analyze_s4.observer_size_report(out, tmp_path / "ana")

    # The small count leak passes the coarse deviation gate ...
    assert report["invariants"]["passed"]
    assert report["invariants"]["max_abs_deviation_from_modal"] <= 8
    # ... but the MI/classifier leakage gate catches the correlation, failing the run.
    assert report["leakage_gate_passed"] is False
    assert not report["passed"]


def _tcp_frame(payload: bytes) -> bytes:
    src_mac = b"\x02\x44\x00\x00\x00\x02"
    dst_mac = b"\x02\x44\x00\x00\x00\x01"
    src_ip = bytes([10, 44, 0, 2])
    dst_ip = bytes([10, 44, 0, 1])
    tcp = struct.pack(">HHIIBBHHH", 20000, 40000, 1, 1, 5 << 4, 0x18, 8192, 0, 0)
    total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_length, 1, 0x4000, 64, 6, 0, src_ip, dst_ip)
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload
