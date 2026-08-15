"""Deterministic Gate S3 tests for the offline fixed-cell construction."""

from __future__ import annotations

import dataclasses
import struct
from pathlib import Path

import pytest

from .cell_codec import (
    CHUNK_CAPACITY,
    ETHERNET_HEADER_LEN,
    PUBLIC_HEADER_LEN,
    WIRE_SIZE,
    CellDecodeError,
    CellEncodeError,
    CellReplayError,
    DecodeStatus,
    Direction,
    EncodeStatus,
    KeyState,
    PrivateHeader,
    _encrypt_cell,
    _encode_cells_for_stream,
    decode_slot,
    default_policy,
    derive_offline_test_keys,
    encode_slot,
    fixed_public_feature,
    public_header_from_frame,
    serialize_frame_bundle,
)
from .corpus import (
    build_synthetic_corpus,
    extract_captured_transactions,
    frame_bundle_size,
    make_ipv4_tcp_frame,
)
from .pcapio import PcapPacket, read_pcap, write_pcap
from .observer_analysis import build_epoch_features, check_invariants


ROOT = Path(__file__).resolve().parents[4]
SEL_READ = ROOT / "defense4/size/native_parity/evidence/hw_rrc_joint_20260812T223342Z/captures/read.pcap"
SEL_SBO = ROOT / "defense4/size/native_parity/evidence/hw_rrc_joint_20260812T223342Z/captures/sbo.pcap"
ION = ROOT / "defense4/size/native_parity/evidence/ion_comparison/dev_cmp.pcap"
OPEN_DNP3 = ROOT / "defense4/size/evidence/cover_frame_gate/real_channel/evidence/cap_frag.pcapng"
TEST_SEED = "Defense4-S3-public-evidence-v1"


def _states(epoch: int = 7):
    keys = derive_offline_test_keys(TEST_SEED)
    return KeyState.fresh(epoch, keys), KeyState.fresh(epoch, keys)


def _request_frames():
    return (make_ipv4_tcp_frame(49, "request-fixture", "forward"),)


def _encoded_request(epoch: int = 100):
    policy = default_policy()
    tx, _ = _states()
    return policy, encode_slot(_request_frames(), policy, "request", epoch, tx, 3)


def test_policy_has_one_fixed_public_transcript() -> None:
    policy = default_policy()
    assert WIRE_SIZE == 256
    assert CHUNK_CAPACITY == 180
    assert [(s.name, s.direction.value, s.cell_count, s.offsets_us) for s in policy.slots.values()] == [
        ("request", "forward", 4, (0, 250, 500, 750)),
        ("ack", "reverse", 2, (1000, 1250)),
        ("response", "reverse", 14, tuple(range(200000, 203251, 250))),
        ("tail", "forward", 2, (203500, 203750)),
    ]
    assert sum(slot.cell_count for slot in policy.slots.values()) == 22


def test_synthetic_corpus_is_balanced_and_stratified() -> None:
    corpus = build_synthetic_corpus()
    primary = [case for case in corpus if case.primary_rn_l]
    assert len(corpus) == 120
    assert len(primary) == 100
    counts = {length: sum(c.protected_inner_length == length for c in primary) for length in (17, 49, 58, 243, 1574)}
    assert counts == {17: 20, 49: 20, 58: 20, 243: 20, 1574: 20}


def test_all_synthetic_slots_recover_exact_inner_frames() -> None:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_SEED)
    tx = KeyState.fresh(11, keys)
    rx = KeyState.fresh(11, keys)
    for epoch_id, case in enumerate(build_synthetic_corpus(), start=1):
        for slot_name, frames in case.slots.items():
            encoded = encode_slot(frames, policy, slot_name, epoch_id, tx, protected_type=9)
            assert not encoded.overflow, (case.case_id, slot_name, frame_bundle_size(frames))
            assert len(encoded.cells) == policy.slot(slot_name).cell_count
            assert all(len(cell.frame) == WIRE_SIZE for cell in encoded.cells)
            decoded = decode_slot(
                [cell.frame for cell in reversed(encoded.cells)],
                policy,
                slot_name,
                policy.slot(slot_name).direction,
                rx,
            )
            assert decoded.frames == tuple(frames)
            assert decoded.epoch_id == epoch_id


@pytest.mark.parametrize(
    "path,master,relay,prefix",
    [
        (SEL_READ, "192.168.10.1", "192.168.10.7", "sel-read"),
        (SEL_SBO, "192.168.10.1", "192.168.10.7", "sel-sbo"),
        (ION, "192.168.10.1", "192.168.10.8", "ion"),
    ],
)
def test_current_testbed_captured_cases_round_trip(path: Path, master: str, relay: str, prefix: str) -> None:
    cases = extract_captured_transactions(
        path,
        master_ip=master,
        relay_ip=relay,
        case_prefix=prefix,
        limit=3,
    )
    assert cases
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_SEED)
    tx = KeyState.fresh(12, keys)
    rx = KeyState.fresh(12, keys)
    for epoch_id, case in enumerate(cases, start=1):
        for slot_name, frames in case.slots.items():
            encoded = encode_slot(frames, policy, slot_name, epoch_id, tx)
            assert not encoded.overflow, (case.case_id, slot_name)
            decoded = decode_slot(
                [cell.frame for cell in encoded.cells],
                policy,
                slot_name,
                policy.slot(slot_name).direction,
                rx,
            )
            assert decoded.frames == tuple(frames)


def test_large_opendnp3_response_bundle_round_trips_exactly() -> None:
    cases = extract_captured_transactions(
        OPEN_DNP3,
        master_ip="127.0.0.1",
        server_port=20805,
        case_prefix="open",
        limit=4,
    )
    large = max(cases, key=lambda case: frame_bundle_size(case.slots["response"]))
    frames = large.slots["response"]
    policy = default_policy()
    assert frame_bundle_size(frames) <= policy.slot("response").max_stream_len
    tx, rx = _states(13)
    encoded = encode_slot(frames, policy, "response", 1, tx)
    decoded = decode_slot(
        [cell.frame for cell in encoded.cells], policy, "response", Direction.REVERSE, rx
    )
    assert decoded.frames == frames


def test_public_header_does_not_encode_length_type_or_cover_state() -> None:
    policy = default_policy()
    public_prefixes = []
    for frames, protected_type in [
        ((), 0),
        ((make_ipv4_tcp_frame(17, "short", "forward"),), 7),
        ((make_ipv4_tcp_frame(243, "long", "forward"),), 255),
    ]:
        tx, _ = _states(21)
        encoded = encode_slot(frames, policy, "request", 99, tx, protected_type)
        public_prefixes.append(
            [cell.frame[: ETHERNET_HEADER_LEN + PUBLIC_HEADER_LEN] for cell in encoded.cells]
        )
    assert public_prefixes[0] == public_prefixes[1] == public_prefixes[2]


def test_data_and_cover_have_identical_public_structural_features() -> None:
    policy = default_policy()
    results = []
    for frames in ((), _request_frames()):
        tx, _ = _states(22)
        encoded = encode_slot(frames, policy, "request", 5, tx)
        results.append([fixed_public_feature(cell) for cell in encoded.cells])
    assert results[0] == results[1]


def test_reordering_and_exact_duplicate_are_accepted() -> None:
    policy, encoded = _encoded_request()
    _, rx = _states()
    frames = [cell.frame for cell in reversed(encoded.cells)]
    frames.append(frames[0])
    decoded = decode_slot(frames, policy, "request", Direction.FORWARD, rx)
    assert decoded.frames == _request_frames()


@pytest.mark.parametrize("missing_index", range(14))
def test_each_missing_response_cell_fails_closed(missing_index: int) -> None:
    policy = default_policy()
    tx, rx = _states(31 + missing_index)
    frames = (make_ipv4_tcp_frame(1400, f"loss-{missing_index}", "reverse"),)
    encoded = encode_slot(frames, policy, "response", 8, tx)
    surviving = [cell.frame for i, cell in enumerate(encoded.cells) if i != missing_index]
    with pytest.raises(CellDecodeError):
        decode_slot(surviving, policy, "response", Direction.REVERSE, rx)
    assert not rx.received_nonces


@pytest.mark.parametrize("tag_byte", range(16))
def test_each_tag_byte_corruption_fails_closed(tag_byte: int) -> None:
    policy, encoded = _encoded_request(200 + tag_byte)
    damaged = [cell.frame for cell in encoded.cells]
    first = bytearray(damaged[0])
    first[-16 + tag_byte] ^= 0x01
    damaged[0] = bytes(first)
    _, rx = _states()
    with pytest.raises(CellDecodeError):
        decode_slot(damaged, policy, "request", Direction.FORWARD, rx)
    assert not rx.received_nonces


def test_conflicting_duplicate_fails_closed() -> None:
    policy, encoded = _encoded_request()
    conflict = bytearray(encoded.cells[0].frame)
    conflict[-1] ^= 1
    cells = [cell.frame for cell in encoded.cells] + [bytes(conflict)]
    _, rx = _states()
    with pytest.raises(CellDecodeError, match="conflicting duplicate"):
        decode_slot(cells, policy, "request", Direction.FORWARD, rx)
    assert not rx.received_nonces


def test_valid_replay_fails_closed() -> None:
    policy, encoded = _encoded_request()
    cells = [cell.frame for cell in encoded.cells]
    _, rx = _states()
    assert decode_slot(cells, policy, "request", Direction.FORWARD, rx).frames
    with pytest.raises(CellReplayError):
        decode_slot(cells, policy, "request", Direction.FORWARD, rx)


def test_unseen_older_epoch_is_rejected_after_newer_epoch() -> None:
    policy = default_policy()
    tx, rx = _states(38)
    older = encode_slot(_request_frames(), policy, "request", 10, tx)
    newer = encode_slot(_request_frames(), policy, "request", 11, tx)
    assert decode_slot(
        [cell.frame for cell in newer.cells], policy, "request", Direction.FORWARD, rx
    ).epoch_id == 11
    received_before = set(rx.received_nonces)
    with pytest.raises(CellReplayError, match="stale"):
        decode_slot(
            [cell.frame for cell in older.cells], policy, "request", Direction.FORWARD, rx
        )
    assert rx.received_nonces == received_before
    restored = KeyState.fresh(
        38,
        derive_offline_test_keys(TEST_SEED),
        accepted_epochs=rx.accepted_epochs,
    )
    with pytest.raises(CellReplayError, match="stale"):
        decode_slot(
            [cell.frame for cell in older.cells],
            policy,
            "request",
            Direction.FORWARD,
            restored,
        )


def test_authenticated_cells_from_two_counter_windows_cannot_be_spliced() -> None:
    policy = default_policy()
    tx, rx = _states(39)
    first = encode_slot(_request_frames(), policy, "request", 1, tx)
    second = encode_slot(_request_frames(), policy, "request", 1, tx)
    spliced = [first.cells[0].frame, first.cells[1].frame, second.cells[2].frame, second.cells[3].frame]
    with pytest.raises(CellDecodeError, match="counter base"):
        decode_slot(spliced, policy, "request", Direction.FORWARD, rx)
    assert not rx.received_nonces


@pytest.mark.parametrize(
    "offset,replacement",
    [
        (12, b"\x08\x00"),
        (18, b"\x02"),
        (19, b"\x02"),
        (20, b"\x00\x00\x00\x08"),
    ],
)
def test_wrong_public_metadata_fails_closed(offset: int, replacement: bytes) -> None:
    policy, encoded = _encoded_request()
    damaged = [cell.frame for cell in encoded.cells]
    first = bytearray(damaged[0])
    first[offset : offset + len(replacement)] = replacement
    damaged[0] = bytes(first)
    _, rx = _states()
    with pytest.raises(CellDecodeError):
        decode_slot(damaged, policy, "request", Direction.FORWARD, rx)
    assert not rx.received_nonces


def test_wrong_direction_and_wire_size_fail_closed() -> None:
    policy, encoded = _encoded_request()
    frames = [cell.frame for cell in encoded.cells]
    _, rx = _states()
    with pytest.raises(CellDecodeError):
        decode_slot(frames, policy, "request", Direction.REVERSE, rx)
    with pytest.raises(CellDecodeError):
        public_header_from_frame(frames[0][:-1], policy)


@pytest.mark.parametrize(
    "field,value",
    [
        ("slot_id", 2),
        ("cell_count", 5),
        ("cell_index", 4),
        ("reserved", 1),
        ("payload_len", CHUNK_CAPACITY + 1),
        ("payload_offset", 4 * CHUNK_CAPACITY + 1),
        ("flags", 2),
    ],
)
def test_aead_valid_malformed_private_metadata_fails_closed(field: str, value: int) -> None:
    policy = default_policy()
    slot = policy.slot("request")
    tx, rx = _states(40)
    frames = []
    for index in range(slot.cell_count):
        private = PrivateHeader(
            epoch_id=1,
            slot_id=slot.slot_id,
            flags=0,
            cell_index=index,
            cell_count=slot.cell_count,
            frame_count=0,
            serialized_stream_len=0,
            payload_offset=index * CHUNK_CAPACITY,
            payload_len=0,
            protected_type=0,
            reserved=0,
        )
        if index == 0:
            private = dataclasses.replace(private, **{field: value})
        counter = tx.next_counter(Direction.FORWARD)
        frames.append(
            _encrypt_cell(policy, Direction.FORWARD, tx, counter, private, b"")
        )
    with pytest.raises(CellDecodeError):
        decode_slot(frames, policy, "request", Direction.FORWARD, rx)
    assert not rx.received_nonces


@pytest.mark.parametrize("frame_length", [0, 13, 1519])
def test_aead_valid_malformed_frame_bundle_length_fails_closed(frame_length: int) -> None:
    policy = default_policy()
    slot = policy.slot("response")
    tx, rx = _states(40)
    stream = struct.pack(">I", frame_length) + b"x" * frame_length
    cells = _encode_cells_for_stream(
        stream=stream,
        frame_count=1,
        status=EncodeStatus.DATA,
        policy=policy,
        slot=slot,
        epoch_id=1,
        key_state=tx,
        protected_type=0,
    )
    with pytest.raises(CellDecodeError, match="Ethernet frame length"):
        decode_slot(
            [cell.frame for cell in cells], policy, "response", Direction.REVERSE, rx
        )
    assert not rx.received_nonces


def test_overflow_emits_fixed_cover_without_partial_output() -> None:
    policy = default_policy()
    frames = (b"x" * 1518, b"y" * 999)
    assert len(serialize_frame_bundle(frames)) > policy.slot("response").max_stream_len
    tx, rx = _states(41)
    encoded = encode_slot(frames, policy, "response", 1, tx, protected_type=13)
    assert encoded.status is EncodeStatus.OVERFLOW
    assert encoded.overflow
    assert len(encoded.cells) == 14
    decoded = decode_slot(
        [cell.frame for cell in encoded.cells], policy, "response", Direction.REVERSE, rx
    )
    assert decoded.status is DecodeStatus.COVER
    assert decoded.frames == ()


def test_encoder_rejects_nonce_reuse_after_counter_restart() -> None:
    policy = default_policy()
    tx, _ = _states(42)
    encode_slot(_request_frames(), policy, "request", 1, tx)
    tx.tx_counters[Direction.FORWARD] = 0
    emitted_before = set(tx.emitted_nonces)
    with pytest.raises(CellEncodeError, match="reuse"):
        encode_slot(_request_frames(), policy, "request", 2, tx)
    assert tx.emitted_nonces == emitted_before


def test_directional_key_and_nonce_spaces_are_distinct() -> None:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_SEED)
    tx = KeyState.fresh(43, keys)
    forward = encode_slot((), policy, "request", 1, tx)
    reverse = encode_slot((), policy, "ack", 1, tx)
    assert forward.cells[0].cell_counter == reverse.cells[0].cell_counter == 0
    assert keys.forward != keys.reverse
    assert forward.cells[0].frame != reverse.cells[0].frame


def test_deterministic_offline_vector_is_byte_stable() -> None:
    policy = default_policy()
    vectors = []
    for _ in range(2):
        tx, _ = _states(51)
        result = encode_slot(_request_frames(), policy, "request", 77, tx, 5)
        vectors.append([cell.frame for cell in result.cells])
    assert vectors[0] == vectors[1]


@pytest.mark.parametrize("length", [0, 13, 1519])
def test_invalid_inner_ethernet_lengths_are_rejected(length: int) -> None:
    with pytest.raises(CellEncodeError):
        serialize_frame_bundle((b"x" * length,))


def test_pcap_writer_reader_round_trip_is_byte_stable(tmp_path: Path) -> None:
    policy, encoded = _encoded_request()
    packets = [
        PcapPacket(1_700_000_000_000_000 + cell.offset_us, cell.frame)
        for cell in encoded.cells
    ]
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"
    write_pcap(first, packets)
    recovered = list(read_pcap(first))
    write_pcap(second, recovered)
    assert recovered == packets
    assert first.read_bytes() == second.read_bytes()


def test_counter_stride_is_normalized_per_direction() -> None:
    rows = []
    for epoch, forward_start, reverse_start in (("1", 0, 0), ("2", 6, 16)):
        for order, (direction, counter) in enumerate(
            (("forward", forward_start), ("forward", forward_start + 1),
             ("reverse", reverse_start), ("reverse", reverse_start + 1))
        ):
            rows.append(
                {
                    "capture_epoch_index": epoch,
                    "direction": direction,
                    "wire_len": "256",
                    "slot_name": "test",
                    "slot_offset_us": str(order),
                    "cell_index": str(order % 2),
                    "cell_counter": str(counter),
                    "policy_id": "1",
                    "fragment_flag": "0",
                    "retry_or_error_flag": "0",
                    "_row_order": str(len(rows)),
                }
            )
    labels = [
        {
            "capture_epoch_index": epoch,
            "protected_inner_length": length,
            "source_transaction_id": epoch,
            "primary_rn_l": "1",
            "status": "success",
        }
        for epoch, length in (("1", "17"), ("2", "49"))
    ]
    features, _ = build_epoch_features(rows, labels)
    assert features[0]["counter_stride_pattern"] == "forward:1;reverse:1"
    assert features[0]["counter_stride_pattern"] == features[1]["counter_stride_pattern"]
    assert check_invariants(features)["passed"]


def test_observer_invariant_fails_when_visible_mac_varies() -> None:
    rows = []
    for epoch, src_mac in (("1", "02:00:00:00:00:01"), ("2", "02:00:00:00:00:09")):
        rows.append(
            {
                "capture_epoch_index": epoch,
                "direction": "forward",
                "wire_len": "256",
                "slot_name": "request",
                "slot_offset_us": "0",
                "cell_index": "0",
                "cell_counter": epoch,
                "policy_id": "1",
                "src_mac": src_mac,
                "dst_mac": "02:00:00:00:00:02",
                "fragment_flag": "0",
                "retry_or_error_flag": "0",
                "_row_order": epoch,
            }
        )
    labels = [
        {
            "capture_epoch_index": epoch,
            "protected_inner_length": length,
            "source_transaction_id": epoch,
            "primary_rn_l": "1",
            "status": "success",
        }
        for epoch, length in (("1", "17"), ("2", "49"))
    ]
    features, _ = build_epoch_features(rows, labels)
    report = check_invariants(features)
    assert not report["passed"]
    assert "fixed_public_metadata_vector" in report["failed"]
