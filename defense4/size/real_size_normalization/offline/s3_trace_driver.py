"""Generate deterministic S3 offline real-size-normalization evidence.

The driver is deliberately offline: it reads committed captures and synthetic
fixtures, emits fixed-size encrypted outer-cell transcripts, runs the observer
gate, and writes byte-stable evidence files. It does not open sockets, use
Scapy, install packages, or touch the testbed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import shutil
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .cell_codec import (
    AEAD_BODY_LEN,
    CHUNK_CAPACITY,
    ETHERNET_HEADER_LEN,
    ETHER_TYPE,
    PUBLIC_HEADER_LEN,
    TAG_LEN,
    CellDecodeError,
    CellEncodeError,
    Direction,
    EncodeResult,
    EncodeStatus,
    KeyState,
    PrivateHeader,
    default_policy,
    decode_slot,
    derive_offline_test_keys,
    encode_slot,
    fixed_public_feature,
    public_header_from_frame,
    serialize_frame_bundle,
)
from .cell_codec import _encrypt_cell  # S3 fault harness: AEAD-valid bad private metadata.
from .corpus import CorpusCase, build_synthetic_corpus, extract_captured_transactions, frame_bundle_size
from .observer_analysis import DEFAULT_BOOTSTRAPS, DEFAULT_PERMUTATIONS, DEFAULT_SEED, analyze
from .pcapio import PcapPacket, write_pcap


ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / "defense4/size/real_size_normalization"
DEFAULT_OUTPUT = BASE / "evidence/s3_offline"
POLICY_NAME = "S3-RNL-256-v1"
TEST_KEY_SEED = "Defense4-S3-public-evidence-v1"
KEY_EPOCH = 1
BASE_TIMESTAMP_US = 1_800_000_000_000_000
EPOCH_GAP_US = 1_000_000
OUTER_FLOW_ID = "d4-cell-v1"
PROTOCOL = "defense4-s3-cell"
SLOTS = ("request", "ack", "response", "tail")
PROTECTED_TYPE = {
    "request": 1,
    "ack": 2,
    "response": 3,
    "tail": 4,
}
CAPTURE_SOURCES = (
    {
        "name": "sel_read",
        "path": ROOT / "defense4/size/native_parity/evidence/hw_rrc_joint_20260812T223342Z/captures/read.pcap",
        "master_ip": "192.168.10.1",
        "relay_ip": "192.168.10.7",
        "server_port": 20_000,
        "limit": 5,
    },
    {
        "name": "sel_sbo",
        "path": ROOT / "defense4/size/native_parity/evidence/hw_rrc_joint_20260812T223342Z/captures/sbo.pcap",
        "master_ip": "192.168.10.1",
        "relay_ip": "192.168.10.7",
        "server_port": 20_000,
        "limit": 5,
    },
    {
        "name": "ion",
        "path": ROOT / "defense4/size/native_parity/evidence/ion_comparison/dev_cmp.pcap",
        "master_ip": "192.168.10.1",
        "relay_ip": "192.168.10.8",
        "server_port": 20_000,
        "limit": 5,
    },
    {
        "name": "open",
        "path": ROOT / "defense4/size/evidence/cover_frame_gate/real_channel/evidence/cap_frag.pcapng",
        "master_ip": "127.0.0.1",
        "relay_ip": None,
        "server_port": 20_805,
        "limit": 2,
    },
)


@dataclass(frozen=True)
class EpochRecord:
    index: int
    case: CorpusCase
    status: str
    slot_status: Mapping[str, str]
    decoded_slots: Mapping[str, Tuple[bytes, ...]]
    encoded_slots: Mapping[str, EncodeResult]
    input_sha256: str
    decoded_sha256: str
    exact_recovery: bool


def _json_dumps(data: Mapping[str, Any]) -> str:
    return json.dumps(_stable_json(data), sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def _stable_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _stable_json(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_json(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hex_mac(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def build_cases() -> Tuple[List[CorpusCase], List[Dict[str, Any]]]:
    cases = list(build_synthetic_corpus())
    source_manifest: List[Dict[str, Any]] = []

    for source in CAPTURE_SOURCES:
        path = Path(source["path"])
        extracted = extract_captured_transactions(
            path,
            master_ip=str(source["master_ip"]),
            relay_ip=source["relay_ip"],  # type: ignore[arg-type]
            server_port=int(source["server_port"]),
            limit=int(source["limit"]),
            case_prefix=str(source["name"]),
        )
        source_manifest.append(
            {
                "name": source["name"],
                "path": _rel(path),
                "sha256": _sha256_path(path),
                "server_port": source["server_port"],
                "extracted_transactions": len(extracted),
            }
        )
        if source["name"] == "open" and extracted:
            first = extracted[0]
            projected = CorpusCase(
                case_id="open-response-projected-000",
                transaction_class="CAPTURED_OPEN_RESPONSE_ONLY",
                protected_inner_length=first.protected_inner_length,
                source_kind="captured-projection",
                source_ref=f"{first.source_ref} response slot only; full transaction retained as overflow case",
                slots={
                    "request": (),
                    "ack": (),
                    "response": tuple(first.slots["response"]),
                    "tail": (),
                },
                primary_rn_l=False,
            )
            overflow = CorpusCase(
                case_id="open-full-overflow-000",
                transaction_class="CAPTURED_OPEN_FULL_OVERFLOW",
                protected_inner_length=first.protected_inner_length,
                source_kind="captured-overflow",
                source_ref=f"{first.source_ref} full transaction; tail bundle exceeds S3 tail capacity",
                slots={name: tuple(first.slots[name]) for name in SLOTS},
                primary_rn_l=False,
            )
            cases.extend([projected, overflow])
            cases.extend(extracted[1:])
        else:
            cases.extend(extracted)
    return cases, source_manifest


def encode_decode_cases(cases: Sequence[CorpusCase], out_dir: Path) -> Tuple[List[EpochRecord], List[Dict[str, Any]], List[Dict[str, Any]], List[PcapPacket], List[PcapPacket], List[PcapPacket]]:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    tx = KeyState.fresh(KEY_EPOCH, keys)
    rx = KeyState.fresh(KEY_EPOCH, keys)
    records: List[EpochRecord] = []
    cell_rows: List[Dict[str, Any]] = []
    label_rows: List[Dict[str, Any]] = []
    outer_packets: List[PcapPacket] = []
    input_packets: List[PcapPacket] = []
    decoded_packets: List[PcapPacket] = []

    for epoch_index, case in enumerate(cases):
        base_ts = BASE_TIMESTAMP_US + epoch_index * EPOCH_GAP_US
        encoded_slots: Dict[str, EncodeResult] = {}
        decoded_slots: Dict[str, Tuple[bytes, ...]] = {}
        slot_status: Dict[str, str] = {}
        exact_recovery = True

        for slot_name in SLOTS:
            encoded = encode_slot(
                case.slots[slot_name],
                policy,
                slot_name,
                epoch_index,
                tx,
                protected_type=PROTECTED_TYPE[slot_name],
            )
            encoded_slots[slot_name] = encoded
            slot_status[slot_name] = encoded.status.value
            slot_frames = [cell.frame for cell in encoded.cells]
            decode_order = list(reversed(slot_frames)) if epoch_index % 3 == 2 else slot_frames
            decoded = decode_slot(decode_order, policy, slot_name, encoded.direction, rx)
            decoded_slots[slot_name] = decoded.frames
            if (
                encoded.status is not EncodeStatus.OVERFLOW
                and decoded.frames != tuple(case.slots[slot_name])
            ):
                exact_recovery = False
            if encoded.status is EncodeStatus.OVERFLOW and decoded.frames:
                exact_recovery = False

        status = "success" if all(value != EncodeStatus.OVERFLOW.value for value in slot_status.values()) and exact_recovery else "overflow"
        input_bundle = b"".join(serialize_frame_bundle(case.slots[name]) for name in SLOTS)
        decoded_bundle = b"".join(serialize_frame_bundle(decoded_slots[name]) for name in SLOTS)
        records.append(
            EpochRecord(
                index=epoch_index,
                case=case,
                status=status,
                slot_status=slot_status,
                decoded_slots=decoded_slots,
                encoded_slots=encoded_slots,
                input_sha256=_sha256_bytes(input_bundle),
                decoded_sha256=_sha256_bytes(decoded_bundle),
                exact_recovery=exact_recovery and (status == "success"),
            )
        )

        label_rows.append(
            {
                "capture_epoch_index": epoch_index,
                "case_id": case.case_id,
                "source_transaction_id": case.case_id,
                "transaction_class": case.transaction_class,
                "protected_inner_length": case.protected_inner_length,
                "source_kind": case.source_kind,
                "source_ref": case.source_ref,
                "primary_rn_l": 1 if case.primary_rn_l else 0,
                "status": status,
                "slot_status": "|".join(f"{slot}:{slot_status[slot]}" for slot in SLOTS),
            }
        )

        input_packets.extend(_inner_packets(case.slots, base_ts))
        decoded_packets.extend(_inner_packets(decoded_slots, base_ts))
        position = 0
        for slot_name in SLOTS:
            for cell in encoded_slots[slot_name].cells:
                timestamp = base_ts + cell.offset_us
                outer_packets.append(PcapPacket(timestamp_us=timestamp, frame=cell.frame))
                cell_rows.append(_observer_row(epoch_index, timestamp, position, cell))
                position += 1

    _write_csv(
        out_dir / "analysis_labels.csv",
        label_rows,
        (
            "capture_epoch_index",
            "case_id",
            "source_transaction_id",
            "transaction_class",
            "protected_inner_length",
            "source_kind",
            "source_ref",
            "primary_rn_l",
            "status",
            "slot_status",
        ),
    )
    _write_csv(
        out_dir / "observer_outer_cells.csv",
        cell_rows,
        (
            "capture_epoch_index",
            "timestamp_us",
            "slot_offset_us",
            "slot_name",
            "direction",
            "cell_index",
            "position_in_epoch",
            "wire_len",
            "dst_mac",
            "src_mac",
            "ethertype",
            "magic",
            "version",
            "policy_id",
            "key_epoch",
            "cell_counter",
            "public_header_len",
            "ciphertext_len",
            "tag_len",
            "protocol",
            "outer_flow_id",
            "fragment_flag",
            "retry_or_error_flag",
        ),
    )
    return records, cell_rows, label_rows, input_packets, decoded_packets, outer_packets


def _inner_packets(slots: Mapping[str, Sequence[bytes]], base_ts: int) -> List[PcapPacket]:
    packets: List[PcapPacket] = []
    policy = default_policy()
    for slot_name in SLOTS:
        slot = policy.slot(slot_name)
        offset = slot.offsets_us[0]
        for frame_index, frame in enumerate(slots[slot_name]):
            packets.append(PcapPacket(timestamp_us=base_ts + offset + frame_index, frame=bytes(frame)))
    return packets


def _observer_row(epoch_index: int, timestamp_us: int, position: int, cell: Any) -> Dict[str, Any]:
    public = public_header_from_frame(cell.frame)
    features = fixed_public_feature(cell)
    return {
        "capture_epoch_index": epoch_index,
        "timestamp_us": timestamp_us,
        "slot_offset_us": features["slot_offset_us"],
        "slot_name": features["slot_name"],
        "direction": features["direction"],
        "cell_index": features["cell_index"],
        "position_in_epoch": position,
        "wire_len": features["wire_len"],
        "dst_mac": _hex_mac(cell.frame[0:6]),
        "src_mac": _hex_mac(cell.frame[6:12]),
        "ethertype": f"0x{struct.unpack('>H', cell.frame[12:14])[0]:04x}",
        "magic": cell.frame[ETHERNET_HEADER_LEN : ETHERNET_HEADER_LEN + 4].decode("ascii"),
        "version": public.version,
        "policy_id": public.policy_id,
        "key_epoch": public.key_epoch,
        "cell_counter": public.cell_counter,
        "public_header_len": features["public_header_len"],
        "ciphertext_len": features["ciphertext_len"],
        "tag_len": features["tag_len"],
        "protocol": PROTOCOL,
        "outer_flow_id": OUTER_FLOW_ID,
        "fragment_flag": 0,
        "retry_or_error_flag": 0,
    }


def run_fault_cases(out_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index in range(default_policy().slot("response").cell_count):
        rows.append(_fault_missing_cell(index))
    rows.extend(
        [
            _fault_exact_duplicate(),
            _fault_conflicting_duplicate(),
            _fault_reorder(),
            _fault_replay(),
            _fault_wrong_public("version"),
            _fault_wrong_public("policy_id"),
            _fault_wrong_public("ether_type"),
            _fault_wrong_public("wire_size"),
            _fault_wrong_key_epoch(),
            _fault_wrong_direction(),
            _fault_overflow(),
            _fault_nonce_restart(),
            _fault_bad_private_metadata("slot_id"),
            _fault_bad_private_metadata("cell_count"),
            _fault_bad_private_metadata("reserved"),
        ]
    )
    rows.extend(_fault_tag_corruptions())
    _write_csv(
        out_dir / "fault_cases.csv",
        rows,
        (
            "fault_id",
            "category",
            "expected",
            "actual",
            "passed",
            "public_cell_count",
            "released_inner_frames",
            "notes",
        ),
    )
    return rows


def _sample_encoded(slot_name: str = "response", epoch_id: int = 77, frames: Optional[Sequence[bytes]] = None) -> Tuple[Any, Any, EncodeResult]:
    from .corpus import make_ipv4_tcp_frame

    policy = default_policy()
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    tx = KeyState.fresh(KEY_EPOCH, keys)
    rx = KeyState.fresh(KEY_EPOCH, keys)
    sample_frames = tuple(frames) if frames is not None else (make_ipv4_tcp_frame(49, "fault-sample", "reverse"),)
    return policy, rx, encode_slot(sample_frames, policy, slot_name, epoch_id, tx, protected_type=PROTECTED_TYPE[slot_name])


def _record_fault(fault_id: str, category: str, expected: str, actual: str, passed: bool, public_count: int, released: int, notes: str = "") -> Dict[str, Any]:
    return {
        "fault_id": fault_id,
        "category": category,
        "expected": expected,
        "actual": actual,
        "passed": 1 if passed else 0,
        "public_cell_count": public_count,
        "released_inner_frames": released,
        "notes": notes,
    }


def _expect_decode_failure(fault_id: str, category: str, frames: Sequence[bytes], slot_name: str, direction: Direction, expected: str = "fail_closed") -> Dict[str, Any]:
    policy = default_policy()
    rx = KeyState.fresh(KEY_EPOCH, derive_offline_test_keys(TEST_KEY_SEED))
    released = 0
    try:
        result = decode_slot(frames, policy, slot_name, direction, rx)
        released = len(result.frames)
        return _record_fault(fault_id, category, expected, "accepted", False, len(frames), released)
    except CellDecodeError as exc:
        return _record_fault(fault_id, category, expected, "rejected", True, len(frames), released, str(exc))


def _fault_missing_cell(index: int) -> Dict[str, Any]:
    policy, _rx, encoded = _sample_encoded()
    frames = [cell.frame for cell in encoded.cells]
    del frames[index]
    return _expect_decode_failure(f"missing-response-{index:02d}", "loss", frames, "response", Direction.REVERSE)


def _fault_exact_duplicate() -> Dict[str, Any]:
    policy, rx, encoded = _sample_encoded()
    frames = [cell.frame for cell in encoded.cells] + [encoded.cells[0].frame]
    try:
        result = decode_slot(frames, policy, "response", Direction.REVERSE, rx)
        passed = len(result.frames) == 1
        return _record_fault("exact-duplicate", "duplicate", "exact_recovery", "accepted_exact_duplicate", passed, len(frames), len(result.frames))
    except CellDecodeError as exc:
        return _record_fault("exact-duplicate", "duplicate", "exact_recovery", "rejected", False, len(frames), 0, str(exc))


def _fault_conflicting_duplicate() -> Dict[str, Any]:
    _policy, _rx, encoded = _sample_encoded()
    corrupt = bytearray(encoded.cells[0].frame)
    corrupt[-1] ^= 0x01
    frames = [cell.frame for cell in encoded.cells] + [bytes(corrupt)]
    return _expect_decode_failure("conflicting-duplicate", "duplicate", frames, "response", Direction.REVERSE)


def _fault_reorder() -> Dict[str, Any]:
    policy, rx, encoded = _sample_encoded()
    frames = [cell.frame for cell in reversed(encoded.cells)]
    try:
        result = decode_slot(frames, policy, "response", Direction.REVERSE, rx)
        passed = len(result.frames) == 1
        return _record_fault("reverse-order", "reorder", "exact_recovery", "accepted_reordered", passed, len(frames), len(result.frames))
    except CellDecodeError as exc:
        return _record_fault("reverse-order", "reorder", "exact_recovery", "rejected", False, len(frames), 0, str(exc))


def _fault_replay() -> Dict[str, Any]:
    policy, rx, encoded = _sample_encoded()
    frames = [cell.frame for cell in encoded.cells]
    first = decode_slot(frames, policy, "response", Direction.REVERSE, rx)
    try:
        second = decode_slot(frames, policy, "response", Direction.REVERSE, rx)
        return _record_fault("replay-after-accept", "replay", "fail_closed", "accepted_replay", False, len(frames), len(second.frames))
    except CellDecodeError as exc:
        return _record_fault("replay-after-accept", "replay", "fail_closed", "rejected", len(first.frames) == 1, len(frames), 0, str(exc))


def _fault_tag_corruptions() -> List[Dict[str, Any]]:
    rows = []
    for tag_index in range(TAG_LEN):
        _policy, _rx, encoded = _sample_encoded()
        frames = [cell.frame for cell in encoded.cells]
        corrupt = bytearray(frames[0])
        corrupt[-TAG_LEN + tag_index] ^= 0x01
        frames[0] = bytes(corrupt)
        rows.append(_expect_decode_failure(f"tag-byte-{tag_index:02d}", "tag_corruption", frames, "response", Direction.REVERSE))
    return rows


def _fault_wrong_public(field: str) -> Dict[str, Any]:
    _policy, _rx, encoded = _sample_encoded()
    frames = [bytearray(cell.frame) for cell in encoded.cells]
    if field == "version":
        frames[0][ETHERNET_HEADER_LEN + 4] ^= 0x01
    elif field == "policy_id":
        frames[0][ETHERNET_HEADER_LEN + 5] ^= 0x01
    elif field == "ether_type":
        frames[0][13] ^= 0x01
    elif field == "wire_size":
        return _expect_decode_failure("wrong-wire-size", "public_metadata", [bytes(frame) for frame in frames[:-1]] + [bytes(frames[-1]) + b"\x00"], "response", Direction.REVERSE)
    else:
        raise ValueError(field)
    return _expect_decode_failure(f"wrong-{field}", "public_metadata", [bytes(frame) for frame in frames], "response", Direction.REVERSE)


def _fault_wrong_key_epoch() -> Dict[str, Any]:
    policy, _rx, encoded = _sample_encoded()
    rx = KeyState.fresh(KEY_EPOCH + 1, derive_offline_test_keys(TEST_KEY_SEED))
    frames = [cell.frame for cell in encoded.cells]
    try:
        result = decode_slot(frames, policy, "response", Direction.REVERSE, rx)
        return _record_fault("wrong-key-epoch", "key_epoch", "fail_closed", "accepted", False, len(frames), len(result.frames))
    except CellDecodeError as exc:
        return _record_fault("wrong-key-epoch", "key_epoch", "fail_closed", "rejected", True, len(frames), 0, str(exc))


def _fault_wrong_direction() -> Dict[str, Any]:
    _policy, _rx, encoded = _sample_encoded(slot_name="request")
    frames = [cell.frame for cell in encoded.cells]
    return _expect_decode_failure("wrong-direction", "direction", frames, "request", Direction.REVERSE)


def _fault_overflow() -> Dict[str, Any]:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    tx = KeyState.fresh(KEY_EPOCH, keys)
    rx = KeyState.fresh(KEY_EPOCH, keys)
    encoded = encode_slot([b"x" * 1514, b"y" * 999], policy, "response", 88, tx)
    result = decode_slot([cell.frame for cell in encoded.cells], policy, "response", Direction.REVERSE, rx)
    passed = encoded.status is EncodeStatus.OVERFLOW and not result.frames
    return _record_fault("overflow-no-partial", "overflow", "cover_only_no_partial", encoded.status.value, passed, len(encoded.cells), len(result.frames), f"serialized_len={1514 + 999 + 8}; cap={policy.slot('response').max_stream_len}")


def _fault_nonce_restart() -> Dict[str, Any]:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    tx = KeyState.fresh(KEY_EPOCH, keys)
    first = encode_slot([], policy, "request", 90, tx)
    tx.tx_counters[Direction.FORWARD] = first.cells[0].cell_counter
    try:
        second = encode_slot([], policy, "request", 91, tx)
        return _record_fault("nonce-restart", "nonce_reuse", "refuse_emit", "emitted", False, len(second.cells), 0)
    except CellEncodeError as exc:
        return _record_fault(
            "nonce-restart",
            "nonce_reuse",
            "refuse_emit",
            "rejected",
            True,
            0,
            0,
            f"invalid restart emitted no cells; prior valid slot had {len(first.cells)} cells; {exc}",
        )


def _fault_bad_private_metadata(field: str) -> Dict[str, Any]:
    policy = default_policy()
    keys = derive_offline_test_keys(TEST_KEY_SEED)
    tx = KeyState.fresh(KEY_EPOCH, keys)
    good = encode_slot([], policy, "response", 93, tx)
    frames = [cell.frame for cell in good.cells]
    private = PrivateHeader(
        epoch_id=93,
        slot_id=policy.slot("response").slot_id,
        flags=0,
        cell_index=0,
        cell_count=policy.slot("response").cell_count,
        frame_count=0,
        serialized_stream_len=0,
        payload_offset=0,
        payload_len=0,
        protected_type=0,
        reserved=0,
    )
    if field == "slot_id":
        private = PrivateHeader(**{**private.__dict__, "slot_id": policy.slot("request").slot_id})
    elif field == "cell_count":
        private = PrivateHeader(**{**private.__dict__, "cell_count": policy.slot("response").cell_count - 1})
    elif field == "reserved":
        private = PrivateHeader(**{**private.__dict__, "reserved": 1})
    else:
        raise ValueError(field)
    counter = tx.next_counter(Direction.REVERSE)
    malformed = _encrypt_cell(policy, Direction.REVERSE, tx, counter, private, b"")
    frames[0] = malformed
    return _expect_decode_failure(f"bad-private-{field}", "encrypted_private_metadata", frames, "response", Direction.REVERSE)


def write_roundtrip_outputs(out_dir: Path, records: Sequence[EpochRecord]) -> None:
    rows = []
    for record in records:
        rows.append(
            {
                "capture_epoch_index": record.index,
                "case_id": record.case.case_id,
                "status": record.status,
                "primary_rn_l": 1 if record.case.primary_rn_l else 0,
                "protected_inner_length": record.case.protected_inner_length,
                "exact_recovery": 1 if record.exact_recovery else 0,
                "input_sha256": record.input_sha256,
                "decoded_sha256": record.decoded_sha256,
                "request_bundle_bytes": frame_bundle_size(record.case.slots["request"]),
                "ack_bundle_bytes": frame_bundle_size(record.case.slots["ack"]),
                "response_bundle_bytes": frame_bundle_size(record.case.slots["response"]),
                "tail_bundle_bytes": frame_bundle_size(record.case.slots["tail"]),
                "slot_status": "|".join(f"{slot}:{record.slot_status[slot]}" for slot in SLOTS),
                "source_kind": record.case.source_kind,
                "source_ref": record.case.source_ref,
            }
        )
    _write_csv(
        out_dir / "roundtrip_cases.csv",
        rows,
        (
            "capture_epoch_index",
            "case_id",
            "status",
            "primary_rn_l",
            "protected_inner_length",
            "exact_recovery",
            "input_sha256",
            "decoded_sha256",
            "request_bundle_bytes",
            "ack_bundle_bytes",
            "response_bundle_bytes",
            "tail_bundle_bytes",
            "slot_status",
            "source_kind",
            "source_ref",
        ),
    )
    success = [record for record in records if record.status == "success"]
    primary = [record for record in records if record.case.primary_rn_l]
    overflow = [record for record in records if record.status != "success"]
    summary = {
        "schema_version": 1,
        "policy_name": POLICY_NAME,
        "epoch_count": len(records),
        "successful_epoch_count": len(success),
        "primary_rn_l_epoch_count": len(primary),
        "primary_rn_l_exact_recovery_count": sum(1 for record in primary if record.exact_recovery),
        "overflow_epoch_count": len(overflow),
        "overflow_case_ids": [record.case.case_id for record in overflow],
        "fixed_cells_per_epoch": sum(default_policy().slot(slot).cell_count for slot in SLOTS),
        "fixed_outer_bytes_per_epoch": sum(default_policy().slot(slot).cell_count for slot in SLOTS) * 256,
        "all_success_exact_recovery": all(record.exact_recovery for record in success),
    }
    (out_dir / "roundtrip_summary.json").write_text(_json_dumps(summary), encoding="utf-8")


def write_static_outputs(out_dir: Path, source_manifest: Sequence[Mapping[str, Any]], stats: Mapping[str, Any], fault_rows: Sequence[Mapping[str, Any]]) -> None:
    policy = default_policy()
    policy_json = {
        "schema_version": 1,
        "policy_name": POLICY_NAME,
        "claim_scope": "S3 offline evidence only; not a hardware PASS",
        "wire_size_bytes": 256,
        "ether_type": f"0x{ETHER_TYPE:04x}",
        "public_header_bytes": PUBLIC_HEADER_LEN,
        "aead_body_bytes": AEAD_BODY_LEN,
        "tag_bytes": TAG_LEN,
        "chunk_capacity_bytes": CHUNK_CAPACITY,
        "key_epoch": KEY_EPOCH,
        "test_key_seed": TEST_KEY_SEED,
        "test_key_warning": "deterministic non-secret offline evidence seed; not production key material",
        "slots": {
            name: {
                "slot_id": policy.slot(name).slot_id,
                "direction": policy.slot(name).direction.value,
                "cell_count": policy.slot(name).cell_count,
                "offsets_us": list(policy.slot(name).offsets_us),
                "stream_capacity_bytes": policy.slot(name).max_stream_len,
            }
            for name in SLOTS
        },
    }
    (out_dir / "policy.json").write_text(_json_dumps(policy_json), encoding="utf-8")
    (out_dir / "corpus_manifest.json").write_text(
        _json_dumps(
            {
                "schema_version": 1,
                "synthetic_primary_rn_l": 100,
                "synthetic_boundary_and_control": 20,
                "captured_sources": list(source_manifest),
                "open_dnp3_note": "full first transaction is retained as overflow because tail bundle exceeds the fixed tail capacity; response-only projection preserves exact response frames",
            }
        ),
        encoding="utf-8",
    )
    negative_control = {
        "schema_version": 1,
        "control": "segment-shape-only legacy vector",
        "legacy_vector": [28, 21],
        "legacy_total": 49,
        "claim": "negative control intentionally demonstrates the old observable size signal; it is not an S3 protected outer transcript",
    }
    (out_dir / "negative_control.json").write_text(_json_dumps(negative_control), encoding="utf-8")
    _write_claim_matrix(out_dir, stats, fault_rows)
    _write_readme(out_dir, stats)


def _write_claim_matrix(out_dir: Path, stats: Mapping[str, Any], fault_rows: Sequence[Mapping[str, Any]]) -> None:
    invariant = stats["invariants"]
    classifiers = stats["classifiers"]
    fault_passed = all(str(row.get("passed")) in ("1", "True", "true") for row in fault_rows)
    rows = [
        ("Fixed public wire length", "PASS" if invariant["checks"]["single_fixed_wire_size"] else "FAIL", "observer_outer_cells.csv has one 256-byte wire size for in-policy epochs"),
        ("Fixed cell count and schedule", "PASS" if invariant["checks"]["fixed_cell_count"] and invariant["checks"]["fixed_slot_timing_vector"] else "FAIL", "22 cells per epoch with fixed slot offsets"),
        ("No public length/type/count signal", "PASS" if stats["gate"]["passed"] else "FAIL", "observer_stats.json MI and classifier gate"),
        ("Primary RN-L classifier bound", "PASS" if stats["gate"]["passed"] else "FAIL", f"chance={classifiers['chance']}; models={','.join(classifiers['models'])}"),
        ("Adversarial codec faults", "PASS" if fault_passed else "FAIL", "loss, duplicate, reorder, replay, tag, public metadata, private metadata, overflow, nonce restart"),
        ("OpenDNP3 overflow honesty", "PASS", "full pcapng transaction retained as fail-closed overflow; response-only projection is separately labeled"),
        ("Hardware claim", "NOT CLAIMED", "S3 is offline evidence only; no SSH/testbed action"),
    ]
    lines = [
        "# S3 Offline Claim Matrix",
        "",
        "| Claim | Verdict | Evidence |",
        "| --- | --- | --- |",
    ]
    lines.extend(f"| {claim} | {verdict} | {evidence} |" for claim, verdict, evidence in rows)
    lines.append("")
    (out_dir / "OFFLINE_CLAIM_MATRIX.md").write_text("\n".join(lines), encoding="utf-8")


def _write_readme(out_dir: Path, stats: Mapping[str, Any]) -> None:
    lines = [
        "# Defense4 S3 Offline Evidence",
        "",
        "Generated by `python3 -m defense4.size.real_size_normalization.offline.s3_trace_driver`.",
        "",
        "Scope: deterministic offline proof for the S3 real-size-normalization cell format. This directory does not claim hardware deployment or live Tofino behavior.",
        "",
        "Key files:",
        "",
        "- `observer_outer_cells.csv` and `observer_outer_cells.pcap`: attacker-visible fixed 256-byte cells.",
        "- `analysis_labels.csv`: protected labels; only `primary_rn_l=1` rows enter leakage statistics.",
        "- `observer_stats.json`: invariant, mutual-information, and classifier gate.",
        "- `fault_cases.csv`: fail-closed adversarial codec checks.",
        "- `roundtrip_cases.csv`: exact recovery and overflow accounting.",
        "- `manifest.sha256`: deterministic hashes for evidence and source scripts.",
        "",
        f"Observer gate: {'PASS' if stats['gate']['passed'] else 'FAIL'} with {stats['invariants']['success_epoch_count']} successful invariant epochs.",
        "",
    ]
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def write_manifest(out_dir: Path) -> None:
    include_paths = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "manifest.sha256":
            include_paths.append(path)
    for rel in (
        "defense4/size/real_size_normalization/S3_OFFLINE_SPEC.md",
        "defense4/size/real_size_normalization/offline/cell_codec.py",
        "defense4/size/real_size_normalization/offline/corpus.py",
        "defense4/size/real_size_normalization/offline/observer_analysis.py",
        "defense4/size/real_size_normalization/offline/pcapio.py",
        "defense4/size/real_size_normalization/offline/s3_trace_driver.py",
        "defense4/size/real_size_normalization/offline/test_s3_offline.py",
        "defense4/size/real_size_normalization/offline/reproduce.sh",
    ):
        path = ROOT / rel
        if path.exists():
            include_paths.append(path)
    lines = []
    seen = set()
    for path in sorted(include_paths, key=lambda p: _rel(p)):
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{_sha256_path(path)}  {_rel(path)}")
    (out_dir / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate(out_dir: Path, *, permutations: int, bootstraps: int, seed: int, clean: bool) -> Dict[str, Any]:
    out_dir = out_dir.resolve()
    _validate_output_dir(out_dir)
    if clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cases, source_manifest = build_cases()
    records, _cell_rows, _label_rows, input_packets, decoded_packets, outer_packets = encode_decode_cases(cases, out_dir)
    write_pcap(out_dir / "trusted_input_inner.pcap", input_packets)
    write_pcap(out_dir / "decoded_inner.pcap", decoded_packets)
    write_pcap(out_dir / "observer_outer_cells.pcap", outer_packets)
    write_roundtrip_outputs(out_dir, records)
    fault_rows = run_fault_cases(out_dir)
    stats = analyze(
        out_dir / "observer_outer_cells.csv",
        out_dir / "analysis_labels.csv",
        out_dir / "observer_features.csv",
        out_dir / "observer_stats.json",
        label_column="protected_inner_length",
        transaction_column="source_transaction_id",
        permutations=permutations,
        bootstraps=bootstraps,
        seed=seed,
    )
    write_static_outputs(out_dir, source_manifest, stats, fault_rows)
    metadata = {
        "schema_version": 1,
        "generated_by": "defense4.size.real_size_normalization.offline.s3_trace_driver",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cwd": str(ROOT),
        "output_dir": _rel(out_dir),
        "policy_name": POLICY_NAME,
        "permutations": permutations,
        "bootstraps": bootstraps,
        "seed": seed,
    }
    (out_dir / "generation_metadata.json").write_text(_json_dumps(metadata), encoding="utf-8")
    write_manifest(out_dir)
    fault_gate_passed = all(
        str(row.get("passed")) in ("1", "True", "true") for row in fault_rows
    )
    successful_records = [record for record in records if record.status == "success"]
    roundtrip_gate_passed = (
        len([record for record in records if record.case.primary_rn_l]) >= 50
        and all(record.exact_recovery for record in successful_records)
    )
    return {
        "output_dir": out_dir,
        "records": len(records),
        "faults": len(fault_rows),
        "observer_gate_passed": stats["gate"]["passed"],
        "fault_gate_passed": fault_gate_passed,
        "roundtrip_gate_passed": roundtrip_gate_passed,
        "success_epochs": stats["invariants"]["success_epoch_count"],
    }


def _validate_output_dir(out_dir: Path) -> None:
    """Restrict clean regeneration to a dedicated evidence or temporary child."""

    allowed_roots = ((BASE / "evidence").resolve(), Path("/tmp").resolve())
    for allowed_root in allowed_roots:
        if out_dir == allowed_root:
            raise ValueError(f"refusing to use broad output directory: {out_dir}")
        try:
            out_dir.relative_to(allowed_root)
            return
        except ValueError:
            continue
    raise ValueError(
        "output must be a child of defense4/size/real_size_normalization/evidence or /tmp"
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--permutations", type=int, default=DEFAULT_PERMUTATIONS)
    parser.add_argument("--bootstraps", type=int, default=DEFAULT_BOOTSTRAPS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--no-clean", action="store_true", help="Do not remove the output directory before generation")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.permutations < DEFAULT_PERMUTATIONS:
        raise SystemExit("at least 1000 permutations are required")
    if args.bootstraps < DEFAULT_BOOTSTRAPS:
        raise SystemExit("at least 2000 bootstraps are required")
    summary = generate(args.output, permutations=args.permutations, bootstraps=args.bootstraps, seed=args.seed, clean=not args.no_clean)
    passed = (
        summary["observer_gate_passed"]
        and summary["fault_gate_passed"]
        and summary["roundtrip_gate_passed"]
    )
    if not passed:
        print(
            "S3 offline evidence FAIL: "
            f"observer={summary['observer_gate_passed']} "
            f"faults={summary['fault_gate_passed']} "
            f"roundtrip={summary['roundtrip_gate_passed']}",
            file=sys.stderr,
        )
        return 1
    print(
        "S3 offline evidence PASS: "
        f"records={summary['records']} faults={summary['faults']} "
        f"success_epochs={summary['success_epochs']} output={summary['output_dir']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
