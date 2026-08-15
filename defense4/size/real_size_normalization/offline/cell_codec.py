"""Offline fixed-volume AEAD cell codec for Defense4 S3.

This module is intentionally limited to the S3 offline proof surface. It does
not touch hardware, does not perform key exchange, and does not provide
production key management. The helper ``derive_offline_test_keys`` is
deterministic and non-secret; it exists only for reproducible offline tests.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MAGIC = b"D4C1"
VERSION = 1
ETHER_TYPE = 0x88B5
WIRE_SIZE = 256
ETHERNET_HEADER_LEN = 14
PUBLIC_HEADER = struct.Struct(">4sBBIQ")
PUBLIC_HEADER_LEN = PUBLIC_HEADER.size
PRIVATE_HEADER = struct.Struct(">QBBHHHIIHBB")
PRIVATE_HEADER_LEN = PRIVATE_HEADER.size
TAG_LEN = 16
AEAD_BODY_LEN = WIRE_SIZE - ETHERNET_HEADER_LEN - PUBLIC_HEADER_LEN
PLAINTEXT_LEN = AEAD_BODY_LEN - TAG_LEN
CHUNK_CAPACITY = PLAINTEXT_LEN - PRIVATE_HEADER_LEN
FRAME_LEN = struct.Struct(">I")
MIN_INNER_FRAME_LEN = 14
MAX_INNER_FRAME_LEN = 1_518

DATA_FLAG = 0x01
RESERVED_ZERO = 0


class CellCodecError(Exception):
    """Base class for fail-closed codec errors."""


class CellEncodeError(CellCodecError):
    """Raised when an epoch cannot be encoded safely."""


class CellDecodeError(CellCodecError):
    """Raised when a slot cannot be authenticated and decoded safely."""


class CellReplayError(CellDecodeError):
    """Raised when a valid cell reuses an already accepted nonce."""


class CellOverflowError(CellCodecError):
    """Raised by strict callers when inner bytes exceed fixed capacity."""


class Direction(str, Enum):
    """Observer-visible cell direction."""

    FORWARD = "forward"
    REVERSE = "reverse"


class EncodeStatus(str, Enum):
    """Local-only encoder status."""

    DATA = "data"
    COVER = "cover"
    OVERFLOW = "overflow"


class DecodeStatus(str, Enum):
    """Trusted-boundary decoder status."""

    DATA = "data"
    COVER = "cover"


@dataclass(frozen=True)
class MacPair:
    """Outer Ethernet MAC addresses for one public direction."""

    src: bytes
    dst: bytes

    def __post_init__(self) -> None:
        if len(self.src) != 6 or len(self.dst) != 6:
            raise ValueError("outer MAC addresses must be exactly 6 bytes")


@dataclass(frozen=True)
class SlotSpec:
    """Fixed public slot definition."""

    name: str
    slot_id: int
    direction: Direction
    cell_count: int
    offsets_us: Tuple[int, ...]

    def __post_init__(self) -> None:
        if self.cell_count <= 0:
            raise ValueError("cell_count must be positive")
        if len(self.offsets_us) != self.cell_count:
            raise ValueError("offset count must match cell_count")
        if not 0 <= self.slot_id <= 255:
            raise ValueError("slot_id must fit in one byte")

    @property
    def max_stream_len(self) -> int:
        return self.cell_count * CHUNK_CAPACITY


@dataclass(frozen=True)
class CellPolicy:
    """Versioned fixed-cell policy for the S3 offline codec."""

    policy_id: int
    slots: Mapping[str, SlotSpec]
    outer_macs: Mapping[Direction, MacPair]
    wire_size: int = WIRE_SIZE
    ether_type: int = ETHER_TYPE

    def __post_init__(self) -> None:
        if not 0 <= self.policy_id <= 255:
            raise ValueError("policy_id must fit in one byte")
        if self.wire_size != WIRE_SIZE:
            raise ValueError("this codec fixes C=256 bytes")
        if self.ether_type != ETHER_TYPE:
            raise ValueError("this codec fixes EtherType 0x88B5")
        for direction in Direction:
            if direction not in self.outer_macs:
                raise ValueError("outer MACs must be defined for both directions")
        seen_ids: Set[int] = set()
        for name, slot in self.slots.items():
            if name != slot.name:
                raise ValueError("slot mapping key must match SlotSpec.name")
            if slot.slot_id in seen_ids:
                raise ValueError("slot_id values must be unique")
            seen_ids.add(slot.slot_id)

    def slot(self, name: str) -> SlotSpec:
        try:
            return self.slots[name]
        except KeyError as exc:
            raise CellEncodeError("unknown slot %r" % (name,)) from exc


@dataclass(frozen=True)
class DirectionalKeys:
    """ChaCha20-Poly1305 keys for both public directions."""

    forward: bytes
    reverse: bytes

    def key_for(self, direction: Direction) -> bytes:
        key = self.forward if direction is Direction.FORWARD else self.reverse
        if len(key) != 32:
            raise CellCodecError("ChaCha20-Poly1305 keys must be 32 bytes")
        return key


@dataclass
class KeyState:
    """Per-session offline nonce and replay ledger.

    The state prevents nonce reuse within this process by tracking emitted and
    accepted ``(direction, key_epoch, counter)`` tuples. A real deployment must
    persist counters or rotate to a fresh key epoch before restart; this offline
    module intentionally does not implement production persistence.
    """

    key_epoch: int
    keys: DirectionalKeys
    tx_counters: MutableMapping[Direction, int]
    emitted_nonces: Set[Tuple[Direction, int, int]]
    received_nonces: Set[Tuple[Direction, int, int]]
    accepted_epochs: MutableMapping[Tuple[Direction, int], int]

    @classmethod
    def fresh(
        cls,
        key_epoch: int,
        keys: DirectionalKeys,
        start_counters: Optional[Mapping[Direction, int]] = None,
        accepted_epochs: Optional[Mapping[Tuple[Direction, int], int]] = None,
    ) -> "KeyState":
        counters: Dict[Direction, int] = {
            Direction.FORWARD: 0,
            Direction.REVERSE: 0,
        }
        if start_counters:
            counters.update(dict(start_counters))
        for counter in counters.values():
            _check_u64(counter, "counter")
        restored_epochs = dict(accepted_epochs or {})
        for (direction, slot_id), epoch_id in restored_epochs.items():
            if not isinstance(direction, Direction):
                raise ValueError("accepted epoch direction must be a Direction")
            _check_u8(slot_id, "accepted epoch slot_id")
            _check_u64(epoch_id, "accepted epoch_id")
        _check_u32(key_epoch, "key_epoch")
        return cls(
            key_epoch=key_epoch,
            keys=keys,
            tx_counters=counters,
            emitted_nonces=set(),
            received_nonces=set(),
            accepted_epochs=restored_epochs,
        )

    def next_counter(self, direction: Direction) -> int:
        counter = self.tx_counters[direction]
        _check_u64(counter, "counter")
        if counter == (1 << 64) - 1:
            raise CellEncodeError("counter exhausted; rotate key epoch")
        nonce_id = (direction, self.key_epoch, counter)
        if nonce_id in self.emitted_nonces:
            raise CellEncodeError("refusing to reuse emitted nonce")
        self.emitted_nonces.add(nonce_id)
        self.tx_counters[direction] = counter + 1
        return counter

    def reject_if_received(self, direction: Direction, key_epoch: int, counter: int) -> None:
        if (direction, key_epoch, counter) in self.received_nonces:
            raise CellReplayError("replayed nonce")

    def mark_received(self, direction: Direction, key_epoch: int, counter: int) -> None:
        nonce_id = (direction, key_epoch, counter)
        if nonce_id in self.received_nonces:
            raise CellReplayError("replayed nonce")
        self.received_nonces.add(nonce_id)

    def reject_if_stale_epoch(
        self, direction: Direction, slot_id: int, epoch_id: int
    ) -> None:
        last = self.accepted_epochs.get((direction, slot_id))
        if last is not None and epoch_id <= last:
            raise CellReplayError("stale or repeated slot epoch")

    def mark_epoch(self, direction: Direction, slot_id: int, epoch_id: int) -> None:
        self.reject_if_stale_epoch(direction, slot_id, epoch_id)
        self.accepted_epochs[(direction, slot_id)] = epoch_id


@dataclass(frozen=True)
class PublicHeader:
    """Parsed public header. It deliberately contains no inner length/type bits."""

    version: int
    policy_id: int
    key_epoch: int
    cell_counter: int


@dataclass(frozen=True)
class PrivateHeader:
    """Authenticated encrypted per-cell metadata."""

    epoch_id: int
    slot_id: int
    flags: int
    cell_index: int
    cell_count: int
    frame_count: int
    serialized_stream_len: int
    payload_offset: int
    payload_len: int
    protected_type: int
    reserved: int = RESERVED_ZERO


@dataclass(frozen=True)
class EncodedCell:
    """One emitted fixed-size outer Ethernet frame and its nominal slot offset."""

    frame: bytes
    direction: Direction
    slot_name: str
    cell_index: int
    cell_counter: int
    offset_us: int


@dataclass(frozen=True)
class EncodeResult:
    """Encoder result. ``status`` is local-only and is never in the public frame."""

    status: EncodeStatus
    slot_name: str
    direction: Direction
    epoch_id: int
    cells: Tuple[EncodedCell, ...]
    overflow: bool = False


@dataclass(frozen=True)
class DecodeResult:
    """Decoder result: exact inner frames or no frames."""

    status: DecodeStatus
    slot_name: str
    direction: Direction
    epoch_id: int
    frames: Tuple[bytes, ...]
    protected_type: int


def default_policy() -> CellPolicy:
    """Return the approved S3 provisional policy.

    Slot offsets are in microseconds and are fixed observer-visible scheduling
    metadata for offline traces:

    - request: forward, K=4, offsets 0..750 us;
    - ack: reverse, K=2, offsets 1000 and 1250 us;
    - response: reverse, K=14, offsets 200000..203250 us;
    - tail: forward, K=2, offsets 203500 and 203750 us.
    """

    return CellPolicy(
        policy_id=1,
        slots={
            "request": SlotSpec(
                name="request",
                slot_id=1,
                direction=Direction.FORWARD,
                cell_count=4,
                offsets_us=(0, 250, 500, 750),
            ),
            "ack": SlotSpec(
                name="ack",
                slot_id=2,
                direction=Direction.REVERSE,
                cell_count=2,
                offsets_us=(1000, 1250),
            ),
            "response": SlotSpec(
                name="response",
                slot_id=3,
                direction=Direction.REVERSE,
                cell_count=14,
                offsets_us=tuple(range(200000, 203251, 250)),
            ),
            "tail": SlotSpec(
                name="tail",
                slot_id=4,
                direction=Direction.FORWARD,
                cell_count=2,
                offsets_us=(203500, 203750),
            ),
        },
        outer_macs={
            Direction.FORWARD: MacPair(
                src=bytes.fromhex("020000000001"),
                dst=bytes.fromhex("020000000002"),
            ),
            Direction.REVERSE: MacPair(
                src=bytes.fromhex("020000000002"),
                dst=bytes.fromhex("020000000001"),
            ),
        },
    )


def derive_offline_test_keys(seed_name: str) -> DirectionalKeys:
    """Derive deterministic non-secret test keys from a public seed name.

    These keys are for offline reproducibility only. They are not random, not
    secret, and must never be used for deployed traffic or hardware tests.
    """

    if not seed_name:
        raise ValueError("seed_name must be non-empty and public")
    domain = b"Defense4 S3 offline non-secret test key v1\0"
    seed = seed_name.encode("utf-8")
    return DirectionalKeys(
        forward=hashlib.sha256(domain + b"forward\0" + seed).digest(),
        reverse=hashlib.sha256(domain + b"reverse\0" + seed).digest(),
    )


def serialize_frame_bundle(frames: Sequence[bytes]) -> bytes:
    """Serialize complete inner Ethernet frames as repeated length+bytes."""

    chunks: List[bytes] = []
    for frame in frames:
        if not isinstance(frame, (bytes, bytearray)):
            raise TypeError("frames must be bytes-like")
        frame_bytes = bytes(frame)
        if not MIN_INNER_FRAME_LEN <= len(frame_bytes) <= MAX_INNER_FRAME_LEN:
            raise CellEncodeError(
                "inner Ethernet frame length must be 14..1518 bytes without FCS"
            )
        _check_u32(len(frame_bytes), "frame length")
        chunks.append(FRAME_LEN.pack(len(frame_bytes)))
        chunks.append(frame_bytes)
    return b"".join(chunks)


def deserialize_frame_bundle(stream: bytes, frame_count: int) -> Tuple[bytes, ...]:
    """Deserialize a frame bundle, rejecting trailing or truncated bytes."""

    frames: List[bytes] = []
    offset = 0
    for _ in range(frame_count):
        if offset + FRAME_LEN.size > len(stream):
            raise CellDecodeError("truncated frame length")
        (length,) = FRAME_LEN.unpack(stream[offset : offset + FRAME_LEN.size])
        offset += FRAME_LEN.size
        if not MIN_INNER_FRAME_LEN <= length <= MAX_INNER_FRAME_LEN:
            raise CellDecodeError(
                "decoded inner Ethernet frame length must be 14..1518 bytes without FCS"
            )
        if offset + length > len(stream):
            raise CellDecodeError("truncated frame bytes")
        frames.append(stream[offset : offset + length])
        offset += length
    if offset != len(stream):
        raise CellDecodeError("trailing bytes after frame bundle")
    return tuple(frames)


def encode_slot(
    inner_frames: Sequence[bytes],
    policy: CellPolicy,
    slot_name: str,
    epoch_id: int,
    key_state: KeyState,
    protected_type: int = 0,
) -> EncodeResult:
    """Encode one fixed public slot.

    The function always emits exactly ``K`` cells for the selected slot. If the
    serialized inner bundle does not fit, it emits exactly ``K`` authenticated
    cover cells and returns local status ``OVERFLOW`` with no partial data.
    """

    slot = policy.slot(slot_name)
    _check_u64(epoch_id, "epoch_id")
    _check_u8(protected_type, "protected_type")

    stream = serialize_frame_bundle(inner_frames)
    status = EncodeStatus.DATA if stream else EncodeStatus.COVER
    overflow = len(stream) > slot.max_stream_len
    if overflow:
        stream = b""
        status = EncodeStatus.OVERFLOW

    cells = _encode_cells_for_stream(
        stream=stream,
        frame_count=0 if overflow else len(inner_frames),
        status=status,
        policy=policy,
        slot=slot,
        epoch_id=epoch_id,
        key_state=key_state,
        protected_type=protected_type,
    )
    return EncodeResult(
        status=status,
        slot_name=slot_name,
        direction=slot.direction,
        epoch_id=epoch_id,
        cells=tuple(cells),
        overflow=overflow,
    )


def encode_epoch(
    inner_frames: Sequence[bytes],
    policy: CellPolicy,
    slot_name: str,
    epoch_id: int,
    key_state: KeyState,
    protected_type: int = 0,
) -> EncodeResult:
    """Compatibility wrapper for S3 tests that call epoch-level encoding."""

    return encode_slot(inner_frames, policy, slot_name, epoch_id, key_state, protected_type)


def decode_slot(
    cells: Iterable[bytes],
    policy: CellPolicy,
    slot_name: str,
    direction: Direction,
    key_state: KeyState,
) -> DecodeResult:
    """Authenticate, reorder, and decode one fixed slot.

    The decoder accepts bounded reordering by authenticating the complete cell
    set and sorting by the encrypted ``cell_index``. It releases exact frames
    only after every required cell is present and all metadata is consistent.
    Any corruption, missing cell, replay, wrong public metadata, conflicting
    duplicate, overflow spill, or malformed private metadata raises a
    ``CellDecodeError`` and releases no partial frames.
    """

    slot = policy.slot(slot_name)
    if direction is not slot.direction:
        raise CellDecodeError("direction does not match slot policy")

    unique_frames = _dedupe_public_frames(tuple(cells))
    if len(unique_frames) != slot.cell_count:
        raise CellDecodeError("slot has missing or extra cells")

    parsed: List[Tuple[PrivateHeader, bytes, PublicHeader]] = []
    pending_received: List[Tuple[Direction, int, int]] = []
    for frame in unique_frames:
        private, payload, public = _decrypt_cell(frame, policy, direction, key_state)
        key_state.reject_if_received(direction, public.key_epoch, public.cell_counter)
        parsed.append((private, payload, public))
        pending_received.append((direction, public.key_epoch, public.cell_counter))

    frames, status, epoch_id, protected_type = _reassemble_slot(parsed, slot)
    key_state.reject_if_stale_epoch(direction, slot.slot_id, epoch_id)
    for received_direction, key_epoch, counter in pending_received:
        key_state.mark_received(received_direction, key_epoch, counter)
    key_state.mark_epoch(direction, slot.slot_id, epoch_id)
    return DecodeResult(
        status=status,
        slot_name=slot_name,
        direction=direction,
        epoch_id=epoch_id,
        frames=frames,
        protected_type=protected_type,
    )


def decode_epoch(
    cells: Iterable[bytes],
    policy: CellPolicy,
    slot_name: str,
    direction: Direction,
    key_state: KeyState,
) -> DecodeResult:
    """Compatibility wrapper for S3 tests that call epoch-level decoding."""

    return decode_slot(cells, policy, slot_name, direction, key_state)


def public_header_from_frame(frame: bytes, policy: Optional[CellPolicy] = None) -> PublicHeader:
    """Parse only the observer-visible public header."""

    if len(frame) != WIRE_SIZE:
        raise CellDecodeError("wrong fixed wire size")
    ether_type = struct.unpack(">H", frame[12:14])[0]
    expected_ether_type = policy.ether_type if policy is not None else ETHER_TYPE
    if ether_type != expected_ether_type:
        raise CellDecodeError("wrong EtherType")
    start = ETHERNET_HEADER_LEN
    magic, version, policy_id, key_epoch, cell_counter = PUBLIC_HEADER.unpack(
        frame[start : start + PUBLIC_HEADER_LEN]
    )
    if magic != MAGIC:
        raise CellDecodeError("wrong magic")
    if version != VERSION:
        raise CellDecodeError("wrong version")
    if policy is not None and policy_id != policy.policy_id:
        raise CellDecodeError("wrong policy")
    return PublicHeader(version, policy_id, key_epoch, cell_counter)


def fixed_public_feature(cell: EncodedCell) -> Dict[str, object]:
    """Return public observer features for invariant tests."""

    return {
        "slot_name": cell.slot_name,
        "direction": cell.direction.value,
        "cell_index": cell.cell_index,
        "wire_len": len(cell.frame),
        "public_header_len": PUBLIC_HEADER_LEN,
        "ciphertext_len": AEAD_BODY_LEN - TAG_LEN,
        "tag_len": TAG_LEN,
        "slot_offset_us": cell.offset_us,
        "fragment_flag": 0,
        "retry_or_error_flag": 0,
    }


def _encode_cells_for_stream(
    stream: bytes,
    frame_count: int,
    status: EncodeStatus,
    policy: CellPolicy,
    slot: SlotSpec,
    epoch_id: int,
    key_state: KeyState,
    protected_type: int,
) -> List[EncodedCell]:
    if len(stream) > slot.max_stream_len:
        raise CellEncodeError("stream exceeds fixed slot capacity")
    _check_u16(frame_count, "frame_count")
    _check_u32(len(stream), "serialized_stream_len")

    cells: List[EncodedCell] = []
    for cell_index, offset_us in enumerate(slot.offsets_us):
        payload_offset = cell_index * CHUNK_CAPACITY
        payload = stream[payload_offset : payload_offset + CHUNK_CAPACITY]
        flags = DATA_FLAG if status is EncodeStatus.DATA else 0
        private = PrivateHeader(
            epoch_id=epoch_id,
            slot_id=slot.slot_id,
            flags=flags,
            cell_index=cell_index,
            cell_count=slot.cell_count,
            frame_count=frame_count if status is EncodeStatus.DATA else 0,
            serialized_stream_len=len(stream) if status is EncodeStatus.DATA else 0,
            payload_offset=payload_offset,
            payload_len=len(payload) if status is EncodeStatus.DATA else 0,
            protected_type=protected_type if status is EncodeStatus.DATA else 0,
        )
        counter = key_state.next_counter(slot.direction)
        frame = _encrypt_cell(
            policy=policy,
            direction=slot.direction,
            key_state=key_state,
            counter=counter,
            private=private,
            payload=payload if status is EncodeStatus.DATA else b"",
        )
        cells.append(
            EncodedCell(
                frame=frame,
                direction=slot.direction,
                slot_name=slot.name,
                cell_index=cell_index,
                cell_counter=counter,
                offset_us=offset_us,
            )
        )
    return cells


def _encrypt_cell(
    policy: CellPolicy,
    direction: Direction,
    key_state: KeyState,
    counter: int,
    private: PrivateHeader,
    payload: bytes,
) -> bytes:
    outer = _outer_ethernet(policy, direction)
    public = PUBLIC_HEADER.pack(
        MAGIC,
        VERSION,
        policy.policy_id,
        key_state.key_epoch,
        counter,
    )
    aad = outer + public
    plaintext = _pack_plaintext(private, payload)
    nonce = _nonce(key_state.key_epoch, counter)
    ciphertext = ChaCha20Poly1305(key_state.keys.key_for(direction)).encrypt(nonce, plaintext, aad)
    if len(ciphertext) != AEAD_BODY_LEN:
        raise CellEncodeError("AEAD output length mismatch")
    frame = aad + ciphertext
    if len(frame) != WIRE_SIZE:
        raise CellEncodeError("wire size mismatch")
    return frame


def _decrypt_cell(
    frame: bytes,
    policy: CellPolicy,
    direction: Direction,
    key_state: KeyState,
) -> Tuple[PrivateHeader, bytes, PublicHeader]:
    if len(frame) != WIRE_SIZE:
        raise CellDecodeError("wrong fixed wire size")
    expected_outer = _outer_ethernet(policy, direction)
    outer = frame[:ETHERNET_HEADER_LEN]
    if outer != expected_outer:
        raise CellDecodeError("wrong outer Ethernet direction or EtherType")
    public = public_header_from_frame(frame, policy)
    if public.key_epoch != key_state.key_epoch:
        raise CellDecodeError("unexpected key epoch")
    public_bytes = frame[ETHERNET_HEADER_LEN : ETHERNET_HEADER_LEN + PUBLIC_HEADER_LEN]
    aad = outer + public_bytes
    body = frame[ETHERNET_HEADER_LEN + PUBLIC_HEADER_LEN :]
    if len(body) != AEAD_BODY_LEN:
        raise CellDecodeError("wrong AEAD body length")
    nonce = _nonce(public.key_epoch, public.cell_counter)
    try:
        plaintext = ChaCha20Poly1305(key_state.keys.key_for(direction)).decrypt(nonce, body, aad)
    except Exception as exc:
        raise CellDecodeError("authentication failed") from exc
    if len(plaintext) != PLAINTEXT_LEN:
        raise CellDecodeError("plaintext length mismatch")
    private, payload = _unpack_plaintext(plaintext)
    return private, payload, public


def _reassemble_slot(
    parsed: Sequence[Tuple[PrivateHeader, bytes, PublicHeader]],
    slot: SlotSpec,
) -> Tuple[Tuple[bytes, ...], DecodeStatus, int, int]:
    by_index: Dict[int, Tuple[PrivateHeader, bytes]] = {}
    epoch_id: Optional[int] = None
    frame_count: Optional[int] = None
    stream_len: Optional[int] = None
    protected_type: Optional[int] = None
    flags: Optional[int] = None
    counter_base: Optional[int] = None

    for private, payload, public in parsed:
        _validate_private_header(private, slot)
        if public.cell_counter < private.cell_index:
            raise CellDecodeError("public counter precedes encrypted cell index")
        candidate_counter_base = public.cell_counter - private.cell_index
        counter_base = (
            candidate_counter_base
            if counter_base is None
            else _same(counter_base, candidate_counter_base, "counter base")
        )
        if private.cell_index in by_index:
            raise CellDecodeError("conflicting duplicate cell index")
        by_index[private.cell_index] = (private, payload)
        epoch_id = private.epoch_id if epoch_id is None else _same(epoch_id, private.epoch_id, "epoch")
        frame_count = (
            private.frame_count
            if frame_count is None
            else _same(frame_count, private.frame_count, "frame_count")
        )
        stream_len = (
            private.serialized_stream_len
            if stream_len is None
            else _same(stream_len, private.serialized_stream_len, "serialized_stream_len")
        )
        protected_type = (
            private.protected_type
            if protected_type is None
            else _same(protected_type, private.protected_type, "protected_type")
        )
        flags = private.flags if flags is None else _same(flags, private.flags, "flags")

    if set(by_index) != set(range(slot.cell_count)):
        raise CellDecodeError("missing cell index")
    assert epoch_id is not None
    assert frame_count is not None
    assert stream_len is not None
    assert protected_type is not None
    assert flags is not None

    if stream_len > slot.max_stream_len:
        raise CellDecodeError("stream length exceeds slot capacity")
    if flags & ~DATA_FLAG:
        raise CellDecodeError("unknown private flags")
    if stream_len == 0:
        if flags != 0 or frame_count != 0:
            raise CellDecodeError("cover cell has data metadata")
        return tuple(), DecodeStatus.COVER, epoch_id, protected_type
    if flags != DATA_FLAG:
        raise CellDecodeError("data stream missing data flag")
    if frame_count == 0:
        raise CellDecodeError("non-empty stream with zero frame_count")

    stream = bytearray(stream_len)
    for index in range(slot.cell_count):
        private, payload = by_index[index]
        expected_offset = index * CHUNK_CAPACITY
        expected_len = max(0, min(CHUNK_CAPACITY, stream_len - expected_offset))
        if private.payload_offset != expected_offset:
            raise CellDecodeError("bad payload offset")
        if private.payload_len != expected_len:
            raise CellDecodeError("bad payload length")
        if len(payload) != expected_len:
            raise CellDecodeError("payload length mismatch")
        if expected_len:
            stream[expected_offset : expected_offset + expected_len] = payload

    frames = deserialize_frame_bundle(bytes(stream), frame_count)
    return frames, DecodeStatus.DATA, epoch_id, protected_type


def _validate_private_header(private: PrivateHeader, slot: SlotSpec) -> None:
    if private.slot_id != slot.slot_id:
        raise CellDecodeError("wrong encrypted slot id")
    if private.cell_count != slot.cell_count:
        raise CellDecodeError("wrong encrypted cell_count")
    if private.cell_index >= slot.cell_count:
        raise CellDecodeError("encrypted cell_index out of range")
    if private.reserved != RESERVED_ZERO:
        raise CellDecodeError("reserved field must be zero")
    if private.payload_len > CHUNK_CAPACITY:
        raise CellDecodeError("payload exceeds chunk capacity")
    if private.payload_offset > slot.max_stream_len:
        raise CellDecodeError("payload offset exceeds slot capacity")
    if private.payload_offset + private.payload_len > slot.max_stream_len:
        raise CellDecodeError("payload range exceeds slot capacity")


def _pack_plaintext(private: PrivateHeader, payload: bytes) -> bytes:
    if len(payload) > CHUNK_CAPACITY:
        raise CellEncodeError("payload exceeds chunk capacity")
    header = PRIVATE_HEADER.pack(
        private.epoch_id,
        private.slot_id,
        private.flags,
        private.cell_index,
        private.cell_count,
        private.frame_count,
        private.serialized_stream_len,
        private.payload_offset,
        private.payload_len,
        private.protected_type,
        private.reserved,
    )
    padding_len = PLAINTEXT_LEN - PRIVATE_HEADER_LEN - len(payload)
    if padding_len < 0:
        raise CellEncodeError("negative padding")
    padding = _deterministic_offline_padding(private, padding_len)
    plaintext = header + payload + padding
    if len(plaintext) != PLAINTEXT_LEN:
        raise CellEncodeError("plaintext size mismatch")
    return plaintext


def _unpack_plaintext(plaintext: bytes) -> Tuple[PrivateHeader, bytes]:
    values = PRIVATE_HEADER.unpack(plaintext[:PRIVATE_HEADER_LEN])
    private = PrivateHeader(*values)
    if private.payload_len > CHUNK_CAPACITY:
        raise CellDecodeError("payload_len exceeds chunk capacity")
    payload_start = PRIVATE_HEADER_LEN
    payload_end = payload_start + private.payload_len
    payload = plaintext[payload_start:payload_end]
    return private, payload


def _dedupe_public_frames(frames: Tuple[bytes, ...]) -> Tuple[bytes, ...]:
    by_public_nonce: Dict[Tuple[bytes, int], bytes] = {}
    for frame in frames:
        if len(frame) != WIRE_SIZE:
            raise CellDecodeError("wrong fixed wire size")
        header = public_header_from_frame(frame)
        public_key = (frame[: ETHERNET_HEADER_LEN + PUBLIC_HEADER_LEN], header.cell_counter)
        existing = by_public_nonce.get(public_key)
        if existing is None:
            by_public_nonce[public_key] = frame
        elif existing != frame:
            raise CellDecodeError("conflicting duplicate public nonce")
    return tuple(by_public_nonce.values())


def _outer_ethernet(policy: CellPolicy, direction: Direction) -> bytes:
    macs = policy.outer_macs[direction]
    return macs.dst + macs.src + struct.pack(">H", policy.ether_type)


def _nonce(key_epoch: int, counter: int) -> bytes:
    _check_u32(key_epoch, "key_epoch")
    _check_u64(counter, "counter")
    return struct.pack(">IQ", key_epoch, counter)


def _deterministic_offline_padding(private: PrivateHeader, length: int) -> bytes:
    if length <= 0:
        return b""
    seed = PRIVATE_HEADER.pack(
        private.epoch_id,
        private.slot_id,
        private.flags,
        private.cell_index,
        private.cell_count,
        private.frame_count,
        private.serialized_stream_len,
        private.payload_offset,
        private.payload_len,
        private.protected_type,
        private.reserved,
    )
    return hashlib.shake_256(b"Defense4 S3 offline padding\0" + seed).digest(length)


def _same(current: int, candidate: int, field: str) -> int:
    if current != candidate:
        raise CellDecodeError("inconsistent %s" % field)
    return current


def _check_u8(value: int, field: str) -> None:
    if not 0 <= value <= 0xFF:
        raise ValueError("%s must fit in uint8" % field)


def _check_u16(value: int, field: str) -> None:
    if not 0 <= value <= 0xFFFF:
        raise ValueError("%s must fit in uint16" % field)


def _check_u32(value: int, field: str) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("%s must fit in uint32" % field)


def _check_u64(value: int, field: str) -> None:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("%s must fit in uint64" % field)


def _self_check() -> None:
    policy = default_policy()
    keys = derive_offline_test_keys("public-s3-self-check")
    tx = KeyState.fresh(7, keys)
    rx = KeyState.fresh(7, keys)

    frames = (b"\x01" * 20, b"\x02" * 45)
    encoded = encode_slot(frames, policy, "request", 100, tx, protected_type=11)
    assert encoded.status is EncodeStatus.DATA
    assert len(encoded.cells) == 4
    assert all(len(cell.frame) == WIRE_SIZE for cell in encoded.cells)
    decoded = decode_slot(
        [cell.frame for cell in reversed(encoded.cells)],
        policy,
        "request",
        Direction.FORWARD,
        rx,
    )
    assert decoded.status is DecodeStatus.DATA
    assert decoded.frames == frames
    assert decoded.protected_type == 11

    try:
        decode_slot([cell.frame for cell in encoded.cells], policy, "request", Direction.FORWARD, rx)
    except CellReplayError:
        pass
    else:
        raise AssertionError("replay was accepted")

    cover_tx = KeyState.fresh(8, keys)
    cover_rx = KeyState.fresh(8, keys)
    cover = encode_slot([], policy, "ack", 101, cover_tx)
    assert cover.status is EncodeStatus.COVER
    cover_decoded = decode_slot([cell.frame for cell in cover.cells], policy, "ack", Direction.REVERSE, cover_rx)
    assert cover_decoded.frames == tuple()
    assert cover_decoded.status is DecodeStatus.COVER

    overflow_tx = KeyState.fresh(9, keys)
    overflow_rx = KeyState.fresh(9, keys)
    overflow = encode_slot([b"x" * 1514, b"y" * 999], policy, "response", 102, overflow_tx)
    assert overflow.status is EncodeStatus.OVERFLOW
    assert overflow.overflow is True
    overflow_decoded = decode_slot(
        [cell.frame for cell in overflow.cells],
        policy,
        "response",
        Direction.REVERSE,
        overflow_rx,
    )
    assert overflow_decoded.frames == tuple()

    corrupt = bytearray(encoded.cells[0].frame)
    corrupt[-1] ^= 0x01
    corrupt_rx = KeyState.fresh(7, keys)
    try:
        decode_slot([bytes(corrupt)] + [cell.frame for cell in encoded.cells[1:]], policy, "request", Direction.FORWARD, corrupt_rx)
    except CellDecodeError:
        pass
    else:
        raise AssertionError("corrupt tag was accepted")

    missing_rx = KeyState.fresh(7, keys)
    try:
        decode_slot([cell.frame for cell in encoded.cells[:-1]], policy, "request", Direction.FORWARD, missing_rx)
    except CellDecodeError:
        pass
    else:
        raise AssertionError("missing cell was accepted")


if __name__ == "__main__":
    _self_check()
    print("cell_codec self-check PASS")
