from __future__ import annotations

import os
import stat
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defense4.size.real_size_normalization.offline.cell_codec import (
    CellDecodeError,
    Direction,
    KeyState,
    default_policy,
    decode_slot,
    derive_offline_test_keys,
    encode_slot,
)
from defense4.size.real_size_normalization.software import l2_shim


def test_classifier_places_lifecycle_frames_in_declared_slots() -> None:
    arp_request = _arp_frame(opcode=1)
    arp_reply = _arp_frame(opcode=2)
    syn = _tcp_frame(b"", Direction.FORWARD, flags=0x02)
    pure_ack = _tcp_frame(b"", Direction.FORWARD, flags=0x10)
    fin = _tcp_frame(b"", Direction.FORWARD, flags=0x11)
    response_payload = _tcp_frame(b"response", Direction.REVERSE)
    syn_ack = _tcp_frame(b"", Direction.REVERSE, flags=0x12)

    assert l2_shim.classify_inner_frame("vision", arp_request) == "request"
    assert l2_shim.classify_inner_frame("vision", syn) == "request"
    assert l2_shim.classify_inner_frame("vision", pure_ack) == "tail"
    assert l2_shim.classify_inner_frame("vision", fin) == "tail"
    assert l2_shim.classify_inner_frame("ufispace", arp_reply) == "ack"
    assert l2_shim.classify_inner_frame("ufispace", syn_ack) == "ack"
    assert l2_shim.classify_inner_frame("ufispace", response_payload) == "response"


def test_fifo_blocks_cross_slot_overtaking_and_preserves_order() -> None:
    queue = l2_shim.SlotFrameQueue(max_frames=4, max_bytes=512)
    request_a = _arp_frame(opcode=1, suffix=b"a")
    tail = _tcp_frame(b"", Direction.FORWARD, flags=0x10)
    request_b = _arp_frame(opcode=1, suffix=b"b")

    assert queue.admit(request_a, "request")
    assert queue.admit(tail, "tail")
    assert queue.admit(request_b, "request")

    first = queue.pop_for_slot("request", 512)
    assert first.frames == (request_a,)
    blocked = queue.pop_for_slot("request", 512)
    assert blocked.frames == tuple()
    assert blocked.blocked_by_older_slot
    assert queue.pop_for_slot("tail", 512).frames == (tail,)
    assert queue.pop_for_slot("request", 512).frames == (request_b,)


def test_fifo_bounds_and_single_oversize_overflow() -> None:
    queue = l2_shim.SlotFrameQueue(max_frames=2, max_bytes=100)
    small = _arp_frame(opcode=1)
    assert queue.admit(small, "request")
    assert not queue.admit(small, "request")
    assert queue.drops == 1

    overflow_queue = l2_shim.SlotFrameQueue(max_frames=2, max_bytes=4096)
    big = b"\xff" * 200
    assert overflow_queue.admit(big, "request")
    popped = overflow_queue.pop_for_slot("request", 100)
    assert popped.overflow
    assert popped.frames == tuple()
    assert overflow_queue.frame_count == 0


def test_public_window_receiver_accepts_reorder_and_exact_duplicate() -> None:
    policy = default_policy()
    keys = derive_offline_test_keys("l2-shim-window-test")
    tx = KeyState.fresh(3, keys)
    rx = KeyState.fresh(3, keys)
    frame = _tcp_frame(b"abc", Direction.FORWARD)
    encoded = encode_slot((frame,), policy, "request", 0, tx, protected_type=1)
    cells = [cell.frame for cell in encoded.cells]
    receiver = l2_shim.PublicWindowReceiver(Direction.FORWARD)

    assert receiver.add(cells[2]) is None
    assert receiver.add(cells[0]) is None
    assert receiver.add(cells[2]) is None
    assert receiver.duplicate_cells == 1
    assert receiver.add(cells[3]) is None
    ready = receiver.add(cells[1])

    assert ready is not None
    slot_name, epoch_id, grouped = ready
    assert (slot_name, epoch_id) == ("request", 0)
    decoded = decode_slot(grouped, policy, "request", Direction.FORWARD, rx)
    assert decoded.frames == (frame,)


def test_public_window_receiver_fails_closed_on_conflicting_duplicate() -> None:
    policy = default_policy()
    keys = derive_offline_test_keys("l2-shim-conflict-test")
    tx = KeyState.fresh(3, keys)
    frame = _tcp_frame(b"abc", Direction.FORWARD)
    encoded = encode_slot((frame,), policy, "request", 0, tx, protected_type=1)
    cells = [cell.frame for cell in encoded.cells]
    corrupt = bytearray(cells[0])
    corrupt[-1] ^= 0x01
    receiver = l2_shim.PublicWindowReceiver(Direction.FORWARD)

    assert receiver.add(cells[0]) is None
    ready = receiver.add(bytes(corrupt))

    assert ready is not None
    assert receiver.conflicting_duplicates == 1
    with pytest.raises(CellDecodeError):
        decode_slot(ready[2], policy, "request", Direction.FORWARD, KeyState.fresh(3, keys))


def test_runtime_key_file_requires_exact_0600_64_bytes(tmp_path) -> None:
    key_path = tmp_path / "shim.key"
    key_path.write_bytes(b"\x01" * 32 + b"\x02" * 32)
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)

    keys = l2_shim.load_runtime_keys(key_path)

    assert keys.forward == b"\x01" * 32
    assert keys.reverse == b"\x02" * 32

    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    with pytest.raises(l2_shim.L2ShimError):
        l2_shim.load_runtime_keys(key_path)


def test_l2_shim_source_has_no_tcp_socket_api() -> None:
    source = l2_shim.Path(l2_shim.__file__).read_text(encoding="utf-8")

    assert "SOCK_STREAM" not in source
    assert "listen(" not in source
    assert "accept(" not in source
    assert "connect(" not in source


def _arp_frame(*, opcode: int, suffix: bytes = b"") -> bytes:
    dst = b"\xff" * 6
    src = b"\x02\x44\x00\x00\x00\x01"
    sender_ip = b"\x0a\x2c\x00\x01"
    target_ip = b"\x0a\x2c\x00\x02"
    body = (
        b"\x00\x01"
        b"\x08\x00"
        b"\x06"
        b"\x04"
        + opcode.to_bytes(2, "big")
        + src
        + sender_ip
        + b"\x00" * 6
        + target_ip
    )
    frame = dst + src + b"\x08\x06" + body + suffix
    return frame + b"\x00" * max(0, 60 - len(frame))


def _tcp_frame(payload: bytes, direction: Direction, *, flags: int = 0x18) -> bytes:
    if direction is Direction.FORWARD:
        src_mac, dst_mac = b"\x02\x44\x00\x00\x00\x01", b"\x02\x44\x00\x00\x00\x02"
        src_ip, dst_ip = b"\x0a\x2c\x00\x01", b"\x0a\x2c\x00\x02"
    else:
        src_mac, dst_mac = b"\x02\x44\x00\x00\x00\x02", b"\x02\x44\x00\x00\x00\x01"
        src_ip, dst_ip = b"\x0a\x2c\x00\x02", b"\x0a\x2c\x00\x01"
    tcp = struct.pack(
        ">HHIIBBHHH",
        40000,
        20000,
        1,
        1,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0x4000,
        64,
        6,
        0,
        src_ip,
        dst_ip,
    )
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload
