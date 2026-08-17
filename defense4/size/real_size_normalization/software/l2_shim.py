"""S4 raw Layer-2 fixed-cell shim core.

This module is the packet-preserving S4 path. It captures complete Ethernet
frames from one trusted interface, carries them through the committed S3
fixed-cell codec on an observed AF_PACKET link, and injects decoded complete
Ethernet frames to the opposite trusted interface. It deliberately does not
open TCP sockets or terminate endpoint sessions.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import resource
import select
import signal
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from collections import deque

from defense4.size.real_size_normalization.offline.cell_codec import (
    ETHER_TYPE,
    WIRE_SIZE,
    CellDecodeError,
    CellEncodeError,
    Direction,
    DirectionalKeys,
    EncodeResult,
    EncodeStatus,
    KeyState,
    default_policy,
    decode_slot,
    encode_slot,
    public_header_from_frame,
    serialize_frame_bundle,
)
from defense4.size.real_size_normalization.offline.pcapio import PcapPacket, write_pcap
from defense4.size.real_size_normalization.software.runner_support import write_ready_file


EPOCH_US = 210_000
QUEUE_MAX_FRAMES = 128
QUEUE_MAX_BYTES = 262_144
KEY_FILE_BYTES = 64
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
PACKET_OUTGOING = 4
IPPROTO_TCP = 6
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
PROTECTED_TYPE = {"request": 1, "ack": 2, "response": 3, "tail": 4}
ROLE_CHOICES = ("vision", "ufispace")
SLOT_ORDER = ("request", "ack", "response", "tail")
FORWARD_WINDOW = ("request", "request", "request", "request", "tail", "tail")
REVERSE_WINDOW = (
    "ack",
    "ack",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
    "response",
)


class L2ShimError(RuntimeError):
    """Base error for fail-closed shim failures."""


@dataclasses.dataclass(frozen=True)
class TcpSummary:
    """Parsed minimal TCP metadata used only for slot classification."""

    flags: int
    payload_len: int

    @property
    def pure_ack(self) -> bool:
        return self.payload_len == 0 and self.flags == 0x10

    @property
    def has_payload(self) -> bool:
        return self.payload_len > 0


@dataclasses.dataclass(frozen=True)
class QueuedFrame:
    """One captured complete Ethernet frame and its selected slot."""

    frame: bytes
    slot_name: str

    @property
    def serialized_len(self) -> int:
        return 4 + len(self.frame)


@dataclasses.dataclass(frozen=True)
class QueuePop:
    """Frames selected for one slot deadline."""

    frames: Tuple[bytes, ...]
    overflow: bool = False
    blocked_by_older_slot: bool = False


@dataclasses.dataclass
class ShimMetrics:
    """Local shim counters; no keys or plaintext bytes are logged."""

    role: str
    cells_tx: int = 0
    cells_rx: int = 0
    frames_in: int = 0
    frames_out: int = 0
    frame_drops: int = 0
    queue_bytes: int = 0
    queue_frames: int = 0
    queue_high_bytes: int = 0
    queue_high_frames: int = 0
    slot_overflows: int = 0
    deadline_misses: int = 0
    auth_failures: int = 0
    replay_failures: int = 0
    incomplete_slots: int = 0
    malformed_cells: int = 0
    decoded_slots: int = 0
    duplicate_cells: int = 0
    conflicting_duplicates: int = 0
    late_us_max: int = 0
    cpu_seconds: float = 0.0
    max_rss_kib: int = 0
    start_monotonic_ns: int = 0
    emit_slip_us_max: int = 0
    emit_slip_us_p99: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class SlotFrameQueue:
    """One bounded order-preserving FIFO for captured inner frames."""

    def __init__(
        self,
        *,
        max_frames: int = QUEUE_MAX_FRAMES,
        max_bytes: int = QUEUE_MAX_BYTES,
    ) -> None:
        self.max_frames = max_frames
        self.max_bytes = max_bytes
        self._items: Deque[QueuedFrame] = deque()
        self._bytes = 0
        self.high_frames = 0
        self.high_bytes = 0
        self.drops = 0

    @property
    def frame_count(self) -> int:
        return len(self._items)

    @property
    def byte_count(self) -> int:
        return self._bytes

    def admit(self, frame: bytes, slot_name: str) -> bool:
        item = QueuedFrame(bytes(frame), slot_name)
        if len(self._items) >= self.max_frames or self._bytes + item.serialized_len > self.max_bytes:
            self.drops += 1
            return False
        self._items.append(item)
        self._bytes += item.serialized_len
        self.high_frames = max(self.high_frames, len(self._items))
        self.high_bytes = max(self.high_bytes, self._bytes)
        return True

    def pop_for_slot(self, slot_name: str, capacity: int) -> QueuePop:
        if not self._items:
            return QueuePop(tuple())
        if self._items[0].slot_name != slot_name:
            return QueuePop(tuple(), blocked_by_older_slot=True)

        selected: List[bytes] = []
        used = 0
        while self._items and self._items[0].slot_name == slot_name:
            item = self._items[0]
            if not selected and item.serialized_len > capacity:
                self._items.popleft()
                self._bytes -= item.serialized_len
                return QueuePop(tuple(), overflow=True)
            if used + item.serialized_len > capacity:
                break
            self._items.popleft()
            self._bytes -= item.serialized_len
            selected.append(item.frame)
            used += item.serialized_len
        return QueuePop(tuple(selected))


class PublicWindowReceiver:
    """Group outer cells by public per-direction counter windows."""

    def __init__(self, direction: Direction) -> None:
        self.direction = direction
        self._groups: Dict[Tuple[str, int], List[bytes]] = {}
        self.duplicate_cells = 0
        self.conflicting_duplicates = 0

    def add(self, frame: bytes) -> Optional[Tuple[str, int, Tuple[bytes, ...]]]:
        header = public_header_from_frame(frame, default_policy())
        slot_name, epoch_id, window_start = slot_from_public_counter(self.direction, header.cell_counter)
        key = (slot_name, epoch_id)
        group = self._groups.setdefault(key, [])
        public_prefix = frame[:32]
        for existing in group:
            if existing[:32] == public_prefix:
                if existing == frame:
                    self.duplicate_cells += 1
                    group.append(frame)
                    return None
                self.conflicting_duplicates += 1
                group.append(frame)
                return key[0], key[1], tuple(group)
        group.append(frame)
        slot = default_policy().slot(slot_name)
        unique_counters = {
            public_header_from_frame(item, default_policy()).cell_counter
            for item in group
        }
        expected = set(range(window_start, window_start + slot.cell_count))
        if expected.issubset(unique_counters):
            return key[0], key[1], tuple(group)
        return None

    def discard(self, slot_name: str, epoch_id: int) -> None:
        self._groups.pop((slot_name, epoch_id), None)

    def expire_before(self, min_epoch: int) -> int:
        old = [key for key in self._groups if key[1] < min_epoch]
        for key in old:
            self._groups.pop(key, None)
        return len(old)


def slot_from_public_counter(direction: Direction, counter: int) -> Tuple[str, int, int]:
    if counter < 0:
        raise ValueError("counter must be non-negative")
    window = FORWARD_WINDOW if direction is Direction.FORWARD else REVERSE_WINDOW
    width = len(window)
    index = counter % width
    epoch_id = counter // width
    slot_name = window[index]
    slot_start_index = window.index(slot_name)
    return slot_name, epoch_id, counter - index + slot_start_index


def classify_inner_frame(role: str, frame: bytes) -> Optional[str]:
    """Classify a trusted inner frame into its S4 fixed slot."""

    if role not in ROLE_CHOICES:
        raise ValueError("role must be vision or ufispace")
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    if role == "vision":
        if ethertype == ETH_P_ARP:
            return "request"
        tcp = parse_tcp(frame)
        if tcp is None:
            return "request"
        if tcp.pure_ack or (tcp.payload_len == 0 and tcp.flags & TCP_FIN):
            return "tail"
        return "request"

    if ethertype == ETH_P_ARP:
        return "ack"
    tcp = parse_tcp(frame)
    if tcp is None:
        return "ack"
    if tcp.has_payload:
        return "response"
    return "ack"


def parse_tcp(frame: bytes) -> Optional[TcpSummary]:
    if len(frame) < 54 or struct.unpack_from(">H", frame, 12)[0] != ETH_P_IP:
        return None
    ip_offset = 14
    ihl = (frame[ip_offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_offset + ihl + 20:
        return None
    total_length = struct.unpack_from(">H", frame, ip_offset + 2)[0]
    if total_length < ihl + 20 or ip_offset + total_length > len(frame):
        return None
    if frame[ip_offset + 9] != IPPROTO_TCP:
        return None
    tcp_offset = ip_offset + ihl
    tcp_header_len = (frame[tcp_offset + 12] >> 4) * 4
    if tcp_header_len < 20 or tcp_offset + tcp_header_len > ip_offset + total_length:
        return None
    payload_len = total_length - ihl - tcp_header_len
    flags = frame[tcp_offset + 13]
    return TcpSummary(flags=flags, payload_len=payload_len)


def load_runtime_keys(path: Path) -> DirectionalKeys:
    """Read a runtime 64-byte key file with 0600 permissions."""

    path = Path(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise L2ShimError("key file must not be readable or writable by group/other")
    raw = path.read_bytes()
    if len(raw) != KEY_FILE_BYTES:
        raise L2ShimError("key file must contain exactly 64 bytes")
    return DirectionalKeys(forward=raw[:32], reverse=raw[32:])


def open_packet_socket(iface: str, *, ethertype: int = ETH_P_ALL, timeout_s: float = 0.0) -> socket.socket:
    """Open an AF_PACKET socket for complete Ethernet frames."""

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
    sock.bind((iface, 0))
    sock.setblocking(timeout_s != 0.0)
    if timeout_s:
        sock.settimeout(timeout_s)
    return sock


class L2Shim:
    """Raw AF_PACKET S4 shim for one role."""

    def __init__(
        self,
        *,
        role: str,
        inner_iface: str,
        outer_iface: str,
        keys: DirectionalKeys,
        key_epoch: int,
        pcap_prefix: Optional[Path] = None,
    ) -> None:
        if role not in ROLE_CHOICES:
            raise ValueError("role must be vision or ufispace")
        self.role = role
        self.inner_iface = inner_iface
        self.outer_iface = outer_iface
        self.policy = default_policy()
        self.queue = SlotFrameQueue()
        self.metrics = ShimMetrics(role=role)
        self.tx_direction = Direction.FORWARD if role == "vision" else Direction.REVERSE
        self.rx_direction = Direction.REVERSE if role == "vision" else Direction.FORWARD
        self.tx_state = KeyState.fresh(key_epoch, keys)
        self.rx_state = KeyState.fresh(key_epoch, keys)
        self.receiver = PublicWindowReceiver(self.rx_direction)
        self.pcap_prefix = Path(pcap_prefix) if pcap_prefix is not None else None
        self.trusted_input: List[PcapPacket] = []
        self.trusted_output: List[PcapPacket] = []
        self.observed: List[PcapPacket] = []
        self._emit_slips_us: List[int] = []
        self._stop = False

    def request_stop(self) -> None:
        """Ask the run loop to finish the current slot and shut down cleanly."""

        self._stop = True

    def run(
        self,
        duration_s: float,
        *,
        start_monotonic_ns: Optional[int] = None,
        ready_file: Optional[Path] = None,
    ) -> Mapping[str, Any]:
        if duration_s <= 0:
            raise ValueError("duration_s must be positive")
        if start_monotonic_ns is None:
            start_monotonic_ns = time.monotonic_ns()
        if start_monotonic_ns < 0:
            raise ValueError("start_monotonic_ns must be non-negative")
        self.metrics.start_monotonic_ns = start_monotonic_ns
        started = start_monotonic_ns / 1_000_000_000.0
        inner = open_packet_socket(self.inner_iface, ethertype=ETH_P_ALL)
        outer = open_packet_socket(self.outer_iface, ethertype=ETH_P_ALL)
        started_cpu = time.process_time()
        # Sockets are bound and can receive: publish readiness before waiting.
        if ready_file is not None:
            write_ready_file(ready_file)
        # Phase-lock to the shared epoch grid: absorb any traffic that arrives
        # before the common start instant so both shims align on one origin.
        self._pump_until(started, inner, outer)
        epoch_id = 0
        try:
            while not self._stop and time.monotonic() - started < duration_s:
                epoch_start = epoch_start_seconds(start_monotonic_ns, epoch_id)
                self._run_epoch(epoch_id, epoch_start, inner, outer, started, duration_s)
                epoch_id += 1
        finally:
            inner.close()
            outer.close()
            self.metrics.cpu_seconds = time.process_time() - started_cpu
            self.metrics.max_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            self.metrics.queue_bytes = self.queue.byte_count
            self.metrics.queue_frames = self.queue.frame_count
            self.metrics.queue_high_bytes = self.queue.high_bytes
            self.metrics.queue_high_frames = self.queue.high_frames
            self.metrics.frame_drops = self.queue.drops
            self.metrics.emit_slip_us_max = max(self._emit_slips_us, default=0)
            self.metrics.emit_slip_us_p99 = percentile_us(self._emit_slips_us, 99)
            self._write_pcaps()
        return self.metrics.as_dict()

    def _run_epoch(
        self,
        epoch_id: int,
        epoch_start: float,
        inner: socket.socket,
        outer: socket.socket,
        run_started: float,
        duration_s: float,
    ) -> None:
        for slot_name in SLOT_ORDER:
            slot = self.policy.slot(slot_name)
            first_cell_at = epoch_start + slot.offsets_us[0] / 1_000_000.0
            deadline = epoch_start + slot.offsets_us[-1] / 1_000_000.0
            self._pump_until(first_cell_at, inner, outer)
            if self.policy.slot(slot_name).direction is self.tx_direction:
                self._emit_slot(slot_name, epoch_id, outer, epoch_start)
            self._pump_until(deadline, inner, outer)
            now = time.monotonic()
            if now > deadline:
                late_us = int((now - deadline) * 1_000_000)
                self.metrics.deadline_misses += 1
                self.metrics.late_us_max = max(self.metrics.late_us_max, late_us)
        epoch_end = epoch_start + EPOCH_US / 1_000_000.0
        stop = min(epoch_end, run_started + duration_s)
        self._pump_until(stop, inner, outer)
        self.metrics.incomplete_slots += self.receiver.expire_before(max(0, epoch_id - 1))

    def _pump_until(self, deadline: float, inner: socket.socket, outer: socket.socket) -> None:
        while True:
            if self._stop:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                readable, _, _ = select.select((inner, outer), (), (), min(remaining, 0.01))
                if not readable:
                    continue
                now_us = now_epoch_us()
                for sock in readable:
                    frame, addr = sock.recvfrom(65535)
                    if len(addr) >= 3 and addr[2] == PACKET_OUTGOING:
                        continue
                    if sock is inner:
                        self._capture_inner(frame, now_us)
                    else:
                        self._capture_outer(frame, now_us, inner)
            except OSError:
                # Interfaces are being torn down at shutdown; stop cleanly so
                # the finally block still flushes pcaps and metrics.
                self._stop = True
                return

    def _capture_inner(self, frame: bytes, timestamp_us: int) -> None:
        slot_name = classify_inner_frame(self.role, frame)
        if slot_name is None:
            self.metrics.frame_drops += 1
            return
        self.trusted_input.append(PcapPacket(timestamp_us, bytes(frame)))
        self.metrics.frames_in += 1
        if not self.queue.admit(frame, slot_name):
            self.metrics.frame_drops += 1

    def _capture_outer(self, frame: bytes, timestamp_us: int, inner: socket.socket) -> None:
        if len(frame) != WIRE_SIZE or struct.unpack_from(">H", frame, 12)[0] != ETHER_TYPE:
            self.metrics.malformed_cells += 1
            return
        self.observed.append(PcapPacket(timestamp_us, bytes(frame)))
        self.metrics.cells_rx += 1
        try:
            ready = self.receiver.add(bytes(frame))
        except CellDecodeError:
            self.metrics.malformed_cells += 1
            return
        self.metrics.duplicate_cells = self.receiver.duplicate_cells
        self.metrics.conflicting_duplicates = self.receiver.conflicting_duplicates
        if ready is None:
            return
        slot_name, epoch_id, frames = ready
        try:
            decoded = decode_slot(frames, self.policy, slot_name, self.rx_direction, self.rx_state)
        except CellDecodeError as exc:
            if "replay" in str(exc) or "stale" in str(exc):
                self.metrics.replay_failures += 1
            else:
                self.metrics.auth_failures += 1
            self.receiver.discard(slot_name, epoch_id)
            return
        self.receiver.discard(slot_name, epoch_id)
        self.metrics.decoded_slots += 1
        for inner_frame in decoded.frames:
            inner.send(inner_frame)
            self.trusted_output.append(PcapPacket(timestamp_us, inner_frame))
            self.metrics.frames_out += 1

    def _emit_slot(self, slot_name: str, epoch_id: int, outer: socket.socket, epoch_start: float) -> None:
        slot = self.policy.slot(slot_name)
        popped = self.queue.pop_for_slot(slot_name, slot.max_stream_len)
        if popped.overflow:
            self.metrics.slot_overflows += 1
        try:
            encoded = encode_slot(
                popped.frames,
                self.policy,
                slot_name,
                epoch_id,
                self.tx_state,
                protected_type=PROTECTED_TYPE[slot_name],
            )
        except CellEncodeError:
            self.metrics.slot_overflows += 1
            encoded = encode_slot((), self.policy, slot_name, epoch_id, self.tx_state)
        if encoded.status is EncodeStatus.OVERFLOW:
            self.metrics.slot_overflows += 1
        self._send_encoded(outer, encoded, epoch_start)

    def _send_encoded(self, outer: socket.socket, encoded: EncodeResult, epoch_start: float) -> None:
        for cell in encoded.cells:
            if self._stop:
                return
            target = epoch_start + cell.offset_us / 1_000_000.0
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            self._emit_slips_us.append(int((time.monotonic() - target) * 1_000_000))
            timestamp_us = now_epoch_us()
            outer.send(cell.frame)
            self.observed.append(PcapPacket(timestamp_us, cell.frame))
            self.metrics.cells_tx += 1

    def _write_pcaps(self) -> None:
        if self.pcap_prefix is None:
            return
        write_pcap(self.pcap_prefix.with_name(self.pcap_prefix.name + "_trusted_input.pcap"), self.trusted_input)
        write_pcap(self.pcap_prefix.with_name(self.pcap_prefix.name + "_trusted_output.pcap"), self.trusted_output)
        write_pcap(self.pcap_prefix.with_name(self.pcap_prefix.name + "_observed.pcap"), sorted(self.observed, key=lambda item: item.timestamp_us))


def now_epoch_us() -> int:
    return int(time.time() * 1_000_000)


def epoch_start_seconds(start_monotonic_ns: int, epoch_id: int) -> float:
    """Absolute monotonic-seconds start of ``epoch_id`` on the shared grid.

    Both shims call this with the SAME ``start_monotonic_ns`` origin so their
    epoch grids are phase-locked rather than each anchored to its own process
    start. Computed directly from the epoch index to avoid accumulated float
    drift over a long run.
    """

    if start_monotonic_ns < 0 or epoch_id < 0:
        raise ValueError("start_monotonic_ns and epoch_id must be non-negative")
    return start_monotonic_ns / 1_000_000_000.0 + epoch_id * (EPOCH_US / 1_000_000.0)


def percentile_us(samples: Sequence[int], pct: float) -> int:
    """Linear-interpolated percentile of integer microsecond samples."""

    if not samples:
        return 0
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (pct / 100.0) * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return int(round(ordered[lo] + (ordered[hi] - ordered[lo]) * frac))


def write_metrics(path: Path, metrics: Mapping[str, Any]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(metrics, sort_keys=True, indent=2, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=ROLE_CHOICES, required=True)
    parser.add_argument("--inner-iface", required=True)
    parser.add_argument("--outer-iface", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--key-epoch", type=int, default=1)
    parser.add_argument(
        "--start-monotonic-ns",
        type=int,
        required=True,
        help="shared time.monotonic_ns origin for the epoch grid; both shims must pass the same value",
    )
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--metrics-json", type=Path, required=True)
    parser.add_argument("--pcap-prefix", type=Path)
    parser.add_argument("--ready-file", type=Path, help="written once sockets are bound")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    keys = load_runtime_keys(args.key_file)
    shim = L2Shim(
        role=args.role,
        inner_iface=args.inner_iface,
        outer_iface=args.outer_iface,
        keys=keys,
        key_epoch=args.key_epoch,
        pcap_prefix=args.pcap_prefix,
    )
    # Install the stop handler at CLI level so it stays active through the
    # metrics write: a late or repeated SIGTERM only re-sets the stop flag and
    # can never hard-terminate the process mid-flush.
    def _request_stop(_signum: int, _frame: Any) -> None:
        shim.request_stop()

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)
    try:
        metrics = shim.run(
            args.duration_s,
            start_monotonic_ns=args.start_monotonic_ns,
            ready_file=args.ready_file,
        )
    finally:
        # Always persist whatever metrics were accumulated, even if the run was
        # interrupted at teardown, so evidence is never silently lost.
        write_metrics(args.metrics_json, shim.metrics.as_dict())
    print(json.dumps({"role": args.role, "metrics": metrics}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
