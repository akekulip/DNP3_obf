"""Test-only raw Ethernet link emulator for S4 outer cells.

The emulator bridges complete Layer-2 frames between two Linux interfaces using
AF_PACKET sockets. It is deliberately small test apparatus: the baseline path
forwards bytes exactly, and optional deterministic fault rules are applied only
after a frame has already been observed from the sender side.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import select
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from defense4.size.real_size_normalization.offline.cell_codec import (
    ETHER_TYPE,
    ETHERNET_HEADER_LEN,
    WIRE_SIZE,
    Direction,
    default_policy,
    public_header_from_frame,
)
from defense4.size.real_size_normalization.software.runner_support import write_ready_file


ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


@dataclasses.dataclass(frozen=True)
class FrameIdentity:
    """Public metadata available without decrypting a fixed cell."""

    direction: Optional[str]
    counter: Optional[int]
    key_epoch: Optional[int]
    position: int


@dataclasses.dataclass(frozen=True)
class ForwardEvent:
    """One frame received from a sender side before link fault injection."""

    ingress: str
    egress: str
    frame: bytes
    identity: FrameIdentity


@dataclasses.dataclass(frozen=True)
class FaultRule:
    """One deterministic post-emission impairment rule."""

    action: str
    direction: Optional[str] = None
    counter: Optional[int] = None
    position: Optional[int] = None
    replay_direction: Optional[str] = None
    replay_counter: Optional[int] = None
    replay_position: Optional[int] = None

    def matches(self, event: ForwardEvent) -> bool:
        identity = event.identity
        return (
            (self.direction is None or self.direction == identity.direction)
            and (self.counter is None or self.counter == identity.counter)
            and (self.position is None or self.position == identity.position)
        )


@dataclasses.dataclass
class LinkMetrics:
    """Runtime counters for a bounded cell-link run."""

    started_at_us: int
    ended_at_us: int = 0
    duration_s: float = 0.0
    frames_received: int = 0
    bytes_received: int = 0
    frames_forwarded: int = 0
    bytes_forwarded: int = 0
    packet_outgoing_ignored: int = 0
    non_cell_frames: int = 0
    cell_frames: int = 0
    dropped: int = 0
    duplicated: int = 0
    reordered: int = 0
    replayed: int = 0
    flushed_reorder: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class FaultPlan:
    """Stateful deterministic fault engine used by both tests and the CLI."""

    def __init__(self, rules: Iterable[FaultRule] = ()) -> None:
        self.rules = tuple(rules)
        self._archive: List[ForwardEvent] = []
        # Held reorder events are keyed by egress lane so a frame delayed on one
        # direction is only ever released behind a later frame on that SAME lane,
        # and is delivered through its own egress rather than the opposite one.
        self._held: Dict[str, ForwardEvent] = {}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "FaultPlan":
        rules = data.get("rules", data.get("faults", []))
        if not isinstance(rules, list):
            raise ValueError("fault plan rules must be a list")
        return cls(_rule_from_mapping(item) for item in rules)

    @classmethod
    def from_json_file(cls, path: Path) -> "FaultPlan":
        with Path(path).open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, Mapping):
            raise ValueError("fault plan JSON must be an object")
        return cls.from_mapping(data)

    def apply(self, event: ForwardEvent, metrics: Optional[LinkMetrics] = None) -> Tuple[bytes, ...]:
        """Return egress frames after applying post-emission faults."""

        matched = next((rule for rule in self.rules if rule.matches(event)), None)
        if matched is not None and matched.action == "drop":
            self._archive.append(event)
            if metrics is not None:
                metrics.dropped += 1
            return ()

        if matched is not None and matched.action == "reorder":
            if event.egress in self._held:
                raise RuntimeError("cannot start a reorder while a frame is held on this egress lane")
            self._archive.append(event)
            self._held[event.egress] = event
            if metrics is not None:
                metrics.reordered += 1
            return ()

        deliveries: List[bytes] = [event.frame]
        held = self._held.pop(event.egress, None)
        if held is not None:
            deliveries.append(held.frame)
            if metrics is not None:
                metrics.flushed_reorder += 1

        if matched is not None and matched.action == "duplicate":
            deliveries.append(event.frame)
            if metrics is not None:
                metrics.duplicated += 1
        elif matched is not None and matched.action == "replay":
            deliveries.append(self._replay_frame(matched, default=event.frame))
            if metrics is not None:
                metrics.replayed += 1
        elif matched is not None and matched.action != "pass":
            raise ValueError("unknown fault action %r" % (matched.action,))

        self._archive.append(event)
        return tuple(deliveries)

    def flush_events(self, metrics: Optional[LinkMetrics] = None) -> Tuple[ForwardEvent, ...]:
        if not self._held:
            return ()
        events = tuple(self._held.values())
        self._held.clear()
        if metrics is not None:
            metrics.flushed_reorder += len(events)
        return events

    def flush(self, metrics: Optional[LinkMetrics] = None) -> Tuple[bytes, ...]:
        return tuple(event.frame for event in self.flush_events(metrics))

    def _replay_frame(self, rule: FaultRule, *, default: bytes) -> bytes:
        for event in reversed(self._archive):
            identity = event.identity
            if (
                (rule.replay_direction is None or rule.replay_direction == identity.direction)
                and (rule.replay_counter is None or rule.replay_counter == identity.counter)
                and (rule.replay_position is None or rule.replay_position == identity.position)
            ):
                return event.frame
        return default


class FrameClassifier:
    """Assign public direction/counter metadata and deterministic positions."""

    def __init__(self) -> None:
        self._policy = default_policy()
        self._positions: Dict[str, int] = {"a_to_b": 0, "b_to_a": 0}
        self._outers = {
            Direction.FORWARD.value: self._outer(Direction.FORWARD),
            Direction.REVERSE.value: self._outer(Direction.REVERSE),
        }

    def event(self, ingress: str, egress: str, frame: bytes, lane: str) -> ForwardEvent:
        position = self._positions[lane]
        self._positions[lane] = position + 1
        direction: Optional[str] = None
        counter: Optional[int] = None
        key_epoch: Optional[int] = None
        if len(frame) == WIRE_SIZE and frame[:ETHERNET_HEADER_LEN] in self._outers.values():
            for candidate, outer in self._outers.items():
                if frame[:ETHERNET_HEADER_LEN] == outer:
                    direction = candidate
                    break
            try:
                header = public_header_from_frame(frame, self._policy)
            except Exception:
                direction = None
            else:
                counter = header.cell_counter
                key_epoch = header.key_epoch
        return ForwardEvent(
            ingress=ingress,
            egress=egress,
            frame=bytes(frame),
            identity=FrameIdentity(direction, counter, key_epoch, position),
        )

    def _outer(self, direction: Direction) -> bytes:
        macs = self._policy.outer_macs[direction]
        return macs.dst + macs.src + struct.pack(">H", ETHER_TYPE)


def apply_fault_plan(events: Iterable[ForwardEvent], plan: FaultPlan) -> Tuple[bytes, ...]:
    """Pure helper used by unit tests to prove deterministic fault ordering."""

    output: List[bytes] = []
    for event in events:
        output.extend(plan.apply(event))
    output.extend(plan.flush())
    return tuple(output)


def open_packet_socket(iface: str) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.setblocking(False)
    return sock


def run_link(
    iface_a: str,
    iface_b: str,
    *,
    duration_s: float,
    fault_plan: FaultPlan,
    ready_file: Optional[Path] = None,
) -> LinkMetrics:
    socks = {iface_a: open_packet_socket(iface_a), iface_b: open_packet_socket(iface_b)}
    peers = {iface_a: iface_b, iface_b: iface_a}
    classifier = FrameClassifier()
    metrics = LinkMetrics(started_at_us=_now_us(), duration_s=duration_s)
    stop = False

    def _stop(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    previous_int = signal.signal(signal.SIGINT, _stop)
    previous_term = signal.signal(signal.SIGTERM, _stop)
    if ready_file is not None:
        write_ready_file(ready_file)
    deadline = time.monotonic() + duration_s if duration_s > 0 else None
    try:
        while not stop and (deadline is None or time.monotonic() < deadline):
            timeout = 0.1
            if deadline is not None:
                timeout = max(0.0, min(timeout, deadline - time.monotonic()))
            readable, _, _ = select.select(list(socks.values()), (), (), timeout)
            for sock in readable:
                frame, addr = sock.recvfrom(65535)
                iface = str(addr[0])
                packet_type = int(addr[2]) if len(addr) > 2 else -1
                if packet_type == PACKET_OUTGOING:
                    metrics.packet_outgoing_ignored += 1
                    continue
                peer = peers[iface]
                lane = "a_to_b" if iface == iface_a else "b_to_a"
                event = classifier.event(iface, peer, frame, lane)
                metrics.frames_received += 1
                metrics.bytes_received += len(frame)
                if event.identity.direction is None:
                    metrics.non_cell_frames += 1
                else:
                    metrics.cell_frames += 1
                for out_frame in fault_plan.apply(event, metrics):
                    socks[peer].send(out_frame)
                    metrics.frames_forwarded += 1
                    metrics.bytes_forwarded += len(out_frame)
        for event in fault_plan.flush_events(metrics):
            socks[event.egress].send(event.frame)
            metrics.frames_forwarded += 1
            metrics.bytes_forwarded += len(event.frame)
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)
        for sock in socks.values():
            sock.close()
        metrics.ended_at_us = _now_us()
    return metrics


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface-a", required=True)
    parser.add_argument("--iface-b", required=True)
    parser.add_argument("--duration", type=float, default=0.0, help="seconds; 0 means until signal")
    parser.add_argument("--fault-plan", type=Path)
    parser.add_argument("--metrics-json", type=Path)
    parser.add_argument("--ready-file", type=Path, help="written once both interfaces are bound")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    plan = FaultPlan.from_json_file(args.fault_plan) if args.fault_plan else FaultPlan()
    metrics = run_link(
        args.iface_a,
        args.iface_b,
        duration_s=args.duration,
        fault_plan=plan,
        ready_file=args.ready_file,
    )
    text = json.dumps(metrics.as_dict(), sort_keys=True, indent=2) + "\n"
    if args.metrics_json:
        args.metrics_json.parent.mkdir(parents=True, exist_ok=True)
        args.metrics_json.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


def _rule_from_mapping(data: Mapping[str, Any]) -> FaultRule:
    action = str(data.get("action", "pass"))
    if action not in {"pass", "drop", "duplicate", "reorder", "replay"}:
        raise ValueError("unsupported fault action %r" % (action,))
    return FaultRule(
        action=action,
        direction=_optional_str(data.get("direction")),
        counter=_optional_int(data.get("counter")),
        position=_optional_int(data.get("position")),
        replay_direction=_optional_str(data.get("replay_direction")),
        replay_counter=_optional_int(data.get("replay_counter")),
        replay_position=_optional_int(data.get("replay_position")),
    )


def _optional_str(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _optional_int(value: Any) -> Optional[int]:
    return None if value is None else int(value)


def _now_us() -> int:
    return time.time_ns() // 1_000


if __name__ == "__main__":
    raise SystemExit(main())
