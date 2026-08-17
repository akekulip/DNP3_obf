"""Independent AF_PACKET observer for S4 outer-link evidence."""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import select
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from defense4.size.real_size_normalization.offline.cell_codec import (
    ETHER_TYPE,
    ETHERNET_HEADER_LEN,
    WIRE_SIZE,
    Direction,
    default_policy,
    public_header_from_frame,
)
from defense4.size.real_size_normalization.offline.pcapio import PcapPacket, write_pcap
from defense4.size.real_size_normalization.software.runner_support import write_ready_file


ETH_P_ALL = 0x0003
PACKET_TYPES = {
    0: "host",
    1: "broadcast",
    2: "multicast",
    3: "otherhost",
    4: "outgoing",
}


@dataclasses.dataclass(frozen=True)
class CaptureRecord:
    timestamp_us: int
    interface: str
    packet_type: int
    frame: bytes
    direction: Optional[str]
    key_epoch: Optional[int]
    cell_counter: Optional[int]

    def metadata(self, index: int) -> Dict[str, Any]:
        ethertype = struct.unpack(">H", self.frame[12:14])[0] if len(self.frame) >= 14 else None
        return {
            "index": index,
            "timestamp_us": self.timestamp_us,
            "interface": self.interface,
            "packet_type": self.packet_type,
            "packet_type_name": PACKET_TYPES.get(self.packet_type, str(self.packet_type)),
            "wire_len": len(self.frame),
            "dst_mac": _mac(self.frame[0:6]) if len(self.frame) >= 14 else "",
            "src_mac": _mac(self.frame[6:12]) if len(self.frame) >= 14 else "",
            "ethertype": "0x%04x" % ethertype if ethertype is not None else "",
            "direction": self.direction or "",
            "key_epoch": "" if self.key_epoch is None else self.key_epoch,
            "cell_counter": "" if self.cell_counter is None else self.cell_counter,
        }


@dataclasses.dataclass
class CaptureMetrics:
    started_at_us: int
    ended_at_us: int = 0
    duration_s: float = 0.0
    packets: int = 0
    bytes: int = 0
    cells: int = 0
    non_cells: int = 0
    outgoing_packets: int = 0
    incoming_packets: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class CellClassifier:
    def __init__(self) -> None:
        self._policy = default_policy()
        self._outers = {
            Direction.FORWARD.value: self._outer(Direction.FORWARD),
            Direction.REVERSE.value: self._outer(Direction.REVERSE),
        }

    def classify(self, frame: bytes) -> Dict[str, Optional[Any]]:
        if len(frame) != WIRE_SIZE or frame[:ETHERNET_HEADER_LEN] not in self._outers.values():
            return {"direction": None, "key_epoch": None, "cell_counter": None}
        direction = None
        for candidate, outer in self._outers.items():
            if frame[:ETHERNET_HEADER_LEN] == outer:
                direction = candidate
                break
        try:
            public = public_header_from_frame(frame, self._policy)
        except Exception:
            return {"direction": None, "key_epoch": None, "cell_counter": None}
        return {
            "direction": direction,
            "key_epoch": public.key_epoch,
            "cell_counter": public.cell_counter,
        }

    def _outer(self, direction: Direction) -> bytes:
        macs = self._policy.outer_macs[direction]
        return macs.dst + macs.src + struct.pack(">H", ETHER_TYPE)


def open_capture_socket(iface: str) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.setblocking(False)
    return sock


def capture(
    iface: str, *, duration_s: float, ready_file: Optional[Path] = None
) -> Tuple[List[CaptureRecord], CaptureMetrics]:
    sock = open_capture_socket(iface)
    classifier = CellClassifier()
    metrics = CaptureMetrics(started_at_us=_now_us(), duration_s=duration_s)
    records: List[CaptureRecord] = []
    stop = False

    def _stop(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    previous_int = signal.signal(signal.SIGINT, _stop)
    previous_term = signal.signal(signal.SIGTERM, _stop)
    if ready_file is not None:
        write_ready_file(ready_file)
    deadline = time.monotonic() + duration_s if duration_s > 0 else None
    previous_ts = -1
    try:
        while not stop and (deadline is None or time.monotonic() < deadline):
            timeout = 0.1
            if deadline is not None:
                timeout = max(0.0, min(timeout, deadline - time.monotonic()))
            readable, _, _ = select.select([sock], (), (), timeout)
            if not readable:
                continue
            frame, addr = sock.recvfrom(65535)
            timestamp_us = max(_now_us(), previous_ts)
            previous_ts = timestamp_us
            packet_type = int(addr[2]) if len(addr) > 2 else -1
            meta = classifier.classify(frame)
            record = CaptureRecord(
                timestamp_us=timestamp_us,
                interface=iface,
                packet_type=packet_type,
                frame=bytes(frame),
                direction=meta["direction"],
                key_epoch=meta["key_epoch"],
                cell_counter=meta["cell_counter"],
            )
            records.append(record)
            metrics.packets += 1
            metrics.bytes += len(frame)
            if record.direction is None:
                metrics.non_cells += 1
            else:
                metrics.cells += 1
            if packet_type == 4:
                metrics.outgoing_packets += 1
            else:
                metrics.incoming_packets += 1
    finally:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)
        sock.close()
        metrics.ended_at_us = _now_us()
    return records, metrics


def write_metadata_jsonl(path: Path, records: Sequence[CaptureRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for index, record in enumerate(records):
            handle.write(json.dumps(record.metadata(index), sort_keys=True) + "\n")


def write_metadata_csv(path: Path, records: Sequence[CaptureRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = (
        "index",
        "timestamp_us",
        "interface",
        "packet_type",
        "packet_type_name",
        "wire_len",
        "dst_mac",
        "src_mac",
        "ethertype",
        "direction",
        "key_epoch",
        "cell_counter",
    )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for index, record in enumerate(records):
            writer.writerow(record.metadata(index))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--duration", type=float, default=0.0, help="seconds; 0 means until signal")
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--jsonl", type=Path)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--metrics-json", type=Path)
    parser.add_argument("--ready-file", type=Path, help="written once the capture socket is bound")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    records, metrics = capture(args.iface, duration_s=args.duration, ready_file=args.ready_file)
    write_pcap(args.pcap, (PcapPacket(record.timestamp_us, record.frame) for record in records))
    if args.jsonl:
        write_metadata_jsonl(args.jsonl, records)
    if args.csv:
        write_metadata_csv(args.csv, records)
    text = json.dumps(metrics.as_dict(), sort_keys=True, indent=2) + "\n"
    if args.metrics_json:
        args.metrics_json.parent.mkdir(parents=True, exist_ok=True)
        args.metrics_json.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


def _mac(data: bytes) -> str:
    return ":".join("%02x" % byte for byte in data)


def _now_us() -> int:
    return time.time_ns() // 1_000


if __name__ == "__main__":
    raise SystemExit(main())
