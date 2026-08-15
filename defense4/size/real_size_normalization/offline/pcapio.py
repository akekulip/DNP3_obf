"""Small deterministic Ethernet capture reader/writer used by Gate S3.

The generated evidence uses classic microsecond PCAP with Ethernet link type 1.
Keeping the writer here avoids making evidence generation depend on packet
capture privileges or a particular Scapy serializer.
"""

from __future__ import annotations

import dataclasses
import struct
from pathlib import Path
from typing import Iterable, Iterator


PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
DLT_EN10MB = 1
SNAPLEN = 65_535


@dataclasses.dataclass(frozen=True)
class PcapPacket:
    """One captured Ethernet frame at a deterministic microsecond timestamp."""

    timestamp_us: int
    frame: bytes


def write_pcap(path: Path, packets: Iterable[PcapPacket]) -> None:
    """Write a byte-stable little-endian Ethernet PCAP."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            struct.pack(
                "<IHHIIII",
                PCAP_MAGIC_USEC,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                SNAPLEN,
                DLT_EN10MB,
            )
        )
        previous = -1
        for packet in packets:
            if packet.timestamp_us < 0:
                raise ValueError("PCAP timestamp must be non-negative")
            if packet.timestamp_us < previous:
                raise ValueError("PCAP packets must be timestamp ordered")
            if len(packet.frame) > SNAPLEN:
                raise ValueError("frame exceeds PCAP snap length")
            previous = packet.timestamp_us
            seconds, micros = divmod(packet.timestamp_us, 1_000_000)
            handle.write(
                struct.pack(
                    "<IIII", seconds, micros, len(packet.frame), len(packet.frame)
                )
            )
            handle.write(packet.frame)


def read_pcap(path: Path) -> Iterator[PcapPacket]:
    """Read classic PCAP or the Ethernet subset of PCAPNG."""

    path = Path(path)
    with path.open("rb") as probe:
        first_word = probe.read(4)
    if first_word == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(path)
        return
    with path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) != 24:
            raise ValueError("truncated PCAP global header")
        magic = global_header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, divisor = "<", 1
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, divisor = ">", 1
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, divisor = "<", 1_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, divisor = ">", 1_000
        else:
            raise ValueError("unsupported capture format (expected classic PCAP)")
        _, major, minor, _, _, snaplen, network = struct.unpack(
            f"{endian}IHHIIII", global_header
        )
        if (major, minor) != (2, 4) or network != DLT_EN10MB:
            raise ValueError("unsupported PCAP version or link type")
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, fraction, captured, original = struct.unpack(
                f"{endian}IIII", packet_header
            )
            if captured > snaplen or captured > original:
                raise ValueError("invalid PCAP captured length")
            frame = handle.read(captured)
            if len(frame) != captured:
                raise ValueError("truncated PCAP frame")
            timestamp_us = seconds * 1_000_000 + fraction // divisor
            yield PcapPacket(timestamp_us=timestamp_us, frame=frame)


def _read_pcapng(path: Path) -> Iterator[PcapPacket]:
    """Read Section/Interface/Enhanced-Packet blocks from an Ethernet PCAPNG."""

    with Path(path).open("rb") as handle:
        prefix = handle.read(12)
        if len(prefix) != 12 or prefix[:4] != b"\x0a\x0d\x0d\x0a":
            raise ValueError("invalid PCAPNG section header")
        if prefix[8:12] == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        elif prefix[8:12] == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        else:
            raise ValueError("invalid PCAPNG byte-order magic")
        handle.seek(0)
        interfaces = []
        previous = -1
        while True:
            header = handle.read(8)
            if not header:
                return
            if len(header) != 8:
                raise ValueError("truncated PCAPNG block header")
            block_type, block_length = struct.unpack(f"{endian}II", header)
            if block_length < 12 or block_length % 4:
                raise ValueError("invalid PCAPNG block length")
            remainder = handle.read(block_length - 8)
            if len(remainder) != block_length - 8:
                raise ValueError("truncated PCAPNG block")
            trailing_length = struct.unpack(f"{endian}I", remainder[-4:])[0]
            if trailing_length != block_length:
                raise ValueError("PCAPNG block length mismatch")
            body = remainder[:-4]

            if block_type == 0x0A0D0D0A:
                if len(body) < 16:
                    raise ValueError("truncated PCAPNG section")
                magic = body[:4]
                if magic == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif magic == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("invalid PCAPNG section byte order")
                interfaces = []
                continue

            if block_type == 1:
                if len(body) < 8:
                    raise ValueError("truncated PCAPNG interface block")
                linktype = struct.unpack_from(f"{endian}H", body, 0)[0]
                if linktype != DLT_EN10MB:
                    raise ValueError("PCAPNG interface is not Ethernet")
                units_per_second = 1_000_000
                options = body[8:]
                offset = 0
                while offset + 4 <= len(options):
                    code, length = struct.unpack_from(f"{endian}HH", options, offset)
                    offset += 4
                    if code == 0:
                        break
                    value = options[offset : offset + length]
                    offset += (length + 3) & ~3
                    if code == 9 and value:
                        resolution = value[0]
                        units_per_second = (
                            2 ** (resolution & 0x7F)
                            if resolution & 0x80
                            else 10 ** resolution
                        )
                interfaces.append((linktype, units_per_second))
                continue

            if block_type != 6:
                continue
            if len(body) < 20:
                raise ValueError("truncated PCAPNG enhanced packet block")
            interface_id, ts_high, ts_low, captured, original = struct.unpack_from(
                f"{endian}IIIII", body, 0
            )
            if interface_id >= len(interfaces) or captured > original:
                raise ValueError("invalid PCAPNG enhanced packet metadata")
            frame = body[20 : 20 + captured]
            if len(frame) != captured:
                raise ValueError("truncated PCAPNG enhanced packet data")
            units_per_second = interfaces[interface_id][1]
            ticks = (ts_high << 32) | ts_low
            timestamp_us = ticks * 1_000_000 // units_per_second
            if timestamp_us < previous:
                raise ValueError("PCAPNG packets are not timestamp ordered")
            previous = timestamp_us
            yield PcapPacket(timestamp_us=timestamp_us, frame=bytes(frame))
