"""Packet integrity oracles for S4 synthetic DNP3/TCP evidence.

The functions here are intentionally side-effect free so they can be reused
against later PCAP-derived Ethernet frames.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import struct
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from defense4.size.native_parity.h3_harness import dnp3_wire


ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6


@dataclasses.dataclass(frozen=True)
class TcpPacket:
    """Parsed Ethernet/IPv4/TCP packet facts needed by checksum and sequence oracles."""

    src_mac: bytes
    dst_mac: bytes
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence: int
    acknowledgment: int
    flags: int
    ip_total_length: int
    tcp_payload: bytes
    frame_length: int

    @property
    def flow_id(self) -> Tuple[str, int, str, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    @property
    def sequence_span(self) -> int:
        span = len(self.tcp_payload)
        if self.flags & 0x02:
            span += 1
        if self.flags & 0x01:
            span += 1
        return span


@dataclasses.dataclass(frozen=True)
class OracleResult:
    """Boolean oracle result with machine-readable errors."""

    ok: bool
    errors: Tuple[str, ...] = ()


def validate_dnp3_frame(frame: bytes) -> bool:
    """Validate DNP3 link header CRC and every user-data block CRC."""

    return not dnp3_crc_errors(frame)


def validate_dnp3_stream(data: bytes) -> OracleResult:
    """Validate one or more complete DNP3 link frames in a TCP byte stream."""

    errors: List[str] = []
    offset = 0
    count = 0
    while offset < len(data):
        if offset + 10 > len(data):
            errors.append("truncated_dnp3_header")
            break
        if data[offset : offset + 2] != b"\x05\x64":
            errors.append("missing_dnp3_sync_at_%d" % offset)
            break
        total = dnp3_frame_length(data[offset:])
        if total is None:
            errors.append("invalid_dnp3_length_at_%d" % offset)
            break
        frame = data[offset : offset + total]
        if len(frame) != total:
            errors.append("truncated_dnp3_frame_at_%d" % offset)
            break
        errors.extend("frame_%d_%s" % (count, item) for item in dnp3_crc_errors(frame))
        offset += total
        count += 1
    if count == 0 and not errors:
        errors.append("empty_dnp3_stream")
    return OracleResult(ok=not errors, errors=tuple(errors))


def dnp3_frame_length(data: bytes) -> Optional[int]:
    """Return the full DNP3 link frame length from a buffer prefix."""

    if len(data) < 3 or data[0:2] != b"\x05\x64":
        return None
    user_len = data[2] - 5
    if user_len < 0:
        return None
    blocks = (user_len + 15) // 16 if user_len else 0
    return 10 + user_len + (2 * blocks)


def dnp3_crc_errors(frame: bytes) -> Tuple[str, ...]:
    """Return DNP3 CRC failures for a complete link frame."""

    errors: List[str] = []
    total = dnp3_frame_length(frame)
    if total is None:
        return ("invalid_dnp3_prefix_or_length",)
    if len(frame) != total:
        return ("dnp3_length_mismatch",)
    header = frame[:8]
    header_crc = struct.unpack_from("<H", frame, 8)[0]
    if dnp3_wire.dnp3_crc(header) != header_crc:
        errors.append("dnp3_header_crc")
    user_len = frame[2] - 5
    pos = 10
    remaining = user_len
    block_index = 0
    while remaining:
        block_len = min(16, remaining)
        block = frame[pos : pos + block_len]
        actual = struct.unpack_from("<H", frame, pos + block_len)[0]
        expected = dnp3_wire.dnp3_crc(block)
        if actual != expected:
            errors.append("dnp3_data_crc_%d" % block_index)
        pos += block_len + 2
        remaining -= block_len
        block_index += 1
    return tuple(errors)


def parse_ethernet_ipv4_tcp(frame: bytes) -> TcpPacket:
    """Parse one Ethernet/IPv4/TCP frame or raise ``ValueError``."""

    if len(frame) < 54:
        raise ValueError("frame too short for Ethernet/IPv4/TCP")
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    if ethertype != ETHERTYPE_IPV4:
        raise ValueError("not IPv4 EtherType")
    ip_offset = 14
    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4:
        raise ValueError("not IPv4")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        raise ValueError("invalid IPv4 header length")
    total_length = struct.unpack_from(">H", frame, ip_offset + 2)[0]
    if total_length < ihl or ip_offset + total_length > len(frame):
        raise ValueError("invalid IPv4 total length")
    if frame[ip_offset + 9] != IPPROTO_TCP:
        raise ValueError("not TCP")
    tcp_offset = ip_offset + ihl
    if tcp_offset + 20 > ip_offset + total_length:
        raise ValueError("truncated TCP header")
    tcp_header_len = (frame[tcp_offset + 12] >> 4) * 4
    if tcp_header_len < 20 or tcp_offset + tcp_header_len > ip_offset + total_length:
        raise ValueError("invalid TCP header length")
    src_ip = str(ipaddress.IPv4Address(frame[ip_offset + 12 : ip_offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(frame[ip_offset + 16 : ip_offset + 20]))
    src_port, dst_port, seq, ack = struct.unpack_from(">HHII", frame, tcp_offset)
    payload_start = tcp_offset + tcp_header_len
    payload_end = ip_offset + total_length
    return TcpPacket(
        src_mac=frame[6:12],
        dst_mac=frame[0:6],
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        sequence=seq,
        acknowledgment=ack,
        flags=frame[tcp_offset + 13],
        ip_total_length=total_length,
        tcp_payload=frame[payload_start:payload_end],
        frame_length=len(frame),
    )


def validate_ipv4_tcp_checksums(frame: bytes) -> OracleResult:
    """Validate IPv4 header checksum and TCP checksum for one Ethernet frame."""

    errors: List[str] = []
    try:
        parse_ethernet_ipv4_tcp(frame)
    except ValueError as exc:
        return OracleResult(False, (str(exc),))

    ip_offset = 14
    ihl = (frame[ip_offset] & 0x0F) * 4
    total_length = struct.unpack_from(">H", frame, ip_offset + 2)[0]
    ip_header = frame[ip_offset : ip_offset + ihl]
    if ones_complement_checksum(ip_header) != 0:
        errors.append("ipv4_header_checksum")

    tcp_offset = ip_offset + ihl
    tcp_segment = frame[tcp_offset : ip_offset + total_length]
    pseudo_header = (
        frame[ip_offset + 12 : ip_offset + 16]
        + frame[ip_offset + 16 : ip_offset + 20]
        + struct.pack(">BBH", 0, IPPROTO_TCP, len(tcp_segment))
    )
    if ones_complement_checksum(pseudo_header + tcp_segment) != 0:
        errors.append("tcp_checksum")
    return OracleResult(ok=not errors, errors=tuple(errors))


def validate_tcp_sequences(frames: Sequence[bytes]) -> OracleResult:
    """Check per-flow TCP sequence continuity in capture order."""

    errors: List[str] = []
    next_seq_by_flow: Dict[Tuple[str, int, str, int], int] = {}
    for index, frame in enumerate(frames):
        checksum = validate_ipv4_tcp_checksums(frame)
        if not checksum.ok:
            errors.extend("frame_%d_%s" % (index, item) for item in checksum.errors)
            continue
        packet = parse_ethernet_ipv4_tcp(frame)
        expected = next_seq_by_flow.get(packet.flow_id)
        if expected is not None and packet.sequence != expected:
            errors.append(
                "frame_%d_sequence_%d_expected_%d" % (index, packet.sequence, expected)
            )
        next_seq_by_flow[packet.flow_id] = (packet.sequence + packet.sequence_span) & 0xFFFFFFFF
    return OracleResult(ok=not errors, errors=tuple(errors))


def tcp_packet_facts(frame: bytes) -> Mapping[str, object]:
    """Return log-safe packet facts without payload bytes."""

    packet = parse_ethernet_ipv4_tcp(frame)
    return {
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "sequence": packet.sequence,
        "acknowledgment": packet.acknowledgment,
        "flags": packet.flags,
        "payload_len": len(packet.tcp_payload),
        "frame_len": packet.frame_length,
    }


def ones_complement_checksum(data: bytes) -> int:
    """Internet checksum used by IPv4 and TCP."""

    if len(data) & 1:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF
