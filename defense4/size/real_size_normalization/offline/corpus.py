"""Deterministic captured and synthetic inner-frame corpus for Gate S3."""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import random
import struct
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Tuple

from .pcapio import read_pcap


FORWARD = "forward"
REVERSE = "reverse"
SLOTS = ("request", "ack", "response", "tail")
INNER_MASTER_MAC = bytes.fromhex("020000000101")
INNER_RELAY_MAC = bytes.fromhex("020000000707")


@dataclasses.dataclass(frozen=True)
class CorpusCase:
    case_id: str
    transaction_class: str
    protected_inner_length: int
    source_kind: str
    source_ref: str
    slots: Mapping[str, Tuple[bytes, ...]]
    primary_rn_l: bool = True


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _payload(length: int, seed: str) -> bytes:
    out = bytearray()
    block = 0
    while len(out) < length:
        out.extend(
            hashlib.blake2s(
                f"{seed}:{block}".encode("utf-8"), digest_size=32
            ).digest()
        )
        block += 1
    return bytes(out[:length])


def make_ipv4_tcp_frame(
    payload_length: int,
    seed: str,
    direction: str,
    *,
    flags: int = 0x18,
    sequence: int = 1,
    acknowledgment: int = 1,
) -> bytes:
    """Build a checksum-valid deterministic Ethernet/IPv4/TCP frame."""

    if payload_length < 0 or payload_length > 1_460:
        raise ValueError("synthetic TCP payload must fit the 1500-byte IPv4 MTU")
    if direction == FORWARD:
        src_mac, dst_mac = INNER_MASTER_MAC, INNER_RELAY_MAC
        src_ip, dst_ip = "192.0.2.1", "192.0.2.7"
        sport, dport = 40_000, 20_000
    elif direction == REVERSE:
        src_mac, dst_mac = INNER_RELAY_MAC, INNER_MASTER_MAC
        src_ip, dst_ip = "192.0.2.7", "192.0.2.1"
        sport, dport = 20_000, 40_000
    else:
        raise ValueError(f"unknown direction: {direction}")

    payload = _payload(payload_length, seed)
    src_ip_bytes = ipaddress.IPv4Address(src_ip).packed
    dst_ip_bytes = ipaddress.IPv4Address(dst_ip).packed
    tcp_wo_checksum = struct.pack(
        ">HHIIBBHHH",
        sport,
        dport,
        sequence & 0xFFFFFFFF,
        acknowledgment & 0xFFFFFFFF,
        5 << 4,
        flags & 0xFF,
        8_192,
        0,
        0,
    )
    pseudo = (
        src_ip_bytes
        + dst_ip_bytes
        + struct.pack(">BBH", 0, 6, len(tcp_wo_checksum) + len(payload))
    )
    tcp_checksum = _checksum(pseudo + tcp_wo_checksum + payload)
    tcp = tcp_wo_checksum[:16] + struct.pack(">H", tcp_checksum) + tcp_wo_checksum[18:]

    total_length = 20 + len(tcp) + len(payload)
    ip_wo_checksum = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        int.from_bytes(hashlib.blake2s(seed.encode(), digest_size=2).digest(), "big"),
        0x4000,
        64,
        6,
        0,
        src_ip_bytes,
        dst_ip_bytes,
    )
    ip_header = ip_wo_checksum[:10] + struct.pack(">H", _checksum(ip_wo_checksum)) + ip_wo_checksum[12:]
    ethernet = dst_mac + src_mac + struct.pack(">H", 0x0800)
    return ethernet + ip_header + tcp + payload


def make_arp_frame(seed: str, direction: str = FORWARD) -> bytes:
    """Build a deterministic 60-byte Ethernet ARP fixture."""

    if direction == FORWARD:
        src, dst = INNER_MASTER_MAC, b"\xff" * 6
        sender, target = "192.0.2.1", "192.0.2.7"
    else:
        src, dst = INNER_RELAY_MAC, INNER_MASTER_MAC
        sender, target = "192.0.2.7", "192.0.2.1"
    body = struct.pack(
        ">HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1 if direction == FORWARD else 2,
        src,
        ipaddress.IPv4Address(sender).packed,
        b"\x00" * 6 if direction == FORWARD else dst,
        ipaddress.IPv4Address(target).packed,
    )
    frame = dst + src + struct.pack(">H", 0x0806) + body
    return frame + _payload(60 - len(frame), f"arp:{seed}")


def _split_payload(length: int) -> List[int]:
    """Use a stable TCP-like segmentation that stays within a standard MTU."""

    if length == 0:
        return []
    chunks: List[int] = []
    remaining = length
    while remaining:
        chunk = min(292, remaining)
        chunks.append(chunk)
        remaining -= chunk
    return chunks


def synthetic_case(case_id: str, protected_length: int, repeat: int) -> CorpusCase:
    response = tuple(
        make_ipv4_tcp_frame(
            size,
            f"{case_id}:response:{index}:{repeat}",
            REVERSE,
            sequence=10_000 + index * 292,
            acknowledgment=21,
        )
        for index, size in enumerate(_split_payload(protected_length))
    )
    slots = {
        "request": (
            make_ipv4_tcp_frame(
                20,
                f"{case_id}:request:{repeat}",
                FORWARD,
                sequence=1,
                acknowledgment=1,
            ),
        ),
        "ack": (
            make_ipv4_tcp_frame(
                0,
                f"{case_id}:ack:{repeat}",
                REVERSE,
                flags=0x10,
                sequence=10_000,
                acknowledgment=21,
            ),
        ),
        "response": response,
        "tail": (
            make_ipv4_tcp_frame(
                0,
                f"{case_id}:tail:{repeat}",
                FORWARD,
                flags=0x10,
                sequence=21,
                acknowledgment=10_000 + protected_length,
            ),
        ),
    }
    return CorpusCase(
        case_id=case_id,
        transaction_class="READ_LENGTH_STRESS",
        protected_inner_length=protected_length,
        source_kind="synthetic",
        source_ref="deterministic Ethernet/IPv4/TCP fixture",
        slots={name: tuple(slots[name]) for name in SLOTS},
        primary_rn_l=True,
    )


def build_synthetic_corpus() -> List[CorpusCase]:
    """Build 100 balanced RN-L epochs plus control and boundary cases."""

    primary: List[CorpusCase] = []
    for length in (17, 49, 58, 243, 1_574):
        for repeat in range(20):
            primary.append(
                synthetic_case(f"rn-l-{length:04d}-{repeat:02d}", length, repeat)
            )
    random.Random(0xD4C311).shuffle(primary)

    boundary_lengths = (0, 1, 2, 7, 15, 16, 31, 63, 179, 180, 181, 359, 360, 361)
    boundaries = [
        dataclasses.replace(
            synthetic_case(f"boundary-{length:04d}", length, 0),
            transaction_class="READ_BOUNDARY",
            primary_rn_l=False,
        )
        for length in boundary_lengths
    ]
    controls = [
        CorpusCase(
            case_id=f"control-{name}",
            transaction_class="LINK_CONTROL",
            protected_inner_length=len(frame),
            source_kind="synthetic-control",
            source_ref=name,
            slots={
                "request": (frame,),
                "ack": (),
                "response": (),
                "tail": (),
            },
            primary_rn_l=False,
        )
        for name, frame in (
            ("arp", make_arp_frame("arp")),
            ("syn", make_ipv4_tcp_frame(0, "syn", FORWARD, flags=0x02)),
            ("fin", make_ipv4_tcp_frame(0, "fin", FORWARD, flags=0x11)),
            ("rst", make_ipv4_tcp_frame(0, "rst", FORWARD, flags=0x14)),
            ("ack-only", make_ipv4_tcp_frame(0, "ack", FORWARD, flags=0x10)),
        )
    ]
    controls.append(
        CorpusCase(
            case_id="control-idle",
            transaction_class="LINK_CONTROL",
            protected_inner_length=0,
            source_kind="synthetic-control",
            source_ref="cover-only idle epoch",
            slots={slot: () for slot in SLOTS},
            primary_rn_l=False,
        )
    )
    return primary + boundaries + controls


def extract_captured_transactions(
    path: Path,
    *,
    master_ip: str,
    relay_ip: Optional[str] = None,
    server_port: int = 20_000,
    limit: int = 10,
    case_prefix: str,
) -> List[CorpusCase]:
    """Extract complete Ethernet frames from a committed DNP3 PCAP/PCAPNG.

    A transaction begins at a master-to-port-20000 TCP data frame and ends
    immediately before the next such request.  The grouping mirrors the frozen
    analyzer's direction and TCP-payload rules without rewriting frozen code.
    """

    rows = []
    for packet in read_pcap(path):
        parsed = _parse_ethernet_ipv4_tcp(packet.frame)
        if parsed is None:
            continue
        src_ip, dst_ip, sport, dport, payload_len = parsed
        if src_ip != master_ip and dst_ip != master_ip:
            continue
        peer = dst_ip if src_ip == master_ip else src_ip
        if relay_ip is not None and peer != relay_ip:
            continue
        if sport != server_port and dport != server_port:
            continue
        direction = FORWARD if dport == server_port else REVERSE
        rows.append((direction, payload_len, packet.frame))

    starts = [
        index
        for index, (direction, payload_len, _) in enumerate(rows)
        if direction == FORWARD and payload_len > 0
    ]
    cases: List[CorpusCase] = []
    for transaction_index, start in enumerate(starts[:limit]):
        stop = starts[transaction_index + 1] if transaction_index + 1 < len(starts) else len(rows)
        window = rows[start:stop]
        first_response = next(
            (
                index
                for index, (direction, payload_len, _) in enumerate(window)
                if direction == REVERSE and payload_len > 0
            ),
            len(window),
        )
        request = tuple(
            frame
            for direction, payload_len, frame in window[:first_response]
            if direction == FORWARD and payload_len > 0
        )
        ack = tuple(
            frame
            for direction, payload_len, frame in window[:first_response]
            if direction == REVERSE and payload_len == 0
        )
        response = tuple(
            frame
            for direction, payload_len, frame in window[first_response:]
            if direction == REVERSE and payload_len > 0
        )
        tail = tuple(
            frame
            for direction, payload_len, frame in window[first_response:]
            if direction == FORWARD and payload_len == 0
        )
        protected_length = sum(
            payload_len
            for direction, payload_len, _ in window[first_response:]
            if direction == REVERSE
        )
        if not request or not response:
            continue
        cases.append(
            CorpusCase(
                case_id=f"{case_prefix}-{transaction_index:03d}",
                transaction_class=f"CAPTURED_{case_prefix.upper()}",
                protected_inner_length=protected_length,
                source_kind="captured",
                source_ref=str(path),
                slots={
                    "request": request,
                    "ack": ack,
                    "response": response,
                    "tail": tail,
                },
                primary_rn_l=False,
            )
        )
    return cases


def _parse_ethernet_ipv4_tcp(
    frame: bytes,
) -> Optional[Tuple[str, str, int, int, int]]:
    """Return IPv4/TCP endpoints and payload length without opening sockets."""

    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    offset = 14
    if ethertype in (0x8100, 0x88A8):
        if len(frame) < 18:
            return None
        ethertype = struct.unpack_from(">H", frame, 16)[0]
        offset = 18
    if ethertype != 0x0800 or len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_len = (version_ihl & 0x0F) * 4
    if ip_header_len < 20 or len(frame) < offset + ip_header_len:
        return None
    total_length = struct.unpack_from(">H", frame, offset + 2)[0]
    if frame[offset + 9] != 6 or total_length < ip_header_len + 20:
        return None
    src_ip = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
    tcp_offset = offset + ip_header_len
    if len(frame) < tcp_offset + 20:
        return None
    sport, dport = struct.unpack_from(">HH", frame, tcp_offset)
    tcp_header_len = (frame[tcp_offset + 12] >> 4) * 4
    if tcp_header_len < 20 or total_length < ip_header_len + tcp_header_len:
        return None
    payload_len = total_length - ip_header_len - tcp_header_len
    if len(frame) < tcp_offset + tcp_header_len + payload_len:
        return None
    return src_ip, dst_ip, sport, dport, payload_len


def frame_bundle_size(frames: Iterable[bytes]) -> int:
    return sum(4 + len(frame) for frame in frames)
