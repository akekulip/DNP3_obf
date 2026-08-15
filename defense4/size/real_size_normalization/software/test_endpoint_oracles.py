from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import struct

from defense4.size.real_size_normalization.software import dnp3_endpoint
from defense4.size.real_size_normalization.software.packet_oracle import (
    dnp3_crc_errors,
    ones_complement_checksum,
    parse_ethernet_ipv4_tcp,
    validate_dnp3_frame,
    validate_dnp3_stream,
    validate_ipv4_tcp_checksums,
    validate_tcp_sequences,
)


def test_balanced_response_corpus_is_dnp3_crc_valid() -> None:
    responses = dnp3_endpoint.build_balanced_responses(100)

    assert len(responses) == 100
    assert {len(item) for item in responses} == set(dnp3_endpoint.RESPONSE_WIRE_LENGTHS)
    assert {sum(1 for item in responses if len(item) == length) for length in dnp3_endpoint.RESPONSE_WIRE_LENGTHS} == {20}
    assert all(validate_dnp3_frame(item) for item in responses)


def test_dnp3_crc_oracle_rejects_header_and_data_corruption() -> None:
    frame = bytearray(dnp3_endpoint.build_response(4))
    header_bad = bytearray(frame)
    header_bad[3] ^= 0x01
    data_bad = bytearray(frame)
    data_bad[10] ^= 0x01

    assert validate_dnp3_stream(bytes(frame)).ok
    assert "dnp3_header_crc" in dnp3_crc_errors(bytes(header_bad))
    assert any(item.startswith("dnp3_data_crc_") for item in dnp3_crc_errors(bytes(data_bad)))


def test_ipv4_tcp_checksum_and_sequence_oracles() -> None:
    first = _make_tcp_frame(b"abc", sequence=100, acknowledgment=1)
    second = _make_tcp_frame(b"defg", sequence=103, acknowledgment=1)
    corrupted = bytearray(first)
    corrupted[-1] ^= 0x01

    parsed = parse_ethernet_ipv4_tcp(first)
    assert parsed.src_port == 40000
    assert parsed.dst_port == 20000
    assert parsed.sequence_span == 3
    assert validate_ipv4_tcp_checksums(first).ok
    assert not validate_ipv4_tcp_checksums(bytes(corrupted)).ok
    assert validate_tcp_sequences((first, second)).ok
    assert not validate_tcp_sequences((second, first)).ok


def test_master_relay_exchange_uses_real_tcp_and_log_safe_metadata(tmp_path) -> None:
    async def run_pair() -> tuple:
        port = _free_port()
        ready = asyncio.Event()
        relay_task = asyncio.create_task(
            dnp3_endpoint.run_relay(
                "127.0.0.1",
                port,
                exchanges=100,
                log_path=tmp_path / "relay.jsonl",
                ready=ready,
            )
        )
        await ready.wait()
        master = await dnp3_endpoint.run_master(
            "127.0.0.1",
            port,
            exchanges=100,
            log_path=tmp_path / "master.jsonl",
        )
        relay = await relay_task
        return master, relay

    master, relay = asyncio.run(run_pair())

    assert master.exchanges == 100
    assert relay.exchanges == 100
    assert master.balanced
    assert relay.balanced
    assert master.dnp3_valid
    assert relay.dnp3_valid
    assert set(master.response_lengths) == set(dnp3_endpoint.RESPONSE_WIRE_LENGTHS)

    rows = [
        json.loads(line)
        for line in (tmp_path / "master.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 100
    assert {"case_id", "request_sha256", "response_sha256", "request_len", "response_len", "elapsed_ms"} <= set(rows[0])
    assert "payload" not in json.dumps(rows)
    assert "key" not in json.dumps(rows)


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _make_tcp_frame(payload: bytes, *, sequence: int, acknowledgment: int) -> bytes:
    src_mac = bytes.fromhex("02000000a001")
    dst_mac = bytes.fromhex("02000000b007")
    src_ip = ipaddress.IPv4Address("198.51.100.1").packed
    dst_ip = ipaddress.IPv4Address("198.51.100.7").packed
    tcp_wo_checksum = struct.pack(
        ">HHIIBBHHH",
        40000,
        20000,
        sequence,
        acknowledgment,
        5 << 4,
        0x18,
        8192,
        0,
        0,
    )
    pseudo = src_ip + dst_ip + struct.pack(">BBH", 0, 6, len(tcp_wo_checksum) + len(payload))
    tcp_checksum = ones_complement_checksum(pseudo + tcp_wo_checksum + payload)
    tcp = tcp_wo_checksum[:16] + struct.pack(">H", tcp_checksum) + tcp_wo_checksum[18:]
    total_length = 20 + len(tcp) + len(payload)
    ip_wo_checksum = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        int.from_bytes(hashlib.blake2s(payload, digest_size=2).digest(), "big"),
        0x4000,
        64,
        6,
        0,
        src_ip,
        dst_ip,
    )
    ip = ip_wo_checksum[:10] + struct.pack(">H", ones_complement_checksum(ip_wo_checksum)) + ip_wo_checksum[12:]
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + ip + tcp + payload
