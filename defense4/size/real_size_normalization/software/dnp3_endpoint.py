"""Native synthetic DNP3/TCP endpoint for S4 software validation.

The relay role listens on a real TCP socket, default port 20000. The master
role connects to it and performs a balanced 100-exchange synthetic DNP3 run.
Logs contain only case identifiers, hashes, lengths, and timing metadata.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from defense4.size.native_parity.h3_harness import dnp3_wire
from defense4.size.real_size_normalization.software.packet_oracle import (
    OracleResult,
    dnp3_frame_length,
    validate_dnp3_frame,
    validate_dnp3_stream,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 20000
DEFAULT_EXCHANGES = 100
RESPONSE_WIRE_LENGTHS = (17, 49, 56, 75, 104)


@dataclasses.dataclass(frozen=True)
class EndpointEvent:
    """Log-safe endpoint event."""

    role: str
    event: str
    case_id: str
    request_len: int
    response_len: int
    request_sha256: str
    response_sha256: str
    dnp3_valid: bool
    elapsed_ms: float
    monotonic_ns: int = 0

    def as_dict(self) -> Dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class EndpointRunResult:
    """Summary for a master or relay endpoint run."""

    role: str
    exchanges: int
    response_lengths: Tuple[int, ...]
    balanced: bool
    dnp3_valid: bool
    events: Tuple[EndpointEvent, ...]

    def as_dict(self) -> Dict[str, object]:
        counts: Dict[str, int] = {}
        for length in self.response_lengths:
            counts[str(length)] = counts.get(str(length), 0) + 1
        return {
            "role": self.role,
            "exchanges": self.exchanges,
            "response_length_counts": counts,
            "balanced": self.balanced,
            "dnp3_valid": self.dnp3_valid,
            "event_count": len(self.events),
        }


class EndpointError(RuntimeError):
    """Raised when the synthetic endpoint run violates its contract."""


def build_request(index: int) -> bytes:
    """Build a native-parity DNP3 request for one exchange."""

    func = dnp3_wire.FUNC_SELECT if index % 2 == 0 else dnp3_wire.FUNC_OPERATE
    return dnp3_wire.build_request(func, app_seq=index & 0x0F)


def build_response(index: int) -> bytes:
    """Build one checksum-valid synthetic DNP3 response in a balanced length class."""

    target_length = RESPONSE_WIRE_LENGTHS[index % len(RESPONSE_WIRE_LENGTHS)]
    if target_length == 49:
        return dnp3_wire.build_echo(req_app_seq=index & 0x0F, transport_seq=index & 0x3F)
    user_len = _user_len_for_wire_len(target_length)
    if user_len < 5:
        raise ValueError("response length cannot hold DNP3 response prefix")
    userdata = bytes(
        [
            0xC0 | (index & 0x3F),
            0xC0 | (index & 0x0F),
            dnp3_wire.FUNC_RESPONSE,
            0x00,
            0x00,
        ]
    ) + _deterministic_bytes(user_len - 5, "response:%d:%d" % (target_length, index))
    frame = dnp3_wire.build_frame(
        userdata,
        dst=dnp3_wire.MASTER_ADDR,
        src=dnp3_wire.OUTSTATION_ADDR,
        ctrl=0x44,
    )
    if len(frame) != target_length:
        raise AssertionError("generated response length mismatch")
    return frame


def build_balanced_responses(count: int = DEFAULT_EXCHANGES) -> Tuple[bytes, ...]:
    """Return balanced checksum-valid response frames across the five classes."""

    if count % len(RESPONSE_WIRE_LENGTHS) != 0:
        raise ValueError("count must be divisible by %d" % len(RESPONSE_WIRE_LENGTHS))
    return tuple(build_response(index) for index in range(count))


async def run_relay(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    exchanges: int = DEFAULT_EXCHANGES,
    connections: int = 1,
    log_path: Optional[Path] = None,
    ready: Optional[asyncio.Event] = None,
) -> EndpointRunResult:
    """Serve ``exchanges`` DNP3 exchanges across ``connections`` sequential sessions."""

    if connections < 1:
        raise ValueError("connections must be positive")
    events: List[EndpointEvent] = []
    completed = asyncio.Event()
    errors: List[BaseException] = []
    served = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal served
        try:
            for index in range(exchanges):
                start = time.perf_counter()
                request = await read_dnp3_frame(reader)
                if not validate_dnp3_frame(request):
                    raise EndpointError("invalid request DNP3 CRC")
                response = build_response(index)
                writer.write(response)
                await writer.drain()
                event = _event(
                    "relay",
                    "served",
                    index,
                    request,
                    response,
                    (time.perf_counter() - start) * 1000.0,
                    time.monotonic_ns(),
                )
                events.append(event)
                _write_event(log_path, event)
        except BaseException as exc:
            errors.append(exc)
        finally:
            writer.close()
            await writer.wait_closed()
            served += 1
            if errors or served >= connections:
                completed.set()

    server = await asyncio.start_server(handle, host, port)
    if ready is not None:
        ready.set()
    try:
        await completed.wait()
    finally:
        server.close()
        await server.wait_closed()
    if errors:
        raise EndpointError(str(errors[0]))
    return _result("relay", events)


async def run_master(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    exchanges: int = DEFAULT_EXCHANGES,
    log_path: Optional[Path] = None,
) -> EndpointRunResult:
    """Connect to the relay and run the balanced DNP3 response corpus."""

    events: List[EndpointEvent] = []
    reader, writer = await asyncio.open_connection(host, port)
    try:
        for index in range(exchanges):
            start = time.perf_counter()
            request = build_request(index)
            writer.write(request)
            await writer.drain()
            response = await read_dnp3_frame(reader)
            expected_length = RESPONSE_WIRE_LENGTHS[index % len(RESPONSE_WIRE_LENGTHS)]
            if len(response) != expected_length:
                raise EndpointError("unexpected response length")
            valid = validate_dnp3_stream(request + response).ok
            event = _event(
                "master",
                "exchanged",
                index,
                request,
                response,
                (time.perf_counter() - start) * 1000.0,
                time.monotonic_ns(),
            )
            if not valid:
                raise EndpointError("invalid DNP3 CRC in exchange")
            events.append(event)
            _write_event(log_path, event)
    finally:
        writer.close()
        await writer.wait_closed()
    return _result("master", events)


async def read_dnp3_frame(reader: asyncio.StreamReader) -> bytes:
    """Read exactly one DNP3 link frame from a TCP stream."""

    prefix = await reader.readexactly(3)
    total = dnp3_frame_length(prefix)
    if total is None:
        raise EndpointError("invalid DNP3 prefix")
    rest = await reader.readexactly(total - len(prefix))
    frame = prefix + rest
    if not validate_dnp3_frame(frame):
        raise EndpointError("invalid DNP3 frame CRC")
    return frame


def verify_balanced_events(events: Sequence[EndpointEvent]) -> OracleResult:
    """Verify event count, five-class balance, and DNP3 validity from log-safe facts."""

    errors: List[str] = []
    counts: Dict[int, int] = {}
    for event in events:
        counts[event.response_len] = counts.get(event.response_len, 0) + 1
        if not event.dnp3_valid:
            errors.append("%s_invalid_dnp3" % event.case_id)
    expected = set(RESPONSE_WIRE_LENGTHS)
    if set(counts) != expected:
        errors.append("response_length_set")
    if counts and len(set(counts.values())) != 1:
        errors.append("response_length_balance")
    return OracleResult(ok=not errors, errors=tuple(errors))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("master", "relay"), required=True)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--exchanges", type=int, default=DEFAULT_EXCHANGES)
    parser.add_argument(
        "--connections",
        type=int,
        default=1,
        help="relay role: number of sequential client sessions to serve before exit",
    )
    parser.add_argument("--log", type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
    if args.role == "relay":
        result = asyncio.run(
            run_relay(
                args.host,
                args.port,
                exchanges=args.exchanges,
                connections=args.connections,
                log_path=args.log,
            )
        )
    else:
        result = asyncio.run(
            run_master(args.host, args.port, exchanges=args.exchanges, log_path=args.log)
        )
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.balanced and result.dnp3_valid else 1


def _result(role: str, events: Sequence[EndpointEvent]) -> EndpointRunResult:
    lengths = tuple(event.response_len for event in events)
    check = verify_balanced_events(events)
    return EndpointRunResult(
        role=role,
        exchanges=len(events),
        response_lengths=lengths,
        balanced=check.ok,
        dnp3_valid=all(event.dnp3_valid for event in events),
        events=tuple(events),
    )


def _event(
    role: str,
    name: str,
    index: int,
    request: bytes,
    response: bytes,
    elapsed_ms: float,
    monotonic_ns: int,
) -> EndpointEvent:
    return EndpointEvent(
        role=role,
        event=name,
        case_id="s4-native-dnp3-%03d" % index,
        request_len=len(request),
        response_len=len(response),
        request_sha256=_sha256(request),
        response_sha256=_sha256(response),
        dnp3_valid=validate_dnp3_stream(request + response).ok,
        elapsed_ms=elapsed_ms,
        monotonic_ns=monotonic_ns,
    )


def _write_event(path: Optional[Path], event: EndpointEvent) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.as_dict(), sort_keys=True) + "\n")


def _user_len_for_wire_len(target_length: int) -> int:
    for user_len in range(0, 250):
        blocks = (user_len + 15) // 16 if user_len else 0
        if 10 + user_len + (2 * blocks) == target_length:
            return user_len
    raise ValueError("unrepresentable DNP3 wire length: %d" % target_length)


def _deterministic_bytes(length: int, seed: str) -> bytes:
    out = bytearray()
    block = 0
    while len(out) < length:
        out.extend(hashlib.blake2s(("%s:%d" % (seed, block)).encode("utf-8"), digest_size=32).digest())
        block += 1
    return bytes(out[:length])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
