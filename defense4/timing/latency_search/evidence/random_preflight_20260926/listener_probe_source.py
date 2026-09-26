#!/usr/bin/env python3
"""Listen for randomized deadline selection digests.

This is intentionally read-only: it subscribes to BFRT learn notifications and
prints decoded digest rows as JSONL. It does not program tables, ports, queues,
mirrors, or pipeline state.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, Iterable

PROGRAM = "defense4_timing"
LEARN_NAME = "pipe.IgDeparser.random_deadline_digest"
FIELDS = (
    "request_tcp_seq",
    "request_tcp_sport",
    "ingress_ts32",
    "ingress_now_word",
    "dnp3_func",
    "rand8",
    "selected_d_ticks",
    "selected_da_dr_ticks",
    "selected_a_ticks",
    "selected_r_ticks",
)


def _normalise(value: Any) -> Any:
    if isinstance(value, bytearray):
        return int.from_bytes(bytes(value), "big")
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    return value


def decode_digest(learn, digest) -> Iterable[Dict[str, Any]]:
    """Decode one BFRT DigestList after its generated digest_id is verified."""
    learn_id = learn.info.id_get()
    if digest.digest_id != learn_id:
        return []
    rows = []
    for data in learn.make_data_list(digest):
        record = {k: _normalise(v) for k, v in data.to_dict().items() if k in FIELDS}
        record["digest_id"] = digest.digest_id
        record["list_id"] = digest.list_id
        target = getattr(digest, "target", None)
        if target is not None:
            record["device_id"] = target.device_id
            record["pipe_id"] = target.pipe_id
        rows.append(record)
    return rows


def open_interface(client_id: int, server: str, port: int, program: str):
    import bfrt_grpc.client as gc

    # Matches the SDE tna_digest PTF path: client 0, subscribed stream,
    # learn notifications enabled by default. The BFRT Python client used here
    # has no public digest-ack helper; SDE examples consume digests with
    # digest_get() and learn.make_data_list().
    interface = gc.ClientInterface(
        grpc_addr=f"{server}:{port}",
        client_id=client_id,
        device_id=0,
        notifications=gc.Notifications(enable_learn=True),
    )
    interface.bind_pipeline_config(program)
    return interface


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--program", default=PROGRAM)
    ap.add_argument("--learn", default=LEARN_NAME)
    ap.add_argument("--server", default="localhost")
    ap.add_argument("--port", type=int, default=50052)
    ap.add_argument("--client-id", type=int, default=119)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--max-digests", type=int, default=0,
                    help="stop after this many decoded records; 0 means run until interrupted")
    args = ap.parse_args(argv)

    interface = open_interface(args.client_id, args.server, args.port, args.program)
    try:
        bfrt_info = interface.bfrt_info_get(args.program)
        learn = bfrt_info.learn_get(args.learn)
        learn_id = learn.info.id_get()
        print(json.dumps({"event": "ready", "program": args.program,
                          "learn": args.learn, "learn_id": learn_id}), flush=True)

        emitted = 0
        try:
            while args.max_digests == 0 or emitted < args.max_digests:
                try:
                    digest = interface.digest_get(timeout=args.timeout)
                except RuntimeError:
                    continue
                if digest.digest_id != learn_id:
                    continue
                for record in decode_digest(learn, digest):
                    record["host_time_ns"] = time.time_ns()
                    print(json.dumps(record, sort_keys=True), flush=True)
                    emitted += 1
                    if args.max_digests and emitted >= args.max_digests:
                        break
        except KeyboardInterrupt:
            return 130
        return 0
    finally:
        interface.tear_down_stream()


if __name__ == "__main__":
    raise SystemExit(main())
