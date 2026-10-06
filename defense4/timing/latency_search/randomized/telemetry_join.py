#!/usr/bin/env python3
"""Join random-deadline digest telemetry to raw master-facing requests."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

FUNC_BY_NAME = {"READ": 1, "SELECT": 3, "OPERATE": 4}
NAME_BY_FUNC = {v: k for k, v in FUNC_BY_NAME.items()}


@dataclass(frozen=True)
class RequestKey:
    sport: int
    seq: int
    func: int


@dataclass(frozen=True)
class JoinResult:
    joined: tuple[dict, ...]
    missing_digest: tuple[dict, ...]
    missing_request: tuple[dict, ...]
    duplicate_requests: tuple[dict, ...]
    duplicate_digests: tuple[dict, ...]
    wrong_selection: tuple[dict, ...]


def _func(value) -> int:
    if isinstance(value, str):
        upper = value.upper()
        if upper in FUNC_BY_NAME:
            return FUNC_BY_NAME[upper]
        return int(value, 0)
    return int(value)


def _key_from_request(row: dict) -> RequestKey:
    return RequestKey(
        sport=int(row.get("tcp_src_port", row.get("sport", row.get("request_tcp_sport")))),
        seq=int(row.get("tcp_seq", row.get("seq", row.get("request_tcp_seq")))),
        func=_func(row.get("dnp3_func", row.get("func", row.get("function")))),
    )


def _key_from_digest(row: dict) -> RequestKey:
    return RequestKey(
        sport=int(row["request_tcp_sport"]),
        seq=int(row["request_tcp_seq"]),
        func=_func(row["dnp3_func"]),
    )


def _expected_by_bucket(plan: dict, rand8: int) -> Optional[dict]:
    for entry in plan.get("entries", []):
        if int(entry["low"]) <= rand8 <= int(entry["high"]):
            return entry
    return None


def validate_selection(digest: dict, plan: Optional[dict]) -> Optional[str]:
    if plan is None:
        return None
    rand8 = int(digest["rand8"])
    entry = _expected_by_bucket(plan, rand8)
    if entry is None:
        return f"rand8 bucket {rand8} is not covered by plan"
    checks = {
        "selected_d_ticks": "d_ticks",
        "selected_da_dr_ticks": "da_dr_ticks",
        "selected_a_ticks": "op_a_ticks",
        "selected_r_ticks": "op_r_ticks",
    }
    for got_name, want_name in checks.items():
        if int(digest[got_name]) != int(entry[want_name]):
            return f"{got_name}={digest[got_name]} does not match plan {want_name}={entry[want_name]}"
    return None


def join(requests: Iterable[dict], digests: Iterable[dict], plan: Optional[dict] = None) -> JoinResult:
    req_map: dict[RequestKey, list[dict]] = {}
    dig_map: dict[RequestKey, list[dict]] = {}
    for req in requests:
        req_map.setdefault(_key_from_request(req), []).append(req)
    for dig in digests:
        dig_map.setdefault(_key_from_digest(dig), []).append(dig)

    joined: list[dict] = []
    missing_digest: list[dict] = []
    missing_request: list[dict] = []
    duplicate_requests: list[dict] = []
    duplicate_digests: list[dict] = []
    wrong_selection: list[dict] = []

    for key, rows in req_map.items():
        if len(rows) > 1:
            duplicate_requests.extend(rows)
        drows = dig_map.get(key, [])
        if not drows:
            missing_digest.extend(rows)
            continue
        if len(drows) > 1:
            duplicate_digests.extend(drows)
            continue
        if len(rows) == 1:
            reason = validate_selection(drows[0], plan)
            record = {"key": key.__dict__, "request": rows[0], "digest": drows[0]}
            if reason:
                record["reason"] = reason
                wrong_selection.append(record)
            else:
                joined.append(record)
    for key, rows in dig_map.items():
        if key not in req_map:
            missing_request.extend(rows)
    return JoinResult(
        joined=tuple(joined),
        missing_digest=tuple(missing_digest),
        missing_request=tuple(missing_request),
        duplicate_requests=tuple(duplicate_requests),
        duplicate_digests=tuple(duplicate_digests),
        wrong_selection=tuple(wrong_selection),
    )


def load_jsonl(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def result_to_dict(result: JoinResult) -> dict:
    return {
        "counts": {
            "joined": len(result.joined),
            "missing_digest": len(result.missing_digest),
            "missing_request": len(result.missing_request),
            "duplicate_requests": len(result.duplicate_requests),
            "duplicate_digests": len(result.duplicate_digests),
            "wrong_selection": len(result.wrong_selection),
        },
        "joined": list(result.joined),
        "missing_digest": list(result.missing_digest),
        "missing_request": list(result.missing_request),
        "duplicate_requests": list(result.duplicate_requests),
        "duplicate_digests": list(result.duplicate_digests),
        "wrong_selection": list(result.wrong_selection),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--requests", required=True, help="JSONL raw master-facing request records")
    ap.add_argument("--digests", required=True, help="JSONL telemetry_listener output")
    ap.add_argument("--plan")
    ap.add_argument("--output")
    args = ap.parse_args(argv)
    plan = None if args.plan is None else json.loads(Path(args.plan).read_text())
    result = join(load_jsonl(args.requests), load_jsonl(args.digests), plan)
    doc = result_to_dict(result)
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n")
    print(text)
    return 0 if not any(doc["counts"][k] for k in ("missing_digest", "missing_request", "duplicate_requests", "duplicate_digests", "wrong_selection")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
