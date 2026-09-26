#!/usr/bin/env python3
"""Summarize randomized latency-campaign evidence without hardware access.

The summarizer admits only locally collected evidence.  It reuses the corrected
capture loader for primary transactions, independently joins capture request keys
to random-deadline digests, and records selected timing values as measurements.
It makes no qualification claim about classifier success.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
from pathlib import Path
import sys
from typing import Mapping, Optional, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from . import analysis, summarize, random_campaign
    from .randomized import policy_planner
except ImportError:  # direct script execution
    import analysis  # type: ignore
    import summarize  # type: ignore
    import random_campaign
    from randomized import policy_planner

CLASS_BY_FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}
PRIMARY_CLASSES = ("READ", "SELECT", "OPERATE")
CSV_FIELDS = (
    "session", "replicate", "block", "policy_name", "arm", "mode", "txn_index",
    "txn_class", "func", "t_req_ns", "tcp_src_port", "tcp_seq", "ack_ms", "clrt_ms", "rt_ms", "app_rtt_ms", "request_gap_ms",
    "selected_da_ms", "selected_gap_ms", "selected_r_ms", "rand8",
    "ack_minus_selected_ms", "response_minus_selected_ms",
)


class RandomSummaryError(Exception):
    """Raised when randomized campaign evidence is incomplete or inconsistent."""


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RandomSummaryError(f"missing required file: {path}") from exc


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if "event" in row and "request_tcp_seq" not in row:
                continue
            rows.append(row)
    return rows


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_tree(paths: Sequence[Path]) -> dict[str, str]:
    out = {}
    for path in sorted({p for p in paths if p.exists()}):
        if path.is_file():
            out[str(path)] = _hash_file(path)
    return out


def _capture_drop_counts(block_dir: Path) -> dict[str, int]:
    log = block_dir / "logs" / "capture.log"
    text = log.read_text(encoding="utf-8")
    counts = re.findall(r"Packets received/dropped on interface .*?:\s*(\d+)/(\d+)", text)
    if len(counts) != 1:
        raise RandomSummaryError(f"{block_dir}: missing capture packet/drop statistics")
    received, dropped = map(int, counts[0])
    if received <= 0 or dropped != 0:
        raise RandomSummaryError(f"{block_dir}: capture loss received={received} dropped={dropped}")
    return {"received_packets": received, "dropped_packets": dropped}


def _request_records_from_capture(block_dir: Path) -> list[dict]:
    pcap = analysis._find_one(block_dir, ("traffic.pcap*", "raw_pcaps/*.pcap*"), "traffic capture")
    safety_times = analysis._output_status_poll_times(pcap)
    records = []
    for pkt in analysis._tcp_packets(pcap):
        if not pkt.from_master or pkt.dnp3_func not in CLASS_BY_FUNC:
            continue
        records.append({
            "request_tcp_sport": int(pkt.sport),
            "request_tcp_seq": int(pkt.seq),
            "dnp3_func": int(pkt.dnp3_func),
            "txn_class": CLASS_BY_FUNC[int(pkt.dnp3_func)],
            "t_req_ns": int(pkt.t_ns),
            "is_safety_poll": pkt.t_ns in safety_times,
        })
    records.sort(key=lambda r: (int(r["t_req_ns"]), int(r["request_tcp_sport"]), int(r["request_tcp_seq"])))
    return records


def _request_key(row: Mapping[str, object]) -> tuple[int, int, int]:
    return (int(row["request_tcp_sport"]), int(row["request_tcp_seq"]), int(row["dnp3_func"]))


def _entry_key(entry: Mapping[str, object]) -> tuple[int, int, int]:
    return (int(entry["priority"]), int(entry["low"]), int(entry["high"]))


def _normalise_entry(entry: Mapping[str, object]) -> dict[str, int]:
    return {
        "low": int(entry["low"]),
        "high": int(entry["high"]),
        "priority": int(entry["priority"]),
        "d_ticks": int(entry["d_ticks"]),
        "da_dr_ticks": int(entry["da_dr_ticks"]),
        "op_a_ticks": int(entry["op_a_ticks"]),
        "op_r_ticks": int(entry["op_r_ticks"]),
    }


def _entries_by_key(entries: Sequence[Mapping[str, object]]) -> list[dict[str, int]]:
    return sorted((_normalise_entry(e) for e in entries), key=_entry_key)


def _resolve_plan(run_dir: Path, block: Mapping[str, object]) -> Optional[Path]:
    raw = block.get("random_plan_path") or block.get("random_plan_remote") or block.get("random_plan")
    if not raw:
        return None
    path = Path(str(raw))
    candidates = [run_dir / 'plans' / path.name]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RandomSummaryError(f"{block.get('label')}: missing random plan {raw}")


def _readback_path(run_dir: Path, label: str, suffix: str) -> Path:
    candidates = [run_dir / f"{label}_{suffix}.json", run_dir / "readbacks" / f"{label}_{suffix}.json"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RandomSummaryError(f"{label}: missing {suffix} readback")


def _validate_fixed_readback(run_dir: Path, block_dir: Path, label: str, block: Mapping) -> Path:
    path = _readback_path(run_dir, label, "fixed_readback")
    fixed = _read_json(path)
    plan_name = 'off_config.json' if block['kind']=='off_reference' else 'fixed_config.json'
    plan = _read_json(run_dir / plan_name)
    try:
        random_campaign.verify_fixed_readback(plan, fixed)
        mode = 0 if block['kind']=='off_reference' else 4
        if fixed['tbl_params']['mode'] != mode or fixed['tbl_params']['read_len'] != 0:
            raise ValueError('wrong timing mode or sizing enabled')
    except (ValueError, RuntimeError, KeyError) as exc:
        raise RandomSummaryError(f'{label}: fixed readback invalid: {exc}') from exc
    return path


def _validate_random_readback(run_dir: Path, label: str, plan_path: Path) -> tuple[Path, list[dict[str, int]]]:
    path = _readback_path(run_dir, label, "random_readback")
    readback = _read_json(path)
    plan = _read_json(plan_path)
    policy_planner.load_plan(plan_path)
    try:
        random_campaign.verify_random_readback(plan, readback)
    except (ValueError, RuntimeError, KeyError) as exc:
        raise RandomSummaryError(f'{label}: random readback invalid: {exc}') from exc
    got = _entries_by_key(readback.get("entries", []))
    want = _entries_by_key(plan.get("entries", []))
    if got != want:
        raise RandomSummaryError(f"{label}: random readback differs from requested plan")
    if readback.get("entry_count") is not None and int(readback["entry_count"]) != len(got):
        raise RandomSummaryError(f"{label}: random readback entry_count mismatch")
    return path, got


def _validate_random_cleared(run_dir: Path, label: str) -> Path:
    path = _readback_path(run_dir, label, "random_readback")
    doc = _read_json(path)
    try:
        random_campaign.verify_clear_readback(doc)
    except (ValueError, RuntimeError, KeyError) as exc:
        raise RandomSummaryError(f'{label}: OFF random table invalid: {exc}') from exc
    return path


def _entry_for_rand(entries: Sequence[Mapping[str, int]], rand8: int) -> Mapping[str, int]:
    matches = [e for e in entries if int(e["low"]) <= rand8 <= int(e["high"])]
    if len(matches) != 1:
        raise RandomSummaryError(f"rand8 bucket {rand8} matched {len(matches)} random entries")
    return matches[0]


def _join_requests_and_digests(label: str, requests: Sequence[dict], digests: Sequence[dict], entries: Sequence[Mapping[str, int]]) -> dict[tuple[int, int, int], dict]:
    req_keys = [_request_key(r) for r in requests]
    if len(set(req_keys)) != len(req_keys):
        raise RandomSummaryError(f"{label}: duplicate capture request keys")
    digest_map = {}
    for digest in digests:
        key = _request_key(digest)
        if key in digest_map:
            raise RandomSummaryError(f"{label}: duplicate digest for request {key}")
        digest_map[key] = digest
    missing = [k for k in req_keys if k not in digest_map]
    if missing:
        raise RandomSummaryError(f"{label}: missing digest for {len(missing)} captured requests")
    extra = [k for k in digest_map if k not in set(req_keys)]
    if extra:
        raise RandomSummaryError(f"{label}: {len(extra)} digests do not match captured requests")
    for digest in digest_map.values():
        rand8 = int(digest["rand8"])
        entry = _entry_for_rand(entries, rand8)
        checks = {
            "selected_d_ticks": "d_ticks",
            "selected_da_dr_ticks": "da_dr_ticks",
            "selected_a_ticks": "op_a_ticks",
            "selected_r_ticks": "op_r_ticks",
        }
        for got_name, want_name in checks.items():
            if int(digest[got_name]) != int(entry[want_name]):
                raise RandomSummaryError(f"{label}: digest selected ticks do not match actual table readback")
    return digest_map


def _ticks_to_ms(value: object) -> float:
    return int(value) / 1_000_000.0


def _policy_name(block: Mapping[str, object], row: Mapping[str, object]) -> str:
    for key in ("policy_name", "policy", "name"):
        if row.get(key):
            return str(row[key])
        if block.get(key):
            return str(block[key])
    label = str(block.get("label", ""))
    if block.get("kind") == "off_reference":
        return "OFF"
    plan = block.get('random_plan_remote') or block.get('random_plan_path')
    if not plan:
        raise RandomSummaryError(f'{label}: no named random policy')
    return Path(str(plan)).stem


def _annotate_primary_rows(block: Mapping[str, object], rows: Sequence[dict], primary_requests: Sequence[dict], digest_map: Optional[Mapping[tuple[int, int, int], dict]]) -> list[dict]:
    if len(rows) != len(primary_requests):
        raise RandomSummaryError(f"{block.get('label')}: primary row/request count mismatch {len(rows)} != {len(primary_requests)}")
    out = []
    by_time = {r['t_req_ns']:r for r in primary_requests}
    if len(by_time) != len(primary_requests):
        raise RandomSummaryError('duplicate request timestamps')
    for row in rows:
        if row['t_req_ns'] not in by_time:
            raise RandomSummaryError('primary timing endpoint has no captured request')
        request = by_time[row['t_req_ns']]
        cls = row.get("txn_class")
        if cls != request.get("txn_class"):
            raise RandomSummaryError(f"{block.get('label')}: primary class order differs from timestamped capture requests")
        record = dict(row)
        record["replicate"] = int(block.get("replicate", record.get("replicate", 0)) or 0)
        record["policy_name"] = _policy_name(block, row)
        record["block"] = block.get("label") or row.get("block")
        record['session'] = 'replicate_%02d' % record['replicate']
        record['arm'] = 'native' if block['kind']=='off_reference' else 'obfuscated'
        record['mode'] = 'OFF' if block['kind']=='off_reference' else 'D4'
        record['tcp_src_port'] = request['request_tcp_sport']
        record['tcp_seq'] = request['request_tcp_seq']
        if digest_map is not None:
            digest = digest_map[_request_key(request)]
            da_ms = _ticks_to_ms(digest["selected_d_ticks"])
            r_ms = _ticks_to_ms(digest["selected_da_dr_ticks"])
            record.update({
                "rand8": int(digest["rand8"]),
                "selected_da_ms": da_ms,
                "selected_gap_ms": r_ms - da_ms,
                "selected_r_ms": r_ms,
                "ack_minus_selected_ms": float(record["ack_ms"]) - da_ms,
                "response_minus_selected_ms": float(record["rt_ms"]) - r_ms,
            })
        out.append(record)
    return out


def _counts_by_class(requests: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts = {cls: 0 for cls in PRIMARY_CLASSES}
    for request in requests:
        cls = str(request.get("txn_class"))
        counts[cls] = counts.get(cls, 0) + 1
    return {k: v for k, v in sorted(counts.items()) if v}


def _write_csv(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})


def _block_specs(schedule: Mapping[str, object]) -> list[dict]:
    raw = schedule.get("schedule")
    if not isinstance(raw, list):
        raise RandomSummaryError("schedule.json does not contain a schedule list")
    return [dict(item) for item in raw]


def _load_primary_rows(block_dir: Path) -> list[dict]:
    status = _read_json(block_dir/'status.json')
    if status.get('failed') or status.get('error') or status.get('ok') is False:
        raise RandomSummaryError(f'{block_dir}: runner reported failure')
    for key in ('outputs_before','outputs_after','capture_exit'):
        if status.get(key) != 0:
            raise RandomSummaryError(f'{block_dir}: missing or failed {key}')
    outcomes = analysis._load_all_outcomes(list((block_dir/'app_jsonl').glob('*.jsonl')))
    analysis._validate_status_counts(block_dir,status,outcomes)
    cap = analysis._find_one(block_dir,('traffic.pcap*','raw_pcaps/*.pcap*'),'traffic capture')
    rows = analysis.rows_from_capture(cap,outcomes,block=block_dir.name)
    safety = analysis._output_status_poll_times(cap)
    txns = analysis._validated_transactions(cap,[t for t in analysis.extract_transactions(cap) if t.t_req_ns not in safety])
    if len(rows) != len(txns):
        raise RandomSummaryError('primary timing extraction count differs')
    for row,txn in zip(rows,txns):
        if (row['func'],row['ack_ms'],row['rt_ms']) != (txn.req_func,txn.ack_ms,txn.resp_ms):
            raise RandomSummaryError('primary timings differ from timestamped capture transaction')
        row['t_req_ns'] = txn.t_req_ns
    return rows


def summarize_run(run_dir: str | Path, *, blocks_root: str | Path | None = None, out_dir: str | Path | None = None, allow_partial: bool = False) -> dict:
    run_dir = Path(run_dir)
    blocks_root = Path(blocks_root) if blocks_root is not None else run_dir / "collected_blocks"
    out_dir = Path(out_dir) if out_dir is not None else run_dir / "summary_random"
    if (run_dir / "failure.json").exists() and not allow_partial:
        raise RandomSummaryError(f"failed run: {run_dir / 'failure.json'}")
    schedule = _read_json(run_dir / "schedule.json")
    final_path = run_dir/'final_status.json'
    final = _read_json(final_path) if final_path.exists() else {}
    complete = final.get('configuration_restored') is True and final.get('error') is None and final.get('completed_blocks') == len(schedule['schedule']) and not (run_dir/'failure.json').exists()
    if not complete and not allow_partial:
        raise RandomSummaryError('run is not complete with verified restoration')
    status = 'ok' if complete else 'partial'
    if complete:
        random_campaign.verify_clear_readback(_read_json(run_dir/'restored_random_table.json'))
        random_campaign.verify_fixed_readback(_read_json(run_dir/'restore_config.json'),_read_json(run_dir/'restored_fixed_config.json'))
    all_rows = []
    block_docs = {}
    input_paths = [run_dir/name for name in ('schedule.json','final_status.json','program_identity.json','provenance.json',
                    'fixed_config.json','off_config.json','restore_config.json','restored_fixed_config.json','restored_random_table.json')]
    random_campaign.validate_program_identity(_read_json(run_dir/'program_identity.json'))
    for block in _block_specs(schedule):
        label = str(block["label"])
        block_dir = blocks_root / label
        if not block_dir.exists():
            if allow_partial:
                block_docs[label] = {"status": "missing_block"}
                continue
            raise RandomSummaryError(f"{label}: missing collected block {block_dir}")
        capture_counts = _capture_drop_counts(block_dir)
        if int(capture_counts.get("dropped_packets", 0)) != 0 or int(capture_counts.get("received_packets", 0)) <= 0:
            raise RandomSummaryError(
                f"{label}: capture loss received={capture_counts.get('received_packets')} "
                f"dropped={capture_counts.get('dropped_packets')}"
            )
        pair_count = summarize.validate_packet_pairs(block_dir)
        primary_rows = _load_primary_rows(block_dir)
        input_paths.extend(p for p in block_dir.rglob('*') if p.is_file())
        requests = _request_records_from_capture(block_dir)
        if pair_count != len(requests):
            raise RandomSummaryError(f"{label}: packet-pair audit count {pair_count} != captured requests {len(requests)}")
        primary_requests = [r for r in requests if not r.get("is_safety_poll")]
        safety_requests = [r for r in requests if r.get("is_safety_poll")]
        expected = {cls:int(block['count']) for cls in PRIMARY_CLASSES}
        if _counts_by_class(primary_requests) != expected or len(safety_requests) != 2:
            raise RandomSummaryError(f'{label}: primary or safety request count differs from schedule')
        if block['kind'] not in ('random_policy','off_reference'):
            raise RandomSummaryError('unknown acquisition block kind')
        fixed_readback = _validate_fixed_readback(run_dir, block_dir, label, block)
        input_paths.append(fixed_readback)
        kind = block.get("kind")
        digest_map = None
        selected_entries = None
        digest_rows: list[dict] = []
        random_readback = None
        plan_path = None
        if kind == "random_policy":
            plan_path = _resolve_plan(run_dir, block)
            random_readback, selected_entries = _validate_random_readback(run_dir, label, plan_path)
            digest_path = block_dir / "digests.jsonl"
            digest_rows = _read_jsonl(digest_path)
            expected_digest_count = int(block.get("digest_count", len(requests)) or 0)
            if len(requests) != expected_digest_count:
                raise RandomSummaryError(f"{label}: captured request count {len(requests)} != expected digest count {expected_digest_count}")
            if len(digest_rows) != expected_digest_count:
                if len(digest_rows) < expected_digest_count:
                    raise RandomSummaryError(f"{label}: missing digest records {len(digest_rows)} != expected {expected_digest_count}")
                raise RandomSummaryError(f"{label}: digest count {len(digest_rows)} != expected {expected_digest_count}")
            digest_map = _join_requests_and_digests(label, requests, digest_rows, selected_entries)
            input_paths.extend([plan_path, random_readback, digest_path])
        else:
            random_readback = _validate_random_cleared(run_dir, label)
            digest_path = block_dir / "digests.jsonl"
            if digest_path.exists() and _read_jsonl(digest_path):
                raise RandomSummaryError(f"{label}: OFF block contains random digests")
            input_paths.append(random_readback)
        annotated = _annotate_primary_rows(block, primary_rows, primary_requests, digest_map)
        all_rows.extend(annotated)
        selected_by_class = {}
        if digest_map is not None:
            for request in requests:
                digest = digest_map[_request_key(request)]
                cls = str(request["txn_class"])
                selected_by_class.setdefault(cls, []).append({
                    "rand8": int(digest["rand8"]),
                    "selected_da_ms": _ticks_to_ms(digest["selected_d_ticks"]),
                    "selected_gap_ms": _ticks_to_ms(digest["selected_da_dr_ticks"]) - _ticks_to_ms(digest["selected_d_ticks"]),
                    "selected_r_ms": _ticks_to_ms(digest["selected_da_dr_ticks"]),
                    "is_safety_poll": bool(request.get("is_safety_poll")),
                })
        block_docs[label] = {
            "status": "ok",
            "kind": kind,
            "replicate": int(block.get("replicate", 0) or 0),
            "primary_transactions": len(primary_rows),
            "captured_requests_including_safety": len(requests),
            "safety_polls": len(safety_requests),
            "packet_pair_count_including_safety": pair_count,
            "capture": capture_counts,
            "primary_counts_by_class": _counts_by_class(primary_requests),
            "digest_counts_by_class": _counts_by_class(requests) if digest_map is not None else {},
            "draw_counts_by_class": {
                cls: {str(rand): sum(1 for item in vals if item["rand8"] == rand) for rand in sorted({v["rand8"] for v in vals})}
                for cls, vals in selected_by_class.items()
            },
            "selected_deadlines_by_class": selected_by_class,
        }
    policies = {}
    for name in sorted({r['policy_name'] for r in all_rows}):
        values = [r for r in all_rows if r['policy_name']==name]
        policies[name] = {'n_exchanges':len(values),'n_blocks':len({r['block'] for r in values}),
                          'operations':analysis.latency_summary(values)}
        for operation, metrics in policies[name]['operations'].items():
            for metric, stats in metrics.items():
                observed = [r[metric] for r in values if r['txn_class']==operation and r.get(metric) is not None]
                stats['variance_ms2'] = statistics.variance(observed) if len(observed)>1 else None
                stats['sd_ms'] = statistics.stdev(observed) if len(observed)>1 else None
    measurements = {
        'policies': policies,
        "status": status,
        "run_dir": str(run_dir),
        "blocks_root": str(blocks_root),
        "row_count": len(all_rows),
        "blocks": block_docs,
        "inputs_sha256": _hash_tree(input_paths),
        "notes": [
            "Random selected timing values are measurements from digest/capture joins, not qualification claims.",
            "Multiple OFF blocks per replicate may need a nearest-OFF subset before later modeling.",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_path = out_dir / "measurements.json"
    _write_csv(out_dir / "primarytransactions.csv", all_rows)
    measurements['primary_csv_sha256'] = _hash_file(out_dir/'primarytransactions.csv')
    measurements['summary_code_sha256'] = _hash_file(Path(__file__))
    write_path.write_text(json.dumps(measurements, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return measurements


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir")
    parser.add_argument("--blocks-root")
    parser.add_argument("--out", required=True)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args(argv)
    result = summarize_run(args.run_dir, blocks_root=args.blocks_root, out_dir=args.out, allow_partial=args.allow_partial)
    print(json.dumps({'status':result['status'],'blocks':len(result['blocks']),'primary_exchanges':result['row_count']}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
