#!/usr/bin/env python3
"""Narrow codebook/parameter configuration helper for latency-search runs.

Offline planning is the default. Live writes are guarded by DEFENSE4_HW_AUTHORIZED=1
and are intentionally limited to tbl_bor_codebook and tbl_params. This file does not
touch ports, mirrors, registers, queue scheduling, or pktgen state.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence, Union

try:
    from . import policy
except ImportError:  # direct script execution
    import policy  # type: ignore

DEFAULT_REMOTE_DIR = Path("/home/decps/dnp3_latency_20260926")
DEFAULT_CONTROL_DIR = DEFAULT_REMOTE_DIR / "control"
CODEBOOK_TABLE = "pipe.Ingress.tbl_bor_codebook"
PARAMS_TABLE = "pipe.Ingress.tbl_params"
BOR_PARAMS_TABLE = "pipe.Ingress.tbl_bor_params"
AUTH_ENV = "DEFENSE4_HW_AUTHORIZED"
SOURCE_CACHE_DRAIN_S = 1.0


@dataclass(frozen=True)
class CodebookEntry:
    low: int
    high: int
    j_ticks: int
    dst_port: int = policy.DEFAULT_RELAY_DST_PORT
    priority: int = 1


@dataclass(frozen=True)
class ParamsDefault:
    mode: int
    d_ticks: int
    da_dr: int
    budget: int
    read_len: int
    action_name: str = "Ingress.set_params"


@dataclass(frozen=True)
class BorParamsDefault:
    a_ticks: int
    r_ticks: int
    anchor_req: int = 1
    action_name: str = "Ingress.set_bor_params"


@dataclass(frozen=True)
class EntryAudit:
    entry_count: int
    overlap_entry_count: int
    overlap_pair_count: int
    missing_buckets: tuple[int, ...]
    extra_buckets: tuple[int, ...]
    valid_policy: bool


@dataclass(frozen=True)
class ConfigPlan:
    codebook_entries: tuple[CodebookEntry, ...]
    params_default: Optional[ParamsDefault] = None
    bor_params_default: Optional[BorParamsDefault] = None
    delete_existing_first: bool = True
    restoration_only: bool = False
    source_cache_drain_s: float = SOURCE_CACHE_DRAIN_S
    notes: tuple[str, ...] = field(default_factory=tuple)


def load_snapshot(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def _table(snapshot: dict[str, Any], name: str) -> dict[str, Any]:
    return snapshot.get("tables", {}).get(name, {})


def _key_value(key: dict[str, Any], name: str) -> int:
    value = key[name]
    if isinstance(value, dict):
        if "value" in value:
            return int(value["value"])
        if "low" in value and "high" in value:
            raise ValueError(f"{name} is a range, not a scalar")
    return int(value)


def _range_low_high(key: dict[str, Any], name: str) -> tuple[int, int]:
    value = key[name]
    if not isinstance(value, dict):
        return int(value), int(value)
    return int(value.get("low", value.get("value"))), int(value.get("high", value.get("value")))


def entry_from_snapshot(raw: dict[str, Any]) -> CodebookEntry:
    key = raw["key"]
    data = raw["data"]
    low, high = _range_low_high(key, "meta.rand8")
    return CodebookEntry(
        low=low,
        high=high,
        j_ticks=int(data["j_ticks"]),
        dst_port=_key_value(key, "hdr.tcp.dst_port"),
        priority=_key_value(key, "$MATCH_PRIORITY"),
    )


def params_from_snapshot(snapshot: dict[str, Any]) -> Optional[ParamsDefault]:
    defaults = _table(snapshot, PARAMS_TABLE).get("default", [])
    if not defaults:
        return None
    raw = defaults[0]
    return ParamsDefault(
        mode=int(raw["mode"]),
        d_ticks=int(raw["d_ticks"]),
        da_dr=int(raw["da_dr"]),
        budget=int(raw["budget"]),
        read_len=int(raw["read_len"]),
        action_name=str(raw.get("action_name", "Ingress.set_params")),
    )


def bor_params_from_snapshot(snapshot: dict[str, Any]) -> Optional[BorParamsDefault]:
    defaults = _table(snapshot, BOR_PARAMS_TABLE).get("default", [])
    if not defaults:
        return None
    raw = defaults[0]
    return BorParamsDefault(
        a_ticks=int(raw["a_ticks"]),
        r_ticks=int(raw["r_ticks"]),
        anchor_req=int(raw["anchor_req"]),
        action_name=str(raw.get("action_name", "Ingress.set_bor_params")),
    )


def snapshot_codebook_entries(snapshot: dict[str, Any]) -> tuple[CodebookEntry, ...]:
    return tuple(entry_from_snapshot(e) for e in _table(snapshot, CODEBOOK_TABLE).get("entries", []))


def audit_entries(entries: Iterable[CodebookEntry]) -> EntryAudit:
    entries = tuple(entries)
    owners: dict[int, list[int]] = {i: [] for i in range(256)}
    extra: set[int] = set()
    for idx, entry in enumerate(entries):
        for bucket in range(entry.low, entry.high + 1):
            if 0 <= bucket <= 255:
                owners[bucket].append(idx)
            else:
                extra.add(bucket)
    missing = tuple(bucket for bucket, hits in owners.items() if not hits)
    overlap_buckets = {bucket for bucket, hits in owners.items() if len(hits) > 1}
    overlap_entries = {
        idx
        for bucket in overlap_buckets
        for idx in owners[bucket]
    }
    pairs: set[tuple[int, int]] = set()
    for hits in owners.values():
        if len(hits) > 1:
            for i, a in enumerate(hits):
                for b in hits[i + 1 :]:
                    pairs.add((min(a, b), max(a, b)))
    valid = not missing and not extra and not pairs and all(e.j_ticks > 0 for e in entries)
    return EntryAudit(
        entry_count=len(entries),
        overlap_entry_count=len(overlap_entries),
        overlap_pair_count=len(pairs),
        missing_buckets=missing,
        extra_buckets=tuple(sorted(extra)),
        valid_policy=valid,
    )


def audit_codebook_snapshot(snapshot: dict[str, Any]) -> EntryAudit:
    return audit_entries(snapshot_codebook_entries(snapshot))


def build_codebook_plan(
    j_set_ms: Sequence[float],
    dst_port: int = policy.DEFAULT_RELAY_DST_PORT,
    params_default: Optional[ParamsDefault] = None,
    bor_params_default: Optional[BorParamsDefault] = None,
) -> ConfigPlan:
    if not j_set_ms:
        raise ValueError("j_set_ms cannot be empty")
    entries: list[CodebookEntry] = []
    n = len(j_set_ms)
    start = 0
    for idx, j_ms in enumerate(j_set_ms, 1):
        end = 255 if idx == n else (idx * 256 // n) - 1
        q = policy.quantize_ms(float(j_ms))
        if q.word <= 0:
            raise ValueError(f"J={j_ms} ms quantizes to zero")
        entries.append(CodebookEntry(low=start, high=end, j_ticks=q.word, dst_port=dst_port, priority=idx))
        start = end + 1
    audit = audit_entries(entries)
    if not audit.valid_policy:
        raise ValueError(f"generated codebook is invalid: {audit}")
    return ConfigPlan(
        codebook_entries=tuple(entries),
        params_default=params_default,
        bor_params_default=bor_params_default,
        delete_existing_first=True,
        notes=("delete all existing codebook keys before install; exact full-coverage readback required",),
    )


def build_policy_plan(p: policy.TimingPolicy, budget: int = 18000, read_len: int = 0, anchor_req: int = 1) -> ConfigPlan:
    mode = {"OFF": 0, "D1": 1, "D2": 2, "D3": 3, "D4": 4, "FAIL_OPEN": 5}[p.mode]
    da_dr = p.da.word + p.gap.word
    return build_codebook_plan(
        p.j_set_ms,
        dst_port=p.relay_dst_port,
        params_default=ParamsDefault(
            mode=mode,
            d_ticks=p.da.word,
            da_dr=da_dr,
            budget=budget,
            read_len=read_len,
        ),
        bor_params_default=BorParamsDefault(
            a_ticks=p.da.word,
            r_ticks=da_dr,
            anchor_req=anchor_req,
        ),
    )


def restore_plan_from_snapshot(snapshot: dict[str, Any]) -> ConfigPlan:
    entries = snapshot_codebook_entries(snapshot)
    return ConfigPlan(
        codebook_entries=entries,
        params_default=params_from_snapshot(snapshot),
        bor_params_default=bor_params_from_snapshot(snapshot),
        delete_existing_first=True,
        restoration_only=True,
        notes=(
            "historical restoration exemption: replays exact snapshot entries, even if overlapping",
            "not a valid latency-search policy; use only for rollback to the captured preflight state",
        ),
    )


def plan_to_dict(plan: ConfigPlan) -> dict[str, Any]:
    data = asdict(plan)
    data["audit"] = asdict(audit_entries(plan.codebook_entries))
    return data


def validate_plan_for_apply(plan: ConfigPlan) -> EntryAudit:
    audit = audit_entries(plan.codebook_entries)
    if not plan.restoration_only:
        if not audit.valid_policy:
            raise ValueError(f"refusing invalid codebook policy before hardware writes: {audit}")
        if plan.params_default is None:
            raise ValueError("non-restore policy must include tbl_params default")
        if plan.bor_params_default is None:
            raise ValueError("non-restore policy must include tbl_bor_params default")
    for entry in plan.codebook_entries:
        if entry.j_ticks <= 0:
            raise ValueError("codebook entries must have positive J ticks")
        if entry.j_ticks & 0xFF:
            raise ValueError("codebook J ticks must be on the 256 ns grid")
        if entry.low < 0 or entry.high > 255 or entry.low > entry.high:
            raise ValueError(f"codebook entry has invalid rand8 range: {entry}")
        if entry.dst_port != policy.DEFAULT_RELAY_DST_PORT:
            raise ValueError(f"unexpected relay dst_port in codebook entry: {entry.dst_port}")
    if plan.params_default is not None:
        p = plan.params_default
        if p.mode not in (0, 1, 2, 3, 4, 5):
            raise ValueError(f"reserved/unknown tbl_params mode: {p.mode}")
        if p.d_ticks < 0 or p.da_dr < 0 or p.budget <= 0 or p.read_len < 0:
            raise ValueError("tbl_params fields must be non-negative, with positive budget")
        if p.d_ticks & 0xFF or p.da_dr & 0xFF:
            raise ValueError("tbl_params delay words must be on the 256 ns grid")
        if p.da_dr < p.d_ticks:
            raise ValueError("tbl_params da_dr must be >= d_ticks")
    if plan.bor_params_default is not None:
        b = plan.bor_params_default
        if b.a_ticks < 0 or b.r_ticks < 0 or b.anchor_req not in (0, 1):
            raise ValueError("tbl_bor_params fields are outside allowed values")
        if b.a_ticks & 0xFF or b.r_ticks & 0xFF:
            raise ValueError("tbl_bor_params delay words must be on the 256 ns grid")
        if b.r_ticks < b.a_ticks:
            raise ValueError("tbl_bor_params r_ticks must be >= a_ticks")
        if b.a_ticks >= 30_000_000 or b.r_ticks >= 30_000_000:
            raise ValueError("tbl_bor_params A/R must stay below the 30 ms operational holding ceiling")
    if plan.params_default is not None and plan.bor_params_default is not None:
        p = plan.params_default
        b = plan.bor_params_default
        if (p.d_ticks, p.da_dr) != (b.a_ticks, b.r_ticks):
            raise ValueError("tbl_params and tbl_bor_params A/R fields must match")
        if p.mode not in (0, 5):
            j_max_ms = max(e.j_ticks for e in plan.codebook_entries) / 1_000_000.0 if plan.codebook_entries else 0.0
            a_ms = b.a_ticks / 1_000_000.0
            r_ms = b.r_ticks / 1_000_000.0
            if not (a_ms > j_max_ms + policy.DEFAULT_NATIVE_ACK_MS):
                raise ValueError("A > J_max + native_ACK guard failed")
            if not (r_ms > j_max_ms + policy.DEFAULT_NATIVE_RESP_MS):
                raise ValueError("R > J_max + native_response guard failed")
    return audit


def write_plan(path: Optional[Union[str, Path]], plan: ConfigPlan) -> None:
    text = json.dumps(plan_to_dict(plan), indent=2, sort_keys=True)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _require_authorized() -> None:
    if os.environ.get(AUTH_ENV) != "1":
        raise RuntimeError(f"refusing hardware writes without {AUTH_ENV}=1")


def _load_bfrt(control_dir: Path):
    import importlib.util
    import sys

    setup_path = control_dir / "defense4_timing_setup.py"
    if not setup_path.exists():
        raise FileNotFoundError(f"missing copied control setup at {setup_path}")
    spec = importlib.util.spec_from_file_location("latency_defense4_timing_setup", setup_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    import bfrt_grpc.client as gc

    interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0, device_id=0)
    interface.bind_pipeline_config(mod.PROGRAM)
    bfrt_info = interface.bfrt_info_get(mod.PROGRAM)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    return gc, interface, bfrt_info, target


def _make_codebook_key(table, gc, entry: CodebookEntry):
    return table.make_key(
        [
            gc.KeyTuple("hdr.tcp.dst_port", entry.dst_port),
            gc.KeyTuple("meta.rand8", low=entry.low, high=entry.high),
            gc.KeyTuple("$MATCH_PRIORITY", entry.priority),
        ]
    )


def _action_name(raw: str) -> str:
    return raw.split(".")[-1] if raw.startswith("Ingress.") else raw


def _read_default_dict(table, target) -> dict[str, Any]:
    got = None
    for item in table.default_entry_get(target, {"from_hw": True}):
        data = item[0] if isinstance(item, tuple) else item
        if data is not None:
            got = data.to_dict()
    return got or {}


def _params_from_default_dict(raw: dict[str, Any]) -> Optional[ParamsDefault]:
    if not raw:
        return None
    return ParamsDefault(
        mode=int(raw["mode"]),
        d_ticks=int(raw["d_ticks"]),
        da_dr=int(raw["da_dr"]),
        budget=int(raw["budget"]),
        read_len=int(raw["read_len"]),
        action_name=str(raw.get("action_name", "Ingress.set_params")),
    )


def _bor_params_from_default_dict(raw: dict[str, Any]) -> Optional[BorParamsDefault]:
    if not raw:
        return None
    return BorParamsDefault(
        a_ticks=int(raw["a_ticks"]),
        r_ticks=int(raw["r_ticks"]),
        anchor_req=int(raw["anchor_req"]),
        action_name=str(raw.get("action_name", "Ingress.set_bor_params")),
    )


def _read_live_plan(codebook, params, bor_params, target) -> ConfigPlan:
    entries = []
    for data, key in codebook.entry_get(target, flags={"from_hw": True}):
        entries.append(entry_from_snapshot({"key": key.to_dict(), "data": data.to_dict()}))
    return ConfigPlan(
        codebook_entries=tuple(entries),
        params_default=_params_from_default_dict(_read_default_dict(params, target)),
        bor_params_default=_bor_params_from_default_dict(_read_default_dict(bor_params, target)),
        delete_existing_first=True,
        restoration_only=True,
        notes=(
            "historical restoration exemption: live backup captured before latency-search mutation",
            "not a valid latency-search policy unless its audit is clean",
        ),
    )


def apply_plan_live(
    plan: ConfigPlan,
    control_dir: Path = DEFAULT_CONTROL_DIR,
    snapshot_backup: Optional[Path] = None,
    readback_output: Optional[Path] = None,
) -> dict[str, Any]:
    """Apply only tbl_bor_codebook, tbl_params, and tbl_bor_params with readback verification."""
    _require_authorized()
    validate_plan_for_apply(plan)
    if snapshot_backup and snapshot_backup.exists():
        raise FileExistsError(f"snapshot backup already exists: {snapshot_backup}")

    gc, interface, bfrt_info, target = _load_bfrt(control_dir)
    codebook = bfrt_info.table_get(CODEBOOK_TABLE)
    params = bfrt_info.table_get(PARAMS_TABLE)
    bor_params = bfrt_info.table_get(BOR_PARAMS_TABLE)

    if snapshot_backup:
        snapshot_backup.write_text(
            json.dumps(plan_to_dict(_read_live_plan(codebook, params, bor_params, target)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    time.sleep(plan.source_cache_drain_s)
    if plan.delete_existing_first:
        keys = []
        for data, key in codebook.entry_get(target, flags={"from_hw": True}):
            keys.append(key)
        if keys:
            codebook.entry_del(target, keys)
    for entry in plan.codebook_entries:
        codebook.entry_add(
            target,
            [_make_codebook_key(codebook, gc, entry)],
            [codebook.make_data([gc.DataTuple("j_ticks", entry.j_ticks)], "set_j")],
        )
    if plan.params_default is not None:
        p = plan.params_default
        params.default_entry_set(
            target,
            params.make_data(
                [
                    gc.DataTuple("d_ticks", p.d_ticks),
                    gc.DataTuple("read_len", p.read_len),
                    gc.DataTuple("budget", p.budget),
                    gc.DataTuple("mode", p.mode),
                    gc.DataTuple("da_dr", p.da_dr),
                ],
                _action_name(p.action_name),
            ),
        )
    if plan.bor_params_default is not None:
        bp = plan.bor_params_default
        bor_params.default_entry_set(
            target,
            bor_params.make_data(
                [
                    gc.DataTuple("a_ticks", bp.a_ticks),
                    gc.DataTuple("r_ticks", bp.r_ticks),
                    gc.DataTuple("anchor_req", bp.anchor_req),
                ],
                _action_name(bp.action_name),
            ),
        )
    time.sleep(plan.source_cache_drain_s)

    readback_entries = []
    for data, key in codebook.entry_get(target, flags={"from_hw": True}):
        raw = {"key": key.to_dict(), "data": data.to_dict()}
        readback_entries.append(entry_from_snapshot(raw))
    audit = audit_entries(readback_entries)
    expected = sorted(plan.codebook_entries, key=lambda e: (e.priority, e.low, e.high, e.j_ticks))
    got = sorted(readback_entries, key=lambda e: (e.priority, e.low, e.high, e.j_ticks))
    if got != expected:
        raise RuntimeError("codebook readback mismatch after install")
    if not plan.restoration_only and not audit.valid_policy:
        raise RuntimeError(f"codebook readback is not a valid policy: {audit}")
    params_got = _read_default_dict(params, target)
    bor_params_got = _read_default_dict(bor_params, target)
    if plan.params_default is not None:
        want = asdict(plan.params_default)
        for k in ("mode", "d_ticks", "da_dr", "budget", "read_len"):
            if params_got.get(k) != want[k]:
                raise RuntimeError(f"tbl_params readback mismatch for {k}: got {params_got.get(k)!r} want {want[k]!r}")
    if plan.bor_params_default is not None:
        want_bor = asdict(plan.bor_params_default)
        for k in ("a_ticks", "r_ticks", "anchor_req"):
            if bor_params_got.get(k) != want_bor[k]:
                raise RuntimeError(
                    f"tbl_bor_params readback mismatch for {k}: got {bor_params_got.get(k)!r} want {want_bor[k]!r}"
                )
    result = {
        "codebook": [asdict(e) for e in got],
        "audit": asdict(audit),
        "tbl_params": params_got,
        "tbl_bor_params": bor_params_got,
    }
    if readback_output:
        readback_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    interface.tear_down_stream()
    return result


def _parse_j_set(spec: str) -> tuple[float, ...]:
    return tuple(float(tok) for tok in spec.replace(",", " ").split())


def _plan_from_json(path: Path) -> ConfigPlan:
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = tuple(CodebookEntry(**e) for e in raw["codebook_entries"])
    params = raw.get("params_default")
    bor_params = raw.get("bor_params_default")
    return ConfigPlan(
        codebook_entries=entries,
        params_default=None if params is None else ParamsDefault(**params),
        bor_params_default=None if bor_params is None else BorParamsDefault(**bor_params),
        delete_existing_first=bool(raw.get("delete_existing_first", True)),
        restoration_only=bool(raw.get("restoration_only", False)),
        source_cache_drain_s=float(raw.get("source_cache_drain_s", SOURCE_CACHE_DRAIN_S)),
        notes=tuple(raw.get("notes", ())),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Latency-search narrow codebook/params configurator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_plan = sub.add_parser("plan-codebook")
    p_plan.add_argument("--j-set", default="0.25 0.5 1")
    p_plan.add_argument("--output")

    p_policy = sub.add_parser("plan-policy")
    p_policy.add_argument("--name", default="manual")
    p_policy.add_argument("--mode", default="D4", choices=["OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"])
    p_policy.add_argument("--da-ms", type=float, required=True)
    p_policy.add_argument("--gap-ms", type=float, required=True)
    p_policy.add_argument("--j-set", default="0.25 0.5 1")
    p_policy.add_argument("--budget", type=int, default=18000)
    p_policy.add_argument("--read-len", type=int, default=0)
    p_policy.add_argument("--anchor-req", type=int, choices=[0, 1], default=1)
    p_policy.add_argument("--output")

    p_audit = sub.add_parser("audit-snapshot")
    p_audit.add_argument("--snapshot", required=True)
    p_audit.add_argument("--output")

    p_restore = sub.add_parser("restore-plan")
    p_restore.add_argument("--snapshot", required=True)
    p_restore.add_argument("--output")

    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--policy", required=True, help="JSON file produced by plan-codebook or restore-plan")
    p_apply.add_argument("--control-dir", default=str(DEFAULT_CONTROL_DIR))
    p_apply.add_argument("--snapshot-backup")
    p_apply.add_argument("--readback-output")

    args = ap.parse_args(argv)
    if args.cmd == "plan-codebook":
        write_plan(args.output, build_codebook_plan(_parse_j_set(args.j_set)))
        return 0
    if args.cmd == "plan-policy":
        p = policy.make_policy(args.name, "manual", args.mode, args.da_ms, args.gap_ms, _parse_j_set(args.j_set))
        write_plan(args.output, build_policy_plan(p, budget=args.budget, read_len=args.read_len, anchor_req=args.anchor_req))
        return 0
    if args.cmd == "audit-snapshot":
        snap = load_snapshot(args.snapshot)
        data = asdict(audit_codebook_snapshot(snap))
        text = json.dumps(data, indent=2, sort_keys=True)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return 0
    if args.cmd == "restore-plan":
        write_plan(args.output, restore_plan_from_snapshot(load_snapshot(args.snapshot)))
        return 0
    if args.cmd == "apply":
        apply_plan_live(
            _plan_from_json(Path(args.policy)),
            control_dir=Path(args.control_dir),
            snapshot_backup=None if not args.snapshot_backup else Path(args.snapshot_backup),
            readback_output=None if not args.readback_output else Path(args.readback_output),
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
