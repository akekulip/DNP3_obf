#!/usr/bin/env python3
"""Guarded BFRT setter for pipe.Ingress.tbl_random_deadlines.

This script is intentionally narrow. It only clears/programs/reads back the
random deadline table. It does not touch ports, queues, mirrors, pktgen, daemon
state, tbl_params, tbl_bor_params, or traffic.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional, Sequence

try:
    from . import policy_planner
except ImportError:  # direct script execution
    import policy_planner  # type: ignore

AUTH_ENV = "DEFENSE4_HW_AUTHORIZED"
PROGRAM = "defense4_timing"
TABLE_NAME = policy_planner.TABLE_NAME
ACTION_NAME = policy_planner.ACTION_NAME


def require_authorized() -> None:
    if os.environ.get(AUTH_ENV) != "1":
        raise RuntimeError(f"refusing BFRT writes without {AUTH_ENV}=1")


def _action_name(name: str) -> str:
    return name.split(".")[-1]


def _entry_key(table, gc, entry: policy_planner.RandomPolicyEntry):
    return table.make_key(
        [
            gc.KeyTuple("meta.rand8", low=entry.low, high=entry.high),
            gc.KeyTuple("$MATCH_PRIORITY", entry.priority),
        ]
    )


def _entry_data(table, gc, entry: policy_planner.RandomPolicyEntry):
    return table.make_data(
        [
            gc.DataTuple("d_ticks", entry.d_ticks),
            gc.DataTuple("da_dr_ticks", entry.da_dr_ticks),
            gc.DataTuple("op_a_ticks", entry.op_a_ticks),
            gc.DataTuple("op_r_ticks", entry.op_r_ticks),
        ],
        _action_name(entry.action_name),
    )


def _range_field(key: dict[str, Any], name: str) -> tuple[int, int]:
    raw = key[name]
    if isinstance(raw, dict):
        return int(raw.get("low", raw.get("value"))), int(raw.get("high", raw.get("value")))
    return int(raw), int(raw)


def _scalar(key: dict[str, Any], name: str) -> int:
    raw = key[name]
    if isinstance(raw, dict):
        return int(raw.get("value", raw.get("low")))
    return int(raw)


def entry_from_readback(data: dict[str, Any], key: dict[str, Any]) -> dict[str, Any]:
    low, high = _range_field(key, "meta.rand8")
    return {
        "low": low,
        "high": high,
        "priority": _scalar(key, "$MATCH_PRIORITY"),
        "d_ticks": int(data["d_ticks"]),
        "da_dr_ticks": int(data["da_dr_ticks"]),
        "op_a_ticks": int(data["op_a_ticks"]),
        "op_r_ticks": int(data["op_r_ticks"]),
        "action_name": str(data.get("action_name", ACTION_NAME)),
    }


def _normalise_expected(entry: policy_planner.RandomPolicyEntry) -> dict[str, Any]:
    return {
        "low": entry.low,
        "high": entry.high,
        "priority": entry.priority,
        "d_ticks": entry.d_ticks,
        "da_dr_ticks": entry.da_dr_ticks,
        "op_a_ticks": entry.op_a_ticks,
        "op_r_ticks": entry.op_r_ticks,
        "action_name": entry.action_name,
    }


def _sorted_entries(entries: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda e: (e["priority"], e["low"], e["high"]))


def _read_default_action(table, target) -> str | None:
    if not hasattr(table, "default_entry_get"):
        return None
    got = None
    for item in table.default_entry_get(target, flags={"from_hw": True}):
        data = item[0] if isinstance(item, tuple) else item
        if data is not None:
            raw = data.to_dict()
            got = raw.get("action_name")
    return None if got is None else str(got)


def verify_default_noaction(table, target) -> str | None:
    action = _read_default_action(table, target)
    if action is None or action.split(".")[-1] != "NoAction":
        raise RuntimeError(f"tbl_random_deadlines default is {action!r}, expected NoAction")
    return action


def open_bfrt(program: str = PROGRAM, client_id: int = 0):
    import bfrt_grpc.client as gc

    interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=client_id, device_id=0)
    try:
        interface.bind_pipeline_config(program)
        bfrt_info = interface.bfrt_info_get(program)
        target = gc.Target(device_id=0, pipe_id=0xFFFF)
        return gc, interface, bfrt_info, target
    except BaseException:
        interface.tear_down_stream()
        raise


def clear_table_live(program: str = PROGRAM, client_id: int = 0) -> dict[str, Any]:
    require_authorized()
    gc, interface, bfrt_info, target = open_bfrt(program, client_id)
    try:
        table = bfrt_info.table_get(TABLE_NAME)
        keys = [key for _data, key in table.entry_get(target, flags={"from_hw": True})]
        if keys:
            table.entry_del(target, keys)
        readback = readback_table(table, target)
        if readback:
            raise RuntimeError("tbl_random_deadlines clear readback is not empty")
        default_action = verify_default_noaction(table, target)
        return {"cleared": True, "deleted": len(keys), "readback": [], "default_action": default_action}
    finally:
        interface.tear_down_stream()


def readback_table(table, target) -> list[dict[str, Any]]:
    rows = []
    for data, key in table.entry_get(target, flags={"from_hw": True}):
        rows.append(entry_from_readback(data.to_dict(), key.to_dict()))
    return _sorted_entries(rows)


def apply_plan_live(
    plan: policy_planner.RandomPolicyPlan,
    program: str = PROGRAM,
    client_id: int = 0,
    output: Optional[Path] = None,
) -> dict[str, Any]:
    require_authorized()
    policy_planner.validate_plan(plan)
    gc, interface, bfrt_info, target = open_bfrt(program, client_id)
    try:
        table = bfrt_info.table_get(TABLE_NAME)
        verify_default_noaction(table, target)
        keys = [key for _data, key in table.entry_get(target, flags={"from_hw": True})]
        if keys:
            table.entry_del(target, keys)
        for entry in plan.entries:
            table.entry_add(target, [_entry_key(table, gc, entry)], [_entry_data(table, gc, entry)])
        got = readback_table(table, target)
        expected = _sorted_entries([_normalise_expected(e) for e in plan.entries])
        if got != expected:
            raise RuntimeError("tbl_random_deadlines readback mismatch")
        result = {
            "program": program,
            "table_name": TABLE_NAME,
            "entry_count": len(got),
            "entries": got,
            "plan": policy_planner.plan_to_dict(plan),
        }
        if output:
            output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result
    finally:
        interface.tear_down_stream()


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_apply = sub.add_parser("apply-plan")
    p_apply.add_argument("--plan", required=True)
    p_apply.add_argument("--program", default=PROGRAM)
    p_apply.add_argument("--client-id", type=int, default=0)
    p_apply.add_argument("--output")
    p_clear = sub.add_parser("clear")
    p_clear.add_argument("--program", default=PROGRAM)
    p_clear.add_argument("--client-id", type=int, default=0)
    p_clear.add_argument("--output")
    args = ap.parse_args(argv)
    if args.cmd == "apply-plan":
        result = apply_plan_live(
            policy_planner.load_plan(args.plan),
            program=args.program,
            client_id=args.client_id,
            output=None if args.output is None else Path(args.output),
        )
    else:
        result = clear_table_live(program=args.program, client_id=args.client_id)
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
