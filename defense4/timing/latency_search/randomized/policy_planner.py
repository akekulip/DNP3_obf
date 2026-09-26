#!/usr/bin/env python3
"""Plan one class-independent randomized deadline policy for tbl_random_deadlines."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Sequence

try:
    from .. import policy as base_policy
except (ImportError, ValueError):  # direct script or top-level randomized package on Python 3.8
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[1]))
    import policy as base_policy  # type: ignore

J_SET_MS = (0.25, 0.5, 1.0)
DEFAULT_CENTERS = ((5.0, 1.0), (5.0, 2.0), (4.0, 4.0), (5.0, 4.0), (5.0, 8.0), (8.0, 4.0), (12.0, 4.0))
DEFAULT_AMPLITUDES = (0.5, 1.0, 2.0, 4.0)
MODES = ("gap", "joint")
TABLE_NAME = "pipe.Ingress.tbl_random_deadlines"
ACTION_NAME = "Ingress.set_random_deadlines"


@dataclass(frozen=True)
class RandomPolicyEntry:
    low: int
    high: int
    priority: int
    center_da_ms: float
    center_gap_ms: float
    amplitude_ms: float
    mode: str
    da_offset_ms: float
    gap_offset_ms: float
    d_ticks: int
    da_dr_ticks: int
    op_a_ticks: int
    op_r_ticks: int
    da_ms: float
    gap_ms: float
    total_ms: float
    action_name: str = ACTION_NAME


@dataclass(frozen=True)
class ExcludedCandidate:
    center_da_ms: float
    center_gap_ms: float
    amplitude_ms: float
    mode: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RandomPolicyPlan:
    table_name: str
    action_name: str
    center_da_ms: float
    center_gap_ms: float
    amplitude_ms: float
    mode: str
    entries: tuple[RandomPolicyEntry, ...]
    excluded: tuple[ExcludedCandidate, ...]
    j_set_ms: tuple[float, ...]
    notes: tuple[str, ...]


def _fmt_float(v: float) -> str:
    return f"{v:.6f}".rstrip("0").rstrip(".")


def _linspace16(amplitude_ms: float) -> tuple[float, ...]:
    a = float(amplitude_ms)
    if a < 0:
        raise ValueError("amplitude_ms must be non-negative")
    if a == 0:
        return tuple(0.0 for _ in range(16))
    return tuple(-a + (2.0 * a * i / 15.0) for i in range(16))


def _linspace4(amplitude_ms: float) -> tuple[float, ...]:
    a = float(amplitude_ms)
    if a < 0:
        raise ValueError("amplitude_ms must be non-negative")
    if a == 0:
        return (0.0, 0.0, 0.0, 0.0)
    return (-a, -a / 3.0, a / 3.0, a)


def offsets_for_mode(amplitude_ms: float, mode: str) -> tuple[tuple[float, float], ...]:
    if mode == "gap":
        return tuple((0.0, gap) for gap in _linspace16(amplitude_ms))
    if mode == "joint":
        da_levels = _linspace4(amplitude_ms)
        gap_levels = _linspace4(amplitude_ms)
        return tuple((da, gap) for da in da_levels for gap in gap_levels)
    raise ValueError(f"unsupported random policy mode {mode!r}; expected one of {MODES}")


def _guard_reasons(da_ms: float, gap_ms: float, j_set_ms: Sequence[float]) -> tuple[str, ...]:
    reasons: list[str] = []
    if da_ms <= 0:
        reasons.append(f"D_A must be positive: {da_ms:g} ms")
    if gap_ms <= 0:
        reasons.append(f"gap must be positive: {gap_ms:g} ms")
    if reasons:
        return tuple(reasons)
    p = base_policy.make_policy("candidate", "random", "D4", da_ms, gap_ms, j_set_ms)
    guard = base_policy.validate_operate_guards(p)
    reasons.extend(guard.reasons)
    if p.da.word <= 0 or p.gap.word <= 0:
        reasons.append("quantized D_A/gap must be positive")
    if p.da.word & 0xFF or p.gap.word & 0xFF or (p.da.word + p.gap.word) & 0xFF:
        reasons.append("delay values must stay on the 256 ns grid")
    if p.op_r_ms >= 30.0:
        reasons.append(f"total R must stay below 30 ms: {p.op_r_ms:g} ms")
    return tuple(reasons)


def _entry(
    *,
    idx: int,
    offset_count: int,
    center_da_ms: float,
    center_gap_ms: float,
    amplitude_ms: float,
    mode: str,
    da_offset_ms: float,
    gap_offset_ms: float,
) -> RandomPolicyEntry:
    low = idx * 256 // offset_count
    high = 255 if idx == offset_count - 1 else ((idx + 1) * 256 // offset_count) - 1
    da_q = base_policy.quantize_ms(center_da_ms + da_offset_ms)
    gap_q = base_policy.quantize_ms(center_gap_ms + gap_offset_ms)
    total = da_q.word + gap_q.word
    return RandomPolicyEntry(
        low=low,
        high=high,
        priority=idx + 1,
        center_da_ms=float(center_da_ms),
        center_gap_ms=float(center_gap_ms),
        amplitude_ms=float(amplitude_ms),
        mode=mode,
        da_offset_ms=float(da_offset_ms),
        gap_offset_ms=float(gap_offset_ms),
        d_ticks=da_q.word,
        da_dr_ticks=total,
        op_a_ticks=da_q.word,
        op_r_ticks=total,
        da_ms=da_q.realized_ms,
        gap_ms=gap_q.realized_ms,
        total_ms=total / 1_000_000.0,
    )


def build_plan(
    *,
    center_da_ms: float,
    center_gap_ms: float,
    amplitude_ms: float,
    mode: str,
    j_set_ms: Sequence[float] = J_SET_MS,
) -> RandomPolicyPlan:
    offsets = offsets_for_mode(amplitude_ms, mode)
    entries: list[RandomPolicyEntry] = []
    reasons: list[str] = []
    for idx, (da_off, gap_off) in enumerate(offsets):
        da_ms = float(center_da_ms) + da_off
        gap_ms = float(center_gap_ms) + gap_off
        pair_reasons = _guard_reasons(da_ms, gap_ms, j_set_ms)
        if pair_reasons:
            label = f"offset[{idx}] da_offset={_fmt_float(da_off)} gap_offset={_fmt_float(gap_off)}"
            reasons.extend(f"{label}: {reason}" for reason in pair_reasons)
        else:
            entries.append(
                _entry(
                    idx=idx,
                    offset_count=len(offsets),
                    center_da_ms=float(center_da_ms),
                    center_gap_ms=float(center_gap_ms),
                    amplitude_ms=float(amplitude_ms),
                    mode=mode,
                    da_offset_ms=da_off,
                    gap_offset_ms=gap_off,
                )
            )
    if reasons:
        raise ValueError("random policy rejected: " + "; ".join(reasons))
    validate_plan_entries(entries)
    return RandomPolicyPlan(
        table_name=TABLE_NAME,
        action_name=ACTION_NAME,
        center_da_ms=float(center_da_ms),
        center_gap_ms=float(center_gap_ms),
        amplitude_ms=float(amplitude_ms),
        mode=mode,
        entries=tuple(entries),
        excluded=(),
        j_set_ms=tuple(float(x) for x in j_set_ms),
        notes=(
            "Clearing the table leaves the P4 default NoAction, restoring fixed tbl_params/tbl_bor_params behavior.",
            "The mapping is class-independent: READ, SELECT, and OPERATE use the same rand8 distribution.",
            "The BOR J draw remains separate and may be correlated by packet draw source; account for it in analysis.",
        ),
    )


def try_build_plan(**kwargs) -> tuple[Optional[RandomPolicyPlan], Optional[ExcludedCandidate]]:
    try:
        return build_plan(**kwargs), None
    except ValueError as exc:
        message = str(exc)
        prefix = "random policy rejected: "
        if message.startswith(prefix):
            message = message[len(prefix):]
        return None, ExcludedCandidate(
            center_da_ms=float(kwargs["center_da_ms"]),
            center_gap_ms=float(kwargs["center_gap_ms"]),
            amplitude_ms=float(kwargs["amplitude_ms"]),
            mode=str(kwargs["mode"]),
            reasons=tuple(message.split("; ")),
        )


def enumerate_plans(
    centers: Sequence[tuple[float, float]] = DEFAULT_CENTERS,
    amplitudes: Sequence[float] = DEFAULT_AMPLITUDES,
    modes: Sequence[str] = MODES,
    j_set_ms: Sequence[float] = J_SET_MS,
) -> dict:
    valid: list[RandomPolicyPlan] = []
    excluded: list[ExcludedCandidate] = []
    for center_da, center_gap in centers:
        for amplitude in amplitudes:
            for mode in modes:
                plan, miss = try_build_plan(
                    center_da_ms=float(center_da),
                    center_gap_ms=float(center_gap),
                    amplitude_ms=float(amplitude),
                    mode=str(mode),
                    j_set_ms=j_set_ms,
                )
                if plan is not None:
                    valid.append(plan)
                elif miss is not None:
                    excluded.append(miss)
    return {"valid_plans": valid, "excluded_configs": excluded}


def validate_plan(plan: RandomPolicyPlan) -> None:
    validate_plan_entries(plan.entries, plan.j_set_ms)
    if plan.table_name != TABLE_NAME or plan.action_name != ACTION_NAME:
        raise ValueError('unexpected random table/action')
    expected = build_plan(center_da_ms=plan.center_da_ms, center_gap_ms=plan.center_gap_ms,
                          amplitude_ms=plan.amplitude_ms, mode=plan.mode,
                          j_set_ms=plan.j_set_ms)
    if plan.entries != expected.entries or plan.excluded:
        raise ValueError('entries differ from the declared complete symmetric policy')


def validate_plan_entries(entries: Sequence[RandomPolicyEntry], j_set_ms: Sequence[float] = J_SET_MS) -> None:
    if len(entries) != 16:
        raise ValueError(f"expected exactly 16 entries, got {len(entries)}")
    owners = {i: 0 for i in range(256)}
    for entry in entries:
        if entry.low < 0 or entry.high > 255 or entry.low > entry.high:
            raise ValueError(f"invalid rand8 range {entry.low}..{entry.high}")
        if entry.priority <= 0:
            raise ValueError("priority must be positive")
        for bucket in range(entry.low, entry.high + 1):
            owners[bucket] += 1
        values = (entry.d_ticks, entry.da_dr_ticks, entry.op_a_ticks, entry.op_r_ticks)
        if entry.d_ticks != entry.op_a_ticks or entry.da_dr_ticks != entry.op_r_ticks:
            raise ValueError("READ/SELECT and OPERATE selected values must match")
        if any(v <= 0 for v in values):
            raise ValueError("selected ticks must be positive")
        if any(v & 0xFF for v in values):
            raise ValueError("selected ticks must be on 256 ns grid")
        if entry.da_dr_ticks <= entry.d_ticks:
            raise ValueError("da_dr_ticks must be > d_ticks")
        if entry.op_r_ticks >= 30_000_000:
            raise ValueError("op_r_ticks must stay below 30 ms")
        actual_da = entry.d_ticks / 1_000_000.0
        actual_gap = (entry.da_dr_ticks - entry.d_ticks) / 1_000_000.0
        actual_total = entry.da_dr_ticks / 1_000_000.0
        if (entry.da_ms, entry.gap_ms, entry.total_ms) != (actual_da, actual_gap, actual_total):
            raise ValueError('descriptive delays do not match actual installed ticks')
        pair_reasons = _guard_reasons(actual_da, actual_gap, j_set_ms)
        if pair_reasons:
            raise ValueError(f"entry violates runtime guards: {pair_reasons}")
    missing = [b for b, count in owners.items() if count == 0]
    duplicate = [b for b, count in owners.items() if count > 1]
    if missing or duplicate:
        raise ValueError(f"rand8 coverage invalid: missing={missing[:8]} duplicate={duplicate[:8]}")


def plan_to_dict(plan: RandomPolicyPlan) -> dict:
    return {
        "table_name": plan.table_name,
        "action_name": plan.action_name,
        "center_da_ms": plan.center_da_ms,
        "center_gap_ms": plan.center_gap_ms,
        "amplitude_ms": plan.amplitude_ms,
        "mode": plan.mode,
        "entries": [asdict(e) for e in plan.entries],
        "excluded": [asdict(e) for e in plan.excluded],
        "j_set_ms": list(plan.j_set_ms),
        "notes": list(plan.notes),
    }


def excluded_to_dict(item: ExcludedCandidate) -> dict:
    return asdict(item)


def enumeration_to_dict(result: dict) -> dict:
    return {
        "valid_plans": [plan_to_dict(p) for p in result["valid_plans"]],
        "excluded_configs": [excluded_to_dict(e) for e in result["excluded_configs"]],
        "counts": {"valid": len(result["valid_plans"]), "excluded": len(result["excluded_configs"])},
    }


def write_plan(plan: RandomPolicyPlan, path: str | Path) -> None:
    Path(path).write_text(json.dumps(plan_to_dict(plan), indent=2, sort_keys=True) + "\n")


def load_plan(path: str | Path) -> RandomPolicyPlan:
    raw = json.loads(Path(path).read_text())
    entries = tuple(RandomPolicyEntry(**e) for e in raw["entries"])
    excluded = tuple(ExcludedCandidate(**e) for e in raw.get("excluded", ()))
    plan = RandomPolicyPlan(
        table_name=raw.get("table_name", TABLE_NAME),
        action_name=raw.get("action_name", ACTION_NAME),
        center_da_ms=float(raw["center_da_ms"]),
        center_gap_ms=float(raw["center_gap_ms"]),
        amplitude_ms=float(raw["amplitude_ms"]),
        mode=str(raw["mode"]),
        entries=entries,
        excluded=excluded,
        j_set_ms=tuple(float(x) for x in raw.get("j_set_ms", J_SET_MS)),
        notes=tuple(raw.get("notes", ())),
    )
    validate_plan(plan)
    return plan


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--center-da-ms", type=float)
    ap.add_argument("--center-gap-ms", type=float)
    ap.add_argument("--amplitude-ms", type=float)
    ap.add_argument("--mode", choices=MODES)
    ap.add_argument("--enumerate", action="store_true")
    ap.add_argument("--output")
    args = ap.parse_args(argv)
    if args.enumerate:
        doc = enumeration_to_dict(enumerate_plans())
    else:
        missing = [name for name in ("center_da_ms", "center_gap_ms", "amplitude_ms", "mode") if getattr(args, name) is None]
        if missing:
            raise SystemExit("missing required args unless --enumerate: " + ", ".join("--" + x.replace("_", "-") for x in missing))
        doc = plan_to_dict(build_plan(
            center_da_ms=args.center_da_ms,
            center_gap_ms=args.center_gap_ms,
            amplitude_ms=args.amplitude_ms,
            mode=args.mode,
        ))
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
