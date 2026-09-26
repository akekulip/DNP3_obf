#!/usr/bin/env python3
"""Offline policy planner for the low-latency timing search.

The planner does not touch hardware. It enumerates the fixed search requested for
the next campaign, records the actual 256 ns-grid values that the P4 setup can
accept, and emits the narrow setup command for each point.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

TICK_NS = 256
DEFAULT_NATIVE_ACK_MS = 2.0
DEFAULT_NATIVE_RESP_MS = 2.0
DEFAULT_RELAY_DST_PORT = 20000
FIXED_DA_MS = (5, 10, 15, 20)
FIXED_GAP_MS = (1, 2, 4, 6, 8)
EXTRA_FIXED = ((4, 4), (12, 4))
SMALL_SHARED_J_SET_MS = (0.25, 0.5, 1.0)
REFERENCE_J_SET_MS = (2.0, 6.0, 12.0)
ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIGURE = ROOT / "defense4" / "timing" / "latency_search" / "configure.py"


@dataclass(frozen=True)
class QuantizedDelay:
    requested_ms: float
    word: int
    realized_ms: float
    quantization_error_ns: int
    low_byte_zero: bool


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reasons: tuple[str, ...]
    risk: str


@dataclass(frozen=True)
class TimingPolicy:
    name: str
    kind: str
    mode: str
    requested_da_ms: float
    requested_gap_ms: float
    da: QuantizedDelay
    gap: QuantizedDelay
    op_a_ms: float
    op_r_ms: float
    j_set_ms: tuple[float, ...]
    relay_dst_port: int = DEFAULT_RELAY_DST_PORT
    note: str = ""


def quantize_ms(ms: float) -> QuantizedDelay:
    if ms < 0:
        raise ValueError("delay must be non-negative")
    requested_ns = int(round(ms * 1_000_000))
    word = (requested_ns // TICK_NS) * TICK_NS
    return QuantizedDelay(
        requested_ms=float(ms),
        word=word,
        realized_ms=word / 1_000_000.0,
        quantization_error_ns=requested_ns - word,
        low_byte_zero=(word & 0xFF) == 0,
    )


def _fmt_float(v: float) -> str:
    return f"{v:.6f}".rstrip("0").rstrip(".")


def make_policy(
    name: str,
    kind: str,
    mode: str,
    da_ms: float,
    gap_ms: float,
    j_set_ms: Sequence[float] = SMALL_SHARED_J_SET_MS,
    note: str = "",
) -> TimingPolicy:
    da = quantize_ms(da_ms)
    gap = quantize_ms(gap_ms)
    return TimingPolicy(
        name=name,
        kind=kind,
        mode=mode,
        requested_da_ms=float(da_ms),
        requested_gap_ms=float(gap_ms),
        da=da,
        gap=gap,
        op_a_ms=da.realized_ms,
        op_r_ms=(da.word + gap.word) / 1_000_000.0,
        j_set_ms=tuple(float(x) for x in j_set_ms),
        note=note,
    )


def build_search_plan() -> list[TimingPolicy]:
    out: list[TimingPolicy] = []
    for da in FIXED_DA_MS:
        for gap in FIXED_GAP_MS:
            out.append(make_policy(f"da{da}_gap{gap}", "fixed", "D4", da, gap))
    for da, gap in EXTRA_FIXED:
        out.append(make_policy(f"da{da}_gap{gap}", "fixed", "D4", da, gap))
    out.extend(
        [
            make_policy(
                "ref_off_20_4",
                "reference",
                "OFF",
                20,
                4,
                REFERENCE_J_SET_MS,
                "Timing OFF reference; codebook recorded only for restore parity.",
            ),
            make_policy(
                "ref_d4_20_4",
                "reference",
                "D4",
                20,
                4,
                REFERENCE_J_SET_MS,
                "High-overhead D4 reference with the historical J codebook.",
            ),
            make_policy(
                "ref_d4_20_8",
                "reference",
                "D4",
                20,
                8,
                REFERENCE_J_SET_MS,
                "High-overhead D4 reference matching the current 28 ms total setting.",
            ),
        ]
    )
    return out


def validate_operate_guards(
    p: TimingPolicy,
    native_ack_ms: float = DEFAULT_NATIVE_ACK_MS,
    native_resp_ms: float = DEFAULT_NATIVE_RESP_MS,
) -> GuardResult:
    reasons: list[str] = []
    j_max = max(p.j_set_ms) if p.j_set_ms else None
    if j_max is None:
        reasons.append("J set is empty")
    else:
        if not (p.op_a_ms > j_max + native_ack_ms):
            reasons.append(
                "A > J_max + native_ACK failed: "
                f"A={_fmt_float(p.op_a_ms)} J_max={_fmt_float(j_max)} native_ACK={_fmt_float(native_ack_ms)}"
            )
        if not (p.op_r_ms > j_max + native_resp_ms):
            reasons.append(
                "R > J_max + native_response failed: "
                f"R={_fmt_float(p.op_r_ms)} J_max={_fmt_float(j_max)} "
                f"native_response={_fmt_float(native_resp_ms)}"
            )
    if p.op_r_ms < p.op_a_ms:
        reasons.append(f"R >= A failed: R={_fmt_float(p.op_r_ms)} A={_fmt_float(p.op_a_ms)}")
    risk = "reference_large_j" if p.kind == "reference" and p.j_set_ms == REFERENCE_J_SET_MS else "normal"
    if p.j_set_ms == SMALL_SHARED_J_SET_MS:
        risk = "codebook_only_operate_variance"
    return GuardResult(ok=not reasons, reasons=tuple(reasons), risk=risk)


def setup_args(p: TimingPolicy, configure: Path = DEFAULT_CONFIGURE) -> list[str]:
    """Return dry-run-safe argv for the narrow policy-plan surface."""
    return [
        "python3",
        str(configure),
        "plan-policy",
        "--name",
        p.name,
        "--mode",
        p.mode,
        "--da-ms",
        _fmt_float(p.da.realized_ms),
        "--gap-ms",
        _fmt_float(p.gap.realized_ms),
        "--j-set",
        " ".join(_fmt_float(x) for x in p.j_set_ms),
    ]


def _policy_json(policies: Iterable[TimingPolicy]) -> dict:
    policies = list(policies)
    rows = []
    refs = []
    for p in policies:
        guard = validate_operate_guards(p)
        row = asdict(p)
        row["guard"] = asdict(guard)
        row["setup_args"] = setup_args(p)
        if p.kind == "reference":
            refs.append(row)
        else:
            rows.append(row)
    return {
        "counts": {
            "fixed": sum(1 for p in policies if p.kind == "fixed"),
            "reference": sum(1 for p in policies if p.kind == "reference"),
        },
        "recommendation": {
            "fixed_search_j_set_ms": list(SMALL_SHARED_J_SET_MS),
            "why": (
                "The historical {2,6,12} ms J set rejects low-D_A points under the "
                "native 2 ms guard; {0.25,0.5,1} ms keeps DA>=4 ms admissible."
            ),
            "operate_risk": (
                "This codebook changes only OPERATE relay-release variance; READ/SELECT "
                "timing is still controlled by D_A and D_R."
            ),
        },
        "policies": rows,
        "references": refs,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Dry-run low-latency timing policy planner")
    ap.add_argument("--json", action="store_true", help="emit machine-readable plan")
    args = ap.parse_args(argv)
    doc = _policy_json(build_search_plan())
    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        for row in doc["policies"] + doc["references"]:
            status = "OK" if row["guard"]["ok"] else "INVALID"
            print(f"{row['name']}: {status} {' '.join(row['setup_args'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
