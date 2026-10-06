#!/usr/bin/env python3
"""Guarded latency-search hardware block runner.

The live path requires DEFENSE4_HW_AUTHORIZED=1. The dry path only writes the
planned paths and capture budget, so it can be tested without touching hardware.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback


HERE = Path(__file__).resolve().parent
ACTIVE_HARNESS = next(
    p for p in (HERE / "active_harness", HERE.parent / "active_harness")
    if p.exists()
)
if str(ACTIVE_HARNESS) not in sys.path:
    sys.path.insert(0, str(ACTIVE_HARNESS))

import read_driver  # noqa: E402
import sbo_driver  # noqa: E402
from session import Session  # noqa: E402


RELAY_IP = "192.168.10.7"
RELAY_PORT = 20000
SRC_IP = "192.168.10.1"
CAPTURE_IFACE = "enp59s0f0np0"
CAPTURE_FILTER = "host 192.168.10.7 and tcp port 20000"
POINTS = [1, 3]


@dataclass(frozen=True)
class BlockPlan:
    label: str
    reads: int
    sbo: int
    gap_ms: float
    budget_ms: float
    duration_s: int
    out_dir: Path
    app_dir: Path
    capture_dir: Path
    readback_dir: Path
    log_dir: Path
    pcap: Path
    read_jsonl: Path
    sbo_jsonl: Path
    timestamp_utc: str


def _timestamp(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _capture_duration_s(reads: int, sbo: int, gap_ms: float, budget_ms: float) -> int:
    read_ms = reads * (budget_ms + gap_ms)
    sbo_ms = sbo * (2 * budget_ms + gap_ms)
    # One second capture warmup, output-state checks, and margin for process startup/teardown.
    return max(6, int((read_ms + sbo_ms) / 1000.0 + 26 + 0.999999))


def build_plan(label: str, *, reads: int, sbo: int, gap_ms: float, budget_ms: float,
               root: Path | None = None, now: datetime | None = None) -> BlockPlan:
    if reads < 0 or sbo < 0:
        raise ValueError("--reads and --sbo must be non-negative")
    if gap_ms < 0 or budget_ms <= 0:
        raise ValueError("--gap-ms must be non-negative and --budget-ms must be positive")
    root = Path(root) if root is not None else HERE
    ts = _timestamp(now)
    out_dir = root / label
    app_dir = out_dir / "app_jsonl"
    capture_dir = out_dir / "raw_pcaps"
    readback_dir = out_dir / "readbacks"
    log_dir = out_dir / "logs"
    stem = f"{label}_{ts}"
    return BlockPlan(
        label=label,
        reads=reads,
        sbo=sbo,
        gap_ms=gap_ms,
        budget_ms=budget_ms,
        duration_s=_capture_duration_s(reads, sbo, gap_ms, budget_ms),
        out_dir=out_dir,
        app_dir=app_dir,
        capture_dir=capture_dir,
        readback_dir=readback_dir,
        log_dir=log_dir,
        pcap=capture_dir / f"{stem}.pcapng",
        read_jsonl=app_dir / f"{stem}_read.jsonl",
        sbo_jsonl=app_dir / f"{stem}_sbo.jsonl",
        timestamp_utc=ts,
    )


def _jsonable_plan(plan: BlockPlan) -> dict:
    data = asdict(plan)
    for key, value in list(data.items()):
        if isinstance(value, Path):
            data[key] = str(value)
    return data


def _prepare_dirs(plan: BlockPlan) -> None:
    plan.out_dir.mkdir(parents=True, exist_ok=False)
    for path in (plan.app_dir, plan.capture_dir, plan.readback_dir, plan.log_dir):
        path.mkdir()


def _read_outputs_script() -> Path:
    candidates = (
        HERE / "read_outputs.py",
        HERE.parent / "stage_reduction" / "hardware" / "20260925" / "read_outputs.py",
    )
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("read_outputs.py not found beside runner or stage_reduction hardware")


def _run_outputs(name: str, plan: BlockPlan, env: dict) -> int:
    script = _read_outputs_script()
    target = plan.readback_dir / f"{name}.jsonl"
    log = plan.log_dir / f"{name}.log"
    with target.open("w") as out, log.open("w") as err:
        result = subprocess.run(["python3", str(script)], env=env, stdout=out,
                                stderr=err, timeout=10, cwd=str(HERE))
    return result.returncode


def _start_capture(plan: BlockPlan):
    log = (plan.log_dir / "capture.log").open("w")
    command = [
        "dumpcap", "-q", "-i", CAPTURE_IFACE, "-f", CAPTURE_FILTER,
        "-a", f"duration:{plan.duration_s}", "-w", str(plan.pcap),
    ]
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    proc._defense4_log = log  # type: ignore[attr-defined]
    return proc


def _stop_capture(proc) -> int:
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    rc = proc.wait(timeout=10)
    log = getattr(proc, "_defense4_log", None)
    if log is not None:
        log.close()
    return rc


def _write_jsonl(path: Path, outcome) -> None:
    with path.open("a") as fh:
        fh.write(json.dumps(outcome.as_dict()) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _outcome_detail(outcome) -> str:
    problems = "; ".join(getattr(outcome, "problems", []) or [])
    return f"{outcome.outcome} ({problems or 'no detail'})"


def _run_reads(plan: BlockPlan, status: dict, connected=None) -> None:
    context = nullcontext(connected) if connected is not None else Session(RELAY_IP, RELAY_PORT, source_address=(SRC_IP, 0))
    with context as session:
        for i in range(plan.reads):
            seq = i & 0x0F
            outcome = session.transaction(
                operation="READ",
                frame=read_driver.build(seq),
                function=read_driver.FUNC_READ,
                app_seq=seq,
                budget_ms=plan.budget_ms,
            )
            _write_jsonl(plan.read_jsonl, outcome)
            status["read_completed"] = i + 1
            if not outcome.ok:
                raise RuntimeError(
                    f"READ transaction {i + 1} failed: {_outcome_detail(outcome)}"
                )
            time.sleep(plan.gap_ms / 1000.0)


def _run_sbo(plan: BlockPlan, status: dict, connected=None) -> None:
    context = nullcontext(connected) if connected is not None else Session(RELAY_IP, RELAY_PORT, source_address=(SRC_IP, 0))
    with context as session:
        seq = 0
        for i in range(plan.sbo):
            select_out, operate_out = sbo_driver.one_sbo(
                session, seq, seq + 1, POINTS, plan.budget_ms, False
            )
            seq = (seq + 2) & 0x0F
            _write_jsonl(plan.sbo_jsonl, select_out)
            _write_jsonl(plan.sbo_jsonl, operate_out)
            status["sbo_completed"] = i + 1
            if not select_out.ok:
                raise RuntimeError(
                    f"SBO transaction {i + 1} failed at SELECT: {_outcome_detail(select_out)}"
                )
            if not operate_out.ok:
                raise RuntimeError(
                    f"SBO transaction {i + 1} failed at OPERATE: {_outcome_detail(operate_out)}"
                )
            time.sleep(plan.gap_ms / 1000.0)


def run_block(plan: BlockPlan, *, dry_run: bool = False) -> int:
    _prepare_dirs(plan)
    (plan.out_dir / "runner.pid").write_text(str(os.getpid()) + "\n")
    status = {
        "label": plan.label,
        "read_count": plan.reads,
        "sbo_count": plan.sbo,
        "gap_ms": plan.gap_ms,
        "budget_ms": plan.budget_ms,
        "capture_duration_s": plan.duration_s,
        "dry_run": dry_run,
        "plan": _jsonable_plan(plan),
        "read_completed": 0,
        "sbo_completed": 0,
    }
    if dry_run:
        (plan.out_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        return 0

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ACTIVE_HARNESS), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    capture = _start_capture(plan)
    try:
        time.sleep(1.0)
        if capture.poll() is not None:
            raise RuntimeError("capture exited before traffic; inspect logs/capture.log")
        status["outputs_before"] = _run_outputs("outputs_before", plan, env)
        if status["outputs_before"] != 0:
            raise RuntimeError("output-state check failed before traffic")
        time.sleep(1.0)
        status["session_mode"] = "one TCP session for READ and SBO"
        with Session(RELAY_IP, RELAY_PORT, source_address=(SRC_IP, 0)) as connected:
            _run_reads(plan, status, connected)
            status["phase"] = "sbo"
            _run_sbo(plan, status, connected)
    except Exception as exc:
        status["error"] = str(exc)
        status["traceback"] = traceback.format_exc()
    finally:
        try:
            time.sleep(1.0)
            status["outputs_after"] = _run_outputs("outputs_after", plan, env)
        except Exception as exc:
            status["outputs_after_error"] = str(exc)
            status["outputs_after"] = 1
        try:
            # Allow libpcap's buffered packets, including final FIN/RST/status reads,
            # to reach dumpcap before asking it to flush and stop.
            time.sleep(1.0)
            status["capture_exit"] = _stop_capture(capture)
        except Exception as exc:
            status["capture_error"] = str(exc)
            status["capture_exit"] = 1
        (plan.out_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n")
    failure_keys = ("outputs_before", "outputs_after", "capture_exit")
    failed = "error" in status or any(status.get(key, 0) != 0 for key in failure_keys)
    return 1 if failed else 0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("label")
    ap.add_argument("--reads", type=int, default=100)
    ap.add_argument("--sbo", type=int, default=100)
    ap.add_argument("--gap-ms", type=float, default=400.0)
    ap.add_argument("--budget-ms", type=float, default=500.0)
    ap.add_argument("--root", type=Path, default=HERE)
    ap.add_argument("--dry-run", action="store_true")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if not args.dry_run and os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        print("REFUSED: DEFENSE4_HW_AUTHORIZED=1 is required", file=sys.stderr)
        return 2
    try:
        plan = build_plan(args.label, reads=args.reads, sbo=args.sbo,
                          gap_ms=args.gap_ms, budget_ms=args.budget_ms,
                          root=args.root)
        return run_block(plan, dry_run=args.dry_run)
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
