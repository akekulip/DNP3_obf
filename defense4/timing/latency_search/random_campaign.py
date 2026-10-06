#!/usr/bin/env python3
"""Guarded acquisition orchestrator for randomized latency policies.

The randomized run keeps every switch mutation narrow and auditable: install a
fixed timing configuration, install or clear ``tbl_random_deadlines``, start a
bounded digest listener before the DNP3 block, collect the block, fetch the
listener output, and join digests to the captured request records locally.  The
live entry point is guarded by ``DEFENSE4_HW_AUTHORIZED=1``; tests inject a
transport and never touch hardware.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import signal
import subprocess
import time
from typing import Any, Optional, Protocol, Sequence

try:
    from . import configure, remote
    from .randomized import bfrt_random_table, policy_planner, telemetry_join
except ImportError:  # direct script execution
    import configure  # type: ignore
    import remote  # type: ignore
    from randomized import bfrt_random_table, policy_planner, telemetry_join  # type: ignore

HERE = Path(__file__).resolve().parent
REMOTE = remote.REMOTE
SDE = "/home/decps/Downloads/bf-sde-9.13.2/install"
AUTH_ENV = "DEFENSE4_HW_AUTHORIZED"
RANDOMIZED = HERE / "randomized"
REMOTE_RANDOMIZED = REMOTE + "/randomized"
DEFAULT_SEED = 20260926
PROGRAM_NAME = "defense4_timing"


class Transport(Protocol):
    def deploy(self) -> None: ...
    def upload_switch(self, files: Sequence[tuple[Path, str]]) -> None: ...
    def upload_vision(self, files: Sequence[tuple[Path, str]]) -> None: ...
    def ssh_switch(self, command: str, **kwargs) -> str: ...
    def ssh_vision(self, command: str, **kwargs) -> str: ...
    def collect_block(self, label: str, output: Path) -> None: ...


class RemoteTransport:
    """Adapter around latency_search.remote with text-returning helpers."""

    def deploy(self) -> None:
        remote.deploy()
        self.upload_switch(_randomized_upload_files())

    def upload_switch(self, files: Sequence[tuple[Path, str]]) -> None:
        remote.upload(remote.SWITCH, files)

    def upload_vision(self, files: Sequence[tuple[Path, str]]) -> None:
        remote.upload(remote.VISION, files)

    def ssh_switch(self, command: str, **kwargs) -> str:
        result = remote.ssh(remote.SWITCH, command, stdout=subprocess.PIPE, text=True, **kwargs)
        return result.stdout

    def ssh_vision(self, command: str, **kwargs) -> str:
        result = remote.ssh(remote.VISION, command, stdout=subprocess.PIPE, text=True, **kwargs)
        return result.stdout

    def collect_block(self, label: str, output: Path) -> None:
        remote.collect(label, output)


@dataclass(frozen=True)
class BlockSpec:
    label: str
    kind: str
    replicate: int
    random_plan_path: Optional[Path]
    random_plan_remote: Optional[str]
    fixed_config_remote: str
    count: int
    digest_count: int


@dataclass(frozen=True)
class PreparedRun:
    run_dir: Path
    phase: str
    count: int
    repeats: int
    seed: int
    schedule: tuple[BlockSpec, ...]
    fixed_config_remote: str
    off_config_remote: str
    restore_config_remote: str
    identity_file: Path


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _require_authorized() -> None:
    if os.environ.get(AUTH_ENV) != "1":
        raise RuntimeError(f"refusing randomized hardware campaign without {AUTH_ENV}=1")


def _shell_env() -> str:
    return "DEFENSE4_HW_AUTHORIZED=1 PYTHONPATH=" + shlex.quote(SDE + "/lib/python3.8/site-packages/tofino")


def _randomized_upload_files() -> list[tuple[Path, str]]:
    names = ("bfrt_random_table.py", "policy_planner.py", "telemetry_listener.py", "telemetry_join.py")
    return [(RANDOMIZED / name, "randomized/" + name) for name in names]


def _base_upload_files(run: PreparedRun) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = [
        (run.run_dir / "fixed_config.json", "fixed_config.json"),
        (run.run_dir / "off_config.json", "off_config.json"),
        (run.run_dir / "restore_config.json", "restore_config.json"),
        (run.run_dir / "schedule.json", "schedule.json"),
        (run.run_dir / "provenance.json", "provenance.json"),
        (run.identity_file, "program_identity.json"),
    ]
    for block in run.schedule:
        if block.random_plan_path is not None and block.random_plan_remote is not None:
            files.append((block.random_plan_path, block.random_plan_remote))
    files.extend(_randomized_upload_files())
    return files


def build_schedule(
    *,
    random_plan_paths: Sequence[Path],
    repeats: int,
    seed: int,
    off_every: int = 2,
    off_name: str = "off_ref",
    phase: str = "pilot",
    count: int = 10,
    run_name: str = "random_run",
) -> tuple[BlockSpec, ...]:
    if not random_plan_paths:
        raise ValueError("at least one random plan JSON is required")
    if repeats <= 0:
        raise ValueError("repeats must be positive")
    if count <= 0:
        raise ValueError("count must be positive")
    if off_every <= 0:
        raise ValueError("off_every must be positive")
    rng = random.Random(seed)
    blocks: list[BlockSpec] = []
    for rep in range(repeats):
        shuffled = [Path(p) for p in random_plan_paths]
        rng.shuffle(shuffled)
        emitted_since_off = 0
        off_index = 0
        for plan in shuffled:
            label = f"{run_name}_r{rep:02d}_{plan.stem}"
            remote_name = f"plans/{plan.name}"
            blocks.append(
                BlockSpec(
                    label=label,
                    kind="random_policy",
                    replicate=rep,
                    random_plan_path=plan,
                    random_plan_remote=remote_name,
                    fixed_config_remote="fixed_config.json",
                    count=count,
                    digest_count=3 * count + 2,
                )
            )
            emitted_since_off += 1
            if emitted_since_off == off_every:
                blocks.append(_off_block(run_name, rep, off_name, off_index, count))
                off_index += 1
                emitted_since_off = 0
        if emitted_since_off:
            blocks.append(_off_block(run_name, rep, off_name, off_index, count))
    return tuple(blocks)


def _off_block(run_name: str, rep: int, off_name: str, off_index: int, count: int) -> BlockSpec:
    return BlockSpec(
        label=f"{run_name}_r{rep:02d}_{off_name}_{off_index:02d}",
        kind="off_reference",
        replicate=rep,
        random_plan_path=None,
        random_plan_remote=None,
        fixed_config_remote="off_config.json",
        count=count,
        digest_count=0,
    )


def _copy_plan(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())
    return dst


def validate_program_identity(identity: dict) -> None:
    program = identity.get("program") or identity.get("program_name")
    if program != PROGRAM_NAME:
        raise ValueError(f"program identity must name {PROGRAM_NAME}, got {program!r}")
    ingress = identity.get("ingress_stages", identity.get("ingress_stage_count"))
    egress = identity.get("egress_stages", identity.get("egress_stage_count", 0))
    if int(ingress) != 7 or int(egress) != 0:
        raise ValueError(f"program identity must report 7 ingress / 0 egress stages, got {ingress!r}/{egress!r}")
    hashes = ("source_sha256", "p4_source_sha256", "candidate_source_sha256", "program_sha256")
    if not any(identity.get(k) for k in hashes):
        raise ValueError("program identity must include a source/program sha256")


def _schedule_rows(schedule: Sequence[BlockSpec]) -> list[dict]:
    rows = []
    for block in schedule:
        row = asdict(block)
        row["random_plan_path"] = None if block.random_plan_path is None else str(block.random_plan_path)
        rows.append(row)
    return rows


def prepare_run(
    *,
    random_plan_paths: Sequence[Path],
    fixed_config_plan: Path,
    off_config_plan: Path,
    restore_config_plan: Path,
    identity_file: Path,
    output_root: Path = HERE / "evidence/randomized",
    phase: str,
    count: int,
    repeats: int,
    seed: int = DEFAULT_SEED,
    off_every: int = 2,
    transport: Optional[Transport] = None,
    timestamp: Optional[str] = None,
) -> PreparedRun:
    if phase not in ("pilot", "screen"):
        raise ValueError("phase must be pilot or screen")
    timestamp = timestamp or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_name = f"random_{phase}_{timestamp}"
    run_dir = Path(output_root) / run_name
    run_dir.mkdir(parents=True, exist_ok=False)
    local_plans = []
    for src in random_plan_paths:
        src = Path(src)
        policy_planner.load_plan(src)
        local_plans.append(_copy_plan(src, run_dir / "plans" / src.name))
    fixed_local = _copy_plan(Path(fixed_config_plan), run_dir / "fixed_config.json")
    off_local = _copy_plan(Path(off_config_plan), run_dir / "off_config.json")
    restore_local = _copy_plan(Path(restore_config_plan), run_dir / "restore_config.json")
    identity_local = _copy_plan(Path(identity_file), run_dir / "program_identity.json")
    validate_program_identity(_load_json(identity_local))
    schedule = build_schedule(
        random_plan_paths=local_plans,
        repeats=repeats,
        seed=seed,
        off_every=off_every,
        phase=phase,
        count=count,
        run_name=run_name,
    )
    run = PreparedRun(
        run_dir=run_dir,
        phase=phase,
        count=count,
        repeats=repeats,
        seed=seed,
        schedule=schedule,
        fixed_config_remote="fixed_config.json",
        off_config_remote="off_config.json",
        restore_config_remote="restore_config.json",
        identity_file=identity_local,
    )
    write_json(
        run_dir / "schedule.json",
        {
            "phase": phase,
            "seed": seed,
            "count_per_operation": count,
            "primary_requests_per_block": 3 * count,
            "status_requests_per_block": 2,
            "digest_records_per_random_block": 3 * count + 2,
            "repeats": repeats,
            "off_every": off_every,
            "schedule": _schedule_rows(schedule),
        },
    )
    source_files = [
        HERE / "random_campaign.py",
        HERE / "run_block.py",
        HERE / "stop_block.py",
        HERE / "configure.py",
        HERE / "policy.py",
        HERE / "remote.py",
        RANDOMIZED / "policy_planner.py",
        RANDOMIZED / "bfrt_random_table.py",
        RANDOMIZED / "telemetry_listener.py",
        RANDOMIZED / "telemetry_join.py",
    ]
    input_hashes = {
        "fixed_config.json": sha256_file(fixed_local),
        "off_config.json": sha256_file(off_local),
        "restore_config.json": sha256_file(restore_local),
    }
    for p in local_plans:
        input_hashes["plans/" + p.name] = sha256_file(p)
    write_json(
        run_dir / "provenance.json",
        {
            "program_identity": _load_json(identity_local),
            "source_sha256": {p.name: sha256_file(p) for p in source_files if p.exists()},
            "input_sha256": input_hashes,
        },
    )
    if transport is None:
        _require_authorized()
        transport = RemoteTransport()
    transport.deploy()
    files = _base_upload_files(run)
    transport.upload_switch(files)
    transport.upload_vision([(HERE / name, name) for name in ("run_block.py", "stop_block.py") if (HERE / name).exists()])
    return run


def _remote(path: str) -> str:
    return REMOTE + "/" + path


def _apply_fixed_config_command(remote_plan: str, readback: str) -> str:
    args = [
        "python3",
        _remote("configure.py"),
        "apply",
        "--policy",
        _remote(remote_plan),
        "--control-dir",
        _remote("control"),
        "--readback-output",
        _remote(readback),
    ]
    return _shell_env() + " " + shlex.join(args)


def _apply_random_command(remote_plan: str, readback: str) -> str:
    args = ["python3", _remote("randomized/bfrt_random_table.py"), "apply-plan", "--plan", _remote(remote_plan), "--output", _remote(readback)]
    return _shell_env() + " " + shlex.join(args)


def _clear_random_command(readback: str) -> str:
    args = ["python3", _remote("randomized/bfrt_random_table.py"), "clear", "--output", _remote(readback)]
    return _shell_env() + " " + shlex.join(args)


def _start_listener_command(label: str, max_digests: int) -> str:
    directory = _remote(label)
    script = _remote("randomized/telemetry_listener.py")
    args = ["python3", script, "--max-digests", str(max_digests)]
    source = (
        "import json, os, pathlib, subprocess\n"
        f"directory=pathlib.Path({directory!r})\n"
        "directory.mkdir(parents=True, exist_ok=False)\n"
        "env=dict(os.environ)\n"
        f"env['PYTHONPATH']={SDE + '/lib/python3.8/site-packages/tofino'!r}\n"
        "with (directory/'digests.jsonl').open('w') as out, (directory/'digest_listener.log').open('w') as err:\n"
        f"    child=subprocess.Popen({args!r}, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, start_new_session=True)\n"
        "    start=pathlib.Path('/proc/%d/stat'%child.pid).read_text().split()[21]\n"
        f"    owner={{'pid':child.pid,'start':start,'script':{script!r}}}\n"
        "    (directory/'digest_listener.pid').write_text(json.dumps(owner))\n"
    )
    return "python3 -c " + shlex.quote(source)


def _wait_listener_ready_command(label: str, timeout_s: int = 10) -> str:
    out = _remote(label + "/digests.jsonl")
    quoted = shlex.quote(out)
    return (
        "python3 -c "
        + shlex.quote(
            "import json, pathlib, sys, time\n"
            f"path=pathlib.Path({out!r})\n"
            f"deadline=time.time()+{int(timeout_s)}\n"
            "while time.time()<deadline:\n"
            "    if path.exists():\n"
            "        for line in path.read_text(errors='replace').splitlines():\n"
            "            try:\n"
            "                row=json.loads(line)\n"
            "            except Exception:\n"
            "                continue\n"
            "            if row.get('event')=='ready':\n"
            "                sys.exit(0)\n"
            "    time.sleep(0.1)\n"
            "raise SystemExit('digest listener did not report ready')\n"
        )
        + " # "
        + quoted
    )


def _wait_listener_complete_command(label: str, expected_digests: int, timeout_s: int = 30) -> str:
    out = _remote(label + "/digests.jsonl")
    return "python3 -c " + shlex.quote(
        "import json, pathlib, sys, time\n"
        f"path=pathlib.Path({out!r})\n"
        f"want={int(expected_digests)}\n"
        f"deadline=time.time()+{int(timeout_s)}\n"
        "while time.time()<deadline:\n"
        "    count=0\n"
        "    if path.exists():\n"
        "        for line in path.read_text(errors='replace').splitlines():\n"
        "            try:\n"
        "                row=json.loads(line)\n"
        "            except Exception:\n"
        "                continue\n"
        "            if row.get('event')!='ready':\n"
        "                count += 1\n"
        "        if count >= want:\n"
        "            sys.exit(0)\n"
        "    time.sleep(0.1)\n"
        "raise SystemExit(f'digest listener recorded {count} of {want} digests')\n"
    )


def _listener_owner_source(label: str) -> str:
    return (
        "import json, os, pathlib, signal, time\n"
        f"owner_path=pathlib.Path({_remote(label + '/digest_listener.pid')!r})\n"
        "if not owner_path.exists(): raise SystemExit(0)\n"
        "owner=json.loads(owner_path.read_text()); pid=owner['pid']\n"
        "proc=pathlib.Path('/proc')/str(pid)\n"
        "def active():\n"
        "    try:\n"
        "        fields=(proc/'stat').read_text().split()\n"
        "        if fields[2]=='Z': return False\n"
        "        words=(proc/'cmdline').read_bytes().split(bytes([0]))\n"
        "    except FileNotFoundError: return False\n"
        "    if fields[21]!=owner['start']:\n"
        "        raise RuntimeError('listener PID ownership mismatch')\n"
        "    if words==[b'']: return False\n"
        "    if owner['script'].encode() not in words:\n"
        "        raise RuntimeError('listener PID ownership mismatch')\n"
        "    return True\n"
    )


def _wait_listener_exit_command(label: str, timeout_s: int = 10) -> str:
    source = _listener_owner_source(label) + (
        f"deadline=time.monotonic()+{timeout_s}\n"
        "while active() and time.monotonic()<deadline: time.sleep(.1)\n"
        "if active(): raise RuntimeError('digest listener pid still running')\n"
    )
    return "python3 -c " + shlex.quote(source)


def _stop_listener_command(label: str, timeout_s: int = 5) -> str:
    source = _listener_owner_source(label) + (
        "if active(): os.kill(pid, signal.SIGTERM)\n"
        f"deadline=time.monotonic()+{timeout_s}\n"
        "while active() and time.monotonic()<deadline: time.sleep(.1)\n"
        "if active(): os.kill(pid, signal.SIGKILL)\n"
        "deadline=time.monotonic()+3\n"
        "while active() and time.monotonic()<deadline: time.sleep(.1)\n"
        "if active(): raise RuntimeError('cannot stop owned digest listener')\n"
    )
    return "python3 -c " + shlex.quote(source)


def _cat_remote_digest_command(label: str) -> str:
    return "cat " + shlex.quote(_remote(label + "/digests.jsonl"))


def _cat_remote_file_command(remote_name: str) -> str:
    return "cat " + shlex.quote(_remote(remote_name))


def _run_block_command(label: str, count: int) -> str:
    args = ["python3", _remote("run_block.py"), label, "--reads", str(count), "--sbo", str(count)]
    return AUTH_ENV + "=1 " + shlex.join(args)


def _json_from_stdout(stdout: str, context: str) -> dict:
    text = stdout.strip()
    if not text:
        raise RuntimeError(f"{context} produced no JSON readback")
    decoder = json.JSONDecoder()
    idx = 0
    last = None
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        try:
            value, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            idx += 1
            continue
        if isinstance(value, dict):
            last = value
        idx = end
    if last is None:
        raise RuntimeError(f"{context} did not contain a JSON object")
    return last


def _normalise_fixed_entry(entry: dict) -> dict:
    return {
        "low": int(entry["low"]),
        "high": int(entry["high"]),
        "j_ticks": int(entry["j_ticks"]),
        "dst_port": int(entry.get("dst_port", configure.policy.DEFAULT_RELAY_DST_PORT)),
        "priority": int(entry["priority"]),
    }


def verify_fixed_readback(plan_doc: dict, readback_doc: dict) -> None:
    expected_entries = sorted((_normalise_fixed_entry(e) for e in plan_doc["codebook_entries"]), key=lambda e: (e["priority"], e["low"], e["high"]))
    got_entries = sorted((_normalise_fixed_entry(e) for e in readback_doc.get("codebook", ())), key=lambda e: (e["priority"], e["low"], e["high"]))
    if got_entries != expected_entries:
        raise RuntimeError("fixed timing codebook readback does not match requested plan")
    expected_params = plan_doc.get("params_default")
    if expected_params is not None:
        got = readback_doc.get("tbl_params") or {}
        for key in ("mode", "d_ticks", "da_dr", "budget", "read_len"):
            if int(got.get(key, -1)) != int(expected_params[key]):
                raise RuntimeError(f"tbl_params readback mismatch for {key}: got {got.get(key)!r} want {expected_params[key]!r}")
    expected_bor = plan_doc.get("bor_params_default")
    if expected_bor is not None:
        got = readback_doc.get("tbl_bor_params") or {}
        for key in ("a_ticks", "r_ticks", "anchor_req"):
            if int(got.get(key, -1)) != int(expected_bor[key]):
                raise RuntimeError(f"tbl_bor_params readback mismatch for {key}: got {got.get(key)!r} want {expected_bor[key]!r}")


def _normalise_random_entry(entry: dict) -> dict:
    return {
        "low": int(entry["low"]),
        "high": int(entry["high"]),
        "priority": int(entry["priority"]),
        "d_ticks": int(entry["d_ticks"]),
        "da_dr_ticks": int(entry["da_dr_ticks"]),
        "op_a_ticks": int(entry["op_a_ticks"]),
        "op_r_ticks": int(entry["op_r_ticks"]),
        "action_name": str(entry.get("action_name", policy_planner.ACTION_NAME)),
    }


def verify_random_readback(plan_doc: dict, readback_doc: dict) -> None:
    if readback_doc.get("program") not in (None, PROGRAM_NAME):
        raise RuntimeError(f"random table readback program mismatch: {readback_doc.get('program')!r}")
    expected = sorted((_normalise_random_entry(e) for e in plan_doc["entries"]), key=lambda e: (e["priority"], e["low"], e["high"]))
    got = sorted((_normalise_random_entry(e) for e in readback_doc.get("entries", ())), key=lambda e: (e["priority"], e["low"], e["high"]))
    if int(readback_doc.get("entry_count", -1)) != len(expected):
        raise RuntimeError("random table readback entry_count does not match requested plan")
    if got != expected:
        raise RuntimeError("random table readback does not match requested plan")


def verify_clear_readback(readback_doc: dict) -> None:
    if readback_doc.get("cleared") is not True:
        raise RuntimeError("random table clear did not report cleared=true")
    if readback_doc.get("readback") != []:
        raise RuntimeError("random table clear readback is not empty")
    if str(readback_doc.get('default_action')).split('.')[-1] != 'NoAction':
        raise RuntimeError('random table default is not verified NoAction')


def _local_fixed_plan(run: PreparedRun, remote_name: str) -> Path:
    mapping = {
        run.fixed_config_remote: run.run_dir / "fixed_config.json",
        run.off_config_remote: run.run_dir / "off_config.json",
        run.restore_config_remote: run.run_dir / "restore_config.json",
    }
    if remote_name not in mapping:
        raise KeyError(f"unknown fixed config remote path {remote_name!r}")
    return mapping[remote_name]


def _local_random_plan(run: PreparedRun, remote_name: str) -> Path:
    if not remote_name.startswith("plans/"):
        raise KeyError(f"unexpected random plan remote path {remote_name!r}")
    return run.run_dir / remote_name


def _fetch_json_file(transport: Transport, remote_name: str, context: str) -> dict:
    stdout = transport.ssh_switch(_cat_remote_file_command(remote_name), timeout=20)
    return _json_from_stdout(stdout, context)


def _apply_and_verify_fixed(transport: Transport, run: PreparedRun, remote_plan: str, readback_name: str) -> dict:
    transport.ssh_switch(_apply_fixed_config_command(remote_plan, readback_name), timeout=60)
    readback = _fetch_json_file(transport, readback_name, "fixed timing readback file")
    verify_fixed_readback(_load_json(_local_fixed_plan(run, remote_plan)), readback)
    write_json(run.run_dir / readback_name, readback)
    return readback


def _apply_and_verify_random(transport: Transport, run: PreparedRun, remote_plan: str, readback_name: str) -> dict:
    transport.ssh_switch(_apply_random_command(remote_plan, readback_name), timeout=60)
    readback = _fetch_json_file(transport, readback_name, "random table readback file")
    verify_random_readback(_load_json(_local_random_plan(run, remote_plan)), readback)
    write_json(run.run_dir / readback_name, readback)
    return readback


def _clear_and_verify_random(transport: Transport, readback_name: str) -> dict:
    transport.ssh_switch(_clear_random_command(readback_name), timeout=60)
    readback = _fetch_json_file(transport, readback_name, "random table clear readback file")
    verify_clear_readback(readback)
    return readback


def filter_digest_rows(text: str) -> list[dict]:
    rows: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("event") == "ready":
            continue
        rows.append(row)
    return rows


def extract_request_rows(pcap_path: Path) -> list[dict]:
    try:
        from . import analysis
    except ImportError:  # direct script execution
        import analysis  # type: ignore

    rows = []
    for pkt in analysis._tcp_packets(Path(pcap_path)):
        if pkt.from_master and pkt.dnp3_func in analysis.FUNC_BY_NAME.values():
            rows.append(
                {
                    "t_ns": pkt.t_ns,
                    "tcp_src_port": pkt.sport,
                    "tcp_seq": pkt.seq,
                    "dnp3_func": pkt.dnp3_func,
                    "app_seq": pkt.app_seq,
                }
            )
    return rows


def _find_pcap(block_dir: Path) -> Path:
    candidates = []
    for pattern in ("traffic.pcap", "traffic.pcapng", "traffic.pcap*", "raw_pcaps/*.pcap", "raw_pcaps/*.pcapng", "raw_pcaps/*.pcap*"):
        candidates.extend(sorted(block_dir.glob(pattern)))
    files = sorted({p for p in candidates if p.is_file()})
    if len(files) != 1:
        raise FileNotFoundError(f"expected one capture pcap under {block_dir}, found {len(files)}")
    return files[0]


def join_random_block_local(block_dir: Path, digest_text: str, plan_path: Path) -> dict:
    block_dir = Path(block_dir)
    request_path = block_dir / "requests.jsonl"
    requests = extract_request_rows(_find_pcap(block_dir))
    _write_jsonl(request_path, requests)
    digests = filter_digest_rows(digest_text)
    digest_path = block_dir / "digests.jsonl"
    _write_jsonl(digest_path, digests)
    result = telemetry_join.join(requests, digests, _load_json(Path(plan_path)))
    doc = telemetry_join.result_to_dict(result)
    write_json(block_dir / "joined_random_deadlines.json", doc)
    bad = [k for k, value in doc["counts"].items() if k != "joined" and value]
    if bad:
        raise RuntimeError(f"random digest join has unmatched or invalid rows: {bad}")
    return doc


def run_block(block: BlockSpec, run: PreparedRun, *, transport: Optional[Transport] = None) -> dict:
    if transport is None:
        _require_authorized()
        transport = RemoteTransport()
    fixed_readback = f"{block.label}_fixed_readback.json"
    random_readback = f"{block.label}_random_readback.json"
    fixed_doc = _apply_and_verify_fixed(transport, run, block.fixed_config_remote, fixed_readback)
    random_doc = None
    joined_doc = None
    local_block_root = run.run_dir / "collected_blocks"
    listener_started = False
    traffic_started = False
    traffic_stopped = True
    try:
        if block.kind == "random_policy":
            if not block.random_plan_remote:
                raise ValueError("random block missing random plan")
            random_doc = _apply_and_verify_random(transport, run, block.random_plan_remote, random_readback)
            listener_started = True
            transport.ssh_switch(_start_listener_command(block.label, block.digest_count), timeout=20)
            transport.ssh_switch(_wait_listener_ready_command(block.label), timeout=20)
        else:
            random_doc = _clear_and_verify_random(transport, random_readback)
            write_json(run.run_dir / random_readback, random_doc)
        traffic_started = True
        traffic_stopped = False
        transport.ssh_vision(_run_block_command(block.label, block.count), timeout=block.count * 2.4 + 90)
        traffic_stopped = True
        if block.kind == "random_policy":
            transport.ssh_switch(_wait_listener_complete_command(block.label, block.digest_count), timeout=max(35, block.count * 3))
            transport.ssh_switch(_wait_listener_exit_command(block.label), timeout=20)
    finally:
        # Never restore policy while a timed-out remote traffic process can remain active.
        if not traffic_stopped:
            try:
                transport.ssh_vision(shlex.join(['python3', _remote('stop_block.py'), block.label]), timeout=30)
                traffic_stopped = True
            except BaseException as exc:
                write_json(run.run_dir / 'traffic_stop_unconfirmed.json', {'block':block.label,'error':repr(exc)})
                raise
        if listener_started:
            transport.ssh_switch(_stop_listener_command(block.label), timeout=20)
            digest_text = transport.ssh_switch(_cat_remote_digest_command(block.label), timeout=20)
            (run.run_dir / (block.label + '_listener_raw.jsonl')).write_text(digest_text)
            listener_log = transport.ssh_switch(_cat_remote_file_command(block.label + '/digest_listener.log'), timeout=20)
            (run.run_dir / (block.label + '_listener.log')).write_text(listener_log)
        if traffic_started:
            transport.collect_block(block.label, local_block_root)
    if block.kind == "random_policy":
        joined_doc = join_random_block_local(local_block_root / block.label, digest_text, _local_random_plan(run, block.random_plan_remote or ""))
        if joined_doc['counts']['joined'] != block.digest_count:
            raise RuntimeError('captured request/digest count differs from planned block')
    block_doc = {
        "label": block.label,
        "kind": block.kind,
        "replicate": block.replicate,
        "count_per_operation": block.count,
        "primary_requests": 3 * block.count,
        "status_requests": 2,
        "fixed_readback": fixed_readback,
        "random_readback": random_readback,
        "random_plan": block.random_plan_remote,
        "local_block_dir": str(local_block_root / block.label),
        "fixed_readback_verified": True,
        "random_readback_verified": True,
        "join_counts": None if joined_doc is None else joined_doc["counts"],
        "fixed_readback_summary": {"codebook_entries": len(fixed_doc.get("codebook", []))},
        "random_readback_summary": random_doc,
    }
    write_json(run.run_dir / "blocks" / (block.label + ".json"), block_doc)
    return block_doc


def _restore(run: PreparedRun, transport: Transport) -> None:
    if (run.run_dir / 'traffic_stop_unconfirmed.json').exists():
        raise RuntimeError('policy restoration withheld: traffic stop unconfirmed')
    cleared = _clear_and_verify_random(transport, "restored_random_table.json")
    write_json(run.run_dir / 'restored_random_table.json', cleared)
    _apply_and_verify_fixed(transport, run, run.restore_config_remote, "restored_fixed_config.json")


def run_campaign(
    *,
    random_plan_paths: Sequence[Path],
    fixed_config_plan: Path,
    off_config_plan: Path,
    restore_config_plan: Path,
    identity_file: Path,
    output_root: Path = HERE / "evidence/randomized",
    phase: str,
    count: Optional[int] = None,
    repeats: Optional[int] = None,
    seed: int = DEFAULT_SEED,
    off_every: int = 2,
    transport: Optional[Transport] = None,
    timestamp: Optional[str] = None,
) -> PreparedRun:
    _require_authorized()
    count = count if count is not None else (10 if phase == "pilot" else 100)
    repeats = repeats if repeats is not None else 5
    transport = transport or RemoteTransport()
    run = prepare_run(
        random_plan_paths=random_plan_paths,
        fixed_config_plan=fixed_config_plan,
        off_config_plan=off_config_plan,
        restore_config_plan=restore_config_plan,
        identity_file=identity_file,
        output_root=output_root,
        phase=phase,
        count=count,
        repeats=repeats,
        seed=seed,
        off_every=off_every,
        transport=transport,
        timestamp=timestamp,
    )
    completed: list[dict] = []
    failed = None
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Campaign interrupted; stopping traffic and restoring configuration')
    old_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        for block in run.schedule:
            print('START', block.label, flush=True)
            completed.append(run_block(block, run, transport=transport))
            write_json(run.run_dir / "progress.json", completed)
            print('CAPTURED', block.label, flush=True)
    except BaseException as exc:
        failed = repr(exc)
        write_json(run.run_dir / "failure.json", {"error": failed, "completed_blocks": len(completed)})
        raise
    finally:
        try:
            _restore(run, transport)
            write_json(run.run_dir / "final_status.json", {"completed_blocks": len(completed), "error": failed,
                                                           "configuration_restored": True})
        except BaseException as exc:
            write_json(run.run_dir / 'restoration_failure.json', {'error':repr(exc)})
            raise
        finally:
            signal.signal(signal.SIGTERM, old_handler)
    return run


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--phase", choices=("pilot", "screen"), required=True)
    ap.add_argument("--random-plan", action="append", required=True, dest="random_plans")
    ap.add_argument("--fixed-config-plan", required=True)
    ap.add_argument("--off-config-plan", required=True)
    ap.add_argument("--restore-config-plan", required=True)
    ap.add_argument("--identity-file", required=True)
    ap.add_argument("--output-root", default=str(HERE / "evidence/randomized"))
    ap.add_argument("--count", type=int)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--off-every", type=int, default=2)
    args = ap.parse_args(argv)
    run_campaign(
        random_plan_paths=[Path(p) for p in args.random_plans],
        fixed_config_plan=Path(args.fixed_config_plan),
        off_config_plan=Path(args.off_config_plan),
        restore_config_plan=Path(args.restore_config_plan),
        identity_file=Path(args.identity_file),
        output_root=Path(args.output_root),
        phase=args.phase,
        count=args.count,
        repeats=args.repeats,
        seed=args.seed,
        off_every=args.off_every,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
