#!/usr/bin/env python3
"""Local asic-model smoke probe for the stage-reduction artifacts.

This is intentionally conservative: it never touches physical interfaces,
does not create veth devices, and writes run artifacts under /tmp/dnp3-model-*.
It validates the generated P4 artifacts, emits DNP3 packet vectors with the
shared wire helper, and then tries the smallest local tofino-model and
bf_switchd probes that can run without hardware access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[4]
WIRE_DIR = REPO_ROOT / "defense4" / "timing" / "implementation" / "harness"
sys.path.insert(0, str(WIRE_DIR))

import dnp3_wire  # noqa: E402


DEFAULT_SDE = Path("/home/philip/bf-sde-9.13.1")
DEFAULT_ARTIFACTS = {
    "baseline": Path("/tmp/dnp3-stage-reduction/repro_baseline/out"),
    "candidate": Path("/tmp/dnp3-stage-reduction/clean_final/out"),
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sde_env(sde: Path) -> dict[str, str]:
    install = sde / "install"
    env = os.environ.copy()
    env["SDE"] = str(sde)
    env["SDE_INSTALL"] = str(install)
    env["PATH"] = f"{install / 'bin'}:{env.get('PATH', '')}"
    lib_parts = [str(install / "lib"), "/usr/local/lib", env.get("LD_LIBRARY_PATH", "")]
    environment = install / "share" / "environment"
    if environment.exists():
        for line in environment.read_text(errors="replace").splitlines():
            if line.startswith("SDE_DEPENDENCIES="):
                dep = line.split("=", 1)[1].strip()
                dep_path = (install / dep).resolve() if not dep.startswith("/") else Path(dep)
                lib_parts.insert(0, str(dep_path / "lib"))
                break
    env["LD_LIBRARY_PATH"] = ":".join(p for p in lib_parts if p)
    return env


def run_cmd(
    argv: list[str],
    *,
    env: dict[str, str] | None,
    timeout_s: int,
    stdout_path: Path,
) -> dict[str, Any]:
    started = time.time()
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w") as out:
        proc = subprocess.run(
            argv,
            stdout=out,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            cwd=stdout_path.parent,
            timeout=timeout_s,
            check=False,
        )
        status = proc.returncode
    return {
        "argv": argv,
        "status": status,
        "timeout_s": timeout_s,
        "elapsed_s": round(time.time() - started, 3),
        "log": str(stdout_path),
    }


def run_cmd_timeout_ok(
    argv: list[str],
    *,
    env: dict[str, str] | None,
    timeout_s: int,
    stdout_path: Path,
) -> dict[str, Any]:
    started = time.time()
    status: int | str
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w") as out:
        try:
            proc = subprocess.run(
                argv,
                stdout=out,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                cwd=stdout_path.parent,
                timeout=timeout_s,
                check=False,
            )
            status = proc.returncode
        except subprocess.TimeoutExpired:
            status = "timeout"
    return {
        "argv": argv,
        "status": status,
        "timeout_s": timeout_s,
        "elapsed_s": round(time.time() - started, 3),
        "log": str(stdout_path),
    }


def artifact_summary(label: str, out_dir: Path) -> dict[str, Any]:
    required = [
        "manifest.json",
        "bfrt.json",
        "defense4_timing.conf",
        "pipe/context.json",
        "pipe/tofino.bin",
    ]
    files: dict[str, Any] = {}
    missing: list[str] = []
    for rel in required:
        path = out_dir / rel
        if not path.exists():
            missing.append(rel)
            continue
        files[rel] = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    program_name = None
    compiler_version = None
    source_p4 = out_dir.parent / "defense4_timing.p4"
    source_sha256 = sha256_file(source_p4) if source_p4.exists() else None
    if (out_dir / "manifest.json").exists():
        manifest = json.loads((out_dir / "manifest.json").read_text())
        compiler_version = manifest.get("compiler_version")
        programs = manifest.get("programs") or []
        if programs:
            program_name = programs[0].get("program_name")

    return {
        "label": label,
        "out_dir": str(out_dir),
        "ok": not missing,
        "missing": missing,
        "program_name": program_name,
        "compiler_version": compiler_version,
        "source_p4": str(source_p4) if source_p4.exists() else None,
        "source_sha256": source_sha256,
        "files": files,
    }


def write_packet_vectors(run_dir: Path) -> dict[str, Any]:
    vectors_dir = run_dir / "vectors"
    vectors_dir.mkdir(parents=True, exist_ok=True)
    vectors = {
        "select": dnp3_wire.build_request(dnp3_wire.FUNC_SELECT, 0),
        "operate": dnp3_wire.build_request(dnp3_wire.FUNC_OPERATE, 0),
        "echo": dnp3_wire.build_echo(req_app_seq=0, transport_seq=0x20),
    }
    summary: dict[str, Any] = {}
    for name, payload in vectors.items():
        path = vectors_dir / f"{name}.bin"
        path.write_bytes(payload)
        summary[name] = {
            "path": str(path),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "hex": payload.hex(),
        }
    parsed = dnp3_wire.parse_request(next(dnp3_wire.deframe(vectors["select"]))[1])
    summary["select_parse"] = parsed
    summary["echo_matches_sel_reference"] = (
        vectors["echo"].hex()
        == "05642644010000002f77e0c08184000c011702000101c8000000f05a"
        "0000000000010101c80000000000000097da00ffff"
    )
    return summary


def classify_model_log(log_path: Path, status: int | str) -> dict[str, Any]:
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    blocker = None
    unclassified_nonzero = False
    if "Unable to drop privileges to purely CAP_NET_RAW" in text:
        blocker = "tofino-model requires CAP_NET_RAW/root in this environment"
    elif "sudo: a password is required" in text:
        blocker = "SDE wrapper requires passwordless sudo"
    elif status == "timeout":
        blocker = None
    elif isinstance(status, int) and status != 0:
        unclassified_nonzero = True
    return {
        "started": status == "timeout",
        "process_start_only": status == "timeout",
        "blocker": blocker,
        "unclassified_nonzero": unclassified_nonzero,
        "first_lines": text.splitlines()[:20],
    }


def classify_switchd_log(log_path: Path, status: int | str) -> dict[str, Any]:
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    return {
        "parsed_p4_profile": "P4 profile for dev_id 0" in text,
        "saw_program": "p4_name: defense4_timing" in text,
        "process_start_only": True,
        "status_note": "timeout means bf_switchd stayed alive until the harness stopped it",
        "first_lines": text.splitlines()[:30],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sde", type=Path, default=DEFAULT_SDE)
    parser.add_argument("--baseline-out", type=Path, default=DEFAULT_ARTIFACTS["baseline"])
    parser.add_argument("--candidate-out", type=Path, default=DEFAULT_ARTIFACTS["candidate"])
    parser.add_argument("--timeout-s", type=int, default=8)
    args = parser.parse_args()

    run_dir = Path(f"/tmp/dnp3-model-{int(time.time())}-{os.getpid()}")
    run_dir.mkdir(parents=True, exist_ok=False)
    logs_dir = run_dir / "logs"
    logs_dir.mkdir()

    env = sde_env(args.sde)
    report: dict[str, Any] = {
        "run_dir": str(run_dir),
        "sde": str(args.sde),
        "sde_install": str(args.sde / "install"),
        "packets": write_packet_vectors(run_dir),
        "artifacts": {},
        "probes": {},
        "limitations": [
            "No physical interfaces, hardware switch, or live network traffic used.",
            "This smoke harness does not prove real queue timing.",
            "A successful process-start probe is config/startup evidence only, not packet validation.",
            "Packet I/O through asic-model requires a successfully running tofino-model plus veth/PTF plumbing.",
        ],
    }

    sudo_probe = run_cmd(
        ["sudo", "-n", "true"],
        env=env,
        timeout_s=3,
        stdout_path=logs_dir / "sudo_probe.log",
    )
    report["probes"]["passwordless_sudo"] = sudo_probe

    for label, out_dir in {"baseline": args.baseline_out, "candidate": args.candidate_out}.items():
        artifact = artifact_summary(label, out_dir)
        report["artifacts"][label] = artifact
        conf = out_dir / "defense4_timing.conf"
        if not artifact["ok"]:
            continue

        model_log = logs_dir / f"{label}_tofino_model.log"
        model_run_dir = logs_dir / f"{label}_model_logs"
        model_run_dir.mkdir(parents=True, exist_ok=True)
        model_result = run_cmd_timeout_ok(
            [
                str(args.sde / "install" / "bin" / "tofino-model"),
                "--no-port-monitor",
                "-d",
                "1",
                "-k",
                "1",
                "-f",
                "None",
                "--p4-target-config",
                str(conf),
                "--install-dir",
                str(args.sde / "install"),
                "--chip-type",
                "2",
                "--log-dir",
                str(model_run_dir),
                "--pkt-log-len",
                "256",
            ],
            env=env,
            timeout_s=args.timeout_s,
            stdout_path=model_log,
        )
        model_result["classification"] = classify_model_log(model_log, model_result["status"])
        report["probes"][f"{label}_tofino_model"] = model_result

        switchd_log = logs_dir / f"{label}_bf_switchd.log"
        switchd_result = run_cmd_timeout_ok(
            [
                str(args.sde / "install" / "bin" / "bf_switchd"),
                "--conf-file",
                str(conf),
                "--install-dir",
                str(args.sde / "install"),
                "--background",
                "--skip-port-add",
            ],
            env=env,
            timeout_s=args.timeout_s,
            stdout_path=switchd_log,
        )
        switchd_result["classification"] = classify_switchd_log(
            switchd_log, switchd_result["status"]
        )
        report["probes"][f"{label}_bf_switchd_config"] = switchd_result

    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    stable_report = Path(__file__).resolve().parent / "latest_model_smoke_report.json"
    stable_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    all_artifacts_ok = all(a["ok"] for a in report["artifacts"].values())
    model_blockers = [
        p["classification"]["blocker"]
        for key, p in report["probes"].items()
        if key.endswith("_tofino_model") and p.get("classification", {}).get("blocker")
    ]
    unclassified_model_failures = [
        key
        for key, p in report["probes"].items()
        if key.endswith("_tofino_model")
        and p.get("classification", {}).get("unclassified_nonzero")
    ]

    print(f"report={report_path}")
    print(f"stable_report={stable_report}")
    print(f"artifacts_ok={all_artifacts_ok}")
    print(f"model_blockers={model_blockers}")
    print(f"unclassified_model_failures={unclassified_model_failures}")
    print("packet_vectors=generated")
    if unclassified_model_failures:
        return 3
    return 2 if model_blockers else (0 if all_artifacts_ok else 1)


if __name__ == "__main__":
    raise SystemExit(main())
