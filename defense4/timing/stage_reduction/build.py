#!/usr/bin/env python3
"""Compile one immutable candidate snapshot and retain auditable resource evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def final_allocation(summary):
    """The compiler appends placement retries; only the final one is emitted."""
    final = summary.rsplit("Table allocation done", 1)[-1]
    report = {}
    for name, pattern in {
        "ingress_stages": r"Number of stages for ingress table allocation: (\d+)",
        "egress_stages": r"Number of stages for egress table allocation: (\d+)",
        "critical_path": r"Critical path length through the table dependency graph: (\d+)",
        "tables": r"Number of tables allocated: (\d+)",
    }.items():
        match = re.search(pattern, final)
        if match is None:
            raise ValueError(f"Missing final compiler evidence: {name}")
        report[name] = int(match[1])
    return report


def context_stages(context):
    def stages(node):
        if isinstance(node, dict):
            if "stage_number" in node:
                yield node["stage_number"]
            for value in node.values():
                yield from stages(value)
        elif isinstance(node, list):
            for value in node:
                yield from stages(value)
    return {f"{gress}_stages": 1 + max(
        (n for t in context["tables"] if t.get("direction") == gress
         for n in stages(t)), default=-1)
        for gress in ("ingress", "egress")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--compiler", default="/home/philip/bf-sde-9.13.1/install/bin/bf-p4c")
    parser.add_argument("--max-ingress", type=int)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / "defense4_timing.p4"
    shutil.copyfile(args.source, snapshot)
    command = [args.compiler, "--target", "tofino", "--arch", "tna", "-g", "-DU_BOR",
               "-o", str(output / "out"), str(snapshot)]
    report = {"source": str(args.source.resolve()),
              "source_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
              "compiler": subprocess.check_output([args.compiler, "--version"], text=True).strip(),
              "command": command}
    start = time.monotonic()
    with (output / "compile.log").open("w") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    report.update(exit_code=result.returncode, elapsed_seconds=round(time.monotonic() - start, 3))
    if result.returncode == 0:
        logs = output / "out" / "pipe" / "logs"
        summary = (logs / "table_summary.log").read_text()
        report.update(final_allocation(summary))
        actual = context_stages(json.loads((output / "out" / "pipe" / "context.json").read_text()))
        if any(report[key] != value for key, value in actual.items()):
            raise ValueError(f"Final allocation disagrees with context.json: {actual}")
        report["context_stages"] = actual
        for name in ("table_summary.log", "table_dependency_summary.log", "mau.resources.log"):
            shutil.copyfile(logs / name, output / name)
        phv = max(logs.glob("phv_allocation_summary_*.log"),
                  key=lambda p: int(p.stem.rsplit("_", 1)[-1]))
        shutil.copyfile(phv, output / "phv_allocation_summary.log")
        report["final_phv_report"] = phv.name
        assembly = output / "out" / "pipe" / "defense4_timing.bfa"
        shutil.copyfile(assembly, output / "assembly.bfa")
        report["resource_report_sha256"] = {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("table_summary.log", "table_dependency_summary.log",
                         "mau.resources.log", "phv_allocation_summary.log", "assembly.bfa")
        }
        report["artifact_sha256"] = {
            str(p.relative_to(output / "out")): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (output / "out" / "bfrt.json", output / "out" / "pipe" / "context.json",
                      output / "out" / "pipe" / "tofino.bin")
        }
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if result.returncode:
        raise SystemExit(result.returncode)
    if args.max_ingress is not None and report["ingress_stages"] > args.max_ingress:
        raise SystemExit(f"Stage target missed: {report['ingress_stages']} > {args.max_ingress}")


if __name__ == "__main__":
    main()
