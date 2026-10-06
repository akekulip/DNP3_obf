#!/usr/bin/env python3
"""Bounded, captured hardware smoke block using the repository's guarded harness."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument("label")
p.add_argument("--reads", type=int, default=20)
p.add_argument("--sbo", type=int, default=10)
a = p.parse_args()
if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
    raise SystemExit("REFUSED: DEFENSE4_HW_AUTHORIZED=1 is required")
root = Path(__file__).resolve().parent
out = root / a.label
out.mkdir(exist_ok=False)
env = dict(os.environ, PYTHONPATH=str(root / "active_harness"))

def run(name, command):
    with (out / (name + ".log")).open("w") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                timeout=45, cwd=root)
    print(name, result.returncode, flush=True)
    return result.returncode

status = {"label": a.label, "read_count": a.reads, "sbo_count": a.sbo}
with (out / "dumpcap.log").open("w") as caplog:
    capture = subprocess.Popen(["dumpcap", "-q", "-i", "enp59s0f0np0", "-f",
                                "host 192.168.10.7 and tcp port 20000", "-a", "duration:60",
                                "-w", str(out / "traffic.pcapng")],
                               stdout=caplog, stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        if capture.poll() is not None:
            raise RuntimeError("Capture exited before traffic; inspect dumpcap.log")
        status["outputs_before"] = run("outputs_before", ["python3", "read_outputs.py"])
        if status["outputs_before"]:
            raise RuntimeError("Output-state check failed; no test traffic sent")
        status["read"] = run("read", ["python3", "active_harness/read_driver.py", "--live",
                                     "--count", str(a.reads), "--gap-ms", "400", "--budget-ms", "500",
                                     "--out", str(out / "read.jsonl")])
        if status["read"]:
            raise RuntimeError("READ validation failed; no SBO sent")
        if a.sbo:
            status["sbo"] = run("sbo", ["python3", "active_harness/sbo_driver.py", "--live",
                                       "--count", str(a.sbo), "--gap-ms", "400", "--budget-ms", "500",
                                       "--indices", "1,3", "--out", str(out / "sbo.jsonl")])
    except Exception as exc:
        status["error"] = str(exc)
    finally:
        status["outputs_after"] = run("outputs_after", ["python3", "read_outputs.py"])
        if capture.poll() is None:
            capture.send_signal(signal.SIGINT)
        status["capture_exit"] = capture.wait(timeout=10)
        (out / "status.json").write_text(json.dumps(status, indent=2) + "\n")
print(json.dumps(status), flush=True)
raise SystemExit(1 if "error" in status or any(status.get(k, 0) != 0 for k in
                 ("outputs_before", "outputs_after", "read", "sbo", "capture_exit")) else 0)
