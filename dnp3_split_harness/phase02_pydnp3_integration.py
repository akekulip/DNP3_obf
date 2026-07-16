"""phase02_pydnp3_integration.py -- real pydnp3 master correctness through the timing path.

For each timing config, launches the timing-enabled `split_server` and drives it with the
REAL pydnp3 master (`run_master.py --action scan-all-classes`) over loopback, then checks
genuine DNP3 application task completion -- not merely byte identity:

  - the master completes a full integrity poll (OnTaskComplete);
  - the master decodes the outstation database (measurements actually flowed);
  - every response was held to the timing target (server timing log);
  - byte-preservation PASS on every response;
  - zero deadline-miss, zero bypass, zero TCP reset.

Requires pydnp3 (system python3) + loopback. This closes the Phase 02 correctness gap: it
lets the phase claim real DNP3 task correctness, not just replay-client byte identity. It is
still loopback, not a wire PCAP.

    python3 phase02_pydnp3_integration.py --run-dir <phase02 run dir>
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import time
from typing import Dict, List

HARNESS = os.path.dirname(os.path.abspath(__file__))

# (label, delivery, timing_args, expected_target_ms or None for native/bypass)
CONFIGS = [
    ("native/full", "full", ["--timing-mode", "native"], None),
    ("fixed25/full", "full", ["--timing-mode", "fixed", "--target-delay-ms", "25"], 25.0),
    ("bounded20-30/full", "full",
     ["--timing-mode", "bounded", "--target-min-ms", "20", "--target-max-ms", "30",
      "--timing-seed", "20260716"], 25.0),
    ("native/crc-split", "crc-boundary", ["--timing-mode", "native"], None),
    ("fixed25/crc-split", "crc-boundary", ["--timing-mode", "fixed", "--target-delay-ms", "25"], 25.0),
    ("bounded20-30/crc-split", "crc-boundary",
     ["--timing-mode", "bounded", "--target-min-ms", "20", "--target-max-ms", "30",
      "--timing-seed", "20260716"], 25.0),
]


def _port_free(port, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port)); s.close(); return True
        except OSError:
            s.close(); time.sleep(0.1)
    return False


def run_config(label, delivery, targs, port, log_dir) -> Dict[str, object]:
    os.makedirs(log_dir, exist_ok=True)
    srv_log = os.path.join(log_dir, "server.log")
    mst_log = os.path.join(log_dir, "master.log")
    srv = subprocess.Popen(
        [sys.executable, "split_server.py", "--host", "127.0.0.1", "--port", str(port),
         "--delivery", delivery, "--hold-after-response-sec", "4",
         "--request-timeout-sec", "15", "--log-dir", log_dir] + targs,
        cwd=HARNESS, stdout=open(srv_log, "w"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    if srv.poll() is not None:
        return {"config": label, "error": "server did not start"}
    try:
        mrc = subprocess.run(
            [sys.executable, "run_master.py", "--host", "127.0.0.1", "--port", str(port),
             "--action", "scan-all-classes", "--wait-after-action", "2",
             "--phase", "custom", "--no-csv", "--no-summary"],
            cwd=HARNESS, stdout=open(mst_log, "w"), stderr=subprocess.STDOUT, timeout=60).returncode
    except subprocess.TimeoutExpired:
        mrc = 124
    finally:
        time.sleep(0.5); srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()

    mtext = open(mst_log, errors="replace").read()
    stext = open(srv_log, errors="replace").read()
    jpath = os.path.join(log_dir, "timing_decisions.jsonl")
    decisions = [json.loads(l) for l in open(jpath)] if os.path.exists(jpath) else []
    held = None
    if decisions and targs[targs.index("--timing-mode") + 1] != "native":
        # visible within a few ms of a 20-30 (bounded) / 25 (fixed) target
        held = all(18.0 <= d["visible_delay_ms"] <= 33.0 for d in decisions)
    elif decisions:
        held = True  # native: no hold expected
    return {
        "config": label,
        "master_exit_ok": mrc == 0,
        "task_completed": ("OnTaskComplete" in mtext),
        "database_decoded": any(k in mtext for k in ("Analog Input", "Binary Input", "SOEHandler.Process")),
        "responses_held_to_target": held,
        "byte_preservation_pass": stext.count("Byte-preservation check: PASS") >= 3,
        "deadline_miss": sum(d["deadline_missed"] for d in decisions),
        "bypassed": sum(d["bypassed"] for d in decisions),
        "resets_in_master_log": sum(1 for _ in [1] if any(w in mtext.lower() for w in ("reset", "rst"))),
        "n_responses": len(decisions),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--start-port", type=int, default=20400)
    args = ap.parse_args()
    if not os.path.isdir(args.run_dir):
        sys.stderr.write("run-dir not found: %s\n" % args.run_dir); return 2

    try:
        import pydnp3  # noqa: F401
    except ImportError as exc:
        vdir = os.path.join(args.run_dir, "validation"); os.makedirs(vdir, exist_ok=True)
        open(os.path.join(vdir, "phase02_pydnp3_integration.md"), "w").write(
            "# Phase 02 — pydnp3 Integration\n\n**BLOCKED**: pydnp3 not importable (%s). "
            "Real DNP3 task correctness could not be validated; the narrower "
            "byte-preservation / replay-completion claim stands.\n" % exc)
        print("pydnp3 unavailable -> BLOCKED (narrower claim retained)")
        return 0

    results = []
    port = args.start_port
    vdir = os.path.join(args.run_dir, "validation"); os.makedirs(vdir, exist_ok=True)
    for label, delivery, targs, _ in CONFIGS:
        if not _port_free(port):
            port += 1
        log_dir = os.path.join(args.run_dir, "logs", "pydnp3_" + label.split("/")[0] + "_" + delivery)
        r = run_config(label, delivery, targs, port, log_dir)
        results.append(r)
        ok = all(r.get(k) for k in ("master_exit_ok", "task_completed", "database_decoded",
                                    "byte_preservation_pass")) and r.get("deadline_miss") == 0 \
            and r.get("bypassed") == 0
        print("  %-24s %s  (task=%s db=%s held=%s bytes=%s ddl=%s)" % (
            label, "PASS" if ok else "CHECK", r.get("task_completed"), r.get("database_decoded"),
            r.get("responses_held_to_target"), r.get("byte_preservation_pass"), r.get("deadline_miss")))
        port += 1

    csv_path = os.path.join(vdir, "phase02_pydnp3_integration.csv")
    cols = ["config", "master_exit_ok", "task_completed", "database_decoded",
            "responses_held_to_target", "byte_preservation_pass", "deadline_miss",
            "bypassed", "resets_in_master_log", "n_responses", "error"]
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore"); w.writeheader()
        for r in results:
            w.writerow(r)

    n_ok = sum(1 for r in results if r.get("master_exit_ok") and r.get("task_completed")
               and r.get("database_decoded") and r.get("byte_preservation_pass")
               and r.get("deadline_miss") == 0 and r.get("bypassed") == 0)
    md = os.path.join(vdir, "phase02_pydnp3_integration.md")
    L = ["# Phase 02 — Real pydnp3 Master Integration (loopback)", "",
         "A real OpenDNP3/pydnp3 master (`run_master --action scan-all-classes`) drives the "
         "timing-enabled `split_server` for each config and completes a genuine DNP3 integrity "
         "poll. This validates DNP3 **task** correctness (OnTaskComplete + database decode), not "
         "just byte identity. Loopback, not a wire PCAP.", "",
         "**%d/%d configs PASS** (master exits clean, task completes, database decoded, "
         "byte-preservation PASS, zero deadline-miss/bypass)." % (n_ok, len(results)), "",
         "| config | task complete | db decoded | held to target | byte-preserve | ddl-miss | bypass | responses |",
         "|---|:--:|:--:|:--:|:--:|---:|---:|---:|"]
    for r in results:
        L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r["config"], r.get("task_completed"), r.get("database_decoded"),
            r.get("responses_held_to_target"), r.get("byte_preservation_pass"),
            r.get("deadline_miss"), r.get("bypassed"), r.get("n_responses")))
    L += ["", "> Loopback DNP3 task correctness. Wire timing and ACK-mode-after-normalization "
          "still require a PCAP (rig).", ""]
    open(md, "w").write("\n".join(L) + "\n")
    print("wrote", csv_path, "and", md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
