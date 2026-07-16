"""phase03_capture.py -- Phase 03A wire capture runner (needs a capture-capable environment).

For each timing config it captures a loopback PCAP with dumpcap while a REAL pydnp3 master
drives the timing-enabled split_server, so every transaction is on the wire and can later be
classified (COMBINED vs SEPARATE ACK) by phase03_analyze.py. It also supports a controlled
application-write delay sweep to characterize the separation transition.

CAPTURE PERMISSION IS REQUIRED. This host cannot capture (dumpcap is root:wireshark and this
user is not in the wireshark group; no rig). A preflight check records the environment and, if
capture is unavailable, writes capture_environment.json and exits 3 WITHOUT fabricating data.
Enabling capture (adding the user to the wireshark group, or running on the rig) needs explicit
human approval -- do not change permissions automatically.

    python3 phase03_capture.py --run-dir <fresh> --mode matrix    # the 7-config wire matrix
    python3 phase03_capture.py --run-dir <fresh> --mode sweep     # app-write delay sweep
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HARNESS, "tests"))

MATRIX = [
    ("native_full", "full", ["--timing-mode", "native"]),
    ("fixed25_full", "full", ["--timing-mode", "fixed", "--target-delay-ms", "25"]),
    ("bounded20-30_full", "full", ["--timing-mode", "bounded", "--target-min-ms", "20",
                                   "--target-max-ms", "30", "--timing-seed", "20260716"]),
    ("native_crc-split", "crc-boundary", ["--timing-mode", "native"]),
    ("fixed25_crc-split", "crc-boundary", ["--timing-mode", "fixed", "--target-delay-ms", "25"]),
    ("bounded20-30_crc-split", "crc-boundary", ["--timing-mode", "bounded", "--target-min-ms", "20",
                                                "--target-max-ms", "30", "--timing-seed", "20260716"]),
    ("fixed300-rto105_bypass", "full", ["--timing-mode", "fixed", "--target-delay-ms", "300",
                                        "--rto-safe-ms", "105"]),
]
SWEEP_DELAYS_MS = [0, 1, 2, 5, 10, 15, 20, 25, 30, 35, 40, 50, 75, 100]


def _cmd_out(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        return r.stdout.decode("utf-8", "replace").strip(), r.returncode
    except (OSError, subprocess.SubprocessError):
        return "", 1


def _find_dumpcap():
    """Return (path, executable_by_this_user). dumpcap may exist but be root:wireshark."""
    p = shutil.which("dumpcap")
    if p:
        return p, True
    for cand in ("/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/usr/local/bin/dumpcap"):
        if os.path.exists(cand):
            return cand, os.access(cand, os.X_OK)
    return None, False


def record_environment(run_dir):
    dumpcap, execable = _find_dumpcap()
    ver, _ = _cmd_out([dumpcap, "--version"]) if (dumpcap and execable) else ("", 1)
    tshark_ver, _ = _cmd_out(["tshark", "--version"])
    env = {
        "hostname": socket.gethostname(),
        "os": platform.platform(), "kernel": platform.release(),
        "interfaces": _cmd_out(["ip", "-o", "link"])[0][:2000],
        "dumpcap_path": dumpcap, "dumpcap_executable_by_user": execable,
        "dumpcap_version": ver.splitlines()[0] if ver else None,
        "tshark_version": tshark_ver.splitlines()[0] if tshark_ver else None,
        "user_groups": _cmd_out(["id", "-nG"])[0],
        "capture_location": "loopback (lo) sender==receiver (single host)",
        "capture_side": "both (single-host loopback)",
        "clock_sync": "single host monotonic/epoch clock (no cross-host sync needed on loopback)",
        "offload_note": "loopback has no NIC offloads; a rig run must record NIC + ethtool -k offloads",
    }
    with open(os.path.join(run_dir, "capture_environment.json"), "w") as fh:
        json.dump(env, fh, indent=2)
    return env


def capture_available(run_dir):
    """True iff dumpcap can actually capture on lo. Records the accurate reason if not."""
    path, execable = _find_dumpcap()
    if path is None:
        return False, "dumpcap not installed"
    if not execable:
        return False, ("dumpcap present at %s but not executable by this user "
                       "(root:wireshark; user not in the 'wireshark' group)" % path)
    test = os.path.join(run_dir, ".captest.pcap")
    try:
        r = subprocess.run(["dumpcap", "-i", "lo", "-a", "duration:1", "-w", test],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "dumpcap failed to run: %s" % exc
    finally:
        if os.path.exists(test):
            os.remove(test)
    if r.returncode != 0:
        return False, "dumpcap exited %d: %s" % (r.returncode, r.stderr.decode("utf-8", "replace")[:200])
    return True, "ok"


def _run_session(port, delivery, timing_args, log_dir, pcap_path):
    """Capture on lo while a real pydnp3 master scans through the timing-enabled split_server.

    The controlled 'application-write delay' for the sweep is expressed through the existing
    fixed timing mode (hold the response to request_received + target), so no new split_server
    flag is introduced and the validated Phase 02 scheduler is untouched.
    """
    os.makedirs(log_dir, exist_ok=True)
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % port, "-w", pcap_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    srv = subprocess.Popen(
        [sys.executable, "split_server.py", "--host", "127.0.0.1", "--port", str(port),
         "--delivery", delivery, "--hold-after-response-sec", "3", "--request-timeout-sec", "15",
         "--log-dir", log_dir] + timing_args,
        cwd=HARNESS, stdout=open(os.path.join(log_dir, "server.log"), "w"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    ok = srv.poll() is None
    if ok:
        subprocess.run([sys.executable, "run_master.py", "--host", "127.0.0.1", "--port", str(port),
                        "--action", "scan-all-classes", "--wait-after-action", "2",
                        "--phase", "custom", "--no-csv", "--no-summary"],
                       cwd=HARNESS, stdout=open(os.path.join(log_dir, "master.log"), "w"),
                       stderr=subprocess.STDOUT, timeout=60)
    time.sleep(0.5)
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill()
    time.sleep(0.5); cap.terminate()
    try:
        cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
    return os.path.exists(pcap_path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--mode", choices=["matrix", "sweep"], default="matrix")
    ap.add_argument("--start-port", type=int, default=20300)
    args = ap.parse_args()
    os.makedirs(args.run_dir, exist_ok=True)
    pdir = os.path.join(args.run_dir, "pcaps"); os.makedirs(pdir, exist_ok=True)

    env = record_environment(args.run_dir)
    ok, why = capture_available(args.run_dir)
    if not ok:
        env["capture_available"] = False
        env["capture_blocked_reason"] = why
        json.dump(env, open(os.path.join(args.run_dir, "capture_environment.json"), "w"), indent=2)
        sys.stderr.write(
            "CAPTURE UNAVAILABLE: %s\n"
            "Phase 03A needs a capture-capable environment. Options (need human approval):\n"
            "  - add this user to the 'wireshark' group (then re-login), or\n"
            "  - run on the Vision/Hulk rig, or\n"
            "  - run on a host with dumpcap/tshark capture permission.\n"
            "No data was fabricated; capture_environment.json records the reason.\n" % why)
        return 3

    env["capture_available"] = True
    json.dump(env, open(os.path.join(args.run_dir, "capture_environment.json"), "w"), indent=2)

    port = args.start_port
    if args.mode == "matrix":
        for label, delivery, targs in MATRIX:
            pcap = os.path.join(pdir, label + ".pcap")
            got = _run_session(port, delivery, targs, os.path.join(args.run_dir, "logs", label), pcap)
            print("  %-24s -> %s (%s)" % (label, pcap, "captured" if got else "FAILED"))
            port += 1
    else:  # sweep: hold the combined response to a fixed target (= controlled app-write delay)
        for d in SWEEP_DELAYS_MS:
            targs = ["--timing-mode", "native"] if d == 0 else \
                    ["--timing-mode", "fixed", "--target-delay-ms", str(d)]
            pcap = os.path.join(pdir, "delay_%03dms.pcap" % d)
            got = _run_session(port, "full", targs,
                               os.path.join(args.run_dir, "logs", "delay_%03d" % d), pcap)
            print("  delay %3d ms -> %s (%s)" % (d, pcap, "captured" if got else "FAILED"))
            port += 1
    print("captured pcaps in", pdir, "-> analyze with: python3 phase03_analyze.py --run-dir %s --pcap-dir %s" % (
        args.run_dir, pdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
