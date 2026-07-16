"""phase03_capture.py -- Phase 03A wire capture runner (needs a capture-capable environment).

For each timing config it captures a loopback PCAP with dumpcap while the replay client drives
the timing-enabled split_server through the captured request set, so >=100 real TCP transactions
per config are on the wire and can be classified (COMBINED vs SEPARATE ACK) by phase03_analyze.py.
It also supports a controlled application-write delay sweep (expressed through the existing fixed
timing mode -- no new scheduler flag; the validated Phase 02 scheduler is untouched).

CAPTURE PERMISSION IS REQUIRED. Run under a shell that carries the 'wireshark' group, e.g.
`sg wireshark -c 'python3 phase03_capture.py ...'` (NOT sudo). A preflight records the environment
and, if capture is unavailable, writes capture_environment.json and exits 3 WITHOUT fabricating.

    sg wireshark -c 'python3 phase03_capture.py --mode matrix --reps 25'
    sg wireshark -c 'python3 phase03_capture.py --mode sweep  --reps 20'
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
import loopback_smoke as LS   # noqa: E402  (replay client helpers)
import run_manifest           # noqa: E402

PORT = 20000                  # all configs use the canonical DNP3 port (run sequentially)

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
    p = shutil.which("dumpcap")
    if p:
        return p, True
    for cand in ("/usr/bin/dumpcap", "/usr/sbin/dumpcap", "/usr/local/bin/dumpcap"):
        if os.path.exists(cand):
            return cand, os.access(cand, os.X_OK)
    return None, False


def record_environment():
    dumpcap, execable = _find_dumpcap()
    ver, _ = _cmd_out(["dumpcap", "--version"])
    tshark_ver, _ = _cmd_out(["tshark", "--version"])
    return {
        "hostname": socket.gethostname(), "os": platform.platform(), "kernel": platform.release(),
        "interfaces": _cmd_out(["ip", "-o", "link"])[0][:2000],
        "dumpcap_path": dumpcap, "dumpcap_executable_by_process": execable,
        "dumpcap_version": ver.splitlines()[0] if ver else None,
        "tshark_version": tshark_ver.splitlines()[0] if tshark_ver else None,
        "process_groups": _cmd_out(["id", "-nG"])[0],
        "capture_location": "loopback (lo), single host gambit (sender==receiver)",
        "capture_side": "both (single-host loopback)",
        "clock_sync": "single-host clock; no cross-host sync (loopback)",
        "offload_note": "loopback has no NIC offloads; a rig run must record NIC + ethtool -k",
        "scope_label": ("Measured on the gambit loopback interface, Linux kernel %s, in the "
                        "tested socket and application configuration." % platform.release()),
    }


def capture_available():
    path, execable = _find_dumpcap()
    if path is None:
        return False, "dumpcap not installed"
    if not execable:
        return False, ("dumpcap present at %s but not executable by this process "
                       "(root:wireshark; run under `sg wireshark -c ...`)" % path)
    test = os.path.join(HARNESS, ".captest.pcap")
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


def _one_session(port, delivery, timing_args, log_dir):
    """One replay-client connection through a fresh split_server. Returns (total, byte_ok)."""
    os.makedirs(log_dir, exist_ok=True)
    srv = subprocess.Popen(
        [sys.executable, "split_server.py", "--host", "127.0.0.1", "--port", str(port),
         "--delivery", delivery, "--hold-after-response-sec", "1", "--request-timeout-sec", "8",
         "--log-dir", log_dir] + timing_args,
        cwd=HARNESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conn = LS.wait_listening(srv, port)
    total = byte_ok = 0
    if conn:
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for req, expected in LS.load_groups():
                conn.sendall(req)
                data, _ = LS.recv_exact(conn, len(expected), time.time() + 6.0)
                total += 1
                byte_ok += 1 if data == expected else 0
        finally:
            conn.close()
    try:
        srv.wait(timeout=3)
    except subprocess.TimeoutExpired:
        srv.kill()
    return total, byte_ok


def capture_config(label, delivery, timing_args, reps, pcap_path, log_root):
    """One dumpcap over `reps` replay sessions on PORT -> one pcap per config."""
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % PORT, "-w", pcap_path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    total = byte_ok = 0
    for rep in range(reps):
        t, b = _one_session(PORT, delivery, timing_args, os.path.join(log_root, "%s_rep%03d" % (label, rep)))
        total += t; byte_ok += b
        time.sleep(0.15)          # let the listen socket free for the next SO_REUSEADDR bind
    time.sleep(0.6)
    cap.terminate()
    try:
        cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
    return total, byte_ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["matrix", "sweep"], default="matrix")
    ap.add_argument("--reps", type=int, default=25, help="replay sessions per config (5 txns each)")
    ap.add_argument("--delays-ms", default=None,
                    help="sweep only: comma-separated app-write delays (ms) overriding the default "
                         "coarse list, e.g. --delays-ms 35,36,37,38,39,40 for a 1 ms refinement")
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--out-dir", default=HARNESS)
    args = ap.parse_args()

    ok, why = capture_available()
    if not ok:
        os.makedirs(args.out_dir, exist_ok=True)
        env = record_environment(); env["capture_available"] = False; env["capture_blocked_reason"] = why
        json.dump(env, open(os.path.join(args.out_dir, "capture_environment.json"), "w"), indent=2)
        sys.stderr.write("CAPTURE UNAVAILABLE: %s\nRun under `sg wireshark -c '...'` (not sudo), "
                         "or on the rig. No data fabricated.\n" % why)
        return 3

    import scapy  # noqa: F401
    dumpcap_ver = record_environment()["dumpcap_version"]
    short = "wire_matrix" if args.mode == "matrix" else "wire_delay_sweep"
    inputs = [os.path.join(HARNESS, "payloads", "replay", "metadata.json")]
    try:
        run = run_manifest.RunContext.start(
            phase="phase_03a", short_name=short, inputs=inputs, argv=sys.argv,
            run_dir=args.run_dir, base_dir=args.out_dir, config=vars(args),
            extra_tool_versions={"scapy": getattr(scapy, "__version__", "present"),
                                 "dumpcap": dumpcap_ver})
    except run_manifest.RunDirectoryError as exc:
        sys.stderr.write("%s\n" % exc); return 2

    env = record_environment(); env["capture_available"] = True
    json.dump(env, open(os.path.join(run.run_dir, "capture_environment.json"), "w"), indent=2)
    pdir = run.subdir("pcaps"); log_root = run.subdir("logs")
    print("Phase 03A capture run:", run.run_id, "(mode=%s reps=%d)" % (args.mode, args.reps))
    print(env["scope_label"])

    sweep_delays = ([int(x) for x in args.delays_ms.split(",") if x.strip() != ""]
                    if args.delays_ms else SWEEP_DELAYS_MS)
    summary = []
    jobs = ([(l, d, t) for l, d, t in MATRIX] if args.mode == "matrix"
            else [("delay_%03dms" % dl, "full",
                   (["--timing-mode", "native"] if dl == 0 else
                    ["--timing-mode", "fixed", "--target-delay-ms", str(dl)])) for dl in sweep_delays])
    for label, delivery, targs in jobs:
        pcap = os.path.join(pdir, label + ".pcap")
        total, byte_ok = capture_config(label, delivery, targs, args.reps, pcap, log_root)
        got = os.path.exists(pcap)
        summary.append({"label": label, "delivery": delivery, "transactions": total,
                        "byte_identical": byte_ok, "pcap": os.path.relpath(pcap, run.run_dir),
                        "captured": got})
        print("  %-24s txns=%d bytesOK=%d pcap=%s" % (label, total, byte_ok, "yes" if got else "FAILED"))
    json.dump(summary, open(run.path("tables", "phase03_capture_summary.json"), "w"), indent=2)
    run.finish(exit_status=0)
    print("pcaps in", pdir)
    print("analyze: python3 phase03_analyze.py --run-dir %s --pcap-dir %s" % (run.run_dir, pdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
