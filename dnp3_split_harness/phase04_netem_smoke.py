"""phase04_netem_smoke.py -- Phase 04 netem smoke test (human-authorized 2026-07-16).

Question this answers: can a `tc`/netem egress control point hold an EXISTING pure TCP ACK
independently of the DNP3 response -- byte-preservingly, without forging anything, and without
breaking the connection? This is the coarse pre-check before investing in the eBPF mechanism; it
does NOT build the eBPF mechanism.

Design: drive the replay server in the SEPARATE-ACK regime (fixed 50 ms app-write delay +
--server-quickack, so a standalone pure ACK precedes the response), captured twice on `lo`:
  * native   -- no netem: request -> prompt pure ACK (~0 ms) -> response (~50 ms).
  * ack30    -- prio+netem delays ONLY the server's pure ACK (src_port 20000, pure-ACK flags)
                by 30 ms; the payload response is not matched, so it stays fast.
Expected if the control point works: request->ACK moves ~0 -> ~30 ms while request->response
stays ~50 ms, i.e. the ACK->response gap shrinks ~50 -> ~20 ms, with 0 retransmissions/resets and
100% byte-identical responses (netem only DELAYS existing packets -- no synthesis, no byte edits).

Runs ONLY inside a user network namespace (non-sudo, isolated):
    unshare -rn python3 phase04_netem_smoke.py --run-dir runs/<UTC>_phase04_netem_smoke
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HARNESS, "tests"))
import loopback_smoke as LS   # noqa: E402
import characterize_ack_traces as C   # noqa: E402
import phase01_reconstruct as R        # noqa: E402

PORT = 20000
SERVER_ARGS = ["--timing-mode", "fixed", "--target-delay-ms", "50", "--server-quickack",
               "--delivery", "full"]


def _run(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode("utf-8", "replace")


def setup_lo():
    _run(["ip", "link", "set", "lo", "up"])


def add_ack_netem(delay_ms):
    """Classful prio on lo; netem delays band 1:1; steer ONLY the server's pure ACKs there."""
    _run(["tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3"])
    _run(["tc", "qdisc", "add", "dev", "lo", "parent", "1:1", "handle", "10:",
          "netem", "delay", "%dms" % delay_ms])
    # pure ACK = ACK set, SYN/FIN/RST/PSH clear. The mask MUST include PSH (0x08): mask 0x1f
    # covers ACK+PSH+RST+SYN+FIN, so a PSH+ACK response (0x18) does NOT match and stays fast.
    # (An earlier 0x17 mask omitted PSH and wrongly delayed responses too -- a concrete instance
    # of the flag-classification fragility the feasibility report warned about.)
    _run(["tc", "filter", "add", "dev", "lo", "parent", "1:", "protocol", "ip", "prio", "1",
          "flower", "ip_proto", "tcp", "src_port", str(PORT), "tcp_flags", "0x10/0x1f",
          "flowid", "1:1"])


def clear_tc():
    _run(["tc", "qdisc", "del", "dev", "lo", "root"])


def one_session(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    srv = subprocess.Popen(
        [sys.executable, "split_server.py", "--host", "127.0.0.1", "--port", str(PORT),
         "--hold-after-response-sec", "1", "--request-timeout-sec", "8", "--log-dir", log_dir]
        + SERVER_ARGS, cwd=HARNESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    conn = LS.wait_listening(srv, PORT)
    total = byte_ok = 0
    if conn:
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for req, expected in LS.load_groups():
                conn.sendall(req)
                data, _ = LS.recv_exact(conn, len(expected), time.time() + 8.0)
                total += 1
                byte_ok += 1 if data == expected else 0
        finally:
            conn.close()
    try:
        srv.wait(timeout=3)
    except subprocess.TimeoutExpired:
        srv.kill()
    return total, byte_ok


def capture_scenario(label, use_netem, reps, run_dir):
    pcap = os.path.join(run_dir, "pcaps", label + ".pcap")
    os.makedirs(os.path.dirname(pcap), exist_ok=True)
    clear_tc()
    if use_netem:
        add_ack_netem(30)
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % PORT, "-w", pcap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    total = byte_ok = 0
    for rep in range(reps):
        t, b = one_session(os.path.join(run_dir, "logs", "%s_rep%03d" % (label, rep)))
        total += t; byte_ok += b
        time.sleep(0.2)
    time.sleep(0.6)
    cap.terminate()
    try:
        cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
    clear_tc()
    return pcap, total, byte_ok


def analyze(pcap, label):
    """Non-first-request timing for the separate-ACK transactions in one pcap."""
    txns = R.build_rich_transactions(C.run_tshark(pcap), pcap, label)
    first = {}
    for t in txns:
        if t.tcp_stream not in first or t.req_frame < first[t.tcp_stream]:
            first[t.tcp_stream] = t.req_frame
    nf = [t for t in txns if t.req_frame != first[t.tcp_stream]]
    sep = [t for t in nf if t.ack_mode == "SEPARATE"]

    def med(vals):
        vals = sorted(v for v in vals if v is not None)
        return round(vals[len(vals) // 2], 4) if vals else None
    return {
        "label": label, "n_nonfirst": len(nf),
        "n_separate": len(sep),
        "req_to_ack_ms_median": med([t.req_to_pure_ack_ms for t in sep]),
        "ack_to_resp_ms_median": med([t.pure_ack_to_resp_ms for t in sep]),
        "req_to_resp_ms_median": med([t.req_to_resp_ms for t in nf]),
        "retransmissions": sum(t.retransmission_count for t in nf),
        "duplicate_acks": sum(t.duplicate_ack_count for t in nf),
        "resets": sum(1 for t in nf if t.reset),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--reps", type=int, default=10)
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.stderr.write("Run inside a user netns: unshare -rn python3 phase04_netem_smoke.py ...\n")
        return 2
    os.makedirs(args.run_dir, exist_ok=True)
    setup_lo()

    results = {}
    byte_ok_total = byte_total = 0
    for label, use_netem in [("native", False), ("ack30_netem", True)]:
        pcap, total, byte_ok = capture_scenario(label, use_netem, args.reps, args.run_dir)
        byte_ok_total += byte_ok; byte_total += total
        results[label] = analyze(pcap, label)
        results[label]["byte_identical"] = "%d/%d" % (byte_ok, total)
        print("%-12s txns=%d byteOK=%d" % (label, total, byte_ok))

    out = os.path.join(args.run_dir, "netem_smoke_summary.json")
    json.dump(results, open(out, "w"), indent=2)
    print("\n=== netem smoke result (non-first SEPARATE transactions) ===")
    for label in ("native", "ack30_netem"):
        s = results[label]
        print("  %-12s req->ACK med=%s ms | ACK->resp med=%s ms | req->resp med=%s ms | "
              "sep=%d/%d | retrans=%d dupACK=%d reset=%d | byte=%s" % (
                  label, s["req_to_ack_ms_median"], s["ack_to_resp_ms_median"],
                  s["req_to_resp_ms_median"], s["n_separate"], s["n_nonfirst"],
                  s["retransmissions"], s["duplicate_acks"], s["resets"], s["byte_identical"]))
    print("\nwrote", out)
    print("byte-identical overall: %d/%d" % (byte_ok_total, byte_total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
