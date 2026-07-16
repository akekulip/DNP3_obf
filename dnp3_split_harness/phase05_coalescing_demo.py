"""phase05_coalescing_demo.py -- socket-coalescing defended-wire demonstration (human-authorized).

Shows, on the ACTUAL wire (not a trace-transformation), that ACK-mode normalization by socket-side
coalescing converts a would-be separate-ACK flow into a combined one -- byte-preservingly and
without dropping any packet. Two captures of the replay server:

  undefended_separate : --server-quickack (forces a standalone pure ACK -> separate mode, the
                        analog of a naturally separate device such as SEL-751)
  defended_coalesced  : NO quickack, response written within the delayed-ACK window (~5 ms) so the
                        kernel piggybacks the ACK on the response -> combined mode

Both replay the SAME captured response bytes, so byte-identity isolates the ACK-mode change.
Expected: is_separate 1 -> 0 on the wire; 0 retransmissions/resets; 100% byte-identical. No BPF,
no drops, no netns.

Needs capture permission (run under `sg wireshark -c '...'`, not sudo):
    sg wireshark -c 'python3 phase05_coalescing_demo.py --run-dir runs/<UTC>_phase05_coalescing'
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
import loopback_smoke as LS            # noqa: E402
import characterize_ack_traces as C    # noqa: E402
import phase01_reconstruct as R         # noqa: E402

PORT = 20000
CONFIGS = [
    ("undefended_separate", ["--timing-mode", "fixed", "--target-delay-ms", "5",
                             "--server-quickack", "--delivery", "full"]),
    ("defended_coalesced", ["--timing-mode", "fixed", "--target-delay-ms", "5",
                            "--delivery", "full"]),   # no quickack -> ACK piggybacks
]


def one_session(server_args, log_dir):
    os.makedirs(log_dir, exist_ok=True)
    srv = subprocess.Popen(
        [sys.executable, "split_server.py", "--host", "127.0.0.1", "--port", str(PORT),
         "--hold-after-response-sec", "1", "--request-timeout-sec", "8", "--log-dir", log_dir]
        + server_args, cwd=HARNESS, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def capture(label, server_args, reps, run_dir):
    pcap = os.path.join(run_dir, "pcaps", label + ".pcap")
    os.makedirs(os.path.dirname(pcap), exist_ok=True)
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % PORT, "-w", pcap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    total = byte_ok = 0
    for rep in range(reps):
        t, b = one_session(server_args, os.path.join(run_dir, "logs", "%s_rep%03d" % (label, rep)))
        total += t; byte_ok += b
        time.sleep(0.2)
    time.sleep(0.6)
    cap.terminate()
    try:
        cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
    return pcap, total, byte_ok


def analyze(pcap, label):
    txns = R.build_rich_transactions(C.run_tshark(pcap), pcap, label)
    first = {}
    for t in txns:
        if t.tcp_stream not in first or t.req_frame < first[t.tcp_stream]:
            first[t.tcp_stream] = t.req_frame
    nf = [t for t in txns if t.req_frame != first[t.tcp_stream]]   # non-first (exclude handshake quickack)
    n = len(nf) or 1
    sep = sum(1 for t in nf if t.ack_mode == "SEPARATE")

    def med(vals):
        vals = sorted(v for v in vals if v is not None)
        return round(vals[len(vals) // 2], 4) if vals else None
    return {
        "nonfirst_n": len(nf),
        "separate": sep, "combined": sum(1 for t in nf if t.ack_mode == "COMBINED"),
        "separate_fraction": round(sep / n, 4),
        "req_to_ack_ms_median": med([t.req_to_pure_ack_ms for t in nf]),
        "req_to_resp_ms_median": med([t.req_to_resp_ms for t in nf]),
        "retransmissions": sum(t.retransmission_count for t in nf),
        "resets": sum(1 for t in nf if t.reset),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--reps", type=int, default=20)
    args = ap.parse_args()
    os.makedirs(args.run_dir, exist_ok=True)
    res = {}
    byte_ok_total = byte_total = 0
    for label, server_args in CONFIGS:
        pcap, total, byte_ok = capture(label, server_args, args.reps, args.run_dir)
        byte_ok_total += byte_ok; byte_total += total
        res[label] = analyze(pcap, label)
        res[label]["byte_identical"] = "%d/%d" % (byte_ok, total)
        print("%-20s txns=%d byteOK=%d" % (label, total, byte_ok))
    json.dump(res, open(os.path.join(args.run_dir, "coalescing_demo_summary.json"), "w"), indent=2)
    print("\n=== socket-coalescing defended-wire demo (non-first requests) ===")
    for label, _ in CONFIGS:
        s = res[label]
        print("  %-20s separate=%d/%d (%.0f%%) | req->ACK med=%s | req->resp med=%s | "
              "retrans=%d reset=%d | byte=%s"
              % (label, s["separate"], s["nonfirst_n"], 100 * s["separate_fraction"],
                 s["req_to_ack_ms_median"], s["req_to_resp_ms_median"],
                 s["retransmissions"], s["resets"], s["byte_identical"]))
    u = res["undefended_separate"]; d = res["defended_coalesced"]
    ok = (u["separate_fraction"] > 0.9 and d["separate_fraction"] < 0.1
          and d["retransmissions"] == 0 and d["resets"] == 0 and byte_ok_total == byte_total)
    print("\n[=] %s: coalescing flips separate->combined on the wire (is_separate %.0f%%->%.0f%%), "
          "byte-identical, no breakage." % ("PASS" if ok else "CHECK",
          100 * u["separate_fraction"], 100 * d["separate_fraction"]))
    print("byte-identical overall: %d/%d" % (byte_ok_total, byte_total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
