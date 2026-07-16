"""phase04_ebpf_prototype.py -- drive + measure the Phase 04 eBPF EDT mechanism.

Runs INSIDE a network namespace, AS ROOT (BPF load needs CAP_BPF). Loads ack_edt.o on lo egress
with an `fq` root qdisc, drives the replay server (separate-ACK regime: fixed 5 ms + quickack, so a
prompt separate ACK and an early response both sit below the eBPF targets and can be delayed to
them), captures on lo, and reports whether the pure ACK and the response were independently pinned
to their per-flow EDT targets (request->ACK 20 ms, request->response 40 ms).

Invoked by run_prototype.sh (which creates the netns + compiles the object). Not for standalone use.

    ip netns exec <ns> python3 phase04_ebpf_prototype.py --run-dir <dir> --obj <ack_edt.o>
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
# separate-ACK regime, response written early (5 ms) so both native egress times are below the
# eBPF targets (ACK 20 ms, response 40 ms) and get delayed UP to them.
SERVER_ARGS = ["--timing-mode", "fixed", "--target-delay-ms", "5", "--server-quickack",
               "--delivery", "full"]
ACK_TARGET_MS = 20
RESP_TARGET_MS = 40


def _run(cmd):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode("utf-8", "replace")


def load_bpf(obj):
    _run(["ip", "link", "set", "lo", "up"])
    _run(["tc", "qdisc", "add", "dev", "lo", "root", "fq"])
    _run(["tc", "qdisc", "add", "dev", "lo", "clsact"])
    rc, out = _run(["tc", "filter", "add", "dev", "lo", "egress", "bpf", "da", "obj", obj, "sec", "tc"])
    print(out.strip())
    rc2, show = _run(["tc", "filter", "show", "dev", "lo", "egress"])
    print(show.strip())
    return "id" in show   # a loaded program shows an id


def teardown():
    _run(["tc", "qdisc", "del", "dev", "lo", "clsact"])
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


def capture(run_dir, reps):
    pcap = os.path.join(run_dir, "ebpf_prototype.pcap")
    os.makedirs(run_dir, exist_ok=True)
    cap = subprocess.Popen(["dumpcap", "-i", "lo", "-f", "tcp port %d" % PORT, "-w", pcap],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    total = byte_ok = 0
    for rep in range(reps):
        t, b = one_session(os.path.join(run_dir, "logs", "rep%03d" % rep))
        total += t; byte_ok += b
        time.sleep(0.2)
    time.sleep(0.6)
    cap.terminate()
    try:
        cap.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cap.kill()
    return pcap, total, byte_ok


def analyze(pcap):
    txns = R.build_rich_transactions(C.run_tshark(pcap), pcap, "ebpf")
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
        "nonfirst_n": len(nf), "separate_n": len(sep),
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
    ap.add_argument("--obj", required=True, help="path to ack_edt.o")
    ap.add_argument("--reps", type=int, default=10)
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.stderr.write("must run as root inside the netns (see run_prototype.sh)\n"); return 2

    print("[*] loading ack_edt.o on lo egress + fq ...")
    if not load_bpf(args.obj):
        print("BPF LOAD FAILED"); teardown(); return 3
    try:
        pcap, total, byte_ok = capture(args.run_dir, args.reps)
        res = analyze(pcap)
    finally:
        teardown()

    res["byte_identical"] = "%d/%d" % (byte_ok, total)
    json.dump(res, open(os.path.join(args.run_dir, "ebpf_prototype_summary.json"), "w"), indent=2)
    print("\n=== eBPF EDT prototype result (non-first SEPARATE transactions) ===")
    print("  targets: request->ACK = %d ms, request->response = %d ms (gap-normalized)"
          % (ACK_TARGET_MS, RESP_TARGET_MS))
    print("  MEASURED: req->ACK med=%s ms | ACK->resp med=%s ms | req->resp med=%s ms"
          % (res["req_to_ack_ms_median"], res["ack_to_resp_ms_median"], res["req_to_resp_ms_median"]))
    print("  separate=%d/%d | retrans=%d dupACK=%d reset=%d | byte=%s"
          % (res["separate_n"], res["nonfirst_n"], res["retransmissions"],
             res["duplicate_acks"], res["resets"], res["byte_identical"]))
    ok = (res["req_to_ack_ms_median"] and abs(res["req_to_ack_ms_median"] - ACK_TARGET_MS) < 3
          and res["req_to_resp_ms_median"] and abs(res["req_to_resp_ms_median"] - RESP_TARGET_MS) < 3
          and res["resets"] == 0 and res["retransmissions"] == 0 and byte_ok == total)
    print("\n[=] %s: ACK and response independently pinned to their EDT targets, byte-identical, no breakage."
          % ("PASS" if ok else "CHECK"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
