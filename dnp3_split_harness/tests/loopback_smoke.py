"""
Loopback integration + Phase-1 timing validation for split_server.py.

No pydnp3 and no rig required. A minimal "replay master" walks the captured
exchange (payloads/replay/metadata.json), sends each captured master frame, and
reads back exactly the grouped response byte-count -- so it reconstructs the
identical response regardless of how the server split it. For each timing config
it launches split_server as a subprocess, drives one exchange, and records:

  - byte identity: received response == concatenation of the captured resp files;
  - visible request->response time (time-to-first-response-byte from send).

It runs native / fixed / bounded and prints a summary showing the visible time
tracking the configured target. Loopback is a smoke test, not wire truth (the
rig run on Vision/Hulk is the real bar); this proves correctness + the timing
hook end-to-end.

Run:  python3 tests/loopback_smoke.py
"""

import json
import os
import socket
import subprocess
import sys
import time

HARNESS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPLAY_DIR = os.path.join(HARNESS, "payloads", "replay")
HOST = "127.0.0.1"


def load_groups():
    """Return ordered [(orig_bytes, expected_response_bytes), ...] from metadata."""
    events = json.load(open(os.path.join(REPLAY_DIR, "metadata.json")))
    groups = []
    cur_req = None
    resp = bytearray()
    for ev in events:
        if ev["direction"] == "orig":
            if cur_req is not None:
                groups.append((cur_req, bytes(resp)))
            cur_req = open(os.path.join(REPLAY_DIR, ev["filename"]), "rb").read()
            resp = bytearray()
        else:
            resp += open(os.path.join(REPLAY_DIR, ev["filename"]), "rb").read()
    if cur_req is not None:
        groups.append((cur_req, bytes(resp)))
    return groups


def recv_exact(conn, n, deadline):
    """Read exactly n bytes; return (data, t_first_byte_ns)."""
    buf = bytearray()
    t_first = None
    while len(buf) < n:
        if time.time() > deadline:
            break
        conn.settimeout(max(0.01, deadline - time.time()))
        try:
            chunk = conn.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        if t_first is None:
            t_first = time.monotonic_ns()
        buf += chunk
    return bytes(buf), t_first


def wait_listening(proc, port, timeout=8.0):
    """Poll-connect until the server accepts (it logs 'Listening' then accept())."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            s = socket.create_connection((HOST, port), timeout=0.3)
            return s  # first connection: hand it straight to the exchange
        except OSError:
            time.sleep(0.05)
    return False


def run_one(port, delivery, timing_args, log_dir):
    """Launch the server, drive one exchange, return per-transaction records."""
    cmd = [sys.executable, os.path.join(HARNESS, "split_server.py"),
           "--host", HOST, "--port", str(port), "--delivery", delivery,
           "--replay-dir", "payloads/replay", "--log-dir", log_dir,
           "--request-timeout-sec", "8", "--hold-after-response-sec", "1"] + timing_args
    proc = subprocess.Popen(cmd, cwd=HARNESS, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    conn = wait_listening(proc, port)
    if not conn:
        proc.kill()
        raise RuntimeError("server did not come up on port %d" % port)

    records = []
    groups = load_groups()
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i, (req, expected) in enumerate(groups, 1):
            t_send = time.monotonic_ns()
            conn.sendall(req)
            data, t_first = recv_exact(conn, len(expected), time.time() + 6.0)
            visible_ms = ((t_first - t_send) / 1e6) if t_first else None
            records.append({
                "txn": i, "req_len": len(req), "resp_len": len(expected),
                "recv_len": len(data), "byte_identical": data == expected,
                "visible_first_byte_ms": round(visible_ms, 3) if visible_ms else None,
            })
    finally:
        conn.close()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    return records


def main():
    tmp = os.path.join(HARNESS, "logs", "loopback_smoke")
    os.makedirs(tmp, exist_ok=True)
    port = 20077

    configs = [
        ("native / full", "full", ["--timing-mode", "native"]),
        ("fixed 25ms / full", "full", ["--timing-mode", "fixed", "--target-delay-ms", "25"]),
        ("bounded 20-30ms / full", "full",
         ["--timing-mode", "bounded", "--target-min-ms", "20", "--target-max-ms", "30",
          "--timing-seed", "12345"]),
        ("native / crc-split", "crc-boundary", ["--timing-mode", "native"]),
        ("fixed 25ms / crc-split", "crc-boundary",
         ["--timing-mode", "fixed", "--target-delay-ms", "25"]),
    ]

    all_ok = True
    print("{:28s} {:>6s} {:>7s} {:>10s}  {}".format(
        "config", "txns", "bytesOK", "READ_ms", "note"))
    for label, delivery, targs in configs:
        try:
            recs = run_one(port, delivery, targs, tmp)
        except Exception as exc:
            print("{:28s}  ERROR: {}".format(label, exc))
            all_ok = False
            continue
        port += 1  # fresh port per run avoids TIME_WAIT bind races
        bytes_ok = all(r["byte_identical"] and r["recv_len"] == r["resp_len"] for r in recs)
        # the big multi-fragment READ response (2407 B) is the meaningful timed txn
        read_rec = max(recs, key=lambda r: r["resp_len"])
        all_ok = all_ok and bytes_ok
        print("{:28s} {:6d} {:>7s} {:>10s}  {}".format(
            label, len(recs), "PASS" if bytes_ok else "FAIL",
            str(read_rec["visible_first_byte_ms"]),
            "READ resp=%dB" % read_rec["resp_len"]))

    print("\nBYTE-IDENTITY: {}".format("ALL PASS" if all_ok else "FAILURES PRESENT"))
    print("Expect: fixed/bounded READ_ms >= target (~25ms); native READ_ms small (<~5ms).")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
