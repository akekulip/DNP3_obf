#!/usr/bin/env python3
"""phase05_rig_replay.py -- two-host RIG defended-wire replay endpoint (stdlib only).

Runs on the rig hosts (Python 3, no third-party deps). Driven by phase05_rig_defended_wire.py on the
dev box. One shared spec.json defines, per device PCAP, the ordered list of real (request, response)
first-segment byte pairs plus each transaction's native request->response time and native ACK mode.

Both roles iterate the SAME fixed session order -- for cond in conditions: for pcap in pcaps -- so the
k-th client connection (k-th TCP stream in the single capture) is session k. The server applies the
condition's ACK/timing policy; the client just sends requests and reads responses.

  --role server  (Hulk): bind :PORT, start ONE local dumpcap, accept one connection per session,
                 replay that PCAP's real response bytes with the condition policy, then stop capture.
  --role client  (Vision): connect once per session, send the real request bytes, read the response.

Policies (identical to the loopback eval phase05_defended_wire_eval.py):
  native        : reproduce each txn's native ACK mode (separate via TCP_QUICKACK) + native timing.
  coalesced     : no quickack, response inside the delayed-ACK window -> ACK mode combined; native timing.
  coalesced_edt : coalesced + response timing raised to a common target.
"""
import argparse
import json
import socket
import subprocess
import sys
import time


def load_spec(path):
    with open(path) as fh:
        return json.load(fh)


def session_order(spec):
    return [(c, p) for c in spec["conditions"] for p in spec["pcaps"]]


def recv_exact(conn, n, deadline):
    buf = bytearray()
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
        buf += chunk
    return bytes(buf)


def serve(args):
    spec = load_spec(args.spec)
    port = spec["port"]
    win = spec["delayed_ack_window_ms"]
    edt = spec["edt_target_ms"]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    cap = None
    if args.capture:
        filt = "tcp port %d" % port
        if args.client_ip:
            filt += " and host %s" % args.client_ip
        cap = subprocess.Popen(["dumpcap", "-i", args.iface, "-f", filt, "-w", args.capture],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
    print("READY", flush=True)
    for (cond, pcap) in session_order(spec):
        txns = spec["replay"][pcap]
        conn, _ = srv.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            for (req_hex, resp_hex, native_ms, native_sep) in txns:
                conn.recv(65535)  # lock-step request
                if cond == "native" and native_sep:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                delay = max(native_ms, edt) if cond == "coalesced_edt" else native_ms
                if cond != "native" or not native_sep:
                    delay = min(delay, win - 8.0)     # stay inside the delayed-ACK window -> combined
                if delay > 0:
                    time.sleep(delay / 1000.0)
                conn.sendall(bytes.fromhex(resp_hex))
        finally:
            conn.close()
    if cap:
        time.sleep(0.8)
        cap.terminate()
        try:
            cap.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cap.kill()
    srv.close()
    print("DONE", flush=True)
    return 0


def client(args):
    spec = load_spec(args.spec)
    port = spec["port"]
    sent = ok = 0
    for (cond, pcap) in session_order(spec):
        txns = spec["replay"][pcap]
        conn = None
        for _ in range(80):
            try:
                conn = socket.create_connection((args.hulk_ip, port), timeout=5)
                break
            except OSError:
                time.sleep(0.1)
        if conn is None:
            print(json.dumps({"error": "connect failed", "session": [cond, pcap]}), flush=True)
            return 1
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            for (req_hex, resp_hex, _native_ms, _native_sep) in txns:
                conn.sendall(bytes.fromhex(req_hex))
                exp = bytes.fromhex(resp_hex)
                got = recv_exact(conn, len(exp), time.time() + 8.0)
                sent += 1
                ok += 1 if got == exp else 0
                time.sleep(0.003)
        finally:
            conn.close()
        time.sleep(0.05)
    print(json.dumps({"sent": sent, "byte_ok": ok}), flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--role", required=True, choices=["server", "client"])
    ap.add_argument("--spec", required=True)
    ap.add_argument("--iface", default="eno1")
    ap.add_argument("--capture", default=None, help="server: local pcap path to write")
    ap.add_argument("--client-ip", default=None, help="server: restrict capture to this peer")
    ap.add_argument("--hulk-ip", default=None, help="client: server address to connect to")
    args = ap.parse_args()
    return serve(args) if args.role == "server" else client(args)


if __name__ == "__main__":
    sys.exit(main())
