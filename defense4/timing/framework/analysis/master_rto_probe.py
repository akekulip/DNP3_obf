#!/usr/bin/env python3
"""Measure the MASTER's own TCP retransmission timer on the DNP3 connection, with the kernel's own view alongside the wire.

Same method as audit_current/master_rto_20260916/master_rto.py (one connection; drop everything inbound from the outstation on THAT 4-tuple only; send one
READ; nothing can acknowledge it, so the master's stack retransmits on its own timer and the capture records every attempt), with two additions the Phase 9 plan
asks for: TCP_INFO (rto, rtt, rttvar, retransmits, backoff) is sampled on the same socket before the drop and every 20 ms during it. Run as root on the master host:
    master_rto_probe.py OUT.json OUT.pcap [HOLD_S] [IFACE]
Refuses to start if a rule with the probe comment already exists; the rule is removed and its absence verified in a `finally`."""
import json
import socket
import struct
import subprocess
import sys
import time

RELAY, PORT = "192.168.10.7", 20000
READ = bytes.fromhex("05640dc400000100f387c0c0010a020000165a2c")      # the frozen READ builder's frame for seq 0 (g10v2, points 0..22)
COMMENT = "master-rto-probe"
TCP_INFO = 11


def tcp_info(sock):
    b = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 232)
    return {"state": b[0], "retransmits": b[2], "probes": b[3], "backoff": b[4],
            "rto_us": struct.unpack_from("<I", b, 8)[0], "unacked": struct.unpack_from("<I", b, 24)[0],
            "total_retrans": struct.unpack_from("<I", b, 36)[0],
            "rtt_us": struct.unpack_from("<I", b, 68)[0], "rttvar_us": struct.unpack_from("<I", b, 72)[0]}


def ipt(*args):
    return subprocess.run(["iptables", *args], capture_output=True, text=True).returncode


def main(argv):
    out_json, out_pcap = argv[0], argv[1]
    hold = float(argv[2]) if len(argv) > 2 else 30.0
    iface = argv[3] if len(argv) > 3 else "enp59s0f0np0"
    stale = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True).stdout.count(COMMENT)
    if stale:
        print(json.dumps({"refused": "a %s rule already exists" % COMMENT}))
        return 2
    rec = {"started_at": time.time(), "hold_s": hold, "iface": iface}
    s = socket.create_connection((RELAY, PORT), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sport = s.getsockname()[1]
    rec["four_tuple"] = "%s:%d -> %s:%d" % (s.getsockname()[0], sport, RELAY, PORT)
    rec["tcp_info_idle"] = tcp_info(s)
    cap = subprocess.Popen(["tcpdump", "-i", iface, "-w", out_pcap, "--time-stamp-precision=nano", "-U", "-s", "128", "tcp port %d" % sport],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    rule = ["-p", "tcp", "-s", RELAY, "--sport", str(PORT), "--dport", str(sport), "-m", "comment", "--comment", COMMENT, "-j", "DROP"]
    rec["install_rc"] = ipt("-A", "INPUT", *rule)
    rec["verify_installed_rc"] = ipt("-C", "INPUT", *rule)
    samples = []
    try:
        if rec["install_rc"] == 0 and rec["verify_installed_rc"] == 0:
            t0 = time.time()
            s.sendall(READ)
            rec["sent_at"] = t0
            while time.time() - t0 < hold:
                samples.append(dict(t=time.time() - t0, **tcp_info(s)))
                time.sleep(0.02)
    finally:
        rec["remove_rc"] = ipt("-D", "INPUT", *rule)
        rec["absent_rc"] = ipt("-C", "INPUT", *rule)                     # 1 == absent
        rec["cleanup_verified"] = (rec["remove_rc"] == 0 and rec["absent_rc"] == 1)
        time.sleep(1.0)
        cap.terminate()
        cap.wait(timeout=10)
        try:
            s.close()
        except OSError:
            pass
    rec["tcp_info_samples"] = samples
    open(out_json, "w").write(json.dumps(rec, indent=1))
    print(json.dumps({k: v for k, v in rec.items() if k != "tcp_info_samples"}))
    return 0 if rec["cleanup_verified"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
