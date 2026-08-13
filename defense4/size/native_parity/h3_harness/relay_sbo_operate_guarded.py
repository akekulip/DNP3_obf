"""Guarded 2-CROB SELECT->OPERATE driver for the physical SEL-751 BOR run.

Runs on the MASTER leg (Vision, 192.168.10.1) and drives N Select-Before-Operate
transactions to the relay THROUGH the switch (which holds/releases the OPERATE per BOR).

SAFETY: every control frame is built via relay_operate_guarded (hard {1,3} guard;
index 6 / breaker-close and everything outside {1,3} is refused at construction).
A post-build sentinel re-checks each frame targets exactly {1,3} before it is sent.
This drives an OPERATE, so run it ONLY with Philip's explicit authorization and with
the isolation audit's {1,3} empty-fanout proof in force. Monitor relay outputs
(check_all_outputs.py / sel TAR) before and after; abort on any physical output assertion.

Usage (on Vision):
  python3 relay_sbo_operate_guarded.py --count 50 --gap-ms 50 [--relay 192.168.10.7] [--src 192.168.10.1]
Capture master-facing in parallel:  tcpdump/dumpcap on the Vision dp9 iface, host 192.168.10.7.
"""

import argparse
import socket
import sys
import time

from relay_operate_guarded import build_select, build_operate, assert_frame_targets_authorized
from dnp3_wire import deframe

RELAY_PORT = 20000


def _recv_frame(sock, timeout=2.0):
    """Read one DNP3 link frame's (userdata) from the socket, or None on timeout/close."""
    sock.settimeout(timeout)
    buf = b""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        frames = list(deframe(buf))
        if frames:
            _total, userdata = frames[0]
            return userdata
    return None


def _status(userdata):
    """Extract app func + first CROB status from an echo, for a quick SUCCESS check."""
    if not userdata or len(userdata) < 4:
        return None, None
    func = userdata[1]
    # G12V1 qual 0x17: obj = grp,var,qual,count, then (idx, CROB[11]) pairs; status is CROB byte 10.
    obj = userdata[3:]
    st = None
    if len(obj) >= 4 + 1 + 11 and obj[2] == 0x17:
        st = obj[4 + 1 + 10]  # first CROB status octet
    return func, st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--gap-ms", type=float, default=50.0)
    ap.add_argument("--relay", default="192.168.10.7")
    ap.add_argument("--src", default="192.168.10.1")
    ap.add_argument("--indices", default="1,3", help="MUST be a subset of {1,3}; guard refuses otherwise")
    args = ap.parse_args()

    indices = [int(x) for x in args.indices.split(",") if x.strip() != ""]
    # Pre-flight: prove the guard accepts these indices and refuses to build anything else.
    try:
        assert_frame_targets_authorized(build_operate(0, indices))
    except Exception as e:
        print("ABORT: guard rejected --indices %r: %s" % (indices, e))
        sys.exit(2)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.bind((args.src, 0))
    except OSError:
        pass  # binding is best-effort; the routing/iface picks the master leg
    s.connect((args.relay, RELAY_PORT))
    print("connected %s -> %s:%d  (%d guarded SBO txns, indices=%s)"
          % (args.src, args.relay, RELAY_PORT, args.count, indices))

    ok_sel = ok_op = 0
    for i in range(args.count):
        seq = i & 0x0F
        # --- SELECT (guarded {1,3}) ---
        sel = build_select(seq, indices)
        assert_frame_targets_authorized(sel)
        t_sel = time.monotonic()
        s.sendall(sel)
        rs = _recv_frame(s)
        f_s, st_s = _status(rs)
        # --- OPERATE (guarded {1,3}) ---
        op = build_operate(seq, indices)
        assert_frame_targets_authorized(op)
        t_op = time.monotonic()
        s.sendall(op)
        ro = _recv_frame(s)
        f_o, st_o = _status(ro)
        sel_ok = (f_s == 0x81 and st_s == 0)
        op_ok = (f_o == 0x81 and st_o == 0)
        ok_sel += int(sel_ok)
        ok_op += int(op_ok)
        print("  txn %3d seq=%x SELECT func=0x%s st=%s %s | OPERATE func=0x%s st=%s %s | op_wall=%.2fms"
              % (i, seq,
                 ("%02x" % f_s) if f_s is not None else "--", st_s, "OK" if sel_ok else "??",
                 ("%02x" % f_o) if f_o is not None else "--", st_o, "OK" if op_ok else "??",
                 (time.monotonic() - t_op) * 1e3))
        time.sleep(args.gap_ms / 1e3)

    s.close()
    print("SUMMARY: SELECT ok %d/%d, OPERATE ok %d/%d. "
          "Confirm relay OUT/TRIP contacts stayed 0 via check_all_outputs.py / TAR."
          % (ok_sel, args.count, ok_op, args.count))
    sys.exit(0 if (ok_sel == args.count and ok_op == args.count) else 1)


if __name__ == "__main__":
    main()
