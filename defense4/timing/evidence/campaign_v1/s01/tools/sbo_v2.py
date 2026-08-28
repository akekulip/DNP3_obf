#!/usr/bin/env python3
"""sbo_v2.py — corrected guarded SELECT->OPERATE driver (campaign v1 tooling).

Two defects fixed relative to relay_sbo_operate_guarded.py (which is FROZEN and untouched):
  1. the OPERATE reused the SELECT's application sequence number, so the outstation
     answered NO_SELECT for every operate.  DNP3 increments the sequence per request.
  2. the status parser could not extract the CROB status octet, so rejections were
     invisible in the driver's own summary.

SAFETY: the {1,3} guard is IMPORTED unchanged from relay_operate_guarded; every frame is
still passed through assert_frame_targets_authorized, so index 6 / breaker-close and
anything outside {1,3} is refused at construction exactly as before.
"""
import argparse, socket, sys, time
from relay_operate_guarded import build_select, build_operate, assert_frame_targets_authorized

RELAY_PORT = 20000
STAT = {0: "SUCCESS", 1: "TIMEOUT", 2: "NO_SELECT", 3: "FORMAT_ERROR", 4: "NOT_SUPPORTED",
        5: "ALREADY_ACTIVE", 6: "HARDWARE_ERROR", 7: "LOCAL", 8: "TOO_MANY_OPS",
        9: "NOT_AUTHORIZED", 10: "AUTOMATION_INHIBIT", 11: "PROCESSING_LIMITED",
        12: "OUT_OF_RANGE", 126: "NON_PARTICIPATING", 127: "UNDEFINED"}


def _userdata(p):
    out = bytearray(); i = 10
    while i < len(p):
        n = min(16, len(p) - i - 2)
        if n <= 0:
            break
        out += p[i:i + n]; i += n + 2
    return bytes(out)


def _recv_frame(s, timeout=2.0):
    """Read one complete DNP3 link frame, reassembling across TCP segments."""
    s.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return buf
        if not chunk:
            return buf
        buf += chunk
        j = buf.find(b"\x05\x64")
        if j >= 0 and len(buf) >= j + 3:
            ud = buf[j + 2] - 5
            if ud >= 0:
                total = 10 + ud + 2 * ((ud + 15) // 16)
                if len(buf) >= j + total:
                    return buf[j:j + total]


def _status(frame):
    """(app_func, crob_status) from a response frame, or (None, None)."""
    if not frame:
        return None, None
    u = _userdata(frame)
    if len(u) < 3:
        return None, None
    func = u[2]
    obj = u[5:]
    if func == 0x81 and len(obj) >= 16 and obj[0] == 12:
        return func, obj[15]
    return func, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--gap-ms", type=float, default=50.0)
    ap.add_argument("--relay", default="192.168.10.7")
    ap.add_argument("--src", default="192.168.10.1")
    ap.add_argument("--indices", default="1,3", help="MUST be exactly {1,3}; anything else refused")
    ap.add_argument("--select-only", action="store_true")
    a = ap.parse_args()

    indices = [int(x) for x in a.indices.split(",") if x.strip()]
    if sorted(indices) != [1, 3]:
        sys.exit("ABORT: --indices must be exactly {1,3}; got %r" % indices)
    assert_frame_targets_authorized(build_operate(0, indices))   # prove the guard accepts

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((a.src, 0))
    except OSError:
        pass
    s.connect((a.relay, RELAY_PORT))
    print("connected %s -> %s:%d  (%d SBO, indices=%s)" % (a.src, a.relay, RELAY_PORT, a.count, indices))

    ok_sel = ok_op = 0
    for i in range(a.count):
        sel_seq = (2 * i) & 0x0F
        op_seq = (2 * i + 1) & 0x0F           # <-- the fix: operate advances the sequence
        sel = build_select(sel_seq, indices); assert_frame_targets_authorized(sel)
        s.sendall(sel); f_s, st_s = _status(_recv_frame(s))
        if a.select_only:
            ok_sel += int(st_s == 0)
            print("  txn %3d SELECT seq=%x func=%s status=%s" % (i, sel_seq, f_s and hex(f_s), STAT.get(st_s, st_s)))
            time.sleep(a.gap_ms / 1e3); continue
        op = build_operate(op_seq, indices); assert_frame_targets_authorized(op)
        t0 = time.monotonic(); s.sendall(op); f_o, st_o = _status(_recv_frame(s))
        ok_sel += int(st_s == 0); ok_op += int(st_o == 0)
        print("  txn %3d SELECT seq=%x status=%-10s | OPERATE seq=%x status=%-10s | op_wall=%.2fms"
              % (i, sel_seq, STAT.get(st_s, st_s), op_seq, STAT.get(st_o, st_o),
                 (time.monotonic() - t0) * 1e3))
        time.sleep(a.gap_ms / 1e3)
    print("SUMMARY: SELECT ok %d/%d, OPERATE ok %d/%d" % (ok_sel, a.count, ok_op, a.count))
    s.close()


if __name__ == "__main__":
    main()
