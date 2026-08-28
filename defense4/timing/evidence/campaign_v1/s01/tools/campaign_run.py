#!/usr/bin/env python3
"""campaign_run.py — v1 campaign block runner: interleaved READ + guarded SBO on ONE
DNP3 session, randomized spacing, single advancing application sequence.

Frozen artefacts are NOT modified: the guarded {1,3} builders and the read-frame builder
are imported unchanged, so index 6 / breaker-close remains refused at construction.

Emits a per-transaction JSONL log (application layer). Wire timing comes from the
master-facing pcap via the repository extractor; the two are joined on txn_id order.
"""
import argparse, json, random, socket, sys, time
from relay_operate_guarded import build_select, build_operate, assert_frame_targets_authorized
from relay_read_g10_23 import read_frame

STAT = {0: "SUCCESS", 1: "TIMEOUT", 2: "NO_SELECT", 3: "FORMAT_ERROR", 4: "NOT_SUPPORTED",
        5: "ALREADY_ACTIVE", 6: "HARDWARE_ERROR", 7: "LOCAL", 8: "TOO_MANY_OPS",
        9: "NOT_AUTHORIZED", 10: "AUTOMATION_INHIBIT", 11: "PROCESSING_LIMITED",
        12: "OUT_OF_RANGE"}


def ud(p):
    o = bytearray(); i = 10
    while i < len(p):
        n = min(16, len(p) - i - 2)
        if n <= 0: break
        o += p[i:i + n]; i += n + 2
    return bytes(o)


def recv(s, timeout=3.0):
    s.settimeout(timeout); buf = b""
    while True:
        try: c = s.recv(4096)
        except socket.timeout: return buf
        if not c: return buf
        buf += c
        j = buf.find(b"\x05\x64")
        if j >= 0 and len(buf) >= j + 3:
            n = buf[j + 2] - 5
            if n >= 0:
                tot = 10 + n + 2 * ((n + 15) // 16)
                if len(buf) >= j + tot: return buf[j:j + tot]


def parse(frame):
    """(app_func, crob_status_or_None)"""
    if not frame: return None, None
    u = ud(frame)
    if len(u) < 3: return None, None
    func = u[2]; obj = u[5:]
    if func == 0x81 and len(obj) >= 16 and obj[0] == 12:
        return func, obj[15]
    return func, None


def schedule(n_read, n_sbo, min_gap, rng):
    """Interleave n_sbo SBO slots among n_read reads with >= min_gap reads between them."""
    slots = ["R"] * n_read
    placed, tries = 0, 0
    idx = []
    while placed < n_sbo and tries < 100000:
        tries += 1
        p = rng.randrange(min_gap, n_read - min_gap)
        if all(abs(p - q) >= min_gap for q in idx):
            idx.append(p); placed += 1
    out = []
    idx = sorted(idx)
    for i, r in enumerate(slots):
        out.append("R")
        if i in idx: out.append("S")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", required=True)
    ap.add_argument("--block", required=True)
    ap.add_argument("--condition", required=True, help="native|obfuscated")
    ap.add_argument("--mode", required=True)
    ap.add_argument("--j-ms", default="")
    ap.add_argument("--n-read", type=int, default=400)
    ap.add_argument("--n-sbo", type=int, default=40)
    ap.add_argument("--min-gap", type=int, default=6)
    ap.add_argument("--gap-ms", type=float, default=20.0)
    ap.add_argument("--seed", type=int, default=20260827)
    ap.add_argument("--indices", default="1,3")
    ap.add_argument("--relay", default="192.168.10.7")
    ap.add_argument("--src", default="192.168.10.1")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    idxs = [int(x) for x in a.indices.split(",")]
    if sorted(idxs) != [1, 3]:
        sys.exit("ABORT: indices must be exactly {1,3}")
    assert_frame_targets_authorized(build_operate(0, idxs))

    rng = random.Random(a.seed)
    plan = schedule(a.n_read, a.n_sbo, a.min_gap, rng)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: s.bind((a.src, 0))
    except OSError: pass
    s.connect((a.relay, 20000))

    seq = 0; txn = 0; nread = nsel = nop = 0
    oks = {"SELECT": 0, "OPERATE": 0}
    fh = open(a.out, "w")
    t_block0 = time.time()
    for step, kind in enumerate(plan):
        if kind == "R":
            t0 = time.time(); s.sendall(read_frame(seq & 0xF)); f = recv(s); t1 = time.time()
            func, _ = parse(f)
            rec = dict(operation="READ", function_code=1, app_seq=seq & 0xF,
                       resp_func=func, status=None, valid=(func == 0x81))
            seq += 1; nread += 1
            rec.update(session_id=a.session, block_id=a.block, condition=a.condition,
                       mode=a.mode, j_ms=a.j_ms, txn_id=txn, step=step,
                       t_send=t0, t_recv=t1, rtt_ms=(t1 - t0) * 1e3)
            fh.write(json.dumps(rec) + "\n"); txn += 1
        else:
            sel = build_select(seq & 0xF, idxs); assert_frame_targets_authorized(sel)
            t0 = time.time(); s.sendall(sel); fs = recv(s); t1 = time.time()
            f1, st1 = parse(fs); sel_seq = seq & 0xF; seq += 1
            op = build_operate(seq & 0xF, idxs); assert_frame_targets_authorized(op)
            t2 = time.time(); s.sendall(op); fo = recv(s); t3 = time.time()
            f2, st2 = parse(fo); op_seq = seq & 0xF; seq += 1
            nsel += 1; nop += 1
            oks["SELECT"] += int(st1 == 0); oks["OPERATE"] += int(st2 == 0)
            for nm, fc, sq, ts, te, fu, stt in (("SELECT", 3, sel_seq, t0, t1, f1, st1),
                                                ("OPERATE", 4, op_seq, t2, t3, f2, st2)):
                fh.write(json.dumps(dict(session_id=a.session, block_id=a.block,
                         condition=a.condition, mode=a.mode, j_ms=a.j_ms, txn_id=txn,
                         step=step, operation=nm, function_code=fc, app_seq=sq,
                         resp_func=fu, status=STAT.get(stt, stt), valid=(stt == 0),
                         t_send=ts, t_recv=te, rtt_ms=(te - ts) * 1e3)) + "\n")
                txn += 1
        time.sleep(a.gap_ms / 1e3)
    fh.close(); s.close()
    print("block=%s cond=%s mode=%s J=%s  READ=%d SELECT=%d OPERATE=%d  "
          "SELECT ok=%d/%d OPERATE ok=%d/%d  wall=%.1fs"
          % (a.block, a.condition, a.mode, a.j_ms or "-", nread, nsel, nop,
             oks["SELECT"], nsel, oks["OPERATE"], nop, time.time() - t_block0))


if __name__ == "__main__":
    main()
