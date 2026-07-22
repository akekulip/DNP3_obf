#!/usr/bin/env python3.8
"""mb_sample.py — switch-side GROUND-TRUTH rate sampler (run ON the switch during backlog).

dp9 is a hairpin: it RECEIVES Hulk's 64 B input and TRANSMITS the switch's shaped 128 B output.
So the dp9 MAC counters give clean, live, per-read rates immune to Hulk tcpdump loss / NIC
coalescing AND to the TM drop counter's ~5 s batch-sweep:
    input_pps   = d($FramesReceivedOK)/dt
    dequeue_pps = d($FramesTransmittedLength_128_255)/dt   (only shaped S1 leaves dp9)
Plus REAL_S1 queue depth (usage_cells) to confirm the queue is pinned (backlogged).

Usage: python3.8 mb_sample.py [n_seconds]     (default 22)
"""
import sys, time
SDE_PY = "/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages"
sys.path.insert(0, SDE_PY + "/tofino"); sys.path.insert(0, SDE_PY)
import bfrt_grpc.client as gc

PROG = "queue_microbench"
PG_ID_DP9, PGQ_REAL_S1 = 2, 9
TX_S1 = "$FramesTransmittedLength_128_255"
RX_OK = "$FramesReceivedOK"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 22

iface = gc.ClientInterface("localhost:50052", client_id=23, device_id=0, notifications=None)
iface.bind_pipeline_config(PROG)
bi = iface.bfrt_info_get(PROG)
tgtall = gc.Target(device_id=0, pipe_id=0xffff)
tgt0   = gc.Target(device_id=0, pipe_id=0)
ps = bi.table_get("$PORT_STAT")
qc = bi.table_get("tf1.tm.counter.queue")
kps = ps.make_key([gc.KeyTuple("$DEV_PORT", 9)])
kq  = qc.make_key([gc.KeyTuple("pg_id", PG_ID_DP9), gc.KeyTuple("pg_queue", PGQ_REAL_S1)])

def snap():
    tx = rx = 0
    for d, _ in ps.entry_get(tgtall, [kps], {"from_hw": True}):
        dd = d.to_dict(); tx = dd.get(TX_S1, 0); rx = dd.get(RX_OK, 0)
    use = 0
    for d, _ in qc.entry_get(tgt0, [kq], {"from_hw": True}):
        use = d.to_dict().get("usage_cells")
    return rx, tx, use

prx = ptx = None
deqs = []
print("sec  in_pps  DEQ_pps(shaped128)  use_cells")
for i in range(N):
    rx, tx, use = snap()
    if prx is not None:
        deq = tx - ptx
        deqs.append(deq)
        print("%3d  %6d  %6d  %d" % (i, rx - prx, deq, use))
    prx, ptx = rx, tx
    time.sleep(1)
if deqs:
    s = sorted(deqs); med = s[len(s)//2]
    print("DEQ_pps: median=%d min=%d max=%d mean=%.0f  (n=%d samples)"
          % (med, min(deqs), max(deqs), sum(deqs)/len(deqs), len(deqs)))
