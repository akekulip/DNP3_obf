import socket, struct, time, sys
SO_TXTIME = 61; SCM_TXTIME = 61; CLOCK_MONOTONIC = 1
DELAY_NS = 30_000_000
rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", 0))
rx.settimeout(2.0); port = rx.getsockname()[1]
def one(use_txtime):
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmsg = []
    if use_txtime:
        tx.setsockopt(socket.SOL_SOCKET, SO_TXTIME, struct.pack("=iI", CLOCK_MONOTONIC, 0))
        txtime = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + DELAY_NS
        cmsg = [(socket.SOL_SOCKET, SCM_TXTIME, struct.pack("=Q", txtime))]
    t0 = time.perf_counter()
    tx.sendmsg([b"PING"], cmsg, 0, ("127.0.0.1", port))
    try:
        rx.recvfrom(64); dt = (time.perf_counter() - t0) * 1000
        return dt
    except socket.timeout:
        return None
    finally:
        tx.close()
base = [one(False) for _ in range(5)]
edt  = [one(True)  for _ in range(5)]
base = [x for x in base if x is not None]; edt = [x for x in edt if x is not None]
def med(v): 
    v=sorted(v); return v[len(v)//2] if v else None
print("no-txtime  arrival median: %.3f ms (n=%d)" % (med(base), len(base)))
print("SO_TXTIME  arrival median: %s ms (n=%d)" % ("%.3f"%med(edt) if edt else "N/A", len(edt)))
if edt and med(edt) > 20:
    print("=> fq ENFORCED the SO_TXTIME EDT (~30 ms hold): enforcement half VALIDATED non-sudo.")
elif edt:
    print("=> fq did NOT hold the packet (~0 ms): fq is not pacing by tstamp in this config.")
