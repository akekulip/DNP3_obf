"""Does the released interval's tail move with the master's inter-request spacing?

The blocks are `g<gap>_<arm>` from `_bin/run_phase_test.sh`: one arm, one policy, four spacings.
The relay does identical work in all of them, so any movement in the tail is arrival phase.

    python3 phase_test.py
"""
from __future__ import annotations
import csv, pathlib, statistics as st, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "evidence" / "campaign_v1" / "repro"))
import pcap_dnp3 as P                                             # noqa: E402

D_A_MS = 19.999872
PCAPS = HERE.parent / "raw_pcaps"


def main() -> int:
    caps = sorted(PCAPS.glob("g*_*.pcap"))
    if not caps:
        sys.exit("no g*_*.pcap under %s; run _bin/run_phase_test.sh first" % PCAPS)
    out = []
    print("%-8s %-4s %-8s %6s %10s %10s %10s %10s" %
          ("block", "arm", "class", "n", "idle med", "ack med", "tail med", "tail p95"))
    for cap in caps:
        stem = cap.name[: -len(".pcap")]
        gap, arm = stem.split("_", 1)
        rep = P.extract(str(cap))
        prev = None
        rows = []
        for i, x in enumerate(rep.exchanges):
            idle = None if prev is None else (x.t_req_ns - prev) / 1e6
            rows.append((P.FUNC_NAME.get(x.func, str(x.func)),
                         x.ack_gap_ns / 1e6, x.clrt_ns / 1e6, idle, i))
            prev = x.t_resp_ns
        for c in ("READ", "SELECT", "OPERATE"):
            v = [r for r in rows if r[0] == c and r[4] > 0 and r[3] is not None]
            if not v:
                continue
            ack = sorted(r[1] for r in v)
            tail = sorted(a - D_A_MS for a in ack)
            idl = [r[3] for r in v]
            print("%-8s %-4s %-8s %6d %10.4f %10.4f %10.4f %10.4f" %
                  (gap, arm, c, len(v), st.median(idl), st.median(ack),
                   st.median(tail), tail[int(0.95 * (len(tail) - 1))]))
            out.append(dict(block=gap, arm=arm, cls=c, n=len(v),
                            idle_med=st.median(idl), ack_med=st.median(ack),
                            tail_med=st.median(tail)))
    with open(HERE / "phase_test.csv", "w", newline="") as f:
        w = csv.DictWriter(f, ["block", "arm", "cls", "n", "idle_med", "ack_med", "tail_med"])
        w.writeheader(); w.writerows(out)
    print("\nwrote", HERE / "phase_test.csv")
    for arm in ("A0", "A1"):
        rd = [r for r in out if r["arm"] == arm and r["cls"] == "READ"]
        if len(rd) > 1:
            t = [r["tail_med"] for r in rd]
            print("  %s: READ tail median across the four spacings %s ms -> range %.4f ms"
                  % (arm, ["%.4f" % x for x in t], max(t) - min(t)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
