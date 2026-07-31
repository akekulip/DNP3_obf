"""Campaign counter reader — synchronized and using the shared counter map.

CORRECTIONS.md §4.1: Tofino Stats-ALU counters require an operations_execute(...,
"SyncCounters") before reading; from_hw=True alone can return a stale zero. The old
inline campaign reader called only entry_get(from_hw=True) with no sync, which weakened
the "exactly 64 admitted / 0 stale / 0 fail-open" claims. §4.2: it also hardcoded a
counter map that had drifted from the P4. This reader syncs once per array and indexes by
the shared control/counter_map.py, so a future P4 counter change cannot silently
under-read here.

Runs on the switch (python3.8, SDE site-packages on PYTHONPATH). Emits `CTR {json}`.
Exit 0 on a clean read, 2 on any failure (so the campaign can mark the block invalid).
"""
import json, os, sys
sys.path.insert(0, "/home/decps/d3")
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("/home/decps/d3/control", "/home/decps/d3",
           os.path.join(_HERE, "..", "control")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import bfrt_grpc.client as gc
import counter_map

PROG = os.environ.get("D3_PROG", "case_a_defense3")
CID = int(sys.argv[1]) if len(sys.argv) > 1 else 555


def main():
    i = gc.ClientInterface("localhost:50052", client_id=CID, device_id=0, notifications=None)
    i.bind_pipeline_config(PROG)
    b = i.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=0, pipe_id=0xffff)

    def read_array(table_name, name_to_index):
        tb = b.table_get(table_name)
        # SYNC once for the whole array before any read (CORRECTIONS.md §4.1).
        tb.operations_execute(tgt, "SyncCounters")
        out = {}
        for nm, ix in name_to_index.items():
            v = 0
            for d, _ in tb.entry_get(
                    tgt, [tb.make_key([gc.KeyTuple("$COUNTER_INDEX", ix)])],
                    {"from_hw": True}):
                x = d.to_dict().get("$COUNTER_SPEC_PKTS", 0)
                v = max(v, x if isinstance(x, int) else 0)
            out[nm] = v
        return out

    fresh = read_array("ctr_fresh", counter_map.CF)
    deq = read_array("ctr_deq", counter_map.CD)

    # queue drops for Q_HOLD (qid 1) and Q_BLOCK (qid 7)
    q = {}
    tq = b.table_get("tf1.tm.counter.queue")
    for qq in (1, 7):
        for d, _ in tq.entry_get(
                gc.Target(device_id=0, pipe_id=0),
                [tq.make_key([gc.KeyTuple("pg_id", 2), gc.KeyTuple("pg_queue", qq)])],
                {"from_hw": True}):
            q["qid%d" % qq] = d.to_dict().get("drop_count_packets")

    print("CTR " + json.dumps({"fresh": fresh, "deq": deq, "qdrops": q,
                               "synced": True}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print("CTR " + json.dumps({"error": str(e)[:200], "synced": False}))
        raise SystemExit(2)
