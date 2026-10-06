"""Compare two live snapshots table by table. Counters, statistics, registers and timestamps are runtime state and are reported separately from configuration.
Usage: compare_snapshots.py A.json[.gz] B.json[.gz]   exit 0 if no configuration table differs."""
import gzip
import json
import sys

# Runtime STATE, not configuration: counters, statistics, and the program's registers (a cold start resets them by design).
NOISE_TABLES = ("tm.counter", "$PORT_STAT", "$PORT_FEC", "$PORT_RS_FEC", "$PORT_FEC_STAT", "$MIRROR_STAT", "log_tbl_counter",
                "tbl_dbg_counter", "tf1.log_tbl_counter", "pipe.Ingress.reg_", "pipe.Ingress.ctr_", "pipe.Egress.reg_", "pipe.Egress.ctr_")
NOISE_SUBSTR = ("counter", ".reg_", ".ctr_")
ALIAS_STATE = ("eg_port", "ig_port", "pool", "dpg", "ig_port_ctr", "eg_port_ctr")   # short aliases of the tm.counter.* tables
NOISE_FIELDS = {"$PORT_UP", "$TIMESTAMP_1588_VALUE", "$TIMESTAMP_1588_ID", "time_ns"}


def load(p):
    return json.load((gzip.open if p.endswith(".gz") else open)(p, "rt"))


def norm(x, drop=()):
    if isinstance(x, dict):
        return {k: norm(v, drop) for k, v in sorted(x.items()) if k not in drop and k != "is_default_entry"}
    if isinstance(x, list):
        return sorted((norm(i, drop) for i in x), key=lambda i: json.dumps(i, sort_keys=True))
    return x


def compare(a, b, ignore_link_state=True):
    ta, tb = a["tables"], b["tables"]
    drop = NOISE_FIELDS if ignore_link_state else set()
    cfg, noise, missing = [], [], sorted(set(ta) ^ set(tb))
    for n in sorted(set(ta) & set(tb)):
        same = all(norm(ta[n].get(k), drop) == norm(tb[n].get(k), drop) for k in ("entries", "default"))
        if not same:
            (noise if n.startswith(NOISE_TABLES) or n in ALIAS_STATE or any(x in n for x in NOISE_SUBSTR) else cfg).append(n)
    return {"configuration_differs": cfg, "state_differs": noise, "only_in_one": missing, "tables": len(set(ta) & set(tb))}


if __name__ == "__main__":
    r = compare(load(sys.argv[1]), load(sys.argv[2]))
    print(json.dumps(r, indent=1))
    sys.exit(1 if r["configuration_differs"] or r["only_in_one"] else 0)
