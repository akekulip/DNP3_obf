#!/usr/bin/env python3
"""Reduce the committed ##VEC## byte-vectors into u_SBO(K) / u_READ(N) size tables.

Input : one JSON object per line (the emitter's ##VEC## payload), from the real
        opendnp3 master/outstation serializations.
Output: derived_sizes.json with, per axis, the exact serialized sizes measured from
        bytes, the fitted linear model a + b*x, and a check against the hypotheses.

Nothing here re-invents bytes; it only counts and fits what the C++ harness serialized.
"""
import json
import math
import sys


def link_size(u: int) -> int:
    return 10 + u + 2 * math.ceil(u / 16.0)


def fit_linear(xs, ys):
    """Exact 2-point / least-squares slope+intercept over integer samples."""
    n = len(xs)
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    if denom == 0:
        return None, None
    b = (n * sxy - sx * sy) / denom
    a = (sy - b * sx) / n
    return a, b


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "evidence/vectors.jsonl"
    dst = sys.argv[2] if len(sys.argv) > 2 else "evidence/derived_sizes.json"

    vecs = []
    with open(src) as f:
        for line in f:
            line = line.strip()
            if line:
                vecs.append(json.loads(line))

    out = {
        "_meta": {
            "provenance": "DERIVED from committed ##VEC## byte-vectors emitted by real "
                          "opendnp3 master/outstation serializations (software only).",
            "link_size_model": "link_size(u) = 10 + u + 2*ceil(u/16)",
        },
        "sbo": {},
        "read": {},
        "intersections": [],
    }

    # ---- SBO: per qualifier mode, u_echo(K) and wire, fit + compare to 9 + 12K ----
    for qmode in ("allow_one_byte", "always_two_bytes"):
        rows = sorted([v for v in vecs if v.get("kind") == "sbo" and v.get("qmode") == qmode],
                      key=lambda v: v["K"])
        if not rows:
            continue
        ks = [r["K"] for r in rows]
        u_echo = [r["u_echo"] for r in rows]
        u_req = [r["u_req"] for r in rows]
        a_e, b_e = fit_linear(ks, u_echo)
        a_r, b_r = fit_linear(ks, u_req)
        headers = sorted({r["g12_headers"] for r in rows})
        out["sbo"][qmode] = {
            "one_shared_header": headers == [1],
            "g12_headers_observed": headers,
            "u_echo_model": f"{round(a_e)} + {round(b_e)}K",
            "u_req_model": f"{round(a_r)} + {round(b_r)}K",
            "matches_relay_u_sbo_9_plus_12K": (round(a_e) == 9 and round(b_e) == 12),
            "samples": [
                {
                    "K": r["K"],
                    "select_echo_bytes": r["select_echo_bytes"],
                    "u_echo": r["u_echo"],
                    "wire_echo": r["wire_echo"],
                    "u_req": r["u_req"],
                    "wire_req": r["wire_req"],
                }
                for r in rows
            ],
        }

    # ---- READ: per object type, u_read(N) and wire, fit + compare to hypotheses ----
    hypo = {"G30V1": (10, 5), "G10V2": (10, 1)}
    for obj in ("G30V1", "G10V2"):
        rows = sorted([v for v in vecs if v.get("kind") == "read" and v.get("obj") == obj],
                      key=lambda v: v["total_points"])
        if not rows:
            continue
        ns = [r["total_points"] for r in rows]
        us = [r["u_read"] for r in rows]
        a, b = fit_linear(ns, us)
        ha, hb = hypo[obj]
        out["read"][obj] = {
            "u_read_model": f"{round(a)} + {round(b)}N",
            "matches_hypothesis": (round(a) == ha and round(b) == hb),
            "hypothesis": f"{ha} + {hb}N",
            "samples": [
                {"N": r["total_points"], "app_bytes": r["app_bytes"], "u_read": r["u_read"], "wire": r["wire"]}
                for r in rows
            ],
        }

    # ---- native-size intersections (relay 0x17 SBO echo) between the two axes ----
    # For SBO K CROBs the relay echo has u = 9 + 12K. A READ matches when its u is equal:
    #   G10V2: 10 + N   = 9 + 12K  -> N = 12K - 1            (integer for every K)
    #   G30V1: 10 + 5N  = 9 + 12K  -> N = (12K - 1) / 5      (integer iff K % 5 == 3)
    for k in range(1, 13):
        u = 9 + 12 * k
        n_g10 = 12 * k - 1
        n_g30 = (12 * k - 1) / 5.0
        row = {
            "sbo_K": k,
            "u_sbo": u,
            "target_wire_B": link_size(u),
            "g10v2_N": n_g10,  # always an integer -> a G10V2 READ always matches an SBO K
            "g10v2_matches": (10 + n_g10) == u,
            "g30v1_N": (int(n_g30) if n_g30.is_integer() else None),
            "g30v1_matches": n_g30.is_integer(),
        }
        out["intersections"].append(row)

    with open(dst, "w") as f:
        json.dump(out, f, indent=2)

    # human summary
    print("DERIVED SIZE TABLES (from real serialized bytes)\n")
    for qmode, d in out["sbo"].items():
        print(f"SBO [{qmode}]: u_echo = {d['u_echo_model']}  one-shared-header={d['one_shared_header']}"
              f"  matches_relay(9+12K)={d['matches_relay_u_sbo_9_plus_12K']}")
        for s in d["samples"]:
            print(f"    K={s['K']:>2}  echo_APDU={s['select_echo_bytes']:>3}B  u_echo={s['u_echo']:>3}"
                  f"  wire_echo={s['wire_echo']:>3}B")
    for obj, d in out["read"].items():
        print(f"READ [{obj}]: u_read = {d['u_read_model']}  matches_hypothesis({d['hypothesis']})="
              f"{d['matches_hypothesis']}")
        for s in d["samples"]:
            print(f"    N={s['N']:>2}  app={s['app_bytes']:>3}B  u_read={s['u_read']:>3}  wire={s['wire']:>3}B")
    print("\nINTERSECTIONS (relay 0x17 SBO echo u=9+12K vs READ u):")
    print("    SBO_K  wire_B   G10V2_N(=12K-1)   G30V1_N(int iff K%5==3)")
    for it in out["intersections"]:
        g30 = it["g30v1_N"] if it["g30v1_matches"] else "-"
        print(f"    {it['sbo_K']:>4}   {it['target_wire_B']:>5}     {it['g10v2_N']:>6}            {g30:>6}")
    print(f"\nwrote {dst}")


if __name__ == "__main__":
    main()
