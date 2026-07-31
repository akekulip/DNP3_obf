"""Campaign preflight: the loaded program must be the FINAL repaired build before any
block runs (CORRECTIONS.md §2.2/§4.3). Binds D3_PROG, asserts the R1/R2/R3 BFRT objects
are present, and (when given) checks the source SHA-256 of the loaded p4 against an
expected value. Prints `PREFLIGHT {json}`; exit 0 if the build is the final repaired
program, 2 otherwise (so the campaign aborts instead of measuring the wrong program).

Usage (on the switch):  python3 preflight.py [expected_source_sha256]
"""
import hashlib, json, os, sys
sys.path.insert(0, "/home/decps/d3")
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in ("/home/decps/d3/control", "/home/decps/d3",
           os.path.join(_HERE, "..", "control")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import bfrt_grpc.client as gc
import counter_map

PROG = os.environ.get("D3_PROG", "case_a_defense3")
EXPECT_SHA = sys.argv[1] if len(sys.argv) > 1 else None
# the loaded p4 source on the switch, if present, for the optional hash check
SRC_CANDIDATES = ("/home/decps/d3/%s.p4" % PROG,
                  "/home/decps/d3/case_a_defense3.p4")

REQUIRED = ("tbl_resp_authorise", "reg_failopen")


def main():
    rec = {"prog": PROG, "required": list(REQUIRED), "present": [], "absent": []}
    i = gc.ClientInterface("localhost:50052", client_id=901, device_id=0, notifications=None)
    i.bind_pipeline_config(PROG)
    b = i.bfrt_info_get(PROG)
    for name in REQUIRED:
        try:
            b.table_get(name)
            rec["present"].append(name)
        except Exception:
            rec["absent"].append(name)
    rec["cf_block_reject_index"] = counter_map.CF["BLOCK_REJECT"]

    # optional source-hash check (CORRECTIONS.md §2.2: expected source SHA-256)
    if EXPECT_SHA:
        rec["expected_sha256"] = EXPECT_SHA
        for p in SRC_CANDIDATES:
            if os.path.exists(p):
                got = hashlib.sha256(open(p, "rb").read()).hexdigest()
                rec["source_path"] = p
                rec["source_sha256"] = got
                rec["sha_match"] = (got == EXPECT_SHA)
                break
        else:
            rec["source_sha256"] = None
            rec["sha_match"] = None  # source not staged; not fatal on its own

    ok = (not rec["absent"]
          and rec["cf_block_reject_index"] == 17
          and rec.get("sha_match", True) is not False)
    rec["ok"] = ok
    print("PREFLIGHT " + json.dumps(rec, default=str))
    return 0 if ok else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print("PREFLIGHT " + json.dumps({"prog": PROG, "ok": False, "error": str(e)[:200]}))
        raise SystemExit(2)
