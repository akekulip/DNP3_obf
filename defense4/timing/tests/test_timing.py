#!/usr/bin/env python3
"""Tests for the timing extraction and analysis.

Runs without pytest so the reproduction has no test-framework dependency:
    python3 tests/test_timing.py
Every check prints its own name and PASS/FAIL with the observed value. The process exits
non-zero if anything fails.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

TIMING_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TIMING_ROOT / "analysis"))

from dnp3_timing import (FUNC_OPERATE, FUNC_READ, FUNC_SELECT, TCP_ACK,  # noqa: E402
                         Transaction, extract_transactions, read_packets, read_txn_rows)
from pcap_reader import decode_tcp, iter_frames  # noqa: E402

EVID = TIMING_ROOT / "evidence" / "final_read_sbo"
RAW = EVID / "raw_pcaps"
FROZEN = EVID / "derived_csv"

CAPTURES = ["e1_native.pcap", "e2_def_read.pcap", "e2_def.pcap",
            "sbo_j2.pcap", "sbo_j6.pcap", "sbo_j12.pcap"]

# Expected analysed sample counts after cold-start exclusion. Locked so a silent change in
# extraction or exclusion shows up as a failure rather than as a quietly different result.
EXPECTED_ANALYSED = {
    ("native_txn.csv", FUNC_READ): 999,
    ("native_txn.csv", FUNC_SELECT): 488,
    ("defended_read_txn.csv", FUNC_READ): 599,
    ("defended_txn.csv", FUNC_SELECT): 499,
}
EXPECTED_OPERATE_PER_J = 30

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    print("  [%s] %-58s %s" % ("PASS" if condition else "FAIL", name, detail))
    return bool(condition)


# ---------------------------------------------------------------------------------------
def test_monotonic_timestamps():
    for cap in CAPTURES:
        last, ok, worst = None, True, None
        for t_ns, _ in iter_frames(RAW / cap):
            if last is not None and t_ns < last:
                ok, worst = False, (last, t_ns)
                break
            last = t_ns
        check("monotonic capture timestamps: %s" % cap, ok,
              "" if ok else "regression at %r" % (worst,))


def test_tcp_direction_and_endpoints():
    from dnp3_timing import MASTER, RELAY
    for cap in CAPTURES:
        bad = 0
        for _t, frame in iter_frames(RAW / cap):
            d = decode_tcp(frame)
            if d is None:
                continue
            if {d["src"], d["dst"]} != {MASTER, RELAY}:
                bad += 1
        check("every TCP packet is master<->relay: %s" % cap, bad == 0,
              "off-flow packets=%d" % bad)


def test_request_ack_response_pairing():
    for cap in CAPTURES:
        txns = extract_transactions(RAW / cap)
        missing_ack = sum(1 for t in txns if t.t_ack_ns is None)
        missing_resp = sum(1 for t in txns if t.t_resp_ns is None)
        check("every request has an ACK: %s" % cap, missing_ack == 0,
              "missing=%d of %d" % (missing_ack, len(txns)))
        check("every request has a response: %s" % cap, missing_resp == 0,
              "missing=%d of %d" % (missing_resp, len(txns)))


def test_ordering_within_transaction():
    """T_req <= T_ack <= T_resp for every paired transaction, and CLRT strictly positive."""
    for cap in CAPTURES:
        bad_order = bad_clrt = 0
        for t in extract_transactions(RAW / cap):
            if t.t_ack_ns is None or t.t_resp_ns is None:
                continue
            if not (t.t_req_ns <= t.t_ack_ns <= t.t_resp_ns):
                bad_order += 1
            if not (t.clrt_ms > 0):
                bad_clrt += 1
        check("T_req <= T_ack <= T_resp: %s" % cap, bad_order == 0, "violations=%d" % bad_order)
        check("CLRT strictly positive: %s" % cap, bad_clrt == 0, "violations=%d" % bad_clrt)


def test_function_codes():
    seen = {}
    for cap in CAPTURES:
        codes = {t.req_func for t in extract_transactions(RAW / cap)}
        seen[cap] = codes
        check("only READ/SELECT/OPERATE requests: %s" % cap,
              codes <= {FUNC_READ, FUNC_SELECT, FUNC_OPERATE}, "codes=%s" % sorted(codes))
    check("READ is function 1", FUNC_READ == 1)
    check("SELECT is function 3", FUNC_SELECT == 3)
    check("OPERATE is function 4", FUNC_OPERATE == 4)
    check("native capture carries READ and SELECT only",
          seen["e1_native.pcap"] == {FUNC_READ, FUNC_SELECT}, str(sorted(seen["e1_native.pcap"])))
    for J in (2, 6, 12):
        cap = "sbo_j%d.pcap" % J
        check("SBO capture carries OPERATE: %s" % cap, FUNC_OPERATE in seen[cap])


def test_no_duplicate_transactions():
    for cap in CAPTURES:
        txns = extract_transactions(RAW / cap)
        ids = [t.txn for t in txns]
        starts = [t.t_req_ns for t in txns]
        check("transaction ids unique: %s" % cap, len(set(ids)) == len(ids))
        check("no two transactions share a request time: %s" % cap,
              len(set(starts)) == len(starts),
              "duplicates=%d" % (len(starts) - len(set(starts))))


def test_cold_start_handling():
    for cap in CAPTURES:
        txns = extract_transactions(RAW / cap)
        cold = [t for t in txns if t.cold]
        syns = sum(1 for p in read_packets(RAW / cap)
                   if p.from_master and (p.flags & 0x02))
        check("one cold-start flag per connection: %s" % cap, len(cold) == syns,
              "cold=%d syn=%d" % (len(cold), syns))
        check("cold-start transactions are the earliest: %s" % cap,
              all(c.txn <= len(txns) for c in cold) and cold[0].txn == 1 if cold else True)


def test_deterministic_sample_counts():
    for (fname, func), expected in EXPECTED_ANALYSED.items():
        rows = [r for r in read_txn_rows(FROZEN / fname) if int(r["req_func"]) == func]
        analysed = [r for r in rows
                    if r["cold"].strip() in ("0", "") and r["clrt_ms"].strip()]
        check("analysed count %s func=%d" % (fname, func), len(analysed) == expected,
              "got %d expected %d" % (len(analysed), expected))
    for J in (2, 6, 12):
        rows = list(csv.DictReader(open(FROZEN / ("sbo_j%d.csv" % J))))
        check("OPERATE count J=%d" % J, len(rows) == EXPECTED_OPERATE_PER_J,
              "got %d expected %d" % (len(rows), EXPECTED_OPERATE_PER_J))


def test_no_silent_clipping():
    """Every request in a capture must appear as a row; extraction may not drop observations."""
    for cap, fname in [("e1_native.pcap", "native_txn.csv"),
                       ("e2_def_read.pcap", "defended_read_txn.csv"),
                       ("e2_def.pcap", "defended_txn.csv")]:
        n_txn = len(extract_transactions(RAW / cap))
        n_rows = len(read_txn_rows(FROZEN / fname))
        check("no observation dropped: %s" % cap, n_txn == n_rows,
              "extracted=%d rows_in_frozen_csv=%d" % (n_txn, n_rows))


def test_padding_is_not_payload():
    """A padded pure ACK must report zero payload, not the Ethernet padding bytes."""
    padded = 0
    for _t, frame in iter_frames(RAW / "e1_native.pcap"):
        d = decode_tcp(frame)
        if d is None:
            continue
        if (d["flags"] & TCP_ACK) and len(frame) == 60 and len(d["payload"]) == 0:
            padded += 1
    check("padded pure ACKs report zero payload", padded > 0,
          "padded ACKs seen=%d" % padded)


def test_no_hardcoded_results_in_figure_sources():
    """No published measurement may appear as a numeric literal in figure code.

    The check is done on the parsed syntax tree, not on the file text, so numbers quoted in
    a docstring or in a caption string are correctly ignored — a caption is allowed, and
    expected, to state the result in words. What must never happen is a measurement being
    typed into the plotting code, because then the figure would stop tracking the data.

    Design constants are not measurements and are permitted: the configured R-A = 4 ms
    reference line, the 0.5 chance baseline, axis limits and bin edges.
    """
    import ast

    measurements = [1.272, 2.107, 12.275, 18.178, 0.4243563, 0.5921017, 0.0018367,
                    0.592, 1.354, 2.5296, 0.0222, 0.0212]
    counts = {999, 488, 599, 499, 1489}
    bad = []
    for p in sorted((TIMING_ROOT / "figures" / "source").glob("fig_T*.py")):
        tree = ast.parse(p.read_text())
        hits = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            v = node.value
            if isinstance(v, bool):
                continue
            if isinstance(v, float):
                for m in measurements:
                    if abs(v - m) < 1e-6:
                        hits.append((v, node.lineno))
            elif isinstance(v, int) and v in counts:
                hits.append((v, node.lineno))
        if hits:
            bad.append((p.name, hits))
    check("no published measurement hard-coded in figure code", not bad, str(bad))


def test_stats_reproduce_frozen_verdict():
    """Regenerated statistics must agree with the frozen VERDICT to its stated precision."""
    stats_path = TIMING_ROOT / "build" / "timing_stats.json"
    if not stats_path.exists():
        check("timing_stats.json present (run reproduce.sh first)", False, str(stats_path))
        return
    st = json.load(open(stats_path))
    frozen = json.load(open(EVID / "audit" / "VERDICT.json"))
    c = st["clrt_stats"]
    f = frozen["timing_CLRT"]
    pairs = [("native_READ", f["native_CLRT_ms"]["READ"]),
             ("native_SELECT", f["native_CLRT_ms"]["SELECT"]),
             ("defended_READ", f["defended_CLRT_ms"]["READ"]),
             ("defended_SELECT", f["defended_CLRT_ms"]["SELECT"])]
    for key, fz in pairs:
        got = c[key]
        check("%s n matches frozen" % key, got["n"] == fz["n"],
              "got %d frozen %d" % (got["n"], fz["n"]))
        check("%s median matches frozen" % key, abs(got["median"] - fz["median"]) < 5e-4,
              "got %.4f frozen %.4f" % (got["median"], fz["median"]))
        check("%s std matches frozen" % key, abs(got["std"] - fz["std"]) < 5e-3,
              "got %.4f frozen %.4f" % (got["std"], fz["std"]))
    mi = st["MI_class_CLRT_bits_commonbins"]
    fm = frozen["formby"]["MI_class_CLRT_bits_commonbins"]
    check("MI native matches frozen", abs(mi["native"] - fm["native"]) < 1e-3,
          "got %.5f frozen %.5f" % (mi["native"], fm["native"]))
    check("MI defended matches frozen", abs(mi["defended"] - fm["defended"]) < 1e-3,
          "got %.5f frozen %.5f" % (mi["defended"], fm["defended"]))
    check("MI defended lies inside its permutation null",
          mi["defended"] <= mi["defended_perm_null_ci"][1],
          "%.6f vs null hi %.6f" % (mi["defended"], mi["defended_perm_null_ci"][1]))
    clf = st["classifier"]
    fc = frozen["formby"]["classifier"]
    check("classifier native BA matches frozen",
          abs(clf["native_balanced_acc"] - fc["native_balanced_acc"]) < 5e-3,
          "got %.4f frozen %.4f" % (clf["native_balanced_acc"], fc["native_balanced_acc"]))
    check("classifier defended BA matches frozen",
          abs(clf["defended_balanced_acc"] - fc["defended_balanced_acc"]) < 5e-3,
          "got %.4f frozen %.4f" % (clf["defended_balanced_acc"], fc["defended_balanced_acc"]))


def main():
    print("Timing test suite")
    print("evidence: %s\n" % EVID)
    for fn in [test_monotonic_timestamps, test_tcp_direction_and_endpoints,
               test_request_ack_response_pairing, test_ordering_within_transaction,
               test_function_codes, test_no_duplicate_transactions,
               test_cold_start_handling, test_deterministic_sample_counts,
               test_no_silent_clipping, test_padding_is_not_payload,
               test_no_hardcoded_results_in_figure_sources,
               test_stats_reproduce_frozen_verdict]:
        print("%s:" % fn.__name__)
        fn()
        print()
    n_fail = sum(1 for _, ok, _ in RESULTS if not ok)
    print("RESULT: %s  (%d checks, %d failed)"
          % ("PASS" if n_fail == 0 else "FAIL", len(RESULTS), n_fail))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
