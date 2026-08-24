#!/usr/bin/env python3
"""Compare regenerated timing CSVs against the frozen ones, by SHA-256 and by value.

Byte equality is reported but is not the criterion. Two differences are expected and
harmless, and the comparison is built to show them for what they are rather than to hide
them:

  * timestamp columns are written at nanosecond precision here and at microsecond
    precision in the frozen files, so the files cannot be byte-identical;
  * measurement columns can differ by one unit in the last printed digit (0.001 ms),
    because the frozen pipeline computed intervals in float64 epoch seconds while this one
    subtracts integer nanoseconds. One microsecond is far below the resolution of the
    quantity being measured and moves no published statistic.

Anything larger than one last-digit unit is a real disagreement and is printed in full.

Usage: compare_frozen.py <regenerated_dir> <frozen_dir> [--tolerance-ms 0.001]
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

TXN_FILES = ["native_txn.csv", "defended_read_txn.csv", "defended_txn.csv"]
SBO_FILES = ["sbo_j2.csv", "sbo_j6.csv", "sbo_j12.csv"]
TXN_EXACT = ["class", "mode", "txn", "req_func", "req_len", "cold"]
TXN_NUMERIC = ["clrt_ms"]
SBO_EXACT = ["Jpolicy", "txn"]
SBO_NUMERIC = ["A_ms", "R_ms", "echo_ack_ms"]


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def rows(p):
    with open(p) as f:
        return list(csv.DictReader(f))


def compare(new, old, exact_cols, numeric_cols, tol):
    a, b = rows(new), rows(old)
    hard, n_last_digit, max_abs = [], 0, 0.0
    if len(a) != len(b):
        hard.append("row count %d (regenerated) vs %d (frozen)" % (len(a), len(b)))
    for i, (ra, rb) in enumerate(zip(a, b), start=1):
        for c in exact_cols:
            if ra.get(c, "") != rb.get(c, ""):
                hard.append("row %d column %s: %r vs %r" % (i, c, ra.get(c), rb.get(c)))
        for c in numeric_cols:
            va, vb = ra.get(c, "").strip(), rb.get(c, "").strip()
            if (va == "") != (vb == ""):
                hard.append("row %d column %s: %r vs %r (presence differs)" % (i, c, va, vb))
                continue
            if va == "":
                continue
            d = abs(float(va) - float(vb))
            max_abs = max(max_abs, d)
            if d > tol + 1e-12:
                hard.append("row %d column %s: %s vs %s (delta %.6f ms)" % (i, c, va, vb, d))
            elif d > 0:
                n_last_digit += 1

    same_bytes = sha256(new) == sha256(old)
    if hard:
        status = "MISMATCH"
    elif same_bytes:
        status = "IDENTICAL BYTES"
    else:
        status = "VALUES AGREE within %.3f ms" % tol
    print("  %-24s %-34s rows=%-5d last-digit diffs=%-5d max|delta|=%.6f ms"
          % (Path(new).name, status, len(a), n_last_digit, max_abs))
    for h in hard[:20]:
        print("      %s" % h)
    if len(hard) > 20:
        print("      ... and %d more" % (len(hard) - 20))
    return not hard


def main():
    argv = sys.argv[1:]
    tol = 0.001
    if "--tolerance-ms" in argv:
        i = argv.index("--tolerance-ms")
        tol = float(argv[i + 1])
        del argv[i:i + 2]
    new, old = Path(argv[0]), Path(argv[1])
    print("Regenerated vs frozen timing CSVs (tolerance %.3f ms = one last printed digit)"
          % tol)
    ok = True
    for f in TXN_FILES:
        ok &= compare(new / f, old / f, TXN_EXACT, TXN_NUMERIC, tol)
    for f in SBO_FILES:
        ok &= compare(new / f, old / f, SBO_EXACT, SBO_NUMERIC, tol)
    print("\nRESULT: %s" % (
        "every measured value reproduces within one last printed digit" if ok
        else "REAL DIFFERENCES FOUND — see above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
