#!/usr/bin/env python3
"""pcap -> per-transaction CLRT CSV.

Usage: extract_clrt.py <pcap> <class> <mode> <out.csv>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3_timing import extract_transactions, write_txn_csv, FUNC_NAME  # noqa: E402


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    pcap, cls, mode, out = sys.argv[1:5]
    txns = extract_transactions(pcap)
    write_txn_csv(txns, out, cls, mode)
    by_func = {}
    missing = 0
    for t in txns:
        by_func[FUNC_NAME.get(t.req_func, t.req_func)] = \
            by_func.get(FUNC_NAME.get(t.req_func, t.req_func), 0) + 1
        if t.clrt_ms is None:
            missing += 1
    print("  %-22s -> %-28s %s  cold=%d  unpaired=%d"
          % (Path(pcap).name, Path(out).name, by_func,
             sum(t.cold for t in txns), missing))


if __name__ == "__main__":
    main()
