#!/usr/bin/env python3
"""pcap -> per-OPERATE SBO timing CSV (A, R, echo-ACK).

Usage: extract_sbo.py <pcap> <label> <out.csv>
"""
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dnp3_timing import extract_operate_timing, write_sbo_csv  # noqa: E402


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    pcap, label, out = sys.argv[1:4]
    rows = extract_operate_timing(pcap)
    write_sbo_csv(rows, out, label)
    A = [a for a, _, _ in rows]
    R = [r for _, r, _ in rows]
    D = [d for _, _, d in rows]
    print("  %-14s n_operate=%-3d A med=%6.2f  R med=%6.2f  echo-ACK med=%.3f std=%.3f"
          % (label, len(rows), st.median(A), st.median(R), st.median(D), st.pstdev(D)))


if __name__ == "__main__":
    main()
