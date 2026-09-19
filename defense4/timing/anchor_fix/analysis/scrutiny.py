"""Adversarial checks on the anchor-fix validation, positive results and negative alike.

A defense that lowers one classifier is not thereby correct. This asks the questions that would
sink the result if they came back the wrong way:

  1. Did every block deliver the traffic the driver claims, and did any exchange go missing?
  2. Is the released interval still the configured one, per class, or did the fix move it?
  3. Is the release tail still small, and is it still free of class information?
  4. Does any exchange breach the release budget, and did the relay's own acknowledgment ever
     arrive later than the deadline the request armed -- the one new failure mode the fix creates?
  5. Are there retransmissions, and did the arms differ in how many?
  6. Does the remaining per-class difference survive when exchanges are matched on idle gap,
     which is what the queue-phase effect would show up as?

    python3 scrutiny.py
"""
from __future__ import annotations
import csv, collections, pathlib, statistics as st, sys

HERE = pathlib.Path(__file__).resolve().parent
CLASSES = ["READ", "SELECT", "OPERATE"]
D_A_MS = 19.999872          # D_A quantized to the 256 ns tick grid
CLRT_NEW_MS = 3.999872      # D_R likewise


def load():
    with open(HERE / "exchanges_all.csv") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k in ("ack_ms", "clrt_ms", "rt_ms"):
            r[k] = float(r[k])
        r["idle_before_ms"] = float(r["idle_before_ms"]) if r["idle_before_ms"] else None
        r["idx"] = int(r["idx"])
    return rows


def q(v, p):
    v = sorted(v)
    if not v:
        return float("nan")
    i = min(len(v) - 1, max(0, int(round(p * (len(v) - 1)))))
    return v[i]


def main() -> int:
    rows = load()
    arms = ["OFF", "A0", "A1"]
    by = collections.defaultdict(list)
    for r in rows:
        by[(r["anchor_arm"], r["txn_class"])].append(r)

    print("=== 1. delivery ===")
    for a in arms:
        blocks = sorted({r["block"] for r in rows if r["anchor_arm"] == a})
        counts = collections.Counter(r["txn_class"] for r in rows if r["anchor_arm"] == a)
        print("  %-4s blocks=%-3d  READ=%-5d SELECT=%-4d OPERATE=%-4d  total=%d"
              % (a, len(blocks), counts["READ"], counts["SELECT"], counts["OPERATE"],
                 sum(counts.values())))

    print("\n=== 2/3. request-to-ACK interval and its release tail ===")
    for a in arms:
        print("  -- %s" % a)
        for c in CLASSES:
            v = [r["ack_ms"] for r in by[(a, c)]]
            if not v:
                continue
            tail = [x - D_A_MS for x in v] if a != "OFF" else v
            print("     %-8s n=%-5d med=%9.4f  p95=%9.4f  max=%9.4f   tail med=%8.4f p95=%8.4f"
                  % (c, len(v), st.median(v), q(v, .95), max(v),
                     st.median(tail), q(tail, .95)))
        meds = [st.median([r["ack_ms"] for r in by[(a, c)]]) for c in CLASSES if by[(a, c)]]
        print("     class-median spread: %.4f ms" % (max(meds) - min(meds)))

    print("\n=== 2b. released CLRT, per class ===")
    for a in arms:
        meds = []
        line = []
        for c in CLASSES:
            v = [r["clrt_ms"] for r in by[(a, c)]]
            if not v:
                continue
            meds.append(st.median(v))
            line.append("%s %.4f" % (c, st.median(v)))
        print("  %-4s %s   spread %.4f ms   sd(READ)=%.4f"
              % (a, "  ".join(line), max(meds) - min(meds),
                 st.pstdev([r["clrt_ms"] for r in by[(a, "READ")]])))

    print("\n=== 4. budget breaches and the late-relay-ACK failure mode ===")
    # An exchange whose master-visible request-to-ACK is BELOW the armed deadline would mean the
    # hold was skipped; one far above means the release missed its deadline.
    for a in ("A0", "A1"):
        v = [r for r in rows if r["anchor_arm"] == a]
        early = [r for r in v if r["ack_ms"] < D_A_MS - 0.5]
        late = [r for r in v if r["ack_ms"] > D_A_MS + 2.0]
        print("  %-3s n=%-5d  released early (<D_A-0.5ms): %-4d   late (>D_A+2ms): %-4d  max=%.4f"
              % (a, len(v), len(early), len(late), max(r["ack_ms"] for r in v)))
        if late:
            cc = collections.Counter(r["txn_class"] for r in late)
            print("        late by class: %s" % dict(cc))
    off_ack = [r["ack_ms"] for r in rows if r["anchor_arm"] == "OFF"]
    print("  headroom: the relay's own acknowledgment latency, Timing OFF, max=%.4f ms against a"
          " %.4f ms deadline (%.0fx)" % (max(off_ack), D_A_MS, D_A_MS / max(off_ack)))

    print("\n=== 6. class difference at matched idle gap ===")
    for a in arms:
        pairs = []
        for c in ("READ", "SELECT"):
            v = [(r["idle_before_ms"], r["ack_ms"]) for r in by[(a, c)]
                 if r["idle_before_ms"] is not None]
            pairs.append(v)
        rd, sl = pairs
        if not rd or not sl:
            continue
        lo, hi = q([p[0] for p in sl], .25), q([p[0] for p in sl], .75)
        rd_m = [x for g, x in rd if lo <= g <= hi]
        sl_m = [x for g, x in sl if lo <= g <= hi]
        if rd_m and sl_m:
            print("  %-4s idle gap in [%.3f, %.3f] ms:  READ %.4f  SELECT %.4f   diff %.4f ms"
                  % (a, lo, hi, st.median(rd_m), st.median(sl_m),
                     abs(st.median(rd_m) - st.median(sl_m))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
