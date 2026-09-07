#!/usr/bin/env python3
"""Corrected select-before-operate driver: the OPERATE is gated on the SELECT.

The defect this replaces is specific. In the frozen
`implementation/harness/relay_sbo_operate_guarded.py` the OPERATE is built and sent at lines
134 to 137, while `sel_ok` is not computed until line 140. An OPERATE therefore followed a
SELECT whose response had never been checked, and whose status could not have been checked
anyway, because that file's status decoder does not skip the two-octet IIN.

Here the OPERATE is not built at all unless the SELECT response is complete, carries the
matching application sequence number, returns object group 12 variation 1 with qualifier 0x17,
lists exactly the requested points, and reports status SUCCESS for each. Otherwise the
transaction is recorded as `NOT_ATTEMPTED` with the reasons, and the driver moves on. There is
no automatic OPERATE retry, and adding one would need an argued policy, because a retried
OPERATE is a second control action.

Safety is unchanged and not reimplemented: the frame builders and the {1, 3} allowlist are
imported from the frozen guard, and the post-build sentinel runs on every control frame.

    python3 sbo_driver.py --dry-run
    DEFENSE4_HW_AUTHORIZED=1 python3 sbo_driver.py --count 40 --budget-ms 500 --out log.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from dnp3_codec import FUNC_SELECT, FUNC_OPERATE, parse_frame
from frozen_builders import (AUTHORIZED_POINTS, ForbiddenPointError, build_select,
                             build_operate, assert_frame_targets_authorized)
from session import Session, Outcome, OUTCOME_NOT_ATTEMPTED

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"


def guarded(func: int, seq: int, points) -> bytes:
    """Build a control frame through the frozen guard, then validate bytes and CRCs."""
    frame = build_select(seq & 0x0F, points) if func == FUNC_SELECT \
        else build_operate(seq & 0x0F, points)
    assert_frame_targets_authorized(frame)          # frozen post-build sentinel
    parsed, rest = parse_frame(frame)
    if parsed is None or rest:
        raise ValueError("built control frame does not parse cleanly")
    if parsed.user_data[2] != func:
        raise ValueError("refusing: built frame function 0x%02x != 0x%02x"
                         % (parsed.user_data[2], func))
    return frame


def one_sbo(s: Session, seq_select: int, seq_operate: int, points, budget_ms: float,
            select_only: bool):
    """One SBO pair. Returns (select outcome, operate outcome)."""
    sel = guarded(FUNC_SELECT, seq_select, points)
    sel_out = s.transaction(operation="SELECT", frame=sel, function=FUNC_SELECT,
                            app_seq=seq_select, budget_ms=budget_ms,
                            expect_points=points, require_success=True)
    if select_only:
        return sel_out, Outcome(operation="OPERATE", function=FUNC_OPERATE,
                                app_seq=seq_operate, outcome=OUTCOME_NOT_ATTEMPTED,
                                problems=["select-only rehearsal; no OPERATE is issued"])
    # The gate. Nothing is built for the OPERATE unless the SELECT is fully valid.
    if not sel_out.ok:
        return sel_out, Outcome(
            operation="OPERATE", function=FUNC_OPERATE, app_seq=seq_operate,
            outcome=OUTCOME_NOT_ATTEMPTED,
            problems=["SELECT did not complete successfully (%s): %s"
                      % (sel_out.outcome, "; ".join(sel_out.problems) or "no detail")])
    op = guarded(FUNC_OPERATE, seq_operate, points)
    op_out = s.transaction(operation="OPERATE", frame=op, function=FUNC_OPERATE,
                           app_seq=seq_operate, budget_ms=budget_ms,
                           expect_points=points, require_success=True)
    return sel_out, op_out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--gap-ms", type=float, default=20.0)
    ap.add_argument("--budget-ms", type=float, default=500.0)
    ap.add_argument("--indices", default="1,3",
                    help="must be exactly the authorized set; anything else is refused")
    ap.add_argument("--relay", default=RELAY_IP)
    ap.add_argument("--src", default=SRC_IP)
    ap.add_argument("--out", default=None)
    ap.add_argument("--select-only", action="store_true",
                    help="rehearsal: issue the guarded SELECT and no OPERATE")
    ap.add_argument("--dry-run", action="store_true", default=None)
    ap.add_argument("--live", dest="dry_run", action="store_false",
                    help="open a socket; also requires DEFENSE4_HW_AUTHORIZED=1")
    a = ap.parse_args(argv)
    dry = True if a.dry_run in (None, True) else False

    points = [int(x) for x in a.indices.split(",") if x.strip()]
    if set(points) != set(AUTHORIZED_POINTS):
        print("REFUSED: --indices must be exactly %s; got %r"
              % (sorted(AUTHORIZED_POINTS), points), file=sys.stderr)
        return 2
    try:
        assert_frame_targets_authorized(build_operate(0, points))
    except ForbiddenPointError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2

    if dry:
        print("dry run: building guarded SELECT/OPERATE frames, opening no socket")
        for seq in (0, 1):
            for func, name in ((FUNC_SELECT, "SELECT"), (FUNC_OPERATE, "OPERATE")):
                f = guarded(func, seq, points)
                print("  %-7s seq=%x len=%d %s" % (name, seq, len(f), f.hex()))
        print("frames build, pass the {1,3} guard and CRC-validate; nothing was sent")
        return 0

    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        print("REFUSED: live operation needs DEFENSE4_HW_AUTHORIZED=1", file=sys.stderr)
        return 2

    fh = open(a.out, "w") if a.out else None
    counts = {}
    try:
        with Session(a.relay, RELAY_PORT, source_address=(a.src, 0)) as s:
            print("connected %s -> %s:%d (%d SBO, points=%s%s)"
                  % (a.src, a.relay, RELAY_PORT, a.count, points,
                     ", SELECT-only" if a.select_only else ""))
            seq = 0
            for _ in range(a.count):
                sel_out, op_out = one_sbo(s, seq, seq + 1, points, a.budget_ms, a.select_only)
                seq += 2
                for out in (sel_out, op_out):
                    key = "%s/%s" % (out.operation, out.outcome)
                    counts[key] = counts.get(key, 0) + 1
                    if fh:
                        fh.write(json.dumps(out.as_dict()) + "\n")
                    if not out.ok and out.outcome != OUTCOME_NOT_ATTEMPTED:
                        print("  %s %s %s" % (out.operation, out.outcome,
                                              "; ".join(out.problems)))
                time.sleep(a.gap_ms / 1e3)
    finally:
        if fh:
            fh.close()
    print("outcomes: %s" % counts)
    print("confirm relay OUT/TRIP contacts stayed 0 before drawing any conclusion")
    expected = a.count if not a.select_only else 0
    return 0 if counts.get("OPERATE/OK", 0) == expected else 1


if __name__ == "__main__":
    sys.exit(main())
