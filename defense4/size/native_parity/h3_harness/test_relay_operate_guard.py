"""Proves the {1,3} guard: no SELECT/OPERATE frame can be built for a forbidden index.
Run: python3 test_relay_operate_guard.py   (exit 0 = all guards hold)."""

import sys
import relay_operate_guarded as g
from dnp3_wire import FUNC_SELECT, FUNC_OPERATE

FAILS = []


def expect_refused(desc, fn):
    try:
        fn()
    except g.ForbiddenPointError as e:
        print("  REFUSED ok: %-42s -> %s" % (desc, e))
        return
    FAILS.append("NOT refused: %s" % desc)
    print("  !! NOT REFUSED: %s" % desc)


def expect_ok(desc, fn):
    try:
        v = fn()
        print("  allowed ok: %-42s" % desc)
        return v
    except Exception as e:
        FAILS.append("wrongly refused: %s (%s)" % (desc, e))
        print("  !! WRONGLY REFUSED: %s -> %s" % (desc, e))


print("### {1,3} guard — must REFUSE everything outside {1,3} ###")
# The one that matters most: breaker-close index 6.
expect_refused("OPERATE index [6] (breaker CLOSE)", lambda: g.build_operate(0, [6]))
expect_refused("SELECT  index [6] (breaker CLOSE)", lambda: g.build_select(0, [6]))
expect_refused("OPERATE index [0]", lambda: g.build_operate(0, [0]))
expect_refused("OPERATE index [2]", lambda: g.build_operate(0, [2]))
expect_refused("OPERATE index [4]", lambda: g.build_operate(0, [4]))
expect_refused("OPERATE index [5]", lambda: g.build_operate(0, [5]))
expect_refused("OPERATE mixed [1,6]", lambda: g.build_operate(0, [1, 6]))
expect_refused("OPERATE mixed [3,6]", lambda: g.build_operate(0, [3, 6]))
expect_refused("OPERATE mixed [1,2]", lambda: g.build_operate(0, [1, 2]))
expect_refused("OPERATE empty []", lambda: g.build_operate(0, []))
expect_refused("raw object build [6]", lambda: g.build_guarded_crob_object([6]))

print("### the authorized set must be ALLOWED and target exactly {1,3} ###")
sel = expect_ok("SELECT  index [1,3]", lambda: g.build_select(0, [1, 3]))
op = expect_ok("OPERATE index [1,3]", lambda: g.build_operate(0, [1, 3]))
# Default must be {1,3}.
op_def = expect_ok("OPERATE default (no indices)", lambda: g.build_operate(0))

print("### post-build sentinel: the built frames target EXACTLY {1,3} on the wire ###")
for name, fr in (("SELECT", sel), ("OPERATE", op), ("OPERATE-default", op_def)):
    if fr is None:
        continue
    try:
        pts = g.assert_frame_targets_authorized(fr)
        if set(pts) == {1, 3}:
            print("  %-16s wire points = %s  ok" % (name, pts))
        else:
            FAILS.append("%s wire points %s != {1,3}" % (name, pts))
            print("  !! %s wire points %s != {1,3}" % (name, pts))
    except Exception as e:
        FAILS.append("%s sentinel error: %s" % (name, e))
        print("  !! %s sentinel error: %s" % (name, e))

print()
if FAILS:
    print("GUARD TEST FAILED (%d):" % len(FAILS))
    for f in FAILS:
        print("  -", f)
    sys.exit(1)
print("GUARD TEST PASSED — no forbidden index can produce a control frame; {1,3} verified on the wire.")
sys.exit(0)
