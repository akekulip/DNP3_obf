#!/usr/bin/env python3
# =============================================================================
#  test_trial_isolation.py — offline proof that the trial-isolation mechanism
#  in four_queue_dequeue_oracle_setup.py actually does what it claims.
#
#  NO SWITCH. NO gRPC. Every function that would touch the switch is replaced
#  with a call into FakeSwitch, a ~90-line model of the four queues, the three
#  accounting registers, the port shaper and the packet generator. Running this
#  needs nothing but python3.
#
#  ---------------------------------------------------------------------------
#  WHY THESE THREE TESTS AND NOT OTHERS
#
#  The five-control pilot failed in one specific way: control A ended INVALID
#  with released=False, left 124 packets backlogged, and control B1 then drained
#  A's leftovers together with its own batch. Two properties would each have
#  broken that chain, and both are tested here:
#
#    1. THE CLEANUP RUNS ON THE FAILURE PATH. A trial whose preload gate is not
#       satisfied must still leave the switch empty and its counters zeroed —
#       identically to a trial that succeeded.
#    2. A DIRTY START IS REFUSED. Even if cleanup fails or is skipped, the next
#       trial must not run. A refusal is a usable result; a number produced from
#       a contaminated queue is not.
#
#  A third test covers the case the pilot never reached: a trial that fails with
#  an UNEXPECTED exception (not the orderly preload-gate refusal) must still be
#  cleaned up, because `finally` is what makes the guarantee unconditional.
#
#  Run:  python3 setup/test_trial_isolation.py
# =============================================================================
"""Offline tests for assert_clean_start / cleanup_trial / run_trial isolation."""
import os
import sys

# The import must follow the sys.path insert: this file lives beside the module
# it tests and is run directly, not as part of a package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import four_queue_dequeue_oracle_setup as S


# ===========================================================================
# The model
# ===========================================================================
class FakeSwitch(object):
    """Enough of the switch to exercise the isolation logic, and no more.

    `drains_on_line_rate` is the interesting knob: with it False the queues
    never empty, which is how "cleanup FAILED and said so" is distinguished
    from "cleanup silently claimed success".
    """

    def __init__(self, drains_on_line_rate=True):
        self.usage = {"ABLOCK": 0, "ACK": 0, "RBLOCK": 0, "RESP": 0}
        self.drops = {r: 0 for r in self.usage}
        self.total_dequeues = 0
        self.written = 0
        self.overflow = 0
        self.app_enable = False
        self.gate_armed = False
        self.line_rate = True
        self.drains_on_line_rate = drains_on_line_rate
        self.calls = []          # ordered log of every switch-touching call

    def log(self, what, detail=""):
        self.calls.append((what, detail))

    # ---- generation ------------------------------------------------------
    def generate(self, n=128, leak=0):
        """Park n packets across the four queues; `leak` of them escape."""
        per = n // 4
        for r in self.usage:
            self.usage[r] += per
        self.log("generate", "n=%d leak=%d" % (n, leak))
        for _ in range(min(leak, n)):
            self._dequeue_one()

    def _dequeue_one(self):
        for r in self.usage:
            if self.usage[r] > 0:
                self.usage[r] -= 1
                break
        else:
            return
        idx = self.total_dequeues
        self.total_dequeues += 1
        if idx < S.TRACE_LEN:
            self.written += 1
        else:
            self.overflow += 1

    def drain_all(self):
        if not (self.line_rate and self.drains_on_line_rate):
            return
        while any(v > 0 for v in self.usage.values()):
            self._dequeue_one()


# ===========================================================================
# The stubs — every switch-touching entry point in the module
# ===========================================================================
def install_stubs(sw):
    orig = {}

    def patch(name, fn):
        orig[name] = getattr(S, name)
        setattr(S, name, fn)

    patch("queue_counters", lambda bi, tgt0, a: dict(
        (r, {"qid": q, "pg_queue": q, "usage_cells": sw.usage[r],
             "watermark_cells": sw.usage[r], "drop_count_packets": sw.drops[r]})
        for r, q, _x in S.ROLES))

    def _reg_read(bi, tgt, name, idx, chk=None):
        return {S.REG_TOTAL: sw.total_dequeues, S.REG_WRITTEN: sw.written,
                S.REG_OVERFLOW: sw.overflow}.get(name)
    patch("reg_read", _reg_read)

    def _reg_zero(bi, tgt, name, idx, chk):
        sw.log("reg_zero", name)
        if name == S.REG_TOTAL:
            sw.total_dequeues = 0
        elif name == S.REG_WRITTEN:
            sw.written = 0
        elif name == S.REG_OVERFLOW:
            sw.overflow = 0
        return True
    patch("reg_zero", _reg_zero)

    patch("ctr_zero", lambda bi, tgt, name, idx, chk=None: True)
    patch("read_app_enable", lambda bi, tgts, a: sw.app_enable)

    def _set_app_enable(bi, tgts, a, enable, chk):
        sw.app_enable = enable
        sw.log("set_app_enable", str(enable))
        return True
    patch("set_app_enable", _set_app_enable)

    def _dp8_line_rate(bi, tgts, a, chk):
        sw.gate_armed = False
        sw.line_rate = True
        sw.log("dp8_line_rate")
        sw.drain_all()
        return True
    patch("dp8_line_rate", _dp8_line_rate)

    def _reset_queue_counters(bi, tgt0, a, out, chk):
        sw.drops = {r: 0 for r in sw.drops}
        sw.log("reset_queue_counters")
        out["queue_counters_reset"] = True
    patch("reset_queue_counters", _reset_queue_counters)

    # --- the measured part of a trial, replaced wholesale --------------------
    # The trial BODY is not what these tests are about; the try/finally around
    # it is. Each test installs its own body via sw.body.
    patch("_trial_body", lambda bi, tgt, tgt0, tgts, a, out, chk: sw.body(out, chk))

    return orig


def remove_stubs(orig):
    for name, fn in orig.items():
        setattr(S, name, fn)


class Args(object):
    port_l = 8
    port_pgen = 68
    app_id = 1
    trial_id = 1
    seed = 1
    cleanup_drain = 0.0
    cleanup_timeout = 2.0
    stable_gap = 0.0
    no_cleanup = False


# ===========================================================================
# The tests
# ===========================================================================
def _run(sw, body, no_cleanup=False):
    a = Args()
    a.no_cleanup = no_cleanup
    sw.body = body
    out, chk = {}, S.Checks()
    orig = install_stubs(sw)
    try:
        S.run_trial(None, None, None, [("pipe0", None)], a, out, chk)
    finally:
        remove_stubs(orig)
    return out, chk


def test_invalid_trial_is_cleaned_up():
    """A trial that ends INVALID must still leave the switch clean."""
    sw = FakeSwitch()

    def body(out, chk):
        # exactly the pilot's control A: 128 generated, 4 leak, preload gate not
        # satisfied, so the release is NOT performed and 124 stay parked.
        sw.gate_armed = True
        sw.line_rate = False
        sw.generate(128, leak=4)
        out["preload_gate_ok"] = False
        out["released"] = False
        out["verdict"] = "INVALID"
        chk.fail("PRELOAD GATE", "not satisfied (simulated)")

    out, chk = _run(sw, body)
    backlog = sum(sw.usage.values())
    clean = out["cleanup"]["clean"]
    print("  trial verdict            : %s" % out.get("verdict"))
    print("  released                 : %s" % out.get("released"))
    print("  backlog after cleanup    : %d (pilot left 124 here)" % backlog)
    print("  cleanup verified clean   : %s" % clean)
    print("  counters after cleanup   : total=%d written=%d overflow=%d"
          % (sw.total_dequeues, sw.written, sw.overflow))
    print("  pktgen app_enable        : %s" % sw.app_enable)
    ok = (out.get("verdict") == "INVALID" and out.get("released") is False
          and backlog == 0 and clean is True and sw.total_dequeues == 0
          and sw.written == 0 and sw.overflow == 0 and sw.app_enable is False)
    # And the order the cleanup did it in, which is the part that matters:
    # nothing may be zeroed before the queues have drained.
    names = [c[0] for c in sw.calls]
    order_ok = (names.index("set_app_enable") < names.index("dp8_line_rate")
                < names.index("reg_zero"))
    print("  cleanup call order       : %s" % " -> ".join(names))
    print("  reset happens AFTER drain: %s" % order_ok)
    return ok and order_ok


def test_unexpected_exception_is_cleaned_up():
    """`finally`, not a tidy return path, is what makes the guarantee hold."""
    sw = FakeSwitch()

    def body(out, chk):
        sw.gate_armed = True
        sw.line_rate = False
        sw.generate(128, leak=0)
        raise RuntimeError("simulated gRPC failure mid-trial")

    a = Args()
    sw.body = body
    out, chk = {}, S.Checks()
    orig = install_stubs(sw)
    raised = None
    try:
        S.run_trial(None, None, None, [("pipe0", None)], a, out, chk)
    except RuntimeError as e:
        raised = str(e)
    finally:
        remove_stubs(orig)
    backlog = sum(sw.usage.values())
    print("  exception propagated     : %s" % raised)
    print("  backlog after cleanup    : %d" % backlog)
    print("  cleanup ran              : %s" % ("cleanup" in out))
    print("  cleanup verified clean   : %s" % (out.get("cleanup") or {}).get("clean"))
    return (raised is not None and backlog == 0
            and (out.get("cleanup") or {}).get("clean") is True)


def test_dirty_start_is_refused():
    """The second half of the guarantee: a dirty switch must not be measured."""
    sw = FakeSwitch()
    # exactly the state control B1 inherited from control A
    sw.usage = {"ABLOCK": 31, "ACK": 32, "RBLOCK": 30, "RESP": 31}
    sw.total_dequeues = 4
    sw.written = 4
    ran = {"body": False}

    def body(out, chk):
        ran["body"] = True

    out, chk = _run(sw, body)
    print("  inherited backlog        : 124 (31/32/30/31), total_dequeues=4")
    print("  trial body executed      : %s  (must be False)" % ran["body"])
    print("  verdict                  : %s" % out.get("verdict"))
    print("  refusal reason           : %s" % (out.get("refused_dirty_start") or "")[:96])
    print("  cleanup still ran        : %s" % ("cleanup" in out))
    print("  clean afterwards         : %s" % (out.get("cleanup") or {}).get("clean"))
    return (ran["body"] is False and out.get("verdict") == "INVALID"
            and out.get("refused_dirty_start")
            and (out.get("cleanup") or {}).get("clean") is True)


def test_failed_cleanup_is_reported_not_hidden():
    """A cleanup that cannot drain must FAIL loudly, not claim success."""
    sw = FakeSwitch(drains_on_line_rate=False)

    def body(out, chk):
        sw.gate_armed = True
        sw.line_rate = False
        sw.generate(128, leak=0)
        out["released"] = False
        out["verdict"] = "INVALID"

    out, chk = _run(sw, body)
    rec = out["cleanup"]
    fails = [r for r in chk.rows if r[0] == "FAIL"]
    print("  backlog after cleanup    : %d (the queues cannot drain here)"
          % sum(sw.usage.values()))
    print("  cleanup 'clean'          : %s  (must be False)" % rec["clean"])
    print("  FAIL rows raised         : %d" % len(fails))
    for r in fails[:3]:
        print("      FAIL %s" % r[1])
    return rec["clean"] is False and len(fails) > 0


def test_no_cleanup_then_refuses():
    """--no-cleanup is debug-only, and the next trial must refuse to start."""
    sw = FakeSwitch()

    def body(out, chk):
        sw.gate_armed = True
        sw.line_rate = False
        sw.generate(128, leak=0)
        out["released"] = False

    out1, _c1 = _run(sw, body, no_cleanup=True)
    left = sum(sw.usage.values())
    ran = {"body": False}

    def body2(out, chk):
        ran["body"] = True

    out2, _c2 = _run(sw, body2)
    print("  backlog left by trial 1  : %d" % left)
    print("  trial 2 body executed    : %s  (must be False)" % ran["body"])
    print("  trial 2 refusal          : %s" % bool(out2.get("refused_dirty_start")))
    return ("cleanup" not in out1 and left == 128 and ran["body"] is False
            and bool(out2.get("refused_dirty_start")))


TESTS = [
    ("cleanup runs on an INVALID trial (the pilot's control A)",
     test_invalid_trial_is_cleaned_up),
    ("cleanup runs after an unexpected exception (the `finally`)",
     test_unexpected_exception_is_cleaned_up),
    ("a dirty start is REFUSED (the pilot's control B1)",
     test_dirty_start_is_refused),
    ("a cleanup that cannot drain FAILS loudly",
     test_failed_cleanup_is_reported_not_hidden),
    ("--no-cleanup leaves a dirty switch and the next trial refuses",
     test_no_cleanup_then_refuses),
]


def main():
    print("")
    print("TRIAL-ISOLATION TESTS — no switch, no gRPC, FakeSwitch model")
    n_bad = 0
    for name, fn in TESTS:
        print("")
        print("-" * 78)
        print("TEST: %s" % name)
        try:
            ok = fn()
        except Exception as e:                       # a crash is a failure
            ok = False
            print("  EXCEPTION: %r" % (e,))
        print("  RESULT: %s" % ("PASS" if ok else "FAIL"))
        if not ok:
            n_bad += 1
    print("")
    print("=" * 78)
    if n_bad:
        print("TRIAL-ISOLATION TESTS FAILED: %d of %d" % (n_bad, len(TESTS)))
        return 1
    print("TRIAL-ISOLATION TESTS PASSED: %d/%d" % (len(TESTS), len(TESTS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
