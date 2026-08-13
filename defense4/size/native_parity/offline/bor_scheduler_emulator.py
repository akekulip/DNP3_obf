#!/usr/bin/env python3
"""Offline discrete-event emulator of a Tofino strict-priority loopback scheduler.

Purpose
-------
Demonstrate, with a self-contained model (stdlib only), WHY the BOR
(Blocked-OPERATE-Release) defense needs TWO independent loopback scheduling
domains instead of one.

The scheduling primitive
------------------------
A "scheduling domain" is ONE dequeue server shared by several strict-priority
queues. Time advances in discrete loop-passes of duration ``tau``. On each pass
the server picks the HIGHEST-priority NON-EMPTY queue (a higher qid number means
higher priority), serves exactly ONE item from it, and advances ``now`` by tau.

Two item kinds live in the queues:

* Reservoir token -- belongs to a reservoir queue with an absolute deadline D.
  A reservoir is seeded with K tokens at t=T0. When a token is served:
    - if now <  D : RE-ENQUEUE it (the token stays resident, count unchanged),
    - if now >= D : DROP it (this is how the reservoir DRAINS: once the deadline
      passes, each subsequent serve removes one token until the reservoir empties).

* Held real packet -- belongs to a hold queue with a release deadline D. A hold
  queue holds exactly ONE real packet, seeded at T0. When it is served:
    - if now >= D : RELEASE it (it leaves the domain; the release time is recorded
      and it is never re-enqueued again),
    - if now <  D : RE-ENQUEUE it (still being held).

The starvation mechanism
------------------------
Each hold queue sits at a LOWER priority than its paired reservoir. While the
reservoir is resident (now < D) it keeps winning the strict-priority arbitration
and re-enqueuing, so the paired hold packet is STARVED and never served. Only
once the reservoir's deadline passes and it DRAINS to empty does the lower-
priority hold queue get the server -- and by then now >= D, so the held packet
releases immediately. The reservoir is thus a self-clearing timer that pins the
release of the held packet to ~D.

Why one domain is not enough
----------------------------
In the OLD single-domain design all six queues share one server, so the ACK
reservoir (deadline A) and the RESP reservoir (deadline R) must drain first
before the OPERATE stage at the bottom is ever reached. By the time the server
gets to the OPERATE reservoir (deadline J, with J < A < R), now is already >= R,
so the OPERATE releases at ~R -- NOT at its intended ~J. The OPERATE deadline is
effectively overwritten by the higher stages sharing the same server.

The NEW design splits the work across TWO independent servers (loopback
domains): the ACK/RESP stages run on the dp8 domain and the OPERATE stage runs
on its own BOR_L (dp10) domain. Now the OPERATE reservoir drains on its own
server at ~J and the OPERATE releases at ~J, independent of A and R.

Run ``python3 bor_scheduler_emulator.py`` to execute the self-test and print the
report. Exit 0 on pass, nonzero on any failed assertion.
"""

# ----------------------------------------------------------------------------
# Parameters (named constants; J < A < R, and K*tau << J so each reservoir
# cycles many times before its deadline).
# ----------------------------------------------------------------------------
T0 = 0.0            # seed time for all reservoirs and held packets (s)
J = 10.0e-3         # OPERATE stage deadline (s)
A = 20.0e-3         # ACK stage deadline (s)
R = 24.0e-3         # RESPONSE stage deadline (s)
K = 64              # reservoir depth (tokens)
TAU = 250.0e-9      # loop-pass duration (s)

# Safety cap on total loop-passes per domain (R/tau ~= 96000 for the busiest
# stage, plus a few K drains; five million is comfortably clear).
ITER_CAP = 5_000_000

MS = 1.0e3          # seconds -> milliseconds for the report


class Queue(object):
    """One strict-priority queue holding either reservoir tokens or a held packet."""

    def __init__(self, qid, kind, deadline, label):
        self.qid = qid                # priority; higher qid == higher priority
        self.kind = kind              # 'reservoir' or 'hold'
        self.deadline = deadline      # absolute deadline D (s)
        self.label = label            # human-readable name, e.g. 'R_ack'
        self.count = 0                # reservoir: token count
        self.present = False          # hold: real packet resident?

    def seed(self, k):
        if self.kind == "reservoir":
            self.count = k
        else:  # hold queue always seeds exactly one real packet
            self.present = True

    def nonempty(self):
        if self.kind == "reservoir":
            return self.count > 0
        return self.present


class Domain(object):
    """One dequeue server shared by several strict-priority queues."""

    def __init__(self, name, queues, tau=TAU, t0=T0):
        self.name = name
        self.queues = list(queues)
        self.tau = tau
        self.now = t0
        self.releases = {}             # hold label -> release time (s)
        self.release_events = []       # ordered list of (label, time)
        self.drain_times = {}          # reservoir label -> last-drop time (s)
        self.first_pass_nonempty = None  # labels non-empty on the very first pass

    def _highest_nonempty(self):
        best = None
        for q in self.queues:
            if q.nonempty() and (best is None or q.qid > best.qid):
                best = q
        return best

    def run(self, cap=ITER_CAP):
        """Advance until every hold releases and every reservoir drains."""
        passes = 0
        first = True
        while passes < cap:
            q = self._highest_nonempty()
            if q is None:
                break  # all holds released and all reservoirs drained
            if first:
                # snapshot at t ~= T0, before serving the first item
                self.first_pass_nonempty = [c.label for c in self.queues
                                            if c.nonempty()]
                first = False
            if q.kind == "reservoir":
                q.count -= 1                       # serve one token
                if self.now < q.deadline:
                    q.count += 1                   # re-enqueue: stays resident
                else:
                    self.drain_times[q.label] = self.now  # DROP; keep last drop
            else:  # hold
                if self.now >= q.deadline:
                    q.present = False              # RELEASE and leave the domain
                    self.releases[q.label] = self.now
                    self.release_events.append((q.label, self.now))
                # else: re-enqueue -- held packet simply stays present
            self.now += self.tau
            passes += 1
        return passes


def _make_queues(specs):
    """Build and seed fresh queues from (qid, kind, deadline, label) specs."""
    qs = []
    for qid, kind, deadline, label in specs:
        q = Queue(qid, kind, deadline, label)
        q.seed(K)
        qs.append(q)
    return qs


def build_old_domain():
    """OLD design: ONE domain, six queues (priority high -> low)."""
    specs = [
        (7, "reservoir", A, "R_ack"),
        (6, "hold",      A, "H_ack"),
        (5, "reservoir", R, "R_resp"),
        (4, "hold",      R, "H_resp"),
        (3, "reservoir", J, "R_op"),
        (2, "hold",      J, "H_op"),
    ]
    return Domain("OLD-single", _make_queues(specs))


def build_new_domains():
    """NEW design: TWO independent domains (two separate servers)."""
    dp8 = Domain("NEW-dp8", _make_queues([
        (7, "reservoir", A, "R_ack"),
        (6, "hold",      A, "H_ack"),
        (5, "reservoir", R, "R_resp"),
        (4, "hold",      R, "H_resp"),
    ]))
    bor_l = Domain("NEW-BOR_L(dp10)", _make_queues([
        (3, "reservoir", J, "R_op"),
        (2, "hold",      J, "H_op"),
    ]))
    return dp8, bor_l


def _fmt_ms(x):
    return "n/a" if x is None else ("%.4f" % (x * MS))


def main():
    tol = 5 * K * TAU  # tolerance band used by every "near a deadline" check
    checks = []        # (name, ok, detail) for the final report

    def check(name, ok, detail):
        checks.append((name, bool(ok), detail))
        return bool(ok)

    # ---- run OLD (one domain) -------------------------------------------
    old = build_old_domain()
    old.run()
    release_op_OLD = old.releases.get("H_op")
    release_ack_OLD = old.releases.get("H_ack")
    release_resp_OLD = old.releases.get("H_resp")
    drain_op_OLD = old.drain_times.get("R_op")

    # ---- run NEW (two domains) ------------------------------------------
    dp8, bor_l = build_new_domains()
    dp8.run()
    bor_l.run()
    release_ack_NEW = dp8.releases.get("H_ack")
    release_resp_NEW = dp8.releases.get("H_resp")   # SELECT/echo response
    release_op_NEW = bor_l.releases.get("H_op")
    op_reservoir_drain_time_NEW = bor_l.drain_times.get("R_op")
    n_op_releases_NEW = sum(1 for lbl, _ in bor_l.release_events if lbl == "H_op")

    # ---- report tables ---------------------------------------------------
    print("=" * 70)
    print("BOR strict-priority loopback scheduler emulator")
    print("Parameters: J=%.1f ms  A=%.1f ms  R=%.1f ms  K=%d  tau=%.0f ns  "
          "tol=5*K*tau=%.4f ms"
          % (J * MS, A * MS, R * MS, K, TAU * 1e9, tol * MS))
    print("=" * 70)
    header = "%-14s %14s %14s %14s %16s"
    print(header % ("design", "OPERATE(ms)", "ACK(ms)", "echo/RESP(ms)",
                    "R_op drain(ms)"))
    print(header % ("OLD 1-domain", _fmt_ms(release_op_OLD),
                    _fmt_ms(release_ack_OLD), _fmt_ms(release_resp_OLD),
                    _fmt_ms(drain_op_OLD)))
    print(header % ("NEW 2-domain", _fmt_ms(release_op_NEW),
                    _fmt_ms(release_ack_NEW), _fmt_ms(release_resp_NEW),
                    _fmt_ms(op_reservoir_drain_time_NEW)))
    print("-" * 70)

    # ---- assertions (a)-(g) ---------------------------------------------
    # (a) OLD OPERATE release is NEAR R and FAR from J.
    ok_a = (release_op_OLD is not None
            and abs(release_op_OLD - R) < tol
            and (release_op_OLD - J) > 0.5 * (R - J))
    check("(a) OLD OPERATE near R, far from J",
          ok_a,
          "release_op_OLD=%s ms" % _fmt_ms(release_op_OLD))

    # (b) NEW SELECT/echo (H_resp on dp8) releases at ~R.
    ok_b = (release_resp_NEW is not None
            and abs(release_resp_NEW - R) < tol)
    check("(b) NEW SELECT/echo releases at ~R",
          ok_b,
          "release_resp_NEW=%s ms" % _fmt_ms(release_resp_NEW))

    # (c) NEW qid3 R_op reservoir drains at ~J.
    ok_c = (op_reservoir_drain_time_NEW is not None
            and abs(op_reservoir_drain_time_NEW - J) < tol)
    check("(c) NEW R_op reservoir drains at ~J",
          ok_c,
          "op_reservoir_drain_time_NEW=%s ms" % _fmt_ms(op_reservoir_drain_time_NEW))

    # (d) exactly ONE OPERATE release, ~J, immediately after R_op drains.
    ok_d = (n_op_releases_NEW == 1
            and release_op_NEW is not None
            and abs(release_op_NEW - J) < tol
            and op_reservoir_drain_time_NEW is not None
            and release_op_NEW >= op_reservoir_drain_time_NEW)
    check("(d) NEW exactly ONE OPERATE release at ~J, after drain",
          ok_d,
          "n=%d  release_op_NEW=%s ms  drain=%s ms"
          % (n_op_releases_NEW, _fmt_ms(release_op_NEW),
             _fmt_ms(op_reservoir_drain_time_NEW)))

    # (e) dp8 ACK and RESP reservoirs are resident at admission (first pass).
    fp = dp8.first_pass_nonempty or []
    ok_e = ("R_ack" in fp and "R_resp" in fp)
    check("(e) NEW dp8 R_ack & R_resp resident at t~=T0",
          ok_e,
          "first_pass_nonempty=%s" % (fp,))

    # (f) NEW ACK releases at ~A and echo at ~R.
    ok_f = (release_ack_NEW is not None and abs(release_ack_NEW - A) < tol
            and release_resp_NEW is not None and abs(release_resp_NEW - R) < tol)
    check("(f) NEW ACK at ~A and echo at ~R",
          ok_f,
          "release_ack_NEW=%s ms  release_resp_NEW=%s ms"
          % (_fmt_ms(release_ack_NEW), _fmt_ms(release_resp_NEW)))

    # (g) NON-VACUOUS discriminator: OLD and NEW OPERATE releases differ by more
    #     than half the J..R gap.
    ok_g = (release_op_OLD is not None and release_op_NEW is not None
            and (release_op_OLD - release_op_NEW) > 0.5 * (R - J))
    check("(g) OLD vs NEW OPERATE differ > 0.5*(R-J)",
          ok_g,
          "delta=%.4f ms  (0.5*(R-J)=%.4f ms)"
          % ((release_op_OLD - release_op_NEW) * MS, 0.5 * (R - J) * MS))

    # Explicit discriminator line: assertion (a)'s NEAR-R predicate must be
    # FALSE for the NEW OPERATE release -- proving the test tells the two
    # designs apart rather than passing vacuously.
    new_op_near_R = (release_op_NEW is not None
                     and abs(release_op_NEW - R) < tol)
    print("DISCRIMINATOR: (a)'s NEAR-R predicate applied to NEW OPERATE "
          "release = %s (expected False)" % new_op_near_R)
    print("               NEW OPERATE=%s ms is near J=%.4f ms, NOT near R=%.4f ms"
          % (_fmt_ms(release_op_NEW), J * MS, R * MS))
    print("-" * 70)

    # ---- print each assertion's PASS/FAIL line, then hard-assert ---------
    all_ok = True
    for name, ok, detail in checks:
        status = "PASS" if ok else "FAIL"
        print("%-4s %-46s | %s" % (status, name, detail))
        all_ok = all_ok and ok
    # (g)'s discriminator predicate must be False for non-vacuity:
    disc_ok = (new_op_near_R is False)
    print("%-4s %-46s | %s"
          % ("PASS" if disc_ok else "FAIL",
             "(g) discriminator: NEW-op NOT near R",
             "predicate=%s" % new_op_near_R))
    all_ok = all_ok and disc_ok
    print("-" * 70)

    # Hard assertions (each raises with a clear message on failure).
    assert ok_a, "assertion (a) FAILED: OLD OPERATE not near R / not far from J"
    assert ok_b, "assertion (b) FAILED: NEW SELECT/echo not at ~R"
    assert ok_c, "assertion (c) FAILED: NEW R_op reservoir not drained at ~J"
    assert ok_d, "assertion (d) FAILED: NEW OPERATE not a single ~J release after drain"
    assert ok_e, "assertion (e) FAILED: dp8 reservoirs not resident at admission"
    assert ok_f, "assertion (f) FAILED: NEW ACK/echo not at ~A / ~R"
    assert ok_g, "assertion (g) FAILED: OLD vs NEW OPERATE not discriminated"
    assert disc_ok, "discriminator FAILED: NEW OPERATE unexpectedly near R"

    print("ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
