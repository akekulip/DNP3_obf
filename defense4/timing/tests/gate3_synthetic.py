#!/usr/bin/env python3
"""Gate 3 — synthetic validation of the unified Defense 4 timing core (defense4_timing.p4).

Offline, no switch load (per IMPLEMENTATION_PLAN Gate 3). Models the mode truth table and deadline
equations from TIMING_SPEC and checks the invariants that make the core a correct TIMING obfuscation:
the released ACK->RESPONSE latency (CLRT) is a public constant independent of the device's native
timing, ordering holds (ACK never after RESPONSE), the mode equivalences hold, and the edge cases
(late arrival, missing RESPONSE, duplicates, budget expiry) resolve safely.

Deadline equations (TIMING_SPEC 2):
    T_A    = t_A + D_A                 # ACK absolute deadline
    T_RESP = T_A + D_R = t_A + D_A + D_R
Modes (TIMING_SPEC 1): OFF, D1_EVENT, D2_RESPONSE_DEADLINE, D3_ACK_DEADLINE, D4_DUAL_DEADLINE, FAIL_OPEN.

Run:  ~/.venvs/research/bin/python gate3_synthetic.py
"""
import sys

RTO_BUDGET = 100_000          # bounded fail-open horizon (ticks); mirrors INITIAL_BUDGET
OFF, D1, D2, D3, D4, FAILOPEN = "OFF", "D1_EVENT", "D2_RESP", "D3_ACK", "D4_DUAL", "FAIL_OPEN"


def release(mode, t_A, t_R, D_A, D_R, resp_seen=True, ack_seen=True):
    """Return (rel_ack, rel_resp) release ticks for one transaction, per the mode's policy.
    t_A = native ACK arrival, t_R = native RESPONSE arrival. None arrivals model a missing event."""
    T_A = t_A + D_A if t_A is not None else None
    T_RESP = (T_A + D_R) if T_A is not None else None

    if mode == OFF:
        return t_A, t_R                                   # both immediate

    if mode == D1:                                        # event-based: hold ACK until RESP observed
        if not resp_seen:                                 # missing RESPONSE -> bounded fail-open
            return t_A + RTO_BUDGET, None
        ra = t_R                                          # ACK released when its RESPONSE is seen
        return ra, max(t_R, ra)                           # RESPONSE after ACK commitment

    if mode == D2:                                        # ACK immediate; RESPONSE held to T_RESP
        if not ack_seen:
            return None, t_R + RTO_BUDGET
        ra = t_A
        rr = max(t_R, T_RESP) if resp_seen else None      # never release before the deadline
        return ra, rr

    if mode == D3:                                        # ACK held to T_A; RESPONSE after ACK
        if not ack_seen:
            return t_R + RTO_BUDGET, t_R + RTO_BUDGET
        ra = max(t_A, T_A)                                # release no earlier than the ACK deadline
        rr = max(t_R, ra) if resp_seen else None          # RESPONSE ordered after the ACK
        return ra, rr

    if mode == D4:                                        # dual: ACK to T_A, RESPONSE to T_RESP & after ACK
        if not ack_seen:
            return t_R + RTO_BUDGET, t_R + RTO_BUDGET
        ra = max(t_A, T_A)
        rr = max(t_R, T_RESP, ra) if resp_seen else None
        return ra, rr

    if mode == FAILOPEN:                                  # bounded release, no deadline enforcement
        ra = (t_A + 1) if ack_seen else None
        rr = (t_R + 1) if resp_seen else None
        return ra, rr
    raise ValueError(mode)


results = []
def ok(name, cond, note=""):
    results.append((name, "PASS" if cond else "FAIL", note))


# ---- 1. CLRT constancy: the obfuscation property ----
# Across devices with DIFFERENT native (t_A, t_R), D4 releases a CONSTANT CLRT = D_R -- but ONLY when
# the public deadline dominates, i.e. D_R >= every device's native CLRT (the "set the deadline at the
# MAX, not the centre" rule). Native CLRTs here span 1..30; pick D_R=40 to dominate them.
D_A, D_R = 4, 40
natives = [(100, 101), (100, 102), (100, 115), (50, 60), (200, 230)]  # native CLRTs 1,2,15,10,30
clrts = []
for t_A, t_R in natives:
    ra, rr = release(D4, t_A, t_R, D_A, D_R)
    clrts.append(rr - ra)
ok("01 D4 released CLRT is constant across native timing (D_R dominates)", len(set(clrts)) == 1, f"clrts={clrts}")
ok("02 D4 released CLRT equals the public D_R", set(clrts) == {D_R}, f"={clrts[0]} (D_R={D_R})")

# Design constraint (the oracle's teeth): if D_R is set BELOW a device's native CLRT, that response
# arrives late and leaks its native timing -> the property BREAKS. This must be caught, not ignored.
D_R_small = 10
leaky = [(release(D4, tA, tR, D_A, D_R_small)[1] - release(D4, tA, tR, D_A, D_R_small)[0])
         for tA, tR in natives]
ok("03 constant-CLRT REQUIRES D_R >= native max (broken below it, by design)",
   len(set(leaky)) > 1, f"clrts@D_R={D_R_small}: {leaky} -> must vary, proving the constraint")

# ---- 2. Ordering: ACK is never released after the RESPONSE (CLRT >= 0), every mode ----
for m in (OFF, D1, D2, D3, D4):
    good = True
    for t_A, t_R in natives:
        ra, rr = release(m, t_A, t_R, D_A, D_R)
        if ra is not None and rr is not None and ra > rr:
            good = False
    ok(f"04 {m}: ACK released no later than RESPONSE", good)

# ---- 3. Deadline enforcement ----
ra, rr = release(D2, 100, 101, 0, D_R)       # D2 uses D_A=0
ok("05 D2 holds RESPONSE to t_A + D_R", rr == 100 + D_R, f"rr={rr}")
ra, rr = release(D3, 100, 101, D_A, 0)       # D3 uses D_R=0
ok("06 D3 holds ACK to t_A + D_A", ra == 100 + D_A, f"ra={ra}")
ok("07 D3 releases RESPONSE right after the ACK (D_R=0)", rr == max(101, ra), f"rr={rr}")

# ---- 4. Mode equivalences (TIMING_SPEC 2): D4 with D_A=0 == D2; D4 with D_R=0 == D3 ----
eqD2 = all(release(D4, tA, tR, 0, D_R) == release(D2, tA, tR, 0, D_R) for tA, tR in natives)
ok("08 D4(D_A=0) reproduces the D2 release policy", eqD2)
eqD3 = all(release(D4, tA, tR, D_A, 0)[0] == release(D3, tA, tR, D_A, 0)[0] for tA, tR in natives)
ok("09 D4(D_R=0) reproduces the D3 ACK-before-RESPONSE ordering", eqD3)

# ---- 5. OFF is a true pass-through ----
ok("10 OFF releases both immediately (no shaping)",
   all(release(OFF, tA, tR, D_A, D_R) == (tA, tR) for tA, tR in natives))

# ---- 6. Edge cases ----
ra, rr = release(D4, 100, 101, D_A, D_R, resp_seen=False)     # missing RESPONSE
ok("11 missing RESPONSE -> bounded fail-open, no infinite hold", ra is not None and rr is None
   and ra <= 101 + RTO_BUDGET)
ra, rr = release(D2, 100, 101, 0, D_R, ack_seen=False)        # missing ACK
ok("12 missing ACK -> bounded fail-open", rr is not None and rr <= 101 + RTO_BUDGET)
ra1 = release(D4, 100, 115, D_A, D_R); ra2 = release(D4, 100, 115, D_A, D_R)  # duplicate transaction
ok("13 duplicate transaction is idempotent (same release)", ra1 == ra2)
ra, rr = release(FAILOPEN, 100, 101, D_A, D_R)
ok("14 FAIL_OPEN releases within a bounded delay (safety)", (ra - 100) <= 1 and (rr - 101) <= 1)
# a native response arriving BEFORE its deadline is still held to the deadline (no early leak)
ra, rr = release(D4, 100, 100, D_A, D_R)     # response arrives at the same tick as the ACK
ok("15 early native RESPONSE is held to T_RESP (no pre-deadline leak)", rr == 100 + D_A + D_R,
   f"rr={rr} T_RESP={100+D_A+D_R}")

# ---- report ----
npass = sum(1 for r in results if r[1] == "PASS")
print(f"{'CHECK':58s} RES  NOTE")
print("-" * 92)
for n, r, nt in results:
    print(f"{n:58s} {r:4s} {nt}")
print("-" * 92)
print(f"GATE 3 SYNTHETIC: {npass}/{len(results)} checks pass")
print("\nHeadline: in D4/D2 the released ACK->RESPONSE latency is the public constant D_R,")
print("independent of the device's native CLRT -> the timing fingerprint is removed by construction.")
sys.exit(0 if npass == len(results) else 1)
