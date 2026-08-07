# Phase 4 targeted lifecycle cases (corrected binary, physical SEL-751)

Targeted cases that the physical relay campaigns (A + B) already exercise, extracted from the
committed raw evidence. Software-outstation-only negatives (missing ACK, missing RESPONSE, FIN/RST,
combined, multi-segment, SELECT/OPERATE) are NOT here; they need the outstation wired through the
switch (see the boundary note at the bottom).

## 1. Response obligation survives the ACK release (the mandatory lifecycle proof)

The pre-fix defect retired the transaction at ACK release, so a response arriving after that was
bypassed. The corrected binary must hold it. Counter `RESP_HOLD_LATE` counts exactly this: a response
that arrived AFTER the ACK was released and was still held (not bypassed).

| campaign | D2 (D_A=0, ACK releases immediately) | D4 |
|---|---|---|
| A | early 0, **late 120**, bypass 0 | early 93, **late 27**, bypass 0 |
| B | early 0, **late 120**, bypass 0 | early 87, **late 33**, bypass 0 |

D2 sets D_A=0, so the ACK is released immediately and every response arrives after it. Across A+B, all
**240** D2 responses arrived after the ACK release and were held, 0 bypass. D4 held 60 late-arriving
responses after the ACK release, 0 bypass. The lifecycle fix is proven on silicon by the counters, not
just by timing.

## 2. Generation rollover on one connection (>= 33 READs, C0..CF)

Every campaign block is ONE sustained TCP connection carrying 60 READs whose DNP3 application-control
octet advances C0..CF and rolls over. Example CA_D4_1: one_connection=True, 60 polls, 16 distinct
app-sequence values (0xC0..0xCF), so C0..CF rolls over 3.8 times on a single connection with no
per-poll state clear. 60 > 33, so the >=33-READ rollover requirement is met by every block (20 blocks
across A+B).

## 3. Fail-open, bounded release, and re-arm (PASS)

Targeted test on the physical relay: D4 4/10 with a small budget of 800, which sets the fail-open
horizon to 1.37 ms (shorter than the response arrival), forcing the fail-open path on every poll.
Result (`targeted_failopen/`, scorer scenario `fail_open`, verdict PASS):

- responded **30/30** — every response still delivered (bounded release, never stranded);
- **RELEASE_FAILOPEN = 30**, RELEASE_DEADLINE = 0 — all releases via the fail-open path;
- **ARM_FRESH = 30** — every next transaction re-armed;
- reg_tag idle after the block — no stale state.

This exercises the same code path a genuine missing response takes and proves the no-stranding
invariant on silicon: when the reservoir drains before the deadline, the held packet is released and
the transaction re-arms. Budget was restored to 18000 (D4 verified) after the test.

## Boundary: software-outstation-only negatives

Missing ACK, missing RESPONSE, missing both, duplicate/retransmit at the transport layer, FIN/RST at
three points, combined ACK-bearing response, multi-segment response, wrong identity, and SELECT/OPERATE
cannot be produced by the READ-only physical relay. The controlled software outstation that produces
them is built and unit-tested offline (`defense4/timing/control/outstation/`, 58/58). Running them
LIVE requires the outstation on a switch port with the P4 flow-match pointed at it, which would
reconfigure the fixed function and take the switch out of the current relay-facing D4 deployment. That
is a testbed-setup step (a host on a spare switch port plus a P4 flow reconfiguration), not done here.
