Preserve and commit the SALU repair immediately.

The repair is accepted as a valid root-cause result:

    TAG_INACTIVE=0xFF did not fit the SALU signed immediate comparison.
    The compiled predicate became a comparison against -255 and the
    conditional state write never committed.
    TAG_INACTIVE=0x00 compiles correctly and allows the arm write.

Before another Gate 2 transaction, complete two checks.

======================================================================
CHECK 1 — INACTIVE MARKER SAFETY
======================================================================

Audit all P4, setup, cleanup, analyzer and restore paths so the inactive
tag is consistently zero.

Prove that no active transaction generation can equal zero.

If generation arithmetic can wrap to zero, reserve zero explicitly:

    next_gen = current_gen + 1
    if next_gen == 0:
        next_gen = 1

Add tests for initialization, normal increment and wrap.

Audit every selected-build SALU comparison against constants in the
0x80–0xFF range. Inspect compiler assembly and preserve any suspicious
signed-immediate lowering as evidence.

======================================================================
CHECK 2 — PRODUCTION BLOCKER-START LATENCY
======================================================================

Do not yet delay the synthetic ACK merely to allow the reservoir to
start.

First determine whether the observed approximately 1 ms startup belongs
only to the synthetic harness or to the actual production READ-triggered
blocker path.

Build a minimal measurement using the exact blocker trigger mechanism
intended for live Defense 3.

For at least 100 clean trials record:

    t_READ_ingress
    t_pktgen_trigger
    t_first_blocker_admitted
    t_final_blocker_admitted

Report:

    READ-to-first-blocker minimum, median, p95, p99 and maximum
    READ-to-full-reservoir minimum, median, p95, p99 and maximum
    first-trial-after-load results
    warm-trial results
    packet count
    queue drops
    restore result

The relevant physical baseline is:

    READ→ACK minimum approximately 0.400 ms
    READ→ACK median approximately 0.505 ms

The current queue construction requires Q_BLOCK to become effective
before the earliest protected ACK.

If production full-reservoir startup is safely below the physical ACK
floor, classify the 1 ms result as a synthetic-harness scheduling error
and correct the synthetic event schedule.

If production startup is near 1 ms, classify it as an architecture
failure. Do not hide it by scheduling the synthetic ACK later.

In that case investigate, microbenchmark and select a faster Tofino-only
trigger:

    1. READ-derived recirculation-pattern pktgen trigger;
    2. READ-triggered internal replication/multicast reservoir;
    3. pre-positioned internal tokens activated by transaction generation;
    4. another hardware event-triggered pktgen construction.

For each alternative measure time from READ ingress to the first and
final blocker becoming effective.

Do not use a controller fast path.
Do not declare the mechanism impossible after one trigger mode fails.

======================================================================
GATE 2 AFTER TRIGGER VALIDATION
======================================================================

Only after proving that the production blocker reservoir is active before
a realistic ACK may Gate 2 be rerun.

Use a synthetic schedule consistent with the physical READ→ACK timing,
not an artificially delayed ACK.

For D=2 ms require:

    exactly one 64-token burst
    reservoir effective before ACK admission
    ACK enters Q_HOLD only after Q_BLOCK is effective
    RESPONSE enters behind ACK
    ACK_RELEASE_FAILOPEN = 0
    blocker budget expiry = 0
    stale termination = 0
    all 64 blockers terminate due to deadline
    no ACK forwarding before t_ACK + D
    ACK forwarded before RESPONSE
    transaction state clean

Measure separately:

    t_ACK
    d_ACK
    first deadline termination
    final deadline termination
    ACK forward commitment
    RESPONSE forward commitment
    actual ACK hold
    drain tail
    ACK-to-RESPONSE separation

Do not describe the current 480 ns result as a successful Defense 3 hold.
It is a successful lifecycle-path observation with an invalid timing
precondition and a fail-open release.

Continue from this point in a fresh session after committing all current
evidence.