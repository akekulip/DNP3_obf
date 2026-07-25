Continue on the existing branch:

research/queue-resident-transaction-release

Use the latest committed descendant containing:

- QUEUE_RELEASE_RESEARCH_REOPENING.md
- INDIRECT_QUEUE_RELEASE_DESIGN_SPACE.md
- INTERNAL_TOKEN_THREAT_AND_VISIBILITY_MODEL.md
- FIRST_EXPERIMENT_PAIRED_BUFFER.md

The IBSPG architecture is accepted as the LEAD CANDIDATE for experimental
investigation.

It is not yet accepted as a working mechanism or final contribution.

Do not describe it as validated, successful, novel or production-ready until the
required silicon evidence exists.

PRIMARY OBJECTIVE

Build and run the smallest Tofino-1 microbenchmark that determines whether an
Internal-Blocker Strict-Priority Gate can:

1. keep an original real packet resident in a low-priority TM queue;
2. prevent that real packet from leaving while a higher-priority internal blocker
   queue remains continuously occupied;
3. drain the blocker using a data-plane event;
4. release the original real packet afterward;
5. prevent the internal blocker token from ever appearing on dp9 or dp11;
6. perform this without continuously recirculating the original real packet.

Use synthetic marked packets first.

Do not begin with full DNP3 traffic or the physical SEL.

CURRENT TESTBED

- Vision/master host connected through dp9
- Hulk/outstation host connected through dp11
- queue_microbench_abs.conf is the mandatory restoration target
- switch currently has one intended bf_switchd instance
- frozen Phase-1 and defense P4 programs must remain untouched

ARCHITECTURAL MODEL

Use an internal loopback port L with:

- Q_BLOCK = high strict-priority queue
- Q_HOLD = low strict-priority queue

Packet classes:

- BLOCKER_TOKEN
- HELD_REAL
- DRAIN_MATCH
- DRAIN_UNRELATED
- optional TIMEOUT trigger

BLOCKER_TOKEN:

- has an unambiguous private internal marker
- contains slot_id and generation
- exists only on the internal loopback path
- re-enters Q_BLOCK while its transaction is not drainable
- is dropped internally when the matching drain condition becomes true
- must never egress dp9 or dp11

HELD_REAL:

- represents the original ACK during the first primitive experiment
- enters Q_HOLD
- remains byte-identical
- must make only a fixed small number of pipeline/loopback passes
- must not repeatedly circulate while waiting

DRAIN_MATCH:

- updates only the matching slot and generation
- causes blocker tokens belonging to that slot to stop re-enqueuing

DRAIN_UNRELATED:

- must not drain the blocker
- must not release HELD_REAL

PART 1 — STATIC TM CONFIGURATION

Create a standalone microbenchmark directory, for example:

research/tofino_dcrn_feasibility/p4/ibspg_microbench/

Do not modify existing queue_microbench or defense sources.

Document and configure:

- internal loopback dev_port
- Q_BLOCK qid
- Q_HOLD qid
- strict-priority values
- queue scheduling enablement
- shaping, if used
- queue depth or buffer allocation
- protected ports dp9 and dp11
- internal token marker
- restoration procedure

All TM configuration may be installed once during initialization.

No per-transaction control-plane operation is allowed.

Produce:

IBSPG_TM_CONFIGURATION.md

PART 2 — COMPILE-ONLY P4 PROTOTYPE

Implement the minimum P4 pipeline necessary to:

- recognize synthetic packet roles
- derive or carry slot_id and generation
- assign BLOCKER_TOKEN to Q_BLOCK
- assign HELD_REAL to Q_HOLD
- set reg_drain[slot] on matching DRAIN_MATCH
- reject unrelated drain events
- drop a blocker token internally when reg_drain[slot] is set
- loop a blocker token internally otherwise
- forward HELD_REAL to the protected destination only after it dequeues from
  Q_HOLD and returns through the loopback path
- strip all internal metadata before protected egress

Record:

- parser stages
- ingress stages
- egress stages
- SRAM
- TCAM
- exact-match resources
- stateful ALUs
- PHV
- warnings
- queue resources

The first prototype may use one fixed synthetic slot.

Do not add full DNP3 parsing or multi-flow matching until the blocker primitive is
proven.

PART 3 — BLOCKER-OCCUPANCY VARIANTS

Implement and compare at least these blocker variants:

A. Single looping blocker token
   - control experiment
   - expected to expose the empty-gap risk

B. Multiple phased blocker tokens
   - test N = 2, 4, 8 and other justified values
   - determine whether Q_BLOCK remains continuously occupied

C. Multiple blocker tokens with Q_BLOCK shaping
   - use shaping only while Q_BLOCK has persistent backlog
   - determine whether the dequeue rate can be kept below the token loopback
     replenishment rate
   - do not reuse the earlier sparse-flow assumption; this queue is deliberately
     backlogged

D. On-demand blocker creation
   - create the blocker ring from an internal clone/mirror or another supported
     mechanism at transaction arm
   - consume every blocker after drain
   - verify no blocker remains after completion

If cloning or mirroring is used:

- configure its session once at initialization
- keep all copies internal
- prove no clone appears on dp9 or dp11
- do not alter the original real packet

Produce:

IBSPG_BLOCKER_OCCUPANCY_DESIGN.md

PART 4 — BASIC STRICT-PRIORITY CONTROL TEST

Before testing transaction release, establish the scheduler behavior.

Test sequence:

1. Populate Q_BLOCK with a controlled persistent blocker backlog.
2. Enqueue one HELD_REAL packet into Q_HOLD.
3. Observe for a bounded interval substantially longer than ordinary switching
   latency.
4. Confirm whether HELD_REAL remains in Q_HOLD.
5. Drain or stop replenishing Q_BLOCK.
6. Confirm whether HELD_REAL then dequeues.

Measure:

- Q_BLOCK occupancy
- Q_HOLD occupancy
- Q_BLOCK enqueue/dequeue counts
- Q_HOLD enqueue/dequeue counts
- queue watermarks
- drop counts
- HELD_REAL egress timestamp
- blocker drain timestamp

PASS only if persistent high-priority backlog completely prevents low-priority
service during the observation window.

If low-priority traffic receives service while Q_BLOCK remains nonempty, record
that result and do not claim strict-priority gating.

PART 5 — EMPTY-GAP EXPERIMENT

This is the load-bearing experiment.

For each blocker variant and token count:

1. Start the blocker mechanism.
2. Confirm Q_BLOCK has active backlog.
3. Enqueue HELD_REAL into Q_HOLD.
4. Do not send DRAIN_MATCH.
5. Observe for a bounded test period.
6. Verify that HELD_REAL never appears at the protected egress.
7. Record minimum Q_BLOCK depth over time.
8. Repeat enough times to detect intermittent premature release.

Required evidence:

- no premature HELD_REAL egress
- Q_HOLD remains occupied
- Q_BLOCK does not reach an unsafe empty interval
- exact blocker enqueue/dequeue behavior
- no blocker escape

Do not infer continuous occupancy only from average counters.

Use the finest supported queue occupancy and packet timestamp evidence.

If the hardware cannot sample occupancy finely enough, infer gaps using repeated
held-packet release trials and report the measurement limitation.

Determine:

- minimum safe blocker-token count
- minimum safe blocker backlog
- useful shaping rate
- loopback return latency
- scheduler service rate
- probability of premature release, if nonzero

PART 6 — MATCHED-DRAIN RELEASE EXPERIMENT

Use one synthetic slot A.

Sequence:

1. Arm slot A.
2. Establish its blocker ring.
3. Enqueue HELD_REAL-A into Q_HOLD.
4. Verify it remains held.
5. Send DRAIN_UNRELATED for slot B or wrong generation.
6. Verify HELD_REAL-A remains held.
7. Send DRAIN_MATCH for slot A and the correct generation.
8. Verify blocker tokens stop replenishing.
9. Verify Q_BLOCK drains.
10. Verify HELD_REAL-A dequeues afterward.
11. Verify slot A state clears according to the microbenchmark lifecycle.

Measure:

- time DRAIN_MATCH enters the switch
- time reg_drain changes, where observable
- time the last blocker leaves Q_BLOCK
- time HELD_REAL-A leaves Q_HOLD
- time HELD_REAL-A appears at Hulk
- drain-to-release latency
- release jitter over repeated trials

Run enough repetitions to characterize:

- median
- minimum
- maximum
- p95
- p99 where sample count supports it

PASS only if:

- unrelated drain never releases the held packet
- matching drain consistently releases it
- no held packet leaves before the matching drain
- no blocker escapes
- held-packet bytes are unchanged

PART 7 — INTERNAL-TOKEN VISIBILITY PROOF

Capture continuously on both protected host-facing paths.

Required proof:

- zero BLOCKER_TOKEN frames at Vision
- zero BLOCKER_TOKEN frames at Hulk
- dp9/dp11 TX counters equal the expected REAL-packet count
- internal loopback counters contain the blocker traffic
- the private blocker marker never appears outside the internal path
- no internal bridge header appears on a released real packet

Any blocker token observed on dp9 or dp11 is external synthetic traffic and is a
test failure.

Do not relabel it as internal after an escape.

Follow the evidentiary rules in:

INTERNAL_TOKEN_THREAT_AND_VISIBILITY_MODEL.md

PART 8 — INTERNAL BANDWIDTH AND COST

Measure the cost of maintaining the blocker.

For each viable variant record:

- blocker packets per second
- blocker packet size
- internal bits per second
- loopback port utilization
- Q_BLOCK occupancy
- ingress pipeline traversals
- egress pipeline traversals
- stateful operations per blocker pass
- cost while a transaction is active
- cost while no transaction is active
- drain tail after matching response
- maximum simultaneous blocker rings supported

Evaluate whether blockers should be:

- permanently active
- created on READ for HOLD_ACK
- created on ACK for HOLD_RESPONSE
- destroyed after release or timeout

Prefer on-demand blocker rings when feasible.

For HOLD_ACK, investigate creation on READ so Q_BLOCK is already established before
the pure ACK can arrive.

For HOLD_RESPONSE, investigate creation on the ACK while the target release state
is recorded.

PART 9 — TIMEOUT / FAIL-OPEN

Test a missing-drain condition.

The design must not hold HELD_REAL indefinitely.

Use a bounded timeout implemented through:

- blocker pass count
- compact timestamp comparison
- or another data-plane mechanism supported by evidence

At timeout:

- blocker tokens must drain or stop replenishing
- HELD_REAL must fail open
- state must clear
- timeout telemetry must increment
- no token may escape

Measure timeout error and cleanup completeness.

PART 10 — DECISION GATE

Classify IBSPG after the primitive experiments.

PASS-CANDIDATE only if:

- original HELD_REAL remains in TM queue memory during the hold interval
- persistent blocker occupancy prevents premature service
- matching drain releases it
- unrelated drain does not release it
- blocker tokens remain entirely internal
- real packet bytes and length remain unchanged
- original real packet does not continuously recirculate
- release latency and jitter are bounded
- timeout/fail-open works
- internal bandwidth is measured and acceptable
- switch restores cleanly

PARTIAL if:

- the primitive works but has measurable empty-gap leakage, excessive internal
  bandwidth, unstable release jitter or insufficient isolation

REFUTED if:

- Q_HOLD receives service while Q_BLOCK is demonstrably nonempty
- a reliable no-gap blocker cannot be maintained
- blocker drain cannot release the held packet
- internal tokens escape protected ports
- timeout cannot safely release the packet

Do not declare the entire indirect design space impossible from one failed variant.

If single-token fails, test multi-token and shaped-backlog variants.

If the IBSPG family fails after those bounded variants, evaluate the already
identified two-stage or backpressure alternatives separately.

PART 11 — PAIRED ACK/RESPONSE EXPERIMENT

Proceed only if the blocker-gate primitive passes.

Use synthetic ACK-A and RESPONSE-A:

1. READ-A or synthetic ARM-A creates slot and blocker.
2. ACK-A enters Q_HOLD.
3. RESPONSE-B does not release ACK-A.
4. RESPONSE-A enters Q_HOLD behind ACK-A and sets drain.
5. Blockers drain.
6. Q_HOLD releases ACK-A first.
7. RESPONSE-A follows.
8. Both packets remain byte-identical.
9. State clears.

Measure:

- ACK-to-response output gap
- FIFO ordering
- cross-transaction isolation
- release jitter
- queue occupancy
- token bandwidth
- cleanup

Only after this passes should DNP3 packet parsing and the exact flow-slot matching
primitive be integrated.

PART 12 — DNP3 INTEGRATION GATE

Do not contact the physical SEL.

Use synthetic or replayed DNP3 traces.

Integrate:

- parser-hardened Phase-1 classifier
- exact admitted-flow to slot mapping
- generation
- expected ACK
- DNP3 application sequence
- unified transaction state

Test:

- normal READ/ACK/RESPONSE
- unrelated response
- duplicate ACK
- duplicate response
- retransmission
- FIN/RST
- timeout
- link-only frame transparency
- unknown-flow bypass
- two admitted flows
- stale generation

PART 13 — NOVELTY STATUS

Do not yet title IBSPG as a novel contribution.

After silicon results, update:

NOVELTY_AND_CONTRIBUTION_ANALYSIS.md

Distinguish:

Inherited from Ditto:
- TM buffering
- static priority
- loopback hierarchy
- occupancy-based scheduling

GridCloak candidate contribution:
- transaction-coupled blocker drain
- queue-resident ACK/response pairing
- response-triggered occupancy change
- internal non-observable blocker ring
- ACK-before-response FIFO release
- no externally visible chaff
- on-demand per-transaction queue gate

Search for prior work implementing the same high-priority blocker-drain construction
before claiming novelty.

PART 14 — REPORT AND COMMITS

Create coherent commits for:

1. compile-only blocker-gate microbenchmark
2. static-priority and empty-gap experiments
3. matched-drain and visibility experiments
4. blocker-cost and timeout experiments
5. paired ACK/response experiment
6. DNP3 integration only if earlier gates pass

Produce:

IBSPG_MICROBENCH_FINAL_REPORT.md

The report must distinguish:

- designed
- compiled
- configured
- tested on silicon
- passed
- partially passed
- refuted
- not tested

FINAL RESTORATION

After every hardware experiment and at completion:

- restore queue_microbench_abs.conf
- verify exactly one intended bf_switchd process
- restore expected empty $PORT baseline
- Vision reachable at 10.10.54.19
- Vision retains 192.168.10.1
- Hulk reachable at 10.10.54.158
- no replay, capture, pktgen, blocker or probe process remains
- no internal token remains circulating
- record final git status and commits

Proceed autonomously through compile-only development and bounded synthetic silicon
experiments.

Do not pause after ordinary reversible successes.

Stop only for physical intervention, destructive risk, management-connectivity risk,
firmware/OS changes, SEL involvement, or a genuine choice between multiple
experimentally successful mechanisms.