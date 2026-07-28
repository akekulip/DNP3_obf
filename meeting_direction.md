Create and validate a new Case A timing-defense variant:

CASE A: PREDETERMINED ACK-DELAY RELEASE

Branch:
research/case-a-fixed-ack-delay

Research objective:
Implement a Tofino-1 mechanism that holds a pure TCP ACK until a predetermined ACK-relative deadline:

    t_release = t_ACK + D

The release must not depend on the matching DNP3 RESPONSE arriving.

This is a new Case A variant. It is not Case B, not packet-size obfuscation, and not a replacement for the completed Defense 2 implementation.

Preserve the current tested request-triggered Tofino pktgen implementation and reuse its blocker-token mechanism.

----------------------------------------------------------------------
1. PRESERVE THE CURRENT BASELINE
----------------------------------------------------------------------

Before changing code:

1. Identify the exact commit containing the tested request-triggered pktgen Defense 2 implementation.
2. Record:
   - commit hash;
   - P4 source;
   - setup script;
   - runner;
   - SDE version;
   - ingress and egress stage usage;
   - queue configuration;
   - pktgen configuration;
   - current live-test report.
3. Confirm that the baseline still compiles.
4. Do not modify or overwrite the proven Defense 2 files.
5. Create new files for the fixed-delay ACK variant.
6. Do not touch unrelated dirty files.

Suggested new files:

    p4/case_a_fixed_ack_delay.p4
    setup/case_a_fixed_ack_delay_setup.py
    run/run_fixed_ack_delay.sh
    run/poll_fixed_ack_delay.py
    design/CASE_A_FIXED_ACK_DELAY_DESIGN.md
    evidence/CASE_A_FIXED_ACK_DELAY_REPORT.md

----------------------------------------------------------------------
2. TARGET PACKET SEQUENCE
----------------------------------------------------------------------

The target device behavior is:

    Class 0 READ
        ↓
    pure TCP ACK
        ↓
    DNP3 RESPONSE

The switch must apply the new mechanism only to a correctly classified
Case A transaction.

Do not apply the defense to unrelated TCP packets, retransmissions,
connection establishment packets, or non-DNP3 traffic.

----------------------------------------------------------------------
3. REQUIRED ARCHITECTURE
----------------------------------------------------------------------

Reuse the proven request-triggered blocker-token construction:

    Fresh eligible Class 0 READ detected
        ↓
    Tofino pktgen generates K blocker tokens internally
        ↓
    Tokens enter Q_BLOCK
        ↓
    Q_BLOCK has strict priority over Q_HOLD

Use:

    Q_BLOCK = high-priority queue
    Q_HOLD  = low-priority FIFO queue

Reuse the current queue IDs and internal loopback configuration unless
the existing implementation demonstrates that different IDs are required.

The tokens must remain internal to Tofino. No host-generated blockers
and no 0x88C1 frames may appear on external links.

----------------------------------------------------------------------
4. READ PROCESSING
----------------------------------------------------------------------

When a fresh eligible Class 0 READ is detected:

1. Create or advance the transaction generation.
2. Mark the transaction active.
3. Clear stale ACK and RESPONSE state.
4. Mark the ACK deadline as not yet valid.
5. Trigger exactly one internal pktgen blocker reservoir.
6. Forward the original READ byte-identically to the SEL-751.
7. Suppress duplicate token generation for duplicate or retransmitted
   copies of the same READ.

The already-tested pktgen mechanism must be reused. Do not redesign
pktgen unless a change is strictly necessary for this new defense.

----------------------------------------------------------------------
5. BLOCKER BEHAVIOR BEFORE ACK ARRIVAL
----------------------------------------------------------------------

The blocker reservoir may already be circulating before the pure ACK
arrives.

While:

    transaction_active == 1
    and ack_deadline_valid == 0

each valid current-generation blocker must:

1. remain associated with the active transaction;
2. decrement or update its fail-open pass budget;
3. return to Q_BLOCK;
4. not terminate because no ACK deadline has been installed yet.

If the ACK never arrives, the pass-budget or watchdog mechanism must
eventually terminate the blocker reservoir and clean the transaction.

There must be no possibility of an indefinite hold.

----------------------------------------------------------------------
6. PURE ACK PROCESSING
----------------------------------------------------------------------

When the matching pure TCP ACK arrives:

1. Identify it using the established Case A transaction key.
2. Read the Tofino ingress hardware timestamp:

       t_ACK = ingress timestamp

3. Store:

       ack_deadline = t_ACK + D

4. Set:

       ack_deadline_valid = 1

5. Mark the original ACK as the held ACK.
6. Enqueue the original ACK in Q_HOLD.
7. Do not forward the ACK immediately.
8. Do not alter its Ethernet, IP, TCP, or payload bytes.
9. Do not generate another blocker reservoir.
10. Do not use the control plane to release the ACK.

D must be configured before the experiment. It may be:

- a compile-time constant; or
- a register configured once by the setup script.

There must be no per-transaction controller fast-path operation.

Start with:

    D = 2 ms

This is close to the approximately 2 ms center of the non-outlier native
SEL-751 CLRT measurements.

The implementation must allow later experiments with:

    D = 0.5 ms
    D = 1 ms
    D = 2 ms
    D = 3 ms

----------------------------------------------------------------------
7. RESPONSE PROCESSING
----------------------------------------------------------------------

There are two required response-arrival cases.

CASE 1: RESPONSE arrives before the ACK deadline

    ACK is already waiting in Q_HOLD
        ↓
    matching RESPONSE arrives
        ↓
    enqueue RESPONSE behind ACK in the same Q_HOLD FIFO
        ↓
    do not release either packet before the deadline

When Q_BLOCK drains, FIFO ordering must produce:

    ACK first
    RESPONSE second

The RESPONSE must never overtake the held ACK.

CASE 2: RESPONSE arrives after the ACK has been released

    ACK deadline expires
        ↓
    ACK is released
        ↓
    RESPONSE arrives later

In this case:

1. forward the RESPONSE normally;
2. do not start another hold;
3. do not generate another blocker reservoir;
4. preserve the RESPONSE bytes.

Use explicit transaction state such as:

    ack_seen
    ack_held
    ack_released
    response_seen
    response_queued
    transaction_generation

Do not rely on packet arrival assumptions that are not represented in
state.

----------------------------------------------------------------------
8. DEADLINE COMPARISON
----------------------------------------------------------------------

The deadline comparison must occur in ingress.

For each returning blocker:

    now = current ingress timestamp

If:

    ack_deadline_valid == 0

then:

    return blocker to Q_BLOCK
    subject to the fail-open budget

If:

    now < ack_deadline

then:

    return blocker to Q_BLOCK

If:

    now >= ack_deadline

then:

    drop the blocker
    do not re-enqueue it

After all current-generation blockers terminate:

    Q_BLOCK becomes empty
        ↓
    Traffic Manager serves Q_HOLD
        ↓
    ACK is released
        ↓
    queued RESPONSE, if present, follows the ACK

The Traffic Manager performs queue scheduling only.

The deadline decision must not be placed in egress.

----------------------------------------------------------------------
9. RELEASE PATH
----------------------------------------------------------------------

The held ACK and any queued RESPONSE will be dequeued from Q_HOLD and
sent through the established internal loopback release path.

On the release pass:

1. identify the released ACK or RESPONSE;
2. remove only internal encapsulation or internal role metadata;
3. forward the original packet toward Vision;
4. prevent the packet from being re-enqueued;
5. prevent recursive holding;
6. preserve byte-identical external packet content.

The ACK must leave before a RESPONSE that arrived before the deadline.

Use FIFO ordering rather than a separate response-triggered release rule.

----------------------------------------------------------------------
10. TRANSACTION CLEANUP
----------------------------------------------------------------------

Clean state safely after one of the following:

A. ACK released and RESPONSE subsequently forwarded;

B. ACK and queued RESPONSE both released;

C. fail-open budget expires;

D. connection reset or teardown invalidates the transaction;

E. transaction timeout occurs.

Cleanup must:

1. clear active transaction state;
2. invalidate the ACK deadline;
3. invalidate stale generations;
4. clear ACK and RESPONSE status;
5. prevent old blockers from affecting the next transaction;
6. permit the next eligible READ to trigger a new blocker reservoir.

Do not clear state before the queued packets have completed the required
release lifecycle.

----------------------------------------------------------------------
11. EXPECTED TIMING TRANSFORMATION
----------------------------------------------------------------------

Validate the following expected behavior.

For a native CLRT greater than D:

    CLRT_out ≈ CLRT_native - D

Example:

    CLRT_native = 3.0 ms
    D = 2.0 ms
    expected CLRT_out ≈ 1.0 ms

For a native CLRT less than or equal to D:

    RESPONSE reaches the switch before the ACK deadline
        ↓
    RESPONSE waits behind ACK
        ↓
    ACK and RESPONSE release back-to-back

Therefore:

    CLRT_out ≈ hardware release separation

This should be tens of microseconds or lower depending on the actual
queue and release path. Measure it rather than assuming an exact value.

Overall expected model:

    CLRT_out ≈ max(CLRT_native - D, δ_release)

Do not claim that all output CLRT values are identical.

The research question is whether the mechanism shifts and compresses the
native CLRT distribution enough to disrupt device fingerprinting.

----------------------------------------------------------------------
12. HARDWARE AND PIPELINE CONSTRAINTS
----------------------------------------------------------------------

1. Tofino-1 only.
2. BF-SDE 9.13.1 local compile.
3. BF-SDE 9.13.2 switch validation.
4. No SmartNIC, DPU, eBPF, host pacing, or software queue.
5. No controller fast-path dependency.
6. No Vision-generated blocker packets.
7. No more than one egress MAU stage.
8. Target zero egress tables where the existing release rewrite permits.
9. Keep all load-bearing state, matching and deadline comparison in ingress.
10. Do not combine packet-size padding or splitting with this implementation.
11. Do not optimize away correctness to save stages.
12. Do not modify the completed Defense 2 implementation.

The current implementation uses 10 ingress stages, but three stages are
believed to be dispensable.

For this task:

- first implement the mechanism correctly;
- then identify which three stages are auxiliary;
- strip only clearly dispensable telemetry, guards or research scaffolding;
- compile again;
- report the actual final stage count.

Do not claim seven stages until the compiler confirms seven stages.

----------------------------------------------------------------------
13. MINIMUM MICROBENCHMARKS
----------------------------------------------------------------------

Before loading the full live-inline implementation, create controlled
tests for these cases.

TEST A: ACK only

    READ
    ACK
    no RESPONSE

Expected:

- ACK held until D;
- ACK released;
- blockers terminate;
- fail-open and cleanup remain safe.

TEST B: Early RESPONSE

    READ
    ACK
    RESPONSE arrives before D

Expected:

- ACK queued first;
- RESPONSE queued behind ACK;
- neither exits before D;
- ACK exits before RESPONSE;
- no packet reordering.

TEST C: Late RESPONSE

    READ
    ACK
    ACK deadline expires
    RESPONSE arrives after D

Expected:

- ACK releases at D;
- RESPONSE forwards normally later;
- CLRT reduced by approximately D.

TEST D: RESPONSE near deadline

Test RESPONSE arrival just before, at, and just after the deadline.

Expected:

- no duplicate release;
- no packet loss;
- no response-before-ACK condition;
- deterministic state cleanup.

TEST E: Duplicate READ

Expected:

- one transaction generation;
- one pktgen burst;
- no duplicate blocker reservoir.

TEST F: Duplicate or retransmitted ACK

Expected:

- no second held ACK;
- no deadline corruption;
- no duplicate blocker generation.

TEST G: Stale blocker

Expected:

- blocker from an old generation is dropped;
- it cannot block the next transaction.

----------------------------------------------------------------------
14. COMPILE GATES
----------------------------------------------------------------------

Compile using both SDE environments.

Required results:

1. bf-p4c 9.13.1:
   - zero errors;
   - zero unsupported constructs.

2. bf-p4c 9.13.2:
   - zero errors;
   - successful switch load.

Report:

- ingress stages;
- egress stages;
- SRAM usage;
- TCAM usage;
- PHV usage;
- Map RAM usage;
- stateful ALUs;
- logical tables;
- parser states;
- deparser additions.

Compare the result against:

- current tested pktgen Defense 2;
- existing response-triggered ACK defense;
- new fixed-delay ACK defense.

----------------------------------------------------------------------
15. LIVE SEL-751 EVALUATION
----------------------------------------------------------------------

Use the physical inline topology:

    Vision
      → Tofino
      → SEL-751

Run read-only Class 0 polls only.

For each configuration, collect at least 30 successful transactions:

1. Native forwarding.
2. Existing response-triggered ACK release.
3. New fixed-delay ACK release with D = 1 ms.
4. New fixed-delay ACK release with D = 2 ms.
5. New fixed-delay ACK release with D = 3 ms.
6. Existing response-hold Defense 2 with G = 25 ms.

For the new fixed-delay implementation, measure:

- ACK hold duration;
- output CLRT;
- READ-to-RESPONSE latency;
- packet loss;
- packet reordering;
- TCP retransmissions;
- duplicate ACKs;
- transaction completion;
- blocker count;
- stale blocker count;
- fail-open events.

Preserve every raw PCAP and switch counter output.

Do not append multiple runs into one ambiguous file.

Use separate run directories:

    evidence/fixed_ack_delay/
        native/
        d_1ms/
        d_2ms/
        d_3ms/

----------------------------------------------------------------------
16. EXTERNAL-TRAFFIC SAFETY CHECKS
----------------------------------------------------------------------

Verify on both external links:

    eth.type == 0x88c1

Expected:

    zero packets

Confirm:

1. blocker tokens never reach Vision;
2. blocker tokens never reach the SEL-751;
3. internal trigger packets never reach external ports;
4. original DNP3 packets remain byte-identical;
5. no internal encapsulation is externally visible.

----------------------------------------------------------------------
17. ANALYSIS OUTPUT
----------------------------------------------------------------------

Generate one comparison table:

| Mechanism | Packet held | Release event | Expected CLRT effect |
| Native | None | None | Native distribution |
| Response-triggered ACK hold | ACK | RESPONSE arrival | CLRT near zero |
| Fixed-delay ACK hold | ACK | t_ACK + D | CLRT shifted left |
| Response hold | RESPONSE | t_ACK + G | CLRT clustered near G |

Generate these plots:

1. Native versus fixed-delay ACK CLRT distributions.
2. CLRT distributions for D = 1, 2 and 3 ms.
3. Native, response-triggered ACK hold, fixed-delay ACK hold and
   response-hold Defense 2 on one common axis.
4. End-to-end READ-to-RESPONSE latency.
5. ACK hold duration error:

       actual ACK release time - configured deadline

Do not manufacture values.

Use only measured data.

----------------------------------------------------------------------
18. REQUIRED REPORT CONTENT
----------------------------------------------------------------------

The final implementation report must explain:

1. The exact Case A objective.
2. Why the mechanism is different from response-triggered ACK release.
3. Why it is different from response-hold Defense 2.
4. How request-triggered pktgen is reused.
5. Why K blockers are required.
6. Where the ACK deadline is stored.
7. Where the deadline comparison occurs.
8. How early responses are kept behind the ACK.
9. How late responses are forwarded.
10. How packet ordering is preserved.
11. How fail-open behavior works.
12. How transaction generations prevent stale-token interference.
13. Exact ingress and egress resource usage.
14. Native and protected CLRT statistics.
15. Whether the distribution was shifted or compressed.
16. Added transport and application latency.
17. Any negative results or failed constructions.
18. Remaining limitations.

----------------------------------------------------------------------
19. STOP CONDITIONS
----------------------------------------------------------------------

Stop and document evidence rather than silently changing the design if:

1. the response can overtake the held ACK;
2. Q_HOLD does not preserve ACK-before-RESPONSE FIFO order;
3. the blocker reservoir becomes temporarily empty before the deadline;
4. pktgen produces more than one reservoir per transaction;
5. blockers appear on an external port;
6. the implementation requires controller intervention per transaction;
7. egress requires more than one stage;
8. the ACK cannot be released close to its configured deadline;
9. the mechanism causes TCP instability;
10. the final implementation cannot distinguish early and late responses.

Do not pivot to Case B or packet-size work.

----------------------------------------------------------------------
20. COMMIT PLAN
----------------------------------------------------------------------

Use separate commits for:

1. baseline snapshot and design document;
2. ACK deadline and state machine;
3. Q_HOLD integration;
4. early-response FIFO behavior;
5. late-response forwarding;
6. compile and resource validation;
7. microbenchmarks;
8. live SEL-751 validation;
9. analysis and final report.

At the end, provide:

- branch name;
- commit hashes;
- changed files;
- compile summaries;
- switch-load result;
- stage count;
- test matrix;
- PCAP locations;
- measured CLRT statistics;
- known limitations.

Do not declare completion based only on compilation.
Completion requires a successful live physical SEL-751 test.


Expected mechanism
Fresh READ
    ↓
Request-triggered pktgen creates blockers
    ↓
Q_BLOCK stays occupied

Pure ACK arrives
    ↓
Store deadline = t_ACK + D
    ↓
Place ACK in Q_HOLD

Response before deadline
    ↓
Place response behind ACK in Q_HOLD

At deadline
    ↓
Blockers terminate
    ↓
Q_BLOCK empties
    ↓
ACK releases first
    ↓
Queued response follows

Start with D=2 ms, then evaluate D=1, 2, and 3 ms. The main result is not merely whether the mechanism works, but how each D reshapes the native SEL-751 CLRT distribution.