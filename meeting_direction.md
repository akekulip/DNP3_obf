PROJECT DIRECTIVE: REFOCUS AND COMPLETE CASE A DEFENSE 3


Do not load commit caa3ecc onto the switch.

Commit caa3ecc is accepted as an exploratory READ-anchored dual-release
artifact. Preserve its source, reports, compiler evidence and tests
unchanged. It is not the implementation requested by Dr. Lin in the
latest meeting.

======================================================================
1. RESEARCH OBJECTIVE
======================================================================

The active task remains Case A only:

    Class-0 READ
        → pure TCP ACK
        → DNP3 RESPONSE

Implement the new mechanism introduced by Dr. Lin, named:

    DEFENSE 3 — PREDETERMINED ACK-DELAY RELEASE

The switch must hold the original pure TCP ACK for a configured delay D:

    d_ACK = t_ACK + D

The ACK release must not depend on RESPONSE arrival.

The intended CLRT transformation is:

    CLRT_out ≈ max(CLRT_native − D, δ_release)

Two packet-arrival cases must work.

CASE A — RESPONSE arrives after the ACK deadline:

    ACK arrives
        → ACK held until t_ACK + D
        → ACK released
        → RESPONSE arrives later
        → RESPONSE forwarded normally

CASE B — RESPONSE arrives before the ACK deadline:

    ACK arrives and is held
        → RESPONSE arrives before t_ACK + D
        → RESPONSE is queued behind ACK
        → at the deadline ACK leaves first
        → RESPONSE follows through the same FIFO

This is not Defense 2.

Defense 2:
    forwards ACK immediately and holds RESPONSE until t_ACK + G.

Defense 3:
    holds ACK until t_ACK + D and holds only an early RESPONSE needed to
    preserve ACK-before-RESPONSE ordering.

Do not redesign Defense 3 into a READ-anchored two-deadline mechanism.

======================================================================
2. NON-NEGOTIABLE SCOPE
======================================================================

Stay within these boundaries:

- Tofino-1 only.
- Case A only.
- One active protected transaction in the initial implementation.
- One protected TCP session.
- Sequential Class-0 polling.
- No packet-size padding or splitting.
- No Case B device behavior.
- No SmartNIC, DPU, eBPF or host-edge mechanism.
- No per-transaction controller action.
- No host-generated blocker tokens.
- No four-queue production architecture.
- No second response deadline.
- No attempt to normalize every possible traffic interval.
- No attempt to build a device classifier inside the switch.

The implementation goal is to reshape the CLRT feature, not to solve
universal traffic-analysis anonymity.

======================================================================
3. DO NOT DECLARE THE TASK IMPOSSIBLE
======================================================================

A compiler failure, PHV allocation problem, queue anomaly, pktgen issue,
state race or failed test is not permission to declare the mechanism
impossible.

For every obstacle:

1. Reproduce it deterministically.
2. Reduce it to the smallest failing microbenchmark.
3. Preserve the compiler output, BFRT readback, trace or PCAP.
4. Identify the actual root cause.
5. Consult:
   - the installed BF-SDE 9.13.1 and 9.13.2 documentation;
   - official Tofino examples and BFRT schema;
   - prior successful and failed constructions in this repository;
   - relevant primary research papers.
6. Convene the expert panel described below.
7. Produce at least two technically valid Tofino-1 constructions.
8. Compile or microbenchmark the alternatives.
9. Select the simplest construction that preserves correctness.
10. Return to the main implementation.

Do not respond with:
    “not possible,”
    “Tofino cannot do this,”
    “use a controller,”
    “move to a SmartNIC,”
    or “pivot to another defense”

unless the exact hardware limitation has been demonstrated by primary
documentation and a minimal silicon or compiler experiment.

Even when one construction is refuted, continue with an equivalent
Tofino-1 construction.

======================================================================
4. FORM AN EXPERT REVIEW PANEL FIRST
======================================================================

Before modifying P4, launch independent expert agents with these roles:

A. Tofino pipeline and PHV architect
   - inspect stage dependencies, logical-table saturation, PHV lifetimes,
     SALU use and possible egress placement.

B. Traffic Manager and queue-scheduling engineer
   - verify the minimal two-queue construction, FIFO assumptions, blocker
     reservoir behavior and release ordering.

C. TCP and DNP3 protocol engineer
   - define exact READ, pure ACK, RESPONSE, retransmission and keepalive
     predicates.

D. Adversarial traffic-analysis researcher
   - define the precise CLRT attacker model;
   - distinguish native-trained and defense-aware attackers;
   - determine what fixed D can and cannot claim.

E. Experimental-methods and statistics reviewer
   - define calibration and evaluation datasets;
   - select D values without fitting and testing on the same campaign;
   - define classifier and distribution metrics.

F. Safety and verification engineer
   - inspect cleanup, fail-open, stale-generation handling, transaction
     ordering, switch loading and restoration.

G. Skeptical systems-paper reviewer
   - attack novelty, assumptions, unsupported claims and unnecessary
     architecture.

Each agent must independently produce a short technical memo.

Save them under:

    design/defense3_panel/
        01_tofino_architect.md
        02_tm_engineer.md
        03_protocol_engineer.md
        04_traffic_analysis.md
        05_experimental_methods.md
        06_safety_review.md
        07_skeptical_reviewer.md

Then conduct a synthesis panel.

The synthesis must produce:

    design/defense3_panel/CONSENSUS.md

It must explicitly state:

- essential functionality;
- unnecessary functionality;
- ingress-only logic;
- candidate egress logic;
- minimum persistent state;
- minimum queues;
- expected stage use;
- primary risks;
- resolved disagreements;
- chosen implementation.

The panel is advisory. After synthesis, continue automatically into
implementation. Do not stop merely to report panel opinions.

======================================================================
5. INVENTORY AND FREEZE EXISTING WORK
======================================================================

Record:

- current branch and commit;
- exploratory commit caa3ecc;
- exact proven Defense 2 pktgen baseline;
- stripped baseline commit;
- current compiler versions;
- current switch program and state;
- rollback procedure.

Create:

    design/DEFENSE3_BASELINE.md

Create a new branch:

    research/case-a-defense3-fixed-ack-delay

Do not modify:

- the proven Defense 2 implementation;
- the READ-anchored dual-release branch;
- four-queue oracle evidence;
- prior PCAPs and reports.

Copy only components needed for Defense 3 into new files.

Suggested files:

    p4/case_a_defense3_fixed_ack_delay.p4
    setup/case_a_defense3_fixed_ack_delay_setup.py
    run/run_defense3.sh
    run/poll_defense3.py
    analysis/analyze_defense3.py
    design/CASE_A_DEFENSE3_DESIGN.md
    evidence/defense3/
    reports/CASE_A_DEFENSE3_REPORT.md

======================================================================
6. MINIMAL DEFENSE 3 ARCHITECTURE
======================================================================

Use exactly two internal queues:

    Q_BLOCK — high priority
    Q_HOLD  — low priority FIFO

Required order:

    Q_BLOCK > Q_HOLD

Q_BLOCK contains one validated K=64 internal blocker reservoir.

Q_HOLD contains:

    original pure TCP ACK
    followed by the original RESPONSE only when the RESPONSE arrives
    before ACK release

Use one deadline:

    ack_deadline = t_ACK + D

Use one blocker class.

Use one request-triggered pktgen burst:

    K = 64

K=64 is the validated safe reservoir depth for the current scheduler and
loopback configuration. Do not claim that 64 is mathematically minimal.

Do not generate 128 blockers.

Do not use:

    Q_ABLOCK
    Q_ACK
    Q_RBLOCK
    Q_RESP as four production queues
    d_RESP
    response blockers
    READ-relative A and R
    Q_FINAL

======================================================================
7. TRANSACTION LIFECYCLE
======================================================================

FRESH ELIGIBLE READ

When a new protected Class-0 READ is detected:

1. Confirm no protected transaction is active.
2. Advance transaction generation exactly once.
3. Store the expected master ACK value.
4. Store or select the expected relay TCP sequence state.
5. Set:
       transaction_active = 1
       awaiting_ack       = 1
       deadline_valid     = 0
       response_queued    = 0
6. Trigger exactly one internal K=64 blocker burst.
7. Forward the original READ byte-identically to the relay.
8. Suppress a second burst for a duplicate or retransmitted READ.

If another eligible READ arrives while a transaction is active:

    forward it normally
    increment CONCURRENT_TRANSACTION_ESCAPE
    do not overwrite active state
    do not generate another reservoir

BEFORE ACK ARRIVAL

Returning current-generation blockers must continue circulating while:

    deadline_valid == 0

They must remain bounded by a fail-open pass budget.

If the ACK never arrives:

    terminate blockers through fail-open
    clean transaction state
    record ACK_MISSING_FAIL_OPEN

MATCHING PURE TCP ACK

When the exact transaction ACK arrives:

1. Verify the exact ACK predicate.
2. Record:
       t_ACK = ingress hardware timestamp
3. Store:
       ack_deadline = t_ACK + D
4. Set:
       deadline_valid = 1
       awaiting_ack   = 0
5. Enqueue the original ACK into Q_HOLD.
6. Do not forward it immediately.
7. Do not trigger pktgen again.
8. Suppress duplicate held ACKs.

EARLY RESPONSE

If the matching RESPONSE arrives before the ACK has completed its release:

1. Enqueue the original RESPONSE into Q_HOLD.
2. Because ACK was inserted first, FIFO must preserve:
       ACK → RESPONSE
3. Set:
       response_queued = 1
4. Do not create a second deadline.
5. Do not create response blockers.

LATE RESPONSE

If the matching RESPONSE arrives after the ACK release pass:

1. Forward it normally.
2. Do not enqueue it into Q_HOLD.
3. Clean transaction state after forwarding.
4. Record RESPONSE_AFTER_ACK_RELEASE.

BLOCKER RETURN

For each valid current-generation blocker:

    if deadline_valid == 0:
        decrement fail-open budget
        return to Q_BLOCK

    else if now < ack_deadline:
        decrement fail-open budget
        return to Q_BLOCK

    else:
        terminate
        do not re-enqueue

The comparison occurs in ingress.

When all blockers terminate:

    Q_BLOCK becomes empty
        → Q_HOLD becomes eligible
        → ACK leaves
        → early RESPONSE, if present, follows

ACK RELEASE PASS

On the released ACK’s dp8 return pass:

1. Assign the master-facing output port and normal final FIFO.
2. Mark release using generation-bound state:

       ack_release_gen = current_generation

3. Prevent the ACK from being held again.
4. Preserve original external packet bytes.

Do not use a stale Boolean such as ack_released=1.

Use:

    ack_release_gen == current_generation

to decide whether a later RESPONSE belongs to the post-release path.

EARLY RESPONSE RELEASE PASS

The RESPONSE queued behind ACK must:

1. follow ACK through the same final master-facing FIFO;
2. preserve byte identity;
3. complete and clean the active transaction;
4. invalidate the generation safely.

======================================================================
8. EXACT PACKET CLASSIFICATION
======================================================================

Do not use the coarse ACK classifier from the skeleton.

The protected ACK predicate must include:

- relay-facing ingress direction;
- protected session or installed 5-tuple;
- IPv4/TCP structure valid for the prototype;
- ACK-only flags;
- zero TCP payload;
- expected TCP acknowledgment number;
- expected relay TCP sequence;
- active current generation;
- one-shot AWAITING_ACK state.

It must reject:

- SYN-ACK;
- FIN-ACK;
- RST;
- PSH/data packets;
- keepalives with retrograde sequence numbers;
- duplicate ACKs;
- ACKs outside an active transaction;
- unrelated TCP flows.

The protected RESPONSE predicate must include:

- relay-facing ingress;
- protected reverse session;
- active current generation;
- expected TCP sequence and acknowledgment relationship;
- DNP3 solicited RESPONSE classification;
- one-shot response state.

State the response-segmentation scope explicitly.

If the current prototype supports only the observed single-segment
Class-0 response:

    bypass unsupported segmented responses
    increment UNSUPPORTED_SEGMENTATION
    clean or fail open safely

Do not silently claim multi-segment support.

======================================================================
9. MINIMUM PERSISTENT STATE
======================================================================

The panel must attempt to implement the core using no more state than:

- active transaction generation;
- expected master acknowledgment;
- expected relay sequence;
- ACK deadline;
- deadline-valid marker;
- ACK-release generation;
- compact transaction state;
- optional cleanup/watchdog value.

Collapse booleans into a compact state value when it reduces tables and
dependencies.

Do not add separate registers merely for convenient telemetry.

Detailed timestamps and counters belong in an instrumented build.

======================================================================
10. INGRESS VERSUS EGRESS ENGINEERING
======================================================================

The following must remain in ingress:

- READ, ACK, RESPONSE and blocker classification;
- transaction and generation matching;
- deadline installation;
- deadline comparison;
- stale-token handling;
- queue selection;
- early-versus-late RESPONSE decision;
- fail-open decision.

Investigate moving only stateless work to egress:

- internal role-marker cleanup;
- internal shim removal;
- final stateless port/header rewrite;
- release-path counter;
- measurement-only release timestamp.

Do not assume egress migration saves resources.

Compile and compare at least these variants:

A. all required logic in ingress;
B. final release rewrite and marker cleanup in egress;
C. egress rewrite plus measurement-only counter/timestamp.

For each variant report:

- ingress stages;
- egress stages;
- critical path;
- logical table IDs by stage;
- PHV;
- SRAM;
- Map RAM;
- TCAM;
- SALU use.

Select the simplest variant that:

- compiles;
- uses no more than one egress stage;
- preserves correctness;
- leaves meaningful ingress margin.

Do not move load-bearing state to egress.

======================================================================
11. RESOURCE-LED RE-ENGINEERING
======================================================================

Start from the stripped baseline, not from the full dual-release program.

Remove:

- second deadline register;
- second expiry table;
- second blocker role;
- second blocker budget;
- four-queue action branches;
- Q_FINAL;
- READ-relative target selection;
- response-blocker generation;
- dual-release telemetry.

Reuse:

- request-triggered pktgen;
- K=64 blocker reservoir;
- whole-container expiry match;
- generation-bound state pattern;
- exact trace accounting;
- transactional restore runner;
- negative-control analyzer;
- known-safe compiler idioms.

Compile after every substantive addition.

Maintain a resource ledger:

    reports/DEFENSE3_RESOURCE_LEDGER.md

Do not wait until the full implementation to discover stage pressure.

Target:

    ingress <= 10/12 stages
    egress  <= 1 stage

Lower is preferable, but correctness has priority.

======================================================================
12. EXPERT FAILURE-RESOLUTION PROCESS
======================================================================

When a test or compile fails, automatically create a failure packet:

    evidence/defense3/failures/<failure-id>/

Include:

- exact source commit;
- compiler or runtime command;
- complete output;
- register and queue readback;
- packet trace where applicable;
- smallest reproduction;
- suspected dependency graph;
- proposed alternatives.

Reconvene only the relevant expert agents.

They must debate:

- whether the failure is architectural;
- whether it is a compiler placement issue;
- whether a table/action can be collapsed;
- whether a register dependency can be rewritten;
- whether stateless work can move to egress;
- whether an equivalent queue construction exists.

The panel must choose and test a resolution.

Do not merely document a hurdle and stop.

======================================================================
13. SYNTHETIC IMPLEMENTATION GATES
======================================================================

GATE 1 — RESOURCE AND LOAD

Require:

- BF-SDE 9.13.1 compile PASS;
- BF-SDE 9.13.2 compile PASS;
- switch load PASS;
- queue priority write and readback PASS;
- pktgen configuration PASS;
- transactional restore PASS.

GATE 2 — ONE NORMAL TRANSACTION

Use synthetic READ, ACK and RESPONSE events.

Start with:

    D = 2 ms

Require:

- one READ;
- one K=64 blocker burst;
- one ACK admitted to Q_HOLD;
- one early RESPONSE admitted behind ACK;
- no ACK before t_ACK + D;
- no RESPONSE before ACK;
- ACK released first;
- RESPONSE released second;
- all blockers terminate;
- transaction returns clean.

GATE 3 — FIVE NORMAL TRANSACTIONS

Run five consecutive transactions.

Require 5/5:

- exact blocker counts;
- no premature release;
- ACK-before-RESPONSE;
- no stale-generation interference;
- no packet loss or duplicate release;
- clean state after every transaction.

GATE 4 — THREE ESSENTIAL BOUNDARIES

A. RESPONSE arrives just before ACK deadline:
   - queue behind ACK;
   - ACK remains first.

B. RESPONSE arrives after ACK release:
   - RESPONSE forwards normally;
   - no re-hold.

C. Missing RESPONSE:
   - ACK still releases at D;
   - watchdog cleans state safely.

Run each three times.

Only after these pass, run:

- duplicate READ;
- duplicate ACK;
- keepalive during active transaction;
- missing ACK;
- stale token;
- FIN/RST;
- unsupported segmentation;
- timestamp wrap.

Do not build an excessive test matrix before the core lifecycle works.

======================================================================
14. PHYSICAL SEL-751 VALIDATION
======================================================================

After synthetic gates pass, integrate the physical SEL-751.

Use read-only Class-0 polls only.

Run an independent calibration campaign first:

    native n >= 100

Lock D values after calibration.

Then run independent evaluation arms:

    native
    Defense 1
    Defense 2
    Defense 3 D=1 ms
    Defense 3 D=2 ms
    Defense 3 D=3 ms

Use at least 100 successful transactions per final arm where practical.

Use randomized complete blocks and an absolute monotonic polling schedule.

Measure:

- READ→ACK;
- ACK→RESPONSE;
- READ→RESPONSE;
- ACK hold duration;
- configured-deadline error;
- release tail;
- packet loss;
- reorder;
- retransmissions;
- duplicate ACKs;
- transaction completion;
- late-response fraction;
- fail-open count;
- internal blocker leakage.

Verify on external links:

    eth.type == 0x88C1

Expected:

    zero packets

Do not mix unrelated campaigns or append to existing CSV files.

======================================================================
15. ATTACKER AND CLASSIFIER EVALUATION
======================================================================

Do not assume the switch knows the attacker’s profile.

The switch uses a configured D and does not run a classifier.

Evaluate two attacker models where the available dataset supports them:

A. Native-trained attacker
   - train on native labeled traffic;
   - test on Defense 3 traffic;
   - measure whether deployment invalidates an existing model.

B. Defense-aware attacker
   - train and test on defended traces from multiple devices or
     configurations using the same policy.

Do not claim cross-device anonymity with only one physical relay.

If multiple labeled timing profiles do not exist:

- report the limitation;
- evaluate the transformation of the SEL-751 distribution;
- evaluate native-versus-protected detectability;
- provide a concrete multi-device acquisition plan;
- do not fabricate labels.

Do not use binned entropy as the only result.

Report:

- complete distributions;
- quantiles;
- correlation;
- mutual information where labels exist;
- classifier accuracy, precision, recall and confusion matrix where
  justified;
- latency-versus-clamping tradeoff for D.

The main research question is:

    How does predetermined ACK delay D reshape the native CLRT
    distribution, and how much classifier degradation is obtained for
    the ACK latency introduced?

======================================================================
16. CLAIM BOUNDARIES
======================================================================

Supportable initial claim:

    Defense 3 implements a predetermined ACK-delay transformation for
    Case A DNP3 traffic entirely on Tofino-1, without endpoint changes,
    host-generated blockers or controller fast-path release.

Possible empirical claim:

    For responses arriving before the configured ACK deadline, the
    mechanism preserves ACK-before-RESPONSE ordering and clamps the
    observed CLRT near the hardware release separation.

Do not claim:

- universal traffic-analysis resistance;
- all-interval normalization;
- complete anonymity;
- multi-device concurrency;
- support for untested segmentation;
- that K=64 is minimal;
- that a recognizable defense is indistinguishable from native traffic.

======================================================================
17. END-TO-END COMPLETION REQUIREMENT
======================================================================

Continue through:

1. expert-panel review;
2. architecture synthesis;
3. stripped implementation;
4. compile probes;
5. resource optimization;
6. synthetic tests;
7. safety tests;
8. physical SEL validation;
9. statistical analysis;
10. classifier evaluation where supported;
11. final reports;
12. repository cleanup;
13. commit and rollback verification.

Do not stop after design, compilation or one successful synthetic test.

Do not ask for approval between ordinary engineering phases.

Switch access is authorized for this Defense 3 task provided every
hardware run uses:

- a pre-run snapshot;
- isolated test configuration;
- trap-based restoration;
- exactly one bf_switchd verification;
- explicit Defense 2 restoration;
- queue and shaper restoration;
- preserved logs and evidence.

Stop only for:

- a genuine physical safety risk;
- loss of switch access;
- missing credentials that cannot be avoided;
- an action that could operate or reconfigure the physical relay;
- a requirement to change the SEL-751 configuration.

Read-only Class-0 polling is permitted.

======================================================================
18. FINAL DELIVERABLES
======================================================================

Produce:

    design/CASE_A_DEFENSE3_DESIGN.md
    design/defense3_panel/CONSENSUS.md
    p4/case_a_defense3_fixed_ack_delay.p4
    setup/case_a_defense3_fixed_ack_delay_setup.py
    run/run_defense3.sh
    run/poll_defense3.py
    analysis/analyze_defense3.py
    reports/DEFENSE3_RESOURCE_LEDGER.md
    reports/CASE_A_DEFENSE3_REPORT.md
    evidence/defense3/

Final report must include:

- exact architecture;
- exact state machine;
- exact ACK and RESPONSE predicates;
- queue configuration;
- pktgen construction;
- resource usage;
- ingress/egress placement experiments;
- synthetic evidence;
- physical evidence;
- timing distributions;
- classifier results where supported;
- latency tradeoff;
- failures and resolved hurdles;
- unsupported claims;
- remaining limitations;
- branch and commit hashes;
- rollback procedure.

The final completion statement must distinguish:

    designed
    compiled
    loaded
    synthetically validated
    physically validated
    statistically evaluated

Do not report “complete” unless all applicable stages have passed.