You are resuming the Tofino P4 implementation of ACK-response timing control for DNP3.

Read this entire instruction before modifying anything.

Your task is to implement and evaluate Dr. Lin’s original ACK-delay idea on the Tofino switch. Do not reinterpret the task as generic request-to-response delay normalization.

======================================================================
1. PRIMARY RESEARCH OBJECTIVE
======================================================================

The target fingerprint is the cross-layer response time, CLRT, used by Formby et al.:

    CLRT = time(DNP3 response) - time(pure TCP ACK)

The relevant native structure is:

    Master request
        ↓
    Pure TCP ACK from outstation
        ↓
    DNP3 application response from outstation

Dr. Lin proposed two controllable cases:

CASE A: REDUCE CLRT
    Delay the existing pure TCP ACK toward the response.
    Keep the DNP3 response at approximately its native release time.
    This reduces ACK→response spacing while adding little or no
    request→response latency.

CASE B: INCREASE CLRT
    Forward the pure TCP ACK normally.
    Delay the DNP3 response.
    This increases ACK→response spacing and increases total
    request→response latency.

These are the two primary policies to implement and evaluate.

Do not confuse them with the previous policy that delayed both the ACK
and response to one request-relative deadline.

======================================================================
2. EXACT CASE DEFINITIONS
======================================================================

Native separate-ACK transaction:

    request at t_req
    pure ACK at t_ack
    response at t_resp

Native CLRT:

    G_native = t_resp - t_ack

----------------------------------------------------------------------
CASE A: ACK_DELAY_REDUCE_CLRT
----------------------------------------------------------------------

Goal:

    Make the visible ACK→response gap smaller.

Required behavior:

    1. Observe and arm on an eligible DNP3 request.
    2. Identify the existing pure TCP ACK.
    3. Hold only the pure ACK.
    4. Do not intentionally delay the response by a large target.
    5. When the response arrives, release the held ACK first.
    6. Release the response after the ACK with only the smallest
       hardware-safe ordering guard.

The defended timing should be:

    t_ack_out = approximately t_resp_ready
    t_resp_out = t_ack_out + delta

Therefore:

    G_reduce = t_resp_out - t_ack_out
             = approximately delta

Expected effect:

    request→ACK increases
    ACK→response decreases
    request→response remains approximately native plus a very small guard

Example:

    Native:
        request = 0.0 ms
        ACK     = 0.1 ms
        response = 16.0 ms
        CLRT = 15.9 ms

    Defended:
        request = 0.0 ms
        ACK     = 15.9 ms
        response = 16.1 ms
        CLRT = 0.2 ms

The principal benefit is low added operational latency.

----------------------------------------------------------------------
CASE B: RESPONSE_DELAY_INCREASE_CLRT
----------------------------------------------------------------------

Goal:

    Make the visible ACK→response gap larger.

Required behavior:

    1. Observe and arm on an eligible DNP3 request.
    2. Identify the existing pure TCP ACK.
    3. Forward the pure ACK immediately.
    4. Record the ACK timestamp.
    5. Select a common device-independent target gap.
    6. Hold the DNP3 response until:

           deadline = t_ack + G_i

    7. Release at:

           t_resp_out = max(t_resp_ready, deadline)

Expected effect:

    request→ACK remains native
    ACK→response increases
    request→response increases

Example:

    Native:
        request = 0.0 ms
        ACK     = 0.1 ms
        response = 16.0 ms
        CLRT = 15.9 ms

    Defended:
        request = 0.0 ms
        ACK     = 0.1 ms
        response = 30.1 ms
        CLRT = 30.0 ms

======================================================================
3. COMBINED ACK-BEARING RESPONSE CASE
======================================================================

Some devices produce:

    request
        ↓
    one ACK-bearing DNP3 response

There is no standalone pure TCP ACK.

For these transactions:

    CLRT, as defined by Formby et al., is unavailable.

Do not invent a pure ACK timestamp.

Do not call request→response time CLRT.

Do not synthesize a TCP ACK in the current phase.

Do not suppress, split, or rewrite the ACK-bearing response.

Primary behavior for combined transactions:

    - classify the transaction as COMBINED;
    - record that no pure ACK exists;
    - bypass the two primary CLRT policies;
    - preserve the packet unchanged.

A separate optional experiment may delay the combined ACK-bearing response
to study request→response timing, but that must be:

    - reported separately;
    - excluded from the primary Dr. Lin CLRT result;
    - described as a combined-response extension;
    - never described as ACK→response normalization.

ACK synthesis is a later research line and is out of scope.

======================================================================
4. CURRENT PROJECT STATE
======================================================================

Inspect the repository before changing code.

Relevant known files may include:

    p4/dcrn.p4
    p4/dcrn_setup.py
    p4/dp8_loopback.py
    p4/M1_local_compile_result.md
    p4/M2_e2e_singlehost_result.md
    p4/e2e_evidence/
    extract_payloads.py
    split_server.py
    run_master.py
    split_ba.py
    ba_dev.py
    RESUME_STATE.md
    WORKING_NOTES.md

Do not assume every filename or location is exact. Locate the actual files.

Known Tofino status:

    - bf-p4c 9.13.1 local compile fits.
    - Ingress measured 9 of 12 stages.
    - On-switch DNP3 request arming works.
    - Response classification works.
    - Recirculation works.
    - Byte preservation works.
    - Real pydnp3 sessions work.
    - The current recirculation hold has produced uncontrolled
      approximately 38 to 100 ms release times.
    - The intended approximately 33 ms release has not yet been
      demonstrated reliably.
    - QID_HOLD must be assigned on every recirculation-egress path.
    - Sparse-frame queue pacing and timestamp refresh remain critical
      hardware questions.
    - MAX_PASS must be a fail-open guard, not the normal release mechanism.

Do not hide or overwrite this current status.

======================================================================
5. TRAFFIC SOURCES
======================================================================

Use the real device captures from Traffic Trace/:

    SEL751
    AB1400
    ION7550

Use them in three distinct ways.

----------------------------------------------------------------------
A. ORIGINAL PCAP ANALYSIS
----------------------------------------------------------------------

Analyze the original captures to determine:

    - number of DNP3 requests;
    - number of pure TCP ACKs;
    - number of ACK-bearing responses;
    - separate versus combined mode;
    - request→ACK;
    - ACK→response;
    - request→response;
    - response sizes;
    - segmentation;
    - retransmissions;
    - connection boundaries.

Expected source behavior based on prior analysis:

    SEL751:
        predominantly separate ACK then response

    AB1400:
        predominantly combined ACK-bearing response

    ION7550:
        predominantly combined ACK-bearing response

Verify this from the actual captures. Do not rely only on memory.

----------------------------------------------------------------------
B. PCAP-DERIVED LIVE TCP REPLAY
----------------------------------------------------------------------

Use extract_payloads.py or the equivalent tool to extract genuine DNP3
application request and response payloads.

Use a live TCP master and replay server through the Tofino switch.

This test provides:

    - valid live TCP state;
    - real sequence and ACK numbers;
    - retransmission behavior;
    - RTO behavior;
    - real DNP3 application bytes.

It does not guarantee reproduction of the original device TCP stack.

The Linux kernel may change:

    - pure ACK behavior;
    - ACK combination;
    - segmentation;
    - packet boundaries;
    - timing;
    - TCP options.

Always classify the resulting wire traffic.

Describe this test as:

    "PCAP-derived DNP3 payload replay over a live Linux TCP connection."

Do not describe it as:

    "Exact replay of the physical device TCP fingerprint."

----------------------------------------------------------------------
C. CONTROLLED SEPARATE-ACK LIVE REPLAY
----------------------------------------------------------------------

The two Dr. Lin cases require:

    request → pure ACK → DNP3 response

Create a controlled replay mode that reliably produces this structure.

Use socket-side behavior only to create the native packet structure.

Possible mechanisms to investigate:

    - TCP_QUICKACK;
    - controlled response readiness;
    - socket scheduling;
    - TCP_NODELAY where appropriate;
    - short application processing delay before send.

Important:

    The socket may be used to cause the kernel to emit a pure ACK.

    The socket must not implement the defense delay.

The switch must perform the actual ACK or response delay.

Do not use:

    sleep(defense_target)

inside the replay application to claim Tofino enforcement.

For every run, verify the actual wire structure before including it in the
CLRT evaluation.

======================================================================
6. MASTER STARTUP BEHAVIOR
======================================================================

The live replay server may support only Class-0 READ transactions and may
not answer ENABLE_UNSOLICITED correctly.

The current run_master.py change that clears unsolClassMask must be placed
behind an explicit command-line option, for example:

    --suppress-startup-unsolicited

Requirements:

    - default behavior must remain normal pydnp3 behavior;
    - the flag must be documented;
    - the experiment manifest must state when it is used;
    - the reason must be recorded;
    - no silent protocol behavior changes.

Document:

    "Startup unsolicited enablement was disabled because the replay server
     contains only captured Class-0 request-response mappings."

======================================================================
7. ELIGIBLE TRAFFIC
======================================================================

Initial scope must remain narrow.

Eligible:

    - IPv4;
    - TCP;
    - DNP3 port 20000;
    - established TCP session;
    - routine solicited Class-0 READ;
    - one outstanding request per flow;
    - clearly matched request and response;
    - clearly classified pure ACK or ACK-bearing response.

Bypass and fail open for:

    - SYN, SYN-ACK, FIN, RST;
    - handshake traffic;
    - retransmissions;
    - duplicate ACKs;
    - SACK recovery;
    - zero-window probes;
    - meaningful window updates;
    - TCP keepalives;
    - out-of-order packets;
    - fragmented IPv4;
    - ambiguous DNP3 parsing;
    - unsolicited DNP3 responses;
    - DNP3 controls;
    - select/operate;
    - direct operate;
    - application CONFIRM;
    - multiple outstanding requests;
    - concurrent ambiguous transactions;
    - unknown sequence state;
    - register collision;
    - state timeout;
    - pass-count exhaustion;
    - queue or parser uncertainty.

Fail open means:

    - forward unchanged;
    - do not drop;
    - do not modify;
    - increment a bypass/fail-open counter;
    - log the reason where possible.

======================================================================
8. TOFINO P4 ARCHITECTURE
======================================================================

The Tofino switch sits inline between the master-facing and
outstation-facing sides.

The P4 pipeline must perform:

    1. Request recognition.
    2. Per-flow transaction arming.
    3. Pure ACK classification.
    4. ACK-bearing response classification.
    5. Policy selection.
    6. Register state updates.
    7. Recirculation decision.
    8. QID_HOLD assignment.
    9. Deadline or event condition check.
    10. Release or fail-open decision.
    11. Counters and telemetry.

The control plane may configure:

    - policy mode;
    - eligible flow entries;
    - target distributions;
    - guard distributions;
    - register defaults;
    - queue configuration;
    - shaping configuration;
    - safety limits.

The control plane must not make per-packet decisions.

No controller involvement in the fast path.

======================================================================
9. PER-FLOW STATE
======================================================================

Design the smallest safe state machine that fits Tofino.

At minimum, consider these logical states:

    IDLE

    ARMED_WAIT_ACK_OR_RESPONSE

    ACK_HELD_WAIT_RESPONSE
        Used for CASE A

    ACK_FORWARDED_WAIT_RESPONSE
        Used for CASE B

    RESPONSE_SEEN_WAIT_ACK_RELEASE
        Used only if the response must wait briefly for the held ACK

    COMPLETE

    BYPASS

Potential register fields:

    valid
    transaction_generation
    policy_mode
    request_timestamp
    request_end_sequence
    expected_ack_number
    pure_ack_seen
    pure_ack_timestamp
    response_seen
    response_timestamp
    ack_release_requested
    ack_released
    target_gap
    deadline
    original_output_port
    timeout_epoch
    bypass_reason

Avoid unnecessary fields and preserve stage headroom.

Use generation values or equivalent protection so stale state cannot match a
later transaction.

Use one outstanding transaction per flow in the initial implementation.

======================================================================
10. CASE A P4 STATE MACHINE
======================================================================

Mode name:

    ACK_DELAY_REDUCE_CLRT

Required packet behavior:

REQUEST:

    - classify eligible request;
    - record request timestamp and sequence state;
    - arm the flow;
    - forward the request normally.

PURE ACK:

    - verify it acknowledges the armed request;
    - record its native arrival timestamp;
    - mark ACK pending;
    - save original master-facing output port;
    - send it into the recirculation hold path;
    - set ig_tm_md.qid = QID_HOLD on every recirculation-egress path;
    - do not release until response_seen is true or safety timeout occurs.

DNP3 RESPONSE:

    - verify it belongs to the armed transaction;
    - set response_seen;
    - request release of the held ACK;
    - do not send the response before the pure ACK;
    - hold the response only for the minimum required ordering guard;
    - release ACK first;
    - release response after delta;
    - complete and clear the transaction state.

The implementation must solve the race between:

    - ACK recirculating;
    - response entering the pipeline;
    - shared register visibility;
    - ACK release;
    - response release.

Do not assume same-cycle register visibility.

Build a microbenchmark to determine the minimum reliable ordering guard.

Initial calibration:

    - use a fixed small guard only to validate correctness;
    - then test a common bounded small-guard distribution.

The final guard must not depend on:

    - device identity;
    - source IP as a device label;
    - response size;
    - source PCAP;
    - native response time;
    - native ACK time.

Acceptance goal for Case A:

    - ACK always precedes response;
    - ACK→response gap becomes a common small distribution;
    - request→response added latency is minimal;
    - zero response-before-ACK violations;
    - zero retransmissions and resets;
    - byte identity remains perfect.

======================================================================
11. CASE B P4 STATE MACHINE
======================================================================

Mode name:

    RESPONSE_DELAY_INCREASE_CLRT

REQUEST:

    - classify eligible request;
    - select a target gap G_i from a common policy;
    - store G_i;
    - arm the transaction;
    - forward request normally.

PURE ACK:

    - verify it acknowledges the request;
    - store t_ack;
    - forward it immediately;
    - compute or store:

          deadline = t_ack + G_i

DNP3 RESPONSE:

    - verify it belongs to the transaction;
    - if now < deadline:
          recirculate through QID_HOLD;
    - if now >= deadline:
          release through the normal output port;
    - if response was already ready after deadline:
          release immediately and record a deadline miss;
    - clear state when the response completes.

Release equation:

    t_resp_out = max(t_resp_ready, t_ack + G_i)

The target distribution must be common and device-independent.

Use two configurations:

    P1_FIXED:
        one fixed target gap for calibration only

    P2_COMMON_BOUNDED:
        final operating candidate

P2 may use discrete values suitable for Tofino, such as:

    G0, G1, G2, G3, G4, G5

Do not hardcode final numerical values without calibration.

Derive the target range from:

    - native CLRT distribution;
    - high-quantile native response readiness;
    - measured scheduler guard;
    - master RTO;
    - fail-open margin.

The lower bound should be high enough to minimize deadline misses.

The upper bound must remain safely below effective RTO.

======================================================================
12. TARGET SELECTION
======================================================================

Do not use a device-specific policy.

Bad:

    SEL uses one gap distribution
    AB1400 uses another
    ION7550 uses another

Bad:

    target selected from IP address
    target selected from response size
    target selected from source PCAP
    target selected from native timing
    target selected from separate/combined mode

Correct:

    one common target sequence or distribution shared by every eligible flow

For Tofino, implement a reproducible common bounded target source.

Preferred first implementation:

    - preloaded target sequence in registers;
    - long sequence;
    - global transaction counter;
    - same sequence for all flows;
    - seed and sequence recorded in experiment manifest.

The index must not be derived from device identity.

Fixed mode is only a calibration control.

======================================================================
13. HOLD PRIMITIVE MUST BE FIXED FIRST
======================================================================

Do not evaluate the two policies using the current uncontrolled 38 to 100 ms
recirculation behavior.

First prove that the switch can enforce controlled timing.

Verify:

    - QID_HOLD is set on every recirculation-egress path;
    - released packets use the normal output queue;
    - bypassed packets use the normal output queue;
    - queue 5 is actually configured and selected;
    - queue counters increase for held packets;
    - global_tstamp or the selected time source refreshes on every pass;
    - deadline comparison matures over recirculation;
    - release is caused by deadline/event condition;
    - MAX_PASS is not the normal release cause.

Run staged hold tests:

    1 ms
    2 ms
    5 ms
    10 ms
    20 ms
    33 ms

For each:

    - target;
    - observed delay;
    - pass count;
    - queue counters;
    - release reason;
    - scheduler error;
    - MAX_PASS count;
    - retransmissions;
    - resets;
    - drops;
    - duplicates;
    - byte identity.

If a lone sparse packet is not paced by the shaped queue:

    1. Prove that result.
    2. Do not add multiple changes at once.
    3. Investigate the minimum fallback.
    4. Only then consider a controlled metronome or pktgen packet to keep
       the internal queue paced.
    5. The metronome must never leave the internal recirculation path.
    6. Record its bandwidth and resource cost.
    7. Do not use it without a separate microbenchmark.

======================================================================
14. PACKET SIZE AND SEGMENTATION
======================================================================

Use real captured responses of different sizes.

At minimum include:

    - SEL751-derived responses;
    - AB1400-derived responses;
    - ION7550-derived responses;
    - small responses;
    - larger responses;
    - multi-segment responses where available.

Measure:

    corr(response_size, scheduler_error)
    corr(response_size, observed_CLRT)
    corr(response_size, added_latency)

The hold mechanism must not create a new device-correlated size/timing channel.

Verify:

    - TCP sequence order;
    - no segment inversion;
    - no duplicate segment;
    - no dropped segment;
    - application reassembly succeeds;
    - byte-identical DNP3 payloads;
    - later segment cannot overtake an earlier held segment.

======================================================================
15. EXPERIMENT MATRIX
======================================================================

Run the following conditions.

----------------------------------------------------------------------
E0: NATIVE / BYPASS
----------------------------------------------------------------------

No ACK or response delay.

Purpose:

    establish native CLRT and transport baseline.

----------------------------------------------------------------------
E1: ACK_DELAY_REDUCE_CLRT_FIXED_GUARD
----------------------------------------------------------------------

Calibration only.

Hold pure ACK until response arrives.
Release ACK before response with a fixed small guard.

Purpose:

    prove the Case A state machine and ordering.

----------------------------------------------------------------------
E2: ACK_DELAY_REDUCE_CLRT_COMMON_BOUNDED_GUARD
----------------------------------------------------------------------

Final Case A candidate.

Use a common bounded small-guard distribution.

Purpose:

    reduce CLRT without creating a perfectly constant new signature.

----------------------------------------------------------------------
E3: RESPONSE_DELAY_INCREASE_CLRT_FIXED
----------------------------------------------------------------------

Calibration only.

Forward ACK immediately.
Hold response to one fixed ACK-relative target.

Purpose:

    prove Case B deadline enforcement.

----------------------------------------------------------------------
E4: RESPONSE_DELAY_INCREASE_CLRT_COMMON_BOUNDED
----------------------------------------------------------------------

Final Case B candidate.

Forward ACK immediately.
Hold response to a common bounded ACK-relative target distribution.

----------------------------------------------------------------------
E5: COMBINED_RESPONSE_EXTENSION
----------------------------------------------------------------------

Optional and separately reported.

For transactions with no pure ACK:

    - classify COMBINED;
    - either bypass;
    - or delay ACK-bearing response using a request-relative policy.

Do not mix E5 into the CLRT evaluation.

======================================================================
16. TEST TOPOLOGIES
======================================================================

Use the following progression.

----------------------------------------------------------------------
T0: LOCAL COMPILE
----------------------------------------------------------------------

Compile with local bf-p4c 9.13.1.

Record:

    - errors;
    - warnings;
    - stage count;
    - critical path;
    - table count;
    - SRAM;
    - TCAM;
    - power estimate.

The current baseline is 9 of 12 ingress stages.

Do not regress beyond the 12-stage hard limit.

----------------------------------------------------------------------
T1: SCRATCH SWITCH FORWARDING
----------------------------------------------------------------------

Compile on the switch SDE 9.13.2.

Verify transparent forwarding and rollback.

No delay policy yet.

----------------------------------------------------------------------
T2: SINGLE-HOST HULK HAIRPIN
----------------------------------------------------------------------

Use the validated dp8/dp9/dp68 topology.

Hulk may host:

    master namespace
    outstation namespace

Use VEPA macvlans only after confirming:

    - source pruning disabled where required;
    - no stale root-namespace IP answering;
    - NetworkManager state recorded;
    - cleanup procedure ready.

Use real pydnp3 and real device-derived DNP3 payloads.

----------------------------------------------------------------------
T3: VISION↔HULK TWO-HOST RIG
----------------------------------------------------------------------

Authoritative external-observer capture on the master-facing side.

Use physical NICs.

Record offloads.

Disable where required:

    tso
    gso
    gro
    lro

Record the exact ethtool state before and after.

----------------------------------------------------------------------
T4: REAL PHYSICAL DEVICES
----------------------------------------------------------------------

Final authoritative device experiment:

    master
        ↕
    Tofino switch
        ↕
    physical SEL751 / AB1400 / ION7550

SEL751 is the primary device for separate-ACK CLRT testing.

AB1400 and ION7550 are primarily combined-response cases unless their wire
traffic shows otherwise.

Do not claim physical-device validation from socket replay alone.

======================================================================
17. CAPTURE REQUIREMENTS
======================================================================

Use authoritative captures after the switch, on the master-facing side.

Where possible also capture before the hold.

Before-hold capture:

    shows native packet readiness.

After-hold capture:

    shows attacker-visible timing.

Do not rely solely on direction-split capture if it is lossy.

If one full-duplex capture contains repeated wire occurrences:

    - document the split method;
    - identify first and last occurrence rules;
    - validate packet matching using TCP sequence, ACK, flags, and payload hash;
    - record ambiguities;
    - never silently discard unmatched packets.

Use packet hashes and sequence information to match before and after packets.

Do not compare capture timestamps as bytes.

Account for checksum offload differences.

DNP3 payload identity must be compared separately and exactly.

======================================================================
18. METRICS
======================================================================

For every eligible transaction, export:

    run_id
    session_id
    profile
    source_pcap
    flow_id
    transaction_id
    observed_ack_mode
    request_timestamp
    pure_ack_timestamp_before
    pure_ack_timestamp_after
    response_ready_timestamp
    response_release_timestamp
    selected_policy
    selected_target_gap
    observed_request_to_ack
    observed_ack_to_response
    observed_request_to_response
    scheduler_error
    response_size
    segment_count
    pass_count
    release_reason
    deadline_miss
    max_pass_fail_open
    retransmission
    reset
    ordering_violation
    duplicate
    drop
    byte_identity

Primary timing values:

    request→ACK
    ACK→response
    request→response

Primary Dr. Lin metric:

    CLRT = ACK→response

Do not call request→response CLRT.

======================================================================
19. FORMBY-STYLE ATTACKER EVALUATION
======================================================================

Build a dedicated CLRT attacker evaluation.

For separate-ACK transactions only:

    CLRT_i = t_response_i - t_pure_ack_i

Use feature families based on the paper:

    - mean CLRT;
    - variance of CLRT;
    - CLRT histogram;
    - approximately 200 bins or a justified equivalent;
    - multiple observation-window sizes.

Evaluate:

    NATIVE
    ACK_DELAY_REDUCE_CLRT
    RESPONSE_DELAY_INCREASE_CLRT

Use grouped splits.

Groups must preserve:

    - hardware run;
    - TCP session;
    - connection;
    - replay sequence;
    - source capture grouping.

Do not randomly split transactions from the same session across train and test.

Report:

    - balanced accuracy;
    - macro precision;
    - macro recall;
    - confusion matrix;
    - confidence interval;
    - per-profile results;
    - number of independent hardware runs;
    - number of classifier resamples.

Do not treat classifier resamples as independent hardware experiments.

For combined transactions:

    - CLRT is missing by definition;
    - do not fill it with zero;
    - do not use a sentinel value in the CLRT-only classifier;
    - analyze ACK mode separately.

======================================================================
20. EXPECTED SCIENTIFIC RESULTS
======================================================================

CASE A should show:

    request→ACK increases
    ACK→response collapses to a small common distribution
    request→response changes only slightly
    low operational latency overhead

CASE B should show:

    request→ACK remains native
    ACK→response increases to a common bounded distribution
    request→response increases
    higher operational latency overhead

The comparison should answer:

    Which policy reduces device classification more effectively?

    Which policy adds less latency?

    Which policy is easier and safer to implement on Tofino?

    Does a small common ACK→response guard create a detectable new signature?

    Does response-delay introduce size-dependent scheduler error?

    Does either policy remain safe under TCP retransmission and RTO behavior?

======================================================================
21. SAFETY AND ACCEPTANCE CRITERIA
======================================================================

A hardware run passes only if:

    - zero packet drops attributable to the policy;
    - zero unexpected duplicates;
    - zero response-before-ACK violations in separate mode;
    - zero TCP resets;
    - zero retransmissions in established steady-state traffic;
    - zero DNP3 application failures;
    - byte-identical DNP3 responses;
    - correct request-response matching;
    - no state leakage between transactions;
    - no stale register matches;
    - no policy applied to bypass traffic;
    - release caused by the intended condition;
    - MAX_PASS not used during normal successful cases;
    - cleanup and rollback succeed.

Case A additionally requires:

    - ACK held successfully;
    - response not given a large artificial delay;
    - ACK released before response;
    - added request→response latency within declared small bound.

Case B additionally requires:

    - pure ACK forwarded immediately;
    - response released near ACK-relative target;
    - small bounded scheduler error;
    - low deadline-miss rate;
    - RTO-safe operation.

======================================================================
22. WHAT NOT TO DO
======================================================================

Do not:

    - redesign the work as generic request→response normalization;
    - delay both ACK and response to one 33 ms request-relative target in
      the primary Dr. Lin experiment;
    - call request→response timing CLRT;
    - synthesize a TCP ACK;
    - suppress an ACK;
    - coalesce ACK and response;
    - rewrite TCP sequence or ACK numbers;
    - modify DNP3 bytes;
    - pad or split packets in this phase;
    - use application sleep as the defense;
    - claim live socket replay reproduces the physical device TCP stack;
    - claim raw PCAP replay proves live TCP safety;
    - use one final fixed timing target;
    - use device-specific target distributions;
    - choose targets from IP, device label, packet size, or native timing;
    - treat uncontrolled 38 to 100 ms output as common-bounded policy;
    - treat MAX_PASS fail-open as successful deadline release;
    - silently change pydnp3 startup behavior;
    - collapse all profiles into one pooled result;
    - ignore combined versus separate ACK mode;
    - insert missing CLRT values as zero;
    - use ungrouped random train/test splits;
    - claim timing-channel elimination from a single small run;
    - claim physical-device validation from Hulk socket replay;
    - add metronome traffic before proving sparse-frame pacing failure;
    - touch the shared switch without a rollback plan;
    - leave the switch or Hulk network configuration altered after a run;
    - store passwords, secrets, or sudo credentials;
    - commit PCAPs containing secrets without review;
    - add Claude attribution, codenames, or unsupported claims.

======================================================================
23. DEVELOPMENT GATES
======================================================================

GATE 0: REPOSITORY AUDIT

    - inspect current code and evidence;
    - confirm branch;
    - confirm working tree;
    - identify untracked work;
    - identify current switch program;
    - create no changes yet.

GATE 1: POLICY SPECIFICATION

    - write the two state machines;
    - define metrics;
    - define bypass rules;
    - define acceptance criteria;
    - add Python reference model and unit tests.

GATE 2: HOLD PRIMITIVE

    - fix QID_HOLD;
    - prove timestamp refresh;
    - prove controlled delay;
    - prove deadline release;
    - prove MAX_PASS is only fail-open.

GATE 3: LOCAL P4 COMPILE

    - compile;
    - resource report;
    - stage-fit confirmation;
    - no switch touch.

GATE 4: ON-SWITCH TRANSPARENT FORWARDING

    - install;
    - byte-identical forwarding;
    - rollback;
    - stop and report.

GATE 5: CASE A MICROBENCHMARK

    - separate ACK;
    - hold ACK;
    - response arrival triggers ACK release;
    - ACK-before-response guaranteed;
    - fixed small guard;
    - stop and report.

GATE 6: CASE B MICROBENCHMARK

    - ACK forwarded;
    - response held to ACK-relative deadline;
    - fixed target;
    - stop and report.

GATE 7: COMMON BOUNDED POLICIES

    - bounded guard for Case A;
    - bounded target gap for Case B;
    - no device-specific selection.

GATE 8: DEVICE-DERIVED LIVE REPLAY

    - SEL751;
    - AB1400;
    - ION7550;
    - real captured response bytes;
    - actual wire ACK mode classified.

GATE 9: VISION↔HULK CAMPAIGN

    - independent physical runs;
    - external-observer capture;
    - attacker evaluation.

GATE 10: PHYSICAL DEVICE CAMPAIGN

    - SEL751 separate-ACK primary test;
    - AB1400 and ION7550 combined extension;
    - final evidence.

Do not mark a later gate complete because an earlier software model passed.

======================================================================
24. SWITCH AUTHORIZATION
======================================================================

Local code changes and unprivileged local compilation are authorized.

Before touching the shared Tofino switch:

    - record current program;
    - record port configuration;
    - record traffic-manager configuration;
    - prepare rollback;
    - prepare cleanup;
    - show the exact commands;
    - request explicit GO if no current switch authorization exists.

Once a switch window is authorized:

    - make only the gated change;
    - collect evidence;
    - restore the co-resident program;
    - restore ports and queues;
    - verify normal forwarding;
    - stop and report before adding the next mechanism.

======================================================================
25. REQUIRED DELIVERABLES
======================================================================

Create or update:

    p4/ACK_DELAY_POLICY.md

        - Dr. Lin objective
        - Formby CLRT definition
        - Case A
        - Case B
        - combined limitation
        - equations
        - state diagrams
        - bypass policy

    p4/ACK_DELAY_STATE_MACHINE.md

        - states
        - transitions
        - register fields
        - race handling
        - timeout behavior
        - fail-open behavior

    p4/ACK_DELAY_EXPERIMENT_PLAN.md

        - conditions
        - topologies
        - metrics
        - attacker evaluation
        - acceptance criteria

    p4/ACK_DELAY_CURRENT_STATUS.md

        - completed
        - measured
        - blocked
        - unresolved
        - next gate

    p4/evidence/ack_delay/

        - PCAPs
        - JSON
        - CSV
        - resource reports
        - switch logs
        - queue counters
        - manifests
        - hashes
        - plots

    tests/

        - Python policy tests
        - state-transition tests
        - target-selection tests
        - fail-open tests
        - parser classification tests
        - conformance tests against P4 behavior where possible

Update:

    RESUME_STATE.md
    WORKING_NOTES.md
    phase_status.json or equivalent

Use SHA-256 manifests for evidence.

======================================================================
26. REQUIRED REPORTING FORMAT
======================================================================

At every checkpoint, report:

OPERATION REVIEW

    - exact changes made;
    - exact commands run;
    - what was measured;
    - what was inferred;
    - what remains unproven.

RESULT TABLE

    - native;
    - Case A;
    - Case B;
    - combined extension if run.

TRANSPORT SAFETY

    - retransmissions;
    - resets;
    - ordering;
    - drops;
    - duplicates;
    - byte identity.

TOFINO RESOURCES

    - stages;
    - tables;
    - SRAM;
    - TCAM;
    - queue configuration;
    - recirculation passes;
    - internal bandwidth.

SCIENTIFIC INTERPRETATION

    - effect on CLRT;
    - effect on request→response;
    - latency overhead;
    - residual channels;
    - limitations.

CURRENT STATUS

    - PASS;
    - PASS_WITH_LIMITATION;
    - IN_PROGRESS;
    - BLOCKED;
    - FAIL.

NEXT GATE

    - one precise next action;
    - no broad menu unless a real decision is required.

======================================================================
27. FIRST ACTION IN THIS TURN
======================================================================

Begin with a repository and evidence audit.

Then produce:

    1. A concise reconstruction of the current Tofino implementation.
    2. A comparison between the existing DCRN behavior and Dr. Lin’s two
       ACK-centric cases.
    3. A file-by-file implementation plan.
    4. The proposed P4 state machine.
    5. The minimum changes required to implement Case A first.
    6. A list of current hardware unknowns.
    7. A local compile plan.
    8. A switch-touch gate.

Do not touch the switch in the first action unless a valid explicit
authorization for the current window already exists.

The first implementation priority is:

    CASE A: ACK_DELAY_REDUCE_CLRT

because this is the most direct realization of Dr. Lin’s original idea and
has the lowest expected request→response latency overhead.

After Case A passes, implement:

    CASE B: RESPONSE_DELAY_INCREASE_CLRT

Do not start ACK synthesis.
Do not combine this work with padding or splitting.
Do not broaden the eligible DNP3 operation set.