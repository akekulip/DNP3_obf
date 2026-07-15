You are working inside the existing DNP3 experimental repository. Before editing anything, inspect the complete repository, especially the current OpenDNP3 master, outstation, replay server, split harness, timing scripts, packet analyzers, lab configuration, and existing experiment reports.

You also have access to these real-device PCAP traces:

- AB1400.pcap
- AB1400L.pcap
- SEL751.pcap
- SEL751L.pcap
- ION7550.pcap
- ION7550L.pcap

Research objective
Implement and evaluate protocol-aware timing manipulation for DNP3/TCP traffic.

The work must proceed in two phases.

PHASE 1 is the primary implementation:
For the behavior we currently have, where the TCP ACK is piggybacked with the DNP3 application RESPONSE, add bounded response-time normalization.

PHASE 2 is a follow-on experiment:
For devices such as the SEL-751 that emit a separate pure TCP ACK before the DNP3 RESPONSE, support experiments that delay:
- the existing pure TCP ACK only;
- the DNP3 response only;
- both packets independently;
- or neither packet.

Do not start with TCP ACK synthesis. Do not forge a new TCP ACK in the first implementation.

==================================================
1. FIRST STUDY AND DOCUMENT THE REAL TRACE BEHAVIOR
==================================================

Parse all six PCAPs directly. Do not rely only on filenames or assumptions.

For every TCP flow using DNP3 port 20000, identify:

- client/master IP and port;
- outstation/device IP and port;
- payload-bearing DNP3 request;
- first reverse-direction TCP packet;
- whether that first packet is a pure ACK;
- first reverse-direction payload-bearing DNP3 response;
- request-to-first-ACK time;
- request-to-response time;
- ACK-to-response time;
- request payload size;
- response payload size;
- TCP flags;
- TCP sequence and acknowledgement numbers;
- retransmissions, duplicate ACKs, resets, or out-of-order packets.

Classify every transaction as:

A. COMBINED_ACK_RESPONSE
   The first reverse-direction response packet carries both:
   - TCP ACK
   - DNP3 application payload

B. SEPARATE_ACK_RESPONSE
   A pure TCP ACK appears first, followed later by a DNP3 payload-bearing response.

C. OTHER_OR_AMBIGUOUS
   Any transaction that cannot be cleanly classified.

Validate the following expected high-level pattern, but report the actual measured values rather than blindly assuming them:

- SEL-751 traces should mostly show SEPARATE_ACK_RESPONSE.
- AB1400 and ION7550 traces should mostly show COMBINED_ACK_RESPONSE.

Generate:

- reports/ack_trace_characterization.csv
- reports/ack_trace_characterization.json
- reports/ack_trace_summary.md

The CSV must include one row per transaction.

The summary must include per-device:

- total transactions;
- percentage combined;
- percentage separate;
- median, p95, and maximum request-to-ACK;
- median, p95, and maximum request-to-response;
- median, p95, and maximum ACK-to-response gap;
- request and response payload-size distributions;
- retransmission/reset counts.

Do not call the DNP3 response an “application ACK.”
Use the correct terms:

- pure TCP ACK;
- ACK-bearing DNP3 RESPONSE;
- DNP3 application CONFIRM only when an actual DNP3 CONFIRM function is present.

==================================================
2. PHASE 1: BOUNDED NORMALIZATION OF COMBINED ACK + RESPONSE
==================================================

Current behavior:
The outstation generates the DNP3 RESPONSE quickly enough that the operating system piggybacks the TCP ACK on the same TCP segment.

Goal:
Hold the already-generated ACK-bearing DNP3 RESPONSE until a bounded, class-independent target time measured from request arrival.

This is not additive jitter.

Wrong design:

    visible_delay = native_processing_time + random_jitter

Correct design:

    target_delay = sample from a common bounded distribution
    desired_release = request_arrival + target_delay
    actual_release = max(response_ready_time, desired_release)

The target distribution must not depend on:

- CROB count;
- response size;
- request size;
- native response-ready time;
- device identity;
- database size;
- number of points;
- secret or protected transaction characteristics.

Implement at least these modes:

1. native
   Send the response immediately as currently implemented.

2. fixed-normalized
   Use one configurable target delay from request arrival.

3. bounded-normalized
   Sample a target from a configurable bounded distribution.

Initially support:

- uniform distribution;
- deterministic PRNG seed;
- configurable lower and upper bounds in milliseconds.

Example:

    target_delay_ms = random.uniform(10.0, 15.0)

But do not hardcode 10–15 ms as the final default. The values must be command-line configurable and validated against native timing and timeout measurements.

Required command-line options should be similar to:

    --timing-mode native
    --timing-mode fixed
    --timing-mode bounded
    --target-delay-ms 12
    --target-min-ms 10
    --target-max-ms 15
    --timing-seed 12345

Use a monotonic high-resolution clock, preferably:

    time.monotonic_ns()

Track these timestamps:

- request_received_ns;
- response_ready_ns;
- target_release_ns;
- actual_release_ns;
- send_start_ns;
- send_complete_ns.

For every transaction, log:

- transaction ID;
- flow ID;
- request size;
- response size;
- native ready delay;
- selected target delay;
- added hold delay;
- visible request-to-response delay;
- target met or missed;
- bypass reason;
- queue depth;
- timing mode;
- random seed or sample index.

Use absolute-deadline waiting rather than repeated relative sleeps where practical.

Preserve:

- response bytes exactly;
- TCP connection;
- DNP3 sequence and function;
- TCP ordering;
- request-response ordering;
- application correctness.

Do not:

- edit DNP3 payload bytes;
- edit CRCs;
- synthesize DNP3 CONFIRM;
- forge ACKs;
- reorder responses;
- delay critical traffic without an explicit policy.

==================================================
3. PHASE 1 SAFETY AND FAIL-OPEN LOGIC
==================================================

Implement fail-open behavior.

Send immediately and record a bypass when:

- the target deadline has already been missed;
- the response took longer than the selected target;
- the configured target is unsafe;
- the response would violate FIFO ordering;
- the queue exceeds a configurable limit;
- the traffic is unsupported;
- the transaction is marked critical;
- timeout or RTO information is unavailable and strict safety mode is enabled.

Provide configurable limits:

    --max-hold-ms
    --max-queue-depth
    --strict-safety
    --critical-function-bypass
    --unknown-traffic-bypass

Do not use an arbitrary 200 ms safety threshold.

Create a separate script to measure or estimate the effective TCP retransmission behavior on both endpoints using controlled response delays.

Test delays such as:

    0, 1, 2, 5, 10, 20, 50, 100 ms

Record:

- retransmissions;
- duplicate ACKs;
- connection reset;
- DNP3 task timeout;
- application success;
- observed TCP RTO-related behavior.

Keep the timing policy well below the measured unsafe boundary.

==================================================
4. PHASE 1 EXPERIMENT MATRIX
==================================================

Run the current combined ACK-bearing response implementation under:

A. Native
B. Fixed normalization
C. Bounded normalization

For bounded normalization, test at least three configurable ranges after confirming they are safe.

For example only:

- 5–10 ms;
- 10–15 ms;
- 15–25 ms.

Do not use these ranges if they are below native response time or unsafe.

For each configuration, run enough repetitions to support statistics. Use at least 30 repetitions per class, and preferably 100 or more where practical.

Test:

- multiple CROB counts;
- small READ responses;
- large READ responses;
- the existing SELECT and OPERATE cases;
- current replay/split cases where applicable.

For SELECT and OPERATE:

- use only software/laboratory controls;
- preserve SBO ordering;
- record SELECT and OPERATE separately;
- do not assume both should share the same target unless explicitly configured;
- apply critical-control bypass by default.

Metrics:

- request-to-response median, p95, p99, maximum;
- response-ready-to-release hold time;
- deadline miss rate;
- bypass rate;
- DNP3 task success;
- retransmissions;
- resets;
- sequence errors;
- response byte identity;
- correlation between timing and CROB count;
- linear-regression slope and R²;
- mutual information where available;
- attacker classification accuracy;
- repeated-averaging attack performance.

The primary hypothesis is:

    After bounded normalization, the visible request-to-response
    distribution should be approximately independent of CROB count
    for transactions that meet the target deadline.

Explicitly report missed-target transactions because their native tail may still leak information.

==================================================
5. PHASE 2: CREATE OR USE SEPARATE ACK + DNP3 RESPONSE
==================================================

Do this only after Phase 1 is implemented, tested, and documented.

There are two sub-phases.

------------------------------------------
5A. SOCKET-LEVEL ACK SEPARATION EXPERIMENT
------------------------------------------

Goal:
Determine whether delaying the application write causes the host TCP stack to emit a pure ACK before the DNP3 response.

Do not forge a TCP ACK.

At the outstation or replay server:

1. receive the DNP3 request;
2. record request arrival;
3. generate or prepare the response;
4. delay the application write by a controlled amount;
5. capture whether the kernel sends a pure TCP ACK before the write;
6. send the normal DNP3 response;
7. verify protocol correctness.

Test controlled application-write delays:

    0, 1, 2, 5, 10, 20, 50 ms

Also test relevant socket options where supported:

- TCP_NODELAY on/off;
- TCP_QUICKACK where available;
- default delayed ACK behavior;
- existing buffering and write patterns.

Do not change multiple socket variables in the same initial experiment. Use one-factor-at-a-time tests first.

Capture at both endpoints if possible.

Account for:

- TSO;
- GSO;
- GRO;
- checksum offload;
- host-capture artifacts.

Produce a matrix showing:

- requested application-write delay;
- pure ACK emitted: yes/no;
- request-to-ACK;
- request-to-response;
- ACK-to-response;
- retransmissions;
- DNP3 success;
- whether results are stable across repetitions.

The objective is to identify a repeatable, natural host behavior that produces:

    request -> pure TCP ACK -> DNP3 response

------------------------------------------
5B. DELAY EXISTING ACK AND RESPONSE PACKETS
------------------------------------------

Once a flow already has a separate pure ACK and DNP3 response, support the following experiment modes:

1. native
   Delay neither packet.

2. ack-delay-only
   Delay the existing pure ACK.
   Do not delay the DNP3 response unless FIFO constraints require it.

3. response-delay-only
   Release the ACK normally and delay the DNP3 response.

4. independent-delay
   Configure separate target delays for ACK and response.

5. gap-normalized
   Choose a bounded target ACK-to-response gap and schedule the existing packets accordingly.

Required options may include:

    --ack-mode native
    --ack-delay-ms
    --ack-target-min-ms
    --ack-target-max-ms
    --response-delay-ms
    --response-target-min-ms
    --response-target-max-ms
    --gap-target-min-ms
    --gap-target-max-ms

Definitions:

    request_to_ack =
        ack_release_time - request_arrival_time

    request_to_response =
        response_release_time - request_arrival_time

    ack_to_response_gap =
        response_release_time - ack_release_time

Preserve the ordering constraint:

    ACK release time <= response release time

Do not allow a delayed ACK to be released after the DNP3 response.

If the chosen ACK delay would violate ordering, either:

- clamp it safely;
- resample;
- or bypass and log the reason.

==================================================
6. WHY ACK DELAY CAN CHANGE THE APPARENT PROCESSING TIME
==================================================

The real SEL-751 traces show a separate ACK and later DNP3 response.

An attacker may estimate device processing time as:

    apparent_processing =
        response_timestamp - pure_ack_timestamp

Example:

Native:

    request          0.0 ms
    pure ACK         3.7 ms
    DNP3 response   16.7 ms
    visible gap     13.0 ms

Delay response only:

    pure ACK         3.7 ms
    response        21.7 ms
    visible gap     18.0 ms

Delay ACK only:

    pure ACK         8.7 ms
    response        16.7 ms
    visible gap      8.0 ms

This does not make the physical response ready earlier. It changes only the observer-visible difference between the ACK and the DNP3 response.

The implementation must distinguish clearly between:

- changing true processing time;
- changing request-to-response time;
- changing the visible ACK-to-response gap.

==================================================
7. TRACE-BASED TARGET PROFILES
==================================================

Use the real traces to create descriptive target profiles, but do not immediately imitate a device without validating safety.

Create profile files such as:

    profiles/sel751_separate_ack.json
    profiles/ab1400_combined_ack.json
    profiles/ion7550_combined_ack.json

Each profile should contain only measured descriptive statistics:

- ACK mode;
- request-to-ACK distribution;
- request-to-response distribution;
- ACK-to-response distribution;
- request-size distribution;
- response-size distribution;
- sample count;
- source PCAP names.

Do not include raw packet payloads unless required.

Support loading a profile for experiments, but separate:

- observed profile;
- configured experimental policy.

Do not automatically deploy a measured device profile without operator approval.

==================================================
8. ATTACKER EVALUATION
==================================================

Implement an attacker-side analysis that uses:

- request-to-response delay;
- request-to-ACK delay;
- ACK-to-response gap;
- combined versus separate ACK behavior;
- request size;
- response size;
- packet count;
- joint timing and size features.

Evaluate:

- native traces;
- Phase 1 bounded normalization;
- Phase 2 ACK manipulation;
- whether the defense itself is detectable.

At minimum include:

- threshold classifier;
- logistic regression;
- random forest;
- gradient boosting if available;
- repeated-observation averaging;
- device-identification classifier;
- detect-the-defense binary classifier.

Use train/test separation that prevents adjacent packets from the same capture from leaking across splits. Prefer capture-level or time-block splits.

Report:

- accuracy;
- precision;
- recall;
- F1;
- ROC-AUC;
- confusion matrix;
- feature importance;
- confidence intervals where practical.

Include an ablation study:

- timing only;
- size only;
- ACK mode only;
- timing + size;
- all features.

==================================================
9. CODE ARCHITECTURE
==================================================

Do not scatter sleeps throughout the code.

Create a reusable timing policy module, for example:

    timing_policy.py

Suggested abstractions:

    TimingProfile
    TimingDecision
    FlowTimingState
    ReleaseScheduler
    BypassReason

Example decision output:

    {
        "flow_id": ...,
        "transaction_id": ...,
        "packet_role": "combined_response" | "pure_ack" | "dnp3_response",
        "native_ready_ns": ...,
        "target_release_ns": ...,
        "actual_release_ns": ...,
        "delay_ns": ...,
        "deadline_missed": false,
        "bypassed": false,
        "bypass_reason": null
    }

Use per-flow FIFO queues.

Never use a global scheduler that can reorder packets within a TCP flow.

For multiple flows, a heap of flow-head deadlines is acceptable only if each flow maintains strict FIFO ordering.

==================================================
10. REQUIRED TESTS
==================================================

Add unit tests for:

- fixed target release;
- bounded target release;
- deterministic seeded output;
- response ready before target;
- response ready after target;
- target deadline miss;
- per-flow FIFO;
- multiple-flow scheduling;
- ACK before response ordering;
- invalid target range;
- queue-limit bypass;
- critical-flow bypass;
- byte-for-byte response preservation;
- no packet synthesis in Phase 1;
- no ACK-after-response release.

Add integration tests for:

- native OpenDNP3 transaction;
- combined ACK-bearing response with delay;
- forced socket separation where possible;
- separate ACK and response delay;
- SELECT then OPERATE ordering;
- no retransmission/reset under safe settings.

==================================================
11. REQUIRED OUTPUTS
==================================================

At the end, provide:

1. Repository assessment
   - Relevant files and current architecture.
   - Where requests are received.
   - Where responses are generated.
   - Where bytes are sent.
   - Best insertion point for timing control.

2. Trace characterization
   - Exact findings from all six PCAPs.
   - Device-specific combined/separate ACK behavior.
   - Statistical tables.

3. Implementation plan
   - Phase 1 first.
   - Phase 2 only after Phase 1 succeeds.

4. Code changes
   - List every modified or added file.
   - Provide concise diffs or summaries.

5. Run commands
   - Native mode.
   - Fixed-normalized mode.
   - Bounded-normalized mode.
   - Socket ACK-separation sweep.
   - ACK-delay-only.
   - Response-delay-only.
   - Independent-delay.
   - Gap-normalized.

6. Experiment scripts
   - One reproducible command or script per experiment.
   - Automatic PCAP naming.
   - JSON/CSV output.
   - No stale-file reuse.

7. Validation report
   - Byte identity.
   - DNP3 task completion.
   - Retransmissions.
   - Resets.
   - Timeouts.
   - Deadline misses.
   - Bypass rates.

8. Research report
   - What was demonstrated.
   - What remains unproven.
   - Limits of the current host/kernel behavior.
   - P4 feasibility for delaying existing packets.
   - Why ACK synthesis is deferred.

==================================================
12. STRICT RESEARCH CLAIMS
==================================================

Do not claim:

- that bounded timing normalization fully removes all leakage;
- that ACK manipulation reduces actual device processing time;
- that all DNP3 devices use the same TCP ACK behavior;
- that the SEL-751 timing profile generalizes to other SEL devices;
- that a host-side capture always represents exact wire timing;
- that socket delay will always force a separate ACK;
- that P4 can safely synthesize TCP ACKs without additional state.

Use precise wording:

- “observer-visible ACK-to-response gap”;
- “request-to-response timing”;
- “ACK-bearing DNP3 response”;
- “pure TCP ACK”;
- “measured on this device, trace, host, and configuration”;
- “bounded normalization reduced correlation/classification in the tested setup.”

Final priority order:

1. Characterize the real traces.
2. Implement bounded normalization for the current combined ACK-bearing response.
3. Validate safety and correctness.
4. Experiment with socket-level ACK separation.
5. Delay existing pure ACK and DNP3 response packets independently.
6. Evaluate attacker classification.
7. Only then assess a P4 implementation.