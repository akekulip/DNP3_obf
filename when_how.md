You are the lead principal investigator and systems architect for a DNP3/SCADA
traffic-obfuscation research project.

Your task is to conduct a deep, evidence-based investigation into:

1. WHEN a DNP3 transaction should be split.
2. WHEN it should be padded.
3. WHEN its timing should be normalized or otherwise hidden.
4. HOW these three mechanisms should be combined.
5. HOW to implement the combined policy with the lowest practical latency,
   bandwidth, CPU, memory, buffering, recirculation, and operational overhead.
6. HOW to evaluate whether the combined mechanism actually prevents
   fingerprinting without breaking DNP3 correctness or grid operations.

Use specialized expert agents in parallel. Do not solve this as one general-purpose
agent. The final synthesis must reconcile contradictions, identify unsupported claims,
and clearly separate measured facts, standards, paper-reported results, engineering
inferences, and untested hypotheses.

Do not modify production source code during this research phase. Create research,
design, evaluation, and implementation-planning artifacts only.

======================================================================
1. REPOSITORY AND PROJECT CONTEXT
======================================================================

Start by inspecting the repository and locating all relevant files, including:

- dnp3_split_harness/
- dnp3_multicrob_harness/
- split_server.py
- analyze_ack.py
- replay/splitting scripts
- multi-CROB test scripts
- PCAP captures
- timing reports
- CRC-boundary splitting documentation
- ACK-timing research
- padding experiments
- OpenDNP3 configuration and source references
- research/ack_timing_normalization/
- GROUNDING.md
- measured_timing_data.md
- literature_review.md
- hardware_design.md
- evaluation_plan.md
- research_gaps_and_novelty.md
- sources_audit.md
- advisor_brief.md

Do not assume filenames or paths exist exactly as listed. Search the repository and
record the actual locations.

Current known research setting:

- Master: Vision, 10.10.54.19
- Outstation: Hulk, 10.10.54.158:20000
- Protocol: DNP3 over TCP
- Implementation: OpenDNP3 software master and outstation
- Eventual hardware target: Intel/Barefoot Tofino 1
- Additional possible targets: NVIDIA BlueField DPU, Netronome SmartNIC, FPGA
- Threat model: passive on-path observer
- Observer may use packet size, response volume, packet count, segmentation,
  request-to-response delay, inter-packet gaps, TCP behavior, and repeated polling
  to fingerprint the outstation or infer configuration/request complexity.

Known measured facts to preserve unless repository evidence disproves them:

- The outstation often piggybacks the DNP3 RESPONSE on the TCP segment that ACKs the
  request.
- The primary timing observable is therefore the request-to-ACK-bearing-response
  delay, not a standalone pure TCP ACK.
- Baseline large READ traffic showed 9/9 piggybacked responses.
- Mean request-to-ACK was approximately 0.239 ms.
- Mean request-to-response was approximately 1.014 ms.
- CROB-count sweep:
  - SELECT-response slope approximately 0.179 ms/CROB, R² approximately 0.9985.
  - OPERATE-response slope approximately 0.214 ms/CROB, R² approximately 0.9954.
  - OPERATE response increased from approximately 1.62 ms to 4.90 ms for
    N = 1 to 16.
- Invalid CROB indexes return OUT_OF_RANGE.
- A partial SELECT failure prevents the normal OPERATE progression in the current
  master workflow.
- Invalid-index padding is therefore not currently a safe padding mechanism for
  a real SBO transaction.
- The current byte-preserving splitting mechanism operates only at already valid
  DNP3 CRC/block boundaries and preserves the original application bytes.
- Tofino Traffic Manager shaping can pace traffic and normalize gaps, but does not
  necessarily impose an absolute first-packet release deadline on a lone packet in
  an empty queue.
- Precise first-packet absolute delay is straightforward in software and on hardware
  with explicit timed-send support, but is not a native Tofino 1 match-action
  primitive.

Treat all cross-device and database-size claims as hypotheses unless independently
supported by experiments or literature.

======================================================================
2. HARD CURRENT-PHASE CONSTRAINTS
======================================================================

The current phase is byte-preserving.

Unless explicitly categorized as future work, do not design mechanisms that:

- alter DNP3 application bytes;
- alter DNP3 object counts;
- alter DNP3 object values;
- alter DNP3 lengths;
- recompute DNP3 CRCs;
- forge TCP ACKs;
- rewrite TCP sequence or acknowledgment numbers;
- suppress required DNP3 responses;
- synthesize DNP3 application CONFIRMs;
- synthesize control operations;
- implement an active TCP proxy;
- introduce invalid CROB indexes into a live operational SBO transaction;
- reorder TCP segments;
- change the final DNP3 application semantics.

The current allowed mechanisms are:

- splitting existing bytes at verified safe boundaries;
- controlling when existing bytes are released;
- pacing existing packets or chunks;
- selecting among preapproved policies;
- bypassing obfuscation when safety or deadlines require it.

Any mechanism that violates these rules must be clearly placed in a separate
“future, protocol-modifying phase.”

======================================================================
3. THE CORE RESEARCH PROBLEM
======================================================================

Determine a principled policy for choosing among:

A. SPLIT

Change the observable packet or segment structure by dividing an existing response
into smaller wire units while preserving all original DNP3 bytes and order.

B. PAD

Increase apparent size, packet count, transaction volume, or activity so that a
small or quiet transaction resembles a larger target.

Padding must be separated into distinct categories:

1. Semantic DNP3 padding.
2. Valid dummy or inert DNP3 objects.
3. Invalid-object padding.
4. Padding outside the DNP3 message.
5. Tunnel or encrypted-envelope padding.
6. Cover traffic or decoy transactions.
7. Packet-count padding.
8. Silence hiding.
9. Timing-only “padding” through delayed release.

Do not treat these as equivalent.

C. TIMING NORMALIZATION

Control one or more timing observables:

- request first byte to response first byte;
- request final byte to response first byte;
- request to first ACK-bearing response;
- response first byte to response final byte;
- inter-chunk gaps;
- inter-DNP3-frame gaps;
- inter-TCP-segment gaps;
- DNP3 application CONFIRM to next response fragment;
- complete transaction duration;
- SELECT response to OPERATE request;
- polling interval;
- quiet-period or silence duration.

D. COMBINED POLICY

Determine when the correct mechanism is:

- split only;
- pad only;
- timing only;
- split plus timing;
- pad plus timing;
- split plus pad;
- split plus pad plus timing;
- immediate bypass.

======================================================================
4. PRIMARY RESEARCH QUESTIONS
======================================================================

Answer these questions rigorously.

RQ1. What information does each observable leak?

For each observable, determine whether it reveals:

- transaction type;
- DNP3 function code;
- object count;
- response size;
- CROB count;
- configured point count;
- database size;
- device implementation;
- OS/TCP stack;
- device model;
- CPU load;
- network load;
- outstation role;
- physical criticality;
- operational state;
- poll schedule.

RQ2. When is splitting useful?

Determine:

- minimum response size at which splitting provides meaningful privacy;
- whether splitting only changes per-packet size or also changes total-volume inference;
- whether attackers can simply sum the chunks;
- whether packet count becomes a new fingerprint;
- whether fixed split patterns create a new fingerprint;
- whether randomized split points are averageable;
- whether splits should use:
  - DNP3 CRC-block boundaries;
  - link-frame boundaries;
  - application-fragment boundaries;
  - TCP segmentation only;
  - fixed-size chunk targets;
  - randomized chunk targets;
  - decoy-distribution matching;
- how splitting interacts with TCP coalescing, MSS, GRO, GSO, TSO, NIC offloads,
  Nagle, TCP_NODELAY, and capture vantage point;
- when a small response should not be split because splitting increases uniqueness
  or overhead.

RQ3. When is padding necessary?

Determine:

- when splitting cannot make a small message resemble a large target;
- whether total transaction bytes remain a fingerprint after splitting;
- whether packet-count equalization requires padding;
- whether silence requires cover traffic;
- whether DNP3 permits protocol-safe padding in any layer;
- whether vendor-specific or reserved fields can legally carry padding;
- whether valid but operationally inert points are feasible;
- whether an RTAC/gateway can expose safe dummy points;
- whether dummy points remain distinguishable from real points;
- whether invalid indexes are useful only as a negative result;
- whether separate decoy transactions are safe;
- whether encrypted tunnels provide a better place for padding;
- whether padding outside DNP3 preserves application correctness;
- how much bandwidth and packet-count overhead each strategy introduces;
- which padding mechanisms require endpoint cooperation, proxies, CRC changes, or
  application modifications.

RQ4. When must timing be hidden?

Determine whether timing should be normalized when:

- native response time depends on CROB count;
- native response time depends on object count;
- response time depends on database size;
- response time differs between SELECT and OPERATE;
- response time differs across devices;
- inter-fragment gaps reveal processing behavior;
- TCP ACK piggyback behavior reveals stack/device class;
- polling cadence reveals operational state;
- silence reveals events or lack of events;
- split chunks introduce a new timing signature.

Determine when timing should not be altered because:

- the message is operationally critical;
- the delay budget is too small;
- the transaction is unsupported;
- the timing signal is already independent of the secret;
- normalization would create a stronger artificial fingerprint;
- the response is close to a TCP or DNP3 deadline;
- queue buildup would affect other flows.

RQ5. Which timing policy is best?

Compare:

- no delay;
- fixed additive delay;
- additive random jitter;
- constant-time release;
- bounded randomized normalization;
- bucketed release;
- learned quantile target;
- decoy-distribution matching;
- size-decorrelation;
- request-complexity decorrelation;
- per-device normalization;
- global normalization;
- per-transaction-class normalization;
- per-criticality-class normalization;
- constant-rate pacing;
- inter-chunk-gap normalization;
- adaptive deadline selection.

Test the hypothesis that additive jitter is averageable, while class-independent
normalization is not.

RQ6. How should the three mechanisms be composed?

Determine whether the pipeline should be:

    classify → split → pad → schedule

or:

    classify → choose target profile → transform shape → schedule release

or another design.

Identify whether timing targets must account for the number of split chunks and whether
splitting itself changes the timing budget.

RQ7. How can the mechanism minimize overhead?

Optimize for:

- added latency;
- p95 and p99 latency;
- packet-count increase;
- bandwidth increase;
- CPU utilization;
- memory use;
- held packets;
- queue occupancy;
- TCP retransmissions;
- DNP3 retries;
- scheduling precision;
- Tofino recirculation bandwidth;
- Tofino register use;
- Tofino table stages;
- DPU memory/copy overhead;
- FPGA BRAM/URAM/DDR use;
- control-plane intervention;
- policy complexity;
- operational configuration burden.

RQ8. What is the strongest publishable contribution?

Assess whether the contribution should be framed as:

- conditional split/pad/timing policy;
- criticality-aware DNP3 traffic obfuscation;
- byte-preserving traffic normalization;
- cross-layer DNP3 metadata obfuscation;
- adaptive privacy-overhead optimization;
- target-profile-based DNP3 traffic shaping;
- timing normalization plus shape normalization;
- a negative result on protocol-safe DNP3 padding;
- a hardware/software co-design;
- a multi-objective decision engine.

Do not assume novelty. Verify it.

======================================================================
5. REQUIRED SPECIALIZED AGENTS
======================================================================

Launch at least nine specialized agents in parallel.

Agent A: DNP3 protocol and OpenDNP3 expert

Tasks:

- inspect DNP3 frame, transport, application, object, and CRC structure;
- identify every legal and illegal split boundary;
- determine application-fragment and link-frame interactions;
- investigate padding fields, reserved fields, qualifiers, object headers,
  count/range encodings, and legal no-op mechanisms;
- study SELECT/OPERATE, DIRECT_OPERATE, READ, event responses, application CONFIRM,
  unsolicited responses, and link confirmations;
- verify findings against IEEE 1815, OpenDNP3 source, and implementation behavior;
- explicitly classify each mechanism as:
  - byte-preserving;
  - protocol-valid but semantic-changing;
  - implementation-specific;
  - invalid;
  - future proxy/endpoint work.

Agent B: TCP transport and packetization expert

Tasks:

- analyze TCP ACK piggybacking;
- pure ACK versus payload-bearing ACK;
- MSS and segmentation;
- TCP reassembly;
- retransmission timeout;
- fast retransmit;
- delayed ACK;
- ACK thinning/compression;
- Nagle and TCP_NODELAY;
- GSO, TSO, GRO, LRO, checksum offload;
- packet reordering risk;
- how splitting appears at different capture points;
- whether splitting at the application send layer survives NIC/kernel coalescing;
- how to measure effective RTO on Vision and Hulk;
- define strict timing and queueing budgets.

Agent C: Traffic-analysis and fingerprinting expert

Tasks:

- find prior research on:
  - ICS device fingerprinting;
  - CLRT fingerprinting;
  - response-time fingerprinting;
  - IoT fingerprinting;
  - website fingerprinting;
  - encrypted traffic classification;
  - packet-size and timing attacks;
  - repeated-observation attacks;
  - defense-aware classifiers;
- determine which features remain after split, padding, and timing normalization;
- determine whether packet count, total bytes, burst shape, timing buckets, or policy
  bypasses create new fingerprints;
- design the strongest attacker.

Agent D: Padding and anonymity-system expert

Tasks:

- study:
  - adaptive padding;
  - constant-rate padding;
  - link padding;
  - cover traffic;
  - mix networks;
  - BuFLO;
  - Tamaraw;
  - WTF-PAD;
  - FRONT;
  - Walkie-Talkie;
  - RegulaTor;
  - Surakav;
  - traffic morphing;
  - differential privacy traffic shaping;
- determine which ideas transfer to DNP3;
- identify why dummy traffic, padding bytes, or packet synthesis may be incompatible
  with the current byte-preserving phase;
- identify realistic future padding architectures;
- quantify expected bandwidth and latency overhead.

Agent E: Software systems implementation expert

Tasks:

- inspect the current replay/split server;
- design the lowest-overhead software policy engine;
- compare:
  - synchronous monotonic deadline sleep;
  - asyncio call_at;
  - priority heap;
  - timing wheel;
  - calendar queue;
  - tc/netem;
  - ETF/SO_TXTIME;
  - eBPF TC;
  - XDP;
  - AF_XDP;
  - DPDK;
  - NFQUEUE;
  - transparent proxy;
- determine which mechanisms are appropriate for endpoint-generated responses and
  which only apply to in-path forwarding;
- design an implementation that supports split decisions, padding capability flags,
  and timing policy selection without one thread per packet.

Agent F: P4/Tofino programmable-data-plane expert

Tasks:

- determine how to:
  - identify DNP3 response classes;
  - measure request-to-response delay;
  - classify large/small responses;
  - mark packets for queues;
  - pace split chunks;
  - normalize inter-frame gaps;
  - implement or reject first-packet absolute delay;
  - store request timestamps;
  - enforce FIFO ordering;
  - bound recirculation;
  - handle timestamp wraparound;
- inspect Tofino 1 limitations:
  - parser depth;
  - table stages;
  - register/SALU constraints;
  - queue count;
  - TM programmability;
  - buffer limits;
  - recirculation bandwidth;
  - timestamp width;
  - range-comparison limits;
- distinguish documented capability from inference;
- identify a minimal ASIC implementation and a future advanced implementation.

Agent G: DPU, SmartNIC, and FPGA expert

Tasks:

- compare BlueField, Netronome, FPGA, and host software;
- study timed send, PTP-based launch time, calendar queues, DRAM buffering,
  inline mode, DOCA, Micro-C, hardware queues, and timestamped transmit;
- identify the cleanest hardware home for:
  - first-response absolute delay;
  - payload buffering;
  - padding;
  - cover traffic;
  - per-flow policy;
  - accurate timed release;
- provide quantitative resource and overhead estimates where sources permit.

Agent H: Power-system operations and safety expert

Tasks:

- classify DNP3 traffic into:
  - routine integrity polling;
  - event polling;
  - unsolicited events;
  - SELECT;
  - OPERATE;
  - DIRECT_OPERATE;
  - critical control;
  - noncritical supervisory control;
  - protection traffic;
- determine when privacy shaping must be bypassed;
- study relevant latency and reliability requirements;
- determine how an operator-supplied criticality allowlist should work;
- ensure the design does not claim that DNP3 fields reveal physical criticality;
- define fail-open and fail-safe behavior.

Agent I: Statistical evaluation and optimization expert

Tasks:

- build the policy evaluation methodology;
- define:
  - regression;
  - mutual information;
  - conditional mutual information;
  - classification accuracy;
  - privacy gain;
  - Wasserstein distance;
  - Jensen-Shannon divergence;
  - KS statistics;
  - Pareto frontiers;
  - deadline-miss rate;
  - overhead metrics;
- design multi-objective optimization:
  - maximize privacy;
  - minimize latency;
  - minimize bandwidth;
  - minimize CPU/memory;
  - preserve correctness;
- determine required sample size, cross-validation strategy, confidence intervals,
  equivalence tests, significance tests, and defense-aware evaluation.

Agent J: Hostile senior reviewer

Tasks:

- review all findings as a skeptical IEEE/ACM reviewer;
- challenge:
  - whether splitting really hides anything if total bytes remain visible;
  - whether padding is protocol-safe;
  - whether timing normalization creates a new fingerprint;
  - whether one outstation is enough;
  - whether CROB count is a legitimate database-size proxy;
  - whether Tofino implementation is realistic;
  - whether overhead claims are measured;
  - whether the contribution duplicates traffic shaping;
  - whether the threat model is internally consistent;
  - whether unencrypted DNP3 payload visibility makes the fingerprinting claim trivial;
- identify fatal weaknesses and required experiments.

======================================================================
6. LITERATURE-SEARCH REQUIREMENTS
======================================================================

Search broadly using available web, scholarly, RFC, source-code, and vendor-documentation
tools.

Search terms must include combinations of:

- DNP3 traffic fingerprinting
- DNP3 response time fingerprinting
- SCADA device fingerprinting
- ICS Cross-Layer Response Time
- CLRT fingerprinting
- PLC processing time fingerprinting
- packet size normalization
- traffic morphing packet size
- random segmentation traffic obfuscation
- TCP segmentation fingerprint defense
- packet count normalization
- response size padding
- industrial protocol padding
- DNP3 padding
- DNP3 dummy points
- DNP3 no-op objects
- DNP3 cover traffic
- ICS cover traffic
- SCADA traffic shaping
- packet timing normalization
- response time normalization
- latency padding timing side channel
- bounded randomized release
- constant-time network response
- predictive timing mitigation
- timing bucketing
- ACK timing covert channel
- Network Pump ACK timing
- repeated timing attack averaging jitter
- website fingerprinting adaptive padding
- traffic analysis defense padding timing
- P4 traffic obfuscation
- P4 packet splitting
- P4 traffic shaping
- Tofino packet delay
- Tofino Traffic Manager pacing
- Tofino recirculation packet hold
- P4 absolute packet scheduling
- SmartNIC timed packet release
- BlueField accurate send scheduling
- FPGA timestamped packet scheduler
- time-aware shaper P4
- differential privacy network shaping
- privacy latency Pareto network traffic

Prioritize:

- IEEE Xplore;
- ACM Digital Library;
- USENIX;
- NDSS;
- RFC Editor;
- P4.org;
- official Intel/Barefoot documentation;
- official NVIDIA BlueField/DOCA documentation;
- Linux kernel documentation;
- OpenDNP3 source/documentation;
- official vendor relay/RTAC documentation;
- peer-reviewed primary literature.

For every paper:

- verify title;
- verify authors;
- verify venue;
- verify year;
- verify DOI or stable URL;
- identify peer-reviewed status;
- state whether full text, abstract, or metadata only was reviewed;
- identify software, simulation, hardware, testbed, or deployment;
- record source-code/artifact availability;
- record exact relevance to split, pad, timing, or combined policy;
- do not invent citations.

======================================================================
7. REQUIRED TAXONOMY
======================================================================

Create a taxonomy with three independent axes.

Axis 1: SHAPE/SIZE

- total bytes;
- largest packet;
- packet-size distribution;
- number of packets;
- fragment count;
- TCP segment count;
- DNP3 link-frame count;
- application-fragment count.

Axis 2: TIMING

- request-to-first-response;
- inter-packet gap;
- burst duration;
- response completion time;
- CONFIRM-to-next-fragment;
- transaction duration;
- polling interval;
- silence duration.

Axis 3: SEMANTICS/SAFETY

- monitoring;
- event reporting;
- control;
- critical control;
- protection;
- unknown;
- unsupported.

For each transaction class, document which axes leak and which mechanisms can safely
address them.

======================================================================
8. REQUIRED DECISION FRAMEWORK
======================================================================

Produce a decision tree and policy matrix that answers:

WHEN TO SPLIT

Split only when evidence shows that:

- the natural packet or frame size is a distinguishing feature;
- the response is large enough for meaningful repartitioning;
- safe split boundaries exist;
- splitting does not violate ordering or CRC integrity;
- the packet-count increase is within budget;
- total-volume leakage is acknowledged;
- timing normalization can prevent the new chunk schedule becoming a fingerprint.

WHEN TO PAD

Pad only when:

- the real transaction is smaller than the chosen anonymity profile;
- total bytes or packet count remain identifying after splitting;
- an approved protocol-safe padding mechanism exists;
- semantic correctness is preserved;
- bandwidth overhead is acceptable;
- the mechanism does not block SELECT/OPERATE;
- the mechanism does not create distinguishable error statuses;
- operational policy authorizes it.

If no safe padding mechanism exists, record residual size leakage rather than inventing
unsafe padding.

WHEN TO NORMALIZE TIMING

Normalize timing when:

- timing has measurable dependence on request complexity, configuration, device, or load;
- repeated observations allow an attacker to recover the underlying mean;
- split chunks introduce distinctive gaps;
- response timing gives incremental information beyond size;
- the transaction has sufficient safety margin.

BYPASS timing normalization when:

- the operation is marked critical;
- the transaction is unsolicited/urgent;
- the deadline budget is insufficient;
- the target is already missed;
- queue occupancy exceeds a limit;
- packet order might be violated;
- the transaction is unsupported;
- RTO margin is uncertain.

COMBINATION RULE

Investigate and validate this candidate:

- large routine response:
  split + first-response timing normalization + inter-chunk-gap normalization;

- small routine response:
  timing normalization;
  add padding only when an approved padding mechanism exists;

- noncritical SELECT/OPERATE response:
  tight N-independent timing normalization;
  optional splitting only if size warrants;
  no invalid-index padding;

- critical control or urgent event:
  bypass or extremely restricted shaping;

- silence:
  requires future cover traffic;
  delay and splitting cannot hide absence of packets.

Treat this as a hypothesis to test, not a conclusion to assume.

======================================================================
9. TARGET-PROFILE DESIGN
======================================================================

Design a target-profile system.

Each profile should contain:

- profile ID;
- applicable DNP3 transaction classes;
- safety class;
- target packet-size pattern;
- target packet-count range;
- split-boundary policy;
- padding mechanism permitted;
- timing target distribution;
- first-response deadline;
- inter-chunk-gap distribution;
- complete-transaction deadline;
- TCP RTO safety fraction;
- maximum queue occupancy;
- maximum concurrent held packets;
- deadline-miss action;
- bypass conditions;
- reproducible random seed requirements;
- telemetry requirements.

Evaluate whether target profiles should be:

- global;
- per protocol class;
- per outstation type;
- per device;
- per criticality class;
- per anonymity group;
- decoy-device based;
- learned from empirical distributions.

The policy must not choose targets using a secret variable that would itself leak the
secret.

======================================================================
10. LOW-OVERHEAD POLICY ENGINE
======================================================================

Design a runtime policy engine.

Candidate model:

    transaction = classify(request, response)

    if transaction.critical or unsupported:
        release unchanged immediately

    profile = choose_public_target_profile(transaction)

    if response has a distinctive large shape:
        split only at verified safe boundaries

    if response is smaller than the target:
        if approved padding is available:
            apply approved padding
        else:
            record residual size leakage

    choose a target response-release time independent of:
        native processing time;
        CROB count;
        object count;
        device identity;
        database size;
        CPU load.

    compute:
        candidate_release =
            max(response_ready_time,
                request_time + selected_target_delay)

    ensure:
        candidate_release <= operational_deadline
        candidate_release <= measured_RTO_safety_deadline
        FIFO order preserved
        cumulative transaction deadline preserved
        held-packet and queue limits preserved

    if any constraint fails:
        release immediately
        record a policy bypass

    otherwise:
        release according to:
            normalized first-response deadline;
            normalized inter-chunk gaps;
            cumulative transaction deadline.

The design must include:

- exact state machine;
- transaction matching;
- timestamp selection;
- safe boundary discovery;
- queue discipline;
- concurrency handling;
- per-flow FIFO;
- deadline calculation;
- fail-open behavior;
- random seed handling;
- logging;
- configuration;
- metrics export;
- unit tests;
- integration tests;
- PCAP validation.

======================================================================
11. SOFTWARE IMPLEMENTATION STUDY
======================================================================

Develop a concrete software design for the current replay/split server.

It must support:

- native/no-defense mode;
- split-only mode;
- timing-only mode;
- split-plus-timing mode;
- future padding capability flags;
- target profiles;
- fixed deadline;
- bounded random target;
- bucketed target;
- decoy target;
- size/request-complexity decorrelation;
- inter-chunk-gap normalization;
- strict per-class delay budgets;
- immediate-release fallback;
- reproducible experiments;
- no busy waiting;
- no thread per packet;
- monotonic high-resolution time;
- CSV/JSON telemetry;
- PCAP-grounded correctness validation.

Recommend the simplest implementation that satisfies the workload.

Do not recommend DPDK, AF_XDP, eBPF, tc, or timing wheels merely because they exist.
Justify them quantitatively or reject them.

Provide pseudocode, data structures, interfaces, configuration schema, error handling,
and estimated computational complexity.

======================================================================
12. TOFINO IMPLEMENTATION STUDY
======================================================================

Design a staged Tofino implementation.

Stage 1: Classification and telemetry

- identify DNP3/TCP direction;
- identify ACK-bearing responses;
- identify READ versus SELECT/OPERATE where parsable;
- record request timestamps;
- record response timestamps;
- count packets, bytes, queues, and gaps;
- mirror samples for offline analysis.

Stage 2: Split/chunk pacing

- mark traffic for queues;
- pace already-created chunks;
- normalize inter-chunk gaps;
- preserve ordering;
- avoid controller fast-path dependence.

Stage 3: First-response timing

Investigate:

- recirculation plus timestamp deadline;
- queue gating;
- pktgen-assisted scheduling;
- time-aware shaper;
- controller-configured timing buckets;
- whether exact absolute delay is realistic;
- maximum number of recirculation passes;
- timing resolution;
- register width;
- deadline comparison;
- wraparound;
- fail-open path;
- overload handling.

Stage 4: Future protocol-modifying functions

Place padding, payload reconstruction, and ACK decoupling outside the current phase unless
supported by a separate DPU/FPGA/proxy architecture.

Provide:

- P4 pipeline sketch;
- metadata;
- tables;
- registers;
- counters;
- queue assignments;
- control-plane policy;
- resource budget;
- estimated latency;
- recirculation load;
- failure behavior;
- hardware test plan.

======================================================================
13. EXPERIMENTAL PLAN
======================================================================

Design experiments for:

Transaction classes:

- Class 0 READ;
- event READ;
- small status responses;
- multi-fragment responses;
- SELECT;
- OPERATE;
- DIRECT_OPERATE;
- unsupported/unknown;
- urgent/critical bypass.

Request complexity:

- CROBs: 1, 2, 3, 4, 5, 6, 8, 10, 12, 16;
- database sizes or point counts;
- small and large response payloads;
- single and multi-fragment cases;
- low and high CPU load.

Policies:

- P0 native;
- P1 fixed additive delay;
- P2 additive jitter;
- P3 constant-time;
- P4 bounded randomized normalization;
- P5 bucketed normalization;
- P6 size/request-complexity decorrelation;
- P7 decoy-distribution matching;
- P8 inter-frame-gap normalization;
- split only;
- timing only;
- split plus timing;
- padding only where a verified safe mechanism exists;
- split plus pad plus timing where authorized.

Correctness metrics:

- identical DNP3 application bytes;
- valid CRCs;
- correct SELECT status;
- correct OPERATE status;
- final output state;
- application CONFIRM behavior;
- no reordering;
- no retransmissions;
- no TCP reset;
- no DNP3 retry;
- no DNP3 timeout;
- no missed operational deadline;
- no unintended control action.

Privacy metrics:

- timing-to-CROB-count regression slope;
- R²;
- MAE/RMSE for inferred CROB count;
- mutual information;
- conditional mutual information I(T;N|size);
- device/config classification accuracy;
- balanced accuracy;
- macro F1;
- ROC-AUC;
- privacy gain;
- repeated-observation attack accuracy;
- defense-aware attack accuracy;
- Wasserstein distance;
- JS divergence;
- KS distance;
- packet-count leakage;
- total-byte leakage;
- profile-bypass leakage.

Overhead metrics:

- added latency mean/median/p95/p99/max;
- transaction completion time;
- SELECT-to-OPERATE interval;
- packet-count increase;
- bandwidth increase;
- CPU use;
- memory;
- held packets;
- queue occupancy;
- scheduler error;
- Tofino recirculation bandwidth;
- register/table use;
- DPU/FPGA resource use;
- deadline-miss rate;
- policy-bypass rate.

Attackers:

- threshold;
- template matcher;
- random forest;
- gradient boosting;
- SVM;
- temporal 1D-CNN where justified;
- defense-aware attacker;
- repeated-poll averaging attacker;
- attacker using total bytes plus timing;
- attacker using packet count plus timing;
- attacker attempting to detect the defense itself.

======================================================================
14. OPTIMIZATION AND POLICY-SELECTION REQUIREMENTS
======================================================================

Formulate policy selection as a constrained multi-objective problem.

Objectives:

- minimize information leakage;
- minimize classification accuracy;
- minimize added latency;
- minimize bandwidth overhead;
- minimize packet-count overhead;
- minimize CPU/memory overhead;
- minimize hardware resource use;
- minimize deadline misses;
- minimize distinguishability of the defense itself.

Hard constraints:

- DNP3 correctness = 100%;
- no unintended operation;
- no TCP retransmission;
- no DNP3 timeout;
- FIFO preserved;
- byte-preservation during the current phase;
- critical traffic bypassed;
- cumulative transaction deadline preserved.

Produce:

- privacy-latency Pareto frontier;
- privacy-bandwidth Pareto frontier;
- privacy-hardware-cost Pareto frontier;
- recommended operating points;
- separate recommended policies for software, Tofino, DPU, and FPGA.

======================================================================
15. REQUIRED DELIVERABLES
======================================================================

Create:

    research/split_pad_timing_policy/

with these files:

1. executive_summary.md

A clear explanation for Philip and Dr. Lin:

- what split, pad, and timing normalization each accomplish;
- when each is required;
- when each is unsafe;
- how they compose;
- recommended implementation path;
- main novelty;
- main limitations.

2. terminology_and_threat_model.md

Precisely define:

- split;
- segmentation;
- fragmentation;
- padding;
- dummy traffic;
- cover traffic;
- timing normalization;
- timing randomization;
- pacing;
- delay;
- ACK-bearing response;
- pure ACK;
- DNP3 CONFIRM;
- criticality;
- anonymity profile.

3. literature_review.md

Deep literature review organized by:

- DNP3/ICS;
- traffic analysis;
- splitting/segmentation;
- padding/cover traffic;
- timing mitigation;
- software systems;
- programmable switches;
- SmartNIC/DPU/FPGA;
- operational safety.

4. paper_matrix.csv

Columns:

- title;
- authors;
- year;
- venue;
- DOI;
- stable URL;
- peer reviewed;
- evidence level;
- split relevance;
- padding relevance;
- timing relevance;
- protocol;
- attacker model;
- mechanism;
- software/hardware;
- platform;
- experiment type;
- security result;
- overhead result;
- limitations;
- relevance to this project.

5. bibliography.bib

Verified BibTeX only.

6. split_analysis.md

Cover:

- safe split boundaries;
- protocol semantics;
- TCP/NIC effects;
- attacker residuals;
- overhead;
- recommended split policy.

7. padding_analysis.md

Cover:

- all padding mechanisms;
- invalid-index negative result;
- valid dummy point feasibility;
- gateway/RTAC possibilities;
- tunnel padding;
- cover traffic;
- silence hiding;
- safety and overhead;
- current-phase versus future-phase classification.

8. timing_analysis.md

Cover:

- which timing signals leak;
- normalization versus jitter;
- first-response and inter-chunk timing;
- RTO and operational budgets;
- traffic-class policies;
- recommended timing distributions.

9. combined_decision_policy.md

Include:

- complete decision tree;
- policy matrix by transaction class;
- target-profile architecture;
- runtime pseudocode;
- bypass logic;
- failure handling.

10. software_design.md

Detailed low-overhead software implementation.

11. tofino_design.md

Detailed staged Tofino design with documented capabilities versus inference.

12. dpu_fpga_design.md

BlueField, Netronome, and FPGA comparison.

13. safety_and_operations.md

DNP3 and grid-operational safety analysis.

14. evaluation_plan.md

Experiments, attackers, metrics, statistics, sample sizes, hypotheses, and success criteria.

15. overhead_model.md

Quantitative latency, bandwidth, CPU, memory, queue, recirculation, and hardware-cost model.

16. research_gaps_and_novelty.md

Hostile-review assessment.

17. advisor_brief.md

A concise meeting brief answering:

- When do we split?
- When do we pad?
- When do we hide timing?
- What can be built now?
- What requires a future phase?
- What are the three strongest experiments?
- Which decisions require Dr. Lin’s approval?

18. sources_audit.md

Per important claim:

- source;
- section/page/line where available;
- evidence type;
- confidence;
- contradiction/caveat;
- whether independently verified.

19. implementation_roadmap.md

A staged roadmap:

- Phase 0: baseline measurement;
- Phase 1: software split plus timing;
- Phase 2: safe padding investigation;
- Phase 3: Tofino pacing/gap normalization;
- Phase 4: absolute-delay hardware;
- Phase 5: multi-device evaluation;
- Phase 6: publication-ready integrated system.

======================================================================
16. FINAL SYNTHESIS FORMAT
======================================================================

After all agents finish:

1. Have Agent J review all artifacts.
2. Resolve contradictions.
3. Remove unsupported claims.
4. Verify every citation.
5. Clearly label:
   - measured fact;
   - standard-defined behavior;
   - vendor-documented behavior;
   - paper-reported result;
   - engineering inference;
   - untested hypothesis.
6. Produce a final synthesis using this structure:

Main fingerprinting channels:
When to split:
What to split:
How to split:
When not to split:

When to pad:
What to pad:
How to pad:
Why current padding may be unavailable:
Future safe padding options:

When to normalize timing:
Which timing signals:
Recommended timing policy:
Traffic classes to bypass:
Deadline and RTO policy:

Recommended combined decision rule:
Recommended software implementation:
Recommended Tofino implementation:
Recommended DPU/FPGA implementation:

Expected privacy benefit:
Expected latency overhead:
Expected bandwidth overhead:
Expected hardware overhead:

Strongest contribution:
Strongest negative result:
Main reviewer concern:
Immediate next experiment:
Evidence confidence:

======================================================================
17. QUALITY AND INTEGRITY REQUIREMENTS
======================================================================

- Do not invent papers, standards, features, hardware capabilities, or measurements.
- Do not assume an abstract proves implementation details.
- Do not label simulation as hardware.
- Do not claim a device fingerprinting result from one device.
- Do not claim database-size leakage from the CROB-count sweep alone.
- Do not claim padding is solved when only invalid-index padding has been tested.
- Do not claim splitting hides total transaction size.
- Do not claim timing normalization hides visible DNP3 payload content.
- Do not assume 200 ms is a universal TCP RTO.
- Do not claim Tofino supports arbitrary packet sleep.
- Do not claim DNP3 fields reveal physical criticality.
- Do not recommend delaying protection traffic.
- Do not hide negative results.
- Include simpler alternatives when complex mechanisms are unnecessary.
- Prefer low-overhead solutions.
- Separate current implementation from future protocol-modifying work.
- Use clear IEEE/ACM research language.
- After every highly technical section, include a plain-language explanation.

Begin by reading the repository and existing research package. Then create the shared
grounding document. Only after grounding is complete should the specialized agents be
launched in parallel.