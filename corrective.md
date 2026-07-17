You are implementing the corrective completion of the timing axis in the DNP3 traffic-
obfuscation research repository.

The work is a new corrective subphase:

PHASE 04B — DUAL-CASE RELEASE-TIME NORMALIZATION

This is not a new splitting phase.
This is not a padding phase.
This is not ACK-mode coalescing.
This is not the final composition of all defenses.

The objective is to implement and validate a wire-level timing normalizer that works
correctly for both native TCP response structures:

1. SEPARATE:
   request → pure TCP ACK → DNP3 RESPONSE

2. COMBINED:
   request → ACK-bearing DNP3 RESPONSE

Read the repository, Git history, phase reports, source PCAPs, current tests, and the
existing HTML explainer before making changes.

Read at minimum:

- docs/ack_timing_obfuscation_research.md
- research/ack_timing_normalization/GROUNDING.md
- research/ack_timing_normalization/advisor_brief.md
- all reports under reports/phases/phase_02*
- all reports under reports/phases/phase_03*
- all reports under reports/phases/phase_04*
- all reports under reports/phases/phase_05_ack_mode_normalization/
- characterize_ack_traces.py
- ack_fingerprint_eval.py
- all timing planners and schedulers
- all existing tc/netem/eBPF feasibility code
- dnp3_obfuscation_phases00_05_report.html

Do not trust stale prose over code, PCAPs, manifests, or current results.

============================================================
1. RESEARCH SCOPE
============================================================

Implement a byte-preserving, no-synthesis, no-suppression timing mechanism.

Allowed:

- observe existing packets;
- classify existing pure TCP ACKs and ACK-bearing DNP3 responses;
- delay existing packets;
- schedule existing packets at an absolute deadline;
- preserve per-flow FIFO order;
- record telemetry;
- fail open.

Forbidden in this subphase:

- DNP3 byte modification;
- CRC recomputation;
- response padding;
- packet splitting;
- TCP ACK synthesis;
- TCP sequence or acknowledgment rewriting;
- dropping or suppressing a pure ACK;
- socket coalescing;
- DNP3 application CONFIRM synthesis or suppression;
- P4/Tofino implementation;
- combining this mechanism with splitting or padding;
- claiming complete device anonymity.

Use the exact terminology:

- Pure TCP ACK:
  ACK flag set, zero TCP payload, no SYN/FIN/RST, associated with the request.

- ACK-bearing DNP3 RESPONSE:
  TCP payload-bearing outstation response that cumulatively acknowledges the request.

- DNP3 application CONFIRM:
  actual DNP3 function code CONFIRM only.

Never call a DNP3 RESPONSE an “application ACK.”

============================================================
2. CORRECT THE EXISTING PHASE INTERPRETATION
============================================================

Audit and document these distinctions.

Phase 02:
- retain as a combined-response application-scheduling baseline;
- state that it does not independently control a pure ACK already emitted by the kernel;
- state that delaying the application write can change ACK mode if it crosses the
  kernel delayed-ACK behavior.

Phase 03A:
- retain as the Linux ACK-separation characterization;
- keep the 36–40 ms transition scoped to the tested gambit Linux configuration;
- do not use it to explain the physical devices’ native ACK policies.

Phase 04:
- distinguish actual measured netem/qdisc control-point evidence from unimplemented
  eBPF design;
- remove any statement that says a complete eBPF scheduler was already built unless
  repository artifacts prove it.

Phase 05:
- retain as ACK-mode normalization through socket coalescing;
- state that Phase 05 changes packet structure where the socket is controlled;
- do not present Phase 05 as the dual-case timing normalizer.

Create Phase 04B rather than rewriting or deleting prior history.

============================================================
3. MECHANISM NAME AND OBJECTIVE
============================================================

Name the mechanism:

DCRN — Dual-Case Release-Time Normalizer

Objective:

For every eligible transaction, select a target release deadline from a public
transaction-class profile that is identical across SEL-751-, AB1400-, and ION7550-derived
traffic. Delay the existing reverse-direction packet or packets so the visible ACK and
response timing no longer reflects device processing time.

DCRN must preserve native packet structure during this phase:

- separate remains separate;
- combined remains combined.

ACK-mode normalization is a separate Phase 05 primitive.

============================================================
4. TARGET-POLICY DESIGN
============================================================

For transaction i define:

t0       = request arrival timestamp at the normalizer
tA_ready = pure TCP ACK availability time, if present
tR_ready = DNP3 response availability time
Di       = selected class-independent target delay
Ti       = t0 + Di

Target selection must depend only on:

- declared public transaction class;
- experiment policy;
- deterministic experiment seed;
- transaction counter or stable transaction identifier.

Target selection must NOT depend on:

- device label;
- source PCAP name;
- source IP used as a device identifier;
- native ACK mode;
- response size;
- native response time;
- packet count;
- source-capture position in a way that repeats a short target sequence.

Implement at least:

P0_NATIVE
- no timing modification.

P1_FIXED_DEADLINE
- one calibrated target D for the eligible class.

P2_COMMON_BOUNDED
- target sampled from one common bounded distribution [Dlow, Dhigh];
- same distribution for every device;
- deterministic reproducible seed;
- no PRNG reset per device, capture, session, or repetition.

Do not call P2 “random jitter.”
Call it “normalization to a common bounded target distribution.”

============================================================
5. TARGET CALIBRATION
============================================================

Do not hard-code the final target before analyzing the authoritative native data.

For every eligible transaction class calculate:

- count;
- minimum;
- median;
- p90;
- p95;
- p99;
- p99.9 where sample count supports it;
- maximum request→response readiness;
- first-request and non-first-request values separately;
- scheduler precision/jitter from a calibration run;
- measured effective Vision-side TCP RTO.

Select a target region satisfying:

Dlow >= high-quantile response readiness + scheduler guard

Dhigh < measured effective RTO - safety guard

Prefer:

Dlow >= p99.9 + guard

If a small number of real tails exceed that value, retain them and report deadline
misses. Do not silently discard them.

If no safe target exists below the RTO margin:

- mark the transaction class unsupported;
- bypass it;
- do not invent a successful target.

Record the full calibration rationale in JSON and Markdown.

============================================================
6. TRANSACTION STATE
============================================================

At request ingress record per-flow state:

- normalized flow key;
- request timestamp;
- request TCP sequence;
- request payload length;
- expected cumulative ACK;
- transaction counter;
- public transaction class;
- selected target delay;
- absolute target deadline;
- state;
- first reverse packet type;
- pure ACK seen;
- response seen;
- deadline miss;
- bypass reason;
- cleanup timestamp.

Support the authoritative IPv4/TCP DNP3 port-20000 path first.

The request state must be armed only by a payload-bearing master→outstation DNP3 request.
Handshake packets must not arm timing normalization.

Do not identify the device by its IP address when selecting the target.

============================================================
7. REVERSE-PACKET CLASSIFICATION
============================================================

Classify an eligible pure request ACK as:

- outstation→master direction;
- source port 20000;
- TCP ACK set;
- TCP payload length == 0;
- SYN == 0;
- FIN == 0;
- RST == 0;
- cumulative ACK covers the armed request;
- not a duplicate ACK;
- not a SACK-driven loss signal;
- not a meaningful window update;
- not a keepalive;
- not the ACK of a DNP3 application CONFIRM;
- exactly one unambiguous outstanding transaction.

Classify an eligible ACK-bearing DNP3 RESPONSE as:

- outstation→master direction;
- source port 20000;
- TCP ACK set;
- TCP payload length > 0;
- cumulative ACK covers the armed request;
- belongs to the armed transaction.

Keep the orthogonal fields:

ack_mode:
- COMBINED_ACK_RESPONSE
- SEPARATE_ACK_RESPONSE
- UNDETERMINED

response_delivery:
- FULL
- MULTI_SEGMENT
- AMBIGUOUS

Do not infer ACK mode from response segmentation.

============================================================
8. DUAL-CASE RELEASE POLICY
============================================================

COMBINED case:

When the ACK-bearing DNP3 RESPONSE reaches egress:

release_response =
    max(response_ready_time, absolute_target_deadline)

Assign the packet that absolute release time.

Do not delay the application write to create this delay. The TCP stack must first
produce its native combined response; the egress scheduler delays the existing packet.

SEPARATE case:

When the pure TCP ACK reaches egress:

- assign it the transaction’s absolute target deadline;
- do not drop it;
- do not release it immediately.

When the DNP3 RESPONSE reaches egress:

- assign it the same absolute target deadline if per-flow FIFO ordering reliably emits
  the earlier-enqueued pure ACK first;
- otherwise assign response deadline = target + a small fixed common guard delta.

The desired defended wire shape is:

request ───────── pure ACK → response
                  common target

The ACK-to-response gap should collapse toward scheduler/serialization time and no longer
reflect native device processing time.

The guard delta must:

- be common across all separate transactions;
- be based on measured scheduler behavior;
- not depend on device identity or native timing;
- be reported as a residual.

If either packet arrives after its target deadline:

- pass it immediately;
- record a deadline miss;
- preserve ordering;
- do not drop or synthesize anything.

============================================================
9. IMPLEMENTATION
============================================================

Implement the first real wire-level DCRN executor using Linux tc/eBPF and an fq qdisc,
reusing any valid existing repository infrastructure.

Expected architecture:

tc ingress eBPF:
- observe master→outstation requests;
- arm transaction state;
- choose the class-independent target;
- store the absolute deadline.

tc egress eBPF:
- classify pure ACK versus ACK-bearing response;
- retrieve the transaction deadline;
- assign skb transmit timestamp / EDT;
- record packet classification and scheduling telemetry.

fq qdisc:
- release the packets according to their timestamps.

Before implementation, verify on the actual kernel:

- tc BPF support;
- skb timestamp/EDT behavior;
- fq behavior;
- per-flow ordering for equal deadlines;
- map and helper availability;
- loader compatibility;
- clock domain used by skb timestamps.

Do not merely assume these capabilities.

If equal-deadline FIFO ordering is not reliable:

- use the smallest measured fixed response guard delta that guarantees ACK-before-response;
- record it;
- do not claim zero ACK→response gap.

If the current eBPF loader cannot support the needed maps or helpers:

- update the loader safely;
- or use a minimal supported libbpf/pyroute2 loader;
- preserve Python 3.8 compatibility for repository tooling.

Do not replace the mechanism with a static netem delay. A static netem smoke test is not
the required transaction-aware implementation.

============================================================
10. SAFETY AND FAIL-OPEN POLICY
============================================================

Initially allowlist only routine solicited READ transactions that are unambiguous and
single-outstanding.

Bypass by default:

- SELECT;
- OPERATE;
- DIRECT OPERATE;
- critical control traffic;
- unsolicited responses;
- link keepalives;
- application CONFIRM traffic;
- multi-master ambiguity;
- concurrent outstanding requests;
- retransmission or loss-recovery states;
- unknown DNP3 classes;
- missing request state;
- unknown RTO;
- map exhaustion;
- scheduler failure.

Fail open means native forwarding, not packet loss.

Require:

- no packet suppression;
- no packet synthesis;
- no DNP3 modification;
- no sequence/ACK rewrite;
- no packet reordering;
- no hold beyond the configured safe RTO margin;
- bounded state lifetime;
- dead-man cleanup;
- transparent behavior when the BPF program is detached.

============================================================
11. EXPERIMENTAL CONDITIONS
============================================================

Run paired conditions using the same source transactions, order, seeds, request bytes,
response bytes, hosts, sockets, and capture points:

A. NATIVE
B. OLD_APPLICATION_SCHEDULER
C. DCRN_FIXED
D. DCRN_COMMON_BOUNDED

Do not combine with:

- CRC splitting;
- padding;
- Phase 05 coalescing;
- ACK suppression.

Use:

- SEL-751-derived profile: native separate ACK + response;
- AB1400-derived profile: native combined ACK-bearing response;
- ION7550-derived profile: native combined ACK-bearing response.

Run both:

1. gambit loopback characterization;
2. Vision master ↔ Hulk outstation replay over the real switched 1 G path.

Capture at the actual wire-facing interface for the two-host experiment.

Include first transactions after connection establishment. The new request-armed classifier
must distinguish first-request ACKs from handshake ACKs rather than excluding them by default.

Report first and non-first results separately.

============================================================
12. SAMPLE DESIGN
============================================================

Use all eligible transactions from the authoritative source captures where practical.

Do not silently cap at the first 120 without justification.

If a cap is necessary:

- stratify over native timing quantiles;
- include the slow tail;
- include response-size classes;
- preserve separate and combined cases;
- report the sampling rule;
- record excluded counts and reasons.

Use multiple independent sessions and repeated complete runs.

Minimum target:

- at least 5 independent complete runs;
- at least 100 TCP sessions per profile and condition where operationally practical;
- grouped statistical analysis by run and session.

Do not treat transactions within one stream as fully independent experiments.

============================================================
13. REQUIRED PER-TRANSACTION OUTPUT
============================================================

Create a canonical table containing:

- run_id;
- repetition;
- environment;
- condition;
- device_profile;
- source_pcap;
- source_transaction_id;
- session_id;
- transaction_index;
- first_in_connection;
- public_transaction_class;
- request_timestamp;
- expected_ack;
- native_ack_mode;
- observed_ack_mode;
- pure_ack_ready_timestamp;
- pure_ack_release_timestamp;
- response_ready_timestamp;
- response_release_timestamp;
- selected_target_ms;
- configured_guard_delta_ms;
- scheduler_error_ack_ms;
- scheduler_error_response_ms;
- request_to_ack_event_ms;
- request_to_pure_ack_ms;
- request_to_response_ms;
- pure_ack_to_response_ms;
- response_size;
- response_segment_count;
- deadline_miss;
- bypass;
- bypass_reason;
- retransmission;
- duplicate_ack;
- established_session_reset;
- missing_exchange;
- source_response_sha256;
- received_response_sha256;
- byte_identical.

For combined packets:

- ACK event timestamp equals the ACK-bearing response timestamp;
- request_to_pure_ack_ms remains null;
- pure_ack_to_response_ms remains null in the raw table.

Do not invent a pure-ACK timestamp for combined traffic.

A separate derived feature may define:

ack_event_to_response_ms = 0

for combined traffic because the ACK event and response are the same packet. Label that
derived semantic explicitly.

============================================================
14. TIMING-EFFECTIVENESS EVALUATION
============================================================

Evaluate:

- request→ACK event;
- request→pure ACK where applicable;
- request→response;
- pure ACK→response where applicable;
- response-ready→release hold;
- scheduler target error;
- release-time distribution;
- higher moments and tails;
- deadline-miss rate;
- bypass rate;
- added latency.

Report per profile and condition:

- n;
- minimum;
- median;
- mean;
- standard deviation;
- p90;
- p95;
- p99;
- maximum;
- confidence intervals;
- Wasserstein distance;
- KS statistic with appropriate multiple-comparison handling.

The timing target is successful when:

- request→response distributions substantially overlap across all three profiles;
- request→ACK-event distributions substantially overlap;
- the separate ACK→response gap collapses to the fixed scheduler/serialization residual;
- visible timing is uncorrelated with device label, native processing time, and response
  size within the tested class;
- deadline misses and bypasses are explicitly bounded.

============================================================
15. ATTACKER EVALUATION
============================================================

Use leakage-safe grouped splits by:

- complete run;
- TCP session;
- source transaction identity.

No copy of the same source transaction may appear in both train and test.

Feature families:

mode_only:
- is_separate

ack_event_timing:
- request_to_ack_event_ms

separate_ack_timing:
- request_to_pure_ack_ms
- pure_ack_to_response_ms
- applicable only with missingness handled explicitly and not as a device-label sentinel

response_timing:
- request_to_response_ms

timing_all:
- request_to_ack_event_ms
- request_to_response_ms
- derived ack_event_to_response_ms
- scheduler-independent wire timing only

size:
- request_size
- response_size

all:
- mode;
- timing;
- size;
- approved packet-count fields.

Report:

- accuracy;
- balanced accuracy;
- macro-F1;
- per-profile precision and recall;
- confusion matrices;
- repeated grouped-CV mean;
- standard deviation;
- bootstrap or repeated-CV 95% confidence interval;
- exact seeds;
- uniform baseline 0.333;
- majority baseline.

Expected interpretation:

- mode_only may remain approximately 0.667 because this phase preserves ACK mode;
- timing-only classification should approach the 0.333 balanced baseline;
- size remains unchanged;
- all-feature accuracy may remain above chance because ACK mode and response size are
  separate residual channels.

Do not mark the timing mechanism as failed because mode_only and size remain.

Do not claim full fingerprint anonymity.

============================================================
16. CORRECTNESS AND TRANSPORT HEALTH
============================================================

Verify:

- source and received DNP3 response hashes match;
- 100% byte identity for completed exchanges;
- no DNP3 field changes;
- no packet drops caused by DCRN;
- no established-session retransmissions attributable to DCRN;
- no duplicate ACK anomalies attributable to DCRN;
- no established-session resets;
- no ACK-after-response ordering violation;
- no response-before-request-state match;
- no stale-flow-state contamination;
- no target selection correlated with device, size, or transaction position;
- scheduler behavior is reproducible under the same seed.

Separate pre-connection readiness-probe SYN/RST traffic from established-session resets.

============================================================
17. TESTS
============================================================

Add unit and integration tests for:

- pure ACK classification;
- ACK-bearing response classification;
- handshake ACK exclusion;
- application CONFIRM ACK exclusion;
- expected cumulative ACK matching;
- combined scheduling;
- separate dual-packet scheduling;
- equal-deadline FIFO behavior;
- guard-delta fallback;
- late response/deadline miss;
- fail-open behavior;
- duplicate ACK bypass;
- retransmission bypass;
- concurrent-request bypass;
- deterministic target generation;
- no PRNG reset by device or session;
- target independence from device label;
- target independence from response size;
- state cleanup;
- map exhaustion;
- byte identity;
- status/report consistency.

Run the full existing suite plus new tests.

No skipped test may hide a Phase 04B gate requirement.

============================================================
18. REQUIRED OUTPUTS
============================================================

Create:

reports/phases/phase_04b_dual_case_timing/
    phase_04b_dual_case_timing.md
    phase_status.json
    calibration.md
    calibration.json
    loopback_eval.md
    loopback_eval.json
    rig_eval.md
    rig_eval.json
    attacker_eval.md
    attacker_eval.json
    safety_eval.md
    safety_eval.json
    manifests/
    figures/
    tables/

Required tables:

- phase04b_transactions.csv
- phase04b_target_calibration.csv
- phase04b_timing_summary.csv
- phase04b_deadline_misses.csv
- phase04b_bypass_summary.csv
- phase04b_transport_health.csv
- phase04b_classifier_metrics.csv
- phase04b_classifier_predictions.csv
- phase04b_run_manifest.json

Required figures:

- native_vs_dcrn_timeline
- request_to_ack_event_ecdf
- request_to_response_ecdf
- separate_ack_to_response_gap
- target_vs_visible_ack
- target_vs_visible_response
- scheduler_error
- timing_classifier_accuracy
- all_feature_accuracy
- latency_privacy_tradeoff
- deadline_miss_tail

Every figure must have a metadata sidecar containing:

- producing script;
- exact command;
- run IDs;
- full evidence commit;
- source-table hashes;
- filters;
- sample counts;
- statistical transformation;
- classifier parameters;
- seeds;
- split strategy.

Retain authoritative PCAPs or record their SHA-256 hashes and stable locations.

============================================================
19. UPDATE THE HTML EXPLAINER
============================================================

Update:

dnp3_obfuscation_phases00_05_report.html

Rename or extend it appropriately so it includes Phase 04B without pretending the work
happened in the original Phase 04.

The HTML must accurately explain:

1. The native combined case:
   request → ACK-bearing DNP3 RESPONSE.

2. The native separate case:
   request → pure TCP ACK → DNP3 RESPONSE.

3. Why application-level response delay alone is insufficient:
   it cannot control a kernel-emitted pure ACK and can change ACK mode if delayed too far.

4. The new DCRN control point:
   request timestamp recorded at ingress;
   pure ACK and/or response scheduled at egress;
   same public transaction-class deadline.

5. Combined operation:
   hold the existing ACK-bearing response to the common deadline.

6. Separate operation:
   hold both the existing pure ACK and response to the common deadline;
   emit them back-to-back in FIFO order;
   do not drop or combine them.

7. What DCRN closes:
   device-dependent request→ACK and request→response timing.

8. What DCRN does not close:
   ACK mode;
   response size;
   packet count;
   other non-timing channels.

9. How Phase 05 differs:
   coalescing removes the categorical separate-ACK structure where the socket is controlled.

10. Why the final combined defense will later compose independent primitives.

Correct existing inaccuracies:

- do not claim Phase 04 had a completed eBPF scheduler if it did not;
- restrict the 36–40 ms delayed-ACK finding to the tested Linux configuration;
- do not say physical SEL behavior is caused by exceeding a Linux 40 ms timer;
- do not say only response size can possibly remain;
- use “response size is the dominant stable residual in the evaluated feature set”;
- do not call profile replay a physical-device experiment;
- do not call synthetic dots captured transactions.

Interactive graphics must use actual result data from the authoritative CSV/JSON tables.

If any graphic remains illustrative:

- label it prominently as illustrative;
- do not say each dot is captured.

Add an interactive timing diagram with toggles:

- Native SEL-derived separate;
- Native AB/ION-derived combined;
- DCRN fixed;
- DCRN common bounded;
- Phase 05 coalesced, shown separately and clearly labeled as packet-structure
  normalization.

For DCRN fixed/common bounded:

- SEL-derived pure ACK and response should visibly move to the common target;
- AB/ION-derived ACK-bearing responses should move to the same target;
- preserve the visible two-packet versus one-packet distinction;
- explain that timing is normalized while ACK mode is not.

Add actual-data plots for:

- request→ACK event;
- request→response;
- separate ACK→response gap;
- deadline misses;
- timing-only classifier;
- mode-only classifier;
- size-only classifier;
- all-feature classifier.

Add a “What Dr. Lin’s two-case instruction changed” section.

Add a “What will be combined later” section, but do not present combined results that
were not run.

============================================================
20. STATUS AND VERDICT
============================================================

Phase 04B receives PASS only when:

- a real transaction-aware wire-level scheduler is implemented;
- both separate and combined native cases are exercised;
- pure ACK and response are independently scheduled in the separate case;
- ACK-bearing response is scheduled in the combined case;
- target selection is class-independent;
- timing-only classification approaches the declared baseline;
- byte identity is complete;
- transport health is clean;
- deadline misses and bypasses are reported;
- HTML claims match the evidence;
- tests pass;
- the repository tree is clean.

Do not require:

- ACK-mode removal;
- response-size removal;
- padding;
- splitting;
- full all-feature anonymity.

Those belong to separate primitives.

Keep:

next_phase_allowed = false

until explicit human review and authorization.

============================================================
21. COMMITS AND PROVENANCE
============================================================

Use forward commits only.

1. Evidence commit:
   implementation, tests, experiment scripts, PCAP-derived tables, results.

2. Closeout metadata commit:
   reports, status JSON, HTML explainer, provenance references.

Do not amend or rewrite history.

The final status must record:

- full evidence commit SHA;
- full metadata commit SHA;
- branch;
- clean-tree state;
- test count;
- run IDs;
- PCAP hashes;
- table hashes;
- environment;
- target calibration;
- effective RTO;
- target distribution;
- scheduler guard delta;
- deadline-miss rate;
- bypass rate.

============================================================
22. FINAL RESPONSE FORMAT
============================================================

Print:

PHASE 04B DUAL-CASE TIMING NORMALIZATION COMPLETE

Status: PASS | CONDITIONAL PASS | FAIL
Scoped objective: <one sentence>
Evidence commit: <full SHA>
Closeout metadata commit: <full SHA>
Branch: <branch>
Dirty tree: true | false
Tests: <passed / failed / skipped>

Mechanism:
<how combined and separate packets are handled>

Target policy:
<fixed and bounded targets, calibration, RTO margin>

Loopback run IDs:
- <list>

Vision-Hulk run IDs:
- <list>

Combined-case result:
<request→response normalization and scheduler error>

Separate-case result:
<request→ACK, request→response, ACK→response normalization>

Timing attacker result:
<metrics with CI>

Mode-only result:
<explicitly state that ACK mode is preserved and remains a residual>

Size result:
<explicitly state that size is unchanged>

Deadline misses:
<count, rate, tail explanation>

Bypasses:
<count and reasons>

Transport safety:
<byte identity, retransmissions, duplicate ACKs, resets, ordering>

HTML report:
<path and summary of corrected/added sections>

Supported claims:
- <list>

Unsupported claims:
- complete device anonymity
- ACK-mode removal by DCRN
- response-size removal by DCRN
- physical-device defense unless actually tested
- Tofino implementation

Open Phase 04B blockers:
- none
or
- <actual blocker>

next_phase_allowed: false

STOP: Dual-case timing normalization is complete. Awaiting human review before combining
timing with splitting, padding, or ACK-mode normalization.