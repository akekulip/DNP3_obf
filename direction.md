RESEARCH CORRECTION: IBSPG ROOT-CAUSE INVESTIGATION AND REPAIR

The previous conclusion that the queue-resident research is complete, systematically
negative, or ready to pivot to endpoint timing is NOT accepted.

Do not pivot to:

- endpoint scheduling
- eBPF or EDT
- SmartNICs
- DPUs
- host proxies
- split servers
- platform splits
- continuous recirculation of the original real packet as the final mechanism

unless Philip explicitly approves that change.

This project remains:

- Tofino-1 only
- inline
- queue-buffered
- transaction-aware
- no external chaff
- no controller in the packet fast path
- no continuous thousands-of-pass recirculation of the original ACK or response
- byte-preserving
- ACK-before-response
- bounded and fail-open

A failed configuration is not an authorization to abandon the research direction.

The purpose of research is to identify why the tested mechanism failed, isolate the
load-bearing cause, correct it, and test the corrected mechanism.

CURRENT STATUS

Switch:
- management IP: 10.10.54.81
- BF-SDE: 9.13.2
- restoration target: queue_microbench_abs.conf
- exactly one intended bf_switchd after restoration

Hosts:
- Vision: 10.10.54.19
- Vision relay-side address: 192.168.10.1
- Hulk: 10.10.54.158

Current committed research branch:
research/queue-backpressure-release

Current accepted descendant includes:
- 1090e01
- f2f6879
- 38d02c8

The prior IBSPG history must remain untouched.

Create a new branch from commit 38d02c8:

research/ibspg-root-cause-repair

Do not amend, squash, rebase, reset, or rewrite history.

SCIENTIFIC CORRECTION

The accepted conclusion is narrow:

“The IBSPG configurations tested so far did not achieve a reliable, bounded
strict-priority hold under the tested queue mappings, token populations, shaping
settings, loopback paths, and safety ceilings.”

The following conclusions are NOT accepted:

- IBSPG is impossible
- strict-priority occupancy gating is universally refuted
- all queue-resident indirect constructions are infeasible
- in-network holding is systematically infeasible
- endpoint timing is now the approved direction
- recirculation is automatically the final mechanism

P-SCHED established that:

- scheduling-disable can hold an original packet in TM memory
- the held packet is not dropped
- the held packet does not recirculate
- a matching data-plane register event does not directly enable the queue
- a control-plane re-enable releases it

That experiment isolates the direct TM actuation limitation.

It does not by itself prove that every indirect occupancy, priority, queue-bank,
loopback, or staged construction is impossible.

RESEARCH DISCIPLINE

For every failure:

1. State the exact tested configuration.
2. State the exact observed result.
3. Enumerate plausible root causes.
4. Design experiments that distinguish those causes.
5. Change one independent variable at a time.
6. Re-run the relevant control and treatment.
7. Preserve all negative evidence.
8. Correct the mechanism when a cause is identified.
9. Repeat until the cause is resolved.

Do not convert:

“this configuration failed”

into:

“the architecture is impossible.”

A mechanism may be called architecturally impossible only when:

- an authoritative architecture rule excludes the required behavior;
- all proposed alternatives reduce to that exact excluded behavior;
- the actual implementation has been checked for configuration error;
- the relevant scheduler domain, queue mapping, and priority semantics are proven;
- targeted silicon experiments confirm the predicted behavior;
- no unresolved confound remains;
- the conclusion is narrowly scoped to Tofino-1/BF-SDE 9.13.2;
- Philip reviews the closure argument.

Do not write a “systematic negative contribution” or recommend endpoint timing during
this phase.

PRIMARY OBJECTIVE

Determine the root cause of the IBSPG failure and produce a corrected, lower-resource
IBSPG or closely related queue-resident mechanism.

The lead mechanism remains:

Internal-Blocker Strict-Priority Gate, IBSPG

- original ACK and response reside in Q_HOLD
- Q_HOLD is lower priority
- internal blocker traffic occupies a higher-priority scheduling path
- response/deadline state stops or drains the blocker
- Q_HOLD then receives service
- ACK and response leave in FIFO order
- blocker traffic never exits dp9 or dp11
- the original real packets do not continuously recirculate

Do not integrate full DNP3 until the underlying hold primitive is repaired and proven.

PART 1 — PRESERVE AND CORRECT THE PROJECT RECORD

Read, at minimum:

- IBSPG_MICROBENCH_FINAL_REPORT.md
- IBSPG_STATE_AND_RESUME.md
- QUEUE_RELEASE_RESEARCH_REOPENING.md
- INDIRECT_QUEUE_RELEASE_DESIGN_SPACE.md
- FIRST_EXPERIMENT_PAIRED_BUFFER.md
- INTERNAL_TOKEN_THREAT_AND_VISIBILITY_MODEL.md
- TOFINO_INTERNAL_BACKPRESSURE_AUDIT.md
- TWO_STAGE_QUEUE_RELEASE_ALTERNATIVES.md
- NEXT_QUEUE_PRIMITIVE_EXPERIMENT.md
- PSCHED_MICROBENCH_RESULT.md
- psched_ctl.py
- all IBSPG P4 programs
- all TM configuration scripts
- all run logs
- all compiler reports
- all queue-counter captures
- all host captures
- all port-mapping documents

Create:

IBSPG_RESEARCH_CONTINUATION_DIRECTIVE.md

Record:

- what was actually implemented
- what was actually tested
- what passed
- what failed
- what remains unresolved
- which previous claims were too broad
- which conclusions remain valid
- why further root-cause work is required

Do not delete or alter historical reports.

Add a dated research addendum instead.

PART 2 — FORENSIC RECONSTRUCTION OF EVERY IBSPG RUN

Do not rely on summaries.

Reconstruct every previous IBSPG silicon run from raw evidence.

For each run, record:

- date
- commit
- P4 binary
- switch configuration
- internal port
- physical or recirculation loopback
- pipe
- port group
- qid
- queue mapping
- Q_BLOCK priority
- Q_HOLD priority
- min-priority
- max-priority
- DWRR weight
- shaping enablement
- shaping rate
- shaping burst
- scheduling enablement
- token count
- token size
- token rate
- pass budget
- experiment duration
- expected packet path
- observed port counters
- observed queue counters
- occupancy
- watermark
- drops
- held-packet outcome
- token-escape outcome
- cleanup result

Create:

IBSPG_EXPERIMENT_FORENSIC_LEDGER.md

Explicitly identify missing evidence.

Do not fill missing values by assumption.

PART 3 — BUILD A ROOT-CAUSE TREE

Create:

IBSPG_ROOT_CAUSE_TREE.md

At minimum evaluate these mutually distinguishable causes:

A. CONFIGURATION ERROR
- wrong qid
- wrong pg_id or pg_queue
- wrong queue-to-port mapping
- wrong strict-priority field
- reversed priority numbering
- unexpected min-rate or max-rate setting
- DWRR still active
- shaping applied to the wrong object
- Q_BLOCK and Q_HOLD not in the same arbitration domain
- loopback traffic using another queue
- stale bfrt state
- program and setup-script mismatch

B. SCHEDULER-SEMANTICS ERROR
- “strict priority” is not absolute in the tested hierarchy
- max-priority and min-priority affect different scheduler stages
- queue fairness or anti-starvation behavior exists
- shaping changes eligibility before strict-priority arbitration
- port-level and queue-level arbitration were conflated
- queues are attached to different L1 scheduler nodes
- recirculation-port scheduling differs from physical-port scheduling

C. BLOCKER-REPLENISHMENT ERROR
- Q_BLOCK momentarily becomes empty
- loopback round-trip exceeds service interval
- token count is too small
- tokens synchronize into bursts rather than remaining phased
- shaping creates empty eligibility periods
- token loss reduces the ring below the safe population
- pass-budget expiry creates an unobserved gap
- token creation begins too late, after ACK admission

D. MEASUREMENT ERROR
- queue occupancy sampling is too coarse
- counters are stale
- queue usage is read from the wrong queue
- average occupancy hides sub-microsecond empty intervals
- timestamps refer to different clock domains
- packet capture is not on the actual protected egress
- port counters include unrelated traffic
- held packet was dropped or misrouted rather than held

E. PHYSICAL-PATH ERROR
- dp8 intermittent physical behavior
- FEC or PCS errors
- loopback path mismatch
- MAC-near versus physical-loop behavior
- link flap
- wrong measured port-role mapping

F. ARCHITECTURE LIMIT
- Q_HOLD receives service while Q_BLOCK is continuously nonempty and eligible
- only after A–E have been excluded

For every node define:

- predicted observation
- distinguishing experiment
- required evidence
- correction if confirmed

PART 4 — VERIFY THE ACTUAL TM SCHEDULER HIERARCHY

Inspect the installed BF-SDE 9.13.2 documentation, headers, schemas, examples, and
actual bfrt readback.

Determine precisely:

- where queue strict priority is applied
- whether min_priority and max_priority belong to separate arbitration stages
- whether Q_BLOCK and Q_HOLD share the same scheduler parent
- L1-node attachment
- port-group relationship
- queue scheduling order
- shaping-before-priority or priority-before-shaping behavior
- whether strict priority guarantees starvation of a lower queue
- whether any fairness behavior remains
- differences between physical, MAC-loopback, and recirculation ports
- how DWRR interacts with strict priority
- how min-rate and max-rate eligibility interact with priority
- how queue burst credit affects eligibility

Do not infer semantics from field names.

Cite exact local documentation paths and bfrt readback.

Produce:

TOFINO1_STRICT_PRIORITY_SEMANTICS_AUDIT.md

PART 5 — PROVE QUEUE AND PRIORITY PLACEMENT

Create a readback tool that prints, for Q_BLOCK and Q_HOLD:

- dev_port
- pipe
- port group
- pg_id
- pg_queue
- qid
- scheduler parent or L1 node where available
- scheduling_enable
- min_priority
- max_priority
- DWRR weight
- min-rate enable
- max-rate enable
- shaping rate
- burst
- buffer settings
- current usage
- watermark
- drops

Verify that both queues are in the same intended scheduler domain.

Create:

ibspg_tm_readback.py

The tool must fail loudly when:

- a requested queue does not exist
- readback differs from intended configuration
- program binding is wrong
- queue mapping is ambiguous

Do not run further IBSPG conclusions without passing this placement check.

PART 6 — FINITE-BACKLOG STRICT-PRIORITY ORACLE

Remove token-loop replenishment from the first scheduler experiment.

The purpose is to separate:

- strict-priority behavior
from
- blocker-ring replenishment behavior

Use one internal port and two queues in the same proven scheduler domain.

Experiment:

1. Place a finite but sufficiently large, safely bounded backlog into Q_BLOCK.
2. Confirm Q_BLOCK usage is greater than zero.
3. Enqueue marked packets into Q_HOLD.
4. Observe whether any Q_HOLD packet dequeues while Q_BLOCK remains nonempty.
5. Repeat with different Q_BLOCK backlog sizes.
6. Repeat with shaping disabled everywhere.
7. Repeat with only the required static priority configuration.
8. Repeat on both the documented physical-loopback path and a supported internal path
   where safe.

Use bounded packet counts, not unbounded rate.

Required evidence:

- exact enqueue counts
- exact dequeue counts
- occupancy before, during, and after
- watermark
- held-packet timestamps
- Q_BLOCK-empty timestamp
- Q_HOLD-first-service timestamp
- port counters
- zero token escape
- zero unexplained drop

This experiment answers:

“Does the configured scheduler serve Q_HOLD while Q_BLOCK has a real finite backlog?”

Classify:

- STRICT-PRIORITY CONFIRMED
- PRIORITY CONFIGURATION WRONG
- DIFFERENT SCHEDULER DOMAIN
- FAIRNESS OBSERVED
- MEASUREMENT INCONCLUSIVE
- PHYSICAL-PATH BLOCKED

Do not test the token ring until this control is resolved.

PART 7 — MEASURE BLOCKER LOOP DYNAMICS

If strict priority is confirmed with a finite backlog, measure the blocker loop
independently.

Instrument each blocker token with:

- token_id
- slot_id
- generation
- pass count
- previous-pass timestamp
- current ingress timestamp

Measure:

- loopback round-trip time
- dequeue-to-reenqueue time
- service interval
- token loss
- inter-token spacing
- burst synchronization
- minimum and maximum gap
- queue occupancy trend
- pass-budget expiry

For N in:

- 1
- 2
- 4
- 8
- 16

measure whether the blocker queue becomes empty between replenishment events.

Do not assume tokens are phased because they were injected at different times.

Produce:

IBSPG_BLOCKER_LOOP_DYNAMICS.md

Derive a measured lower bound:

N_required > loopback_round_trip / effective_service_interval

Include a safety margin based on measured maximum jitter, not the average.

PART 8 — ELIMINATE THE EMPTY GAP

Develop and compare at least four blocker constructions:

A. SINGLE RING
- current baseline
- expected to expose the empty gap

B. PHASED MULTI-TOKEN RING
- tokens deliberately staggered
- verify that staggering survives repeated loops

C. PRELOADED BLOCKER RESERVOIR
- establish a bounded Q_BLOCK backlog before admitting the ACK
- replenish only as required
- measure residual drain delay after response

D. DUAL BLOCKER BANK
- two high-priority queues or two independent token sources
- alternate replenishment so at least one blocker path remains occupied
- drain both after the matching response

E. UPSTREAM-PACED BLOCKER SOURCE
- do not shape Q_BLOCK itself
- pace the source or feeder while keeping Q_BLOCK eligible and backlogged
- determine whether this avoids the shaping eligibility gaps observed previously

The exact supported mechanisms must come from Tofino evidence.

Do not invent a queue transfer primitive.

For each construction report:

- queue topology
- scheduler topology
- token path
- original-packet path
- expected continuous-occupancy argument
- measured occupancy
- minimum blocker depth
- internal bandwidth
- drain latency
- drain jitter
- token cleanup
- resource cost
- failure mode

PART 9 — REVISIT SHAPING WITHOUT REPEATING THE SAME ERROR

The previous result showed that shaping Q_BLOCK can create eligibility gaps.

Do not generalize this into “shaping is useless.”

Test separately:

- no shaping
- shaping Q_BLOCK
- shaping the blocker source
- shaping the internal port
- shaping a feeder queue
- different burst sizes
- two alternating sources

For every shaping placement answer:

- does Q_BLOCK remain eligible?
- does Q_BLOCK remain nonempty?
- does Q_HOLD receive service?
- where does credit accumulate?
- where does the eligibility gap occur?
- does a lone packet leave immediately?
- does the mechanism require sustained backlog?

Change one shaping parameter at a time.

Produce:

IBSPG_SHAPING_PLACEMENT_STUDY.md

PART 10 — COMPARE INTERNAL PORT TYPES

The earlier work used multiple internal paths.

Run controlled comparisons where safe:

- physical dp8 loopback
- MAC-near loopback
- MAC-far loopback, if supported and safe
- recirculation port
- any other documented internal path

Use the same:

- P4 program
- queue priorities
- queue mapping
- packet counts
- token population
- pass budget

Record differences in:

- loop round-trip
- scheduling behavior
- occupancy
- token loss
- queue drain rate
- strict-priority behavior
- FEC/PCS dependence
- packet drops

Do not treat one port type’s result as universal.

PART 11 — ON-DEMAND BLOCKER ESTABLISHMENT

A valid HOLD_ACK design must establish blocking before the ACK reaches Q_HOLD.

Investigate:

- blocker creation on READ
- confirmation that the blocker is stable before arming ACK admission
- a compact per-slot blocker_ready state
- ACK fail-open if blocker_ready is false
- blocker teardown after response or timeout

For HOLD_RESPONSE:

- create blocker state when the ACK is forwarded
- verify it is established before the response can enter Q_HOLD

Measure startup latency and race windows.

Produce:

IBSPG_BLOCKER_LIFECYCLE.md

PART 12 — ROOT-CAUSE DECISION GATE

After Parts 1–11, classify the current failure.

Permitted classifications:

- CONFIGURATION ROOT CAUSE CONFIRMED
- SCHEDULER-DOMAIN ROOT CAUSE CONFIRMED
- PRIORITY-SEMANTICS ROOT CAUSE CONFIRMED
- BLOCKER-EMPTY-GAP ROOT CAUSE CONFIRMED
- SHAPING-ELIGIBILITY ROOT CAUSE CONFIRMED
- TOKEN-LOSS ROOT CAUSE CONFIRMED
- PHYSICAL-PATH ROOT CAUSE CONFIRMED
- MEASUREMENT ROOT CAUSE CONFIRMED
- MULTIPLE ROOT CAUSES
- ROOT CAUSE STILL UNRESOLVED

For every confirmed cause:

- implement a correction
- re-run the control
- re-run the IBSPG treatment
- run a regression
- measure cost

Do not close the direction with ROOT CAUSE STILL UNRESOLVED.

PART 13 — CORRECTED IBSPG MICROBENCH

After the root cause is identified, create a new independent corrected variant.

Do not modify frozen programs.

The corrected microbenchmark must prove:

1. Q_BLOCK and Q_HOLD share the intended scheduling domain.
2. Q_BLOCK’s blocker condition is established before HELD_REAL admission.
3. HELD_REAL remains in Q_HOLD for the full no-drain interval.
4. DRAIN_UNRELATED has no effect.
5. DRAIN_MATCH stops blocker replenishment.
6. Residual blockers drain.
7. HELD_REAL releases afterward.
8. HELD_REAL is byte-identical.
9. No blocker token exits dp9 or dp11.
10. Timeout releases safely.
11. All tokens terminate.
12. Original HELD_REAL does not continuously recirculate.

Run:

- 30 initial trials
- then 100 trials for a promising configuration
- then a longer stability campaign only within approved safety bounds

Report every premature release.

Do not average failures away.

PART 14 — PAIRED ACK/RESPONSE ONLY AFTER HOLD PROOF

Proceed only after corrected IBSPG passes.

Use synthetic transaction A:

1. ARM-A establishes blocker.
2. ACK-A enters Q_HOLD.
3. RESPONSE-B does not release ACK-A.
4. RESPONSE-A enters behind ACK-A.
5. RESPONSE-A sets the matching drain state.
6. Blockers stop replenishing.
7. ACK-A leaves first.
8. RESPONSE-A follows by FIFO.
9. Both are byte-identical.
10. State and blockers clear.

Then test two simultaneous admitted slots.

Only after this passes should the parser-hardened DNP3 classifier be integrated.

PART 15 — DO NOT RUN PFC AUTONOMOUSLY

The P-PFC experiment remains explicitly gated.

Do not run it unless Philip separately authorizes it.

Do not use the unrun P-PFC experiment as evidence for either success or impossibility.

PART 16 — CLAIM AND LANGUAGE CONTROL

Until the root-cause campaign is complete, do not write:

- “IBSPG is refuted”
- “in-network hold is systematically infeasible”
- “endpoint timing is the proven path”
- “the queue research is complete”
- “continuous recirculation is the selected final mechanism”
- “the negative result is the contribution”

Use:

- “the tested configuration failed”
- “the current root cause is…”
- “this correction was evaluated…”
- “this mechanism remains unvalidated”
- “the conclusion is scoped to the tested configuration”

Do not update project memory with a broad impossibility conclusion.

Update memory only with:

- exact tested configuration
- exact measured result
- identified root cause
- correction
- corrected result

PART 17 — REPORTING

Produce:

IBSPG_ROOT_CAUSE_AND_REPAIR_REPORT.md

Required structure:

1. Research question
2. Prior implementation
3. Prior failure
4. Forensic reconstruction
5. Root-cause hypotheses
6. Scheduler-semantics audit
7. Queue-placement proof
8. Finite-backlog control
9. Token-loop measurements
10. Empty-gap analysis
11. Shaping-placement results
12. Internal-port comparison
13. Confirmed root cause
14. Corrective design
15. Corrected silicon results
16. Remaining limitations
17. Exact next experiment

Clearly distinguish:

- inferred
- documentation-supported
- compiled
- configured
- observed on silicon
- repeated
- corrected
- unresolved

PART 18 — SAFETY AND RESTORATION

Do not:

- reboot the switch
- reboot hosts
- change management networking
- change firmware
- change the physical SEL
- issue DNP3 writes
- run unbounded token loops
- exceed the existing safe traffic ceiling without explicit approval
- run PFC without explicit approval
- risk shared management connectivity

After every hardware experiment:

- terminate every blocker token
- verify no token remains
- restore queue_microbench_abs.conf
- verify exactly one bf_switchd
- verify switch at 10.10.54.81
- verify Vision at 10.10.54.19
- verify Vision retains 192.168.10.1
- verify Hulk at 10.10.54.158
- verify no capture, replay, pktgen, blocker, or probe remains
- record final counters
- record git status

AUTONOMY

Proceed autonomously through:

- document and code audit
- root-cause analysis
- read-only SDE research
- compile-only prototypes
- bounded reversible microbenchmarks
- corrections
- regressions

Do not stop merely because an experiment fails.

A failed experiment creates the next hypothesis.

Pause only for:

- physical intervention
- destructive risk
- management-connectivity risk
- firmware or OS changes
- PFC authorization
- SEL involvement
- a genuine choice between two experimentally successful corrected designs

The objective is not to finish quickly.

The objective is to understand the failure, correct the mechanism, and produce a
defensible Tofino-native research contribution.