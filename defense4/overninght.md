Resume repository `akekulip/DNP3_obf`, branch `defense4-caseA-hw-integration`.

Expected starting HEAD:

`a085f00463d3ae5160acc001cbcd42dac0a6223a`

This is an overnight autonomous execution task. Do not return a plan. Execute the work, preserve evidence, commit at meaningful checkpoints, push the branch, and continue until the experiment gate is closed or a genuine safety blocker remains after bounded attempts.

The mandatory order is:

1. Audit the repository and current hardware state.
2. Correct the runtime and experimental harness.
3. Complete the hardware, protocol, failure, statistical, and bottleneck experiments.
4. Freeze and reconcile the experimental evidence.
5. Only after the experiment gate closes, use `/research-pipeline` to research and draft the Introduction.
6. Use `/humanizer` only as the final prose pass.

Paper writing is the last task. Do not edit the manuscript, draft the Introduction, or begin literature prose while experiment status remains unknown or incomplete.

Do not call this project or paper “ADTA.” That is not the project name.

# Governing execution rules

* Begin with `git status`, remote synchronization, branch verification, and exact HEAD resolution.
* Inspect the actual commits and files. Do not accept this prompt, `WORKING_NOTES.md`, commit messages, or prior Claude reports as proof.
* Recompute results directly from P4, scripts, PCAPs, JSON, counters, compiler artifacts, and live readbacks.
* Preserve the frozen Defense 1, Defense 2, Defense 3, Part 11, Part 12, and four-queue evidence. Do not modify those sources.
* Do not merge this branch into `main`.
* Do not begin size obfuscation.
* Do not perform SELECT or OPERATE against the physical SEL-751.
* The physical SEL-751 remains READ-only.
* No controller may enter the packet-release fast path.
* Do not weaken a check, reinterpret a failure, or modify the scorer merely to obtain PASS.
* Do not call a selected delay “optimal.” Report it as calibrated, tested, or selected for the campaign.
* Use active, direct technical prose. Do not use em dashes.

# Skills and expert-agent use

Read the available skill instructions before using them.

* Use `/research-pipeline` after the experiment evidence freeze. Follow its storytelling and research philosophy when drafting the Introduction.
* Use `/find-skills` whenever a missing capability would materially help with DNP3 generation, PCAP analysis, experiment statistics, P4/Tofino inspection, or evidence management.
* Use `/humanizer` only after claims, citations, technical terminology, and paragraph logic are locked. It must not alter facts, qualifiers, equations, or citations.
* Use bounded expert agents in parallel for:

  1. P4 and Tofino correctness;
  2. DNP3 and TCP behavior;
  3. experimental design and statistics;
  4. deployment safety;
  5. skeptical evidence review.
* Expert agents are advisory. Only the main agent may load, configure, stop, restore, or otherwise act on the live switch.
* Verify every agent conclusion against primary evidence.

Do not treat “out of scope” as the first answer to a load-bearing correctness hurdle. Before declaring a blocker:

1. identify the exact failed invariant;
2. inspect the relevant source, logs, and hardware state;
3. obtain at least two independent expert analyses;
4. try at least two safe, technically distinct approaches where feasible;
5. preserve the negative result and explain why further attempts would be unsafe or structurally impossible.

# Part A: Repository and evidence audit

## A1. Resolve the actual repository state

Verify:

* local branch and worktree status;
* remote branch HEAD;
* full commit history from `8a152d7` through the actual current HEAD;
* whether `a085f00` remains HEAD;
* all untracked or uncommitted changes;
* whether the source that produced the deployed binary matches the committed blob.

Inspect at minimum:

* `defense4/timing/p4/defense4_caseA.p4`
* `defense4/timing/control/defense4_caseA_setup.py`
* `defense4/timing/control/deploy/bringup_runner.sh`
* `defense4/timing/control/deploy/score_txn.py`
* `defense4/timing/control/deploy/watchdog.sh`
* `defense4/timing/control/deploy/rollback_defense3.sh`
* `defense4/timing/evidence/HARDWARE_BRINGUP_RESULT.md`
* `defense4/timing/evidence/bringup_live_20260807T014243Z/`
* `defense4/TIMING_SPEC.md`
* `defense4/ARCHITECTURE.md`
* `defense4/EVIDENCE_BASELINE.md`
* `defense4/IMPLEMENTATION_PLAN.md`
* `defense4/RISK_REGISTER.md`
* `RESUME_STATE.md`
* `WORKING_NOTES.md`
* the proven Defense 3 setup and harness reused by Defense 4.

## A2. Verify the current switch state read-only

The last report claims:

* switch: `decps@10.10.54.81`;
* current program: `defense4_caseA`;
* one `bf_switchd`;
* D4 mode with `D_A=D_R=0x8000`;
* pktgen armed;
* relay forwarding working;
* no watchdog armed.

Do not assume this remains true.

Before any switch write, collect and preserve:

* process count and full command line;
* active conf file and program name;
* loaded binary hash;
* committed P4 source hash;
* active BF-SDE version;
* port state;
* Traffic Manager queue configuration and priorities;
* queue and port shaping state;
* mirror configuration;
* parser value-set;
* pktgen app, template, counters, trigger and enable state;
* `tbl_params` readback;
* relevant registers and correctness counters;
* relay reachability and normal READ behavior;
* active watchdog, rollback, or stale marker processes.

Create a timestamped read-only current-state snapshot. If the switch differs from the report, record the discrepancy before changing anything.

## A3. Audit the existing bring-up verdict

Create:

`defense4/timing/evidence/POST_BRINGUP_EVIDENCE_AUDIT.md`

For every material claim in `HARDWARE_BRINGUP_RESULT.md`, classify it as:

* `SUPPORTED`
* `PARTIALLY SUPPORTED`
* `UNSUPPORTED`
* `CONTRADICTED`
* `NOT YET TESTED`

Explicitly recheck these already-observed issues:

1. `bringup_runner.sh` invokes `configure` before every transaction.
2. `configure` calls `clear_state`, including resetting `reg_tag`, deadlines, timestamps and counters.
3. Each call to `block.py` uses `N=1`, opens a new TCP connection, and sends `FRAMES[0]`, whose application control is C0.
4. Therefore, the 17 D1 trials did not advance through C0…CF and did not prove rollover.
5. The final trial selected the configured `FAIL_OPEN` bypass mode. It did not induce missing-ACK, missing-RESPONSE, blocker-budget, or watchdog fail-open.
6. D3 mode was not run in the integrated Defense 4 program.
7. `0x8000` is 32,768 ns, or 32.768 µs. It is not a millisecond-scale delay.
8. In the committed D2 trials, native CLRT was approximately 1.83–6.00 ms, so `T_RESP=t_A+32.768 µs` had expired before each native RESPONSE arrived.
9. In the committed D4 trials, `T_RESP=t_A+65.536 µs`, also earlier than the native RESPONSE arrival.
10. Thus D2 and D4 exercised classification, queue traversal, and successful delivery, but did not yet prove useful response-deadline shaping.
11. Queue watermark increases directly attribute occupancy only to the first protected transaction because the watermark is latched.
12. The committed evidence directory contains parsed transaction files but not the referenced raw PCAPs.
13. The current scorer does not directly prove global token escape absence, packet duplication absence, byte identity, or all queue/port drop classes.
14. The final reload that left Defense 4 running is described in `RESUME_STATE.md`, but its detailed readbacks and packet evidence are not committed.
15. `verify-only` still passes `app_enable=False` into the pktgen verifier before separately expecting protected modes to be enabled.
16. Snapshot/restore does not yet restore every state its comments claim, including the complete mirror, port, pktgen and queue scheduling/shaping state.

Do not discard the valid result. Preserve that the original run did establish:

* the program loaded and forwarded real SEL-751 READ traffic;
* 34 transactions received responses;
* the first protected READ generated and admitted 128 tokens;
* qid7, qid6, qid5 and qid4 were all exercised;
* qid5 was demonstrably populated;
* no four-queue TM drop was observed in that short run;
* the tested rollback restored a forwarding Defense 3;
* D1 produced a near-coincident ACK and RESPONSE on the observed wire.

Change the verdict wording only after completing the audit.

## A4. Audit specification-to-implementation alignment

Create a matrix covering:

* OFF;
* D1 event release;
* D2 response deadline;
* D3 ACK deadline;
* D4 dual deadline;
* configured FAIL_OPEN;
* runtime fail-open transition;
* separate ACK;
* combined ACK-bearing RESPONSE;
* generation source and rollover;
* exact flow and transaction matching;
* one-shot admission;
* duplicate READ, ACK and RESPONSE;
* concurrent transactions;
* missing ACK;
* missing RESPONSE;
* FIN and RST cleanup;
* timestamp wrap;
* blocker isolation;
* byte preservation;
* supported DNP3 functions;
* resource and stage limits.

For each property, record:

* what `TIMING_SPEC.md` requires;
* what the committed P4 actually implements;
* what the compiler proves;
* what existing silicon evidence proves;
* what remains unverified or differs from the specification.

In particular, resolve rather than hide:

* the specification’s “internal generation” versus the implementation’s DNP3 application-sequence generation;
* the 16-value C0…CF reuse interval;
* whether mode is latched per transaction or read dynamically on every packet;
* whether a concurrent READ can overwrite session trackers before its arm is rejected;
* whether combined ACK+RESPONSE safely bypasses or reaches a bounded fail-open path;
* whether the implementation protects only READ;
* whether SELECT/OPERATE currently bypass;
* whether both reservoirs are autonomously established early enough for the physical ACK;
* whether the current design has a readiness guard or relies on measured timing margin;
* whether all required FIN/RST and missing-event cleanup paths exist in the integrated source.

# Part B: Correct the runtime and experiment harness

Do not modify the P4 merely to improve telemetry. First correct the control and experimental layers. Modify the P4 only for a demonstrated correctness defect that cannot be resolved in the harness.

## B1. Separate initialization from policy changes

The campaign must not reconfigure ports, queues, pktgen, mirror state, or clear transaction state before every poll.

Implement clear operation boundaries:

* `initialize` or equivalent:

  * configure fixed-function state once;
  * configure queues once;
  * configure pktgen once;
  * clear state only at a deliberate clean campaign boundary;
  * verify every readback.

* `set-policy` or equivalent:

  * change only mode, `D_A`, `D_R`, `D_A+D_R`, READ length and budget;
  * refuse unless the prior transaction is inactive and required queues are safely drained;
  * do not clear `reg_tag`, deadlines, session trackers, counters or timestamps;
  * do not flap or rewrite ports;
  * do not rewrite the pktgen template or queue priorities.

* `clear-evidence`:

  * permitted only while inactive;
  * clear counters and sparse evidence registers at campaign boundaries, not between transactions in a sustained block.

* `verify-only`:

  * correctly expect pktgen enabled for D1–D4 and disabled for OFF/FAIL_OPEN;
  * perform no writes.

* `snapshot` and `restore-only`:

  * either restore all state claimed by their documentation or narrow and rename their semantics honestly;
  * the proven Defense 3 cold reload plus setup remains the canonical emergency rollback.

Add offline tests for every operation and for refusal while a transaction is active.

## B2. Correct parameter handling

Use the proven quantization helper or an equivalent single authority.

For every configured delay, print and save:

* requested milliseconds;
* encoded word;
* realized ticks;
* realized nanoseconds and milliseconds;
* quantization error;
* `D_A+D_R`;
* relationship to the campaign poll interval;
* relationship to the fail-open horizon.

Enforce:

* low byte zero;
* no arithmetic overflow;
* modular comparison half-range;
* established maximum-delay policy;
* `D_A+D_R` below the justified transaction/polling safety bound;
* correct mode-specific constraints.

Do not hand-label `0x8000` as a millisecond-scale delay.

## B3. Build a sustained-connection campaign driver

The driver must support multiple DNP3 READs on one TCP connection and preserve the C0…CF request sequence.

For every poll, record:

* request index;
* request DNP3 application sequence;
* TCP 4-tuple;
* TCP sequence and acknowledgement values;
* request, ACK and RESPONSE timestamps;
* response length and segmentation;
* ACK/RESPONSE ordering;
* CLRT;
* request-to-ACK and request-to-RESPONSE latency;
* retransmissions;
* duplicates;
* connection reset or close;
* socket result;
* mode and realized parameters.

Do not use a new TCP connection for every transaction when claiming sustained operation, cleanup, or generation rollover.

## B4. Expand evidence collection

Extend read-only evidence collection to include, where available:

* every relevant `ctr_fresh` slot;
* every relevant `ctr_deq` slot;
* pktgen trigger, batch and packet counters;
* per-queue watermarks and drops;
* port-level and global TM drops;
* `reg_tag`;
* `reg_deadline`;
* `reg_tresp`;
* `reg_ack_rel`;
* `reg_failopen`;
* session trackers;
* sparse timestamps;
* current `tbl_params`;
* pktgen enable state.

Counters must be aggregated correctly across replicated instances.

Capture all Ethernet traffic on the master-facing interface, not only `host relay_ip`, so an escaped `0x88C1` token cannot be hidden by the capture filter.

The scorer must detect:

* missing ACK;
* missing RESPONSE;
* RESPONSE-before-ACK;
* duplicate ACK or RESPONSE;
* unexpected extra payload;
* retransmission;
* TCP reset;
* DNP3 parsing mismatch;
* token or private EtherType escape;
* unexpected queue or port drops;
* fail-open release;
* stale state after completion;
* failure to re-arm the following transaction.

Preserve raw PCAPs, not only parsed JSON. Create a SHA-256 manifest for every PCAP, log, JSON, source file and compiler artifact.

# Part C: Hardware safety for the overnight campaigns

The prior authorization covers bounded hardware experiments using READ traffic against the physical SEL-751 and controlled emulator/synthetic tests. It does not authorize physical SELECT or OPERATE.

Before the first live write:

1. verify the exact Defense 3 rollback artifacts and command;
2. verify the exact committed Defense 4 source and loaded binary;
3. snapshot current process, ports, TM, pktgen and runtime state;
4. start an independent detached watchdog on the switch;
5. verify the watchdog survives loss of the initiating session;
6. verify rollback remains idempotent;
7. make every experiment block bounded and logged;
8. invoke rollback on configuration failure, management loss, persistent loss, token escape, unbounded hold, queue drops, ordering inversion or cleanup failure.

A shell trap alone is insufficient.

The watchdog should retry or escalate visibly if restoration fails. Do not log “rollback invoked” as if that proves restoration.

If the existing loaded Defense 4 binary exactly matches the committed and compiled artifact, avoid an unnecessary reload. Harness-only corrections do not require recompiling or reloading the P4.

At the successful end, preserve Philip’s instruction to leave Defense 4 running only if:

* the exact program and policy are known;
* forwarding is verified;
* no safety failure remains;
* the final mode and parameters have passed the corrected campaign.

Otherwise restore Defense 3. Report the final state explicitly. Never silently leave an unknown program or policy active.

# Part D: Complete the experiments

## D1. Recover the original raw evidence

Check whether the original `blk_t*.pcap` files still exist on Vision.

* If they exist, copy them into the committed evidence directory and hash them.
* Reparse them independently.
* If they do not exist, state that the original parsed evidence cannot substitute for preserved raw captures.

Do not rerun the original flawed schedule merely to recreate its appearance.

## D2. Correct generation rollover

Run a real sustained rollover test:

* configure D1 once;
* do not clear state or counters between polls;
* keep one TCP connection;
* send at least 33 successful READs, covering C0…CF twice and returning to C0;
* use a safe polling gap;
* record every request sequence;
* verify 128 generated and admitted tokens per protected READ;
* verify no stale-generation release;
* verify every transaction retires;
* verify the next transaction re-arms;
* verify zero token escape, ordering inversion, persistent loss or TM drops.

A collection of C0 requests on new connections is not a rollover test.

## D3. Test actual runtime fail-open

Keep configured `FAIL_OPEN` as a separate bypass-policy test, but do not call it the failure-transition test.

Using an emulator, synthetic harness, or another safe controlled method, test:

1. missing ACK;
2. ACK present but missing RESPONSE;
3. zero or deliberately small budget;
4. fail-open followed by a normal ready transaction;
5. asymmetric reservoir expiry;
6. cleanup after FIN and RST.

Measure:

* time to release or retire;
* which counter records the cause;
* whether any original packet is stranded;
* whether both token roles terminate;
* final register state;
* ability of the next transaction to arm and complete.

No negative event injection may use physical SELECT or OPERATE.

## D4. Validate every integrated mode

Run OFF, D1, D2, D3 and D4 in the integrated Defense 4 program.

### OFF

Establish the native distribution on sustained connections. One transaction is insufficient.

### D1

Prove event-driven behavior rather than merely small CLRT:

* use a RESPONSE arrival later than an ordinary candidate ACK deadline;
* show that the ACK does not release on the ordinary deadline;
* show release only after the matching RESPONSE event or bounded fail-open;
* confirm the resulting release tail and ordering.

### D2

Choose a realized `D_R` that is later than native RESPONSE arrival for a substantial and documented portion of trials.

Require:

* ACK follows the immediate loopback path;
* RESPONSE enters qid4;
* response blocker remains active until `T_RESP`;
* deadline-release counter increments;
* fail-open release counter does not replace the intended deadline;
* output response timing matches the configured target within measured release error.

A trial in which the RESPONSE arrives after an already-expired deadline is a late-arrival path test, not proof of RESPONSE shaping.

### D3

Test the integrated D3 mode even though the frozen Defense 3 program has separate prior evidence.

Require:

* ACK held to `T_A`;
* RESPONSE never overtakes ACK;
* D3-equivalent policy operates inside the unified binary;
* cleanup and subsequent reuse work without reload or state reset.

### D4

Choose meaningful `D_A` and `D_R`.

Require:

* ACK held to `T_A`;
* RESPONSE held to `T_RESP=T_A+D_R` when it arrives early;
* ACK commits before RESPONSE release;
* both deadline release causes are attributable;
* measured output interval reflects the realized successor interval plus measured release tails;
* late native RESPONSE cases are classified separately.

## D5. Parameter calibration

First run a native OFF pilot sufficient to estimate:

* median;
* IQR;
* 5th, 95th and 99th percentiles;
* session-to-session variation;
* retransmission and loss behavior.

Then run a small, justified grid of quantized `D_A` and `D_R` values. Select campaign values based on:

* native timing distribution;
* protocol and QoS bounds;
* polling interval;
* fail-open horizon;
* observed release tails;
* absence of retransmissions and resets.

The purpose is to find a safe, informative tested region, not a mathematical optimum.

Create:

`defense4/timing/evidence/PARAMETER_CALIBRATION.md`

## D6. Statistical campaigns

After pilots, run two independent campaigns.

### Campaign A: fixed-condition blocks

Run at least 100 valid transactions per condition for:

* OFF;
* D1;
* D2;
* D3;
* D4.

Use sustained connections and multiple blocks so one connection is not treated as the entire population.

### Campaign B: randomized block order

Run at least 100 additional valid transactions per condition.

* Randomize condition block order with a recorded seed.
* Change policy only between inactive, verified blocks.
* Do not clear transaction state per poll.
* Preserve separate session and block identifiers.

Report:

* attempted, sent, acknowledged and responded counts;
* valid and excluded trials with reasons;
* CLRT and request latency distributions;
* deadline error;
* release-tail distributions;
* bootstrap confidence intervals;
* reliability outcomes;
* ordering violations;
* drops, duplicates, retransmissions and resets;
* counter-consistency checks.

Do not describe D2 or D4 as normalization unless the deadline mechanism actually creates the claimed output distribution.

## D7. Protocol and adversarial coverage

Audit the existing 22-trace backlog against the current implementation.

For every trace, mark:

* applicable;
* not applicable to the current architecture;
* already proven by frozen evidence;
* requires new hardware/emulator evidence.

Run every applicable trace that is not already proven for the integrated binary.

The minimum matrix includes:

* normal D1/D2/D3/D4;
* incomplete ACK reservoir;
* incomplete RESPONSE reservoir;
* fail-open then recovery;
* overlapping READ and its later RESPONSE;
* request retransmission;
* duplicate ACK;
* duplicate RESPONSE;
* combined ACK-bearing RESPONSE;
* wrong TCP acknowledgement;
* wrong TCP sequence;
* wrong DNP3 application sequence;
* wrong flow, direction or port;
* missing ACK;
* missing RESPONSE;
* zero-budget cleanup;
* FIN and RST at relevant phases;
* stale-generation token;
* forged or wrong-role internal token;
* inactive token arrival;
* bounded 2K drain;
* ACK pending while the RESPONSE barrier drains;
* old-generation cleanup against new state;
* real generation rollover;
* D1 not releasing on an ordinary deadline;
* timestamp-wrap behavior;
* multi-segment RESPONSE safe behavior;
* subsequent-transaction reuse.

Use the physical SEL-751 only for safe READ behavior. Use the existing synthetic/injector machinery or a controlled software outstation for malformed, missing, reordered, combined, high-rate, SELECT/OPERATE, and other negative cases.

## D8. DNP3 operation coverage

Establish the exact protocol boundary before writing.

* Confirm what the current parser protects.
* Test normal READ against the physical relay.
* Test SELECT and OPERATE only against a controlled software outstation, inert decoy point, or safe replay environment.
* Never send physical OPERATE to the SEL-751.
* Determine whether SELECT/OPERATE arm the timing engine, bypass it, or require a separate implementation.
* Test combined ACK+RESPONSE behavior using a controlled outstation capable of producing it.
* Test multi-segment or fragmented RESPONSE behavior.

If SBO is not implemented, do not add it to the paper contribution. You may attempt a bounded, stage-neutral extension only if it preserves all existing safety properties, compiles on Tofino-1, and can be verified safely. Do not force a major unverified redesign merely to improve the Introduction.

## D9. Bottleneck experiments

Create:

`defense4/timing/evidence/DEFENSE4_BOTTLENECKS.md`

Measure and distinguish:

### Hardware/compiler bottlenecks

* exact 9.13.2 compiler command and raw output;
* 12-stage placement;
* critical path;
* PHV allocation and saturated groups;
* SRAM, MapRAM and TCAM;
* register placement;
* stateful and statistics ALUs;
* parser/deparser use;
* pktgen and queue requirements;
* why splitting `reg_deadline` and `reg_tresp` solved the earlier co-location wall;
* the next actual limiting dependency.

Preserve raw compiler and placement artifacts, not only a handwritten summary.

### Runtime bottlenecks

* reservoir establishment time relative to earliest ACK;
* qid7 and qid5 continuity;
* blocker drain and release tails;
* budget-derived fail-open horizon;
* maximum safe deadline relative to poll interval;
* minimum safe polling gap;
* sustained transaction rate;
* one active transaction per scheduler domain;
* behavior under overlapping flows;
* DNP3 C0…CF generation reuse;
* static policy update requirements;
* combined-response limitation;
* READ versus SBO coverage;
* fixed K=64 dependence.

Use an emulator for aggressive rate sweeps. Keep physical-relay polling conservative.

Do not claim general scalability from one global register slot or one protected session.

# Part E: Handle defects constructively

If a mandatory experiment exposes a P4 defect:

1. preserve the failing PCAP, counters, readbacks and minimal reproducer;
2. write a regression test before changing the success criterion;
3. ask independent P4/Tofino experts for at least three bounded fixes;
4. test the smallest behavior-preserving fixes with isolated compiles;
5. do not remove generation isolation, matching, queue residency, fail-open, cleanup or token isolation to fit;
6. if the P4 changes, compile the exact committed blob on BF-SDE 9.13.2;
7. record full source and binary hashes;
8. load only behind the proven watchdog and rollback;
9. rerun every mandatory experiment affected by the change.

A negative result that reveals a real DNP3, TCP, or Tofino limitation is valuable evidence. Preserve it. Do not hide it, but do not stop at the first failed approach.

# Part F: Experimental evidence freeze

Paper writing remains prohibited until this section is complete.

Create:

* `POST_BRINGUP_EVIDENCE_AUDIT.md`
* `SPEC_IMPLEMENTATION_EVIDENCE_MATRIX.md`
* `EXPERIMENT_MATRIX.md`
* `PARAMETER_CALIBRATION.md`
* `DEFENSE4_BOTTLENECKS.md`
* a timestamped raw-evidence directory;
* `SHA256SUMS`;
* `EXPERIMENTAL_EVIDENCE_FREEZE.md`.

Every experiment row must end as:

* `PASS`
* `FAIL`
* `NOT APPLICABLE`
* `BLOCKED WITH EVIDENCE`

No row may remain `UNKNOWN`, `PLANNED`, `ASSUMED`, or `NOT ATTEMPTED`.

The evidence freeze must state:

* exact implementation tested;
* source and binary hashes;
* actual supported modes;
* actual supported DNP3 operations;
* actual generation mechanism;
* actual fail-open behavior;
* proven timing transformations;
* reliability results;
* protocol limitations;
* Tofino bottlenecks;
* R11 status;
* what the current evidence does and does not show about fingerprint mitigation;
* final switch state.

Use one experiment verdict:

* `TIMING EXPERIMENTS PASS`
* `TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY`
* `TIMING EXPERIMENTS FAIL`
* `TIMING EXPERIMENTS BLOCKED`

Proceed to paper writing only for:

* `TIMING EXPERIMENTS PASS`, or
* `TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY`, where every limitation is resolved into explicit paper wording and no mandatory experiment remains unknown.

If the verdict is FAIL or BLOCKED, stop after the engineering report. Do not write an Introduction around unresolved assumptions.

Commit and push the experimental evidence freeze before touching the manuscript.

# Part G: Research and draft the Introduction last

After the experiment gate closes, invoke `/research-pipeline`.

Follow its research and storytelling philosophy. Use `/find-skills` if a research, citation, LaTeX, or source-verification capability is missing.

Use:

* the existing `.bib`;
* the existing reference map;
* local papers;
* Semantic Scholar API/MCP;
* DOI and publisher metadata;
* primary papers and standards.

Semantic Scholar is for discovery and metadata. Verify substantive claims from primary sources.

Create an Introduction claim-to-source matrix containing:

* claim;
* primary source or experimental artifact;
* direct evidence or inference;
* allowed wording;
* wording that would overclaim.

## Dr. Lin’s required Introduction structure

### Paragraph 1: Why fingerprinting matters

* Begin with fingerprinting as an attacker’s way of understanding a target system.
* Explain what it can reveal, such as device type, role, vendor, implementation or behavior.
* Connect it to reconnaissance and attack preparation.
* Narrow from general networks to ICS and power-grid systems.
* Do not begin with P4, Tofino or queue mechanics.

### Paragraph 2: Existing traffic-obfuscation approaches

* Explain size, timing, rate and communication-pattern obfuscation.
* Use representative primary work.
* Explain carefully that many Internet-oriented approaches assume encrypted or payload-opaque traffic.
* Do not claim that all prior approaches require encryption.
* Explain why visible legacy ICS content can distinguish real protocol traffic from dummy or transformed traffic.
* Establish why these methods cannot always transfer directly to plaintext legacy ICS.

### Paragraph 3: Research gap and motivation

* Explain why legacy devices and deployed protocols are difficult to modify.
* Establish the need for a transparent in-network defense.
* State the required invariants: preserve endpoints, protocol exchanges, original packet contents and operational correctness.
* Explain that timing parameters must remain within DNP3, TCP, polling and QoS limits.
* State the trusted plaintext observation-point requirement accurately.

### Paragraph 4: Our design

Tell the design as a high-level story:

* one programmable switch sits between the DNP3 master and field device;
* it observes selected transaction events;
* it controls when the original ACK and RESPONSE become externally visible;
* the original packets remain queue-resident;
* internal blocker tokens recirculate;
* Traffic Manager scheduling provides release because the Tofino data plane cannot recall an arbitrary enqueued packet at a future software-selected time;
* configurable ACK and RESPONSE gates provide event-driven, ACK-deadline, RESPONSE-deadline and dual-deadline transformations;
* these are modes of one framework, not separate architectures.

Keep register names, queue IDs, token formats, stage numbers and low-level arithmetic out of the Introduction.

## Contribution block

Write only contributions supported by `EXPERIMENTAL_EVIDENCE_FREEZE.md`.

Potential contributions may include:

* identifying CLRT as a relevant observable in DNP3 fingerprinting;
* the unified queue-resident ACK/RESPONSE timing framework;
* solutions to the demonstrated DNP3, TCP and Tofino constraints;
* the actual Tofino-1 implementation and resource result;
* the actual silicon experiments and timing transformations.

Do not claim:

* full anonymity;
* elimination of every fingerprint;
* size obfuscation;
* encrypted-packet processing without plaintext visibility;
* general multi-flow scalability;
* complete combined-response protection unless demonstrated;
* SBO support unless implemented and tested;
* production readiness;
* optimal delays;
* universal ICS applicability;
* “first” without systematic literature support.

If only one physical relay was evaluated, do not claim cross-device indistinguishability. Distinguish mechanism feasibility from fingerprint-classification effectiveness.

## Writing and artifact requirements

* Use the canonical terminology established by the evidence freeze.
* Treat the individual defenses as configurations of one framework.
* Use READ as the demonstrated operation unless the new evidence expands this boundary.
* Use simple active IEEE prose in Philip’s tone.
* Do not use em dashes.
* Target approximately one IEEE double-column page, excluding references.
* Preserve a standalone `INTRODUCTION_DRAFT.tex`.
* Update the canonical timing manuscript only after confirming its identity.
* Create `INTRODUCTION_CLAIM_SOURCE_MATRIX.md`.
* Add only verified, nonduplicate bibliography entries.
* Compile the LaTeX and resolve citation and syntax failures.
* Have a skeptical reviewer check every novelty, evidence and threat-model sentence.
* Revise once from concrete reviewer findings.
* Run `/humanizer` only now, as the final language pass. It must preserve all technical qualifiers and citations.

# Final overnight report

Report:

1. starting and ending commits;
2. repository and live-state discrepancies found;
3. corrections made to the runtime and campaign harness;
4. every experiment group and sample count;
5. calibrated parameter values in encoded and realized units;
6. generation-rollover result;
7. actual fail-open result;
8. D1/D2/D3/D4 results;
9. protocol and adversarial results;
10. DNP3 operation boundary;
11. compiler and runtime bottlenecks;
12. R11 status;
13. final switch program, mode, parameters and forwarding state;
14. experiment verdict;
15. Introduction path, only if the experiment gate allowed writing;
16. claim-to-source matrix path;
17. final commit and push status.

Do not summarize planned work as completed. Do not report a PASS from commit messages. Execute, measure, preserve, reconcile, and only then write.
