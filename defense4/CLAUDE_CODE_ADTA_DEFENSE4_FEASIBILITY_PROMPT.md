# Master prompt for Claude Code: ADTA Defense 4 feasibility, architecture, and implementation roadmap

You are the lead systems researcher and principal implementation architect for the ADTA project. Work as a coordinated research team. Use Claude Code subagents in waves for independent expert analysis, repository inspection, P4 review, protocol review, hardware feasibility analysis, experimental design, and adversarial review. Do not stop after producing a generic plan. Inspect the actual repository, reconcile the evidence, reason from Tofino-1 constraints, and produce a technically defensible feasibility decision and implementation roadmap.

## 1. Mission

Determine whether, and under what bounded assumptions, the current ADTA architecture can become a unified Tofino-1 primitive called Defense 4 that:

1. Supports DNP3 READ and full CROB Select-Before-Operate (SBO), where SBO means SELECT followed by OPERATE. Do not substitute DIRECT_OPERATE for SBO.
2. Generalizes the new timing behaviors of Defense 1, Defense 2, and Defense 3 through one configurable release engine.
3. Adds a real size-obfuscation mechanism for the supported SBO and READ envelopes.
4. Preserves DNP3/TCP correctness and operational safety.
5. Runs on the existing Tofino-1 testbed without a controller in the packet-release fast path.
6. Produces a realistic implementation sequence, resource plan, experimental plan, risk register, and claim boundary.

The final result must answer:

> What can we build now on this testbed, what can we build only with a constrained profile, what needs a new microbenchmark, what is infeasible on Tofino-1, and what should remain future work?

## 2. Non-negotiable project constraints

Treat these as hard constraints unless repository evidence proves that one has been superseded:

- Target Tofino-1 only. Do not pivot to a SmartNIC, DPU, host-edge shaper, eBPF implementation, FPGA, software fast path, or split-platform design.
- The controller may install configuration, seed bounded state, collect telemetry, and manage experiments. It must not make per-packet or per-transaction release decisions in the fast path.
- Preserve the queue-resident direction. Real ACK and RESPONSE packets should remain resident in Traffic Manager hold queues where the demonstrated primitive does so. Internal blocker tokens may recirculate, but must never escape externally.
- Treat implementation obstacles as hypotheses to test. Use source inspection, compiler evidence, a focused microbenchmark, or a hardware experiment before declaring a Tofino feature impossible.
- Do not modify frozen Defense 1 or Defense 2 evidence artifacts. Work in a new branch or isolated feasibility directory if changes are necessary.
- Preserve all existing user changes. Begin with `git status`, inspect repository instructions, and avoid destructive Git or filesystem commands.
- Do not load a new P4 program onto the physical switch or change live Traffic Manager configuration merely to complete this planning task unless the user explicitly authorizes it.
- Do not change the SEL-751A IP configuration.
- Do not issue an OPERATE or another actuating command to the physical SEL relay. Generate full SBO first with an OpenDNP3 or equivalent controlled master/outstation. Physical relay work remains read-only unless separately authorized.
- Use simple, precise technical writing. Do not use inflated claims, fabricated results, fabricated citations, or assumed resource numbers.

## 3. Reported testbed context to verify

Do not trust this list blindly. Verify every accessible item against the repository, host configuration, Git history, compiler output, and current lab state. Record discrepancies.

- UfiSpace switch with a Tofino-1 ASIC.
- BF-SDE 9.13.1 is reported on Ubuntu 20.04. Some on-switch parity work may use 9.13.2. Detect the versions actually available and distinguish compiler-version results.
- `~/p4setup.bash` and P4Runtime utilities under `~/tutorials/utils` have been used previously.
- Vision is reported at `10.10.54.19` and `192.168.10.1`.
- Hulk is reported at `10.10.54.158`.
- The UfiSpace management address was last reported as `10.10.54.81`, but it changed after a reboot. Resolve it safely before any connection attempt.
- The SEL-751A is reported at `192.168.10.7/24`, TCP port 20000, DNP3 master address 1, and outstation address 10.
- The lab has two servers connected through the Tofino switch. Determine the real cabling, port map, loopback paths, capture points, and whether one physical Tofino can emulate both trusted boundaries of an observable protected link.

## 4. Evidence chronology and conflict rule

Build an evidence ledger before designing anything. Search the repository, Git history, tags, reports, scripts, packet captures, compiler logs, and experiment outputs. At minimum, look for:

- `GROUNDING.md`
- `CASE_A_QUEUE_DESIGN.md`
- `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md`, especially section 0.5
- Defense 1 and Defense 2 P4 and setup files
- `DEFENSE1_TELEMETRY_REVIEW.md`
- Defense 2 telemetry or live-inline reports
- Part 9 controlled-drain material
- Part 12 `HOLD_RESPONSE` material
- size-pattern builder and Level-1 queue microbenchmark material
- READ, DIRECT_OPERATE, SELECT, OPERATE, RESPONSE, ACK, and CONFIRM traces
- resource reports, `context.json`, compiler summaries, BF-RT scripts, TM setup scripts, and test harnesses

Some older documents may conflict with later hardware results. Resolve conflicts by date, commit, actual code, raw output, and experiment provenance. Do not silently average conflicting statements. Record each conflict and state which source controls and why.

Treat the following as reported anchors that still require verification:

- Defense 1 uses a matching-RESPONSE event to release a held ACK, with bounded fail-open behavior.
- Defense 1 telemetry work was associated with commit `a769dee` and tag `d1-telem-v1-verified`; the frozen files reportedly compiled at 12/12 ingress stages.
- Defense 2 uses an ACK-relative absolute deadline to hold a queue-resident RESPONSE.
- Part 12 `HOLD_RESPONSE`, commit `f00a5fd`, reportedly passed Campaign A and randomized Campaign B for 200/200 releases, with zero premature releases and an approximately 1.72 ms implementation-specific delay offset.
- Defense 2 telemetry work was associated with commit `49c1b0b` and tag `d2-telem-v1-verified`.
- Part 9 controlled data-plane drain reportedly compiled at 11/12 ingress stages and demonstrated priority readback, FIFO forwarding, bounded expiry, and stale-generation isolation.
- The size-pattern builder was associated with commit `e7e7223`.
- The Level-1 size result normalized synthetic tagged frames to one 128-byte outer frame and reduced measured size leakage, but did not demonstrate transparent live-DNP3 normalization, splitting, reassembly, joint size and timing, or full SBO.
- The real size corpus and later physical traces may exceed the historical 128-byte state. Recompute the correct size envelope from raw captures.
- Full SELECT-to-OPERATE SBO was absent from the earlier DIRECT_OPERATE corpus.
- Invalid in-protocol DNP3 padding is negative evidence, not a path to pursue again without a new technical reason.

Use these evidence labels consistently:

- `VERIFIED`: reproduced from source, raw trace, compiler output, or hardware result.
- `REPORTED`: stated in a project artifact but not reproduced in this run.
- `INFERRED`: a conclusion derived from verified facts.
- `PROPOSED`: an architecture choice that has not been demonstrated.
- `BLOCKED`: cannot be verified because a named dependency is unavailable.

Every important conclusion must carry one of these labels and a citation to a repository path, commit, log, capture, or primary source.

## 5. Candidate Defense 4 architecture to evaluate, not assume

Evaluate the following architecture rigorously. You may revise it if the evidence requires revision, but explain every revision.

### 5.1 Functional planes

1. DNP3/TCP parser and classifier.
2. Transaction and phase manager for READ, SELECT, and OPERATE.
3. Policy and public-template mapper.
4. Size encoder using a bounded outer representation, padding profile, or other proven Tofino-compatible mechanism.
5. Configurable timing release engine.
6. Protected-link forwarding and, where required, a trusted decoder that removes filler, decapsulates, and restores byte-identical traffic.
7. Lightweight correctness counters and offline telemetry.

### 5.2 Timing modes

The unified release engine should be tested against these semantic modes:

- `IMMEDIATE`
- `MATCHING_RESPONSE_EVENT`
- `ABSOLUTE_DEADLINE`
- `PREDECESSOR_PLUS_OFFSET`
- bounded `FAIL_OPEN`

Map the defenses as follows, unless the repository establishes a more accurate mapping:

| Mode | ACK behavior | RESPONSE behavior |
| --- | --- | --- |
| No shaping | Immediate | Immediate, with normal ordering |
| Defense 1 | Release ACK on the matching RESPONSE event | Release matching RESPONSE after ACK |
| Defense 2 | Release ACK immediately | Release RESPONSE near ACK plus `G` |
| Defense 3 | Release ACK near configured deadline `D` | Release RESPONSE after ACK and ordering guard |
| Defense 4 | Select event or deadline mode by phase | Apply slot deadline and/or ACK-relative release while coordinating size shaping |

Defense 4 must not be described as adding three delays together. It should expose one common gate engine with selectable predicates.

### 5.3 Candidate queue construction

For one reverse-path phase in one scheduler domain, test this strict-priority order:

`Q_ACK_BLOCK > Q_ACK_HOLD > Q_RESP_BLOCK > Q_RESP_HOLD`

The intended behavior is:

1. The ACK blocker is active before the real ACK becomes schedulable.
2. The real ACK remains in `Q_ACK_HOLD`.
3. The RESPONSE blocker is already resident but starved by the ACK blocker.
4. The real RESPONSE remains in `Q_RESP_HOLD`.
5. The ACK condition terminates or expires the ACK blocker.
6. The ACK drains before the RESPONSE.
7. The RESPONSE blocker becomes dominant.
8. The RESPONSE condition terminates or expires that blocker.
9. The matching RESPONSE drains and transaction state is cleaned.

Check these details explicitly:

- Absolute deadlines are required because a starved lower-priority blocker does not accumulate recirculation passes.
- Pass counts are a bounded fail-open mechanism, not the primary clock.
- The RESPONSE blocker must be primed before the ACK blocker ends.
- Every blocker and real packet needs generation isolation and exact-enough transaction matching.
- `ack_gone` or an equivalent state must enforce ordering, but it may not equal the physical dequeue time. Quantify the distinction.
- Residual blocker drain creates an implementation-dependent release offset.
- Shared FIFO queues cannot selectively release one transaction from behind another. Begin with one active protected transaction per scheduler domain unless an alternative is demonstrated.
- Determine whether SELECT and OPERATE can safely reuse the same queue bank sequentially and whether each protected direction needs its own bank.
- Derive the smallest queue and priority construction. Do not assume that four queues are universally minimal or that eight queues are automatically required.

### 5.4 DNP3 operation model

Model the complete workflows.

READ may contain:

- READ request
- pure TCP ACK, delayed ACK, piggybacked ACK, or no separate ACK
- one or more RESPONSE fragments or TCP segments
- master TCP ACKs
- optional DNP3 CONFIRM when requested

Full CROB SBO means:

- SELECT request using Group 12 Variation 1 CROBs
- optional pure or piggybacked ACK
- SELECT RESPONSE
- OPERATE request
- optional pure or piggybacked ACK
- OPERATE RESPONSE
- optional application CONFIRM

Do not confuse a SELECT RESPONSE with a DNP3 CONFIRM. Link SELECT and OPERATE as one higher-level SBO transaction even when application sequence numbers differ. Define a bounded supported CROB count and test successful and rejected operations in an emulator. Never invent, replay, or synthesize a real OPERATE command to fill a schedule.

### 5.5 Size plane

Do not equate Ethernet trailer padding with complete size concealment. Determine exactly what an observer sees, including Ethernet frame length, IP length, TCP payload length, DNP3 length, cell count, direction pattern, and transaction volume.

Evaluate these alternatives on Tofino-1:

1. A finite set of outer size states with encapsulation and padding.
2. Padding existing TCP/DNP3 segments without arbitrary splitting.
3. Using natural DNP3 or TCP fragmentation boundaries and padding each unit.
4. Outer cellization and trusted reassembly, but only if a microbenchmark proves the required parser, deparser, buffering, and restoration behavior.
5. Explicit overflow or fail-open profiles for packets outside the supported envelope.

For each candidate size state `S`, account for outer-header overhead, MTU, FCS conventions, checksums, payload capacity, and exact observer-visible length. Padding cannot shrink a packet. A fixed cell size can still leak original size through cell count.

If the protection goal includes hiding READ from SBO, CROB count, packet count, burst length, or direction sequence, evaluate a bounded public transaction template with filler cells. If the goal is only within-operation size normalization, do not add filler without explaining the security benefit and cost.

Separate these three protection profiles:

- Profile A: within-operation normalization for READ and SBO separately.
- Profile B: bounded cross-operation traffic-shape normalization for READ versus SBO, including count and direction filler where necessary.
- Profile C: continuous cover that also hides idle periods and transaction frequency.

Do not assume Profile B or C is required for the minimum viable Defense 4. Derive the protection contract from the threat model and meeting goals. Treat continuous cover as optional and high cost unless evidence supports it.

If DNP3 remains plaintext and the observer can inspect function codes, state clearly that timing and size shaping cannot hide the READ, SELECT, and OPERATE semantics. Strong semantic indistinguishability requires an opaque protected representation. Do not call a new outer header encryption. Determine whether cryptographic protection is an external deployment assumption, outside the Tofino primitive, or incompatible with the Tofino-1-only constraint.

### 5.6 Candidate one-switch protected-link topology

Evaluate whether one Tofino can emulate two trusted edges using separate port roles and a physical protected-link loop:

`master-side port -> encoder pass -> protected egress -> physical cable/observable link -> decoder ingress -> outstation-side port`

Use the same protected link in reverse for outstation-to-master traffic. Determine:

- exact ingress/egress port roles in both directions
- how the pipeline distinguishes encode and decode passes
- whether the link is genuinely observer-visible
- whether recirculation or internal loopback would invalidate the observer model
- where packet capture occurs
- whether outer padding can be removed before unmodified DNP3 endpoints
- whether the design consumes extra switch ports, pipelines, mirror resources, or bandwidth

Provide a concrete testbed diagram and port table. If this topology is infeasible, give the precise Tofino or cabling reason and the closest Tofino-1-only alternative.

## 6. Required expert team

Spawn agents in waves if concurrency is limited. Each agent must inspect relevant source files and produce a short evidence-backed note. Agents should not edit the same synthesis files.

1. **Evidence and Git auditor**: reconstruct the chronology, identify controlling documents, map commits/tags to files, and flag stale or contradictory claims.
2. **Tofino Traffic Manager expert**: analyze strict priority, queue behavior, blocker continuity, residual drain, queue counts, scheduler domains, recirculation load, and packet-generator interaction.
3. **P4 architecture and compiler expert**: inspect parser/deparser, registers, stateful ALUs, PHV, stage allocation, checksum handling, cloning, recirculation, and feasible unified-gate structure.
4. **DNP3/TCP and SCADA safety expert**: formalize READ and full SBO state machines, ACK variants, fragmentation, CONFIRM handling, retransmissions, timeouts, SELECT expiry, and safe emulation.
5. **Size-obfuscation and tunneling expert**: assess exact size states, encapsulation/decapsulation, MTU, padding, cell-count leakage, filler, restoration, and one-switch two-edge feasibility.
6. **Security and evaluation expert**: formalize the observer and leakage goals, design joint size/timing attacks and ablations, and define statistical acceptance criteria.
7. **Testbed and experimental-systems expert**: map the real topology, software versions, capture points, automation harness, repeatability, and failure recovery.
8. **Adversarial reviewer**: try to reject the architecture. Identify hidden assumptions, impossible semantics, unsafe steps, resource optimism, concurrency failures, and claims that the evidence does not support.

Require at least two agents to evaluate each critical blocker independently. The lead must reconcile disagreements with evidence. Do not use majority vote as a substitute for proof.

## 7. Work program

### Work package A: repository and evidence audit

1. Read repository guidance files first.
2. Record `git status`, branch, HEAD, tags, and relevant history.
3. Create a repository map for P4, control-plane, traffic generation, analysis, captures, reports, and compiler artifacts.
4. Build a chronological evidence table with claims, source paths, commits, raw evidence, status, and confidence.
5. Identify stale documents and state what supersedes them.
6. Do not cite a summarized report where a raw log or capture exists.

### Work package B: freeze the Defense 4 contract

Define, without ambiguity:

- observer location and visible protocol layers
- whether payloads are plaintext or opaque
- whether both directions are visible
- whether transaction start and idle periods may remain visible
- whether the goal is within-operation normalization, READ-versus-SBO traffic-shape normalization, or continuous cover
- supported READ object/response envelope
- supported number of CROBs per SELECT and OPERATE
- supported fragmentation and TCP segmentation envelope
- one-transaction concurrency assumption or queue-bank count
- exact fail-open behavior
- exact meaning of packet length in every result

If the evidence does not determine a policy choice, present two bounded alternatives and recommend one. Do not hide a design decision inside an implementation assumption.

### Work package C: formal state machine and packet roles

Produce state diagrams for:

- one READ transaction
- SELECT phase
- SELECT-to-OPERATE linkage
- OPERATE phase
- ACK and RESPONSE gate lifecycle
- timeout, retransmission, collision, and cleanup paths

Define the transaction key and state fields. Consider canonical flow, DNP3 link addresses, application sequence, TCP sequence/acknowledgment evidence, phase, and generation. State which fields Tofino can parse and compare at line rate. Do not claim exact matching until the key has been traced through the P4 pipeline.

At minimum analyze:

- pure ACK present, absent, delayed, or piggybacked
- RESPONSE arrives before ACK release
- multi-fragment or multi-segment RESPONSE
- duplicate request or RESPONSE
- TCP retransmission and out-of-order traffic
- SELECT failure
- successful SELECT with no subsequent OPERATE
- OPERATE arriving after a public slot
- FIN or RST
- state collision
- stale blocker generation
- queue overflow
- fail-open timeout
- concurrent transaction attempt

### Work package D: Tofino primitive feasibility

For every required primitive, fill out this matrix:

| Primitive | Needed behavior | Existing evidence | Tofino mechanism | Resource cost | Unknown | Smallest proof |
| --- | --- | --- | --- | --- | --- | --- |

Include at least:

- live DNP3 classification
- bidirectional transaction state
- response-event ACK release
- absolute-deadline ACK release
- ACK-relative RESPONSE release
- two sequential queue gates
- exact-enough transaction and generation matching
- blocker priming and expiry
- queue-resident real-packet hold
- cleanup and bounded fail-open
- outer encapsulation and decapsulation
- exact padded sizes
- filler generation and suppression at decoder
- forward-direction slot scheduling
- multi-phase SBO linkage
- limited concurrency or admission control

Classify every primitive as:

- feasible with existing proof
- feasible with a bounded extension
- requires a named microbenchmark
- infeasible under a named Tofino-1 limitation
- outside the minimum Defense 4 contract

### Work package E: compiler and resource analysis

Reproduce safe offline compiles where the toolchain is available. Do not rely on remembered counts.

1. Compile the frozen baselines without modifying them.
2. Compile or inspect the stripped Defense 2 core if it exists. If it does not exist, specify the exact safe stripping change but do not alter frozen evidence.
3. Report ingress and egress stages, latency, SRAM, Map RAM, TCAM, stateful ALUs, PHV containers, parser/deparser limits, and warnings.
4. Estimate the incremental cost of each Defense 4 component separately.
5. Distinguish compiler-proven numbers from estimates.
6. Check 9.13.1 and 9.13.2 parity only where both environments are actually available.
7. Include Traffic Manager resources, queue and priority requirements, recirculation bandwidth, blocker-token rate, pktgen use, queue occupancy, and external filler bandwidth. These do not all appear in the P4 stage report.
8. Produce a stage and resource headroom table with confidence levels.

If a full combined program does not yet exist, do not fabricate a combined resource total. Give a bounded budget and the compile experiment needed to replace it.

### Work package F: focused microbenchmarks

Design a dependency-ordered microbenchmark plan. Implement only safe, isolated, minimal probes that answer a decisive feasibility question and can compile offline without touching frozen artifacts. Put them under a clearly named new feasibility directory.

Prioritize:

1. Stripped Defense 2 resource baseline.
2. One binary selecting Defense 1, 2, and 3 release predicates.
3. Sequential ACK and RESPONSE gates using the four-queue candidate.
4. Absolute-deadline behavior when the RESPONSE blocker was starved.
5. Outer encapsulate-pad-decap round trip with byte-identical restoration.
6. Exact observer-visible size verification across several size states.
7. Safe filler generation, protected-link transmission, and decoder drop.
8. Offline or emulator-fed parsing of true READ and full SBO traces.
9. SELECT-to-OPERATE phase linkage and timeout cleanup.
10. Joint size-plus-timing path for one READ and one SBO profile.

For every probe, define setup, independent variable, raw outputs, success criterion, failure interpretation, resource measurement, and cleanup. Preserve negative evidence.

### Work package G: safety and timing envelope

Measure or source the relevant limits instead of assuming them:

- effective TCP retransmission timeout on Vision and the peer stack
- master request timeout
- outstation response timeout
- SEL or emulator SELECT timeout
- maximum safe SELECT-response-to-OPERATE delay
- deadline and blocker-drain jitter
- queue occupancy and overflow margin

A prior effective TCP RTO floor near 200 ms and a 10 s SELECT timeout have been reported. Verify these before using them as design limits.

Derive phase-specific timing profiles for READ, SELECT, and OPERATE. A single `D` or `G` need not be valid for all phases.

### Work package H: evaluation design

The evaluation must include correctness, leakage, performance, safety, and resources.

Correctness:

- READ measurements remain correct.
- SELECT and OPERATE semantics remain correct in the controlled emulator.
- restored packets are byte-identical where restoration is claimed.
- filler never reaches an unmodified DNP3 endpoint.
- ACK precedes its matching RESPONSE when required.
- SELECT RESPONSE precedes OPERATE.
- generations never cross.
- timeout and fail-open paths do not corrupt traffic.

Leakage features at the protected-link observer:

- Ethernet length
- IP length if visible
- TCP payload length if visible
- direction
- packet or cell count
- interarrival time
- burst length
- transaction duration
- TCP flags
- fragmentation and segment count
- total bytes

Use ablations that match implemented features. Candidate set:

1. unprotected
2. size only
3. Defense 1 only
4. Defense 2 only
5. Defense 3 only
6. unified timing only
7. Defense 4 without filler
8. full bounded Defense 4 profile

Report accuracy, balanced accuracy where classes are unequal, ROC-AUC where appropriate, mutual information estimates with caveats, confidence intervals, cross-run generalization, and cross-device generalization where data exists. Do not report only separate size and timing results. Include a joint attacker using all observable features.

Performance and safety metrics:

- added latency and jitter
- deadline miss rate
- residual drain offset
- packet loss and reorder
- retransmissions and resets
- DNP3 timeout and SBO failure rate
- throughput
- queue occupancy
- recirculation load
- filler and bandwidth overhead
- Tofino compiler and Traffic Manager resources

### Work package I: implementation roadmap

Produce a dependency graph and phased plan with entry criteria, exit criteria, artifacts, tests, risks, and rollback for each phase.

At minimum separate:

0. Evidence reconciliation and frozen contract.
1. True READ and full SBO corpus using a controlled emulator.
2. Stripped Defense 2 resource baseline.
3. Unified Defense 1/2/3 release engine from one binary.
4. Live DNP3 parser, matching, generation, cleanup, and fail-open.
5. Bounded outer size states with encode/decode and byte-identical restoration.
6. One-switch protected-link topology.
7. READ/SBO mapping and any justified bounded filler template.
8. Joint size and timing integration.
9. Robustness, retransmission handling, and limited concurrency.
10. Full evaluation and paper-ready evidence package.

For each phase, identify which result can kill or simplify later work. Put high-information, low-cost experiments first.

## 8. Required deliverables

Create these files in a new feasibility-study directory. Use the repository's established documentation location if one exists.

1. `DEFENSE4_FEASIBILITY_REPORT.md`
   - Two-page executive summary.
   - Overall verdict: `GO`, `GO WITH CONSTRAINTS`, `NO-GO`, or `SPLIT DECISION`.
   - Verdict by subsystem.
   - Minimum viable Defense 4.
   - Larger forward-looking Defense 4 profile.
   - What must not be claimed yet.

2. `DEFENSE4_ARCHITECTURE_SPEC.md`
   - Threat model and supported envelope.
   - Testbed topology and port-role table.
   - READ and SBO state machines.
   - Packet roles and candidate outer format.
   - Timing modes, predicates, queue plan, and state table.
   - Control-plane versus data-plane responsibilities.
   - Failure, cleanup, and concurrency policy.
   - Mermaid diagrams where they clarify topology or state transitions.

3. `DEFENSE4_EVIDENCE_LEDGER.md`
   - Chronology.
   - Verified versus reported facts.
   - Conflicts and controlling source.
   - Code, commit, capture, log, and compiler references.
   - Negative evidence.

4. `DEFENSE4_IMPLEMENTATION_AND_TEST_PLAN.md`
   - Dependency-ordered milestones.
   - Microbenchmark specifications.
   - Functional and leakage test matrix.
   - Resource measurement plan.
   - Safety constraints and rollback.
   - Estimated effort ranges with assumptions.

5. `DEFENSE4_RISK_REGISTER.md`
   - Risk, cause, impact, likelihood, evidence, mitigation, kill criterion, and owner/work package.

6. Agent notes and any safe compile logs or microbenchmark artifacts in subdirectories. Keep speculative notes out of the final evidence ledger unless the lead validates them.

## 9. Required feasibility decisions

The final report must explicitly decide each of the following:

1. Can one Tofino-1 implement the two trusted boundaries needed for an outer padded representation on the current physical testbed?
2. Can the P4 pipeline add and later remove the proposed outer representation while restoring supported packets byte-for-byte?
3. What maximum READ and SBO sizes can a no-splitting first version support?
4. Is true cellization and reassembly feasible on Tofino-1, or should it remain future work?
5. Is bounded filler necessary for the agreed protection contract?
6. Can pktgen, clone, or recirculated templates produce safe transaction-bound filler without a controller fast path?
7. Can one queue bank support READ, SELECT, and OPERATE sequentially?
8. What is the exact concurrency limit and fail-open behavior?
9. Can one P4 binary reproduce Defense 1, Defense 2, and Defense 3 through configuration?
10. What anchor should Defense 4 use for RESPONSE release when the ACK is also delayed?
11. Can the system observe true ACK dequeue, or must it use a characterized logical `ack_gone`/scheduled-release reference?
12. What compiler and Traffic Manager resources remain after the stripped baseline?
13. Which requirements are proven, which need microbenchmarks, and which are incompatible with Tofino-1?
14. What is the smallest publishable and defensible Defense 4 contribution on this testbed?

## 10. Quality bar and stopping rule

Do not return a list of vague recommendations such as "investigate padding" or "test concurrency." Every unresolved item must name:

- the exact uncertainty
- why it matters
- the smallest experiment or inspection that resolves it
- required inputs and equipment
- measurable success and failure criteria
- expected resource output
- dependency on other work

Before finalizing, send the draft synthesis to the adversarial reviewer and at least one Tofino expert and one DNP3 expert. Resolve all high-severity objections or mark them openly as blockers.

The work is complete only when:

- the evidence chronology is internally consistent
- the protection contract is explicit
- the architecture maps to actual Tofino primitives
- the testbed topology is concrete
- every major hardware assumption has evidence or a named proof experiment
- resource claims are compiler-backed or clearly labeled estimates
- READ and full SBO are both modeled correctly
- physical-relay safety limits are preserved
- minimum, bounded, and future profiles are separated
- the next three implementation experiments are obvious and executable

## 11. Final response to me

When the files are complete, give me a concise synthesis containing:

1. The overall feasibility verdict.
2. The minimum Defense 4 architecture you recommend.
3. The three hardest blockers.
4. The next three experiments in order.
5. The strongest claim the current evidence supports.
6. The claim that must not yet appear in the paper.
7. Files created or changed and any compile or hardware actions performed.

Do not claim that Defense 4 has been implemented merely because Defense 1, Defense 2, or the 128-byte size microbenchmark exists. Defense 4 is demonstrated only after a real READ and a real full SELECT-to-OPERATE SBO flow traverse the same bounded implementation, preserve endpoint behavior, and satisfy the declared observer-visible size and timing contract.
