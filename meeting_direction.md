MASTER RESEARCH DIRECTION PROMPT

Project: DNP3 packet-size and timing obfuscation using a Tofino programmable switch
Primarytext
MASTER RESEARCH DIRECTION PROMPT

Project: DNP3 packet-size and timing obfuscation using a Tofino programmable switch
Primary advisor: Dr. Hui Lin
Current implementation focus: Case A timing obfuscation
Primary physical device: SEL-751
Reference implementation paper: ditto: WAN Traffic Obfuscation at Line Rate

Read this entire instruction before modifying code, running experiments, or touching hardware.

This prompt defines the project terminology, current research direction, scientific intent, implementation order, evidence requirements, hardware gates, and reporting rules.

Do not reinterpret or rename the cases.

======================================================================
1. NON-NEGOTIABLE TERMINOLOGY
======================================================================

There are two DEVICE TRAFFIC CASES.

They are not two defense mechanisms.

----------------------------------------------------------------------
CASE A: SEPARATE PURE ACK AND DNP3 RESPONSE
----------------------------------------------------------------------

Primary device:

    SEL-751

Observed packet structure:

    DNP3 request
        ↓
    pure TCP ACK
        ↓
    DNP3 application response

The pure TCP ACK and DNP3 response are two separate packets.

This is the current research scope.

The ACK-to-response timing can be measured for this case.

The term CLRT may be used only for this separate-ACK case when referring
to the Formby cross-layer response-time feature.

Case A contains two defenses.

CASE A, DEFENSE 1:

    Delay the pure TCP ACK.

Native:

    request → ACK ───────── response

Defended:

    request ───────── ACK → response

Required behavior:

    - identify the matching pure TCP ACK;
    - delay that ACK;
    - keep the response close to its natural readiness time;
    - release the ACK before the response;
    - reduce the visible ACK-to-response gap;
    - minimize additional request-to-response latency.

CASE A, DEFENSE 2:

    Forward the pure ACK and delay the DNP3 response.

Native:

    request → ACK ───── response

Defended:

    request → ACK ───────────────── response

Required behavior:

    - identify and forward the matching pure TCP ACK immediately;
    - record the ACK timing or assign the transaction to a timing slot;
    - delay the response;
    - release the response according to a defensible timing policy;
    - increase or normalize the ACK-to-response gap;
    - quantify all added response latency.

Never call Defense 2 “Case B.”

----------------------------------------------------------------------
CASE B: COMBINED ACK-BEARING DNP3 RESPONSE
----------------------------------------------------------------------

Devices:

    AB1400
    ION7550

Observed packet structure:

    DNP3 request
        ↓
    one packet containing:
        TCP ACK
        DNP3 response

There is no standalone pure TCP ACK.

Therefore:

    - CLRT does not apply;
    - the ACK cannot be independently held;
    - the ACK cannot be forwarded before the response;
    - the complete ACK-bearing response packet would need to be controlled;
    - the proper timing measurement is request-to-response timing.

Case B is OUT OF SCOPE for the current implementation phase.

Do not implement Case B now.

Do not synthesize a standalone TCP ACK.

Do not silently mix AB1400 or ION7550 traffic into the Case A analysis.

Do not use the term CLRT for AB1400 or ION7550 combined-response traffic.

======================================================================
2. CURRENT RESEARCH SCOPE
======================================================================

Focus only on Case A.

The immediate research questions are:

    1. Can the Tofino reduce the SEL-751 ACK-to-response timing by
       delaying the pure ACK?

    2. Can the Tofino increase or normalize the SEL-751
       ACK-to-response timing by delaying the response?

    3. Can a Traffic Manager queue and scheduling mechanism provide a
       more defensible and load-stable timing policy than repeated
       recirculation?

    4. Can the timing defense operate on a physical SEL-751 without
       modifying the relay, master application, TCP stack, or DNP3
       protocol?

    5. How much operational overhead is introduced in latency,
       jitter, packet loss, reordering, internal bandwidth, ports, and
       switch resources?

The larger paper has two technical components:

    PART 1: Packet-size obfuscation
    PART 2: Timing obfuscation

Do not combine all mechanisms into one P4 binary until the timing design
and resource costs are understood.

======================================================================
3. SCIENTIFIC INTENT
======================================================================

The attacker is a passive observer on a protected WAN or network link.

The attacker may observe:

    - packet timestamps;
    - packet sizes;
    - packet directions;
    - ACK mode;
    - traffic volume;
    - encrypted packet metadata.

The attacker cannot read the encrypted DNP3 payload.

The defense must:

    - operate inline;
    - require no modification to the SEL-751;
    - require no modification to the DNP3 master;
    - preserve valid TCP behavior;
    - preserve the DNP3 payload byte-for-byte;
    - preserve ACK-before-response ordering;
    - fail open on ambiguous traffic;
    - minimize operational impact;
    - provide evidence that timing features are reduced or controlled.

Do not claim that all fingerprinting is defeated.

The current work targets specific packet-size and timing features.

Residual features may include:

    - request-to-ACK timing;
    - request-to-response timing;
    - ACK mode;
    - packet size;
    - packet count;
    - direction;
    - defense-specific timing patterns.

Every claim must state exactly which feature was evaluated.

======================================================================
4. EXISTING WORK THAT MUST BE PRESERVED
======================================================================

Begin by auditing the repository.

Do not assume exact paths, branches, tags, hashes, program names, switch
state, or topology.

Verify all of them.

There is an existing Tofino recirculation implementation for Case A,
Defense 1.

It has already demonstrated that:

    - the matching pure ACK can be retained in the Tofino;
    - the response arrival can trigger ACK release;
    - the ACK can leave before the response;
    - the ACK-to-response gap can be reduced to a small hardware guard;
    - DNP3 response bytes can remain unchanged.

There may be frozen commits and tags such as:

    bf4acdff
    ack-delay-caseA-c3-pass
    e6c2280

Do not rely on these names without verifying the repository.

The existing recirculation implementation is a valuable feasibility
baseline.

Do not:

    - delete it;
    - overwrite its evidence;
    - rewrite its history;
    - rename it as the final queue design;
    - claim it is useless;
    - hide its limitations.

Create new files or a new branch for the queue-based design.

The recirculation implementation must remain available for comparison.

======================================================================
5. REQUIRED SOURCE-GROUNDING
======================================================================

Before proposing the queue design, read and document the following
sources.

----------------------------------------------------------------------
A. DITTO PAPER
----------------------------------------------------------------------

Required paper:

    ditto: WAN Traffic Obfuscation at Line Rate

Read the complete paper.

Give special attention to:

    - the traffic pattern definition;
    - packet-size pattern computation;
    - Traffic Manager architecture;
    - priority queues;
    - round-robin scheduling;
    - real versus chaff packet queues;
    - loopback-based two-stage queueing;
    - rate configuration;
    - recirculation;
    - resource use;
    - timing measurements;
    - delay and reordering;
    - performance under load;
    - limitations of current switch shapers.

Create a source map containing:

    - claim;
    - paper section;
    - page;
    - exact supporting passage or accurate paraphrase;
    - relevance to the DNP3 design.

Do not claim that Ditto provides exact deterministic per-packet delay.

The paper states that switch shaping rates can be correct only on average
and may exhibit bursts.

Therefore, queue timing must be measured on our hardware.

----------------------------------------------------------------------
B. FORMBY DEVICE-FINGERPRINTING PAPER
----------------------------------------------------------------------

Locate and read the Georgia Tech/Formby paper.

Document:

    - the exact CLRT definition;
    - the separate pure-ACK assumption;
    - packet matching rules;
    - feature extraction;
    - classifier design;
    - measurement window;
    - device population;
    - limitations;
    - what happens when ACK and response are combined.

Do not infer these details from memory.

Cite the paper precisely in all research notes and paper drafts.

----------------------------------------------------------------------
C. TOFINO AND TNA DOCUMENTATION
----------------------------------------------------------------------

Use official documentation where available.

Verify:

    - Traffic Manager queue capabilities;
    - queue priorities;
    - round-robin or scheduling capabilities;
    - queue shaping;
    - port and queue limits;
    - loopback behavior;
    - recirculation behavior;
    - timestamp availability;
    - ingress and egress register separation;
    - stage and PHV constraints;
    - supported BF-RT operations;
    - installed SDE and compiler versions.

Do not invent undocumented hardware behavior.

If documentation is unavailable, label the item as an unknown and design
a microbenchmark.

----------------------------------------------------------------------
D. CURRENT REPOSITORY EVIDENCE
----------------------------------------------------------------------

Read:

    - current P4 programs;
    - setup scripts;
    - control-plane scripts;
    - queue configuration;
    - experiment notes;
    - PCAP analyses;
    - resource reports;
    - test cases;
    - phase status;
    - manifests;
    - tagged hardware evidence;
    - paper drafts.

Distinguish:

    - measured facts;
    - code behavior;
    - intended behavior;
    - assumptions;
    - unresolved questions.

======================================================================
6. RESEARCH AND VERIFICATION RULES
======================================================================

When research is needed:

    - use primary sources;
    - use official documentation;
    - use the original paper;
    - use the project’s actual code and logs;
    - cite the source;
    - record the date and version.

Do not:

    - use an unsourced blog as the main authority;
    - invent a queue feature;
    - invent a compiler limitation;
    - invent a timing target;
    - invent a hardware topology;
    - assume the current switch program;
    - assume a port is available;
    - assume a device IP address;
    - assume the SEL-751 configuration;
    - assume the queue is deterministic;
    - assume a result from a graph without checking the data.

When evidence conflicts:

    1. preserve both pieces of evidence;
    2. identify the conflict;
    3. determine which source is authoritative;
    4. run a controlled experiment where needed;
    5. report the uncertainty.

Maintain an ASSUMPTIONS_AND_UNKNOWNS.md file.

Every assumption must have:

    - description;
    - why it matters;
    - evidence;
    - validation method;
    - current status.

======================================================================
7. DEVELOPMENT AND EXPERIMENT ORDER
======================================================================

Follow this order.

Do not skip gates.

======================================================================
PHASE 0: REPOSITORY AND HARDWARE AUDIT
======================================================================

No code changes.

No switch changes.

Tasks:

    1. Identify the active branch.
    2. Record git status.
    3. Identify tagged Case A evidence.
    4. Identify current recirculation programs.
    5. Identify any existing queue experiments.
    6. Identify the current paper or Overleaf source.
    7. Identify all SEL-751, AB1400, and ION7550 captures.
    8. Identify current switch, Hulk, Vision, and Netronome documentation.
    9. Verify the current switch program.
    10. Verify whether any hardware process is running.
    11. Verify installed SDE and compiler versions.
    12. Verify the actual available ports and cables.
    13. Identify the rollback procedure.

Required output:

    CURRENT_STATE_AUDIT.md

It must include:

    - what exists;
    - what is proven;
    - what is unproven;
    - what is stale;
    - what is safe to change;
    - what must remain frozen;
    - next off-switch action.

Stop and report before hardware work.

======================================================================
PHASE 1: PAPER AND LITERATURE FOUNDATION
======================================================================

Writing starts now and continues throughout the project.

Tasks:

    1. Verify or create the paper repository.
    2. Use the current agreed IEEE double-column format.
    3. Create the paper section structure.
    4. Add a related-work source map.
    5. Add a terminology section.
    6. Add a trace-analysis section.
    7. Add the two Case A defenses.
    8. Add a recirculation baseline subsection.
    9. Add a Ditto-inspired queue design subsection.
    10. Add explicit open questions and placeholder experiments.

If direct Overleaf access is unavailable:

    - edit the local LaTeX source;
    - create a synchronization note;
    - do not claim to have edited Overleaf.

Use simple, precise writing.

Avoid inflated claims.

Preferred language:

    “The experiment demonstrates...”
    “The evidence supports...”
    “This remains unproven...”
    “The result applies to...”

Avoid:

    “The fingerprint is erased.”
    “The defense defeats all classifiers.”
    “The queue is deterministic.”
    “The implementation has no overhead.”

======================================================================
PHASE 2: RECONSTRUCT DITTO’S QUEUE DESIGN
======================================================================

Do not write P4 yet.

Produce:

    DITTO_QUEUE_RECONSTRUCTION.md

It must explain:

    - what a Ditto pattern is;
    - how pattern states are chosen;
    - how real packets are assigned to pattern states;
    - why each state has real and chaff queues;
    - how priority scheduling works;
    - how round-robin scheduling works;
    - how the two-stage hierarchy is approximated;
    - why loopback ports are used;
    - which packets use recirculation;
    - what is performed in ingress;
    - what is performed in the Traffic Manager;
    - what is performed in egress;
    - how rates are configured;
    - what Ditto measured;
    - what limitations Ditto reported.

Then produce:

    DITTO_TO_DNP3_MAPPING.md

For every Ditto mechanism, state:

    - directly reusable;
    - reusable with modification;
    - unnecessary;
    - unsuitable;
    - unresolved.

Do not blindly implement the complete Ditto system.

The initial goal is timing control for DNP3 Case A, not full WAN volume
anonymity.

======================================================================
PHASE 3: DEFINE THE DNP3 QUEUE RESEARCH QUESTIONS
======================================================================

The queue design must answer these questions before implementation.

----------------------------------------------------------------------
QUESTION 1: DEFENSE 1 EVENT VERSUS SCHEDULE
----------------------------------------------------------------------

Defense 1 is event-driven:

    hold ACK
    response arrives
    release ACK
    release response

Ditto is schedule-driven:

    packet leaves in a predefined queue slot

Determine how these can be combined.

Study at least these alternatives:

    A. Hybrid event and queue design

       - recirculation preserves the ACK until response_seen;
       - after response_seen, ACK and response are assigned to controlled
         Traffic Manager slots;
       - queue controls final release timing.

    B. Queue-resident ACK with response-triggered eligibility

       - ACK is placed into a controlled queue;
       - response event changes release eligibility;
       - verify whether Tofino hardware can support this safely.

    C. Adjacent-slot release

       - ACK and response are released in consecutive pattern slots;
       - preserve ACK-before-response ordering;
       - quantify the added delay.

Do not select one without hardware evidence and documentation support.

----------------------------------------------------------------------
QUESTION 2: DEFENSE 2 TARGET OR PATTERN
----------------------------------------------------------------------

Defense 2 forwards the ACK and delays the response.

The current fixed target is a calibration result, not the final policy.

Research these alternatives:

    A. Fixed common target
    B. Common bounded target distribution
    C. Repeating Ditto-style timing pattern
    D. Next-valid-slot scheduling
    E. Load-aware pattern with a fixed public policy

For each alternative, evaluate:

    - security rationale;
    - added latency;
    - detectability;
    - queue requirements;
    - implementation complexity;
    - load sensitivity;
    - TCP safety;
    - DNP3 operational impact;
    - classifier performance.

Do not select a target based only on:

    “The slowest response was 40 ms, so use 60 ms.”

A final target or pattern must be defensible using:

    - physical SEL-751 timing distribution;
    - high-percentile native readiness;
    - DNP3 operational constraints;
    - TCP retransmission behavior;
    - queue scheduling precision;
    - latency budget;
    - classifier performance;
    - a device-independent policy;
    - related-work principles.

======================================================================
PHASE 4: TRAFFIC MANAGER MICROBENCHMARK
======================================================================

Build the smallest possible queue experiment before modifying the full
DNP3 program.

Create a separate P4 program.

Do not add DNP3 parsing unless required for packet marking.

Initial packet classes:

    - normal packet;
    - delayed packet;
    - optional test chaff packet.

Initial queues:

    - normal queue;
    - shaped or delayed queue.

Possible later queues:

    - real high-priority queue;
    - chaff low-priority queue;
    - round-robin output queues.

Measure:

    - configured queue rate;
    - actual queue rate;
    - packet residence time;
    - output inter-packet timing;
    - jitter;
    - queue depth;
    - queue counters;
    - packet loss;
    - packet ordering;
    - burst behavior;
    - queue drain behavior;
    - first-packet behavior;
    - sparse-packet behavior;
    - background-load sensitivity;
    - packet-size sensitivity;
    - port and loopback use;
    - internal bandwidth.

Test conditions:

    1. One isolated packet.
    2. One packet every 20 ms.
    3. One packet every 10 ms.
    4. One packet every 2 ms.
    5. Small bursts.
    6. Mixed packet sizes.
    7. No background traffic.
    8. Low background traffic.
    9. Moderate background traffic.
    10. High background traffic.

Compare directly against the existing recirculation implementation.

Required comparison:

    - mean delay;
    - median delay;
    - standard deviation;
    - percentiles;
    - worst-case delay;
    - load sensitivity;
    - packet loss;
    - reordering;
    - internal resource cost;
    - implementation complexity.

Do not claim the queue is better before this comparison is complete.

======================================================================
PHASE 5: PHYSICAL SEL-751 DIRECT CONNECTIVITY
======================================================================

This phase may proceed while the queue microbenchmark is being developed,
but hardware changes remain gated.

The objective is to stop relying only on replayed traffic.

First connect the SEL-751 through the normal laboratory Ethernet switch.

Do not initially place the Tofino inline.

Do not change the SEL-751 IP address unless Dr. Lin explicitly approves
and it is necessary.

Use Hulk or Vision as the master after verifying the actual lab topology.

Tasks:

    1. Identify the SEL-751 IP address.
    2. Identify the subnet mask.
    3. Identify the DNP3 TCP port.
    4. Identify the DNP3 outstation address.
    5. Identify the required master address.
    6. Configure the master into the same subnet.
    7. Confirm Layer-2 and Layer-3 reachability.
    8. Confirm a TCP connection.
    9. Run only safe Class-0 READ polling.
    10. Capture the native transaction.
    11. Verify the separate pure-ACK behavior.
    12. Measure the physical device timing distribution.
    13. Record response sizes.
    14. Record TCP options and ACK behavior.
    15. Record all device settings used.

Do not issue:

    - SELECT;
    - OPERATE;
    - DIRECT OPERATE;
    - output control;
    - configuration write;
    - device restart;
    - unsolicited configuration change.

If communication does not work:

    - stop;
    - preserve evidence;
    - document the exact failure;
    - contact Dr. Lin early;
    - do not spend several days making unsupported changes.

Required output:

    SEL751_DIRECT_CONNECTIVITY_REPORT.md

======================================================================
PHASE 6: QUEUE-BASED CASE A, DEFENSE 1
======================================================================

Proceed only after:

    - the queue microbenchmark is understood;
    - the physical SEL-751 baseline is available or the user explicitly
      authorizes replay-based development;
    - the design is documented;
    - the program fits locally;
    - a hardware window is authorized.

Requirements:

    - exact TCP flag qualification;
    - expected ACK-number matching;
    - one outstanding transaction initially;
    - no FIN, RST, keepalive, duplicate ACK, or window-update admission;
    - response matching;
    - ACK-before-response ordering;
    - complete transaction cleanup;
    - fail-open on ambiguity;
    - byte preservation;
    - no cold reload between transactions;
    - zero stale state.

The queue should control the final release pattern.

The recirculation implementation may remain as:

    - the event detector;
    - the packet-retention mechanism;
    - the comparison baseline.

Do not force a pure queue-only design if the hardware cannot safely link
response arrival to ACK eligibility.

A hybrid mechanism is acceptable if:

    - its role is explicit;
    - timing is controlled by the queue;
    - recirculation load is measured;
    - the design is reproducible;
    - the scientific argument is defensible.

======================================================================
PHASE 7: QUEUE-BASED CASE A, DEFENSE 2
======================================================================

Proceed only after Defense 1 queue behavior is understood.

Required behavior:

    - forward the matching pure TCP ACK immediately;
    - classify the later DNP3 response;
    - assign the response to the selected timing pattern;
    - release the response in the correct slot or at the selected target;
    - preserve bytes;
    - clear transaction state;
    - fail open safely.

Evaluate at least:

    - fixed target for calibration;
    - one common bounded policy;
    - one Ditto-style repeating schedule.

Do not allow the target to depend on:

    - SEL-751 identity;
    - source IP as a device label;
    - response size;
    - native response timing;
    - packet-capture source;
    - transaction number in a device-specific sequence.

The policy must be common and device-independent.

======================================================================
PHASE 8: RECIRCULATION VERSUS QUEUE EVALUATION
======================================================================

Compare:

    1. Native traffic.
    2. Defense 1 using recirculation.
    3. Defense 1 using queue or hybrid queue.
    4. Defense 2 using recirculation.
    5. Defense 2 using queue scheduling.

Evaluate under:

    - idle switch;
    - low load;
    - moderate load;
    - high load;
    - mixed packet sizes;
    - long continuous operation.

Metrics:

    - ACK-to-response timing;
    - request-to-ACK timing;
    - request-to-response timing;
    - added response latency;
    - jitter;
    - deadline or slot error;
    - retransmissions;
    - resets;
    - packet loss;
    - duplicates;
    - reordering;
    - payload identity;
    - queue occupancy;
    - recirculation passes;
    - internal bandwidth;
    - switch stages;
    - SRAM;
    - TCAM;
    - stateful ALUs;
    - parser rows;
    - port consumption;
    - power estimate where available.

The result must answer:

    - Which mechanism is more stable under load?
    - Which mechanism adds less operational latency?
    - Which mechanism is easier to justify?
    - Which mechanism uses fewer switch resources?
    - Which mechanism scales better?
    - Does either mechanism create a new timing fingerprint?

======================================================================
PHASE 9: CLASSIFIER AND SECURITY EVALUATION
======================================================================

For separate-ACK SEL-751 traffic, evaluate:

    - native ACK-to-response timing;
    - defended ACK-to-response timing;
    - request-to-ACK timing;
    - request-to-response timing;
    - packet size;
    - ACK mode;
    - combined feature sets.

Do not evaluate only a static native template.

Include an adaptive attacker trained on defended data.

Use grouped splits by:

    - hardware run;
    - TCP connection;
    - session;
    - physical experiment;
    - capture source.

Do not randomly split transactions from the same session across training
and testing.

Report:

    - AUROC;
    - balanced accuracy;
    - macro precision;
    - macro recall;
    - confusion matrix;
    - confidence intervals;
    - independent hardware runs;
    - number of classifier resamples.

Do not call AUROC 0.57 “chance” when its confidence interval is above
0.5.

Use:

    - near-chance residual separability;
    - weak residual separability;
    - reduced separability.

======================================================================
10. HARDWARE AUTHORIZATION RULE
======================================================================

Local code inspection, documentation, reference models, tests, and local
compilation are authorized.

Do not touch the shared Tofino switch without explicit user authorization
for the current program version and current experiment window.

A previous GO does not apply to a modified P4 source.

Before requesting GO, provide:

    - exact source hash;
    - commit hash;
    - local compiler result;
    - stage and resource report;
    - exact switch commands;
    - expected port use;
    - expected Traffic Manager changes;
    - current program snapshot plan;
    - rollback commands;
    - Hulk and Vision cleanup plan;
    - stop conditions.

After every hardware experiment:

    - restore the co-resident program;
    - restore ports;
    - restore queue configuration;
    - restore loopback;
    - restore NetworkManager;
    - stop all experiment processes;
    - verify normal forwarding;
    - record final state.

Never leave an experiment loaded without explicit instruction.

======================================================================
11. VERSION CONTROL AND EVIDENCE
======================================================================

Use a dedicated branch for the Ditto-inspired queue work.

Do not modify frozen evidence tags.

Suggested branch:

    research/caseA-ditto-queue

Verify naming conventions before creating it.

Commit by gate.

Do not combine unrelated changes.

For each hardware result, store:

    - PCAP;
    - parsed CSV;
    - JSON telemetry;
    - compiler logs;
    - resource reports;
    - BF-RT logs;
    - queue counters;
    - switch configuration;
    - topology;
    - host commands;
    - software versions;
    - git commit;
    - P4 hash;
    - experiment manifest;
    - SHA-256 manifest.

Separate:

    raw/
    processed/
    figures/
    logs/
    manifests/

Never modify raw evidence.

======================================================================
12. PAPER WRITING REQUIREMENTS
======================================================================

Writing runs in parallel with implementation.

Maintain these sections as living documents:

    - problem statement;
    - terminology;
    - trace analysis;
    - threat model;
    - Case A Defense 1;
    - Case A Defense 2;
    - software feasibility;
    - recirculation design;
    - Ditto-inspired queue design;
    - physical SEL-751 setup;
    - evaluation;
    - limitations;
    - related work.

Every result paragraph must state:

    - traffic source;
    - physical or replayed;
    - implementation version;
    - sample size;
    - measured metric;
    - central value;
    - spread;
    - safety result;
    - limitation.

Use precise device names:

    SEL-751
    AB1400
    ION7550

Do not use:

    device1
    device2

unless a synthetic profile is explicitly labeled.

Do not say:

    real physical SEL-751

when the experiment used captured SEL-751 payload replay.

Use:

    SEL-751 capture-derived live-TCP replay

for replay experiments.

Use:

    live physical SEL-751

only when the relay is physically connected.

======================================================================
13. WHAT NOT TO DO
======================================================================

Do not:

    - confuse Case A and Case B;
    - call Defense 2 Case B;
    - implement Case B now;
    - call combined response timing CLRT;
    - synthesize TCP ACKs;
    - modify the Linux kernel;
    - continue OS-specific ACK manipulation;
    - scrap the recirculation baseline;
    - claim queue timing is deterministic without measurement;
    - copy the complete Ditto design without justification;
    - add full chaff generation before the minimal timing design works;
    - choose a timing target arbitrarily;
    - claim zero overhead;
    - claim all fingerprinting is defeated;
    - claim physical-device validation from replay;
    - modify the SEL-751 IP without approval;
    - issue DNP3 control commands;
    - use an SDN controller unless a specific need is proven;
    - make per-packet control-plane decisions;
    - touch the switch without GO;
    - edit frozen evidence;
    - omit failed experiments;
    - hide timing offsets;
    - hide packet loss;
    - hide resource overuse;
    - treat MAXPASS as normal release;
    - treat cold reloads as continuous operation;
    - invent citations;
    - invent hardware facts;
    - store credentials;
    - add AI attribution to commits;
    - make commits in Philip’s name without confirming git identity.

======================================================================
14. STOP CONDITIONS
======================================================================

Stop and report when:

    - the source definition is ambiguous;
    - the Ditto paper does not support an assumed mechanism;
    - required hardware documentation is missing;
    - the compiler exceeds the stage limit;
    - the queue cannot provide the assumed scheduling behavior;
    - a packet is reordered incorrectly;
    - the response leaves before the ACK;
    - TCP retransmissions appear;
    - the TCP connection resets;
    - DNP3 bytes change;
    - state does not return to idle;
    - queue occupancy grows continuously;
    - packet loss occurs;
    - loopback traffic escapes;
    - a background load changes timing unexpectedly;
    - the physical SEL-751 configuration is uncertain;
    - a requested hardware action would displace another experiment;
    - rollback is not ready.

Do not patch several mechanisms during the same failed experiment.

Preserve evidence first.

======================================================================
15. REQUIRED STATUS REPORT FORMAT
======================================================================

At the end of every gate, report:

OPERATION REVIEW

    - exact files changed;
    - exact commands run;
    - exact sources consulted;
    - exact hardware touched;
    - exact configuration changes.

MEASURED RESULTS

    - measured values;
    - sample size;
    - variation;
    - confidence interval where applicable.

INFERENCES

    - interpretation;
    - supporting evidence;
    - remaining uncertainty.

TRANSPORT SAFETY

    - retransmissions;
    - resets;
    - loss;
    - duplicates;
    - ordering;
    - byte identity.

TOFINO RESOURCES

    - ingress stages;
    - egress stages;
    - tables;
    - SRAM;
    - TCAM;
    - stateful ALUs;
    - parser resources;
    - queue use;
    - loopback ports;
    - recirculation bandwidth.

CURRENT STATUS

    - PASS;
    - PASS_WITH_LIMITATION;
    - IN_PROGRESS;
    - BLOCKED;
    - FAIL;
    - NOT_YET_PROVEN.

NEXT GATE

    - one precise next action;
    - required authorization;
    - stop conditions.

Do not present a broad menu unless a real architectural decision is
required.

======================================================================
16. REQUIRED DELIVERABLES
======================================================================

Create or update, using the repository’s actual structure:

    CURRENT_STATE_AUDIT.md
    ASSUMPTIONS_AND_UNKNOWNS.md
    DITTO_QUEUE_RECONSTRUCTION.md
    DITTO_TO_DNP3_MAPPING.md
    CASE_A_TERMINOLOGY.md
    CASE_A_QUEUE_DESIGN.md
    QUEUE_MICROBENCH_PLAN.md
    QUEUE_VS_RECIRC_EVALUATION_PLAN.md
    SEL751_DIRECT_CONNECTIVITY_PLAN.md
    SEL751_DIRECT_CONNECTIVITY_REPORT.md
    PAPER_OUTLINE.md
    phase_status.json
    WORKING_NOTES.md
    RESUME_STATE.md

Add tests for:

    - packet classification;
    - expected ACK matching;
    - state transitions;
    - ACK-before-response ordering;
    - fail-open behavior;
    - transaction cleanup;
    - timing-slot selection;
    - target-pattern selection;
    - stale-state rejection;
    - queue assignment;
    - resource-fit regression.

======================================================================
17. FIRST ACTION
======================================================================

Start with PHASE 0 only.

Do not modify code.

Do not touch the switch.

Do not create a queue implementation yet.

Return:

    1. The verified repository state.
    2. The verified terminology used in the current files.
    3. Every file that incorrectly calls Defense 2 “Case B.”
    4. Every file that incorrectly uses CLRT for combined-response traffic.
    5. The frozen recirculation baseline and its evidence.
    6. Existing queue, Traffic Manager, or Ditto-related code.
    7. The actual current hardware and topology documentation.
    8. The current paper or Overleaf source status.
    9. A list of unsupported assumptions currently present.
    10. The proposed file-by-file plan for PHASE 1 and PHASE 2.
    11. A statement of what requires explicit hardware authorization.

The first response must clearly state:

    - no code was changed;
    - no switch was touched;
    - no hardware assumption was treated as fact;
    - all findings came from verified repository or source evidence.

The project direction is:

    Focus on Case A using the physical SEL-751.
    Preserve the working recirculation implementation.
    Study and adapt Ditto’s queue scheduling mechanism.
    Develop a defensible timing pattern with measured overhead.
    Compare queue-based timing against recirculation under load.
    Begin and maintain the paper now.
    Leave Case B for a later phase.