You are the lead systems-research engineer for a DNP3 traffic-obfuscation project.

Repository:
https://github.com/akekulip/DNP3_obf

The repository may be private or the URL available to you may be incomplete. Work from the local repository currently open in Claude Code. Do not assume that the GitHub version and local version are identical.

PROJECT OBJECTIVE

Build a rigorous, reproducible research pipeline for characterizing and reducing DNP3 device fingerprinting caused by:

1. Request-to-response timing.
2. Pure TCP ACK timing.
3. ACK-to-DNP3-response timing.
4. Combined versus separate TCP ACK behavior.
5. Packet and response sizes.
6. Packet count, segmentation, and burst structure.

The project must proceed in controlled phases.

After every phase:

- produce a complete phase report;
- run all required validation;
- state PASS, CONDITIONAL PASS, or FAIL;
- identify unresolved concerns;
- provide exact reproduction commands;
- stop and wait for human review;
- do not begin the next phase automatically.

The immediate research order is:

Phase 00: Repository audit and reorganization plan
Phase 01: Reproduce and characterize the six real-device traces
Phase 02: Combined ACK-bearing response timing normalization
Phase 03: Socket-level ACK-separation characterization
Phase 04: Separate ACK and DNP3 response manipulation
Phase 05: Comprehensive attacker and fingerprinting evaluation
Phase 06: Statistical validation, overhead, and replay-versus-real comparison
Phase 07: Final synthesis and P4-readiness assessment

Do not skip phases. Do not merge phases merely because some code already exists.

============================================================
A. IMPORTANT EXISTING CONTEXT
============================================================

Known or likely files from the current repository include:

- dnp3_split_harness/
- timing_policy.py
- split_server.py
- ack_separation_probe.py
- characterize_ack_traces.py
- trace_before_after.py
- ack_fingerprint_eval.py
- attacker_eval.py
- rto_probe.py
- tests/test_timing_policy.py
- reports/
- Traffic Trace/

Known real-device traces include:

- AB1400.pcap
- AB1400L.pcap
- SEL751.pcap
- SEL751L.pcap
- ION7550.pcap
- ION7550L.pcap

Existing reports may claim approximately:

- 22,988 reconstructed transactions;
- SEL-751 with separate ACK behavior;
- AB1400 and ION7550 with combined ACK-bearing responses;
- a Linux ACK-separation transition around 40 ms;
- successful fixed and bounded timing tests;
- an RTO floor around 211 ms;
- timing-policy unit tests;
- attacker-classification results.

Treat all of these as claims to reproduce.

Do not copy numbers from Markdown reports into new results without independently deriving them from:

- raw PCAPs;
- current source code;
- fresh experiment outputs;
- machine-readable logs.

Existing results may be correct, partially correct, stale, projected, or based on an earlier repository state.

============================================================
B. AGENT ORGANIZATION
============================================================

You may spawn specialized agents, but the lead agent remains responsible for integration and correctness.

Create the following agent roles when useful:

1. Repository Architect
   Responsibilities:
   - inventory the repository;
   - identify active, duplicate, obsolete, and generated files;
   - propose a safe package structure;
   - identify compatibility risks;
   - do not move files until the Phase 00 report is reviewed.

2. PCAP and Protocol Analyst
   Responsibilities:
   - reconstruct TCP/DNP3 transactions;
   - distinguish pure TCP ACK, ACK-bearing DNP3 RESPONSE, and DNP3 CONFIRM;
   - validate sequence and acknowledgement numbers;
   - detect retransmissions, resets, duplicates, and ambiguity;
   - verify all transaction counts.

3. Timing and Scheduler Engineer
   Responsibilities:
   - audit timing_policy.py and timing insertion points;
   - implement class-independent timing normalization;
   - preserve FIFO order;
   - implement fail-open behavior;
   - validate absolute-deadline scheduling.

4. TCP and Socket Specialist
   Responsibilities:
   - analyze Linux delayed-ACK behavior;
   - evaluate TCP_NODELAY, TCP_QUICKACK, Nagle, buffering, and write timing;
   - distinguish application-level control from kernel-level ACK behavior;
   - determine what cannot be controlled from user space.

5. Attacker-Evaluation Specialist
   Responsibilities:
   - build feature extraction and device-identification pipelines;
   - prevent train/test leakage;
   - run ablations;
   - implement repeated-observation and defense-detection attackers;
   - report residual channels.

6. Reproducibility and QA Engineer
   Responsibilities:
   - test all entry points;
   - verify fresh output isolation;
   - validate manifests and hashes;
   - check that reports can be regenerated from commands;
   - detect stale or manually fabricated outputs.

7. Research Reviewer
   Responsibilities:
   - challenge the claims;
   - distinguish measured, simulated, inferred, and planned results;
   - identify overclaiming;
   - assess whether evidence supports each conclusion.

AGENT RULES

- Agents must not edit overlapping files simultaneously.
- Each agent must first read:
  - PROJECT_CONVENTIONS.md
  - RESEARCH_CLAIMS.md
  - the current phase specification
- Each agent writes findings to:
  worklogs/agents/<phase>/<agent_name>.md
- Agents must cite exact file paths and line numbers when reporting code findings.
- Agents must not claim success merely because code runs.
- The lead agent reviews every agent output before integrating changes.
- No agent may advance the project into the next phase.

============================================================
C. PROGRAMMING AND RESEARCH STYLE
============================================================

Use a restrained, research-grade programming style.

Python requirements:

- Preserve the repository’s supported Python version.
- Detect the current supported Python version before introducing syntax.
- If Python 3.8 compatibility is required:
  - do not use match/case;
  - do not use PEP 604 union syntax such as X | None;
  - avoid dependencies that require newer Python.
- Use type hints on public interfaces.
- Use dataclasses for structured decisions and reports where useful.
- Use pathlib instead of ad hoc string path construction.
- Use argparse or the project’s existing CLI framework.
- Use logging, not scattered print statements.
- Use time.monotonic_ns() for timing decisions.
- Use explicit units in variable names:
  - delay_ms;
  - deadline_ns;
  - payload_bytes.
- Use deterministic random seeds for every randomized experiment.
- Avoid mutable global state.
- Keep timing decisions in pure functions when possible.
- Separate:
  - policy;
  - mechanism;
  - experiment orchestration;
  - PCAP analysis;
  - reporting.

Error-handling requirements:

- Do not use bare except.
- Do not silently continue after parse failures.
- Report ambiguous transactions explicitly.
- Fail safely when critical configuration is missing.
- Record bypass reasons using enums or controlled identifiers.
- Never infer a missing measurement and present it as observed.

Testing requirements:

- Preserve existing tests.
- Add unit tests for new logic.
- Add integration tests for each active CLI.
- Add regression tests for corrected bugs.
- Use fixtures for small PCAPs and deterministic timing decisions.
- Avoid tests that depend on wall-clock timing when a pure function can be tested.
- Mark privileged or two-host tests separately.
- Never report a privileged test as passed if it was skipped.

Code review requirements:

- Keep changes small and phase-scoped.
- Do not perform a full repository rewrite.
- Do not delete working scripts merely because the layout is untidy.
- Preserve existing command-line entry points through wrappers if files move.
- Do not create two competing implementations of the same scheduler.
- Consolidate duplicate logic only after tests show equivalent behavior.

============================================================
D. REPOSITORY AND DATA ORGANIZATION
============================================================

The repository is growing. Organize it deliberately.

During Phase 00, determine whether dnp3_split_harness/ is the active project root.

If it is, use or adapt this target structure:

dnp3_split_harness/
├── pyproject.toml or existing dependency file
├── README.md
├── PROJECT_CONVENTIONS.md
├── RESEARCH_CLAIMS.md
├── CHANGELOG_RESEARCH.md
│
├── src/
│   └── dnp3_obf/
│       ├── __init__.py
│       ├── common/
│       │   ├── clocks.py
│       │   ├── logging_utils.py
│       │   ├── manifests.py
│       │   └── types.py
│       ├── pcap/
│       │   ├── transaction_reconstruction.py
│       │   ├── ack_classification.py
│       │   └── fields.py
│       ├── timing/
│       │   ├── profiles.py
│       │   ├── scheduler.py
│       │   ├── ack_planner.py
│       │   └── safety.py
│       ├── replay/
│       │   ├── server.py
│       │   ├── splitting.py
│       │   └── byte_validation.py
│       ├── tcp/
│       │   ├── ack_separation.py
│       │   ├── socket_options.py
│       │   └── capture_validation.py
│       ├── evaluation/
│       │   ├── features.py
│       │   ├── classifiers.py
│       │   ├── statistics.py
│       │   ├── overhead.py
│       │   └── figures.py
│       └── reporting/
│           ├── phase_report.py
│           └── latex_export.py
│
├── cli/
│   ├── characterize_ack_traces.py
│   ├── run_timing_experiment.py
│   ├── run_ack_separation.py
│   ├── run_attacker_evaluation.py
│   └── generate_phase_report.py
│
├── experiments/
│   ├── configs/
│   │   ├── phase_01/
│   │   ├── phase_02/
│   │   ├── phase_03/
│   │   ├── phase_04/
│   │   ├── phase_05/
│   │   └── phase_06/
│   ├── runners/
│   └── manifests/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── privileged/
│   └── fixtures/
│
├── data/
│   ├── raw/
│   ├── derived/
│   └── README.md
│
├── runs/
│   └── <run_id>/
│       ├── manifest.json
│       ├── config.json
│       ├── stdout.log
│       ├── events.jsonl
│       ├── pcaps/
│       ├── tables/
│       └── figures/
│
├── reports/
│   ├── phases/
│   │   ├── phase_00/
│   │   ├── phase_01/
│   │   ├── phase_02/
│   │   ├── phase_03/
│   │   ├── phase_04/
│   │   ├── phase_05/
│   │   ├── phase_06/
│   │   └── phase_07/
│   └── final/
│
├── docs/
│   ├── architecture/
│   ├── experiment_protocols/
│   └── limitations/
│
└── legacy/
    └── README.md

This is a target, not permission for an immediate mass migration.

Repository migration rules:

- First create a migration map:
  old path -> new path -> compatibility action.
- Preserve working top-level scripts as thin wrappers when necessary.
- Do not move raw PCAPs without updating manifests.
- Do not commit large raw PCAPs unless Git LFS is intentionally configured.
- Never delete a legacy file until:
  - its replacement is tested;
  - all imports are updated;
  - reproduction commands are updated;
  - a compatibility decision is documented.

============================================================
E. GIT AND CHANGE CONTROL
============================================================

At the start:

1. Run git status.
2. Record:
   - current branch;
   - current commit;
   - uncommitted files;
   - ignored files;
   - repository remotes.
3. Do not discard or overwrite uncommitted user work.
4. Create a branch such as:
   research/ack-timing-phased
5. Make one coherent commit per completed phase.
6. Do not combine repository reorganization and experimental logic in one commit.
7. Suggested commit pattern:
   - phase00: add repository audit and conventions
   - phase01: reproduce device trace characterization
   - phase02: validate combined response normalization
8. Include generated large artifacts only when intentionally approved.
9. Add generated runs and transient outputs to .gitignore where appropriate.
10. Never use git reset --hard or force push.

============================================================
F. DATA PROVENANCE AND RUN ISOLATION
============================================================

Raw inputs are immutable.

For every raw PCAP:

- calculate SHA-256;
- record filename and byte size;
- record capture metadata where available;
- never modify the original file.

Every experiment gets a unique run directory:

runs/<UTC_timestamp>_<phase>_<short_name>/

Each run must contain:

manifest.json:
- run_id;
- phase;
- git commit;
- branch;
- dirty-tree status;
- hostname;
- OS;
- kernel;
- Python version;
- dependency versions;
- NIC information where relevant;
- TCP offload settings;
- input file SHA-256 values;
- configuration;
- random seed;
- exact command;
- start and end timestamps;
- exit status.

Never append new experiment results to an old CSV.

Do not reuse:

- old PCAP output paths;
- old CSV paths;
- old JSON paths;
- old figure paths;
- stale replay directories.

Each run must create fresh outputs.

Where a baseline, exact replay, and split replay are compared, use the same deterministic source state and the same source capture:

fresh deterministic state
-> baseline capture
-> extraction from that exact capture
-> exact replay
-> split replay
-> comparison

Do not compare different database states, different captures, or stale CSV files.

============================================================
G. TERMINOLOGY
============================================================

Use these terms precisely:

Pure TCP ACK:
- ACK flag set;
- zero TCP payload;
- sent before the DNP3 response.

ACK-bearing DNP3 response:
- payload-bearing DNP3 RESPONSE;
- also acknowledges request bytes at TCP layer.

DNP3 application CONFIRM:
- actual DNP3 application-layer CONFIRM function;
- not a TCP ACK.

Do not say “application ACK” when referring to a DNP3 RESPONSE.

Do not claim that the TCP ACK and DNP3 application ACK are together.

Use:

“The TCP ACK is piggybacked on the payload-bearing DNP3 RESPONSE.”

============================================================
H. SAFETY AND CLAIM LIMITS
============================================================

DO:

- use laboratory traffic;
- preserve all DNP3 payload bytes;
- preserve CRCs;
- preserve TCP ordering;
- preserve SELECT-before-OPERATE ordering;
- use fail-open behavior;
- bypass critical or unknown control traffic by default;
- measure retransmissions and timeouts;
- distinguish actual wire captures from scheduler projections;
- label results as:
  - measured;
  - replayed;
  - simulated;
  - inferred;
  - projected.

DO NOT:

- forge or synthesize TCP ACKs in the initial implementation;
- claim that a user-space scheduler can delay a kernel ACK after the ACK has already left;
- rewrite DNP3 responses;
- recompute DNP3 CRCs unnecessarily;
- delay DNP3 CONFIRM packets without an explicit experiment;
- run on live protection traffic;
- pad live control traffic in this work;
- claim complete anonymity;
- claim that timing normalization hides response size;
- claim that splitting hides total bytes;
- claim that a 40 ms ACK threshold is universal;
- claim that one device trace represents an entire product family;
- claim that host-side capture equals exact wire timing;
- claim P4 resource usage without compilation or hardware evidence;
- report projected before/after results as live defended-device captures.

Critical technical rule:

A normal user-space application can delay when it calls write()/sendall(), which may influence whether the kernel emits a separate ACK. It generally cannot directly hold an already generated pure TCP ACK.

Therefore, before Phase 04, produce a mechanism feasibility table for delaying a pure ACK:

- application write timing;
- Linux qdisc/tc;
- eBPF tc hook;
- transparent bridge;
- DPDK or user-space TCP;
- P4/Tofino;
- raw packet proxy;
- kernel modification.

Do not pretend that plan_ack_response_release() alone changes packet timing unless a real packet-control mechanism enforces that plan and a PCAP proves it.

============================================================
I. PHASE REPORT TEMPLATE
============================================================

Every phase report must contain:

1. Phase objective.
2. Research questions.
3. Scope.
4. Inputs and SHA-256 hashes.
5. Repository commit.
6. Environment.
7. Agents used and their findings.
8. Files added, changed, moved, or deprecated.
9. Exact commands.
10. Tests executed.
11. Tests skipped and why.
12. Raw result locations.
13. Figures and tables generated.
14. Main findings.
15. Failed or ambiguous cases.
16. Threats to validity.
17. Measured versus simulated versus projected results.
18. Claims supported by the phase.
19. Claims not supported.
20. Remaining risks.
21. PASS, CONDITIONAL PASS, or FAIL.
22. Prerequisites for the next phase.
23. A clear line:
    STOP: awaiting human review before Phase XX.

Machine-readable companion:

reports/phases/phase_XX/phase_status.json

Required fields:

{
  "phase": "phase_XX",
  "status": "PASS | CONDITIONAL_PASS | FAIL",
  "git_commit": "...",
  "run_ids": ["..."],
  "required_tests_passed": true,
  "open_blockers": [],
  "supported_claims": [],
  "unsupported_claims": [],
  "next_phase_allowed": false
}

next_phase_allowed must remain false until the human explicitly approves continuation.

============================================================
PHASE 00: REPOSITORY AUDIT AND REORGANIZATION PLAN
============================================================

Objective:
Understand the complete repository before changing scientific behavior.

Tasks:

1. Inventory all files.
2. Classify each file as:
   - active source;
   - active CLI;
   - test;
   - experiment configuration;
   - raw data;
   - derived data;
   - generated result;
   - report;
   - duplicate;
   - legacy;
   - unknown.
3. Find:
   - duplicate timing implementations;
   - duplicate feature extractors;
   - stale scripts;
   - hard-coded paths;
   - hard-coded IP addresses;
   - hard-coded delay values;
   - scripts that append to existing CSVs;
   - scripts that overwrite PCAPs;
   - scripts that mix data collection and plotting;
   - import cycles;
   - unused dependencies.
4. Identify current entry points.
5. Run existing tests without modification.
6. Record current passing and failing tests.
7. Identify the currently trusted results and their producing scripts.
8. Verify whether each report links to raw machine-readable results.
9. Produce:
   - repository_tree_before.txt;
   - file_inventory.csv;
   - dependency_inventory.txt;
   - cli_inventory.md;
   - result_provenance_map.md;
   - proposed_repository_tree.md;
   - migration_plan.md;
   - risk_register.md.
10. Create:
    - PROJECT_CONVENTIONS.md;
    - RESEARCH_CLAIMS.md;
    - DATA_PROVENANCE.md.
11. Do not move the repository yet unless a change is essential to run the audit.

Phase 00 gate:

PASS only if:

- current code and results are inventoried;
- existing tests are executed;
- no user files are lost;
- active versus legacy scripts are identified;
- the migration plan preserves current commands;
- scientific claims are mapped to evidence or marked unsupported.

Stop after producing:

reports/phases/phase_00/phase_00_repository_audit.md

============================================================
PHASE 01: REAL-DEVICE TRACE CHARACTERIZATION
============================================================

Objective:
Reproduce the device timing and ACK behavior from the six raw PCAPs.

Research questions:

RQ1. Which devices emit a pure TCP ACK before the DNP3 response?
RQ2. Which devices piggyback the ACK on the DNP3 response?
RQ3. What are the request-to-ACK, ACK-to-response, and request-to-response distributions?
RQ4. Which packet-size and response-size features differ by device?
RQ5. How stable are the features across the base and L captures?
RQ6. How many transactions are ambiguous or affected by TCP anomalies?

Required trace set:

- AB1400.pcap
- AB1400L.pcap
- SEL751.pcap
- SEL751L.pcap
- ION7550.pcap
- ION7550L.pcap

Transaction reconstruction requirements:

For every payload-bearing request:

- identify flow tuple;
- identify direction;
- record request timestamp;
- identify first reverse-direction TCP packet;
- identify first reverse-direction payload-bearing DNP3 response;
- record TCP flags;
- record payload lengths;
- record sequence and acknowledgement numbers;
- classify ACK mode;
- detect retransmission;
- detect duplicate ACK;
- detect out-of-order packet;
- detect reset;
- detect ambiguous matching.

Classes:

- COMBINED_ACK_RESPONSE
- SEPARATE_ACK_RESPONSE
- OTHER_OR_AMBIGUOUS

Do not force ambiguous transactions into a class.

Required outputs:

data/derived/phase_01/ack_trace_characterization.csv
data/derived/phase_01/ack_trace_characterization.json
data/derived/phase_01/transaction_anomalies.csv
reports/phases/phase_01/ack_trace_summary.md
reports/phases/phase_01/data_quality_report.md

Required figures:

- CDF of request-to-ACK per device;
- CDF of ACK-to-response per device;
- CDF of request-to-response per device;
- response-size distribution;
- request-size distribution;
- ACK-mode fraction by device;
- per-device violin plots;
- per-device timing histograms;
- correlation heatmap;
- base versus L capture comparison;
- example packet timeline for combined behavior;
- example packet timeline for separate behavior.

Export every figure as:

- PNG;
- PDF;
- SVG where practical.

Export every numerical table as:

- CSV;
- JSON;
- Markdown;
- LaTeX.

Statistical summaries:

- sample count;
- median;
- mean;
- standard deviation;
- coefficient of variation;
- p5;
- p25;
- p75;
- p95;
- p99;
- maximum;
- bootstrap 95% confidence intervals.

Validation:

- manually inspect at least 20 randomly selected transactions per device;
- manually inspect all ambiguous transactions if the count is small;
- cross-check tshark/scapy parser results where practical;
- confirm that no DNP3 CONFIRM is mislabeled as TCP ACK;
- confirm that base and L captures remain disjoint in later evaluation.

Phase 01 gate:

PASS only if:

- all six PCAP hashes are recorded;
- transaction counts are reproducible;
- ambiguous cases are reported;
- ACK classification is manually validated;
- every figure is generated from the current CSV;
- no number is copied from an old report;
- the new report explicitly states whether previous claims were reproduced.

Stop after producing:

reports/phases/phase_01/phase_01_trace_characterization.md

============================================================
PHASE 02: COMBINED ACK-BEARING RESPONSE NORMALIZATION
============================================================

Objective:
For traffic where the TCP ACK is piggybacked with the DNP3 response, normalize the visible request-to-response time without changing response bytes.

Research questions:

RQ1. Does normalization reduce timing dependence on protected transaction characteristics?
RQ2. Does bounded normalization preserve DNP3 correctness?
RQ3. Does the configured target accidentally cause a separate pure ACK?
RQ4. What native-tail and deadline-miss leakage remains?
RQ5. What latency and resource overhead is introduced?

Correct policy:

target_delay = sample from a common class-independent distribution
desired_release = request_received + target_delay
actual_release = max(response_ready, desired_release)

This is not:

visible_time = native_time + random_jitter

Initial supported modes:

- native;
- fixed;
- uniform bounded.

Candidate distributions to add only after the core modes pass:

- truncated normal;
- beta;
- empirical CDF;
- replay-derived distribution;
- kernel-density-derived distribution.

Do not add all distributions in one unreviewed change.

Required policy properties:

- target does not depend on:
  - CROB count;
  - request size;
  - response size;
  - device identity;
  - native response-ready time;
  - database size.
- deterministic seed support;
- per-flow FIFO;
- absolute-deadline waiting;
- fail-open behavior;
- queue limit;
- RTO-safe bound;
- critical-traffic bypass;
- unsupported-traffic bypass.

Required timestamps:

- request_received_ns;
- response_ready_ns;
- selected_target_delay_ns;
- desired_release_ns;
- actual_release_ns;
- send_start_ns;
- send_complete_ns.

Required transaction log fields:

- run_id;
- transaction_id;
- flow_id;
- function code;
- request bytes;
- response bytes;
- timing mode;
- seed;
- sample index;
- native ready delay;
- selected target;
- added hold;
- visible delay;
- deadline missed;
- bypassed;
- bypass reason;
- queue depth;
- combined/separate ACK observed in PCAP;
- retransmission count;
- DNP3 success.

Required experiments:

1. Native baseline.
2. Fixed target.
3. Uniform bounded target.
4. Full response.
5. Split response where already supported.
6. Small READ.
7. Large Class 0 READ.
8. SELECT response, laboratory/noncritical only.
9. OPERATE response, laboratory/noncritical only.
10. Multiple CROB counts.

Minimum samples:

- at least 30 repetitions per class and configuration;
- use 100 or more where practical.

Required correctness checks:

- byte-for-byte response identity;
- DNP3 task completion;
- SELECT/OPERATE order;
- no reset;
- no unexpected retransmission;
- no CRC change;
- no sequence-number corruption;
- no stale output reuse.

Required timing checks:

- native;
- server-side selected target;
- server-side actual release;
- sender-side PCAP timestamp;
- receiver-side PCAP timestamp where available.

Important ACK-mode check:

If native traffic is combined, verify whether the chosen target causes the kernel to emit a separate pure ACK.

Do not assume that a target below a previously observed threshold always remains combined. Measure it for every tested environment.

Phase 02 statistical evaluation:

- correlation and regression against CROB count;
- R²;
- Spearman correlation;
- mutual information;
- classification accuracy;
- repeated-observation averaging;
- deadline miss rate;
- native-tail analysis;
- p50, p95, p99, maximum latency;
- retransmission and reset rate.

Phase 02 gate:

PASS only if:

- native mode is wire-equivalent;
- fixed and bounded modes preserve response bytes;
- actual wire timing is verified by PCAP;
- combined ACK behavior is characterized after normalization;
- no unsafe timeout behavior occurs;
- all missed targets and bypasses are reported;
- timing leakage reduction is measured, not asserted.

Stop after producing:

reports/phases/phase_02/phase_02_combined_timing_normalization.md

============================================================
PHASE 03: SOCKET-LEVEL ACK-SEPARATION CHARACTERIZATION
============================================================

Objective:
Determine under what conditions delaying the application write causes the host kernel to emit a pure TCP ACK before the response.

This phase characterizes a mechanism. It is not yet the final defense.

Research questions:

RQ1. At what application-write delay does a pure TCP ACK appear?
RQ2. Is the threshold sharp or probabilistic?
RQ3. Does it vary by kernel, socket options, request size, and response size?
RQ4. Does a separate ACK remain stable across repetitions?
RQ5. Does forcing separation cause retransmissions or DNP3 failure?

Required experiment:

request received
-> timestamp
-> optional controlled wait
-> normal response write
-> packet capture
-> classify combined or separate

Do not forge an ACK.

Delay sweep:

Coarse:
0, 1, 2, 5, 10, 20, 30, 40, 50, 75, 100 ms

Refined:
Once a transition region is observed, test at 1 ms or finer increments around it.

Socket variables:

Test one factor at a time:

- default;
- TCP_NODELAY enabled;
- TCP_NODELAY disabled;
- TCP_QUICKACK where supported;
- different request sizes;
- different response sizes;
- persistent connection versus new connection.

Record:

- OS;
- kernel;
- sysctl values where relevant;
- socket options;
- NIC offloads;
- capture location;
- request-to-pure-ACK;
- request-to-response;
- ACK-to-response gap;
- separate-ACK fraction;
- DNP3 or test-protocol success;
- retransmissions;
- duplicate ACKs;
- resets.

Capture at both endpoints where possible.

Do not infer pure ACK emission from application logs. PCAP is required.

Required outputs:

- threshold curve;
- confidence interval on separate-ACK probability;
- transition-region plot;
- socket-option comparison;
- example combined timeline;
- example separate timeline;
- environment-dependence table.

Required claim restriction:

Use:

“On the tested host, kernel, socket configuration, and traffic pattern, the transition occurred at approximately X ms.”

Do not use:

“Linux always uses a 40 ms delayed ACK.”

Phase 03 gate:

PASS only if:

- the behavior is reproduced from fresh captures;
- pure ACKs are identified using packet fields;
- the transition is measured with repeated samples;
- environment details are captured;
- no ACK is forged;
- instability is reported rather than hidden.

Stop after producing:

reports/phases/phase_03/phase_03_ack_separation.md

============================================================
PHASE 04: SEPARATE ACK AND RESPONSE MANIPULATION
============================================================

Objective:
Evaluate whether an existing pure TCP ACK and later DNP3 response can be delayed independently and safely.

Before implementation, create:

reports/phases/phase_04/ack_control_feasibility.md

The feasibility report must answer:

1. Can the application delay the response?
2. Can the application delay a kernel ACK after emission?
3. What control point is required to delay a pure ACK?
4. Can Linux tc distinguish:
   - zero-payload pure ACK;
   - payload-bearing response?
5. Is eBPF required?
6. Is a transparent bridge more appropriate?
7. Which mechanism maps most directly to future P4?
8. What state is required?
9. What ordering and retransmission risks exist?

Do not proceed with implementation until the feasibility report identifies a real enforcement mechanism.

Candidate mechanisms:

- response delay in application;
- tc netem plus classifier;
- eBPF tc ingress/egress;
- transparent Linux bridge;
- inline user-space proxy;
- DPDK;
- programmable NIC;
- P4/Tofino.

Do not use ACK synthesis.

Required modes after a valid enforcement mechanism is selected:

1. native
2. ACK-delay-only
3. response-delay-only
4. independent delay
5. fixed gap normalization
6. bounded gap normalization

Definitions:

request_to_ack =
    ack_release - request_arrival

request_to_response =
    response_release - request_arrival

ack_to_response_gap =
    response_release - ack_release

Invariant:

ack_release <= response_release

If a selected ACK delay would place the ACK after the response:

- clamp safely;
- resample;
- or bypass;
- log the decision.

Required tests:

- ACK delay shrinks visible gap;
- response delay increases visible gap;
- joint policy produces intended gap;
- no packet reordering;
- no ACK after response;
- no connection reset;
- no unsafe retransmission;
- application response remains byte-identical;
- sequence and acknowledgement numbers remain valid;
- DNP3 completes correctly.

Important research question:

Does normalizing only the gap magnitude reduce fingerprinting if the existence of the separate ACK remains visible?

Evaluate:

- gap magnitude;
- ACK mode;
- request-to-ACK;
- request-to-response;
- joint feature space.

Phase 04 gate:

PASS only if:

- a real mechanism delays the packets;
- PCAP proves the delays;
- packet ordering is correct;
- TCP state remains valid;
- DNP3 correctness is preserved;
- the report distinguishes visible gap changes from true processing-time changes;
- residual ACK-mode leakage is measured.

Stop after producing:

reports/phases/phase_04/phase_04_separate_ack_manipulation.md

============================================================
PHASE 05: COMPREHENSIVE ATTACKER EVALUATION
============================================================

Objective:
Determine what a passive observer can infer before and after each defense.

Build a reusable pipeline:

Raw PCAP
-> transaction reconstruction
-> feature extraction
-> feature validation
-> train/test split
-> normalization fitted on training data only
-> classifier or clusterer
-> evaluation
-> feature attribution
-> residual leakage report

Feature families:

A. Timing
- request-to-first-reverse-packet;
- request-to-ACK;
- ACK-to-response;
- request-to-response;
- inter-packet times;
- burst duration;
- response completion time;
- rolling mean;
- rolling variance;
- repeated-observation mean.

B. Size and shape
- request payload size;
- response payload size;
- IP packet size;
- TCP payload size;
- packet count;
- largest packet;
- total bytes;
- direction changes;
- segmentation pattern;
- fragment count;
- chunk count.

C. ACK behavior
- separate ACK present;
- combined ACK-bearing response;
- number of pure ACKs;
- ACK-to-response gap.

D. Distributional features
- variance;
- coefficient of variation;
- skewness;
- kurtosis;
- entropy;
- burstiness;
- quantiles;
- autocorrelation where sample windows support it.

E. Protocol-aware features
- DNP3 function class where allowed by the attacker model;
- request versus response direction;
- application-fragment count;
- link-frame count.

Attacker models:

Required:

- threshold classifier;
- logistic regression;
- random forest;
- support vector machine;
- k-nearest neighbors;
- gradient boosting available in the existing environment;
- repeated-observation averaging attacker;
- packet-count-only attacker;
- size-only attacker;
- ACK-mode-only attacker;
- timing-only attacker;
- joint-feature attacker;
- detect-the-defense attacker.

Optional:

- XGBoost only if already available or approved;
- SHAP only if dependency and runtime are reasonable;
- 1D-CNN only after conventional models are complete.

Do not add heavyweight dependencies merely to increase the model count.

Feature attribution:

Mandatory:

- permutation importance;
- mutual information;
- univariate effect sizes.

Optional:

- SHAP.

Train/test splitting:

Do not randomly divide adjacent rows from one capture across training and test data.

Use:

- base capture for training;
- L capture for testing;
- or capture-level split;
- or time-block split.

Prevent:

- same TCP connection in train and test;
- same repeated sequence in train and test;
- preprocessing fitted on all data;
- feature leakage from filenames.

Evaluation scenarios:

1. Native.
2. Combined response fixed normalization.
3. Combined response bounded normalization.
4. Separate ACK gap normalization.
5. ACK-delay-only.
6. Response-delay-only.
7. Timing defense only.
8. Size features only.
9. ACK-mode feature only.
10. Timing plus size.
11. All features.
12. Defense-detection classification.
13. Repeated-observation attacker.

Metrics:

- accuracy;
- balanced accuracy;
- precision;
- recall;
- F1;
- macro-F1;
- ROC-AUC;
- PR-AUC where applicable;
- confusion matrix;
- calibration where practical;
- bootstrap confidence intervals;
- clustering ARI and NMI;
- feature importance;
- mutual information.

Required conclusions:

- which timing channels were reduced;
- whether ACK mode remains;
- whether size remains;
- whether the defense becomes a fingerprint;
- whether repeated averaging recovers information;
- whether rare native tails leak.

Phase 05 gate:

PASS only if:

- capture-level separation is used;
- multiple attacker families are evaluated;
- residual leakage is reported;
- chance baselines are stated correctly;
- models are not tuned on the test set;
- timing-only improvements are not presented as complete anonymization.

Stop after producing:

reports/phases/phase_05/phase_05_attacker_evaluation.md

============================================================
PHASE 06: STATISTICS, OVERHEAD, AND REPLAY-VERSUS-REAL
============================================================

Objective:
Quantify significance, operational overhead, and how closely the replay system represents real devices.

Statistical analysis:

Use appropriate tests, not every test indiscriminately.

Include where justified:

- bootstrap confidence intervals;
- Kolmogorov-Smirnov test;
- Mann-Whitney U;
- Wilcoxon signed-rank for paired data;
- Kruskal-Wallis for multiple groups;
- Cliff’s delta;
- Cohen’s d where assumptions are reasonable;
- multiple-comparison correction;
- Wasserstein distance;
- Jensen-Shannon divergence.

Do not rely on p-values alone.

Report:

- effect size;
- confidence interval;
- sample size;
- test assumptions;
- multiple-testing correction.

Operational overhead:

Measure:

- added request-to-response latency;
- p50, p95, p99, maximum;
- scheduling computation time;
- CPU utilization;
- memory usage;
- packet rate;
- throughput;
- packet count;
- bandwidth overhead;
- queue depth;
- queue occupancy;
- deadline misses;
- bypasses;
- retransmissions;
- resets;
- DNP3 task failures;
- response-byte identity.

Separate:

- scheduler computation overhead;
- deliberate hold time;
- split/chunk overhead;
- capture overhead.

Replay-versus-real comparison:

Compare:

1. Real native AB1400.
2. Real native ION7550.
3. Real native SEL-751.
4. Replay-native behavior.
5. Replay-protected behavior.

Metrics:

- KS distance;
- Wasserstein distance;
- Jensen-Shannon divergence;
- quantile differences;
- response-size match;
- ACK-mode match;
- packet-count match;
- timing-distribution match.

Do not use KL divergence without explaining smoothing and support problems.

Required question:

Can an attacker distinguish:

- real device;
- replay server;
- protected replay server?

This is different from identifying device model and must be evaluated separately.

Phase 06 gate:

PASS only if:

- overhead is measured on fresh runs;
- effect sizes accompany significance tests;
- replay realism is quantified;
- scheduler delay is separated from computational overhead;
- detect-replay and detect-defense results are reported.

Stop after producing:

reports/phases/phase_06/phase_06_statistics_overhead_replay.md

============================================================
PHASE 07: FINAL SYNTHESIS AND P4 READINESS
============================================================

Objective:
Consolidate the evidence and determine which mechanisms are ready for P4/Tofino implementation.

Produce:

1. Final research-question table.
2. Claim-to-evidence table.
3. Supported claims.
4. Unsupported claims.
5. Residual leakage channels.
6. Safety limitations.
7. Software architecture.
8. Packet-processing requirements.
9. P4 feasibility assessment.
10. Future experiment plan.

P4 assessment must distinguish:

Likely feasible:

- classify packet direction;
- identify pure TCP ACK;
- identify payload-bearing response;
- classify sizes;
- map flows;
- queue existing packets;
- delay or pace existing packets;
- maintain limited metadata.

Potentially difficult:

- absolute deadline scheduling;
- accurate per-flow timers;
- creating new TCP segments;
- synthesizing ACKs;
- complete TCP state tracking;
- changing host ACK behavior;
- buffering large responses;
- cross-packet application parsing.

Do not claim:

- stage count;
- SRAM use;
- SALU use;
- queue feasibility;
- nanosecond accuracy;
- line-rate operation;

unless supported by:

- compiled P4;
- compiler resource output;
- target-specific test;
- or clearly labeled engineering estimate.

Final outputs:

reports/final/final_master_report.md
reports/final/claim_evidence_matrix.csv
reports/final/limitations.md
reports/final/p4_readiness.md
reports/final/reproduction_guide.md
reports/final/paper_figure_index.md
reports/final/paper_table_index.md

Final gate:

Do not begin P4 implementation automatically.

Stop and request human approval.

============================================================
J. PUBLICATION-QUALITY OUTPUTS
============================================================

All experiments must generate publication-ready outputs automatically.

Figures:

- no screenshots of terminals as primary evidence;
- use Matplotlib or the existing plotting stack;
- use consistent fonts and dimensions;
- ensure grayscale readability;
- label units;
- include sample counts;
- use concise captions;
- avoid decorative effects;
- export PNG and vector PDF;
- do not overwrite old figures.

Tables:

- CSV;
- JSON;
- Markdown;
- LaTeX.

Each figure must have a metadata sidecar:

figure_name.metadata.json

Include:

- source run IDs;
- source CSV;
- script;
- git commit;
- generation command;
- filters;
- statistical transformation;
- creation timestamp.

============================================================
K. REQUIRED TESTS ACROSS THE PROJECT
============================================================

Unit tests:

- fixed release target;
- bounded target;
- deterministic seed;
- response ready before target;
- response ready after target;
- deadline miss;
- fail-open;
- queue limit;
- critical bypass;
- unsupported bypass;
- per-flow FIFO;
- multiple flows;
- ACK-before-response invariant;
- target-range validation;
- byte preservation;
- transaction reconstruction;
- ACK classification;
- feature extraction;
- capture-level split;
- manifest generation.

Integration tests:

- native replay;
- fixed normalization;
- bounded normalization;
- split plus timing;
- ACK-separation probe;
- two-host capture parser;
- SELECT then OPERATE;
- large READ;
- DNP3 task completion;
- fresh output isolation.

Regression tests:

- no appending to an old CSV;
- no overwriting a prior run;
- continuation response is handled consistently;
- no stale replay directory;
- no ambiguous ACK automatically classified;
- no report generated from missing raw data.

============================================================
L. FIRST ACTIONS NOW
============================================================

Begin only Phase 00.

Do the following now:

1. Read the complete repository.
2. Run git status.
3. Record branch and commit.
4. Inventory files.
5. Identify all existing experiment entry points.
6. Run all existing tests.
7. Inspect the existing timing, trace, ACK, replay, and attacker code.
8. Determine whether current reports are reproducible.
9. Identify repository-organization problems.
10. Produce the Phase 00 files and report.
11. Do not implement a new timing distribution.
12. Do not modify ACK behavior.
13. Do not move active files yet unless necessary to complete the audit.
14. Do not begin Phase 01.

End your response with:

PHASE 00 COMPLETE
Status: PASS | CONDITIONAL PASS | FAIL
Report: <path>
Open blockers: <list>
STOP: Awaiting human review before Phase 01.