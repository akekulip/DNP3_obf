======================================================================
13. TUTORIAL, DEMONSTRATION, AND WIRESHARK PACKAGE
======================================================================

The timing deliverable must be understandable and runnable by someone who did
not develop the mechanism.

Do not produce only a technical report.

Produce a complete tutorial package containing:

1. a standalone offline HTML tutorial;
2. a professionally formatted PDF version;
3. a short Quick Start guide;
4. a detailed laboratory runbook;
5. architecture and mechanism diagrams;
6. annotated P4 and Python code explanations;
7. one-command demonstration scripts;
8. Wireshark and tshark capture instructions;
9. native and protected example PCAP files;
10. figure-generation scripts;
11. troubleshooting and recovery instructions.

The package must teach the mechanism from first principles while remaining
technically accurate enough for a research meeting.

Sizing is out of scope for this week. Do not include size-normalization code in
the runnable timing demonstration.

======================================================================
14. REQUIRED DOCUMENT SET
======================================================================

Create the following structure:

deliverables/timing_tutorial/
├── index.html
├── DNP3_TIMING_NORMALIZER_TUTORIAL.pdf
├── README_FIRST.md
├── QUICKSTART.md
├── LAB_RUNBOOK.md
├── WIRESHARK_GUIDE.md
├── CODE_WALKTHROUGH.md
├── TROUBLESHOOTING.md
├── DEMO_SCRIPT_2_MINUTES.md
├── TECHNICAL_TALK_5_MINUTES.md
├── assets/
│   ├── lab_topology.svg
│   ├── packet_path.svg
│   ├── queue_architecture.svg
│   ├── transaction_timeline.svg
│   ├── state_machine.svg
│   ├── deadline_release.svg
│   ├── g_selection_guard.svg
│   ├── native_vs_protected_histogram.png
│   ├── native_vs_protected_ecdf.png
│   ├── clrt_trace.png
│   ├── deadline_error.png
│   ├── release_tail.png
│   └── resource_usage.png
├── example_pcaps/
│   ├── native_demo.pcap
│   ├── protected_demo.pcap
│   └── README.md
└── source/
    ├── tutorial_source.md
    ├── references.md
    └── build_tutorial.sh

The HTML and PDF must be generated from the same source so that they do not
contradict each other.

The HTML must:

- work without internet access;
- use embedded or local CSS and JavaScript;
- contain a navigation sidebar;
- provide copy buttons for commands;
- contain collapsible code explanations;
- embed all diagrams locally;
- link each figure to its generating data and script;
- display correctly on a normal laptop screen.

The PDF must:

- embed every required figure;
- include readable code excerpts;
- avoid clipped commands and diagrams;
- contain page numbers and a table of contents;
- be suitable for sharing with Dr. Lin;
- include the source commit and build date.

Verify the rendered HTML and PDF. Do not merely generate them and assume they
are readable.

======================================================================
15. TUTORIAL WRITING STYLE
======================================================================

Write the tutorial in two layers.

LAYER 1 — SIMPLE EXPLANATION

Explain each idea in plain language:

- what DNP3 is;
- what a master and outstation are;
- what READ, ACK and RESPONSE mean;
- what CLRT is;
- why CLRT can fingerprint a device;
- what the Tofino switch changes;
- where the original response waits;
- what blocker tokens are;
- why blocker tokens never reach the endpoints;
- how the deadline releases the response;
- how G is selected;
- what fail-open means.

Every major section should begin with a short plain-language summary.

LAYER 2 — TECHNICAL DETAIL

Then provide:

- relevant P4 parser logic;
- state/register representation;
- queue IDs and priorities;
- deadline arithmetic;
- transaction matching;
- timeout behavior;
- packet path;
- counters and telemetry;
- exact experiment evidence;
- limitations and security scope.

Define every acronym before using it repeatedly.

Do not use unexplained phrases such as:

- MAU dependency;
- PHV;
- SALU;
- strict-priority starvation;
- generation tag;
- queue-resident hold.

Explain them when they first appear.

======================================================================
16. REQUIRED DIAGRAMS
======================================================================

Produce clean SVG diagrams that remain editable.

Diagram 1 — Laboratory topology

Show:

    Vision/master
    10.10.54.19 management
    192.168.10.1 relay network
           |
          dp9
           |
       Tofino-1
       10.10.54.81
           |
          dp11
           |
    Hulk/outstation-side host
    10.10.54.158

Also show:

    dp8 MAC-near internal loopback

Use arrows to identify:

- READ direction;
- ACK direction;
- RESPONSE direction;
- internal blocker-token loop.

Diagram 2 — Packet path

Show:

    READ arrives
        ↓
    transaction state armed
        ↓
    pure ACK arrives
        ↓
    t_ack recorded
        ↓
    deadline = t_ack + G
        ↓
    RESPONSE arrives
        ↓
    RESPONSE enters Q_RESP
        ↓
    blocker reservoir keeps Q_RESP from draining
        ↓
    deadline expires
        ↓
    blockers terminate
        ↓
    RESPONSE exits unchanged

Diagram 3 — Traffic Manager queues

Show:

    Q_BLOCK: high priority
    Q_RESP: low priority

Explain visually that Q_BLOCK receives service first while blocker tokens exist,
so Q_RESP remains occupied.

Do not depict the original response as continuously recirculating.

Diagram 4 — Transaction timeline

Include:

    READ
    ACK at t_ack
    native RESPONSE arrival
    programmed deadline t_ack + G
    effective hold period
    actual release
    stable release tail

Show both cases:

A. native response arrives before deadline — protection is applied;
B. native response arrives after deadline — zero hold and low-G warning.

Diagram 5 — State machine

Include:

    IDLE
    ARMED
    ACK_QUALIFIED
    RESPONSE_HELD
    DEADLINE_RELEASE
    FAIL_OPEN
    CLEANUP
    IDLE

Show stale and unrelated packets as bypass paths that do not change state.

Diagram 6 — Evidence chain

Show:

    raw PCAP
        ↓
    transaction extraction
        ↓
    CLRT CSV
        ↓
    statistical analysis
        ↓
    figures
        ↓
    reported claim

Every reported number must be traceable through this chain.

======================================================================
17. CODE WALKTHROUGH
======================================================================

Create CODE_WALKTHROUGH.md.

Explain the implementation in execution order, not simply file order.

Required sections:

1. parser and packet classification;
2. direction classification from ingress port;
3. READ transaction arming;
4. pure TCP ACK qualification;
5. packed transaction state;
6. deadline calculation;
7. RESPONSE queue assignment;
8. blocker-token processing;
9. deadline expiry;
10. RESPONSE release;
11. pass-budget fail-open;
12. state cleanup;
13. counters and timestamp registers;
14. Traffic Manager configuration;
15. packet-verification logic.

For every code excerpt include:

- filename;
- exact line range or function/table/action name;
- what the code does;
- why it is needed;
- what would fail without it;
- the corresponding evidence or test.

Do not fill the tutorial with the entire P4 file inline.

Use short, annotated excerpts, then include the complete source as an appendix or
local linked file.

Create a code-to-mechanism table:

| Mechanism | P4 component | Setup component | Test component |
|-----------|---------------|-----------------|----------------|
| READ classification | ... | ... | ... |
| ACK qualification | ... | ... | ... |
| Deadline arm | ... | ... | ... |
| Response hold | ... | ... | ... |
| Release | ... | ... | ... |
| Fail-open | ... | ... | ... |
| Token isolation | ... | ... | ... |

Do not use placeholder table entries in the final document.

======================================================================
18. SIMPLE RUNNABLE LAB INTERFACE
======================================================================

Create a simple command interface.

Preferred user workflow:

    make preflight
    make build
    make load
    make demo-native
    make demo-protected
    make analyze
    make figures
    make restore

Also provide one guarded combined command:

    make demo

The combined command must:

1. run preflight checks;
2. show the detected topology;
3. ask for explicit confirmation before changing the switch program;
4. build or verify the P4 artifact;
5. load the timing program;
6. configure Traffic Manager queues;
7. start PCAP capture;
8. run a small native demonstration;
9. run a small protected demonstration;
10. stop captures cleanly;
11. verify packet identity and timing;
12. generate a short result summary;
13. offer restoration;
14. never leave background captures or generators running.

Create:

Makefile
config/lab.env.example
scripts/00_preflight.sh
scripts/01_build.sh
scripts/02_load.sh
scripts/03_configure_tm.py
scripts/04_start_capture.sh
scripts/05_run_native.sh
scripts/06_run_protected.sh
scripts/07_stop_capture.sh
scripts/08_verify.py
scripts/09_analyze_clrt.py
scripts/10_generate_figures.py
scripts/11_collect_evidence.sh
scripts/12_restore.sh
scripts/demo_all.sh

Every script must:

- use strict error handling;
- print the command being executed;
- write a timestamped log;
- return a nonzero exit code on failure;
- avoid silently ignoring errors;
- record cleanup actions;
- support --help;
- support --dry-run where meaningful.

Do not hard-code an interface name without checking it.

Auto-detect the relay-facing Vision interface using the address 192.168.10.1.

Print the detected interface and require an explicit override when detection is
ambiguous.

======================================================================
19. TWO EXECUTION MODES
======================================================================

Provide two clearly separated modes.

MODE A — SAFE REPLAY DEMO

This is the default mode for the meeting.

Use validated READ, pure ACK and RESPONSE frames.

Required properties:

- no physical relay modification;
- no DNP3 write or control operation;
- no physical recabling;
- deterministic transaction count;
- native and protected PCAPs;
- repeatable in a few minutes.

Example:

    make demo MODE=replay TRIALS=10 G_MS=25

MODE B — LIVE READ-ONLY RELAY MODE

This mode is optional and requires explicit authorization.

Allow only:

- Class-0 READ;
- Request-Link-Status;
- existing approved connection parameters.

Prohibit:

- DIRECT_OPERATE;
- OPERATE;
- SELECT;
- WRITE;
- restart;
- configuration changes;
- password guessing;
- relay IP changes.

The tutorial must clearly label whether a result came from:

- synthetic markers;
- real replayed DNP3;
- physical-relay-generated captures;
- a live inline relay session.

Do not blur these evidence levels.

======================================================================
20. PCAP CAPTURE PACKAGE
======================================================================

The user must be able to capture and inspect the traffic in Wireshark.

Create a capture script that:

- detects the correct interface;
- uses snap length 0;
- preserves full frames;
- records epoch timestamps;
- avoids packet truncation;
- records the capture command;
- writes a capture manifest;
- stops cleanly on Ctrl+C;
- verifies the resulting file is readable.

Use a command pattern equivalent to:

    tcpdump -i <detected-interface> \
        -s 0 \
        -nn \
        -U \
        -w <output-file> \
        'tcp port 20000'

Do not copy this blindly if the installed tcpdump syntax differs. Test it.

Capture at minimum:

    native_demo.pcap
    protected_demo.pcap

Record:

- host;
- interface;
- start time;
- end time;
- filter;
- packet count;
- file SHA-256;
- source commit;
- G value;
- transaction count.

Create a JSON manifest beside each PCAP.

======================================================================
21. WIRESHARK GUIDE
======================================================================

Create WIRESHARK_GUIDE.md with screenshots or locally generated annotated
figures where possible.

Explain:

1. how to open the PCAP;
2. how to confirm the correct interface was captured;
3. how to apply the basic display filter:

       tcp.port == 20000

4. how to identify a pure TCP ACK:

       tcp.len == 0 && tcp.flags.ack == 1

5. how to find retransmissions:

       tcp.analysis.retransmission ||
       tcp.analysis.fast_retransmission

6. how to inspect:

       frame.time_relative
       frame.time_delta
       tcp.seq
       tcp.ack
       tcp.len
       ip.len
       TCP options
       DNP3 function information

Do not invent version-specific DNP3 Wireshark field names.

Run:

    tshark -G fields

against the installed version and identify the exact available DNP3 field names.
Document those version-correct filters.

Explain how to add useful Wireshark columns:

- Time relative;
- Source;
- Destination;
- TCP sequence;
- TCP acknowledgment;
- TCP length;
- DNP3 function;
- transaction identifier when available.

Show how to measure CLRT manually:

    select the pure ACK;
    identify the corresponding RESPONSE;
    subtract the timestamps.

Then show how the analysis script performs the same calculation automatically.

Provide screenshots or annotated packet-list images for:

- native timing;
- protected timing;
- a valid READ;
- a pure ACK;
- a RESPONSE;
- no retransmission;
- no blocker token on the external interface.

======================================================================
22. AUTOMATED PCAP ANALYSIS
======================================================================

Create a deterministic PCAP analysis tool:

    scripts/analyze_clrt.py

Input:

    native or protected PCAP
    master/outstation addresses
    TCP port
    optional transaction map

Output:

    transactions.csv
    summary.json
    validation.json

For each transaction record:

- READ timestamp;
- ACK timestamp;
- RESPONSE timestamp;
- ACK-to-RESPONSE CLRT;
- TCP sequence and acknowledgment values;
- response length;
- retransmission flags;
- duplicate indicators;
- missing-role flags;
- transaction status.

The script must reject ambiguous pairings rather than silently selecting a
packet.

Cross-check its result with tshark extraction.

Create a second independent verifier or tshark command so that the headline CLRT
numbers do not depend on one parser implementation.

======================================================================
23. DEMONSTRATION EXPERIENCE
======================================================================

The demonstration should be simple enough to run during the meeting.

Recommended meeting workflow:

TERMINAL 1 — Switch status

    make status

Show:

- loaded P4 program;
- queue priorities;
- active transaction state;
- blocker and release counters.

TERMINAL 2 — Capture

    make capture OUTPUT=protected_demo.pcap

TERMINAL 3 — Traffic

    make run-protected TRIALS=10 G_MS=25

Then:

    make analyze PCAP=protected_demo.pcap
    make figures

Print a compact result:

    Transactions:              10
    Valid READs:               10
    Qualified ACKs:            10
    Responses held:            10
    Responses released:        10
    Mean ACK→RESPONSE:         ...
    CLRT standard deviation:   ...
    Low-G warnings:             0
    Missing/duplicate frames:   0
    External blocker frames:    0
    Verification:             PASS

Create:

    scripts/demo_status.py

It should display only meeting-relevant information rather than dumping every
register.

======================================================================
24. QUICK START FORMAT
======================================================================

README_FIRST.md should fit on approximately one screen.

It must answer:

1. What does this project demonstrate?
2. Which three machines are involved?
3. Which command checks the lab?
4. Which command runs the demo?
5. Where are the PCAPs stored?
6. How do I open them in Wireshark?
7. Which command restores the switch?
8. What should I do if the demo fails?

QUICKSTART.md should provide a 10-minute path:

    Step 1: source the environment
    Step 2: run preflight
    Step 3: build
    Step 4: load
    Step 5: configure queues
    Step 6: start capture
    Step 7: run native
    Step 8: run protected
    Step 9: analyze
    Step 10: restore

For every step show:

- purpose;
- exact command;
- expected output;
- common failure;
- recovery command.

Do not say only “run the setup script.”

======================================================================
25. TROUBLESHOOTING
======================================================================

Create a symptom-based troubleshooting guide.

Include:

- switch not reachable at 10.10.54.81;
- Vision not reachable at 10.10.54.19;
- Vision missing 192.168.10.1;
- Hulk not reachable at 10.10.54.158;
- more than one bf_switchd process;
- wrong P4 program loaded;
- BFRT binding failure;
- queue priority readback incorrect;
- dp8 loopback not enabled;
- no packets in PCAP;
- PCAP captured on wrong interface;
- DNP3 not decoded by Wireshark;
- pure ACK misclassified;
- response released immediately;
- response never released;
- fail-open triggered unexpectedly;
- low-G warning;
- blocker token visible externally;
- retransmission;
- missing response;
- cleanup script interrupted.

Each entry must include:

    symptom
    likely cause
    diagnostic command
    expected healthy output
    safe correction
    when to stop and ask for authorization

======================================================================
26. SAFETY AND RESTORATION
======================================================================

The runnable package must always preserve the lab.

Before loading:

- record current bf_switchd PID;
- record current P4 binding;
- record port state;
- record queue configuration;
- record host reachability;
- record git state.

After the demonstration:

- stop traffic generators;
- stop tcpdump;
- stop temporary BFRT clients;
- verify no blocker tokens remain;
- verify no active transaction state remains;
- collect final counters;
- restore queue_microbench_abs.conf;
- verify exactly one bf_switchd;
- verify BFRT binding to queue_microbench;
- verify switch reachability;
- verify Vision retains 192.168.10.1;
- verify Hulk reachability;
- write a restoration report.

Create:

    evidence/timing_final/final_state/restoration_report.txt

The cleanup script must be safe to run more than once.

======================================================================
27. TUTORIAL ACCEPTANCE TEST
======================================================================

The documentation package passes only when a fresh terminal can follow the
Quick Start without relying on undocumented shell history.

Perform a clean-room test:

1. open a new shell;
2. clone or enter the clean worktree;
3. read README_FIRST.md only;
4. run preflight;
5. run the safe replay demonstration;
6. produce native and protected PCAPs;
7. run the verifier;
8. generate the figures;
9. open the HTML locally;
10. build or open the PDF;
11. restore the switch.

Record:

- every command;
- exit code;
- runtime;
- any missing dependency;
- any manual correction.

Fix the tutorial until the clean-room run passes.

Do not report completion merely because individual scripts work when run by the
developer who wrote them.

======================================================================
28. FINAL MEETING PACKAGE
======================================================================

The final meeting directory should contain:

meeting_package/
├── START_HERE.html
├── DNP3_TIMING_NORMALIZER_TUTORIAL.pdf
├── QUICKSTART.md
├── demo/
├── source/
├── figures/
├── example_pcaps/
├── evidence_summary/
└── SHA256SUMS

START_HERE.html should link to:

- the tutorial;
- the architecture diagram;
- the two-minute demonstration;
- the complete code;
- example PCAPs;
- the Wireshark guide;
- the final results;
- limitations;
- restoration instructions.

Create one archive:

    timing_meeting_package_<date>_<commit>.tar.gz

Generate and verify SHA-256 hashes.

======================================================================
29. REPORTING CHECKPOINT
======================================================================

Report when the following are ready:

- canonical reference P4 identified;
- G-selection telemetry integrated and compiled;
- Makefile and demo scripts operational;
- native and protected PCAP capture operational;
- PCAP analyzer verified against tshark;
- HTML tutorial rendered;
- PDF rendered;
- clean-room Quick Start run completed;
- switch restoration tested;
- meeting package assembled.

In the checkpoint, provide the exact commands Philip should run for the meeting.

Do not resume size-obfuscation research until this timing tutorial and
demonstration package is complete.