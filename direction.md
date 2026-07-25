ONE-WEEK TIMING DELIVERY DIRECTIVE

For the coming meeting, suspend all further size-obfuscation implementation and
research.

Sizing is not abandoned. Preserve all branches, reports, negative evidence, and
the size-research roadmap, but do not spend this week building or testing new
size mechanisms.

The sole objective is to perfect the Tofino-1 DNP3 timing-fingerprinting and
CLRT-obfuscation result.

======================================================================
1. REQUIRED FINAL OUTCOME
======================================================================

Deliver one clean, reproducible, meeting-ready implementation that proves:

- real DNP3 READ classification;
- pure TCP ACK classification;
- real DNP3 RESPONSE classification;
- physical SEL-751 framing support, including TCP data_offset=8;
- transaction-specific ACK qualification;
- queue-resident RESPONSE hold;
- deadline release at t_ack + G;
- stable release-tail measurement;
- timeout/fail-open;
- generation-safe cleanup;
- no external blocker-token leakage;
- packet byte preservation;
- CLRT-fingerprint reduction;
- explicit detection when configured G is too low.

Do not perform new size-normalization experiments.

======================================================================
2. FREEZE AND IDENTIFY THE REFERENCE IMPLEMENTATION
======================================================================

Audit the existing timing branches and identify the strongest implementation
containing:

- parser-based DNP3 classification;
- packed transaction state;
- HOLD_RESPONSE;
- deadline logic;
- blocker reservoir;
- fail-open;
- token isolation;
- real data_offset=8 support.

Create a clean branch:

    research/timing-final-meeting

Use one canonical P4 filename:

    dnp3_timing_normalizer.p4

Do not delete earlier experimental files.

Create:

    TIMING_REFERENCE_IMPLEMENTATION.md

Document:

- base commit;
- source SHA-256;
- architecture;
- packet roles;
- state machine;
- register layout;
- queue mapping;
- release causes;
- parser-hardening rules;
- known limitations.

======================================================================
3. ADD THE G-SELECTION GUARD
======================================================================

The current system silently provides no effective hold when:

    native_clrt >= G

Implement explicit protection telemetry.

For each transaction record:

    t_ack
    t_response_arrival
    native_clrt
    configured_G
    effective_hold
    response_before_deadline
    response_at_or_after_deadline
    release_reason

Add counters or equivalent evidence for:

    ctr_response_before_deadline
    ctr_response_at_or_after_deadline
    ctr_response_actually_held
    ctr_response_zero_hold
    ctr_release_deadline
    ctr_release_fail_open

Required semantics:

    native_clrt = t_response_arrival - t_ack

    if native_clrt < G:
        effective_hold = G - native_clrt
        protection_applied = true
    else:
        effective_hold = 0
        protection_applied = false
        low_G_warning = true

Do not pretend a transaction is normalized if the response arrives at or after
the target deadline.

Compile and measure whether the guard changes stage use.

Do not remove generation safety, fail-open, or token isolation to make it fit.

======================================================================
4. IMPLEMENTATION REVIEW
======================================================================

Launch independent agents for:

A. P4 parser review
B. packed-state and generation-safety review
C. Traffic Manager and strict-priority review
D. deadline and timestamp arithmetic review
E. fail-open and cleanup review
F. test-harness integrity review
G. adversarial security-claim review

Required parser checks:

- pure ACK must not attempt DNP3 extraction;
- DNP3 magic before deep parsing;
- valid length checks;
- TCP data_offset values used by the SEL supported;
- malformed or unsupported traffic bypasses safely;
- parser role cannot be overwritten from packet-controlled metadata.

Required state checks:

- ACK before READ does not qualify;
- matching ACK qualifies once;
- duplicate ACK does not re-arm;
- stale ACK does not affect a new transaction;
- timeout clears state;
- next transaction succeeds;
- generation wrap is handled or explicitly bounded.

======================================================================
5. FINAL EXPERIMENT CAMPAIGN
======================================================================

Run a clean final campaign only after code review and compile pass.

Stage A — native timing characterization:

- at least 100 read-only transactions;
- preserve raw PCAP;
- measure ACK-to-RESPONSE CLRT;
- record native distribution.

Stage B — protected timing:

Test:

    G = 5 ms
    G = 10 ms
    G = 17 ms
    G = 20 ms
    G = 25 ms
    G = 40 ms

Run at least 30 trials per G.

Select one final G that exceeds the measured native p99 and run 100 repetitions.

For each trial verify:

- READ arm count = 1;
- ACK arm count = 1;
- ACK bypass count = 0 for valid ACK;
- RESPONSE enqueue count = 1;
- RESPONSE release count = 1;
- deadline arithmetic correct;
- release reason correct;
- protection-applied flag correct;
- low-G warning correct;
- no blocker escape;
- no timeout in normal protected trials;
- byte identity;
- no missing;
- no duplicate;
- no reorder;
- state returns to idle.

Preserve campaign exit status and per-trial return codes.

If any trial fails, preserve it and restart the final campaign only after the
root cause is corrected.

======================================================================
6. TIMING-FINGERPRINTING EVALUATION
======================================================================

Build one reproducible analysis pipeline from raw PCAP and switch evidence.

Compute native and protected:

- count;
- min;
- max;
- mean;
- median;
- standard deviation;
- p5;
- p25;
- p75;
- p95;
- p99;
- range;
- number of distinct values;
- empirical CDF;
- histogram;
- jitter.

Evaluate timing leakage at:

    10 us
    50 us
    100 us
    500 us
    1 ms

Compute:

- entropy;
- mutual information with device;
- mutual information with operation where labels exist;
- balanced classification accuracy;
- confusion matrix;
- bootstrap confidence intervals.

Separate:

- CLRT magnitude;
- ACK mode;
- TCP stack features;
- size features.

Do not claim full device anonymity.

The main claim is:

    closes or significantly reduces the CLRT-magnitude channel

Create:

    TIMING_FINGERPRINTING_ANALYSIS.md

======================================================================
7. EVIDENCE PACKAGE
======================================================================

Create:

    evidence/timing_final/

Required contents:

    build/
    source/
    tm_readback/
    native/
    protected/
    g_guard/
    repetition/
    pcaps/
    counters/
    registers/
    packet_identity/
    token_isolation/
    fingerprinting/
    figures/
    final_state/

Preserve:

- exact commands;
- timestamps;
- compiler versions;
- source hash;
- compile logs;
- resource files;
- TM queue configuration;
- raw per-trial output;
- complete PCAPs;
- verifier JSON;
- campaign exit codes;
- cleanup output;
- restoration output;
- git status.

Every final figure must be reproducible from a script committed beside its input
CSV.

======================================================================
8. FINAL FIGURES
======================================================================

Generate publication-quality figures for:

1. architecture;
2. transaction timeline;
3. native versus protected histogram;
4. native versus protected ECDF;
5. CLRT by transaction number;
6. leakage before and after;
7. deadline-error distribution;
8. c1/c2 release-tail decomposition;
9. G-selection guard;
10. resource use.

Do not use misleading truncated axes.

Use readable IEEE-style labels and units.

======================================================================
9. EXPLANATION PACKAGE
======================================================================

Create:

    TIMING_MECHANISM_EXPLAINED.md

It must explain clearly:

- the fingerprinting threat;
- why CLRT leaks device behavior;
- why endpoints and controllers are not used;
- why the original response remains queue-resident;
- what blocker tokens are;
- how strict priority provides holding;
- how the ACK arms the deadline;
- how blocker termination releases the response;
- why the release has a stable implementation tail;
- how fail-open works;
- how G must be selected;
- what the mechanism does and does not conceal.

Also create a two-minute demonstration script and a five-minute technical
explanation script.

======================================================================
10. FINAL CLAIM DISCIPLINE
======================================================================

Allowed claim:

    On Tofino-1, the mechanism classifies real DNP3 transactions and converts
    the ACK-to-RESPONSE interval into a policy-controlled timing state by
    holding the original response in a Traffic Manager queue until a
    data-plane deadline. The implementation requires no controller action in
    the transaction fast path, emits no external blocker traffic, and
    substantially reduces the CLRT-magnitude fingerprint.

Do not claim:

- full device anonymity;
- size obfuscation;
- live inline relay tolerance unless physically tested;
- all DNP3 devices;
- all TCP configurations;
- production readiness.

State clearly that ACK mode and TCP-stack characteristics remain separate
fingerprinting channels.

======================================================================
11. FINAL DELIVERABLES
======================================================================

Deliver:

- dnp3_timing_normalizer.p4
- timing setup/read/runner scripts
- packet verifier
- fingerprinting analysis scripts
- TIMING_REFERENCE_IMPLEMENTATION.md
- TIMING_FINGERPRINTING_ANALYSIS.md
- TIMING_MECHANISM_EXPLAINED.md
- TIMING_FINAL_RESULT.md
- evidence/timing_final/
- final figures
- demonstration instructions
- final commit and tag

Suggested tag:

    timing-final-meeting-v1

======================================================================
12. AUTONOMY AND STOP CONDITIONS
======================================================================

Continue autonomously through:

- code audit;
- compile iterations;
- guard implementation;
- harness correction;
- synthetic validation;
- real-corpus replay;
- fingerprint analysis;
- evidence generation;
- documentation;
- figures;
- cleanup.

Do not resume size work this week.

Pause only for:

- physical recabling;
- physical relay actions beyond read-only polling;
- PFC;
- firmware or OS changes;
- unsafe unbounded token behavior;
- destructive repository actions;
- a requirement to send DNP3 control/write traffic.

Report first when:

- the reference implementation is identified;
- the G guard compiles;
- the final experiment plan is ready;
- any physical action requires authorization.