Resume branch at the latest verified commit and run only the existing
--shaper-sweep mode.

Do not rebuild unless required. If any binary or P4 artifact changes,
recompile and rerun all analyzer self-tests before touching the switch.

Use these preload acceptance conditions:

    pktgen trigger count        = 1
    pktgen packet count         = 128
    enqueued ABLOCK packets     = 32
    enqueued ACK packets        = 32
    enqueued RBLOCK packets     = 32
    enqueued RESP packets       = 32
    usage_cells(Q_ABLOCK)       > 0
    usage_cells(Q_ACK)          > 0
    usage_cells(Q_RBLOCK)       > 0
    usage_cells(Q_RESP)         > 0
    total_dequeues before release = 0
    queue drops                 = 0

Do not require sum(usage_cells)=128. usage_cells measures cells, not
packets.

Test exactly:

    PPS:1:0
    PPS:1:1
    PPS:0:0
    BPS:1:0
    BPS:1:1

Release using exactly one write:

    max_rate_enable = false

Record the timestamp immediately before and after that write and assert:

    release_writes = 1

For every setting:
- start from verified clean queues and zeroed trace state;
- run one screening trial;
- if it passes, run five consecutive confirmation trials;
- always execute cleanup from finally;
- refuse the next trial if any queue, trace register, counter or pktgen
  state remains dirty.

For every 128-packet drain require:

    total_dequeues         = 128
    trace_entries_written  = 128
    trace_overflow         = 0
    32 trace entries per role
    zero duplicate packet_ids
    zero stale trial_ids
    zero unknown roles
    zero queue drops

If no setting passes consistently:
- stop;
- preserve all five configurations as negative evidence;
- report that no tested dp8 shaper state established a reproducible
  zero-leak preload boundary;
- identify Q_GATE as the next construction;
- do not test additional shaper combinations.

Do not run controls A–D in this session.
This run is shaper characterization only.

Afterward restore and verify:

    p4_name=dnp3_timing_normalizer_pktgen
    strict_priority_verified=true
    app_enable=false
    dp8 shaper equals the pre-run snapshot
    all four oracle queues empty
    dp11 unchanged
    exactly one bf_switchd process

Return:
- result for all five configurations;
- screening and confirmation outcomes;
- pre-release dequeue count;
- per-queue occupancy;
- complete trace-integrity fields;
- cleanup result;
- restore verification;
- evidence paths and commit hash.