# IBSPG post-fix experiment plan (Part 1)

Dated addendum to the confirmed root-cause work (`IBSPG_ROOT_CAUSE_AND_REPAIR_REPORT.md`,
`IBSPG_EXPERIMENT_FORENSIC_LEDGER.md`, `IBSPG_ROOT_CAUSE_TREE.md`,
`TOFINO1_STRICT_PRIORITY_SEMANTICS_AUDIT.md`). No historical report is modified.

## Confirmed root cause (locked, not re-litigated)
The prior IBSPG failure was a **scheduler-configuration error**: `Q_BLOCK.min_priority=HIGH` with
`min_rate_enable=false` (so min_priority — the guaranteed-bandwidth pass — was inert), while
`Q_BLOCK.max_priority` and `Q_HOLD.max_priority` both stayed at the default LOW and both queues kept
equal `dwrr_weight=1023`. The **active remaining-bandwidth pass** therefore treated them equally → a
fair split → Q_HOLD serviced. `max_priority` is the correct active strict-priority field.

## Exact corrected fields (verified on silicon)
- `Q_BLOCK.max_priority = HIGH` (readback `7`), `Q_HOLD.max_priority = LOW`. Applied in
  `ibspg_setup.py:set_pri` (now writes AND verifies `max_priority`). Confirmed by `ibspg_tm_readback.py`
  on both dp8 (pg2) and recirc (pg17). Q_BLOCK max-shaper left DISABLED (a shaped high queue is
  ineligible between credits and yields to the low queue — established).

## The active scheduler pass
Remaining-bandwidth (excess) arbitration, ordered by `max_priority`; DWRR is a tie-break among *equal*
`max_priority`. min_priority/min_rate stay disabled (not used).

## Remaining unknowns (the narrowed problem — NOT the retired config claim)
- **U1 — dequeue ORDER at µs scale:** does corrected `max_priority=HIGH` make ALL backlogged Q_BLOCK
  packets dequeue before any Q_HOLD packet? (ssh polling can't see this; needs the on-chip oracle.)
- **U2 — blocker-loop timing:** the self-replenishing ring's dequeue→re-enqueue RTT, jitter, token
  spacing, synchronization, loss, per N.
- **U3 — empty-gap cause:** does Q_BLOCK become temporarily empty, and why (RTT>service-interval,
  too few tokens, burst synchronization, shaping credit, token loss, budget expiry)?
- **U4 — a blocker construction that keeps Q_BLOCK continuously non-empty at bounded cost.**
- **U5 — end-to-end no-drain hold, matched drain, timeout, paired ACK-before-response.**

## Planned causal experiments + evidence to close each unknown
| # | Experiment | Closes | Decisive evidence |
|---|---|---|---|
| P2 | on-chip dequeue-order oracle (`ibspg_dequeue_oracle.p4` + `ibspg_trace_read.py`) | tooling for U1/U5 | compiles; bounded trace; overflow ctr |
| P3 | **finite-backlog A/B/A** (equal→corrected→reversal), NO ring, oracle-traced, 30 reps | **U1** | trace = `BLOCK…BLOCK HOLD` under HIGH; interleaved under LOW; reversal returns |
| P4 | blocker-loop timing, instrumented tokens, N∈{1,2,4,8,16,(32)} | U2 | RTT min/max/mean/sd/p95, token loss, Q_BLOCK min depth |
| P5 | empty-gap model `N_safe > max_RTT/min_service_interval + jitter` | U3 | measured, then experimentally validated (not equation alone) |
| P6 | 4 corrections: phased / preloaded-reservoir / dual-bank / upstream-paced | U4 | Q_BLOCK min-depth never 0; premature-HELD-release=0 |
| P7 | shaping causal study (placement as isolated variable) | U4 | eligibility vs occupancy per placement |
| P8 | no-drain hold (1/5/10/50/100 ms), 30→100 trials | U5 | Q_HOLD usage>0, 0 dequeue in trace, releases on cleanup |
| P9 | matched-drain (unrelated no-release, matched release), 30→100 | U5 | drain-to-release latency/jitter, 0 premature |
| P10 | timeout / fail-open | U5 | bounded release, state+token cleared, telemetry |
| P11 | paired ACK-before-response (+ 2 slots) | U5 | oracle proves ACK before RESPONSE by FIFO |
| P12 | HOLD_RESPONSE branch (TEST_ONLY timing) | U5 | established-before-admit, release on deadline |
| P13 | DNP3 integration (replay first, NO physical SEL) | integration | parser-hardened classifier + slot/gen |

## Gate discipline
Do not touch the blocker ring (P4+) until P3 resolves strict-priority ordering. Do not integrate DNP3
until the synthetic paired-buffer passes. Every token carries pass-budget + generation + private marker
+ a cleanup path. Restore `queue_microbench_abs.conf` after every hardware experiment. Language per the
claim-control list (no impossibility/pivot claims).

## Testbed (locked)
Switch 10.10.54.81 (SDE 9.13.2), restore target `queue_microbench_abs.conf`. Vision/master=dp9=dir0
(10.10.54.19, relay 192.168.10.1); Hulk/outstation=dp11=dir1 (10.10.54.158). Loopback L candidates:
recirc dp68 (pg17, deep backlog achievable) or physical dp8 MAC-near (pg2). Physical SEL untouched.
