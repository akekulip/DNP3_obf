# Part 9 — controlled data-plane drain: experiment plan

Branch `research/ibspg-controlled-drain` (from positive-result checkpoint 4775503). Frozen Part-1..8
files and the ring oracle are NOT modified; all Part-9 work is new files under
`research/ibspg_controlled_drain/`. Tags: [DESIGN] [DOC] [COMPILED] [OBS] [REP] [FIX] [OPEN].

## Research question [DESIGN]
Can a matching data-plane DRAIN event deliberately terminate the internal blocker and release the
queue-resident HELD packets at a selected time, while: an unrelated event does nothing; a
stale-generation event does nothing; no HELD leaks before the match; pass-budget expiry remains an
independent fail-open watchdog; every held packet is forwarded to an observable output byte-identically
and in FIFO order; the blocker never reaches a protected external link; and all state/tokens terminate
cleanly. The release must be actuated entirely by packets + data-plane state — the control plane may
load/configure-static-priority/reset-counters/read-evidence only, never perform the release.

## Validated starting primitive (Parts 3/6/8, do not re-litigate) [OBS/REP]
Corrected `max_priority` HIGH(Q_BLOCK)/LOW(Q_HOLD); one recirculating blocker on dp8 MAC-near loopback
holds 32 HELD with 0 leakage across ~400 loops and releases all 32 intact when it stops
(held-then-released, transitions=1, 15/15). K=0 control drains freely. Loop RTT ≈ 408 ns (403–415).
Release is currently pass-budget expiry — Part 9 replaces that with a deliberate drain.

## Design — one synthetic slot (slot 0), generation-guarded [DESIGN]
Header `ibspg_h{role,slot,gen,seq}` already carries slot+gen+budget. Per-slot registers:
`reg_active`, `reg_gen`, `reg_drain_req` (each a single metadata-driven RegisterAction).

State machine:
```
IDLE --ARM(slot,gen)--> BLOCKING --DRAIN_MATCH(slot,gen)--> DRAINING --> RELEASING --> IDLE
```
- **ARM (role 6)**: active=1, gen=G, drain_req=0; drop (consumed).
- **BLOCK fresh (from dp9)**: enqueue Q_BLOCK.
- **HOLD fresh (from dp9)**: enqueue Q_HOLD.
- **BLOCK looped-back (ingress==dp8)**: read drain_req, gen, active. TERMINATE (drop + active←0) iff
  `active==0 || gen≠current || drain_req==1 || seq==0`; else LOOP (seq−1, re-enqueue Q_BLOCK).
  Termination counters split: controlled (drain_req) / timeout (seq==0) / stale (active==0 or gen≠).
- **DRAIN_M (role 3)**: valid iff active==1 && slot==0 && gen==current → drain_req←1 (ctr_drain_match);
  else reject (ctr_drain_reject_stale | ctr_drain_reject_unrelated); drop.
- **DRAIN_U (role 4)**: non-matching slot → reject (ctr_drain_reject_unrelated); drop.
- **HOLD looped-back = RELEASED**: forward to dp9 (ucast_egress_port=dp9, bypass_egress=0), byte-preserved,
  no drop/no re-enqueue (ctr_hold_release).

**Recording is SPARSE (not per-loop):** Counter externs for tallies; fixed-slot timestamp registers per
event type (`reg_ts_first_block/drain_match/block_term/first_release/last_release`, write-if-zero for
"first", overwrite for "last"). No monotonic 512-trace — ms holds are millions of loops.

**Recording decoupled from blocker mode** (fixes the Part-8 ambiguity): blocker lifetime and timestamp
capture are independent; stopping the blocker does not stop recording.

## Latency metrics [DESIGN]
drain-recognition = t_block_term − t_drain_match; scheduler-release = t_first_release − t_block_term;
end-to-end = t_first_release − t_drain_match; burst = t_last_release − t_first_release. Report
min/median/mean/p95/p99/max/jitter, related to the 408 ns loop RTT. Distinguish drain ingress →
register visibility → next blocker return → termination → Q_HOLD eligibility → egress.

## Gate sequence (run in order; do not skip) [DESIGN]
- **9.1 Compile + resource fit** — local bf-p4c 9.13.1 then on-switch 9.13.2; record SHA-256, errors,
  stages, SRAM/MapRAM/TCAM/SALU/PHV/gateways, table placement, pass-budget path proven in review.
- **9.2 TM readback** — Q_BLOCK qid7 max_priority=HIGH, Q_HOLD qid1 LOW, same scheduler domain, Q_BLOCK
  shaping disabled, both scheduling-enabled, no stale port shaping, exactly one bf_switchd. Fail loud.
- **9.3 No-blocker forwarding control** — 1 then 32 HELD, no blocker: all forward, exact count, byte-id,
  FIFO. Proves the new external-forward path before blocking.
- **9.4 Budget-expiry regression** — 1 blocker + 32 HELD, no drain, small budget: 0 premature release,
  timeout terminates, all 32 release after, externally captured, byte-id, FIFO.
- **9.5 Unrelated + stale-generation negative controls** — neither releases; only the correct match does.
- **9.6 Matching drain, H=1** — no release before drain; controlled_term=1, timeout=0; 1 released byte-id;
  no escape; slot→IDLE.
- **9.7 Matching drain, H=32** — event order ARM/BLOCK/HOLD×32/DRAIN_MATCH/TERM_CONTROLLED/RELEASE×32;
  0 before drain; 32/32 after; FIFO; 0 dup/corrupt/missing; no blocker on dp9/dp11; no timeout.
- **9.8 Hold-duration sweep** — 0.1/1/5/10/12.9/20 ms (12.9 ms = Case-A CLRT target). Watchdog budget >
  requested duration with margin; do NOT exceed proven budget-field width (prove width or widen it).
- **9.9 Repetition** — 30/30 then 100/100, randomized hold/HELD-count/size/ids/drain-timing. One
  premature release / missing / dup / corrupt / stale-release / escape / cleanup-fail = failed trial +
  root cause.

## Causal controls (change one variable) [DESIGN]
K=0 drains; K=1 no-drain holds to watchdog; K=1 unrelated → no release; K=1 stale-gen → no release;
K=1 match → controlled release; LOW/LOW diagnostic → no strict hold; restore HIGH/LOW → hold returns.

## Fail-open [DESIGN]
Match = normal path (release_reason=MATCHED_DRAIN, timeout=0). Watchdog = safety path
(release_reason=TIMEOUT, controlled=0). Prove both independently; timeout must terminate blocker,
release Q_HOLD, clear state, leave no residual token.

## Isolation [DESIGN]
Blocker marker never on dp9/dp11/Vision/Hulk; terminates internally; none residual. Switch counters
AND host captures — not one alone.

## Evidence [DESIGN]
Per accepted run under `evidence/part9/<run-id>/`: program SHA-256, compiler logs, resource report, TM
readback JSON, params, register+counter dump, sparse event trace, Vision/Hulk PCAP, verify JSON,
cleanup report, git commit, datetime, switch+SDE versions, `manifest.json` reconciling
injected = released + dropped + terminated-internal-tokens + resident + unexplained (final: unexplained=0).

## Safety / restoration (every hardware run) [DESIGN]
Restore `queue_microbench_abs.conf`; verify one bf_switchd, ASIC attached, switch 10.10.54.81, Vision
10.10.54.19 (+192.168.10.1), Hulk 10.10.54.158, no residual pktgen/replay/capture/blocker/probe;
record final counters + git status. Do NOT touch SEL / DNP3 writes / PFC / reboots / mgmt net / firmware
/ unbounded blocker / remove watchdog.

## Completion → stop at the Part 11 gate
All of: corrected max_priority readback; 1 blocker; queue-resident hold; 0 leakage before match;
unrelated & stale → no release; match terminates blocker; all release after; exact external count;
full-frame byte identity; FIFO; independent timeout/fail-open; no escape; no residual; 30/30 then
100/100; raw evidence committed; switch restored. Then report; do NOT start paired ACK/response (Part 11)
or DNP3 integration (Part 13).
