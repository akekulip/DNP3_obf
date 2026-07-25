# Part 11 — paired ACK-before-response: plan

Branch `research/ibspg-paired` (from Part 9 completion 90fdaa1). Part 9 files (`ibspg_controlled_drain*`)
frozen; all Part 11 work is new under `research/ibspg_paired/`. Tags: [DESIGN][DOC][COMPILED][OBS][REP][FIX][OPEN].

## Research question [DESIGN]
Can the validated controlled drain hold an **ACK** and a **RESPONSE** together during blocking and, on the
matching drain, release them so that **every ACK leaves before any RESPONSE** — byte-identically, to an
external host — while the Part-9 guarantees still hold (negatives reject, fail-open watchdog, generation
guard, blocker never escapes)?

## Design — three strict-priority levels on the dp8 loopback [DESIGN]
Extends `ibspg_controlled_drain.p4`. Splits the single held role into two ordered roles routed to two hold
queues, with a third strict-priority level providing the order structurally:

| queue | qid | max_priority | holds |
|---|---|---|---|
| Q_BLOCK | 7 | **7 (HIGH)** | recirculating blocker reservoir (K≥64) |
| Q_ACK   | 5 | **3 (MID)**  | ROLE_ACK (7) frames |
| Q_RESP  | 1 | **0 (LOW)**  | ROLE_RESP (2) frames |

During blocking the Q_BLOCK reservoir starves both hold queues. On the matching DRAIN, Q_BLOCK empties and
strict priority drains **all of Q_ACK before any of Q_RESP** (Part-3 max_priority result, extended to 3
distinct levels — a pure control-plane TM property). Released ACK/RESP forward to dp9=Vision, byte-identical.

New roles/queues: ROLE_ACK=7→Q_ACK(qid5); ROLE_RESP=2 (the former HOLD)→Q_RESP(qid1). BLOCK/ARM/DRAIN
unchanged. Ordering instrumentation: `reg_ts_last_ack_release` (overwrite) and `reg_ts_first_resp_release`
(write-if-zero); invariant **last_ack_release < first_resp_release**. Counters: ctr_ack_enq/release,
ctr_resp_enq/release. Stage budget: Part 9 is 11/12, so drop the Part-9 hold-admit ts registers to fit.

## Ordering proof (two independent witnesses) [DESIGN]
1. **On-chip:** `reg_ts_last_ack_release < reg_ts_first_resp_release` (every ACK dequeued before the first response).
2. **Host PCAP (Vision):** in the released capture, all ROLE_ACK records precede all ROLE_RESP records
   (max ACK index < min RESP index). Plus full-frame byte-identity of each role vs the reconstructed injected frames.

## Gate sequence [DESIGN]
- **11.1** compile+fit (local 9.13.1 + on-switch 9.13.2; ≤12 ingress stages).
- **11.2** TM readback: Q_BLOCK max_priority=7 > Q_ACK=3 > Q_RESP=0, all scheduling-enabled, shaping off, one bf_switchd.
- **11.3** forwarding (no blocker): inject ACK+RESP → both forward to Vision, byte-identical, exact count.
- **11.4** budget-expiry fail-open: K=64 + ACK+RESP, no drain → timeout releases both, ACK-before-response preserved.
- **11.5** negatives: unrelated + stale-gen drains → no release of either queue.
- **11.6** matching drain, 1 ACK + 1 RESP: held (0 release during blocking) → DRAIN_MATCH → ACK released
  before RESP (on-chip ts + host order), both byte-identical, `drain_match=1`, `timeout=0`.
- **11.7** matching drain, N ACK + M RESP (e.g. 4+28, 16+16): all N ACK before all M RESP; byte-id; FIFO within each role.
- **11.8** duration sweep (hold 0/20/100/500 ms) — ordering holds across durations; watchdog budget > hold.
- **11.9** repetition 30/30 then 100/100 randomized (ACK/RESP counts, sizes, ids, hold); PASS = both byte-id
  + ACK-before-response + counts + no-timeout.
- **token isolation**: blocker never on dp9/dp11/hosts.

## Causal controls [DESIGN]
K=0 (both drain immediately, ACK still before RESP by priority) · K=64 no-drain (both held) · unrelated →
no release · stale-gen → no release · match → ordered release · LOW/LOW/LOW diagnostic (ordering collapses)
→ restore 7/3/0 (ordering returns).

## Safety / restore
Same as Part 9: restore `queue_microbench_abs.conf`; verify one bf_switchd/ASIC/hosts; Vision retains
192.168.10.1; no residual processes. dp9=Vision capture, dp11=Hulk inject, dp8 MAC-near loopback. Do not
touch SEL/DNP3 writes/PFC/reboots/firmware/unbounded blocker.

## Earned claim (after PASS) — will state only then
"On Tofino-1 the controlled drain releases a held ACK before its held response, byte-identically and in
order, to an external host; ordering is a structural strict-priority property (Q_BLOCK>Q_ACK>Q_RESP)."
Not claimed: real DNP3 CLRT-interval normalization (that is a later part), concurrent slots, physical SEL.
