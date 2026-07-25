# Part 11 — paired ACK-before-response: result

Branch `research/ibspg-paired` (from Part 9 completion 90fdaa1). Tags: [DESIGN][COMPILED][OBS][REP][FIX][OPEN].

## Mechanism [DESIGN]
Extends the validated Part-9 controlled drain. Two held roles routed to two hold queues under a third
strict-priority level on the dp8 loopback: **Q_BLOCK qid7 (max_priority 7) > Q_ACK qid5 (3) > Q_RESP qid1
(0)**. During blocking the K≥64 blocker reservoir starves both hold queues; on the matching drain Q_BLOCK
empties, then strict priority drains **all of Q_ACK before any of Q_RESP** → ACK-before-response is a
structural control-plane property. `ibspg_paired.p4` (SHA `9feae154`): ACK=role7→Q_ACK, RESP=role2→Q_RESP,
both released to dp9=Vision byte-identical; ordering timestamps `reg_ts_last_ack_release` /
`reg_ts_first_resp_release`.

## Gate results [OBS] — all PASS
| Gate | Setup | Result |
|---|---|---|
| **11.1** compile+fit | local 9.13.1 + on-switch 9.13.2 | 0 errors, **12/12 stages** fit, SHA identical |
| **11.2** TM 3-level | set Q_BLOCK/Q_ACK/Q_RESP | max_priority **7 > 3 > 0**, `strict_priority_verified=true` (MID=3 programs on silicon) |
| **11.3** forwarding | K=0, 8 ACK + 8 RESP | both forward to Vision, byte-id, `abr=true` |
| **11.4** fail-open | K=64, 4+28, no drain, budget 600K | `tmo=1` (timeout), all released, byte-id, **ordered `abr=true`** |
| **11.5a** unrelated | K=64, drain slot 9 | `arel=0, rrel=0` — **no release** either queue (`ru=1`) |
| **11.5b** stale gen | K=64, drain gen 6≠7 | `arel=0, rrel=0` — **no release** (`rs=1`) |
| **11.6** 1 ACK + 1 RESP | K=64, match | held → `arel=1, rrel=1`, `dm=1`, verify **PASS**, `abr=true`, gap 26 ns |
| **11.7** N ACK + M RESP | K=64, 4 + 28, match | `arel=4, rrel=28`, all 4 ACK before all 28 RESP, verify **PASS**, gap 26 ns |
| **11.8** duration sweep | K=64, 4+28, hold 0/20/100/500 ms | all verify **PASS**, `abr=true`, gap 25–29 ns consistent |

### The structural proof [OBS] — the crux of Part 11
**Injecting RESP FIRST, then ACK** (K=64, 4 ACK + 28 RESP, match): the ACK **still releases first** —
`abr=true`, gap 27 ns. So ACK-before-response is a strict-priority property, **not arrival/FIFO order**.

### Causal control [OBS]
- Q_ACK=LOW (=Q_RESP, only 2 distinct levels): ordering **collapses** — `order_ts=BAD`, `abr=false`, a
  response releases before the last ACK (DWRR interleave). `strict_priority_verified=false`.
- Restore Q_ACK=3: `strict_priority_verified=true`, `abr=true` returns.
- This proves the third strict-priority level is the **sole** mechanism producing the ordering (the Part-3
  max_priority finding, at three levels).

### Token isolation [OBS] PASS
During a K=64 paired hold, incoming blocker frames (0x88c1 / private src) at Vision=0 and Hulk=0.

### Ordering latency (on-chip ns)
`reg_ts_first_resp_release − reg_ts_last_ack_release` ≈ **26–29 ns** across all drain trials — the gap
between the last ACK and the first response, i.e. the strict-priority handoff time.

## Gate 11.9 — repetition campaign [REP] PASS
100 randomized matching-drain trials (K=64), varying ACK count {1,2,4,8}, RESP count {8,16,24,28}, hold
{0,20,100,300 ms}, size {60,100,150 B}, **and injection order {ack-first, resp-first}**: **100/100 PASS,
0 failures**. Injection-order coverage: 50 ack-first + 50 resp-first — all pass, so the ACK-before-response
ordering holds regardless of arrival order (structural). Ordering handoff gap
(`reg_ts_first_resp_release − reg_ts_last_ack_release`): min 25, median 40, p95 57, max 58 ns.

## COMPLETION — Part 11 gate sequence PASS
11.1 compile+fit (12/12) · 11.2 3-level priority (7>3>0 on silicon) · 11.3 forwarding · 11.4 fail-open
(ordered) · 11.5 unrelated+stale negatives (no release) · 11.6 1+1 · 11.7 N+M · structural(resp-first) ·
causal-control (Q_ACK=LOW collapses ordering) · 11.8 duration sweep · 11.9 100/100 reps · token
isolation — **all PASS**.

### Earned claim
*On Tofino-1 the controlled drain releases a held ACK before its held response — byte-identically, in
order, to an external host — and the ordering is a structural strict-priority property
(Q_BLOCK 7 > Q_ACK 3 > Q_RESP 0): it holds even when the response is injected before the ACK, and
collapses to interleave when the ACK/RESP priority gap is removed. The Part-9 guarantees carry over
unchanged (matching drain releases, unrelated/stale reject, fail-open watchdog, K≥64 reservoir hold,
blocker never escapes to a host).* The ACK→RESPONSE strict-priority handoff is ~25–58 ns.

### Not claimed (out of Part 11 scope)
Real DNP3 CLRT-interval **normalization** (releasing the response a fixed interval after the ACK — a later
part); DNP3 integration (Part 13); concurrent slots; physical SEL; production readiness.

**Next gate: Part 13 (DNP3 integration, replay first) or a CLRT-interval-normalization part — gated on Philip.**
