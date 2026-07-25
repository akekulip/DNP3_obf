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

## Status
- [COMPILED] 11.1 · [OBS] 11.2 3-level · 11.3 · 11.4 fail-open · 11.5 negatives · 11.6 · 11.7 ·
  structural(resp-first) · causal-control · 11.8 duration · token-isolation — **all PASS**.
- [OPEN] 11.9 repetition campaign (30/30 then 100/100 randomized) — running.
