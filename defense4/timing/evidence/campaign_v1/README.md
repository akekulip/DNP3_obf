# campaign_v1 — frozen READ + SBO timing dataset

Real-hardware DNP3 timing dataset collected by explicit direction to replace the single-session
evidence with a session-structured, provenance-frozen corpus. One SEL-751A, one Tofino-1, master-
facing capture. **No simulation, no replay, no synthetic timing.** The older single-session
evidence in `../final_read_sbo/` is left unmodified; this tree is the v1.0 dataset.

## Design (per the campaign spec)

- **Independent sessions.** Each `sNN/` is one session (session-disjoint train/val/test at analysis
  time: 4 train / 1 val / 1 test once ≥6 sessions exist, across ≥3 days).
- **Two arms, same binary.** `native` = timing OFF (mode 0); `obfuscated` = timing ON (mode 4,
  D_A=20 ms, D_R=4 ms, A=20 ms, R=24 ms, J∈{2,6,12} ms). `shape_enable=0` in **both** arms
  (timing-only; verified on the wire — single 49-byte payloads, no size split).
- **Interleaved READ + SBO, spaced.** 400 READ + 40 SBO per block, SBO slots ≥6 reads apart,
  20 ms inter-transaction gap. One advancing DNP3 application sequence per session socket.
- **Randomized block order**, reconfigured per block; seeds frozen (see `MANIFEST.json`).
- **Guarded control point.** SELECT/OPERATE restricted to DNP3 indices {1,3} = remote bits
  RB02/RB04, which the relay's own settings audit proves drive **no** output. Operates complete at
  the protocol layer (SUCCESS) and move no contact. Index 6 (RB07 → breaker close) is refused at
  frame construction.
- **Failures preserved.** Every transaction is logged with its status; nothing is filtered.

## What each session holds

```
sNN/
  raw_pcaps/   sNN_bK_{native,obfuscated}.pcap   master-facing (host 192.168.10.7 tcp)
  app_jsonl/   sNN_bK_{native,obfuscated}.jsonl  one row per transaction, full schema
  provenance/  MANIFEST.json  DATASET.sha256  TIMING_SUMMARY.json
  tools/       campaign_run.py  campaign_block.sh  extract_clrt.py  sbo_v2.py
```

JSONL row schema: `session_id, block_id, condition, mode, j_ms, txn_id, step, operation
(READ|SELECT|OPERATE), function_code, app_seq, resp_func, status, valid, t_send, t_recv, rtt_ms`.

## s01 result (master-facing CLRT / OPERATE echo−ACK, medians)

| arm | READ | SELECT | OPERATE | CLRT SD |
|---|---|---|---|---|
| native (b1,b4,b6) | 2.10–2.12 ms | 1.56–1.82 ms | 2.86–2.92 ms | ~2.6–2.9 ms (heavy tail) |
| obfuscated (b2,b3,b5) | 4.000 ms | 4.000 ms | 3.998–4.000 ms | ~0.01 ms |

Native: the three transaction classes sit at distinct timings (separable — the fingerprint).
Obfuscated: all collapse to 4.000 ms with variance crushed ~250×; the outstation ACK is pinned to
the configured anchor (~21.3 ms READ/SELECT, ~20.6 ms OPERATE). This is the master-visible
transaction-class timing feature being suppressed, control path included.

## Reproduce a session

`tools/campaign_block.sh <session> <blockid> <OFF|D4> <n_read> <n_sbo> <seed>` drives one block:
configure the chip (readback), force shape=0, capture master-facing, run the interleaved driver.
It reads the lab sudo password from `~/.lab_env` at run time (no secret is stored in the repo).

## Remaining sessions (schedule)

s01 done 2026-08-27. For the paper dataset, collect s02…s06 (≥6 total) spread across ≥3 calendar
days, same block script, distinct seeds per block, so sessions are genuinely independent for the
session-disjoint split. Extend to s07–s10 if the classifier needs more test power.

## Collection complete — 22 sessions (2026-08-27..28)

5-hour automated run (`_bin/campaign_5h.sh`, one session every ~13 min). Full rollup in
`DATASET_ROLLUP.json`.

- **22 sessions** s01..s22, **132 pcaps + 132 JSONL**, 40 MB, all sha256-verified.
- **63,360 transactions**: 52,800 READ, 5,280 SELECT, 5,280 OPERATE. **0 anomalies** (no drop,
  timeout, NO_SELECT, malformed, or invalid response anywhere).
- Per-arm CLRT median over 66 block-medians per arm:
  - READ: native 2.118 ms [2.090..2.152], obfuscated 4.000 ms [3.999..4.001]
  - SELECT: native 2.046 ms [1.105..2.350], obfuscated 4.000 ms [3.998..4.002]
  - OPERATE echo-ACK: native 2.942 ms [2.858..4.040], obfuscated 4.000 ms [3.997..4.002]
- Native keeps the three transaction classes separable and heavy-tailed; obfuscated pins all
  three to 4.000 ms with the spread collapsed. The native min/max show the real per-block tail
  variation (e.g. a low SELECT block median ~1.1 ms, a high OPERATE block median ~4.04 ms); these
  are captured as-is, never filtered.
