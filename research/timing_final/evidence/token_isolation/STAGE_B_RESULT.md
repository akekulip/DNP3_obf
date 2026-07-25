# Stage B — protected campaign result (directive §5)

Real SEL-751 frames (data_offset=8, byte-for-byte) replayed through the loaded D1-fixed
`dnp3_timing_normalizer` (sha 82f572ce), two-sided (READ from Vision/dp9, ACK+RESPONSE from
Hulk/dp11, blocker tokens with per-txn gen 0xC0..). Switch config: `--prog dnp3_timing_normalizer`,
no `--paired`, strict priority verified, no Q_BLOCK shaper (review C1-C3). Every gate below is the
review's hardened criteria (C4/W5): all tokens deadline-terminated, zero fail-open, zero stale.

## G-sweep (30 trials each; back-to-back injection → interval driven entirely by the deadline)

| G (ms) | wire CLRT median | sd | tokens enq | all deadline-term | fail-open | stale |
|---:|---:|---:|---:|:---:|:---:|:---:|
| 5  | 4.998  | 0.007 | 1920 | yes (1920) | 0 | 0 |
| 10 | 9.996  | 0.009 | 1920 | yes | 0 | 0 |
| 17 | 16.997 | 0.010 | 1920 | yes | 0 | 0 |
| 20 | 19.998 | 0.007 | 1920 | yes | 0 | 0 |
| 25 | 24.997 | 0.014 | 1920 | yes | 0 | 0 |
| 40 | 39.999 | 0.011 | 1920 | yes | 0 | 0 |

The emitted interval equals the policy G to within ~2 µs at every target, sd ~10 µs.

## Final G = 25 ms — 100 repetitions (headline)

- arm=100, ack_arm=100, ack_bypass=0, resp_enq=100, resp_release=100.
- ctr_block_enq=6400, **ctr_block_term_deadline=6400** (all tokens), timeout=0, stale=0.
- ctr_response_actually_held=100, ctr_release_deadline=100, **ctr_release_fail_open=0**.
- Wire CLRT: **median 24.999 ms, sd 0.010 ms, p99 25.024, range 0.082**, 100/100 clean.
- Leakage: **0.000 bits @1 ms**, 0.366 bits @50 µs (protected).
- tshark cross-check median 24.998 ms — **agrees within 0.715 µs**.
- Isolation: 200 frames at Vision (100 ACK + 100 RESP), **0 blocker (0x88c1) frames**.
- **All review gates PASS.**

## G-selection guard demonstration (§3) — native-timed responses (~2 ms median)

With the outstation-side injector reproducing the real per-transaction native CLRT:

| G (ms) | vs native (2.08 ms) | actually_held | zero_hold (low-G) | verdict |
|---:|---|:---:|:---:|---|
| 1  | below native | 0 | **30** | guard fires — protection NOT applied, low-G warning on all 30 |
| 25 | above native | **30** | 0 | protection applied on all 30 |

This is the directive's "explicit detection when configured G is too low," demonstrated on silicon:
a G below the native interval yields zero hold and the guard flags every transaction, rather than
silently pretending normalization occurred.

## Before / after (headline)

| | native (Stage A, physical relay) | protected (G=25 ms) |
|---|---:|---:|
| CLRT median | 2.034 ms | 24.999 ms |
| CLRT sd | 10.33 ms (heavy tail) | **0.010 ms** |
| leakage @50 µs | 4.44 bits | 0.37 bits |
| leakage @1 ms | 2.32 bits | **0.000 bits** |

Artifacts: `protected/sweep_g{5..40}.{pcap,read.json}`, `protected/final100_g25.*`,
`g_guard/{lowg_g1,protnative_g25}.read.json`, `native/native*`.
