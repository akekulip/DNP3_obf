# LIVE_DEMO_RESULT.md — end-to-end demo on real Tofino-1 (2026-07-25)

The authorized live on-switch demonstration ran end to end on the physical testbed: the timing
normalizer was loaded onto the Tofino-1, real replay traffic was injected from Vision and Hulk,
native and protected transactions were captured and verified, and the switch was restored. This is
a **live on-silicon run**, distinct from (and corroborating) the §5 replay campaign.

Evidence level: real replayed DNP3 frames through the loaded `dnp3_timing_normalizer` program on the
Tofino-1 data plane (not a synthetic-marker or dry-run result). Master 192.168.10.1, outstation
(relay path) 192.168.10.7, G = 25 ms. The replay corpus supplies n = 30 transactions per condition
(the run was requested with 50 trials; the corpus caps at 30).

## Result (n = 30 per condition — the committed live_demo/ evidence)

| quantity | native (mechanism bypass) | protected (hold, G=25 ms) |
|---|---:|---:|
| CLRT median | 1.979 ms | 25.001 ms |
| CLRT std dev | 0.0076 ms | 0.0104 ms |
| CLRT p99 | 2.004 ms | 25.031 ms |
| transactions | 30 (30 clean, 0 ambiguous) | 30 (30 clean, 0 ambiguous) |

(An earlier n = 10 run gave native 1.970 / protected 24.998 ms — consistent.)

Verifier (`08_verify.py`, mode hold_resp) — **VERIFICATION: PASS**, all gates:

- Transactions 30 · Responses released 30 · Mean/median ACK→RESP 25.0023 / 25.001 ms
- **Unmatched frames 0** (byte-identity) · **External blocker frames 0** (token isolation)
- C4_reservoir_depth_ge_64 (K=64) · W5_block_term_timeout_zero · C4_release_fail_open_zero
- W5_release_deadline_eq_nresp (30) · W5_block_term_deadline_eq_nresp_times_k (30×64)
- resp_enq_eq_nresp (30) · resp_release_eq_nresp (30) · W4_no_unmatched_dnp3_frames (0)
- isolation_no_token_escape (0) · base_p13_verify PASS

## Switch restoration

`12_restore.sh` → **RESTORATION: PASS** — bound to `queue_microbench`, exactly one bf_switchd,
switch/Vision/Hulk reachable, Vision retains 192.168.10.1. See `restoration_report.txt`.

## Files

- `native_demo.pcap` / `protected_demo.pcap` — the live captures
- `native_summary.json` / `protected_summary.json` — analyzer output
- `protected_verify.json` — verifier verdict + gates
- `figures/` — CLRT native-vs-protected, timeline, leakage (from the live pcaps)
- `demo_run.log` — the full `demo_all.sh` run log
- `restoration_report.txt` — the post-demo restoration verification

## Note on the lab scripts

The automated live path in `demo_all.sh` had only ever been exercised in dry-run before this session;
running it live surfaced seven latent script bugs (bf_switchd-count parse, remote-vs-local sudo
password, `logcmd` stdout pollution, `sw()`/sudo single-quote nesting, unquoted capstate filter, and
two `pkill -f` self-kills). All are fixed and committed; this run is the result after those fixes.
The mechanism itself was unchanged and was already proven by the §5 campaign — this live run
corroborates it on hardware.
