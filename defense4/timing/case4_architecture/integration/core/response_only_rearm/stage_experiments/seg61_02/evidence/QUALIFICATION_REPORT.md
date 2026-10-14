# candidate61 qualification report (2026-10-14)

Candidate: `seg61_02/evidence/full_04/response_only.p4`, SHA256 `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`, built with SDK 9.13.2 (bfrt `e32df204…`), N11/E12/T11. Branch `implement/seg61-qualified-20261014`, not pushed, no defaults promoted. All hardware runs used the software endpoints on Vision; no relay OPERATE was sent. Every block ended with a verified restore (production swap, port replay, relay slot, Vision offloads and profile, ping), and production `case4_response_path` was observed afterwards.

## Result

The candidate passed every gate in `rearm_01/PLAN.md` steps 1 to 4 on silicon. With size padding on, READ, SELECT and OPERATE responses each reach the master as one 61-byte TCP segment. READ is a single DNP3 frame; SELECT and OPERATE are three frames of 28, 19 and 14 bytes. Application content and every CRC are intact. Release precision matches the strict comparison build.

| Step | What ran | Outcome | Evidence (`hw_campaigns/`) |
|---|---|---|---|
| 1 | Offline verification, config regeneration, validator rejection on all four entry points | 715 tests pass; configs byte-identical and hash-bound | commits `3caa4892a`…`a541ddfa8` |
| 2 | Four-arm smoke | Pass: off/timing_only 49/37/37, size_only/combined 61/61/61 | `candidate61_fourarm_smoke_03` |
| 3 | Persistence (graceful, RST), 7 single-loss classes, reconnect, stale tokens, external replay, held-OPERATE duplicate | All pass | `persistence_*`, `loss_core_950_01`, `reconnect_950_02`, `stale_tokens_950_02`, `old_external_950_01`, `held_operate_350_01` |
| 4 | Three rotated blocks x 4 arms x 500 READs at 59,570 PPS / 950 us, matched strict blocks, piggyback, 14,892 vs 59,570 PPS | Done; see below | `candidate61_eval_*`, `strict_comparison_*`, `candidate61_piggyback_*`, `candidate61_compare_*`; `STEP4_RESULTS.md` |

## Timing (step 4, pooled over three blocks, 1,500 READs per arm)

| Build / arm | Median error | p99 abs error (95% CI) | Over 100 us |
|---|---:|---:|---:|
| candidate61 timing_only | +3 us | 54 us (49–84) | 4 |
| candidate61 combined | +7 us | 51 us (51–52) | 3 |
| strict timing_only | +5 us | 65 us (64–67) | 5 |
| strict combined | +7 us | 51 us (47–62) | 7 |

The 100 us p99 bound is provisional and is not a maximum-error guarantee. At 14,892 PPS the combined arm's p99 is 147 us (47 of 150 READs over 100 us), with about 3.3 times fewer internal packets than at 59,570 PPS (p99 90.5 us, none over). The over-bound READs are ~1.1 ms events that accrue between Vision's transmit and receive taps, in the NIC, the link or the Tofino. They occur in untimed arms and equally in the strict build, so they do not come from the hold or the encoding. Which component adds them is undetermined; they recur about every 128 exchanges.

## Independent checks

- An evidence audit re-derived segment lengths, frame layout, every CRC, CLRT statistics and the off-arm tails from the raw captures with its own parser. Every number reproduced. It corrected one written inference: the earlier statement that the tails "originate at the endpoints" was wrong and has been replaced.
- A cold code review of the branch found no blocker. Its MAJOR finding was fixed: the evidence exceptions in `.gitignore` had un-ignored credential file names inside those folders, so the credential patterns are now re-asserted after the exceptions. Five MINOR findings were fixed: the precision deferral is now visible in `standards.json`, calibration readiness is recorded, SBO pairing and growth handling in the report tool are corrected, and dead code is removed.

## Failures retained, all harness defects fixed on the branch

`fourarm_smoke_01` (argv-list capture command), `fourarm_smoke_02` (calibration capture terminated before its buffer flushed), `reconnect_950_01` (c2 checked on c1's port), `stale_tokens_950_01` (missing Vision source pin; calibration delay pushed c2 past the old tokens), `compare_14892_950_01` (precision-only failure re-flagged as a hard standards failure). None was a data-plane fault.

## Limits and open items

- SBO timing has three samples per arm (one cycle per connection). Repeated SBO cycles were not run.
- Callbacks, switch counters, SELECT authorization and restore cannot be checked from the captures; they rest on the endpoint and switch records.
- Not yet done: the source of the transit-path tail, real-relay compatibility and default promotion.
- Review follow-ups not done: the checker's echoed fields are self-attested (`run_standards_checker`). The test fakes in `test_campaign_run.py` are installed on the class at import time, not per test. The production `clrt_check`-to-exchange path has no unit test.
- Equal 61-byte payloads do not hide plaintext object contents or the one-versus-three DNP3 link-frame structure, so these results do not establish fingerprint resistance.
- The code changes after the hardware runs only adjust what is recorded and reported: precision deferral is now visible, calibration readiness is recorded, and report pairing and robustness are fixed. They do not change acceptance. Run records pin the source hashes that were actually used.
