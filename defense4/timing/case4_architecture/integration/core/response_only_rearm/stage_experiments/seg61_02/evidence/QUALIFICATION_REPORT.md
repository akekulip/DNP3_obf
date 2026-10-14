# candidate61 qualification report (2026-10-14)

Candidate: `seg61_02/evidence/full_04/response_only.p4`, SHA256 `1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa`, built with SDK 9.13.2 (bfrt `e32df204…`), N11/E12/T11. Branch `implement/seg61-qualified-20261014`, later fast-forwarded into `main` and pushed at `f0baa724a` on Philip's instruction; no defaults promoted. All hardware runs used the software endpoints on Vision; no relay OPERATE was sent. Every block ended with a verified restore (production swap, port replay, relay slot, Vision offloads and profile, ping), and production `case4_response_path` was observed afterwards.

## Result

The candidate passed the encoding, lifecycle and READ-timing gates in `rearm_01/PLAN.md` steps 1 to 4 on silicon. Repeated SBO cycles were not run, so that sub-item remains open, and SELECT/OPERATE CLRT is not normalized (see the corrections section). With size padding on, READ, SELECT and OPERATE responses each reach the master as one 61-byte TCP segment. READ is a single DNP3 frame; SELECT and OPERATE are three frames of 28, 19 and 14 bytes. Application content and every CRC are intact. Release precision matches the strict comparison build.

| Step | What ran | Outcome | Evidence (`hw_campaigns/`) |
|---|---|---|---|
| 1 | Offline verification, config regeneration, validator rejection on all four entry points | 715 tests pass on the lab checkout with its compiler trees present; configs byte-identical and hash-bound | commits `3caa4892a`…`a541ddfa8` |
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

The 100 us p99 bound is provisional and is not a maximum-error guarantee. At 14,892 PPS the combined arm's p99 is 147 us (47 of 150 READs over 100 us), with about 3.3 times fewer internal packets than at 59,570 PPS (p99 91 us nearest-rank, none over). Additional elapsed time is observed between the host transmit and receive capture points; it also occurs with timing disabled and in the strict build. Its component and possible interactions remain unresolved; the roughly 128-exchange recurrence is a diagnostic lead.

## Independent checks

- An evidence audit re-derived segment lengths, frame layout, every CRC, CLRT statistics and the off-arm tails from the raw captures with its own parser. Every number reproduced. It corrected one written inference: the earlier statement that the tails "originate at the endpoints" was wrong and has been replaced.
- A cold code review of the branch found no blocker. Its MAJOR finding was fixed: the evidence exceptions in `.gitignore` had un-ignored credential file names inside those folders, so the credential patterns are now re-asserted after the exceptions. Five MINOR findings were fixed: the precision deferral was intended to be visible in `standards.json` (it was not; see the corrections below), calibration readiness is recorded, SBO pairing and growth handling in the report tool are corrected, and dead code is removed.

## Failures retained, all harness defects fixed on the branch

`fourarm_smoke_01` (argv-list capture command), `fourarm_smoke_02` (calibration capture terminated before its buffer flushed), `reconnect_950_01` (c2 checked on c1's port), `stale_tokens_950_01` (missing Vision source pin; calibration delay pushed c2 past the old tokens), `compare_14892_950_01` (precision-only failure re-flagged as a hard standards failure). None was a data-plane fault.

## Limits and open items

- SBO timing has three samples per arm (one cycle per connection). Repeated SBO cycles were not run.
- Callbacks, switch counters, SELECT authorization and restore cannot be checked from the captures; they rest on the endpoint and switch records.
- Not yet done: the source of the transit-path tail, real-relay compatibility and default promotion.
- Review follow-ups not done: the checker's echoed fields are self-attested (`run_standards_checker`). The test fakes in `test_campaign_run.py` are installed on the class at import time, not per test. The production `clrt_check`-to-exchange path has no unit test.
- Equal 61-byte payloads do not hide plaintext object contents or the one-versus-three DNP3 link-frame structure, so these results do not establish fingerprint resistance.
- The code changes after the hardware runs only adjust what is recorded and reported: precision deferral is now visible, calibration readiness is recorded, and report pairing and robustness are fixed. They do not change acceptance. Run records pin the source hashes that were actually used.

## Corrections after the f0baa724a audit (2026-10-14)

- **Repeated SBO is open.** `PLAN.md` had checked the evaluation item that also asked for repeated successful SBO cycles; only one SELECT/OPERATE cycle per connection ran. The sub-item is now open.
- **Precision serialization was incomplete.** `campaign.py::standards_observed` returned `precision_deferred`, but `standards.py::build_standards_artifact` dropped it, so `standards.json` of `candidate61_compare_14892_950_02` shows a structurally clean verdict while `trial.json` records the precision failure. No run was promoted by this. `standards.json` now carries `observed.precision` (status `pass`, `deferred`, `fail` or `not_applicable`, with reasons), and the verdict carries `qualification` (`qualified`, `measurement_only` or `rejected`). Retained artifacts are unchanged.
- **The capture checker proved semantics and length, not this exact profile.** A legal alternative READ layout and a 6/15/1 SBO partition both passed it. A separate per-attempt profile verdict (`read_reencode_01/profile_check.py`, `profile_verdict.json`) now checks every response attempt, retransmissions included, against the exact candidate61 or native image. Re-run over the 60 retained candidate61 trial captures (`analysis/profile_recheck.py`, output `profile_recheck_20261014.json`), 59 pass, 7 of them with real retransmissions; the exception is the already-retained failed `candidate61_reconnect_950_01/c2`, whose c2 capture is not on the commanded port.
- **Control timing.** SELECT and OPERATE CLRT medians are about 5.3 ms and 5.2 ms, including in untimed arms (the fixture's response delay): this candidate normalizes READ's ACK-to-response gap only. The OPERATE request-to-response shift is the 2.4 ms command hold, not CLRT normalization.
- **Statistics.** Percentiles are now nearest-rank and SD the sample SD. The pooled table values are unchanged at the reported precision; the 59,570 PPS rate comparison is 91 us (interpolation gave 90.5 us). Bootstrap intervals resample pooled packets; they are not a block-aware comparison of the builds.
- **Source-only reproducibility.** On a fresh tracked-source export, `test_generator_is_reproducible` needs the ignored compiler outputs. It now skips with the missing paths and rebuild commands, and the generator exits 3 naming them; hardware binding (`campaign.check_bindings`) still fails hard when a build tree is missing.
