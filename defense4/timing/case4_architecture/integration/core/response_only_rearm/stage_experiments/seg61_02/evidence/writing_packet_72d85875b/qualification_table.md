| candidate | gate | status | runs | reasons |
|---|---|---|---|---|
| m5_10 (b758c981) | recovery: graceful persistence | PASS | ctl_m5_persistence_graceful_950_01 |  |
| m5_10 (b758c981) | recovery: RST persistence | PASS | ctl_m5_persistence_rst_950_01 |  |
| m5_10 (b758c981) | recovery: protected reconnect | PASS | ctl_m5_reconnect_950_01 |  |
| m5_10 (b758c981) | recovery: single loss (measurement only) | PASS | ctl_m5_loss_core_950_01 |  |
| m5_10 (b758c981) | recovery: held OPERATE | PASS | ctl_m5_held_operate_350_01, ctl_m5_held_operate_350_02 | ctl_m5_held_operate_350_01: ctl_m5_held_operate_350_01_separate_ack_combined_t0: trial not ok; runner block not ok |
| m5_10 (b758c981) | timing: repeated-SBO qualification b1 | PASS | ctl_m5_qual_repeat_sbo_950_b1 |  |
| m5_10 (b758c981) | timing: repeated-SBO qualification b2 | FAIL | ctl_m5_qual_repeat_sbo_950_b2 | ctl_m5_qual_repeat_sbo_950_b2: ctl_m5_qual_repeat_sbo_950_b2_separate_ack_combined_t0: trial not ok; ctl_m5_qual_repeat_sbo_950_b2_separate_ack_combined_t0: qualification rejected; runner block not ok |
| m5_10 (b758c981) | timing: repeated-SBO qualification b3 | FAIL | ctl_m5_qual_repeat_sbo_950_b3 | ctl_m5_qual_repeat_sbo_950_b3: ctl_m5_qual_repeat_sbo_950_b3_separate_ack_combined_t0: trial not ok; ctl_m5_qual_repeat_sbo_950_b3_separate_ack_combined_t0: qualification rejected; runner block not ok |
| m5_10 (b758c981) | timing: piggyback qualification b1 | PASS | ctl_m5_qual_piggyback_950_b1 |  |
| m5_10 (b758c981) | timing: piggyback qualification b2 | PASS | ctl_m5_qual_piggyback_950_b2 |  |
| m5_10 (b758c981) | timing: piggyback qualification b3 | PASS | ctl_m5_qual_piggyback_950_b3 |  |
| m5_10 (b758c981) | timing: characterization b1 (measurement only) | PASS | ctl_m5_char_repeat_sbo_950_b1 |  |
| m5_10 (b758c981) | timing: characterization b2 (measurement only) | FAIL | ctl_m5_char_repeat_sbo_950_b2 | ctl_m5_char_repeat_sbo_950_b2: ctl_m5_char_repeat_sbo_950_b2_separate_ack_combined_t0: trial not ok; ctl_m5_char_repeat_sbo_950_b2_separate_ack_timing_only_t0: trial not ok; runner block not ok |
| m5_10 (b758c981) | timing: characterization b3 (measurement only) | FAIL | ctl_m5_char_repeat_sbo_950_b3 | ctl_m5_char_repeat_sbo_950_b3: ctl_m5_char_repeat_sbo_950_b3_separate_ack_combined_t0: trial not ok; ctl_m5_char_repeat_sbo_950_b3_separate_ack_timing_only_t0: trial not ok; runner block not ok |
| m5_10 (b758c981) | isolation: quiet new incarnation followed by traffic | FAIL | ctl_m5_stale_iso20_950_01 | ctl_m5_stale_iso20_950_01: ctl_m5_stale_iso20_950_01_separate_ack_combined_t0: trial not ok; runner block not ok |
| m5_10 (b758c981) | contention: nonzero silicon retry activity | PENDING |  | retry laps 0 in every retained run (count_busy[2]) |
| m5_10 (b758c981) | isolation: active-traffic overlap | PENDING |  | source/model test only; no silicon schedule demonstrated |
| m6_07 (3335479b) | recovery: graceful persistence | PENDING |  | not run |
| m6_07 (3335479b) | recovery: RST persistence | PENDING |  | not run |
| m6_07 (3335479b) | recovery: protected reconnect | PENDING |  | not run |
| m6_07 (3335479b) | recovery: single loss (measurement only) | PENDING |  | not run |
| m6_07 (3335479b) | recovery: held OPERATE | PENDING |  | not run |
| m6_07 (3335479b) | timing: repeated-SBO qualification b1 | PENDING |  | not run |
| m6_07 (3335479b) | timing: repeated-SBO qualification b2 | PENDING |  | not run |
| m6_07 (3335479b) | timing: repeated-SBO qualification b3 | PENDING |  | not run |
| m6_07 (3335479b) | timing: piggyback qualification b1 | PENDING |  | not run |
| m6_07 (3335479b) | timing: piggyback qualification b2 | PENDING |  | not run |
| m6_07 (3335479b) | timing: piggyback qualification b3 | PENDING |  | not run |
| m6_07 (3335479b) | timing: characterization b1 (measurement only) | PENDING |  | not run |
| m6_07 (3335479b) | timing: characterization b2 (measurement only) | PENDING |  | not run |
| m6_07 (3335479b) | timing: characterization b3 (measurement only) | PENDING |  | not run |
| m6_07 (3335479b) | isolation: quiet new incarnation followed by traffic | PENDING |  | not run |
| m6_07 (3335479b) | contention: nonzero silicon retry activity | PENDING |  | retry laps 0 in every retained run (count_busy[2]) |
| m6_07 (3335479b) | isolation: active-traffic overlap | PENDING |  | source/model test only; no silicon schedule demonstrated |
