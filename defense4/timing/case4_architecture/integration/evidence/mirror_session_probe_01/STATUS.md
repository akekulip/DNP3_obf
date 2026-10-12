# Silicon confirmation: the trigger runaway starts exactly at READ 7 (2026-10-12)

Agent analysis (route_ab_01/token_stale_01/RESULT.md): bf-p4c gives T's ingress-deparser "no mirror" entry a session id
taken from a compiler temporary that shares a register slot with `md.cur_gen`, the live READ generation, so every T
pass is mirrored to session `cur_gen[9:0]`. Only session 7 is configured (to 196, the generator port). It predicts a
clean run through READ 6 and a storm while generation 7 is live. Probe on the build under test (close_reset_fix_01,
T on, 5 ms fixture, both hold and blocker queues shaped at 14,892 PPS unless noted, fresh cold bring-up each):

| run | READs | READ triggers | generated pkts | OUT_TOKEN_STALE |
|---|--:|--:|--:|--:|
| shaped | 6 | 6 | 24 | 0 |
| shaped | 7 | 3,335 | 13,340 | 29,079 |
| shaped | 8 | 3,544 | 14,176 | 26,793 |
| unshaped (control) | 7 | 20 | 80 | 14,260 |

Prediction holds on hardware: 1 trigger per READ through READ 6, a storm at READ 7, and the unshaped build shows the
same storm with a shorter window (20 triggers vs 3,335, stale 14,260). Earlier runs with 7 or more READs (all 10- and
20- and 50-READ blocks reported so far, shaped or not) include this fault. Their correctness results stand (zero
fallback, exact commits and releases), but their trigger, stale-token, blocker-lap and loop-traffic figures describe a
build with the defect, and the shaped-versus-unshaped comparisons must be repeated on the fixed build.

Rig restored after the probes.
