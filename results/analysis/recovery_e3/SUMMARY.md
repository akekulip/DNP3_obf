# E3: SELECT-response loss recovery on the physical SEL-751 (c72, 2026-10-28/29)

Plan phase E3; audit follow-up. Evidence: c72 build (source SHA-256 `97812585…`), not the diagnostic build.

## What was run

Qualification block 10 (`10_d20_loss_full`) was reproduced once per condition. Its loss preset was replaced by six
identical drops of the first padded SELECT response (`select_resp_padded:1:identity` at the master-host iptables
INPUT chain), one cold connection per drop. Each condition ran as its own single-block campaign, with a fresh
freeze and a dry-run of the exact command immediately before init. Restoration verified OK after every block.

| Campaign | D | Arm | Trials | OPERATE result (CROB status from captured bytes) |
|---|---:|---|---:|---|
| `rc01_hw_c72_recovery_r1_20261028_01` | 20 ms | combined (T=1, padding=1) | 6 | 5 SUCCESS, 1 TIMEOUT (t3) |
| `rc01_hw_c72_recovery_r2_20261028_01` | 20 ms | size_only (T=0, padding=1) | 6 | 6 SUCCESS |
| `rc01_hw_c72_recovery_r3_20261028_01` | 5 ms | combined (T=1, padding=1) | 6 | 5 SUCCESS, 1 TIMEOUT (t2) |
| total | | | 18 | 16 SUCCESS, 2 TIMEOUT |

Six trials per condition are a bounded diagnostic. No rate is estimated and no condition is compared with another.

## What the captures show

All times are measured at the master NIC, in ms from the SELECT request (`e3_trials.json`).
- **Drop and recovery:** in all 18 trials the first SELECT response copy was captured and dropped, and the relay
  retransmitted it after 998.0–1022.9 ms. The master sent OPERATE 1.04–1.10 ms after receiving the retransmission.
- **Where OPERATE lands:** the recovered OPERATE therefore always leaves the master at about 1.0 s (999.1–1024.0 ms).
  The relay's TCP retransmission timeout is about the same length as the SEL-751 select timeout (manual default
  1.0 s, not read from the relay). Recovery from a lost SELECT response always arrives at the edge of the
  selection window, whatever the arm.
- **r1 t3, a second loss:** the master sent OPERATE at 1009.0 ms, then retransmitted it at 1222.9 ms. The relay
  acknowledged only the retransmission (1228.8 ms), so OPERATE reached the relay about 1.22 s after the SELECT and
  was answered TIMEOUT. The roughly 214 ms retransmission matches the first-request retransmissions seen on fresh
  connections (16/256 in the evaluation), here on a request sent after about 1 s of idle time. That the two share a
  cause is a hypothesis; E2 locates first-request losses only.
- **r3 t2:** a single OPERATE copy left at 1004.7 ms (relay ACK at 1008.6 ms) and was answered TIMEOUT. Other
  trials whose OPERATE left later (up to 1024.0 ms in r2, 1021.0 ms in r3) succeeded. The qualification block 10
  t3 (TIMEOUT, single copy at 1017.4 ms) also falls among later successes.

## What this establishes and what it does not

- The size padding does not break the recovery path. The dropped padded SELECT response is retransmitted by the
  relay and delivered, and OPERATE follows. With timing on, the retransmitted copy is not held: OPERATE leaves about
  1 ms after it in every arm.
- TIMEOUT outcomes are not ordered by OPERATE departure time at the master. The selection-window boundary cannot be
  bracketed from master-side times alone. It would need relay-side timestamps for the SELECT response and the
  OPERATE arrival (the diagnostic mirror's ingress copies, or the relay's own SOE), and the relay's select-timeout
  setting, which was not read: no relay settings access was used.
- Two TIMEOUTs in 12 timing-on trials and none in 6 timing-off trials support no conclusion about timing. The
  timing-off first copy arrives about 20 ms earlier at D = 20 ms (4.4–8.7 ms against 23.6–28.7 ms), but OPERATE
  departure is set by the relay's retransmission, not by the first copy.

Files: `e3_trials.json` (per-trial timeline, copies, CROB points, recorded verdicts), `DESIGN.json` (pre-run
registration, written for the superseded three-block campaign `rc01_hw_c72_recovery_20261028_01`, which was
prepared but never initialised; the conditions and preset are the same), `runs/<campaign>/` (freeze, freeze check,
dry-run and init logs). The extraction script is `scripts/analysis/recovery_e3.py`.
