# Errata to b1_offline.json (2026-10-25)

`b1_offline.json` and `b1_offline.py` stay unchanged as committed. This file corrects them.

## 1. Relay TSval granularity
`b1_offline.json` `notes[0]` says "relay TSval steps are 10 ms". That is wrong.

I checked the claim read-only against the master-NIC captures (`relay_wire.json`, `packets.in`, TCP timestamp
option) of the three t3 SELECT-response-loss trials:

| trial | timestamped inbound packets | positive TSval increments | multiples of 30 | rate (units/s) | copy wire gap (ms) | TSval copy gap |
|---|---|---|---|---|---|---|
| `rc01_hw_c67_20261025_06_loss_mixed_950` combined t3 | 48 | 26 | 26 | ~1,021 | 999.492 | 1,020 |
| `rc01_hw_c67_20261025_08_loss_mixed_950` combined t3 | 48 | 28 | 28 | ~1,020 | 1,000.401 | 1,020 |
| `rc01_hw_c67_20261025_07_loss_full_950` combined t3 | 48 | 27 | 27 | ~1,042 | 978.714 | 1,020 |

The smallest positive increment is 30 in all three trials. The TSval runs at about 1,000 units/s, and its
observed increments are multiples of 30. A copy gap of 1,020 therefore means only "about 1.02 s". It does not
establish equal relay wire-departure intervals or rule out relay-side timing differences. The extra copy spacing in
the failing trials (20.778 ms and 21.687 ms relative to trial 07) is smaller than the observed 30-unit step.

## 2. Timing error structure
In WORKING_NOTES, "consecutive errors independent (lag-1 r=0.02)" and "consistent with an independent 0..~2 ms delay
per released packet" are both withdrawn.

A near-zero lag-1 correlation does not establish independence. The error distribution being bounded near ±2.0 ms
does not show a separate 0–2 ms delay on each packet. The `T_c_*` values in `b1_offline.json` are correct as
computed. Only that interpretation is withdrawn.
