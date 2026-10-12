# Mirror fix verified on silicon: one trigger per READ, zero stale tokens (2026-10-12)

Build `route_ab_01/mirror_fix_01/hw_compile_switch_9132` (commits 159daab6c + ef893db5d): bfrt.json 4e24bc8a, p0 aff15250,
p1 296444ce; hardware map, all earlier fixes (IIN, READ app 0, FIN reject, close path, RESET kind 13). Installer from 3e6277da5.
T on, 5 ms separate-ACK fixture, 20 ms READ gap, one connection per block, fresh cold bring-up, shaped = all six hold and
blocker queues at 14,892 PPS (hold burst 1, blocker burst 64). `check_mirror_select` passes on this build, fails on
close_reset_fix_01.

| run | READs | READ triggers | generated pkts | OUT_TOKEN_STALE | held-orig re-waits | loop packets | CLRT median | pop SD | req->ACK | req->resp |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| shaped | 7 | 7 | 28 | 0 | 701 | 3,062 | 813 | 11.8 | 5,522 | 6,335 |
| shaped | 10 | 10 | 40 | 0 | 984 | 4,218 | 808 | 8.8 | 5,521 | 6,326 |
| shaped | 20 | 20 | 80 | 0 | 1,926 | 8,375 | 810 | 11.7 | 5,505 | 6,317 |
| shaped | 50 | 50 | 200 | 0 | 4,745 | 20,528 | 810 | 18.0 | 5,488 | 6,302 |
| unshaped | 20 | 20 | 80 | 0 | 154,962 | 751,270 | 805 | 21.6 | 5,486 | 6,289 |

Every run: master success, all READs match seed, one real SELECT + OPERATE, zero decoy, OUT_ACK_COMMIT = OUT_RESP_RELEASE =
READs, OUT_OP_RELEASE 1, zero fallback, port 48/180/181/182 received-vs-good octet gap 0 on all four ports.

## What this establishes

- **The defect is fixed.** Triggers equal READs at every size including 7, the old failure point (3,335 triggers there
  before); exactly 4 tokens per trigger (k = 2); zero stale tokens (26-29k before). The unshaped build now also gives 1
  trigger per READ (34 for 20 READs before).
- **Loop traffic on the fixed build, 20 READs:** 751,270 packets unshaped vs 8,375 shaped, 90x fewer; held-original
  re-waits 154,962 vs 1,926. Shaped cost is about 410-420 loop packets per READ, flat from 20 to 50 READs.
- **Timing precision is unchanged by shaping:** CLRT median 805-813 us on every run, population SD 8.8-21.6 us; the
  shaped runs are no worse than unshaped (21.6) and added latency is within noise (request->response 6,289 unshaped vs
  6,302-6,335 shaped).
- The earlier 24-67x loop-traffic figures (p2_production_01) were measured with the storm present; this table supersedes
  them. Bytes are in the snapshots (`loop_ports`) and will be tabulated in the paired blocks. One block per row, one fixture
  delay, one gap: not yet a distribution.

Rig restored after the runs (relay slot read back, ping .1 -> .7 ok, NIC flag off).
