# GATE_C_AND_ROLLBACK.md — Phase-5 load authorization + rollback (autonomous run)

## Gate-C conditions (charter §12) — status
| # | condition | status |
|---|---|---|
| 1 | live program = queue microbench | ✅ verified (bf_switchd on queue_microbench_abs.conf) |
| 2 | exact current binary + .conf preserved | ✅ intact at /home/decps/queue_microbench/out (tofino.bin fbddefa…) |
| 3 | tested relaunch command exists | ✅ launch_mb.sh (produced the current loaded microbench) |
| 4 | rollback not dependent on decoy_paper3 | ✅ restore = microbench |
| 5 | new program compiles 9.13.2 0 errors | ✅ Phase 4 (3 stages, parity) |
| 6 | new setup passes dry run | ✅ queue_microbench_trace_setup.py --dry-run |
| 7 | Hulk/Vision can generate + capture | ⏳ harness (generator/collector) building; hosts UP |
| 8 | port mapping known | ✅ dp9 hairpin, pg2/nr1 |
| 9 | strict-priority readback verifiable | ⏳ verify at load (1 real queue QID_REAL_S1) |
| 10 | cover OFF | ✅ trace P4 has no cover path |
| 11 | metronome OFF | ✅ trace P4 has no metronome |
| 12 | no external filler can leave a host port | ✅ no cover/filler concept |
| 13 | stop-on-loss/reordering procedure exists | ✅ defined below |
| 14 | no physical SEL-751 access | ✅ synthetic trace replay only |
| 15 | load window no conflict | ✅ single owner (decps), 1 bf_switchd |
| 16 | microbench restorable | ✅ launch_mb.sh + intact build |

Pending (7, 9) clear when the harness is verified + priority reads back at load. ALL must hold before load.

## LOAD (Phase 5, only after Gate C fully passes)
```
sudo pkill -x bf_switchd                                             # stop microbench
sudo nohup bash /home/decps/queue_microbench_trace/launch_trace.sh & # load trace_v1
sleep 18                                                             # cold init
# verify: bf_switchd on queue_microbench_trace_v1_abs.conf; then run the trace setup --apply;
# read back: 1 real queue, cover=OFF, metronome=OFF, telemetry=0, priority; abort+rollback on mismatch.
```

## ROLLBACK / STOP (run at end, or IMMEDIATELY on any anomaly per charter §16)
```
sudo pkill -x bf_switchd
sudo nohup bash /home/decps/queue_microbench/launch_mb.sh &          # restore microbench (NOT decoy)
sleep 18
pgrep -x bf_switchd >/dev/null && echo UP || echo DOWN
tr '\0' ' ' < /proc/$(pgrep -x bf_switchd|head -1)/cmdline | grep -o 'conf-file [^ ]*'   # expect queue_microbench_abs.conf
```
STOP + rollback triggers: any packet truncated / lost; any ordering inversion; queue occupancy grows
without draining; external cover appears; metronome active; recirc escapes; switch vs receiver counts
disagree; strict priority unverifiable; a different owner appears. Preserve all failure evidence; never
rename a failed result as pass.
Hulk teardown after the run: remove any temp macvlan/netns; tcpdump killed; NIC flags restored.
