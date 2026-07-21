# Case-A Switch-Window Rollback Runbook

For the PI-authorized **narrowly-scoped Case-A window** (C1 compile → C2 forwarding → C3 hold/pacing →
C4 semantic probes → fixed-guard Case-A microbenchmark). Shared Tofino `decps@10.10.54.15` (`ufispace`).
Authorization does NOT cover Case B / common-bounded guards / ACK synthesis / combined manipulation /
padding / multi-flow / device campaign / permanent switch changes / broad TM reconfig.

## Pre-change snapshot (captured read-only, `evidence/switch_snapshot.txt`)
- **Currently loaded program:** `bf_switchd` on `/home/decps/decoy_paper3/gf_v2b.conf`
  (`program-name: decoy_switch_tna`), running as root. This is the co-resident program to restore.
- **gc-switchd:** `inactive` + **`masked`** — the restore target (leave masked; do NOT unmask).
- **SDE 9.13.2** present at `/home/decps/Downloads/bf-sde-9.13.2`.
- **Staged Case-A work dir:** `/home/decps/dcrn_m1/` (will add `dcrn_defense1.p4` + `build_ackA/` + a
  Case-A `dcrn_defense1.conf` + `launch_defense1.sh`).

## C1 — compile only (NON-DESTRUCTIVE, no rollback needed)
Compile `dcrn_defense1.p4` with the switch SDE 9.13.2 **without loading it** — `bf_switchd` is NOT
restarted, the running decoy is untouched. Nothing to roll back.

## C2+ — the gated LOAD (displaces the co-resident program). Rollback MUST be ready first.
Load sequence (only after C1 passes and with GO):
```
# gc-switchd already masked; no unmask.
sudo pkill -x bf_switchd                       # stop decoy
sudo nohup bash /home/decps/dcrn_m1/launch_defense1.sh >/home/decps/dcrn_m1/switchd_ackA.log 2>&1 &
# wait ~18s cold init; then Case-A controller (ports dp8/dp9, recirc dp68, QID_HOLD queue, seed regs)
```

### ROLLBACK (run at the end of the window, or immediately on ANY anomaly)
```
sudo pkill -x bf_switchd                        # stop the Case-A program
sudo nohup bash /home/decps/decoy_paper3/launch_gf_v2b.sh >/home/decps/decoy_paper3/relaunch.log 2>&1 &
sleep 18
pgrep -x bf_switchd >/dev/null && echo CORESIDENT_UP || echo CORESIDENT_DOWN
tr '\0' ' ' < /proc/$(pgrep -x bf_switchd|head -1)/cmdline | grep -o 'conf-file [^ ]*'   # expect gf_v2b.conf
systemctl is-enabled gc-switchd                 # expect: masked (leave as-is)
```
Verify: bf_switchd back on `gf_v2b.conf` (`decoy_switch_tna`); gc-switchd still masked; normal
forwarding restored. **Restore caveat:** a cold restart returns decoy to post-compile state; any
runtime tables its own controller installed need re-running by its owner (flagged, not our concern
to reproduce).

### Hulk-side rollback (if the microbenchmark rig was set up)
```
sudo ip netns del ns_master ns_out; sudo ip link del mv_master; sudo ip link del mv_out
sudo ethtool --set-priv-flags enp59s0f0np0 disable-source-pruning off
sudo ip link set enp59s0f0np0 promisc off
sudo nmcli dev set enp59s0f0np0 managed yes
```

## STOP conditions (halt, preserve logs, roll back, return to local code)
- C1: SDE 9.13.2 reports **>12 ingress stages** or cannot place → STOP; do NOT interactively optimize on
  the shared switch; return to local for stage reduction.
- C2: any drop / duplicate / reset / non-transparent forwarding → STOP + rollback.
- C3: hold cannot exceed ~3 ms, or MAX_PASS triggers before a normal response, or no queue counters →
  STOP + rollback (return to the pacing/clock design).
- C4: any response-before-ACK violation, or non-monotone/unbounded register visibility → STOP + rollback.
- Any unexpected co-resident disruption → immediate rollback.

## Invariants for the whole window
- gc-switchd stays masked throughout; restore decoy at the end; verify normal forwarding; leave NO
  permanent switch change. One gated change at a time; stop and report before the next mechanism.
