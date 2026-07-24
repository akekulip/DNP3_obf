---
name: lab-hosts-dnp3
description: Lab hosts (Vision/Hulk) and how the DNP3 harness runs across them
metadata: 
  node_type: memory
  type: reference
  originSessionId: a1652c5e-2f90-4c4f-9658-90a51824211e
---

DNP3 harness runs on two Dell R440 lab servers, SSH from gambit as user `decps`
(key auth works passwordless; **sudo needs a password** — not stored here, ask
the user). Details: `~/Projects/Tooling/tofino_25g_connectivity_map.md`.

- **Vision = DNP3 master.** mgmt `10.10.54.19` (eno1, 1G); 25G data NIC
  `enp59s0f0np0`. Has python3.12-dev (can build pydnp3).
- **Hulk = DNP3 slave/outstation.** mgmt `10.10.54.158` (eno1, 1G); 25G NIC
  `enp59s0f0np0`. No python3.12-dev (got pydnp3 egg copied from Vision).
- The 25G NICs are wired Vision↔Hulk through a Tofino switch (mgmt now
  **10.10.54.81**, host `ufispace`, P4 `gridcloak`) but have **NO L3** — must
  assign IPs to run DNP3 over the data plane. User chose to run baseline DNP3
  over the **1G management net** instead (works now; does not traverse the Tofino).

**Switch mgmt IP change (2026-07-24): `10.10.54.15` → `10.10.54.81`** (host rebooted;
password/sudo unchanged; use `decps@10.10.54.81`). On the *hosts*, `sudo` works with
`echo "$SSHPASS" | sudo -S …` (verified 2026-07-24).

Verified 2026-06-10: live two-host READ→RESPONSE — Vision master →
Hulk slave, captured on Vision `eno1`, 330 SOE rows, real DNP3 (READ fn 01;
replies `0564 ff..` multi-frame). Harness deployed at
`~/Projects/DNP3/dnp3_experiment_harness/` on both hosts (NOTE: on the dev box
gambit this was split 2026-07-06 into `dnp3_split_harness/` + `dnp3_multicrob_harness/`;
the rig hosts may still hold the old combined dir until you re-deploy — see
[[dnp3-harness-verified]]).

Re-run: start slave on Hulk via `ssh -f` (experiment_outstation --hold), then
`printf '%s\n' '<pw>' | ssh decps@10.10.54.19 'bash ~/run_vision.sh'`
(captures eno1, sends one scan-class0, splits, extracts).

Gotchas: don't background remote procs with bare `ssh '... &'` (returns 255) —
use `ssh -f`. Don't `pkill -f experiment_outstation` (the pattern matches the
pkill's own shell → kills the SSH session); use the bracket trick
`pkill -f "experiment_[o]utstation.py"`. See [[pydnp3-install]],
[[dnp3-harness-verified]].