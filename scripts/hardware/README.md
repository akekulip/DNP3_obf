# Hardware runs: the master and the guarded block

These scripts run the DNP3 master against the physical relay through the switch, one guarded block at a time. Three
hosts take part: a build host (this checkout), the switch (Tofino-1 running the compiled program), and the master host
(a Linux machine whose NIC port faces the switch's dev9). Their addresses and users come from `lab.json`
(`common.hosts`); see "Lab-specific settings" below.

## The master

- `active_harness/` builds and parses the DNP3 frames. `session.py` holds one TCP session to the outstation,
  `read_requests.py` builds the two READ requests (mixed and integrity), and `sbo_driver.py` runs select-before-operate:
  the OPERATE is built only after a complete SELECT response with matching sequence and echo and CROB SUCCESS.
- `active_harness/guarded_builders.py` is the innermost safety step. SELECT and OPERATE may target only binary-output
  indices 1 and 3 (`AUTHORIZED_POINTS`), which drive no output, trip, close or protection logic on the tested relay.
  Every other index is refused while the frame is built, so no control frame for it can exist.
- `relay_master.py` runs one bounded workload over that session: a READ schedule, optional SELECT/OPERATE cycles,
  and, with `strict_cycle`, the order mixed READ, SELECT, OPERATE, integrity READ repeated.
- `vision_run.py` runs on the master host (as root). `setup` and `restore` record and re-apply the NIC receive
  offloads; `run` captures the master NIC (`out.pcap`, `in.pcap`) around one `relay_master` workload.

## A guarded block, end to end

Each hardware experiment is one campaign with one block. Nothing touches the switch before the freeze check passes.

1. **Prepare.** `matrix.py prepare BUILD --native-observation OBS --output CAMPAIGN/manifest.json --campaign-id ID
   --definition NAME` expands a named definition (`lab*.json`) into per-block configs and a manifest.
2. **Freeze.** `freeze_gate.py write BUILD -o CAMPAIGN/freeze.json --configs ...` binds the source, the compiled
   artifacts, the model-gate verdict, the checker closure and the exact configs by SHA-256. `freeze_gate.py check`
   must report 0 changed and 0 missing.
3. **Dry-run.** `run_block_frozen.sh FREEZE campaign CONFIG RUN_ID --dry-run` runs the same command as the block,
   without hardware contact.
4. **Run.** `evaluation_campaign.py init MANIFEST`, then `start`; `status` only reads. The supervisor runs the
   manifest's exact argv through `run_block_frozen.sh`, which checks the freeze again and calls `guarded_block.py`.
   That runs `campaign.py`, which installs the program (`bringup_composite.py` → `installer_base.py`, dry-run by
   default, `--apply` only with `DEFENSE4_HW_AUTHORIZED=1`), runs the trials through `vision_run.py`, and restores
   the production program.
5. **Restore and verify.** `restore_verify.py` checks the restoration independently. Exit status 0 means the block
   and the restore passed, 1 a failed block with a verified restore, and 2 an unverified restore, which stops all
   hardware work.

The relay-side checks (`scripts/checks/`) then judge every trial from the captured bytes, including CROB status.

## Lab-specific settings

- `lab.json` `common.hosts`: host addresses and user names for the switch and the master host.
- Testbed addresses: the master `192.168.10.1` and the relay `192.168.10.7`, port 20000, both private addresses of
  the isolated testbed. They are defined in `scripts/checks/endpoint_profiles.py` and repeated in a few checkers,
  model drivers and the SELECT/OPERATE driver (`grep -rn 192.168.10. scripts`). They stay in code because the checker
  and model closures bind those files by hash.
- SDE install paths: `switch.py`, `installer_base.py`, `restore_ports.py`, `switch_slot.py` and `live_snapshot.py`
  read `SDE_INSTALL` first and fall back to the switch's install path; `launch_composite.sh` takes it as its second
  argument; `matrix.py` writes the switch's SDE path into each manifest; `scripts/build.py` takes `--compiler` (its
  default is the build host's install).
- The master host's run directory comes from `hosts.vision_run_dir` in the lab config, with a fallback in
  `campaign_base.py`.

No credentials are stored in the repository.
