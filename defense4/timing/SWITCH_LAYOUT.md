# Where things live on the lab hosts

Written 2026-09-11, after the switch's home directory was reorganised. Read this before running
anything that names a `/home/decps/...` path.

## Hosts

| address | hostname | what it is | reached as |
|---|---|---|---|
| 10.10.54.81 | `ufispace` | the Tofino-1 switch every result in this paper ran on; its management NIC carries a Hon Hai MAC | `ssh decps@10.10.54.81` |
| 10.10.54.166 | `vision` | the DNP3 master host; runs the campaign driver | `ssh decps@10.10.54.166` |
| 10.10.54.141 | — | Netberg Aurora 610, a second Tofino switch; SSH only, no SDE running as of 2026-09-10; QSFP-cabled to `ufispace` | not yet logged into |

The SEL-751A outstation is at 192.168.10.7 on the relay-side network, which is not reachable from
the 10.10.54.0/24 management subnet.

## The switch: everything is under `/home/decps/Philip_repo/`

On 2026-09-11 the loose items in `/home/decps` were moved into category folders under
`Philip_repo/`, and every script and config inside it was repointed to the new locations. The
switch's own `Philip_repo/MANIFEST.md` has the full account; `Philip_repo/PATH_MAP.tsv` is the
old-path-to-new-path map.

Four items stay at the top level because a running process uses them, and `Philip_repo/in_place/`
links to each: `mcp_m2_gate`, `hawk-e2e-20260909-222400`, and the SDE at
`Downloads/bf-sde-9.13.2` (whose `build/` tree also holds compiled project builds).

## The paths this repository's campaign scripts name

`evidence/campaign_v1/_bin/campaign_block.sh` and `sweep_block.sh`, and the archived copy in
`evidence/campaign_v1/s01/tools/`, still name the switch paths as they were when the campaign
ran. They are **not** edited: `campaign_block.sh` is hash-pinned in
`evidence/campaign_v1/s01/provenance/DATASET.sha256` as the record of what ran. Translate them
instead:

| path in the scripts | host | where it is now |
|---|---|---|
| `/home/decps/rrc_bor_build_v2/control` | switch | `/home/decps/Philip_repo/dnp3-defense4/rrc_bor_build_v2/control` |
| `/home/decps/rrc_bor_build/control` | switch | `/home/decps/Philip_repo/dnp3-defense4/rrc_bor_build/control` |
| `/home/decps/d4_build/control/defense4_caseA_setup.py` | switch | `/home/decps/Philip_repo/dnp3-defense4/d4_build/control/defense4_caseA_setup.py` |
| `/home/decps/d3` | switch | `/home/decps/Philip_repo/dnp3-defense4/d3` |
| `/home/decps/Downloads/bf-sde-9.13.2` | switch | **unchanged** |
| `/home/decps/native_parity/campaign_run.py` | **Vision** | **unchanged**; sha256 `3994aca143b07b06…`, matches the audit |

Two scripts under `implementation/control/`, which is also read-only, name old switch paths:

* `defense4_caseA_setup.py` defaults `--snapshot-out` to `/home/decps/d4_build/d4_snapshot.json`.
  Pass `--snapshot-out /home/decps/Philip_repo/dnp3-defense4/d4_build/d4_snapshot.json`.
* `case_a_defense3_fixed_ack_delay_setup.py` searches `/home/decps/d3/control` and
  `/home/decps/d3`. Neither exists now; run it from
  `/home/decps/Philip_repo/dnp3-defense4/d3`.

This repository's standing rule still applies: no hardware runs, program loads or captures
without explicit instruction. This note records where things are; it does not authorise using
them.

## Vision (10.10.54.166): DNP3 files gathered 2026-09-11

The DNP3/timing experiment files that were loose in Vision's `/home/decps` are now under
`/home/decps/Philip_repo/` (`harnesses/`, `native-baseline/`, `defense-phys/`, `timing/`,
`traffic/`, `captures/`). Vision's own `Philip_repo/MANIFEST.md` is the full account and
`Philip_repo/PATH_MAP.tsv` is the old->new map; 29 files had absolute paths repointed.

Unlike the switch, Vision runs unrelated live services (streambert, adguard, leanbulk) and a
second active project (MCP fabric), so **only DNP3 files were moved**. Four items stay at the top
level because other callers name them, linked from `Philip_repo/in_place/`:

| item | left in place because |
|---|---|
| `native_parity` | the campaign driver; `campaign_block.sh`/`sweep_block.sh` are hash-pinned to it, and it is the master-side entry point for `campaign_v1` |
| `opendnp3`, `dnp3` | used by the `GridCloak` project's hardware scripts |
| `sdnp_val` | used by the `dnp3-research` project |

The MCP, OTA-Shield, service and dotfile items were not touched.
