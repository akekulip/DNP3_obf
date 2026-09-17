# The frozen program on silicon, 2026-09-17: nothing that matters is broken

An authorised hardware session to confirm that the frozen timing program still loads and
configures on the switch after a day of offline work on candidates and documents. **No traffic was
generated, no capture was taken, no relay was contacted, and no result in the manuscript comes
from this session.** What it establishes is that the mechanism and its control plane are intact.

The switch is `ufispace`, `10.10.54.81`, SDE 9.13.2.

## The chip was taken from another project, on instruction

`bf_switchd` was running `mcp_m2_gate/mcp_fabric_ledger_abs.conf`, started 2026-09-16 13:58 and up
for 27 hours. It was stopped and **not restored**, on Philip's explicit instruction. It is recorded
here because the record costs nothing and its absence would not be obvious to whoever comes back
to that project.

`SIGTERM` was refused, the process being root-owned, and `SIGKILL` under `sudo` left the device
held: the next load failed with `Device add failed for dev 0, sts No system resources (2)` although
`bf_kdrv` showed a reference count of zero. Unloading and reloading `bf_kdrv` cleared it. That is
worth knowing before anyone kills a switchd on this box again.

## What was loaded

The build compiled earlier the same day from the frozen source, not an older tree on the switch:

| | sha256 |
|---|---|
| source, `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` | `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |

The switch carries two other trees with this program's name. `rrc_bor_build/` holds a **different**
revision, `5b846064…`, and `rrc_bor_build_v2/` holds the frozen one. Anyone loading by directory
name rather than by source hash can pick up the wrong program.

`bf_switchd` reported `num P4 programs 1`, `p4_name: defense4_rrc_bor_unified12`,
`initialized 1 devices`, with the bfrt gRPC server on 50052.

Two errors in the load log are not ours: a terminal spinner artefact, and
`BF_PLTFM ERROR - ChkSum not matched for 34`, a platform EEPROM checksum on a port module.

## Two defects found, neither in the data plane

### 1. `verify` can never pass its own commit-map check

`hw_verify_tbl_commit` reads the `const` table `tbl_commit` and asserts the 43-entry outcome map.
The two callers do not agree on the target:

```
line 904   configure-all :  hw_verify_tbl_commit(bi, tdev, chk)   # Target(pipe_id=0xffff)
line 966   verify        :  hw_verify_tbl_commit(bi, tgt,  chk)   # Target(pipe_id=PIPE=0)
```

Const entries are reported at the device target, not per pipe. Reading the table three ways on the
loaded program:

```
  pipe0 from_hw   entries=0
  pipe0 sw        entries=0
  all pipes sw    entries=43
```

So `verify` reports `got={}` and fails, while `configure-all` reads all 43 and passes. The check is
right and the map is intact; the `verify` path passes the wrong target. This is in
`implementation/control/`, which must not be modified, so it is recorded rather than fixed. **Use
`configure-all` for a readback, not `verify`.**

### 2. `read_len` cannot round-trip, and the assertion about it cannot pass by default

`configure-all` with default arguments fails on one check:

```
  [FAIL] tbl_params read_len - got=0 want=18
```

Every other field of the same action round-trips exactly. Writing the six fields directly and
reading them back isolates it:

```
wrote:      read_len = 18   d_ticks = 20000000   budget = 18000   mode = 4   da_dr = 24000000
read back:  read_len = 0    d_ticks = 20000000   budget = 18000   mode = 4   da_dr = 24000000
```

The cause is in the P4: `meta.read_len` is assigned at line 1122 and line 2371 and **never read**.
No table, gateway or action consumes it, so the compiler eliminates its storage while `bfrt.json`
still declares the action parameter. The write is accepted and lands nowhere. Both this build and
the campaign's `rrc_bor_build_v2` declare the field identically, so this is a property of the
frozen source rather than of either build.

Nothing depends on it. The source says so itself: `read_len` "is KEPT (written+read back by the
frozen caseA control plane) but no longer drives EXP_ACK, that is per-function now
(tbl_build_exp_ack)". It is a vestigial parameter with a live assertion attached to it.

**What that means for the campaign record.** `campaign_v1/s*/provenance/MANIFEST.json` records
`configure_readback: RESULT: PASS (n_fail=0 n_warn=0)`. With this source that check can only pass
when the requested value equals what the data plane can hold, which is zero, so the campaign was
configured with an explicit `--read-len 0` or its equivalent. That is consistent with the recorded
PASS; it is not consistent with a default invocation, and anyone reproducing the configuration
needs to know which was used.

## The clean run

`configure-all --read-len 0`:

```
RESULT: PASS (n_fail=0 n_warn=0)
  [ok] tbl_commit const map matches COMMIT_MAP        (all 43 outcomes)
  [ok] PRE verified: mgid 0x2849 -> node 0x2851(rid1)+0x2852(rid2) -> dp9
  [ok] timing preserved (d_ticks)
  [ok] pktgen apps ENABLED + shape ON
```

Every deadline, budget and mode parameter installed and read back. The PRE carve group installed
and verified, which is the size layer's multicast group and is why the size-removal candidate
would also need a control plane without it.

## Shaping was left on by the configure, and forced off

The last line above is the documented hazard: `configure-all` finishes with `shape_enable = 1`,
and every campaign block then forced it to zero. The same was done here, as a read-modify-write
that preserves the timing fields:

```
before: d_ticks 20000000  da_dr 24000000  mode 4  budget 18000  shape_enable 1
after : d_ticks 20000000  da_dr 24000000  mode 4  budget 18000  shape_enable 0
```

**The switch is left with the frozen program loaded, fully configured, shaping off**, which is the
campaign's configuration. Nothing else was run against it.

## Files

```
switchd_frozen.log    the load
configure_all.log     the default run, failing on read_len
configure_all2.log    the clean run with --read-len 0
frozen_abs.conf       the conf used, absolute paths, PCIe prefix 0000:04:00.0
```

The first conf attempt failed because `bf-p4c` writes relative paths into the generated `.conf`
and the inherited PCIe prefix named `0000:05:00.0` while the device enumerates at `0000:04:00.0`.
Both are fixed in the conf kept here.
