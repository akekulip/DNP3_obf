# Hardware bring-up of the response-only composite (N + E in pipe 0, T in pipe 1)

Prepared offline on 2026-10-10. Nothing here has run against the switch. `switch.py`, `--apply` and the
teardown are exercised only against `tests/fake/bfrt_grpc`, an in-memory client. That tests our logic and
the client-side behaviour read from the SDE 9.13.1 `bfrt_grpc/client.py`; it says nothing about silicon.

## Which build

Load a composite whose N `ports` table is keyed on `hdr.ip.src`: that is what the current `cp.py` emits,
and the name check refuses any other build. On 2026-10-10 the two that match are under
`evidence/route_ab_01/shared_port_01/`:

| build | T's compiled relay port | use with |
|---|---|---|
| `distinct_compile_switch_9132/out` | 64 | master on dev 9, outstation on dev 64 |
| `shared_compile_switch_9132/out` | 9 | both endpoints on dev 9 |

T's forward and relay ports are compile-time constants, not table entries. `bringup_composite.py` reads them
from `out/response_only.p4pp` (bf-p4c writes it next to `bfrt.json`) and refuses a build whose ports are not
`--master-dev` / `--relay-dev`. Older builds are unusable for a second reason as well:
`clone_marker_composite_01` has the OR clone tag fixed by `ebe33beca`, and `op_tag_composite_02` predates
the `hdr.ip.src` key (its provenance record is `op_tag_composite_02/source/response_only.inputs.json`).

**Hashes are not written here.** `make_conf.py` prints the sha256 of `bfrt.json`, both `context.json` and
both `tofino.bin` for the build it is given. Pass the three it prints for `bfrt.json`, `p0/tofino.bin` and
`p1/tofino.bin` to `bringup_composite.py --expect`. They must equal the build's `manifest.json`
(`artifact_sha256`) on the workstation.

## Files

| file | does |
|---|---|
| `make_conf.py` | bf_switchd conf from `out/`: pipe_scope `[0]`/`[1]`, absolute remote paths, PCIe `0000:04:00.0`. Fails if `--pcie` disagrees or `/sys/bus/pci/devices/<addr>/vendor` is not `0x1d1c` (`--offline` skips that read and prints the command) |
| `rows.py` | N and E rows for slot 0, from `cp.py` only, `check_no_loop` over every row |
| `t_config.py` | T params (range- and order-checked), mirror session 7 → 196, TM strict-priority ladder, pipe-1 packet generator |
| `check_names.py` | offline check of every table, key, match type, width, action, data field, register, duplicate key and table size against `bfrt.json` plus the SDE shared schemas |
| `switch.py` | the only gRPC module |
| `readback.py` | readback of every write, T register reset values, counter snapshot |
| `bringup_composite.py` | dry-run by default; `--apply` is fail-closed |
| `bringup_teardown.py` | generator off, T off, wait for the flush to settle, then undo in reverse with readback |
| `snapshot_counters.py` | JSON of T outcomes, generator counters, queue watermark/drops, `$PORT_STAT`. Read-only, but it binds a BF Runtime client, so it needs `DEFENSE4_HW_AUTHORIZED=1` like the others |
| `tests/` | 29 tests: name-check faults, refusals, and `apply()` / `switch.py` / teardown against the fake client |

## Run order on the switch host

**The master must stay quiet (no SYN, no traffic on the connection) from the launch until
`bringup_composite.py` prints `INSTALLED`.** Writes go in the order queues, generator (apps disabled),
mirror, T params, E rows, N rows, with N's `connection` rows last. The T register check runs before the
first write and again just before `INSTALLED`.

```bash
# 0. on the workstation: copy the build and the scripts, keeping the relative layout cp.py needs
R=/home/decps/Philip_repo/dnp3-defense4/<build name>
E=integration/evidence/route_ab_01/shared_port_01/<distinct|shared>_compile_switch_9132
cd defense4/timing/case4_architecture
rsync -a $E/out/ decps@<switch>:$R/out/
rsync -aR integration/core/response_only/cp.py integration/core/response_only/hw protocol/response_path_cp.py decps@<switch>:$R/src/
# 1. on the switch: PCI check and conf; note the three sha256 lines it prints
cat /sys/bus/pci/devices/0000:04:00.0/vendor          # must print 0x1d1c
python3 $R/src/integration/core/response_only/hw/make_conf.py $R/out --remote-dir $R/out --pcie 0000:04:00.0 -o $R/response_only_hw.conf
# 2. stop the running bf_switchd (rehearsed: RESTORATION_REHEARSAL_20261006.md), then launch the composite,
#    modeled on stage_reduction/hardware/20260925/switch/launch_timing.sh; refuse if bf_switchd is still up
pgrep -x bf_switchd && { echo "bf_switchd still running"; exit 1; }
export SDE=/home/decps/Downloads/bf-sde-9.13.2 SDE_INSTALL=$SDE/install LD_LIBRARY_PATH=$SDE/install/lib
sudo -E setsid nohup bash -c "tail -f /dev/null | $SDE_INSTALL/bin/bf_switchd --install-dir $SDE_INSTALL \
  --conf-file $R/response_only_hw.conf --init-mode=cold --status-port 7777" > $R/switchd.log 2>&1 < /dev/null &
#    wait for :50052; grep -E 'device_add failed|cannot be assigned' $R/switchd.log must be empty
# 3. ports: replay $PORT from the snapshot
python3 framework/control/restore_ports.py response_only live_snapshot_20261006.json.gz --apply --wait 35
# 4. dry-run on the switch (uses the switch's own 9.13.2 shared schemas by default)
cd $R/src/integration/core/response_only/hw
X="--build-out $R/out --expect bfrt.json=<sha> --expect p0/tofino.bin=<sha> --expect p1/tofino.bin=<sha>"
python3 bringup_composite.py $X <endpoint arguments>
# 5. apply; add --enable-pktgen to enable the two apps last, after every readback passed
DEFENSE4_HW_AUTHORIZED=1 python3 bringup_composite.py $X <endpoint arguments> --apply
DEFENSE4_HW_AUTHORIZED=1 python3 snapshot_counters.py -o before.json
# 6. teardown
DEFENSE4_HW_AUTHORIZED=1 python3 bringup_teardown.py --manifest bringup_manifest.json --apply
#    production restore = cold restart with bringup_20261005/launch.sh + restore_ports.py (rehearsed 2026-10-06)
```

Endpoint arguments are plain values and nothing assumes the two dev ports differ:
`--master-ip --master-port --master-dev --relay-ip --relay-port --relay-dev --read-dst --read-src
--crob-index --crob-code --crob-repeat --crob-on --crob-off`.

- **SEL-751 run (distinct build):** `--master-port <fixed port>` alone (defaults 192.168.10.1 dev 9,
  192.168.10.7:20000 dev 64, link addresses outstation 0 / master 1).
- **First run, software endpoints sharing dev 9 (shared build):** `--master-ip 192.168.10.61 --master-port
  <port> --master-dev 9 --relay-ip 192.168.10.62 --relay-port 20000 --relay-dev 9 --read-dst 0x0a00
  --read-src 0x0100`. `--read-dst` / `--read-src` are the DNP3 link destination and source of a request as
  the P4 compares them, in wire byte order: outstation 10 is `0a 00` = 0x0a00, master 1 is `01 00` = 0x0100.
- **CROB.** The gate's SELECT carries index 1, PULSE_ON (code 1), count 1, on 100 ms, off 100 ms. The
  `--crob-*` arguments are not that object. They are the `data_connection` values the model driver installs
  from `vectors.decoy_config()`: the inert decoy object (`vectors.DECOY`, index 201, code 1, count 1, on 0,
  off 0), in wire byte order, so index 201 is 0xC900 = 51456. See open question 5.

### What `--apply` refuses

Before any gRPC call: a file whose sha256 differs from `--expect`; a build compiled for other ports; T
params out of range or not `da < readiness <= cap`; any name-check error; an existing `--manifest-out` file
(it records an install, so tear that down or move it first); and a running daemon that is not exactly one
`bf_switchd` whose `--conf-file` names the files under `--build-out` as program `response_only`.

After connecting, before the first write: a target P4 table that is not empty, mirror session 7 present, a T
register off its reset value. No manifest is created if nothing was written.

During writes it stops at the first failure: a pre-read with no value for a field about to be overwritten, a
write error (the whole gRPC message is printed), a readback mismatch, or a recirculation port that does not
report an identity-mapped queue for the qid. Each write is recorded in the manifest as soon as it succeeds.

**First contact with the generator tables.** Bring-up reads `tf1.pktgen.port_cfg`, `pkt_buffer` and
`app_cfg` before writing them, so the teardown can put the old values back. That pre-read has no silicon
precedent. An app that was never configured may answer with an error, and bring-up will then stop at the
first generator write (nothing but the six queue priorities written, all recorded). If that happens, the
error text printed is the evidence needed to decide how to treat an unconfigured app.

### What the teardown does and does not put back

Generator apps are disabled, T is switched off (`enabled=0`), and no row is deleted until
`OUT_HELD_OFF_FLUSH` and `OUT_TOKEN_OFF` hold still. Then every write is undone in reverse and read back.
An app that held another trigger type before bring-up cannot be restored from the manifest: it is left
disabled as `trigger_recirc_pattern`, reported as `NOT restored`, and the exit code is 1. A restore with no
recorded value is refused and reported the same way.

## Offline result (2026-10-10)

- Dry-run, distinct build with SEL endpoints, and shared build with both endpoints on dev 9: build identity
  OK, compiled ports match, 29 writes plus 2 generator enables,
  `PASS: every table, key, action, data field and register validated`, exit 0.
- `op_tag_composite_02` with the current `cp.py`: refused, five `ports` rows carry `hdr.ip.src`, which that
  table lacks.
- Tests: 29 pass against each of the two builds. Reverting each of 12 fixes in a scratch copy made the
  matching test fail.

```bash
python3 -m unittest discover -s integration/core/response_only/hw/tests -v
HW_BUILD=<dir holding manifest.json and out/> FIXED_SCHEMA_DIR=<bf_rt_shared> python3 -m unittest discover -s …/hw/tests
```

Without `HW_BUILD` the tests take the newest switch-compiled composite under `evidence/route_ab_01` whose
`ports` table has `hdr.ip.src`, build their expected hashes from its `manifest.json`, and skip with a
message if none exists. The fixed-table check uses the SDE 9.13.1 schemas here; step 4 repeats it on the
switch against 9.13.2.

## Model vs hardware state

| state | model (`model_drive_composite.py`) | this bring-up | why |
|---|---|---|---|
| N `ports` 5, `connection` 4, `read_connection` 2 | same shapes | same shapes, real endpoints | from `cp.py` |
| N `data_connection` 2 | `configure` with `vectors.decoy_config()` | same values by default, `--crob-*` to change | open question 5 |
| E `conn` / `odd_ip_t` | slot 0 + slot 1 (8 rows) | slot 0 only (4 rows) | slot 1 was a slot-isolation test with a second master |
| T `params` default | model-clock values (da 50 ms …) | P4 defaults (da 2 ms, readiness 12 ms, cap 16 ms, gap 0.8 ms, op_j 2.4 ms, budget 240000, enabled 1), all on the CLI | silicon clock; `--t-enabled 0` is the Timing OFF arm |
| mirror sid 7 → 196 | no `$max_pkt_len` | `$max_pkt_len` 2048 | the OPERATE clone carries the whole original (4 B tag + 16 B tev + frame ≤ 1514 B) |
| `$PORT` for 68, 70, 196–199 | add attempted, all refused, still 70/70 | not written | the model needed no `$PORT` entry for recirculation ports |
| TM `max_priority` 199: 7>6>5>4, 198: 3>2 | none | written and read back | the model never exercised strict priority |
| generator on 196 (apps 1 and 2) | none | written disabled, enabled last with `--enable-pktgen` | the model has no generator for T; held originals re-wait every lap |
| T registers at reset values | not checked | asserted before the first write and again before `INSTALLED` | `TIMING_QUEUE_MIGRATION_STATUS.md` reset rule |
| write order | N, data_connection, E, T params, mirror | queues, generator, mirror, T params, E, N, N `connection` last | no traffic runs during the model's install |

The model figures above are from `clone_marker_composite_01/model_01` (70/70), the last model run I compared
row by row. I have not compared against a model run of the `shared_port_01` builds.

## Open questions

1. **PCIe prefix and pipe scopes.** `0000:04:00.0` comes from the 2026-09-17 conf that loaded; the vendor
   read in step 1 confirms it on the day. The `[0]`/`[1]` scopes have loaded only for a probe, never for
   this composite.
2. **Strict priority on recirculation ports.** The `sched_cfg` idiom was proven on front-panel loopback ports
   (dp8, dp10), not on pipe-local 198/199. The queue is taken from the port's own `egress_qid_queues[qid]`
   with `ingress_qid_map[qid] == qid` required. That reading of the two fields is mine from the schema, not
   a silicon result; bring-up fails closed if either is absent or not identity.
3. **Pipe-1 generator.** No silicon precedent, including for the pre-reads above. Read the app counters
   after the first OPERATE and READ. The token buffer is 60 zero bytes; T parses only the 6-byte generator
   header in front of it.
4. **k.** The P4 needs only an even token count. The default k=2 (4 tokens per trigger) follows `queue_sim`.
   Defense 2 measured a hold-continuity floor of K=44 and ran K=64 on a 25G loopback. The lap rate on
   198/199 is unmeasured.
5. **`data_connection` values.** Defaults are the model's inert decoy object (index 201). I have not traced
   how the response-only N uses them against the gate's real CROB (index 1, PULSE_ON, count 1, 100/100 ms).
6. **Fixed master port.** N and E match the exact 4-tuple, so the master must bind `--master-port`.
7. **No N rearm after RESET.** After a close, N refuses the next SYN on that 4-tuple (model case
   `RECONNECT_refused_by_N_until_a_rearm_exists`). A new session needs a fresh bring-up.
8. **Missing-entry detection.** `switch.get` treats a driver error as "absent" only if its text contains
   "not found" or "does not exist"; an empty read with no error is raised, not taken as absent. The wording
   is unverified on SDE 9.13.2. A wrong guess fails closed.
9. **Packet buffer readback.** The 9.13.1 client returns a repeated bytes field as None from `to_dict()` and
   keeps the stream in `field_dict[name].val`; `switch.as_dict` reads that. Whether 9.13.2's client and the
   driver return the buffer the same way is unverified. If the buffer still reads back empty, bring-up stops
   at the buffer write with the pre-read error.
10. **Teardown settle.** The defaults (`--quiet` 1 s, timeout 15 s) are not measured.
11. **Daemon identity.** The check reads `ps` and the conf the daemon was started with. It cannot see a conf
    file edited after launch.
