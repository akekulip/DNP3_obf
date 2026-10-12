# Hardware bring-up of the response-only composite (N + E in pipe 0, T in pipe 1)

The installer ran on the switch on 2026-10-11 against `shared_port_01/shared_compile_switch_9132` and
reached `INSTALLED` (31 writes read back); the teardown read back 31 of 32. That build then failed on its
first connection, because the ports it loops through do not recirculate (see below). Everything added since
(ports read from the build, the loopback step, `set_enabled.py`, the default-app teardown rule) has run
only against `tests/fake/bfrt_grpc`, an in-memory client. That tests our logic, not the switch.

## Which build, and where the ports come from

**Only pipe-local port 68 recirculates on this switch** (dev 68 and 196; measured,
`evidence/recirc_ports_01/STATUS.md`). Dev 69-71 and 197-199 have `$PORT` entries, but frames sent there
never return and a loopback write does not take. Every other looping port must be a free front-panel port in
MAC loopback: the plan is `N_ACK_RETURN` 48, `T_IN` 180, `HB_RETURN` 181, `HELD_RETURN` 182.

The installer holds no port numbers. It reads every port from the build, `out/response_only.p4pp` (bf-p4c
writes it next to `bfrt.json`): `n_N_ACK_RETURN`, `n_RETURN_PORT`, `n_READ_HANDOFF_PORT`, `t_T_IN`,
`t_HB_RETURN`, `t_HELD_RETURN`, `t_PKTGEN_RETURN`, `t_FORWARD_PORT`, `t_RELAY_PORT`, the clone session id and
the two ports E's egress parser dispatches on. Those values drive the loopback writes, the TM queue rows,
the generator and mirror ports, and the `n_ack_return=` argument of every `cp.py` builder. A build is
refused offline when:

- its forward / relay ports are not `--master-dev` / `--relay-dev`;
- N's handoff port is not T's input, or E does not dispatch on N's ACK lap port and the master's port;
- a looping port is 9, 10, 11, 64 or an endpoint port;
- a looping port is a pipe-local 69-71 (so every build up to `shared_port_01` is refused);
- its N `ports` table lacks the `hdr.ip.src` key the current `cp.py` emits.

**Hashes are not written here.** `make_conf.py` prints the sha256 of `bfrt.json`, both `context.json` and
both `tofino.bin` for the build it is given. Pass the three for `bfrt.json`, `p0/tofino.bin` and
`p1/tofino.bin` to `--expect`. They must equal the build's `manifest.json` on the workstation.

## Files

| file | does |
|---|---|
| `make_conf.py` | bf_switchd conf from `out/`: pipe_scope `[0]`/`[1]`, absolute remote paths, PCIe `0000:04:00.0`. Fails if `--pcie` disagrees or `/sys/bus/pci/devices/<addr>/vendor` is not `0x1d1c` (`--offline` skips that read) |
| `build_ports.py` | reads every port from `out/response_only.p4pp` and checks them |
| `rows.py` | N and E rows for slot 0, from `cp.py` only, with the build's lap port |
| `t_config.py` | loopback, strict-priority ladder, packet generator, mirror, T params |
| `check_names.py` | offline check of every table, key, match type, width, action, data field, register, duplicate key and table size |
| `switch.py` | the only gRPC module |
| `readback.py` | readback of every write, T register reset values, counter snapshot |
| `bringup_composite.py` | dry-run by default; `--apply` is fail-closed |
| `set_enabled.py` | changes only T's `enabled` on a live install, for alternating Timing OFF / Obfuscated blocks |
| `bringup_teardown.py` | generator off, T off, wait for the flush to settle, then undo in reverse with readback |
| `snapshot_counters.py` | JSON of T outcomes, generator counters, queue watermark/drops on the build's ladder ports, `$PORT_STAT` |
| `tests/` | two suites, see `tests/README.md`: pure-source `test_src_*.py` (no build, no SDE; fake client and P4-source interpreter) and build-dependent `test_build_*.py` (the pinned compiled build + SDE schemas) |

Every script that binds a BF Runtime client needs `DEFENSE4_HW_AUTHORIZED=1`.

## What the installer writes to `$PORT`, and what it never touches

It makes exactly one kind of `$PORT` write: `$LOOPBACK_MODE = BF_LPBK_MAC_NEAR` on each front-panel looping
port the build names, by `entry_mod` on the existing entry (the write that worked on this switch on
2026-10-11, `evidence/recirc_ports_01/recirc_probe.py`; the frozen
`defense4_rrc_bor_unified12_setup.py:hw_config_bor_loopback` is the older precedent). The teardown writes
`BF_LPBK_NONE` back and reads it.

It never writes speed, FEC, auto-negotiation, enable, or any other `$PORT` field. It never creates or
deletes a `$PORT` entry. It never touches dev 9, 10, 11, 64, an endpoint port, or a port whose link was up.
Bringing ports up is `restore_ports.py`'s job.

Before the first write, each port to be looped must have a `$PORT` entry, be enabled, have link down
(a port with link up may be someone's connection), not already be in loopback, and have an empty cage
(media UNKNOWN) unless `--allow-loopback-port <dev>` names it. After the write the mode is read back and
`$PORT_UP` must become True within `--loopback-wait` (default 10 s; it took under 3 s on the switch).
Loopback is volatile: a cold restart clears it, so every bring-up sets it.

## Run order on the switch host

**The master must stay quiet (no SYN, no traffic on the connection) from the launch until
`bringup_composite.py` prints `INSTALLED`.** Writes go in the order loopback, queues, generator (apps
disabled), mirror, T params, E rows, N rows, with N's `connection` rows last. The T register check runs
before the first write and again just before `INSTALLED`.

```bash
# 0. on the workstation: copy the build and the scripts, keeping the relative layout cp.py needs
R=/home/decps/Philip_repo/dnp3-defense4/<build name>
E=integration/evidence/route_ab_01/<build>/<...>compile_switch_9132
cd defense4/timing/case4_architecture
rsync -a $E/out/ decps@<switch>:$R/out/
rsync -aR integration/core/response_only/cp.py integration/core/response_only/port_map.py \
  integration/core/response_only/check_mirror_select.py \
  integration/core/response_only/hw protocol/response_path_cp.py decps@<switch>:$R/src/
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
# 3. ports: replay $PORT from the snapshot (this is what enables the front-panel entries, the free cages too)
python3 framework/control/restore_ports.py response_only live_snapshot_20261006.json.gz --apply --wait 35
# 4. dry-run on the switch: prints the ports read from the build and which of them it will loop
cd $R/src/integration/core/response_only/hw
X="--build-out $R/out --expect bfrt.json=<sha> --expect p0/tofino.bin=<sha> --expect p1/tofino.bin=<sha> \
   --expect p1/response_only.bfa=<sha>"
python3 bringup_composite.py $X <endpoint arguments>
# 5. apply: loopback first, then everything else; --enable-pktgen enables the two apps last
export DEFENSE4_HW_AUTHORIZED=1
python3 bringup_composite.py $X <endpoint arguments> --apply --enable-pktgen
python3 snapshot_counters.py --build-out $R/out -o before.json
# 6. alternate timing blocks on the live install (only T's `enabled` changes; read back each time)
python3 set_enabled.py --manifest bringup_manifest.json --enabled 0     # Timing OFF
python3 set_enabled.py --manifest bringup_manifest.json --enabled 1     # Obfuscated
# 7. teardown (also takes the loopback off)
python3 bringup_teardown.py --manifest bringup_manifest.json --apply
#    production restore = cold restart with bringup_20261005/launch.sh + restore_ports.py (rehearsed 2026-10-06)
```

Endpoint arguments are plain values and nothing assumes the two dev ports differ:
`--master-ip --master-port --master-dev --relay-ip --relay-port --relay-dev --read-dst --read-src
--crob-index --crob-code --crob-repeat --crob-on --crob-off`.

- **SEL-751 run (build with relay port 64):** `--master-port <fixed port>` alone (defaults 192.168.10.1
  dev 9, 192.168.10.7:20000 dev 64, link addresses outstation 0 / master 1).
- **Software endpoints sharing dev 9 (build with relay port 9):** `--master-ip 192.168.10.61 --master-port
  <port> --master-dev 9 --relay-ip 192.168.10.62 --relay-port 20000 --relay-dev 9 --read-dst 0x0a00
  --read-src 0x0100`. `--read-dst` / `--read-src` are the DNP3 link destination and source of a request in
  wire byte order: outstation 10 is `0a 00` = 0x0a00, master 1 is `01 00` = 0x0100.
- **CROB.** The gate's SELECT carries index 1, PULSE_ON (code 1), count 1, on 100 ms, off 100 ms. The
  `--crob-*` arguments are not that object: they are the `data_connection` values the model driver installs
  from `vectors.decoy_config()` (the inert decoy, index 201 = 0xC900 in wire order). The response-only N
  never reads them, so the hardware stores nothing and they read back 0 (measured 2026-10-11).

### Mirror guard (compiler-mirror defect, route_ab_01/token_stale_01)

Before any plan or write, in dry-run and `--apply` alike, the installer runs
`core/response_only/check_mirror_select.check_out(<build-out>)` on `<build-out>/p1/*.bfa`. `--build-out` is
used as given: it need not be named `out` (the campaign deploys `out_<buildname>`). It refuses (exit 1, the `FAIL:` note in the
message) a build whose compiled T ingress deparser could mirror a non-clone pass. That defect copied every T
pass to the session numbered by the live READ generation; it is fixed from `mirror_fix_01` on. Older builds
(`sbo_admission_01`, `close_reset_fix_01`) fail the guard and are refused.

At load time the guard needs exactly one file from the build: `<build-out>/p1/*.bfa` (the pipe-1 assembly). The
`rsync -a $E/out/` deploy step already copies it; `check_mirror_select.py` must be in the `src/` copy (above).
`make_conf.py` refuses an `out/` without exactly one `p1/*.bfa` and prints its sha256.
`--expect p1/response_only.bfa=<sha>` is REQUIRED (with bfrt.json, p0/tofino.bin and p1/tofino.bin): it binds
the file the guard reads to the binaries being loaded. A missing or mismatching hash is refused, in dry-run
and `--apply` alike, before any write.

### What `--apply` refuses

Before any gRPC call: a file whose sha256 differs from `--expect`; a build refused by the port checks above;
T params out of range or not `da < readiness <= cap`; any name-check error; an existing `--manifest-out`
file; and a running daemon that is not exactly one `bf_switchd` whose `--conf-file` names the files under
`--build-out` as program `response_only`.

After connecting, before the first write: a loopback pre-check failure, a target P4 table that is not empty,
the mirror session present, a T register off its reset value. No manifest is created if nothing was written.

During writes it stops at the first failure: a pre-read with no value for a field about to be overwritten, a
write error (the whole gRPC message is printed), a readback mismatch, a looped port whose link does not come
up, or a port that does not report an identity-mapped queue for the qid. Each write is recorded in the
manifest as soon as it succeeds.

### What the teardown does and does not put back

Generator apps are disabled, T is switched off (`enabled=0`), and no row is deleted until
`OUT_HELD_OFF_FLUSH` and `OUT_TOKEN_OFF` hold still. Then every write is undone in reverse and read back;
loopback comes off last.

A generator app whose state before bring-up was the SDE default (disabled, `trigger_timer_one_shot`) is left
disabled and reported as `left disabled (default was a disabled one-shot)`; that is exit 0. Its trigger type
stays `trigger_recirc_pattern` with our pattern: the old type is not rewritten. An app that held any other
trigger type, or was enabled, is left disabled, reported as `NOT restored`, and makes the exit code 1. A
restore with no recorded value is refused and reported the same way.

## Offline result (2026-10-11)

- Tests: 47 pass. Reverting each of 12 of the new behaviours in a scratch copy made a matching test fail.
- Dry-run against `route_ab_01/loopback_ports_01/shared_compile_local/out` (the local SDE 9.13.1 compile of
  the loopback-port build; its 9.13.2 switch compile had not finished) with both endpoints on dev 9: ports
  read as N_ACK_RETURN 48, T_IN 180, HB_RETURN 181, HELD_RETURN 182, RETURN_PORT 68, PKTGEN_RETURN 196;
  33 writes (4 loopback first) plus 2 generator enables; name check PASS; exit 0. The 47 tests also pass
  with `HW_BUILD` pointed at it. The build to load is the 9.13.2 one, with its own hashes.
- Tests are now two suites with no build discovery by modification time: the build-dependent suite uses the
  build pinned in `tests/pinned_build.json` (or `HW_BUILD`); the pure-source suite uses a synthetic fixture
  and needs no compiled tree. See `tests/README.md`.
- `shared_port_01` itself is now refused offline: four looping ports are pipe-local 69-71.

```bash
cd integration/core/response_only/hw
python3 -m unittest discover -s tests -p 'test_src_*.py'                                   # pure-source
FIXED_SCHEMA_DIR=<sde>/install/share/bf_rt_shared python3 -m unittest discover -s tests -p 'test_build_*.py'
```

The fixed-table name check uses the SDE 9.13.1 schemas here; step 4 repeats it on the switch against 9.13.2.

## Model vs hardware state

| state | model (`model_drive_composite.py`) | this bring-up | why |
|---|---|---|---|
| looping ports | pipe-local 68-71 all loop on the model | 68 and 196 only; the rest are front-panel ports in MAC loopback, written first | measured 2026-10-11 |
| N `ports` 5, `connection` 4, `read_connection` 2 | same shapes | same shapes, real endpoints, the build's lap port | from `cp.py` |
| N `data_connection` 2 | `configure` with `vectors.decoy_config()` | same values by default | never read by N; reads back 0 |
| E `conn` / `odd_ip_t` | slot 0 + slot 1 (8 rows) | slot 0 only (4 rows) | slot 1 was a slot-isolation test |
| T `params` default | model-clock values | P4 defaults, all on the CLI | silicon clock; `cap` is not stored and reads 0 |
| mirror session → generator port | no `$max_pkt_len` | `$max_pkt_len` 2048 | the OPERATE clone carries the whole original |
| `$PORT` | add attempted for the recirculation ports, all refused | only `$LOOPBACK_MODE` on the front-panel looping ports | see above |
| TM `max_priority`, 7>6>5>4 on `HELD_RETURN`, 3>2 on `HB_RETURN` | none | written and read back | the model never exercised strict priority |
| generator (apps 1 and 2) | none | written disabled, enabled last with `--enable-pktgen` | the model has no generator for T |
| T registers at reset values | not checked | asserted before the first write and before `INSTALLED` | reset rule |
| write order | N, data_connection, E, T params, mirror | loopback, queues, generator, mirror, T params, E, N, N `connection` last | no traffic runs during the model's install |

## Answered on the switch, 2026-10-11

- Strict-priority writes on pipe-1 queues are accepted and read back. That was on recirculation ports 198 and
  199, which turned out not to loop; the same writes on front-panel ports 181 and 182 are not yet run.
- The pipe-1 generator configuration (port, buffer, two apps, enable) is accepted and read back.
- `tf1.pktgen.port_cfg` and `tf1.pktgen.pkt_buffer` have no hardware read on SDE 9.13.2; `switch.get` falls
  back to software state and bring-up prints which tables were read that way.
- Parameters the P4 never reads are not stored and read 0: T's `cap`, N's five `data_connection` fields.
- The `[0]`/`[1]` pipe scopes and PCIe `0000:04:00.0` loaded this composite.

## Open questions

1. **Loopback step on silicon.** The loopback write itself worked by hand on 48, 180, 181, 182. The
   installer's version (pre-checks, readback, wait for link, undo) has run only against the fake. Whether
   `$MEDIA_TYPE` reads as a string containing `UNKNOWN` for an empty cage is taken from the SDE schema.
2. **TM queues on front-panel ports.** The queue comes from the port's own `egress_qid_queues[qid]` with
   `ingress_qid_map[qid] == qid` required, and the target pipe is the port's pipe. Nothing assumes
   dev >= 196 or a pipe-local id. Not yet run on 181 / 182.
3. **Do tokens and held frames actually circulate.** Counters after the first OPERATE and READ
   (`snapshot_counters.py`) are the evidence. The lap rate on a 25G MAC loopback differs from a
   recirculation port, and k=2 (4 tokens per trigger) follows `queue_sim`; Defense 2 measured a
   hold-continuity floor of K=44 and ran K=64 on a 25G loopback.
4. **Fixed master port.** N and E match the exact 4-tuple, so the master must bind `--master-port`.
5. **No N rearm after RESET.** After a close, N refuses the next SYN on that 4-tuple. A new session needs a
   fresh bring-up.
6. **Missing-entry detection.** `switch.get` treats a driver error as "absent" only on the driver's
   not-found text and never on an "unsupported" error; a wrong guess fails closed.
7. **Teardown settle.** The defaults (`--quiet` 1 s, timeout 15 s) are not measured.
8. **Daemon identity.** The check reads `ps` and the conf the daemon was started with. It cannot see a conf
   file edited after launch.
9. **`set_enabled.py` under traffic.** It rewrites the whole params default action with one changed value.
   Whether a transaction in flight at that moment is released cleanly has not been tested.
