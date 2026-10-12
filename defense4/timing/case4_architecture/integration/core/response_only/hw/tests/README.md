# hw/ tests

Two suites, split by file name. Run both from `integration/core/response_only/hw/`.

| suite | files | needs | command |
|---|---|---|---|
| pure-source | `test_src_*.py` | nothing beyond the repository | `python3 -m unittest discover -s tests -p 'test_src_*.py'` |
| build-dependent | `test_build_*.py` | the compiled evidence tree of the pinned build; the SDE 9.13.1 shared schemas for the name check | `FIXED_SCHEMA_DIR=<sde>/install/share/bf_rt_shared python3 -m unittest discover -s tests -p 'test_build_*.py'` |

`python3 -m unittest discover -s tests` runs both.

## Pure-source suite (`test_src_*.py`)

Runs on a fresh clone with no skips.

- `test_src_installer.py`: the mirror guard (a synthetic defective `p1/*.bfa` is refused before any write,
  a fixed one passes, a missing one is refused), identity hashes, the port checks (ports in use, dead recirculation entries,
  inconsistent or unreadable builds), the refusals, T parameter ranges, write order, the token buffer, the
  ladder and generator app ids, and teardown order.
- `test_src_fake_client.py`: `apply()`, `switch.py`, the teardown, `set_enabled.py`, shaping, padding policy,
  loopback, and the loop-port byte counters, all driven against `fake/bfrt_grpc`, an in-memory client.
- `test_src_cross_component_pktgen.py`: the installer's generator app ids, turned into real timer headers and
  run through T's P4 source in the interpreter (`read/tests/queue_sim.py`).

The build comes from `fixture.py`: a synthetic build in a temporary directory. Its `response_only.p4pp`
holds only the port constants, taken from `pinned_build.json`'s port map. Its `bfrt.json` and the two
`tofino.bin` files are placeholders. Because there is no real `bfrt.json` and no schemas, tests that call
`bringup_composite.main()` replace the offline name check with `fixture.no_name_check()`. The name check is
tested in the build-dependent suite.

What this suite proves: the installer's logic, ordering and fail-closed behaviour; the readback rules; and the
installer↔T contract on generator app ids.

What it does NOT prove:
- Table, key, action and field names against the compiled program and the SDE schemas. That is the
  build-dependent suite.
- Anything about silicon.

The fake client is more lenient than silicon in these ways:
- No key or data validation: any table, key or field name is accepted. Value TYPES are checked like the
  real client: `DataTuple(val=...)` takes only `int`, `str` or `bytearray` (a `list` or plain `bytes` raises
  `TypeError: Please pass an int/long or bytearray`).
- `entry_mod` without an action always works.
- A fixed table's key always exists (`tf1.tm.*`, `tf1.pktgen.*`, registers).
- Shaper `max_rate` is quantized only as modelled (below); other fields read back exactly.
- Timing is not modelled: no clock, no queues, no recirculation latency.

Hardware-measured facts the fake does model:
- `tf1.pktgen.port_cfg` and `tf1.pktgen.pkt_buffer` have no hardware read on SDE 9.13.2. `switch.get` falls
  back to a software-state read. That read returns the repeated-bytes `buffer` as a LIST of ints, which the
  manifest then stores as a list; `bringup_teardown.load` converts it back to bytes before the restore
  (the first campaign run's teardown failed on exactly this: 35 of 36, exit 1).
- Action parameters the P4 never reads are not stored and read 0: T's `set_params(cap)` and N's five
  `data_connection` fields.
- The shaper realizes only a ×4 ladder of rates, burst 1: 58, 232, 930, 3723, 14892, 59570, 238281 PPS. A
  request snaps to the nearest ladder value in log space, which reproduces every measured point (100→58,
  200→232, 300→232, 500→930, 750–1500→930, 2000–5000→3723, 7500–20000→14892, 30000–100000→59570,
  200000→238281).
- The readback gate accepts a snapped rate within 25% of the request. So requesting an exact ladder value
  always passes, and 1000, 300 and 750 pass. 500, 1500, 2000, 100 and 10000 are refused, as on silicon.
  **Request exact ladder values.**
- Recirculation `$PORT` entries (69–71, 197–199) do not take a loopback write.
- On a hardware read the pktgen `buffer` field reads back through `field_dict[...].val`, not `to_dict()`.

## Build-dependent suite (`test_build_*.py`)

`test_build_validation.py` checks the real compiled build:
- its files match the pinned sha256;
- the tracked `manifest.json` agrees with the pin;
- its compiled ports are the pinned ports;
- identity accepts it and refuses a wrong hash;
- the offline name check passes on the real plan, and catches each of 16 injected faults, a table overflow and
  a duplicate key;
- the shared-port plan validates;
- a dry-run of `bringup_composite.py` exits 0.
- the mirror guard passes on the pinned build and refuses `close_reset_fix_01` (each skipped, naming the
  path, if that compiled tree is not present locally).

What it does NOT prove: anything about silicon. The fixed-table names are checked against 9.13.1 here. The
installer's own dry-run on the switch re-checks them against 9.13.2.

The build under test is the entry in `pinned_build.json` (`build_dir`, relative to `integration/`, and its
three sha256). The current entry is the production build
`evidence/route_ab_01/mirror_fix_01/hw_compile_switch_9132`. `HW_BUILD=<dir holding manifest.json and
out/>` overrides it. Nothing chooses a build by modification time.

**The compiled `out/` tree is not tracked in git.** Only `manifest.json` and `remote_manifest.json` are. On a
fresh clone the build classes therefore **fail** (an error in `setUpClass`). The message names the missing
path and the command that produces the tree:

```
python3 defense4/timing/case4_architecture/installed_sdk_build.py \
  defense4/timing/case4_architecture/integration/evidence/route_ab_01/mirror_fix_01/hw_compile_switch_9132/source/response_only.p4 \
  defense4/timing/case4_architecture/integration/evidence/route_ab_01/mirror_fix_01/hw_compile_switch_9132
```

That compiles with SDE 9.13.2 on the switch host. `tofino.bin` embeds a random run id, so a recompile does not
reproduce the pinned sha256. Either copy the original `out/` from the machine that compiled it, or recompile
and update `pinned_build.json` with the new hashes.

Without the SDE schemas, the 6 tests that need them are skipped. The skip reason names the variable to set
(`FIXED_SCHEMA_DIR`, or `SDE_INSTALL` / `SDE`). The 4 pin and identity tests still run.

## When to update the pin

When a new production build is loaded on the switch: set `build_dir` and the three sha256 values from that
build's `manifest.json`, and update the port map if the build's loop ports changed. The pure suite reads the
port map from the pin, so both suites move together.
