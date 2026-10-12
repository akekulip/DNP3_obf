# Mirror fix applied: T never selects the deparser mirror entry with the unwritten session (2026-10-12)

Root cause in `token_stale_01/RESULT.md`. Every build up to `close_reset_fix_01` had it. A T pass that does not
clone selects deparser mirror entry 0, whose session comes from a compiler temporary sharing `md.cur_gen`'s
container. So the pass was mirrored to session = live READ generation [9:0]. At the configured session 7 this
became the READ trigger and stale-token storm.

## Change (source: `read/read_queue_timing.p4`; operate slices regenerated)

- `NO_MIRROR_SESSION = 10w0`, a named constant with the explanation.
- At the top of `apply`: `ig_dprsr_md.mirror_type = MIRROR_TYPE_CLONE; md.clone_ses = NO_MIRROR_SESSION;`.
  Every pass selects the clone entry. Only `admit_request` / `hold_operate` set `CLONE_SESSION_ID` (7). Session 0
  is not a valid session, so nothing is copied.
- `@pa_no_overlay` on `ig_intr_md_for_dprsr.mirror_type` and `md.clone_ses`. bf-p4c drops the initial writes as
  redundant, so the zero must come from a container of their own. Pipe 1 honors the pins.
- Unchanged: the clone marker and tags, the 32-bit allocators, token admission by port and format, RESET kind 13,
  and every earlier fix (IIN mask, FIN/RST reject, close path, timestamp profile, port map). All are present in the
  composed source.
- `read/tests/queue_sim.py` now clones only for the configured session, as the hardware does.

## Build guard

- `core/response_only/build_composite.py <dir> <name> [--sdk local|switch|both] [port flags]` composes, compiles
  and runs `check_mirror_select.check` on each output. It writes `mirror_guard.txt` next to each build and exits
  1 if a compile or guard fails; it refuses an existing directory.
- For the `hw/` installer owner (pointer only; `hw/` not edited): `check_mirror_select.check(build_dir)` returns
  `(ok, notes)`. Refuse to load when `ok` is False.

| build | compile | guard |
|---|---|---|
| hw_compile_local (9.13.1) | exit 0 | PASS |
| hw_compile_switch_9132 (9.13.2) | exit 0 | PASS |
| default_compile_local / shared_default_compile_local | exit 0 | PASS |
| close_reset_fix_01 (previous production, both SDKs) | - | FAIL (`token_stale_01/check_mirror_select.txt`) |

## Resources (hardware map, identical on both SDKs)

| pipe | stages ingress / egress | PHV ingress (containers / bits) | PHV egress |
|---|---|---|---|
| p0 | 12 / 11, critical path 11 | 127 / 2,832 | 118 / 2,535 |
| p1 | 11 / 0, critical path 9 | **52** / 1,542 (was 50) | 21 / 369 |

Pipe 1 gains exactly the two solitary containers: 8-bit 9 -> 10 of 64 (`mirror_type`) and 16-bit 14 -> 15 of 96
(`clone_ses`), the same bits. Pipe 1 stays at about 15% per size, so this does not matter. Pipe 0, the constrained
pipe, is unchanged.

**Hardware-map 9.13.2 (load this):** bfrt.json `4e24bc8a84313b16bfb268aa640bc005548a93bfd63f392abaa8a96909070caa`,
p0/tofino.bin `aff15250cc9af232f99c4d759fd801dd3d4a7b750b712fe760dc637550af2edb`,
p1/tofino.bin `296444ce43e28e3228edd8e1d61c52f2a6f233dc4be357e3e96610e896e02309`.

## Red -> green

| test | red (close_reset_fix_01 build / pre-fix T) | green (this build) |
|---|---|---|
| `model_drive_mirror_guard.py`: sessions 1..1015 to a sink, live READ generation swept 0..1023, one non-cloning T pass each | **1015** passes mirrored, incl. the configured session 7 | **0** |
| `test_t_queue_invariants.py::Q_MirrorSessionOnlyFromCloneActions` (source contract) | 64 of 66 passes violate it | 0 |
| `count_pktgen_return.py`, 10 READs | generation-7 clone 269x, 848 copied frames | every clone 1x, none copied; admit_request 10 = drop_clone 10 |
| `check_mirror_select.py` | FAIL | PASS |

## Regressions (model, this build)

Composite default 70/70, shared 57/57, hardware map 61/61 (`green/composite_hw`); sink probe 62/62
(`green/sink_probe_hw2`); real profile with 10 READs 84/84; sbo_toff 18/18; CLOSE client 24/24,
client_sepack 26/26, server 25/25, rst 22/22, client (hardware map) 25/25, server (hardware map) 26/26.
Suites: response_only 80, read+harness 216, binding 85 (legacy byte-identical), protocol cp 11, hw 78 (+6 skipped).

**A driver defect, found and fixed in this change.** In `e15d9edce` the two OPERATE-blocker checks had been moved
into the MIRROR_SINK branch of `model_drive_composite.py`, so a plain hardware-map run skipped them
(`green/composite_hw_driver_bug_59`, 59 checks). They are back in the reflector block: 61/61, and the sink run is
62/62 (`sink_probe_hw2`; `sink_probe_hw` ran with the earlier driver).

## Only silicon can show

- That every non-cloning pass selecting entry 1 with session 0 copies nothing on the switch. This is supported by
  sessions 0-6 having been presented on every pass before READ 7 with no effect; check any TM mirror drop counter.
- Probe 4: with both ladders shaped, 10 and 50 READs should give READ triggers = READs and stale ~0.
