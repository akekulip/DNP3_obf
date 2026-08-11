# Experiment 2B — hardware bring-up on real Tofino-1

After Philip authorized physical-Tofino work and provided switch-host access, the compiled
handshake normalizer was built with the production toolchain and **loaded + initialized on the
real Tofino-1 ASIC**, then the accepted Defense 4 program was restored. The physical SEL-751 was
never touched; no DNP3 control was issued.

## Environment

- **Switch host:** `decps@10.10.54.81` (ufispace), the same host that runs the accepted Defense 4
  timing deployment. **SDE 9.13.2** at `/home/decps/Downloads/bf-sde-9.13.2`.
- Load/restore used the project's own `swap_generic.sh` (cold `bf_switchd` restart with a conf) —
  the identical mechanism the Defense 4 deploy uses.
- Evidence: `evidence/hardware_9132/` (silicon_load_handshake.log, defense4_restore.log,
  metrics_9132.json, compile_9132.err).

## 1. 9.13.2 compile — PASS (resource-equivalent to 9.13.1)

Same source (SHA-256 `23982bbceb5c3761…`) compiled with the switch's bf-p4c **9.13.2**:

| Metric | 9.13.1 (gambit) | 9.13.2 (switch) |
|---|---|---|
| Result | 0 errors, 2 warnings | 0 errors, 2 warnings |
| Logical tables | 32 | 32 |
| SRAM blocks | 7 | 7 |
| TCAM blocks | 1 | 1 |
| Map RAMs | 4 | 4 |
| Stateful ALUs | 0 | 0 |
| `tofino.bin` size | 1,380,933 B | 1,414,841 B |

The two warnings are identical (`min_parse_depth` parser padding). Resource allocation is
identical across the two SDE versions; only the binary size differs slightly (normal
cross-version codegen). This closes the 9.13.1↔9.13.2 seam noted in `COMPILE_RESULTS.md`.

## 2. Silicon load — PASS (loads + initializes 1 device on Tofino-1)

- First load attempt failed device-add: the bf-p4c-generated conf used paths relative to the
  install dir (`$SDE_INSTALL/out_9132/pipe/context.json`), which do not exist → `No system
  resources`, `initialized 0 devices`. **Fixed** by generating a conf with absolute paths (from
  the Defense 4 conf template) pointing at `/home/decps/hs_build/out_9132/…`.
- Reload result (`silicon_load_handshake.log`):
  ```
  BF_SWITCHD DEBUG -   p4_name: handshake_normalizer
  BF_SWITCHD DEBUG - bf_switchd: initialized 1 devices
  ```
  No device-add error, no `No system resources`. The pipeline config — **including the
  const-entry tables** (`t_norm`, `t_exp`, `t_clamp`), which are part of `context.json` pushed to
  the ASIC at device-add — loaded onto real Tofino-1 silicon. This is the milestone beyond
  compile: **the program is realizable and initializes on physical hardware.**

## 3. What was NOT done: packet-level ASIC functional test

Observing the ASIC actually transform a crafted SYN was **not** performed, and no packet-level
PASS is claimed. Reasons, honestly:

- The minimal program forwards `ucast_egress_port = ingress_port ^ 1`, a 2-port pass-through
  convention that does not match arbitrary front-panel dev-ports.
- This switch's established test-injection path is **in-switch pktgen + mirror-to-CPU** (the host
  front-panel NICs `enp2s0f0/f1` are down, no carrier). pktgen prepends a header the minimal
  parser does not skip, so pktgen packets would not parse cleanly as Ethernet in this program.

A faithful packet test therefore needs a small harness addition (either a pktgen-header-aware
test parser path + mirror-to-CPU capture, or a matched two-port front-panel loopback with the
egress table set to those exact dev-ports). That is the clearly-scoped next hardware step; the
offline oracle (27/27) already pins the golden outputs it would check.

## 4. Restore — Defense 4 back, switch safe

- Defense 4 restored via `swap_generic.sh …/defense4_caseA_fix.conf`
  (`defense4_restore.log`): `p4_name: defense4_caseA`, `initialized 1 devices`, correct conf.
- Total time handshake_normalizer occupied the ASIC: ~01:03:50→01:07:17 UTC (~3.5 min); **no live
  master↔relay DNP3 session was on :20000 during the window.**
- The one platform message `BF_PLTFM ERROR - ChkSum not matched for 33` is a benign transceiver
  (module 33) EEPROM checksum warning that appears on normal boot; unrelated to this work.
- **Caveat left for Philip:** a cold `bf_switchd` restart resets Defense 4's *runtime* control
  plane (pktgen/mirror/params set by `defense4_caseA_setup.py`). Defense 4's documented default
  is OFF/FAIL_OPEN → pktgen disabled → safe pass-through, which is where it now sits. If the prior
  deployment had an active D1–D4 mode armed, re-run `defense4_caseA_setup.py` with the desired
  mode to re-arm it — I left it in the safe default rather than guess the mode.
