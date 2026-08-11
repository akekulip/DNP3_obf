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

## 5. ASIC packet-level test — attempted, PENDING a packet-injection harness (verdict: ASIC_PACKET_PENDING)

Per the mandate I tried to close the packet gap. The concrete blocker on this switch is the
**packet-injection/capture path**, not the program:

- **bf_kdrv (DMA)** is loaded and in use by the running `bf_switchd`; **bf_kpkt (the CPU netdev
  driver)** is present but not loaded, and no CPU packet netdev exists (`/sys/class/net` has none).
  Getting a host-injectable CPU netdev needs a driver swap + a conf `cpu-port`/netdev entry +
  switchd restart — a platform bring-up I would not rush on the production switch.
- **Front-panel host injection** is unavailable right now: the switch host's own NICs
  (`enp2s0f0/f1`) and the master **Vision**'s switch-facing NICs (`enp59s0f0np0/np1`) are all
  **DOWN (no carrier)**; **Hulk** has no scapy. Defense 4 itself verifies via **data-plane
  counters**, not packet capture, so there is no existing capture harness to reuse.
- **pktgen** is available but prepends a 6-byte header the minimal parser does not skip.

**Ready artifacts committed for the harness** (so the run is one step once a path is up):
- `handshake_test_loopback.p4` on the switch (`egress = ingress_port`, so a CPU-injected frame
  loops back to the CPU port for capture) — **compiles clean on 9.13.2** (`0 errors`,
  `evidence/hardware_9132/test_loopback_compile_9132.err`).
- The 27-fixture oracle (`tests/oracle.py`) pins the golden outputs; `tests/ptf/test.py` drives them.

**The one remaining step** (either path): (a) load `bf_kpkt` with the CPU port exposed as a netdev,
load `handshake_test_loopback`, then `scapy sendp`/sniff each fixture on the CPU netdev and compare
to the oracle (byte-level) **and** read `ctr`/`ctr_l3` (per-outcome); or (b) bring up a Vision
front-panel link, set the test egress to Vision's dev-port, inject+capture on Vision. Neither
touches the SEL-751. **No packet-level PASS is claimed** — the verdict for the packet test is
**ASIC_PACKET_PENDING**, distinct from the confirmed **compile PASS + silicon LOAD PASS**.

Defense 4 was restored again after this attempt (`evidence/hardware_9132/defense4_restore2.log`:
`p4_name: defense4_caseA`, 1 device), left in its cold-boot safe default (pktgen unarmed →
pass-through; `defense4_caseA_setup.py` was never run, so nothing armed it).

## 6. ASIC PACKET-LEVEL TEST — DONE via pktgen + counter readback (verdict: ASIC_PACKET_PARTIAL, classification 8/8 on silicon)

The packet gap is closed at the classification level. Using the switch's own **in-switch packet
generator** (`tf1.pktgen`, port 68, timer one-shot) I injected crafted handshake fixtures into a
pktgen-header-aware build (`handshake_pgen.p4`, which skips the 6-byte pktgen header on port 68 and
is otherwise identical; compiles clean on 9.13.2, loads `initialized 1 devices`), and read the
per-outcome data-plane counter `Ingress.ctr` from hardware after each shot. Evidence:
`evidence/hardware_9132/asic_packet_matrix.log`, `pgen_matrix.py`.

**Result: 8/8 distinct outcomes classified correctly on real Tofino-1 silicon** (each fired exactly
one packet; the correct counter index incremented by exactly 1, no others):

| Fixture | Expected `ctr` | On silicon |
|---|---|---|
| SEL751 full-option SYN (data_offset 10) | 1 norm_syn | ✅ {1:1} |
| ION7550 MSS-only SYN (data_offset 6) | 1 norm_syn | ✅ {1:1} |
| AB1400 SYN MSS 1478 | 2 norm_syn_clamp | ✅ {2:1} |
| SYN, MSS not first | 6 syn_failopen | ✅ {6:1} |
| SYN, TCP-MD5 2nd option | 9 security_opt_bypass | ✅ {9:1} |
| SYN-ACK MSS-only | 3 synack_normalize | ✅ {3:1} |
| established ACK + Timestamp | 7 established_leak | ✅ {7:1} |
| data_offset 13 (unsupported) | 11 tcp_unsupported_do | ✅ {11:1} |

This exercises, **on hardware**, the full parser (every option layout, including
data_offset 6–13 and the SYN-ACK/established paths), the `t_exp` and `t_clamp` and `t_norm` tables,
the classification/eligibility logic, and the counters. For the eligible cases (norm_syn,
norm_syn_clamp, synack_normalize) the counter increment confirms `md.eligible=1` drove `t_norm` →
`canon` **fired on silicon**, i.e. the rewrite path executed.

**Why PARTIAL, not full PASS:** this verifies **classification and the eligibility→rewrite
decision** on silicon, not the exact **output bytes** (rewritten option region + recomputed
IPv4/TCP checksums). Byte-level output capture needs an egress capture path (a CPU netdev or a
front-panel capture host), which is the same infrastructure gap as before; the offline oracle
(27/27) already pins those golden bytes. An intermediate finding worth noting: two initial fixtures
with **mis-aligned TCP options** (option length not a 4-byte multiple, so `data_offset` disagreed
with the actual option bytes) were correctly flagged by the ASIC as a length/payload inconsistency
(`syn_payload_bypass`) — the pipeline caught malformed input; the fixtures were then aligned.

Defense 4 restored again afterward (`evidence/hardware_9132/defense4_restore3.log`:
`p4_name: defense4_caseA`, 1 device); the cold `bf_switchd` restart cleared all pktgen runtime
config. SEL-751 untouched; no control ops; the pktgen packets never left the pipeline toward the
relay.

## 7. SUPERSEDES §5/§6 — byte-level ASIC capture: ASIC_PACKET_PASS

Sections 5 (PENDING) and 6 (PARTIAL/classification) are the chronological record; both are
**superseded** by the byte-level capture. Via a `bf_kpkt` CPU netdev (`ens1`) loopback build, the
exact normalized bytes were captured off the ASIC for all three devices and are **byte-identical**
(`INDISTINGUISHABILITY.md` §"BYTE-LEVEL confirmation", `evidence/hardware_9132/asic_byte_capture.log`).
The packet-level verdict is therefore **ASIC_PACKET_PASS** (device-indistinguishable on silicon),
not PENDING/PARTIAL.
