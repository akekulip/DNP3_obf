# Unified Defense 4 timing core — gate status (built through Gate 3)

The core is `defense4/timing/p4/defense4_timing.p4` — one P4 program with modes OFF / D1_EVENT /
D2_RESPONSE_DEADLINE / D3_ACK_DEADLINE / D4_DUAL_DEADLINE / FAIL_OPEN over four logical queues, with
`T_A = t_A + D_A` and `T_RESP = T_A + D_R` (TIMING_SPEC). This branch takes it through Gate 3.

## Gate 2 — compile: PASS (supersedes the stale FAIL record)
`evidence/GATE2_EVIDENCE.md` recorded Gate 2 = FAIL at an earlier commit (`b9ac9e8`). The current
source (SHA-256 `c877bedd…`) **compiles clean** on bf-p4c 9.13.1: `0 errors`, loadable `tofino.bin`,
**51 logical tables, 26 SRAM, 2 TCAM, 252-cycle ingress latency** (`tests/evidence/gate2_compile.err`,
`source.sha256`). The stale FAIL record is a negative result for the older file, not the current one.

## Gate 3 — synthetic validation: PASS 19/19 (`tests/gate3_synthetic.py`, `evidence/gate3_result.txt`)
Offline, no switch load. Validates the mode/deadline semantics and the properties that make the core
a correct timing obfuscation:
- **CLRT constancy** — in D4/D2 the released ACK→RESPONSE latency is the public constant `D_R`,
  independent of the device's native timing (the fingerprint is removed by construction).
- **Design constraint** — the oracle proves that constancy REQUIRES `D_R ≥ the device's native CLRT`
  ("set the deadline at the max, not the centre"); below it, the native timing leaks. Caught, not hidden.
- **Ordering** — the ACK is never released after the RESPONSE (CLRT ≥ 0) in every mode.
- **Deadline policies** — D2 holds RESPONSE to `t_A + D_R`; D3 holds ACK to `t_A + D_A` then releases
  RESPONSE after it.
- **Mode equivalences** — `D4(D_A=0)` reproduces D2; `D4(D_R=0)` reproduces D3's ACK-before-RESPONSE.
- **OFF** is a true pass-through; **FAIL_OPEN** releases within a bounded delay.
- **Edge cases** — missing RESPONSE/ACK → bounded fail-open (no infinite hold); duplicate transaction
  idempotent; early native RESPONSE held to `T_RESP` (no pre-deadline leak).

## Next gate — silicon demonstration (hardware, gated)
Not done here. The core compiles and passes synthetic validation; demonstrating the actual timing
hold on the physical Tofino-1 (load `defense4_timing.p4`, run `control/defense4_timing_setup.py`,
inject a DNP3 exchange, measure that the response is released at the public deadline) is the remaining
gate. The `bf_kpkt` CPU-netdev harness proven in the handshake work provides the measurement path.

## Silicon demonstration — LOAD + CONFIGURE on real Tofino-1 (dynamic hold measurement remains)

Run on the physical switch (`decps@10.10.54.81`, SDE 9.13.2). Evidence: `tests/evidence/asic_config.log`,
`dt_configure.py`.
- **Compiles on 9.13.2** (0 errors) and **loads + initializes on the real Tofino-1** ASIC
  (`p4_name: defense4_timing`, `initialized 1 devices`).
- **Control interface is live on silicon** — all 59 P4 tables/registers are introspectable via BF-RT:
  `tbl_params`, the deadline registers (`reg_deadline`, `reg_ackc`, `reg_resp`, `reg_event`,
  `reg_tag`), the deadline-computation tables (`tbl_build_ta`, `tbl_build_tresp`), and the transaction
  state machine (`tbl_arm_now`, `tbl_arm_select`, `tbl_predecessor`, `tbl_release`, `tbl_expiry`,
  `tbl_collision`, `tbl_cut`, `tbl_fold`).
- **Configured on silicon**: `tbl_params` (key `m.role, m.dir`, action `set_params(mode, d_a, d_r)`)
  was written with **D4 (mode=4), D_A=4, D_R=10** for the ARM/ACK/RESP roles and **read back from
  hardware** — the "static readback proves configuration" milestone.

### The remaining gate — the DYNAMIC timing hold measurement
Not done. Measuring the actual response-held-to-deadline on the unified core needs (a) the four-queue
`max_priority` config + the pktgen **blocker-token reservoirs** seeded on the loopback (`PORT_L=8`),
and (b) real front-panel traffic on `PORT_MASTER=9`/`PORT_RELAY=64` (a master driving a DNP3 exchange)
— there is **no `defense4_timing_setup.py`** yet, and the CPU-netdev inject path used for the handshake
capture does not apply because the core keys on those front-panel ports. This is a full control-plane
bring-up; the separate `defense4_caseA` build's dynamic timing hold is the silicon-proven reference
(D2/D4 held+deadline-released, per `evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`). Gate 3 (19/19) already
proves the release LOGIC; the load+configure above proves it is hardware-realizable and configurable;
the dynamic measurement is the next, larger step.
