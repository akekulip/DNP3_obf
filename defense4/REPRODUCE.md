# Defense 4 — reproduce

All steps below are software/compile/offline (no hardware). Paths are relative to the repo root
`~/Projects/DNP3-size-probe`. Local compiler: `~/bf-sde-9.13.1/install/bin/bf-p4c`. Python:
`$RESEARCH_PYTHON` (= `~/.venvs/research/bin/python`). See `PROJECT_MAP.md` for the artifact index.

## 1. Compile the faithful two-pipe BOR+RRC (both pipes ≤ 12 stages)

```bash
SDE=~/bf-sde-9.13.1; BP=$SDE/install/bin/bf-p4c
cd defense4/size/native_parity/p4

# pipe 0 = frozen RRC + T0-admission + cross-pipe route + SELECT-prepare  -> 12 ingress / 3 egress
$BP --target tofino --arch tna -DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD -DPIPE0_SELECT_PREP \
    -o /tmp/out_p0 defense4_twopipe_pipe0_probe.p4
grep -c "stage 12" /tmp/out_p0/pipe/*.bfa   # max stage; 0 errors + tofino.bin => FITS

# pipe 1 = faithful SELECT-prepares-epoch BOR + Random<T> J  -> 10 ingress / 0 egress
$BP --target tofino --arch tna -o /tmp/out_p1 defense4_twopipe_pipe1_faithful_probe.p4
ls /tmp/out_p1/pipe/tofino.bin                # present => FITS
```

The frozen proven RRC kernel (12 ingress) — the restore baseline — compiles with no flags:
`$BP --target tofino --arch tna -o /tmp/out_rrc defense4_rrc_kernel.p4`.

Reference stage counts: RRC 12 · additive one-pipe BOR 14 · consolidated one-pipe faithful 13 (does
NOT fit — the hold core is an irreducible +1) · **two-pipe: pipe0 12 + pipe1 10 (fits)**. Raw evidence:
`evidence/bor_stage_recovery/`, `evidence/bor_two_pipe*/` (`COMPILE_MATRIX.txt`, per-variant logs).

## 2. Offline acceptance (24 gates) + lifecycle emulators + mutants

```bash
cd defense4/size/native_parity/offline
$RESEARCH_PYTHON test_bor_acceptance_gate.py        # -> 24/24 gates PASS
$RESEARCH_PYTHON bor_rrc_emulator.py                # faithful lifecycle; first_operate_shaped; 17 mutants
$RESEARCH_PYTHON bor_twopipe_faithful_emulator.py   # cross-pipe exactly-once; 8 mutants
```

Every gate is asserted from the emulators (first-OPERATE-held, SELECT-prepares-before-OPERATE, qid3
resident before qid2, byte-identical exactly-once, T0-anchored ACK/echo, `[28,21]` carve, byte-exact
reassembly, fail-open, invalid-deadline-rejected, anti-subtraction, retransmit-no-second-op, 1000+
transactions, 4-bit sequence wraps, frozen RRC regression). Non-vacuity: injecting a failure flips the
corresponding gate.

## 3. CLRT — the physical-silicon result (from the SEL-751 pcaps)

```bash
cd defense4/size/native_parity
J=evidence/hw_rrc_joint_20260812T223342Z/captures
$RESEARCH_PYTHON analyze_rrc_pcaps.py $J/read.pcap $J/sbo.pcap
```

Confirms (physical silicon): READ and SELECT responses both carve to `[28,21]` (30/30, byte-exact 49 B),
and under the D4 hold the pure-ACK→response CLRT is clamped — READ median ≈ 20.003 ms, SELECT ≈ 20.001 ms
(≈ 0.002 ms apart) vs native ≈ 2.1 / 1.1 ms (separable). This is the CLRT-fingerprint normalization.

## 4. Control plane (offline dry-run; hardware writes gated)

```bash
cd defense4/size/native_parity/p4
python3 defense4_bor_twopipe_setup.py dry-run --mode D4 --op-a-ms 16 --op-r-ms 22 --j-set 0,2,4,6,8,10,12
#   valid deadlines (R>=A, A>Jmax+native, Jmax<horizon) -> exit 0, prints the plan.
#   invalid (e.g. --op-a-ms 22 --op-r-ms 6, R<A) -> exit 2, rejected before any connection.
```

Actual hardware configure requires `DEFENSE4_HW_AUTHORIZED=1` and the switch (gated).

## 5. Figures

`defense4/figures/` holds the figure scripts (run with `$RESEARCH_PYTHON`) → PDF + PNG. Captions state
provenance: physical-silicon (CLRT/size), compiler-only (resources), offline/synthetic (physical-timing
convolution). See `PHASE10_RESULTS.md`.

## Not reproducible here (hardware/gated)
The two-program silicon LOAD (ready, gated on a watched window), physical OPERATE (BLOCKED — no
odd-point isolation), and any multi-device physical fingerprint campaign.
