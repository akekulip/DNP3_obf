# Code — authoritative-file guide

## Which file is authoritative

| Role | File | Notes |
|---|---|---|
| **Canonical P4 program** | `p4/defense4_rrc_bor_unified12.p4` | The shipped design. Build flag **`-DU_BOR`**. One ingress pipe, ≤12 MAU stages. Source sha256 `7ce30494…`, silicon binary `33fa3a77`. |
| Frozen baseline kernel | `p4/defense4_rrc_kernel.p4` | RRC-only (size + CLRT), the timing/size baseline the unified program builds on. |
| **Canonical setup** | `control/defense4_rrc_bor_unified12_setup.py` | Configures the canonical program on the switch (ports, TM queues, pktgen, PRE, mirror, session, J codebook, timing). See `control/dependency_manifest.md`. |
| Timing helper | `control/defense4_caseA_setup.py` | Imported by the setup (timing params + 4-queue idiom). |
| Rollback / watchdog | `control/rollback_rrc.sh`, `control/watchdog_rrc.sh` | Operational safety (verified teardown; no snapshot). |
| Guarded-control harness | `harness/relay_sbo_operate_guarded.py`, `harness/relay_operate_guarded.py` | Hard `{1,3}`-index guard; **refuses index 6 (breaker-close)**. Test: `harness/test_relay_operate_guard.py`. |
| Preflight | `harness/preflight_checks.sh` | TCP-timestamp / port / topology preflight (fail-closed). |
| Analysis | `analysis/size_reconstruct.py`, `clrt_extract.py`, `sbo_timing.py`, `e4e5_analysis.py` | Size reconstruction (TCP-seq + DNP3 CRC + IP/TCP checksum), CLRT, BOR J-independence, Formby MI/JS/classifier. |
| Offline verification | `analysis/bor_unified_lifecycle.py`, `analysis/validate_decide_vs_oracle.py` | Lifecycle invariants + mutants; decision-table vs oracle equivalence. |

## Intentionally excluded (historical, in the main repo only)

The two-program / two-pipe BOR path and the stage-recovery / compile probes
(`defense4_rrc_bor_compile_probe.p4`, `*_sr_probe.p4`, `*_stagerecovery_probe.p4`,
`defense4_twopipe_pipe{0,1}*_probe.p4`, and their `BOR_TWO_PIPE_*` / `BOR_STAGE_RECOVERY_*` notes)
were the design-evolution route to the shipped one-pipe result. They are **not** part of this release.
The older `test_bor_acceptance_gate.py` describes the superseded two-pipe design and is **not** the
release test — use `tests/run_all.sh`.

## How to run (offline; no hardware, no SDE)

```bash
cd defense4_release
./tests/run_all.sh            # every offline check; see tests/EXPECTED_RESULTS.md
```

Individually:

```bash
python3 code/analysis/bor_unified_lifecycle.py        # 19/19 invariants, 11/11 mutants killed
python3 code/analysis/validate_decide_vs_oracle.py    # 2,580,480/2,580,480 tuples match
python3 code/harness/test_relay_operate_guard.py      # guard refuses forbidden index sets
```

## What requires physical hardware (testbed only)

Loading the P4 binary, TM/port configuration, contacting the relay, and any physical SELECT/OPERATE
require the Barefoot SDE 9.13.1 + the Tofino-1/SEL-751 testbed and `DEFENSE4_HW_AUTHORIZED=1`. The
physical SEL-751 stays READ-only except the one guarded, authorized `{1,3}` control gate.

## Evidence boundary

Master-facing observables (CLRT, segmentation, BOR ACK/echo invariance, safety) were measured on
silicon. Relay-facing `T0 + J` and exactly-once release were **not** captured (dp68 is internal).
See `../CLAIMS_AND_LIMITATIONS.md`.
