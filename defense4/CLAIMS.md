# Defense 4 — claims and limitations

Authoritative program: `defense4_rrc_bor_unified12` (one Tofino-1, one ingress pipe ≤12 stages,
build flag `-DU_BOR`). Evidence: `size/native_parity/evidence/E_FINAL/`. Notation: for a request/
OPERATE arriving at `T0`, the master sees the ACK at `T0 + A` and the response/echo at `T0 + R`, so
`CLRT = R − A`. Final campaign: `A = 20 ms`, `R = 24 ms` ⇒ `CLRT = 4 ms`. (`A = D_A`,
`R = D_A + D_R`, where `D_R` is the response gap after the ACK.)

## Demonstrated on the physical SEL-751

| # | Claim | Evidence | Number |
|---|---|---|---|
| C1 | CLRT normalized to a fixed policy value | `verdict_stats.json` | native READ 1.272 / SELECT 2.107 ms → **4.001 ms, std ≈0.02** (both) |
| C2 | Fixed per-packet segmentation for eligible 49-byte responses | `size_verdict.csv` | native 100×[49] → **1280×[28,21]**, all CRC + IP/TCP-checksum valid |
| C3 | Zero unsplit-49-byte escapes (defended) | `VERDICT.json` | **0** |
| C4 | Formby CLRT feature-suppression (READ-vs-SELECT) | `verdict_stats.json` | MI 0.424 → **0.0018 bits** (within perm-null); classifier BA 0.592 → **0.500** |
| C5 | BOR master-facing ACK/echo invariance (anti-subtraction) | `sbo_j{2,6,12}.csv` | **echo − ACK = 4.00 ms, std ≈0.026**, invariant across J = 2/6/12 ms |
| C6 | Safety — no physical actuation | `readbacks/relay_outputs_final.json` | **all 32 outputs OPEN**; index-6 breaker-close hard-refused |
| C7 | Testbed unchanged (paired native/defended on one binary) | `E0_testbed_preservation.md` | OFF vs D4 toggle, same binary |

## Compile-confirmed (not a silicon runtime measurement)

| # | Claim | Evidence |
|---|---|---|
| K1 | One pipe, ≤12 ingress MAU stages (egress ≤6) | bf-p4c place logs (`switch_compile_9132/`) |
| K2 | Decision-table flatten: RRC 12→10 stages; BOR fills the freed 2 → 12 in one pass | `RRC_BOR_UNIFIED12_RESULT.md` (archived) |
| K3 | Offline lifecycle: 19/19 invariants, 11/11 mutants killed | `verification/bor_unified_lifecycle.py` |
| K4 | Decision-vs-oracle equivalence: 2,580,480 / 2,580,480 tuples | `verification/validate_decide_vs_oracle.py` |

## NOT demonstrated / NOT claimed (hard boundary)

| # | Limitation | Why |
|---|---|---|
| L1 | **Exactly-once BOR delivery — inferred, not measured** | The relay-facing wire was not captured (dp68 is an internal pktgen/recirc/clone port, not a host tap). `T0 + J` and release multiplicity are model-verified only. The master issued one OPERATE per transaction and no output actuated — that much is observed — but this is not relay-facing duplicate-suppression evidence. |
| L2 | **Multi-device indistinguishability — not claimed** | Only the SEL-751 hardware identity was tested. Its native CLRT + segment-shape signature is *replaced* by a fixed policy; it is not made indistinguishable from other device types. |
| L3 | **Byte-identical-to-source — not claimed** | No source-side original-frame oracle was captured; only a sequence-contiguous, CRC- and checksum-valid 49-byte *reconstruction* is shown. |
| L4 | **Total DNP3 length is not hidden** | 49 bytes stays 49 (28+21). A full TCP reassembler recovers all 49 bytes. What is normalized is per-packet segment *shape* and packet *count*, not application length. |
| L5 | **A/R include a path/capture offset** | The ~21/25 ms master-facing A/R include ~1 ms of path + capture offset over the configured 20/24 ms; the internal switch deadline vs switch-observed T0 was not separately instrumented. |
| L6 | **Classifier split is transaction-disjoint, not session-disjoint** | Single capture session; a stated limitation of the feature-suppression result (it is a transaction-class test, not a device-ID test). |
| L7 | **BOR mitigates, does not "defeat"** | BOR is *designed to mitigate* the Formby physical operation-time fingerprint by anchoring master-visible ACK/echo to T0 and adding bounded release jitter. The master-facing invariance was measured; the physical-operation claim is bounded by L1. |

## One-line boundary

One Tofino, one `unified12` program, two internal scheduling domains → fixed **[28,21]** segmentation
for eligible 49-byte responses, ~**4 ms** policy CLRT, guarded BOR ACK/echo invariance — with the
explicit limitation that **relay-facing T0 + J and exactly-once release were not directly observed.**
