# Defense 4 — release package

A clean, self-contained handoff for the DNP3 in-network obfuscation defense on one Tofino-1. This
folder contains **only** authoritative material; the full research history lives in the main
repository and is intentionally excluded here.

## Start here

1. **`CLAIMS_AND_LIMITATIONS.md`** — exactly what was demonstrated on silicon and what was not.
2. **`docs/DEFENSE4_SIMPLE.pdf`** — plain-language tour (6 pp).
3. **`docs/DEFENSE4_EXPLAINER.pdf`** — full technical tutorial (25 pp, all figures embedded).
4. **`docs/MEETING_REFERENCE.pdf`** — one-page speaking card (30 s / 3 min / detailed + Q&A).
5. **`code/README.md`** — which P4 is authoritative, how to configure it, what needs hardware.
6. **`evidence/E_FINAL/`** — the immutable evidence package (pcaps, CSVs, verdicts, figures).
7. **`tests/run_all.sh`** — one command to run every offline check (see `tests/EXPECTED_RESULTS.md`).

## The result in one paragraph

The authoritative implementation is the one-program **`defense4_rrc_bor_unified12`** design on one
physical Tofino-1 (one ingress pipe, ≤12 MAU stages, build flag `-DU_BOR`). **RRC** timing and fixed
**[28,21]** segmentation were demonstrated against a physical SEL-751: native CLRT (READ 1.27 ms /
SELECT 2.11 ms, high variance) becomes a fixed **4.001 ms (std 0.02)**, and every eligible 49-byte
response leaves as segments [28,21] (1280/1280 CRC/checksum-valid, 0 escapes). **BOR**'s
master-facing ACK/echo anchoring was demonstrated for guarded OPERATE (echo − ACK = R − A ≈ 4.00 ms,
invariant across J = 2/6/12 ms; all 32 relay outputs OPEN). **Relay-facing T0 + J and release
multiplicity were not directly observed** (dp68 is internal, not a tap), so exactly-once BOR is
inferred, not measured. Single device → signature *replacement*, not multi-device indistinguishability.

## Layout

```
defense4_release/
├── README.md                     ← this file
├── CLAIMS_AND_LIMITATIONS.md     ← the claim grid
├── docs/                         ← corrected explainer (pdf/docx/md), meeting sheet, glossary
├── code/
│   ├── README.md                 ← authoritative-file guide + how to run
│   ├── p4/                       ← defense4_rrc_bor_unified12.p4 (canonical) + defense4_rrc_kernel.p4 (baseline)
│   ├── control/                  ← setups + rollback/watchdog + dependency_manifest.md
│   ├── harness/                  ← guarded SELECT/OPERATE safety harness + preflight
│   └── analysis/                 ← size/CLRT/SBO analysis + offline lifecycle & decision-table verifiers
├── evidence/E_FINAL/             ← immutable evidence (pcaps, csv, verdicts, figs, reproduce.sh)
├── figures/
│   ├── vector/                   ← exact SVG masters (FIG-0/8/9/10)
│   └── publication/              ← PNG data + mechanism figures (FIG-1..13; PVA raster alternates excluded)
├── tests/
│   ├── run_all.sh                ← run every offline check
│   └── EXPECTED_RESULTS.md       ← what each check should print
└── MANIFEST.sha256               ← checksums for every file in this package
```

## Notation (used throughout)

For a request/OPERATE arriving at `T0`, the master sees the ACK at `T0 + A` and the response/echo at
`T0 + R`, so **`CLRT = R − A`**. Final campaign: `A = 20 ms`, `R = 24 ms` ⇒ `CLRT = 4 ms`. (`A` and
`R` are the control-plane knobs `D_A` and `D_A + D_R`, where `D_R` is the response gap after the ACK.)

*Evidence commit: the frozen `E_FINAL` package was committed at `5a0fb73` on branch
`defense4-size-native-parity-crc-split`. Program source sha256 `7ce30494…`; silicon binary `33fa3a77`.*
