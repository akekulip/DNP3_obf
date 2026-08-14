# DNP3 Defense 4 — single authority

**Read this first. It supersedes every earlier Defense 4 status note. Where an older file
(`PROJECT_MAP.md`, `REPRODUCE.md`, `OVERNIGHT_STATE.md`, `EXPLAINER.md`, `PAPER-STATE.md`, the
two-pipe narratives) disagrees with this page, this page is correct and the older one is historical.**

## Authoritative result

> The authoritative implementation is the **one-program** `defense4_rrc_bor_unified12` design on
> **one physical Tofino-1**. It fits **one ingress pipe at ≤12 MAU stages** (egress ≤6). **RRC timing
> and fixed [28,21] segmentation were demonstrated against a physical SEL-751**; native CLRT
> (READ 1.27 ms / SELECT 2.11 ms, high variance) becomes a fixed **4.001 ms (std 0.02)**, and every
> eligible 49-byte response leaves as segments **[28,21]** (1280/1280 CRC- and checksum-valid, 0
> unsplit-49-byte escapes). **BOR's master-facing ACK/echo anchoring was demonstrated for guarded
> OPERATE traffic** (echo − ACK = R − A ≈ 4.00 ms, invariant across J = 2/6/12 ms; all 32 relay
> outputs stayed OPEN). **Relay-facing T0 + J and release multiplicity were not directly observed**
> (dp68 is an internal port, not a tap), so exactly-once BOR delivery is inferred, not measured.
> Single device → signature *replacement*, not multi-device indistinguishability.

- **Authoritative P4:** `size/native_parity/p4/defense4_rrc_bor_unified12.p4` (build flag `-DU_BOR`;
  source sha256 `7ce30494…`, silicon binary sha `33fa3a77`).
- **Authoritative setup:** `size/native_parity/p4/defense4_rrc_bor_unified12_setup.py`.
- **Frozen baseline kernel:** `size/native_parity/p4/defense4_rrc_kernel.p4` (RRC-only, size+CLRT).
- **Evidence (immutable):** `size/native_parity/evidence/E_FINAL/` — start with
  `CLAIM_MATRIX.md`, `VERDICT.json`, `README.md`.
- **Explainer / handoff docs:** `size/native_parity/explainer/` — `DEFENSE4_EXPLAINER.pdf`
  (full technical tutorial), `DEFENSE4_SIMPLE.pdf` (plain-language), `MEETING_REFERENCE.pdf`,
  `GLOSSARY.md`. A clean, self-contained release lives in **`../defense4_release/`**.
- **Claims + limitations (one page):** `CLAIMS.md`.

## Topology

```
DNP3 master (Vision, dp9)  →  observed WAN  →  one Tofino-1  →  physical SEL-751 (dp64)
                                             internal loopbacks: dp8 (RRC), dp10 (BOR); pktgen: dp68
```

One Intel Tofino-1 at the outstation edge. No second switch, no decoder, no external tunnel, no
endpoint modification; Tofino-1 data-plane only. The two internal loopbacks (dp8, dp10) are
switch-internal recirculation ports that give RRC and BOR their own Traffic-Manager schedulers — the
master and relay speak end-to-end through one box.

## What is / is not demonstrated (summary — full grid in `CLAIMS.md`)

| Claim | Status |
|---|---|
| RRC CLRT normalization (→ 4.001 ms) | **Demonstrated on silicon** |
| Fixed [28,21] segmentation, 0 escapes | **Demonstrated on silicon** |
| Formby CLRT feature-suppression (READ-vs-SELECT) | **Demonstrated on silicon** |
| BOR master-facing ACK/echo invariance (anti-subtraction) | **Demonstrated on silicon** (guarded OPERATE) |
| Safety (no actuation; all 32 outputs OPEN; index-6 refused) | **Demonstrated on silicon** |
| One pipe, ≤12 ingress stages | **Compile-confirmed** (bf-p4c) |
| Exactly-once BOR / relay-facing T0+J | **NOT observed** (dp68 internal; inferred only) |
| Multi-device indistinguishability | **NOT claimed** (single SEL-751 → replacement) |
| Byte-identical-to-source | **NOT claimed** (only CRC/checksum-valid reconstruction) |

## History / archive

The earlier **two-program, two-pipe, compile-only** BOR path and the stage-recovery / probe
programs were the design-evolution route to the shipped one-pipe result. They are historical and are
being moved under `archive/` (see `archive/README.md`). They remain in git history and must not be
read as the current authority. The decision-table flatten (RRC 12→10 stages) is what let BOR fit in
the freed headroom at 12 in a single pass, so the two-pipe split was not needed.

*Authoritative evidence commit: see `git log` for the branch `defense4-size-native-parity-crc-split`;
the frozen evidence package (`E_FINAL`) was committed at `5a0fb73`.*
