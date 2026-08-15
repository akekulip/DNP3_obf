# Real Size Normalization Decision Thread

This is an append-only coordination and decision log for the S0-S2 design tranche.

## 2026-08-14 — Scope lock

- The user constrained the architecture to the current testbed only: Vision, the existing UFISpace Tofino-1, and the current relay leg.
- No additional host, SmartNIC, gateway appliance, or relay may be introduced.
- The Tofino onboard control CPU is a candidate boundary only if its actual CPU-port path and cryptographic capability are verified.
- The primary observer is passive, protocol-aware, and TCP-aware on the Vision-to-Tofino link.
- Endpoint compromise, key theft, and physical compromise are outside the primary size-confidentiality claim; availability failures and active tampering remain robustness concerns.
- S0-S2 are authorized. Implementation and live hardware mutation stop at the design-approval gate.

## 2026-08-14 — Harness routing

- `tofino-p4` governs target-specific constraints and read-only hardware discipline.
- `filesystem-context` provides durable thread and agent-report artifacts.
- `harness-engineering` separates locked, editable, append-only, and human-controlled surfaces.
- `multi-agent-patterns` routes independent architecture, capability, standards, and adversarial-review lanes through a supervisor integration pass.
- `security-threat-model` defines the threat-model evidence and output contract.
- `ieee-paper-figures` governs the architecture figure source, sizing, export, and rendered validation.

## 2026-08-14 — Read-only live evidence

- Vision is `vision`, with `enp59s0f0np0` up at `192.168.10.1/24`; `cryptography` is installed (`41.0.7`), `openssl` is present, and `wg` is not installed.
- Tofino is `ufispace`, with `ens1` up, `bf_kpkt` as the driver, SDE `9.13.2-281-cpr`, `cryptography` installed (`2.8`), `openssl` present, and `wg` not installed.
- The live switch still runs `bf_switchd` from `/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd` with the expected control-plane listeners (`50052`, `9090`, `7777`).
- The live data-plane side still shows the expected 25G Vision link and the internal switch CPU-side interface, but the S1 audit must decide whether that is enough to host a real relay-edge trust boundary.

## 2026-08-14 — Gate S0 review result

- The size claim is corrected to **SEGMENT SHAPE ONLY** for `[49] -> [28,21]`; the frozen evidence remains unchanged.
- RN-L is defined as length hiding conditioned on a known transaction class, and RN-T as the stronger full protected-transaction policy.
- RN-L must contain at least two distinct inner lengths; a single 49-byte domain is rejected as vacuous.
- The adversarial proof review found the one-sided impossibility argument sound under its explicit endpoint-transparency and observer assumptions.
- S1 must prove a real second trusted boundary; the presence of an onboard CPU or kernel interface alone is insufficient.
