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

## 2026-08-14 — S0-S2 decision posture

- The frozen `[49] -> [28,21]` result remains a historical shape-normalization baseline, not size hiding.
- The selected mechanism class is fixed-volume AEAD cellization.
- The concrete placement is Vision shim + Tofino CPU-side shim, but only conditionally on proving the `bf_kpkt`/`ens1` path as an endpoint-transparent punt/reinject boundary.
- If that proof fails, the mission answer is impossibility under the current testbed constraint, not a weaker packet-shaping workaround.

## 2026-08-14 — Gate S0 review result

- The size claim is corrected to **SEGMENT SHAPE ONLY** for `[49] -> [28,21]`; the frozen evidence remains unchanged.
- RN-L is defined as length hiding conditioned on a known transaction class, and RN-T as the stronger full protected-transaction policy.
- RN-L must contain at least two distinct inner lengths; a single 49-byte domain is rejected as vacuous.
- The adversarial proof review found the one-sided impossibility argument sound under its explicit endpoint-transparency and observer assumptions.
- S1 must prove a real second trusted boundary; the presence of an onboard CPU or kernel interface alone is insufficient.

## 2026-08-14 — Gate S1 audit result

- Vision is verified capable of hosting the master-side trusted shim: 25G `i40e`, MTU 1500 with jumbo headroom, Linux hook points, and installed AES-GCM/ChaCha20-Poly1305 APIs.
- The UFISpace onboard Xeon CPU is the only permitted relay-edge candidate. `ens1` is UP through `bf_kpkt`; standard AEAD APIs work locally; generic SDE CPU-port and driver TX/RX support exists.
- The Defense 4 program does not yet implement or prove bidirectional CPU punt/reinject through the intended RRC/BOR path.
- WireGuard/IPsec tools are absent, and audited ESP/TLS/MACsec interface offloads are fixed off.
- The selected S2 architecture must therefore be conditional on a later approved CPU-boundary proof. Failure of that proof ends the current-testbed mechanism.
- No live state was changed.

## 2026-08-14 — Gate S2 integrated decision

- The earlier S0-S2 posture entry recorded the working hypothesis before the S2 comparison was complete. This entry is the integrated decision record and supersedes that entry's use of "selected."
- Option A, a packet-preserving Layer-2 fixed-volume AEAD cell bridge, is the single **conditional selection awaiting author approval**.
- The design preserves the original inner Ethernet/IP/TCP/DNP3 packet and the existing RRC/BOR ordering; P4 classifies, gates, and steers but performs no cryptography.
- A dual TCP proxy is rejected as the primary design because it replaces end-to-end TCP acknowledgments and would change the existing RRC observation semantics.
- A standard secure tunnel is only a fallback transport after fixed-record cellization; no tunnel tool is currently installed. Existing ESP/TLS/MACsec offload is unavailable on the audited interfaces.
- The outer policy fixes complete wire size `C`, directional cell counts `K_*`, and release slots. Exact parameters and `L_max` are intentionally deferred until the complete S3 corpus is replayed.
- Loss, overflow, and deadline misses do not create public adaptive recovery: the transmitter continues the fixed cover schedule where alive, the receiver drops the incomplete epoch, and any inner TCP recovery occurs in a later full fixed epoch.
- The `P4 <-> ens1/bf_kpkt` path is a hard S6 feasibility condition. If it cannot be proven bidirectionally through the intended timing path with no clear bypass, the mechanism ends under the current-testbed constraint.
- S2 produced an editable SVG and exported PDF; no implementation, package installation, or live hardware state change occurred.

## 2026-08-14 — Author approval and Gate S3 opening

- The author explicitly approved the single conditional S2 decision.
- S3 is authorized for deterministic offline implementation and evidence only.
- S0-S2 security/design artifacts are now locked inputs; new code and evidence remain inside `real_size_normalization/offline/` and `real_size_normalization/evidence/s3_offline/`.
- The approved design still targets RN-L first and still treats the Tofino CPU punt/reinject path as a later hard feasibility condition.
- No live SSH, P4 load, BFRT/port/TM/PRE/mirror/pktgen mutation, traffic injection/capture, relay operation, or package installation is authorized by this approval.

## 2026-08-14 — Gate S3 offline result

- Policy `S3-RNL-256-v1` emits 22 fixed 256-byte outer Ethernet cells, or 5,632 captured bytes, in one fixed direction and slot schedule per epoch.
- The deterministic corpus contains 137 epochs: 100 balanced primary RN-L cases, 36 additional successful boundary/control/captured cases, and one explicitly labeled full-transaction overflow.
- All 136 successful epochs recover exact inner Ethernet frames; all 100 primary RN-L cases recover exactly.
- All public transcript invariants pass; evaluated structural mutual information is 0.0 bits; logistic regression and random forest are exactly at five-class chance with confidence intervals containing chance.
- All 45 adversarial fault cases pass without partial release. The 69-test unit/adversarial suite passes.
- Independent code/evidence review approved with zero open findings. The final manifest file hash is `64a43ac1d814a428f10593d6810df68c997d5b49934390dc9924e22f3eb9810c`.
- This is an offline construction result only. No live testbed action occurred, and the conditional Tofino CPU punt/reinject boundary remains unproven.
- S4 is not opened by this result.
