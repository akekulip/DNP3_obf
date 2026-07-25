# References

Sources for the concepts and prior art in this tutorial. Internal project documents are the primary
record for every measured number; external references are for background and positioning.

## External

- D. Formby, P. Srinivasan, A. Leonard, J. Rogers, R. Beyah. **"Who's in Control of Your Control
  System? Device Fingerprinting for Cyber-Physical Systems."** NDSS 2016. — Origin of the Cross-Layer
  Response Time (CLRT) device-fingerprinting feature this defense normalizes.
- R. Meier, V. Lenders, L. Vanbever. **"Ditto: WAN Traffic Obfuscation at Line Rate."** NDSS 2022. —
  In-network (programmable-switch) traffic-shaping/obfuscation via Traffic-Manager scheduling; the
  scheduling-based, load-stable direction this work follows rather than recirculation-only holding.
- IEEE Std 1815-2012, **Distributed Network Protocol (DNP3).** — Protocol definitions for READ
  (application function code 1), RESPONSE (function code 129), application control, and the data-link
  layer referenced in the code walkthrough.
- Intel/Barefoot **Tofino Native Architecture (TNA)** and **P4₁₆** language specification. — The
  data-plane programming model, Traffic-Manager queueing, and stateful-ALU constraints the
  implementation works within.

*Verification note:* the external citation details above are from training knowledge and standard
venue records, not fetched this session; confirm exact page/DOI before formal publication. The
measured results in this package do not depend on them.

## Internal (authoritative for all measured numbers)

- `research/timing_final/TIMING_REFERENCE_IMPLEMENTATION.md` — the frozen reference program.
- `research/timing_final/TIMING_MECHANISM_EXPLAINED.md` — the twelve-point mechanism explanation.
- `research/timing_final/TIMING_FINGERPRINTING_ANALYSIS.md` — entropy analysis, CIs, cross-device
  channels.
- `research/timing_final/TIMING_FINAL_RESULT.md` — one-page result and claim discipline.
- `research/timing_final/REVIEW_FINDINGS_AND_ACTIONS.md` — the seven review passes and dispositions.
- `research/timing_final/FINAL_EXPERIMENT_PLAN.md` — the campaign design.
- `research/timing_final/evidence/MANIFEST.md` — maps every reported number to a committed file.
- `research/timing_final/p4/dnp3_timing_normalizer.p4` — the canonical P4 program (sha 82f572ce).
