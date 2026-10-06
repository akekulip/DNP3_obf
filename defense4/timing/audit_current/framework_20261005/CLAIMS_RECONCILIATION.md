# Claim and provenance reconciliation — framework track, 2026-10-06

Status words are cumulative evidence, not interchangeable labels: **implemented** (source exists), **offline-tested** (passes tests or a
model), **compiled** (a compiler accepted the exact source), **loaded** (on the switch), **configured** (parameters read back from it),
**hardware-measured** (captured on the lab). A passing model does not prove the P4; a passing compile does not prove queue behaviour; a capture
at an interface does not prove application delivery. **Hardware status, 2026-10-06:** the candidate was loaded once (source `df599101…`), configured in the Timing OFF case, and 30 READs were hardware-measured through it; nothing about its holding behaviour, split or fallback has been run on hardware. Everything else below is offline. Historical claims and the
frozen manuscript are unchanged; nothing here promotes a result to approved evidence.

## Capabilities

| capability | implemented | offline-tested | compiled | loaded / configured / hw-measured | evidence |
|---|---|---|---|---|---|
| Response-ready READ release (dual) | yes | yes — 49 candidate tests (incl. table capacity), model-vs-P4 diff (14+ scenarios), mutation tests | SDE 9.13.1 and 9.13.2, 7 ingress / 0 egress, 88 tables, source `df599101…` | loaded and configured (OFF case); OFF-arm smoke 30/30 READ, median CLRT 2.240 ms; holding arms **not run** | `response_ready/`, `framework/tests/test_model_vs_p4.py` |
| Recovery: fallback, next transaction, stale, wrap | yes | yes | as above | no | same; **limits**: token loss leaves the owner armed (`KNOWN_LIMITATION` test), no FIN/RST handling, tag not cleared by a timeout |
| ACK-focused (Case 1) | by configuration only (D_A = 0) | yes (model, simulator, BMv2) | as above | no | needs a control profile that allows D_A = 0 (the adapter has one; `control.py` does not) |
| Response-focused (Case 2) | yes — new rows, `MODE_D2_RESP` | yes (model, simulator, BMv2) | as above | no | combined-ACK devices never arm it |
| Size split RRC_49_CUT28 | software only | yes — 120 captured segment pairs reproduced byte for byte; BMv2 equals the software carve | **no** (archive kernel only; fit with the 7-stage release unshown) | no | historical 2026-08-12 captures re-analysed, not a current measurement |
| BFRT control adapter | yes | yes, against a schema-faithful fake and the real compiled schema | n/a | `connect()` never run | three parameter tables only |
| BMv2 artifact | yes | yes — 9 cases against the model on real packets | n/a | software timing | `BMV2_ARTIFACT.md`; gating is emulated |
| Generated ACK (Case 3) | software prototype | yes — accepted by real TCP; loss unrecoverable | no | no | `PHASE7_GENERATED_ACK.md`; not a paper case |
| Analysis, statistics, Formby signature, figure | yes | yes | n/a | BMv2 data only | `framework/analysis/`, `framework/results/bmv2_clrt_20261006/` |
| Mechanism diagram | yes | inspected by eye | n/a | n/a | `framework/figures/fig_framework_mechanism.*` |

## Expected versus observed, per case (BMv2 software timing)

| case | expected | observed | note |
|---|---|---|---|
| dual, early response | ACK at D_A = 10 ms, response 1 ms after | ACK +0.6 to +0.7 ms over; gap 0.94–1.10 ms | software release jitter, both signs on the gap |
| dual, late response | ACK at the response, gap 1 ms | ACK within tolerance; gap within ±0.4 ms | |
| ACK-focused | ACK leaves when the response is seen | yes, within tolerance | request-to-ACK now equals the response latency |
| response-focused | ACK unheld; response at max(t_R, t_A + gap) | ACK passes in under 1 ms; response within 2 ms of the model | |
| watchdog | ACK at the horizon; late response native | ACK within 20 % of the observed horizon; response forwarded at its own arrival | next transactions succeed |
| size, joint | [28, 21], reassembly equal, timing preserved | yes in size-only, joint; timing-only unsplit; 57-byte response unsplit | arrival order [28, 21] here, [21, 28] in the 2026-08-12 hardware traces |
| generated ACK | transparent end-to-end delivery | lost request unrecoverable (3,003 ms timeout against a 209 ms control) | CLRT_new tracks latency unless scheduled |
| CLRT population, 120 READs per arm | normalisation | Timing OFF median 7.13 ms (sd 2.84 ms, variance 8.04 ms²); response-ready median 0.99 ms (sd 0.11 ms, variance 0.012 ms²); 113 of 120 within ±0.3 ms of 1 ms, the other 7 between 0.53 and 0.69 ms | matched seeded latencies; no value above the window |

## Unsupported breadth, for author review

- No hardware measurement of any candidate; no comparison of BMv2 with Tofino. The paper must not cite BMv2 timing as line-rate evidence.
- The size mechanism is demonstrated on 2026-08-12 hardware data and in software; the combination with the response-ready P4 is not compiled.
- SELECT and OPERATE are not admitted by the response-ready P4 and not implemented in BMv2; physical OPERATE was not prepared.
- No classifier was run: the populations are one software profile each, not devices, and a READ-only campaign has no READ-versus-SELECT result.
  Binary chance is 0.5 and three-class chance 1/3; the Formby feature vector (B = 200, H = 15 ms declared) is exported for any later evaluation.
- Case 3 is a proposed, software-only capability whose transport requirement is unresolved.
- No notation was introduced: CLRT_original, CLRT_new, D_A, D_R and e_A, e_R keep their meanings; the code name `D_R_ms` is configured CLRT_new.
