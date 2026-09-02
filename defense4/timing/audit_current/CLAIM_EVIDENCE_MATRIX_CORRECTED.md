# Claim–evidence matrix, corrected (2026-09-02)

Every timing claim, paired with the evidence that supports it or the reason it is unproved. Based
on the active `campaign_v1` evidence and the verified implementation. Frozen historical evidence
retains its original terminology; this matrix governs active documents and the manuscript.

## PROVED — established by verified code, configuration, captures, and regenerated statistics

| claim | evidence |
|---|---|
| The read lane **replaces** the master-visible CLRT with `D_R = 4 ms`; it does not shift it. | Common-anchor equations (`QUEUE_AND_ANCHOR_AUDIT §3`) + variance ratio 0.058 (READ) and 0.0001 (SELECT), Brown-Forsythe p < 1e-300, against a counterfactual shifted-native that keeps native SD (`EVIDENCE_AUDIT §3`). |
| Under the mechanism, READ and SELECT CLRT medians are 4.000 ms with IQR 0.006 ms. | `MANUSCRIPT_VALUES.json`; reproduced from 132 captures. |
| The release policy is programmable: visible CLRT tracks configured `D_R` while end-to-end response time is fixed. | 18-point hardware sweep, `fig_policy_coverage_cost`. |
| 24 ms covers 99.900% of native read-lane exchanges; the envelope closes near the fail-open horizon. | Coverage `C(h)`, `EVIDENCE_AUDIT §2`. |
| The mechanism adds no master-facing frame or byte; workload completes (all 5,280 SELECT/OPERATE succeed). | `stats.json:overhead`; 1,448 frames / 130,708 bytes identical in both arms. |
| True end-to-end cost is ≈21–23 ms request-to-response, not the 2 ms CLRT delta. | `stats.json:added_response_latency_ms`. |
| For the evaluated fixed Random-Forest attacker, CLRT-only class inference falls to chance (0.333); MI falls from 0.383 bits to inside a permutation null. | `leakage.json`, `MANUSCRIPT_VALUES.json`. |
| single outstanding transaction; state is single-slot. | 22 registers all `bit<1>`-indexed size 1 (`QUEUE_AND_ANCHOR_AUDIT §4`). |

## SUPPORTED WITH LIMITATIONS — master-facing, one relay, defined sessions

| claim | limitation |
|---|---|
| Master-visible OPERATE response-to-ACK interval stays ≈4 ms under codebook {2,6,12} ms. | Configured codebook recorded; realized per-transaction `J` not observed; master-facing only. |
| Residual leakage: request-to-ACK retrains to 0.662 balanced accuracy under protection. | One SEL-751, 22 grouped runs in one ~5 h campaign; within-campaign, not cross-deployment. |
| Timing-feature suppression is transaction-class (READ/SELECT/OPERATE) inference. | One device; not device identification; scoped to the evaluated attacker. |

## UNPROVED — no evidence in this study

* Physical breaker-operation time suppression — `tP` never measured.
* Relay-facing release at `T0 + J` — no dp64 tap.
* Exactly-once physical execution — not observable master-facing.
* Multi-device indistinguishability — one device only.
* Cross-session / cross-day generalization — one campaign.
* Timing-only causality beyond `campaign_v1` — depends on `shape_enable=0`, which is PARTIAL for
  the frozen `final_read_sbo` configuration provenance (`EVIDENCE_AUDIT §5`).

## CONTRADICTED OR RETIRED

| retired claim | status |
|---|---|
| "echo" as a DNP3 message | corrected to "solicited OPERATE application response" in active artifacts (`TIMING_DEFINITIONS`). |
| SELECT timing as a physical-operation fingerprint | retired; it is SELECT-phase protocol timing. |
| simple-shift interpretation of the read lane | contradicted by the variance collapse + common-anchor equations; it is replacement. |
| "24 ms at 99.9%" | not in either dataset; 24 ms = 100% of the retained frozen sample, 99.900% of campaign_v1 native. |
| CLRT median change mislabeled as end-to-end added latency | corrected: cost is ≈21–23 ms request-to-response. |
| the spec's "frozen authoritative" MI 0.424/BA 0.5921 as the paper's values | those are the **retired** `final_read_sbo` values; the paper reports `campaign_v1` (0.383/0.6515). |

## Requires physical hardware actuation to resolve

Of the UNPROVED items, these can be settled **only** by a physically actuating experiment
(Level C), which is barred by this repository's no-experimentation rule and needs separate
authorization naming the breaker, operator, and rollback: physical operation-time suppression,
and any claim coupling a solicited response to completed actuation. Relay-facing `T0 + J` and
exactly-once delivery need a relay-facing tap (Level B with new capture), also gated. The
remaining items (multi-device, cross-session) need a different campaign design, not actuation.
