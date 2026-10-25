# c67 abort01 survivor gate diagnosis

**Classification: incomplete v2 stimulus/survivor observation, not an ACK-plus-response frame-count mismatch.** Confidence: high. No source, assertions, evidence, Git state, models, or hardware were changed; only this handover report was written.

`ctl_timing_01/evidence/model_abort_m12p_c67_sdk9132_01/abort_results.json` records 80/80 passing driver cases and launch exit 0. The independent v3 gate correctly blocks four negative controls:

| Negative control | Master response copies | All master frames | ACK commits / response releases | Held retries |
| --- | ---: | ---: | --- | ---: |
| `abort_held_READ_plus90` | 0 | 0 | 0 / 0 | 837 |
| `abort_held_READ_plus92` | 0 | 0 | 0 / 0 | 925 |
| `abort_held_SELECT_plus48` | 0 | 0 | 0 / 0 | 922 |
| `abort_held_SELECT_plus50` | 0 | 0 | 0 / 0 | 1140 |

All four show response admission before the invalid RST, no reset to the master, and E reset-front delta zero. They establish rejection of the invalid reset. They do **not** establish eventual delivery of the surviving response.

`model_summary.py:190`–208 requires `responses == 1` and exactly one `RESP_RELEASE + RESP_FALLBACK`, alongside no reset and no E-16 increment. It does not inspect `frames_to_master`, standalone ACK copies, or ACK-commit counts. Consequently, receiving two frames instead of one is not the cause; the retained rows have zero response copies and zero releases. A read-only invocation of the actual `_abort_negatives(results, relay=True)` reproduces exactly these four failures.

The retained executed `driver_dependency_model_contention.py:635`–653 sends a standalone ACK only for `branch == 'released'`. Its held branch sends only the response and waits for admission. For the four negative offsets, lines 693–697 assert only no master reset / no E-16 increment, then record the row. No standalone server ACK is supplied before cleanup at lines 743–746 sends the master's own RST. This construction inherited the older age-based held-response behavior; under `response_ready_ack_d_v2`, a response alone is intentionally insufficient for release. The actual parameter record writes only `gap`, `op_j`, `budget`, and `enabled`; the supplied legacy `pb` is not an effective v2 expiry.

Thus the evidence shows an intentionally retained response waiting for a missing prerequisite, not proof that the invalid RST destroyed the response. The 80/80 driver result is weaker than the surviving-response gate. Do not relax the gate, relabel abort01, or treat this as a data-plane defect without completing the missing stimulus.

Minimal next investigation/repair when implementation resumes:

1. Keep the original held-positive abort cases unchanged: they must observe a held response flushed by a valid reset.
2. For v2 negative controls only, first establish admission and rejection of the invalid RST without a master reset or E-16 increment. Then send a genuine standalone server ACK for the same request and capture resolution before cleanup.
3. Require exactly one correctly mapped ACK and one exact surviving response, `ACK_COMMIT +1`, `RESP_RELEASE +1`, and actual T-clock ACK-after-both-prerequisites / full-D proof. Record the post-completion row used by `_abort_negatives`. Avoid retransmitting the response or issuing a new request as acceptance evidence: the claim concerns the already-held original surviving the invalid reset.
4. Run the bounded abort driver again and recompute v3. A model launch remains necessary to supply this currently absent survivor evidence; a checker-only accounting change cannot create it. If the genuine ACK still cannot release the retained response, inspect that narrow connection's T events and epoch/generation state to distinguish actual invalidation from stimulus admission failure.

The JSON rows, retained driver branch, actual parameter write, and checker conditions settle this mismatch without a broad parse of the large model logs. This blocker is separate from stale dependency hashes and the earlier contention reset-case-name issue.
