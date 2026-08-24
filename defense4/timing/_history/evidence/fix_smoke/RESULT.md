# Fix smoke test: D2 now shapes the RESPONSE (was 240/240 bypass)

Corrected binary sha256 `97175e7d` loaded under the watchdog (Defense 3 rollback target).
D2 policy D_A=0, D_R=8 ms, 20 sustained READs. Counter signature (scored, verdict clean):

| counter | pre-fix (defective) | post-fix |
|---|---|---|
| RESP_BYPASS | 240/240 | **0** |
| RESP_HOLD_LATE | 0 | **20** |
| RESP_HOLD_EARLY | (D_A=0 -> none) | 0 |
| deadline_release | 0 | **20** |
| ack_release / ack_rel_retire | 0 / 240 | **20 / 0** |
| CLRT median | ~2.9 ms (native, unshaped) | **8.025 ms (held to T_RESP)** |

The ACK release now preserves the transaction (ack_rel_retire 0, ack_release 20); the RESPONSE
arriving after ACK release is held in qid4 and released on the T_RESP deadline (RESP_HOLD_LATE 20,
deadline_release 20); zero bypass; no stale reg_tag after the block. The scorer that fails on
protected-mode bypass returns clean. This is the single-mode proof; the full corrected campaigns
(all invariants) follow.
