# WORKING NOTES — Defense 4 lifecycle repair (authorized run, 2026-08-07)

**Task:** the user authorized fixing the D2/D4 lifecycle defect, proving it on silicon, and leaving a
working D4 running. Branch `defense4-caseA-hw-integration`, start HEAD `bf641ac` (after 5682bc7).
Keep the current D4 running through audit/impl/offline-test/compile. Do NOT restore Defense 3 (it is
only the emergency rollback). Preserve a read-only snapshot before any switch write. Arm+verify the
watchdog (D3 rollback target) immediately before loading the corrected binary. No size obfuscation,
no merge to main, do not call it ADTA. Write plain storyline prose (see memory).

## The defect (verified from source, defense4_caseA.p4)
Half 1 — mode-blind retire. `tag_retire_if_unmarked` (RegisterAction on reg_tag, :1424) retires an
unmarked 0xCn tag (`if ((int<8>)v < 8s0) v = TAG_INACTIVE`, no PHV input) and is applied on every
CLASS_ACK_REL (:2402). Correct for D3 (ACK-only), WRONG for D2/D4: at ACK release the RESPONSE has
not arrived, tag is unmarked, so it retires; the later RESPONSE finds txn dead -> RESP_BYPASS.
Silicon: D2 240/240 bypass, D4 80/240 bypass.
Half 2 — qid5 vanishes at T_RESP. The RESP blocker terminates on `expired_resp==1` (:2697,
CD_BLOCK_TERM_DL) even when no RESPONSE is pending, so on a missing/late RESPONSE the reservoir
disappears at T_RESP and can leave stale state.

## Constraints (verified)
- reg_tag SALU is FULL at 2 PHV inputs (meta.gen_in, meta.tag_val, :1260). Cannot add a 3rd.
- reg_tag already has 4 RegisterActions (tag_arm, tag_rmw, tag_read_or_mark, tag_retire_if_unmarked);
  adding a 5th risks the per-SALU action limit.
- meta.tag_val on CLASS_ACK_REL is reg_ack_rel's write operand (the ack-release generation), reused
  as reg_ack_rel PHV input 2 (:792-806). rel_diff (meta.tag_diff) distinguishes RESP_HOLD_EARLY
  (rel_diff!=0) vs RESP_HOLD_LATE (rel_diff==0) — counters CF_RESP_HOLD_EARLY/LATE already exist (:621).
- meta.mode IS available in the apply block (used at :2386). Modes: OFF/D1/D2/D3/D4/FAIL_OPEN.

## The fix (design; the p4-dataplane-engineer is resolving fix-1 operand reuse)
1. Mode-condition the ACK-release retire: D2/D4 PRESERVE the tag (RESPONSE obligation survives ACK
   release); D1/D3 keep retire-if-unmarked. Must reuse an existing reg_tag operand (no 3rd PHV input,
   no 5th action if avoidable). Candidate: encode the retire/preserve decision on meta.tag_val.
2. qid5 terminate-only-when-pending: a LIVE-but-not-PENDING RESP blocker at expired_resp must NOT
   terminate on the deadline; continue to the bounded budget/fail-open path. Only V_BLOCK_PENDING
   (RESPONSE observed) terminates at T_RESP (releases the RESPONSE).
3. Keep RESP_HOLD_EARLY (before ACK release) and RESP_HOLD_LATE (after) separately measured via
   reg_ack_rel rel_diff. Update ACK-release counters (txn_active==1 no longer means "retired").

## Invariants to prove
D2/D4 ACK release preserves the RESPONSE obligation; D1/D3 retire as before; RESPONSE after ACK
release but before T_RESP -> qid4, release at T_RESP, retire, next READ arms; RESPONSE after T_RESP
-> measured late path, safe release, retire, reuse; no RESPONSE -> qid5 stays gen-bound until bounded
fail-open; missing ACK/RESP/dup/stale/FIN-RST/fail-open never strand the next txn. Do NOT mask by
raising D_A.

## Proof required before paper (all on the corrected binary)
9.13.2 compile + full resource artifacts; offline lifecycle regressions; D2 ACK-before-RESP with 0
unplanned bypass; D4 RESP before T_A / between T_A and T_RESP / after T_RESP; missing-ACK + missing-
RESP bounded cleanup; next-txn re-arm; >=33 READs one connection; D1+D3 regression; scorer FAILS on
protected-mode bypass; in/out byte comparison; per-transaction counter reconciliation; token-escape/
ordering/queue-drop/port-drop/retransmit/reset; fixed + randomized campaigns with FULL distributions
(not median-only); one consistent freeze, no contradictory retained prose. Keep the old defective
D2/D4 campaigns as pre-fix evidence (do not overwrite).

## PHASE TRACKER
- [x] Read git + source + baseline snapshot (prefix_snapshot_*, committed bf641ac). Defect verified.
- [x] Design (p4 expert) VERIFIED vs source: 7 changes A-G, no new register/SALU/PHV/counter.
- [x] Implemented 7 changes (A tag_val=0 on ACK_REL; B mode-select retire/preserve; C counter mode-cond; D qid5 pending-gate; E+F read-only ack_rel_r restores EARLY/LATE; G split hold count). reg_tag stays 4 actions, reg_ack_rel 1->2. sha 1242ca4d.
- [ ] Offline: bf-p4c placement/resource check; regression harness.
- [x] Compiled on 9.13.2: 0 errors, 12/12 ingress, bin sha 97175e7d. Artifacts in compiler_9132_fix/.
- [ ] Harness: scorer FAIL-on-bypass + byte comparison; driver in/out byte capture.
- [x] Deployed under watchdog (D3 target): loaded fix binary 97175e7d, forwarding ok. SMOKE PROVEN: D2 now holds RESPONSE (RESP_HOLD_LATE 20, BYPASS 0, CLRT 8.0ms) vs pre-fix 240/240 bypass.
- [ ] Corrected campaigns proving every invariant (fixed + randomized, full distributions).
- [ ] One consistent evidence freeze -> verdict.
- [ ] Only if PASS/closed-partial: revise Introduction + claim-source matrix.

## NEXT ACTION
Improve the scorer (fail on protected-mode bypass) while the expert designs; then implement the P4
fix from the reconciled design; compile; deploy under watchdog; run corrected campaigns.
