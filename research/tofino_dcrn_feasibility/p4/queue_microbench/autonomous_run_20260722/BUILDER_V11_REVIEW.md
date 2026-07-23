# BUILDER_V11_REVIEW.md — Gate A decision (autonomous run 2026-07-22/23)

Two independent Gate-A audits (DNP3/ICS protocol; measurement/statistics), integrated by the main
agent (acting PI). Every finding was verified against source / tshark / recomputation, not accepted on
assertion. **Decision: PASS (conditions cleared).**

## DNP3 / ICS protocol audit — CONDITIONAL PASS with a BLOCKING retraction → CLEARED
- **Parsing/transaction/pure-ACK engine PASS:** DNP3 FC parsing agrees with the tshark dissector on
  100% of frames (SEL751 198 READ / 400 DIRECT_OPERATE / 598 RESPONSE); transaction reconstruction,
  pure-ACK qualification and ACK-role separation are protocol-correct on this corpus.
- **BLOCKING defect found and FIXED:** the earlier v1.1 headline "SEL-751 ~50/50 separate/combined" was
  **false** — `extract_raw` filtered only on port 20000, so a second shared outstation **`10.0.0.2`**
  (combined-ACK, 904 pkts in SEL751.pcap, present in all three base pcaps) was mislabeled. Real
  **SEL-751 (10.0.0.1) = 299/299 = 100% separate**, consistent with the locked ground truth
  (`ACK_DELAY_POLICY.md §5.A`, `CASE_A_TERMINOLOGY.md`). **Fix applied + verified:** each scope is
  filtered to its declared outstation IP (10.0.0.2 removed); an app-CONFIRM no longer opens a
  transaction. The false claim is **retracted** in the report. Per-device max corrected to SEL 120 /
  AB1400 108 / ION7550 115 B (127 B was the interloper).
- **Non-blocking limitations documented** (not fixed; do not use on higher-rate/physical traffic until
  addressed): TCP-coalesced two-frame segments parse only the first FC (~0.25%); frame-split-across-
  segments → labelled `unknown`, no reassembly; multi-fragment (FIR/FIN) reconstruction untested (all
  base responses single-fragment).
- **DNP3 verdict after fixes: PASS.**

## Measurement / statistics audit — CONDITIONAL PASS → CONDITIONS APPLIED
- **Core sound (verified):** MI plug-in estimator correct; constant-feature MI=0 genuine; GroupKFold has
  no train/test flow leakage; balanced-accuracy + chance null correct; §6.11 overhead is per-transaction
  (v1 bug fixed), arithmetic exact, 1 Hz cadence correct; Pareto dominance correct; reproduces
  bit-identically.
- **5 conditions APPLIED (evaluator → v1.2) + verified:** (1) flow-grouped MI bootstrap + permutation-null
  p; (2) Miller–Madow bias + MI≤2e-4 → ~0; (3) grouped-BA CI = leave-one-group-out + Student-t (k=2/z
  removed), "insufficient" when <2 groups/class; (4) ranking + Pareto leakage axis = max MI over
  {device, operation, ack_mode}; (5) log2(k) kept only as a labelled upper bound.
- **Honest finding after decontamination:** the clean base/long corpora are **3 flows = 1 per device /
  1 ack-mode per flow**, so **device and ACK-mode leakage are NOT cross-validatable** ("insufficient").
  `single128` = zero size-channel leak on all scopes (MI=0, perm p=1.0, invariant True). The
  `two_state` **operation** leak is record-level significant (perm p 0.001 base/long, 0.018 multicrob)
  but **flow-robust only where ≥5 flow-groups exist (multicrob)**; on base/long the flow-grouped CI
  spans the null. Report scoped accordingly. **The single128 selection is unaffected.**
- **Stats verdict after conditions: PASS** (with the documented finite-sample caveat).

## Independent verification (main agent)
- 16/16 regression tests pass on the clean corpus; all candidate filenames == candidate_id.
- 10.0.0.2 removed from base; SEL-751 = 299/299 separate (ground-truth-consistent); per-device maxima
  clean; single128 fits the loaded P4 (1 state/queue, 128∈pad set), covers 120→128, 0 unfit, zero
  measured size-channel leak (`single_state_invariant_holds=True`).
- evaluation.json regenerated on the clean corpus with the v1.2 stats; Pareto max-MI axis makes
  single128's zero-leak advantage explicit; cover_larger_corpus dominated by single128.

## GATE A DECISION: **PASS**
The builder v1.1 is accepted for Phase 2. The one blocking defect (a false, ground-truth-contradicting
ack-mode claim) is fixed and retracted; all statistical conditions are applied; the decision-relevant
result (`single128` = zero size-channel leakage; two-state trades padding for an operation signal) is
correctly scoped to the corpus. **Selected Level-1 baseline candidate = `single128_corpus_baseline`**
(the only candidate that fits the existing P4, has zero measured size-channel leakage, covers the true
base-corpus max, and has 0 unfit packets). Proceed to Phase 2 (CANDIDATE_SELECTION.md).

Residual must-fix-before-paper (non-blocking for the Level-1 hardware experiment): more independent
flows/captures per device for generalizable device/ACK-mode leakage; DNP3 reassembly + multi-fragment
handling before higher-rate/physical-SEL-751 traffic.
