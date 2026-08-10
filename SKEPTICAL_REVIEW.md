# SKEPTICAL_REVIEW.md — Adversarial pre-decision review (hostile TDSC / NDSS standard)

> **Reading note (documentation correction, `CORRECTION_LOG.md` §"Second correction").** This review is
> the verbatim output of a read-only reviewer agent and is preserved as the record. Read it with these
> corrections applied: (a) the agreement of the specialist agents and this reviewer is **correlated
> internal analysis that found no counterexample**, not independent evidence or proof; (b) the term
> "DNP3-blind" is superseded — Defense 4 is DNP3-aware and the limitation is bounded per-packet parsing
> and state without arbitrary TCP-stream reassembly; (c) the size/count no-go is the **strongest
> candidate**, provisional, distinguishing absence-from-the-frozen-implementation from architectural
> impossibility; (d) the TCP-header axis is **unresolved**, with counterexamples to compile and test, not
> an impossibility; and (e) any "permanent SER/SOE deletion" reading is corrected to "a premature
> confirmation retires acknowledged events from the DNP3 event buffer and prevents later delivery,"
> pending SEL-specific evidence. The authoritative, corrected verdict is in `DECISION_MEMO.md`.

**Reviewer role:** skeptical PI / falsification referee. **Object under review:** the reconciled recommendation `NO_GO_FULL_TRANSCRIPT` for `DNP3_fixed_transcript`, built on `analysis/native_dnp3_mechanisms.md`, `analysis/tcp_segmentation_and_headers.md`, `analysis/tofino_native_scheduling.md`, against the framing in `CORRECTION_LOG.md`, `RESEARCH_CHARTER.md`, `THREAT_MODEL.md`, `OBSERVABLE_TRANSCRIPT_SPEC.md`, `D4_UPSTREAM_CONTRACT.md`. **Posture:** try to falsify the verdict before the decision memo is finalized. **Read-only.** Not ADTA, not GridCloak, not Defense 4. Pinned upstream `7c4a5a7`.

> Provenance note: this file was authored by a read-only falsification agent that could not write it itself; the lead persisted its content verbatim. It supersedes the prior `SKEPTICAL_REVIEW.md` (which reviewed the pre-reconciliation paired-gateway draft and returned `GO_WITH_BOUNDED_CLAIM`).

## Summary of what I reviewed

The reconciled recommendation asks whether one DNP3-blind Tofino-1, between an unchanged plaintext master and outstation, with no encryption and no decoding peer, can make the master-facing transcript `P_c = [(delta_i, S_i, d_i)]` independent of the protected device. Three specialist analyses converge on `NO` for the full transcript: (a) self-describing plaintext makes the receiver's ignore-rule identical to the observer's strip-rule, so no native cover is both safe and indistinguishable; (b) correct fixed-K re-slicing / padding of the single authoritative TCP stream needs store-and-forward reassembly = a proxy (and the upstream "byte-preserving" `split_server.py` *is* that proxy); (c) endpoint-stamped headers (seq/ack, TSval, data_offset, window-scale) cannot be rewritten statelessly on one switch; (d) a fabricated CONFIRM is a relay-safety catastrophe. The surviving positive is timing-only (frozen D4) plus a stateless scrub of the rewritable header subset; count, size-aggregate, and endpoint-stamped headers are declared residuals; the claimed contribution is the impossibility boundary.

**I could not falsify the core impossibility.** My hardest attacks — constructing a correct on-switch size/count mechanism, and finding an indistinguishable native cover packet the specialists missed — both failed, which *strengthens* the verdict rather than breaking it. The lethal problems are elsewhere: the decision memo about to be finalized still carries the *pre-reconciliation* verdict and rests on the *excluded* architecture; the surviving positive floor is cosmetic over D4 and does not close device identity; and one of the memo's three novelty pillars (TSval closure) is contradicted by the specialists and by the frozen resource audit.

## Strengths (stated honestly)

1. **The impossibility chain is sound and now mechanism-grounded, not hand-waved.** The "ignore-rule = strip-rule" argument is a genuine, generalizable kernel, and it is cross-checked against measured facts (payload never enters the PHV — verified in `research/ditto_comparison/DITTO_VS_DEFENSE3.md:80-82`; `split_server.py` is a socket proxy — verified `:44,515-521,667-669`).
2. **Endpoint safety is treated as a first-class disqualifier, not a footnote.** The CONFIRM/`ProcessIIN` hazards are source-verified (`DITTO_VS_DEFENSE3.md:96-98`), and the analyses refuse to trade a relay WRITE for privacy. This is the right instinct for an ICS venue.
3. **The specialists refuse to borrow the D4 number for the wrong mechanism.** `tofino_native_scheduling.md:37-39,209-213` explicitly forbids citing D4's reactive deadline-release jitter as evidence the periodic grid works. That discipline is exactly what a hostile reviewer would otherwise catch.

## Ranked objections (most-lethal first)

### S1 — MUST-FIX (lethal, consistency). The memo about to be finalized still carries the pre-reconciliation verdict and rests on the excluded architecture.
- **Claim attacked:** that the decision to be finalized is `NO_GO_FULL_TRANSCRIPT`. The on-disk `DECISION_MEMO.md` reads `GO_WITH_BOUNDED_CLAIM` (`:3`), recommends "pursue Architecture 4 as the engineering target" (`:53-55`), and states a bounded claim of independence over `(K, S_i, d_i, t_i, h_rw)` (`:24-30`).
- **Why it is wrong under the binding constraint:** `CORRECTION_LOG.md` C1 (`:24-25`) and `RESEARCH_CHARTER.md:19-22` make paired gateways / encryption / a second endpoint *excluded*, and `TRANSPORT_AND_ENCRYPTION_OPTIONS.md:3-12` banner-flags Architecture 4 as out of scope. The three specialists prove `S_i` and `K` independence are unattainable one-Tofino (`tcp:20-33,§2`; `native:§1,§2`; `scheduling:§3`). So the memo's positive `(K, S_i)` independence is the *Architecture-4* claim, and finalizing it as-is ships a headline that depends on the box the project forbade.
- **What would answer it:** rewrite the memo to `NO_GO_FULL_TRANSCRIPT`; strike `S_i` and `K` from the achievable vector (leaving `d_i`, `t_i`, and the rewritable-header subset); delete "pursue Architecture 4," which is now the excluded alternative, not the engineering target.

### S2 — MUST-FIX (verdict label). The surviving positive floor does not close device identity, so it is cosmetic over D4 as a *defense*.
- **Claim attacked:** that "D4 + stateless header-scrub (TTL, ip.id, DF, checksums, window)" is "the strongest bounded native defense that survives."
- **Why it is wrong:** the leakage study's device fingerprint is an *injective* `(TTL, data_offset)` map (`tcp:264-268`; `leakage-measurements.md:178-190`). One switch closes TTL [P] but not data_offset [E]. So after the scrub, data_offset alone still separates SEL-751 from AB1400/ION7550, and TSval + window-scale remain. The floor is a *partial, non-closing* fingerprint mitigation, not a device-identity defense. Sold as a positive defense it is "D4 plus a TTL rewrite that doesn't actually close identity," which a real reviewer scores `NO_GO`.
- **What would answer it:** demote the floor to a "measured non-closing mitigation" and stand the contribution on the impossibility result (S6). The `NO_GO_FULL_TRANSCRIPT` label is defensible *only* as an impossibility-contribution verdict, not a positive-defense verdict.

### S3 — MUST-FIX (internal contradiction, resource-settled). TSval closure (N2) is a headline novelty in one document and a proxy-only residual in another; the frozen audit sides against the novelty.
- **Claim attacked:** `DECISION_MEMO.md:102-103` ("a first-time closure of the TCP-timestamp channel (N2, TSval/TSecr rewrite) in the data plane … no prior DNP3/ICS work has done").
- **Why it is wrong:** `tcp_segmentation_and_headers.md:257` classifies TSval/TSecr as `[E]` — "needs per-flow bidirectional state and correct echo = proxy; naive clobber → PAWS drops." The reconciled recommendation itself files endpoint-stamped headers as residuals, and TSval is one. The tie-breaker is the frozen resource audit: TSval normalization is the same 32-bit per-flow bidirectional-state category as seq/ack translation, which the audit says does **not** fit — `W0-15` is 512/512 bits and tail stages 8–11 are 16/16 LTIDs, and per-flow seq/ack translation "lands on the saturated ingress tail and on the exhausted W0-15 group, **not priced**" (`p4-resource-audit.md:99,125-126,415-419`; confirmed this session). So N2 is not resource-feasible on the live core.
- **What would answer it:** demote N2 from "novelty pillar" to "unproven, resource-audit predicts infeasible," pending a dedicated compile probe. This removes one of the memo's three novelty pillars and must be reconciled before finalization.

### S4 — MUST-FIX (evaluation power). The empirical half of the impossibility rests on data that can support a negative claim but no device-family residual-leak measurement.
- **Claim attacked:** "the measured achievable floor" and "measured residuals" (`DECISION_MEMO.md:98-99,161-167`).
- **Why it is wrong:** the corpus is one physical unit per model, six flows, permutation-null floor p = 7/91 = 0.0769, with size and timing measured on two different datasets (prior `SKEPTICAL_REVIEW` O4; `EXPERIMENT_PLAN`/`EVIDENCE_LEDGER` as cited there). The *analytical* impossibility (proxy-needed, ignore=strip) is fine on small data. The *empirical* residual-leak claim ("data_offset/TSval/size survive and carry identity") is a device-family claim and cannot be made at n=1 unit/model.
- **What would answer it:** either run the ≥2-units/model, ≥5-sessions/device campaign for the residual measurements, or label every residual number as single-unit illustrative, not a measured device-family result.

### S5 — SHOULD-FIX (endpoint-safety inheritance). The surviving timing-only release is proven only in D4's narrow envelope; it does not get loss/retransmission/multi-segment/concurrency for free.
- **Claim attacked:** that the D4 real-packet release is a safe, correct surviving mechanism for the fixed-transcript setting.
- **Why it is wrong:** `D4_UPSTREAM_CONTRACT.md:44-53,143-151` fixes the tested scope at single-segment READ, one active transaction, **no induced loss/retransmission**, sequential polling, with the R11 reservoir margin **OPEN**. Multi-segment (the 12,204-byte READ), loss, retransmission, teardown, and SELECT/OPERATE are offline-validated 58/58, **not run live**. A held RESPONSE interacts with the outstation's RTO and the master's dup-ACK/fast-retransmit under real WAN loss; none of that is in the live evidence. The fixed-transcript regimes most needed are exactly the ones past D4's live edge.
- **What would answer it:** scope the surviving claim to the single-segment / no-loss / sequential envelope, or re-establish the other regimes live; do not inherit them from D4.

### S6 — SHOULD-FIX (novelty framing of the impossibility). "You need a proxy" is well-known; the result survives review only as a protocol-grounded theorem tied to a refuted belief.
- **Claim attacked:** that the impossibility boundary is a top-venue contribution.
- **Why it might be dismissed:** "traffic normalization needs a cooperating peer / transport termination" is established (Ditto = 2 switches, IP-TFS = 2 endpoints, NetShaper = middlebox pair). A reviewer will say "add a peer; nothing new."
- **Why it can survive:** framed as (a) the **ignore-rule = strip-rule theorem** for self-describing, CRC-checked, correctness-critical plaintext protocols (generalizes to Modbus, IEC 60870-5-104), (b) tied to a **refuted plausible in-repo belief** — the "CRC-boundary splitting preserves bytes" result, which source inspection confirms is a TCP-terminating socket proxy (`split_server.py:515-521`), not a switch capability, and (c) the **ICS-specific safety escalation** — native chaff is a WRITE to a protection relay / SOE deletion (`DITTO_VS_DEFENSE3.md:96-98`), a safety event, not a privacy tradeoff. Stated as "no one has done single-switch plaintext DNP3," it is a strawman and draws reject.
- **What would answer it:** adopt the theorem + refuted-belief + safety-escalation framing explicitly; separate the analytical impossibility from the empirical residual measurements (S4).

### S7 — SHOULD-FIX (boundary mis-classification). Two fields are filed on the wrong side, weakening the residual ledger.
- **ip.id:** rewritable to a constant `[P]` (`tcp:244`), which closes the OS ip.id-counter progression fingerprint. Yet the old `DECISION_MEMO.md:28,161` lists "ip.id progression" among endpoint-stamped residuals. Pick one: if the scrub sets ip.id constant, there is no progression residual.
- **count vs size:** the reconciled rec calls count a residual, but for the tested single-segment class responses are sub-MSS single segments (K = 1), so count is naturally invariant; the real residual there is `ip.len`/`tcp.len` (size), not count. The count leak bites only for the multi-segment (12,204-byte) class. Tighten the conflation.

### NITS
- `PRIOR_WORK_MATRIX.md` carries the correct v2 single-edge banner, but the Novelty-candidate body below it still reads Z.1 "plaintext-safe chaff" / Z.2 "single-edge endpoint-preserving" as pillars; these are struck in the memo but not in the matrix body — reconcile so a future reader does not resurrect them.
- Carry the SDE seam (audit bf-p4c 9.13.1 vs deployed 9.13.2) whenever quoting stage counts.

## Can I construct ANY correct + endpoint-safe on-switch native size-or-count mechanism? — No.

I attempted every candidate the task named, plus one of my own:

1. **Recirculation-buffered re-slicing — NO.** Recirculation re-injects the *same* packet; there is no addressable cross-packet payload buffer (register/SALU state is ≤32-bit scalars, not KB payloads), so the 20-segment 12,204-byte READ cannot be reassembled, and for a single segment recirculation still cannot excise an interior byte range.
2. **Multiple mirror sessions + per-copy seq offsets — NO.** Mirror-truncate keeps a *prefix* (first N bytes); K copies are nested prefixes, not a partition. Keeping seq → overlapping retransmissions (master keeps the first, drops the rest = data loss); bumping seq per copy → prefix bytes land at the wrong stream offset = corruption. Combining mirror-truncate with a compile-time parser-advance works only for K∈{2,3} on a single small segment (parser advance is bounded to tens of bytes), never for the tail cells of a 12 KB READ.
3. **Header-only truncation at existing segment boundaries — NO as a defense.** Forwarding the outstation's natural segments makes K = natural segment count = device/size-dependent, not fixed. Fixing K needs interior split or cross-packet coalesce — both store-and-forward.
4. **Exploit DNP3's 16-byte CRC-block structure — NO.** CRC-block boundaries are interior to the TCP payload and do not align with TCP segment boundaries (measured: a 292 B link frame straddles the 1448 B MSS segment). Cutting on a CRC boundary *is* the interior excision the switch cannot do without reassembly; the reference splitter that does it is a socket proxy (verified).
5. **Fixed count via coalescing rather than splitting — NO.** Coalescing = hold segment 1 until segment 2 arrives and concatenate payloads into one larger segment = cross-packet payload buffer = proxy. Tofino can hold a packet queue-resident (D4 does) but cannot merge two held frames into one segment; releasing two held frames back-to-back still shows the observer two frames (two `ip.len`), so it does not reduce count.

**Sharpest independent test (confirms the boundary rather than breaking it): retransmission of already-delivered data as size-carrying cover.** A replayed outstation→master segment below `rcv.nxt` carries variable payload and is *not* re-delivered to the DNP3 app (SOE-safe). But it is definitionally labelable by `seq < rcv.nxt` — the passive observer tracks `rcv.nxt` from the master's ACKs — and it triggers the master's dup-ACK → the outstation's fast-retransmit, perturbing the real connection. The exact property that makes it app-safe (seq below `rcv.nxt`) is the property that labels it to the observer. This is the ignore=strip theorem holding under its sharpest stress.

**Conclusion:** no correct + endpoint-safe + observer-useful on-switch native size-or-count mechanism exists. The only on-switch-correct construction (K∈{2,3} prefix split of a single small segment) protects nothing — ΔMI = 0 under an aggregating observer and it re-encodes into count/timing.

## Verdicts on the six attack points

1. **"Correct fixed-K needs a proxy" airtight?** **UPHELD** for any *useful* K. Verified that `split_server.py` is the proxy; recirc, mirror+seq, CRC-block, and coalesce all fail; the only on-switch-feasible case is trivial and protects nothing.
2. **Native cover truly impossible?** **UPHELD.** Pure-ACK carries timing not size and risks fast-retransmit; retransmission carries size but is labelable-by-seq and unsafe; unsolicited/keepalive/window-update/broadcast each either leak X, write to the relay, or require an endpoint change. No missed indistinguishable cover.
3. **Boundary complete and correct?** **SUBSTANTIALLY UPHELD**, with three required fixes: ip.id is reachable (memo mis-lists it as a residual); TSval is a residual, not a novelty, and resource-infeasible on the live core; count-vs-size is conflated for the single-segment class.
4. **Bounded claim novel over D4, or cosmetic?** The **positive floor is cosmetic/thin** — it does not close identity (data_offset survives). `NO_GO_FULL_TRANSCRIPT` correctly rejects the full transcript, but the floor must be labeled a non-closing mitigation; sold as a defense it is `NO_GO`.
5. **Endpoint safety of the timing-only release?** **Safe only inside D4's narrow tested envelope.** It inherits untested loss/retransmission/multi-segment/concurrency and the OPEN R11 margin; not free.
6. **Is the impossibility a defensible contribution?** **YES, conditionally** — as the ignore=strip theorem + refuted in-repo belief + ICS-safety escalation, with the analytical result separated from the empirical residual campaign. As "you need a proxy," **NO**.

## Reviewer-stance recommendation

**`NO_GO_FULL_TRANSCRIPT`** — I concur with the reconciled verdict; my strongest falsification attempts failed and thereby reinforced it. But finalization is conditional on three MUST-FIX items, without which the honest verdict drops to `NO_GO` (a memo that finalizes `GO_WITH_BOUNDED_CLAIM` on the excluded Architecture 4 is worse than no memo): (1) rewrite `DECISION_MEMO.md` to the one-Tofino verdict — strike Architecture-4 pursuit, `(K, S_i)` independence, and TSval-as-novelty (S1, S3); (2) demote the positive floor to a non-closing mitigation and stand the paper on the impossibility theorem (S2, S6); (3) run the ≥2-unit/≥5-session campaign for the empirical residuals or label them single-unit illustrative (S4).

**The single condition that would most change this recommendation:** a resource-plus-correctness demonstration that at least one of {size, count, TSval} can be closed on the single switch by a *stateful, non-proxy* rewrite that both compiles on the live core and is accepted by the unchanged endpoints. That is the only thing that converts an impossibility paper into a bounded *positive* contribution (→ `GO_WITH_BOUNDED_CLAIM`). The frozen resource audit predicts it fails (`W0-15` 512/512, tail 16/16), so absent that probe the impossibility framing is locked.
