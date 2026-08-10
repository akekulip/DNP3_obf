# Evidence ledger — independent audit of 16 established findings

> **AMENDED for the one-Tofino constraint (`CORRECTION_LOG.md`).** The 16 findings below are unchanged
> and stand as verified. This revision adds five findings from the native-mechanism investigation,
> labeled as required:
>
> - **F17 [falsification result]** Correct on-switch fixed-K segmentation is impossible on an unchanged
>   master: mirror/multicast + truncation yields nested prefixes (overlapping-retransmission data loss or
>   corrupted stream); correct re-slicing needs store-and-forward TCP reassembly, i.e. a proxy.
>   (`analysis/tcp_segmentation_and_headers.md`.)
> - **F18 [falsification result]** The upstream `split_server.py` "byte preservation" is a
>   TCP-terminating proxy result (`bind/listen/accept/recv/sendall` + cross-segment reassembly) and does
>   not port to the switch. This retires re-segmentation as a native switch mechanism.
> - **F19 [verified fact]** Native protocol-valid cover cannot be made observer-indistinguishable without
>   encryption: in self-describing plaintext DNP3 the receiver's ignore-rule equals the observer's
>   strip-rule. (`analysis/native_dnp3_mechanisms.md`.)
> - **F20 [verified fact]** A fabricated DNP3 CONFIRM causes permanent SER/event-buffer deletion on the
>   outstation; decoy CROBs assert Remote Bits and write SER. Both are catastrophic on a live protection
>   relay and are barred. (`analysis/native_dnp3_mechanisms.md`; upstream `adversary-model.md`.)
> - **F21 [verified fact]** Endpoint-stamped header fields (TSval, seq/ack progression, data-offset /
>   option layout, window-scale) cannot be rewritten on one switch without breaking TCP, so device
>   identity survives via the stack fingerprint; only TTL, ip.id, DF, checksums, and window are
>   switch-normalizable. (`analysis/tcp_segmentation_and_headers.md`.)

**Auditor role:** evidence auditor (read-only).
**Source repo:** `/home/philip/Projects/DNP3`, pinned commit `7c4a5a78183b42cea4334b54faabcd5af14537a8` (`7c4a5a7`),
branch `origin/defense4-caseA-hw-integration`, working tree clean.
**Method:** every finding was checked by opening its artifact — file:line, git object, or JSON key/value —
not by trusting a summary. Leakage numbers were re-pulled from the JSON outputs under
`research/size_timing_coresidency/evidence/leakage/out/`. The post-fix silicon counts were re-derived by
summing the raw fail-closed scorer output (`blocks.jsonl`), not read off the freeze prose. Two numbers were
recomputed from raw data with `$RESEARCH_PYTHON` (the 12,204 B READ from the pcap; the per-mode bypass tallies).
**Working name only:** this repository is `DNP3_fixed_transcript`. It is not ADTA, GridCloak, or Defense 4.
Defense 4 is a frozen upstream timing result and is not rewritten here.

**Label taxonomy:** `verified fact` · `reproduction result` · `inference` · `design hypothesis` · `unresolved question`.

---

## Verdict summary

| # | Finding (short) | Label | Stands? |
|---|---|---|---|
| 1 | D4 is a bounded HW timing proof, not a universal DNP3 proof | verified fact | yes |
| 2 | Post-fix D2 and D4: 240/240 held + deadline-released, 0 response bypass | reproduction result | yes (re-derived from raw) |
| 3 | Scope = one SEL-751, Case-A READ, separate pure ACKs, single-segment, one active txn, no induced loss | verified fact | yes |
| 4 | CRC-boundary splitting preserves total response size for an aggregating observer | reproduction result | yes |
| 5 | Adaptive packet count moves size info into count and duration | reproduction result | yes |
| 6 | Adaptive splitting re-encoded ~1.06 bits (60.6%) of size entropy into timing | reproduction result | yes, with a normalization caveat |
| 7 | Only fixed K closed the idealized measured size channel | reproduction result | yes |
| 8 | Measured fixed-K=3 ≈ 287.3% overhead, corpus-specific | reproduction result | yes |
| 9 | A 12,204-byte READ invalidates K=3 as a general bound | inference (on a verified pcap) | yes, as inference |
| 10 | Trailer padding below IP falsified because ip.len exposes the L3 length | verified fact | yes |
| 11 | TTL + TCP data offset identify the three devices perfectly | verified fact | yes |
| 12 | TCP timestamp behavior stays visible after arrival-time shaping | verified fact (detection) | yes, with a point-estimate caveat |
| 13 | Request size separates READ from DIRECT_OPERATE in this corpus | reproduction result | yes |
| 14 | The 12ig/2eg egress-normalizer compile is a resource shape, not a working defense | verified fact | yes |
| 15 | The 11ig/2eg C1 result is a key-sensitive allocator outcome, not a durable saving | verified fact | yes |
| 16 | Replication, TCP translation, encryption, chaff, fixed-transcript coexistence not yet proven | verified fact (scope gap) | yes |

**Score: 16/16 supported by their own artifacts.** None refuted. Two carry material caveats (F6 normalization,
F12 point-estimate bias). One (F9) is an inference resting on a verified measurement rather than a bare fact.
The single most important discrepancy is external to the list: a same-commit sibling document
(`CHARTER.md`) contradicts the verified Finding 2 by quoting the pre-fix defect numbers as if still open (see
"Cross-cutting discrepancies" below).

---

## Per-finding detail

### Finding 1 — D4 is a bounded hardware timing proof, not a universal DNP3 proof
**Label: verified fact.**
- `defense4/timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md:3` — "Verdict: TIMING EXPERIMENTS PARTIAL WITH
  CLOSED CLAIM BOUNDARY."
- `EXPERIMENTAL_EVIDENCE_FREEZE.md:64-71` — the accepted claim is explicitly bounded: "On the corrected binary,
  on the physical SEL-751, READ-only … No claim is made about the physically-blocked negatives, live byte
  identity, or cross-device classification."
- `final_run/NORMALIZATION_ANALYSIS.md:5-6,34-41` — "This is a **single-device** measure … It is **not** a
  cross-device classification claim."
No discrepancy. The proof is a per-device, mode-conditioned CLRT normalization on one relay, not a claim over DNP3 devices in general.

### Finding 2 — Post-fix D2 and D4 held and deadline-released 240/240 responses with zero response bypass
**Label: reproduction result (independently re-derived from raw scorer output).**
Re-derived by summing `delta_cf_RESP_BYPASS` and `delta_cd_RELEASE_DEADLINE` over both corrected campaigns'
`blocks.jsonl` (`final_run/campaignA_corrected_binary/blocks.jsonl`,
`final_run/campaignB_corrected_binary_seed20260807/blocks.jsonl`):

| mode | held (early+late) | RESP_BYPASS | RELEASE_DEADLINE | source blocks |
|---|---|---:|---:|---|
| D2 | 240 (0 early + 240 late) | **0** | **240** | CA_D2_1/2, CB_D2_1/2 (each RESP_HOLD_LATE=60, RESP_BYPASS=0) |
| D4 | 240 (180 early + 60 late) | **0** | **240** | CA_D4_1/2, CB_D4_1/2 (RESP_BYPASS=0, RELEASE_DEADLINE=60 each) |

Every block has `"verdict":"PASS"`, `"exit_code":0`, `retransmit:0`, `dup_ack/dup_resp:0`.
- Fix commit `e47bcaa` (git show): "Defense 4 lifecycle fix: mode-conditioned ACK-release retire + qid5
  terminate-when-pending … Fixes the confirmed D2/D4 lifecycle defect (D2 240/240 bypass, D4 80/240 bypass)",
  author akekulip, 2026-08-07; ancestor of `7c4a5a7`; edits `defense4/timing/p4/defense4_caseA.p4`.
- `EXPERIMENTAL_EVIDENCE_FREEZE.md:24-27` states the same result (D2/D4 RESP_BYPASS=0 over 240 each; pre-fix
  was D2 240/240, D4 80/240).
**Caveat to carry downstream, not a defect:** "zero response bypass" is true for **D2 and D4 only**. D3 shows
`delta_cf_RESP_BYPASS` of 9/13/6/11 = 39 across A+B, which the freeze reframes as "D3 forwards 39 post-deadline
responses (its D_R=0 design, not a bypass)" (`EXPERIMENTAL_EVIDENCE_FREEZE.md:27`). Do not generalize "0 bypass" to all modes.
**Discrepancy (major, cross-document):** `research/size_timing_coresidency/CHARTER.md:53-59` (dated 2026-08-10,
newer than the freeze) states the defect is still OPEN — "deadline_release 0, RESP_BYPASS 240 … D2 does not
shape, and D4 is a mixture." Those are the **pre-fix** numbers. Finding 2 is correct; the CHARTER paragraph is stale. Detailed below.

### Finding 3 — Demonstrated scope
**Label: verified fact.**
- `EXPERIMENTAL_EVIDENCE_FREEZE.md:39-46` — experiment is master + physical SEL-751 (`.7`, Case A), READ-only;
  no separate software outstation on the shaped path.
- `EXPERIMENTAL_EVIDENCE_FREEZE.md:48-61` — the negatives (missing ACK, missing RESPONSE, FIN/RST, combined,
  multi-segment, SELECT/OPERATE, cross-device) are the "closed claim boundary," out of the experiment's scope.
- Single-segment / no induced loss, from raw `blocks.jsonl`: every block has `multi_segment_resp:[]`,
  `retransmit:0`, `rst_polls:[]`, `fin_midblock:[]`.
- One active protected transaction: `final_run/TARGETED_CASES.md:26-30` — "Every campaign block is ONE sustained
  TCP connection carrying 60 READs," polled sequentially (`n_rows:60`, one connection).
No discrepancy. "Separate pure ACKs" = Case A, consistent with the locked taxonomy.

### Finding 4 — CRC-boundary splitting preserves total response size for an aggregating observer
**Label: reproduction result.**
`out/m2_split_null.json`:
- `modes.native.MI_obsA_vs_native_size.mi = 1.55114250076411` and `modes.native.H_native_size_bits = 1.5511425007641102`
  — the aggregating observable determines the secret exactly (MI = H).
- `modes.split_bpc1.MI_obsA_vs_native_size.mi = 1.5511425007641102` (identical); same for bpc2, bpc4.
- `paired_deltas.split_bpc1_minus_native_MI_obsA.mean = 3.11e-17` with CI95 `[-2.2e-16, 4.4e-16]`; bpc4 = exactly 0.0.
- `byte_identity_assertion` = "…all 11494 responses passed"; `total_bytes_equals_native = True` in every mode.
No discrepancy. Matches `leakage-measurements.md:241-256`.

### Finding 5 — Adaptive packet count transfers size information into count and duration
**Label: reproduction result.**
- Count: `out/m2_split_null.json` — `modes.native.MI_segment_count_vs_native_size.mi = 0.06867413822506022`
  rises to `modes.split_bpc1.MI_segment_count_vs_native_size.mi = 1.0677767577035067` (a 15.5× increase, ≈69% of H).
- Duration: `out/m4_composition.json` — `conditions.P1_split_PERFECT_10ms.MI_duration_vs_size.mi = 1.0598614517476752`.
No discrepancy. Matches `leakage-measurements.md:242,269-270` and §6.

### Finding 6 — Adaptive splitting re-encoded ~1.06 bits (60.6%) of size entropy into the timing transcript
**Label: reproduction result — with a normalization caveat.**
`out/m4_composition.json`, `conditions.P1_split_PERFECT_10ms`:
- `MI_timing_vs_size.mi = 1.0598614517476752` (the ~1.06 bits), `p_value = 0.000999`, pivotal CI95 `[1.0498, 1.0705]`.
- `MI_timing_vs_size.mi_excess_over_null_mean = 0.9405530630156526`.
- `paired_deltas_vs_P0.P1_split_PERFECT_10ms.mean = 1.0623570522753665`, CI95 `[0.9997, 1.1534]` (excludes 0).
- `conditions.P0_native_PERFECT.MI_timing_vs_size.mi = 0.0` (reference).
**Caveat:** the "60.6%" is the **excess-over-null** fraction: 0.9406 / H(1.5511) = 0.606. The raw MI of 1.06 bits
is 1.0599 / 1.5511 = **68.3%** of H. `leakage-measurements.md:391-392` writes "re-encodes 1.0599 of 1.5511 bits
— 60.6%", pairing the raw-MI number with the noise-corrected percentage. Both are defensible individually, but
"~1.06 bits" and "60.6%" are two different normalizations of the same effect, not the same quantity. State which
one a downstream claim uses.

### Finding 7 — Only fixed K closed the idealized measured size channel
**Label: reproduction result.**
- `out/m3_grid_frontier.json` — every fixed-K row has `MI_shape_vs_native_size_bits = 2.22e-16` (≈0);
  e.g. `rows[policy=fixed, c=61, K=3]` and `[c=64, K=3]` both = 2.22e-16, anonymity k=3.
- `out/m4_composition.json` — `conditions.P5_gridfixed_PERFECT.MI_timing_vs_size.mi = 0.0` (`p=1.0`), vs adaptive
  `P1 = 1.0599` and `P4_gridadapt_PERFECT.mi = 0.067918` (`p=0.001`). Randomised-gap fixed-K
  `P6.mi = 0.012318` sits inside the null (`p=0.3147`).
No discrepancy. Matches `leakage-measurements.md:311,384,422`.

### Finding 8 — Measured fixed-K=3 ≈ 287.3% overhead, corpus-specific
**Label: reproduction result.**
`out/m3_grid_frontier.json`, `rows[policy=fixed, c=61, K=3]`:
- `mean_added_bytes = 135.75274056029232`, `mean_overhead_pct = 287.3240525908739`, `anonymity_k_devices = 3`.
- `summary.zero_leakage_min_overhead.fixed = 135.75274056029232`; native `summary.native_size_distribution =
  {37:5736, 54:3296, 61:2369, 74:64, 122:28, 183:1}`, `summary.Lmax = 183`, `summary.H_native_size_bits = 1.5511425`.
"Corpus-specific" because the fixed-K cost is set by `Lmax=183` for this six-capture corpus. No discrepancy.
Matches `leakage-measurements.md:311-313,328`.

### Finding 9 — A 12,204-byte READ invalidates treating K=3 as a general bound
**Label: inference, resting on a verified measurement.**
- Verified measurement (recomputed with scapy on the pinned blob): `dnp3_split_harness/captures/baseline/large_read.pcap`
  carries **12,204** response payload bytes from TCP sport 20000 across **20** non-empty segments — exactly the
  `baseline_segmentation.md:26` figure (12,204 B / 9 fragments / 49 link frames / 20 TCP segments).
- The inference is drawn in `leakage-measurements.md:538-542`: fixed-K overhead scales with `Lmax`; this corpus
  has no large READ, so its 287% "should be read as a floor for this traffic mix, not the deployment cost," and
  the zero-leakage overhead would rise "by roughly two orders of magnitude."
Why "inference": K=3 (from c=61, K≥⌈Lmax/c⌉) is bound to `Lmax=183`. A 12,204 B response needs K≈⌈12204/61⌉≈200,
so K=3 cannot cover it. That step is a sound deduction, not a directly measured fixed-K campaign against the large READ.

### Finding 10 — Trailer padding below IP was falsified because ip.len exposes the original L3 length
**Label: verified fact (measured falsification, multiply corroborated).**
- `research/size_timing_coresidency/reports/pi-scoping.md:84-85` — "the pad sits below IP, so `ip.len` entropy
  stayed at **1.000 bits** with padding ON while `frame.len` went to **0.000**."
- `CHARTER.md:38-41` — "It drove `frame.len` to a single value while leaving `ip.len` and `tcp.len` at full entropy."
- `reports/adversary-model.md:185` — `ip.len` "measured it unmoved at 1.000 bits with padding ON" (cites
  `SIZE_PRIMITIVE_REUSE_AUDIT.md:448-454`); `adversary-model.md:175` — "L2-4 Ethernet trailer … the falsified pad lived here."
- `reports/p4-resource-audit.md:409-410` — "falsified on silicon 2026-07-25 — it pads below IP, so `ip.len` is
  untouched and an observer simply reads `ip.len`. I used it as a resource probe only."
No discrepancy.

### Finding 11 — TTL and TCP data offset identify the three devices perfectly
**Label: verified fact (deterministic, no classifier).**
`out/m1_oracle.json`, `summary.deterministic_stack_rule["D-REAL(real device flows only)"]`:
- `signature_to_labels = {"(64, 5)":["ION7550"], "(64, 8)":["SEL751"], "(128, 5)":["AB1400"]}`,
  `injective = true`, `balanced_accuracy = 1.0`, `n = 11494`.
- `summary.mi_stack_vs_device.mi = 1.5286261574133686 = H_device_bits` — the (TTL, data_offset) signature carries 100% of device entropy.
No discrepancy. Matches `leakage-measurements.md:178-190`.

### Finding 12 — TCP timestamp behavior stays visible after arrival-time shaping
**Label: verified fact (detection) — with a point-estimate caveat.**
`reports/adversary-model.md:67-97` (F2). TSval is stamped by the relay when it builds the segment, so
`TSval(RESPONSE) − TSval(ACK)` "is untouched by any in-network hold." The D-sweep table (n=160/arm, 4 conns/arm)
shows the non-zero ΔTSval channel persisting across the shaping arms:

| arm | wall CLRT (mean) | non-zero ΔTSval | binomial vs "internal gap == observed" |
|---|---:|---:|---|
| native | 4.40 ms | 22/160 | p=0.66 (estimator calibrated) |
| d8 | 0.18 ms | 69/160 | p=5.9e-108 |
| d16 | 0.03 ms | 27/160 | p=2.6e-51 |

**Caveat (stated in the source, `adversary-model.md:91-97`):** under defense the concealed-interval **point
estimate** is biased (poll period 300 ms is a multiple of the 30 ms timestamp tick, so d8 reads 0.431). What is
robust is **detection** — the adversary learns "a middlebox is holding this device's packets" and gets an
order-of-magnitude estimate of the hidden interval. Finding 12 is correct as a detection/visibility claim.

### Finding 13 — Request size separates READ and DIRECT_OPERATE in the present corpus
**Label: reproduction result.**
`out/m5_reconcile.json`:
- `control_vs_read_from_request_size.balanced_accuracy = 1.0`, CI95 `[1.0, 1.0]`, every per-flow accuracy = 1.0.
- `request_size_by_fc = {"min":{"1":22,"5":35}, "max":{"1":22,"5":35}, "count":{"1":5694,"5":5800}}` — READ (fc 1)
  is a constant 22 B, DIRECT_OPERATE (fc 5) a constant 35 B, no overlap (5694+5800 = 11494).
No discrepancy. Corroborates `leakage-measurements.md:124-129` and the corpus-composition correction (§2.1: half the corpus is control traffic).

### Finding 14 — The egress-normalizer 12ig/2eg compile measured a resource shape, not a working size defense
**Label: verified fact (accurate scope reading).**
`reports/p4-resource-audit.md`:
- §5.2 `:336-350` — `S1_egress_size` compiles at **12 ingress / 2 egress**, 0 errors, ingress placement identical
  to baseline `[9 11 5 3 1 6 2 6 16 16 16 16]`.
- §5.5 `:404-410` — "It establishes the **resource shape** … It does **not** revive the mechanism. The
  trailer-padding mechanism this graft transplants was falsified on silicon 2026-07-25 … I used it as a resource probe only."
- §6 scope `:459-463` — "Compile-only … no functional or defensive claim is made about any variant."
No discrepancy. Note: audit compiles use bf-p4c **9.13.1**; the deployed timing binary is BF-SDE **9.13.2**
(`EXPERIMENTAL_EVIDENCE_FREEZE.md:14`). The audit is an offline resource probe, so the SDE difference is not a contradiction, but it should be stated when quoting these stage counts.

### Finding 15 — The 11ig/2eg C1 result is a key-sensitive allocator outcome, not a durable saving
**Label: verified fact (with control experiment).**
`reports/p4-resource-audit.md`:
- §5.4 `:396-398` — `C1_combined` = **11 ingress / 2 egress**, critical path 10, 111 tables, 0 errors.
- §3.2 `:214-222` — the 12→11 drop comes from adding one ingress table keyed on `hdr.ipv4.total_len`; "This is
  an allocator outcome, not a structural improvement, and it is key-sensitive." Control `I2_key_variant` — the
  same table keyed on `meta.pkt_class` — "compiles back at **12** stages … Any future edit can flip it back …
  Placement on this target is not monotonic in program size."
No discrepancy.

### Finding 16 — Replication, TCP translation, encryption, chaff, fixed-transcript coexistence not yet proven
**Label: verified fact (scope gap); each element is an unresolved question / future work.**
- Functional replication: `p4-resource-audit.md:419-422` — CRC-boundary splitting "requires producing *several*
  frames from one … ingress mirroring or multicast replication … the one place where the 'zero ingress cost'
  result does not transfer … should be priced with its own compile before any design commits to it."
- TCP translation: `adversary-model.md:266-280` — "Any padding design must be rejected at the whiteboard unless
  the sequence translator is part of it"; `pi-scoping.md:373` rates the `seq += Δ / ack −= Δ` translator the top
  compile risk. Not built.
- Encryption: `adversary-model.md:466-483,556` — padding inside an encrypted record is unstrippable only when
  "the switch is an endpoint of MACsec/IPsec," which the deployment is not; verdict on the in-band pad candidate is "Do not build."
- Chaff substitution: `adversary-model.md:558` (S3) — "Forbidden on safety grounds … can cause the master to
  WRITE to a live protection relay. Not a privacy trade-off; a disqualification." `adversary-model.md:56-65`
  (F1) additionally shows CROB-decoy padding is a request-size mechanism, "structurally null" at this observer vantage.
- Fixed-transcript coexistence: `CHARTER.md:5-13` — "those two axes have never co-resided in a program that is
  functional on real traffic"; the surviving fixed-K mechanism is identified but not built on silicon
  (`leakage-measurements.md:596-605`). The p4-resource-audit measured only a resource shape (Finding 14).
No discrepancy — the claim is that these are unproven, and the artifacts confirm each is unproven.

---

## Additional findings discovered during the audit

**A1 — The most important discrepancy: CHARTER and auto-memory carry a stale "defect OPEN" verdict that
contradicts the verified Finding 2 at the same commit.** `CHARTER.md:53-59` (2026-08-10) says the
`tag_retire_if_unmarked` defect is open — "deadline_release 0, RESP_BYPASS 240 … D2 does not shape, and D4 is a
mixture … 160/240 held ~8 ms, 80/240 bypassed." Those are the **pre-fix** counts (the freeze records pre-fix D2
240/240 bypass, D4 80/240). The fix `e47bcaa` (2026-08-07) and both corrected campaigns (final_run, 0 bypass)
pre-date the CHARTER by three days. The user auto-memory note `defense4-caseA-hardware-bringup-pass.md` carries
the same pre-fix framing ("D4 … is a MIXTURE … 160/240 held ~8ms, 80/240 bypass"). Net effect: a downstream
reader who trusts the CHARTER or the memory note would wrongly conclude the timing core does not shape. Finding
2, re-derived from raw `blocks.jsonl`, is the correct current state. The CHARTER's design instruction ("Design so
the size axis is separable from, and re-verifiable after, the retirement fix") is prudent, but its present-tense
"defect OPEN" verdict is stale and should be reconciled against `EXPERIMENTAL_EVIDENCE_FREEZE.md`.

**A2 — The size study and the timing proof are on two different datasets.** All leakage numbers (Findings 4-13)
come from the six-capture `Traffic Trace/` corpus (10.0.0.x, a lab configuration whose SEL-751 CLRT median is
12.21 ms, `leakage-measurements.md:140-143`). The D4 timing proof (Findings 1-3) is on the **physical** SEL-751
(192.168.10.7, ~1.4-1.9 ms CLRT). A downstream scheduler must not treat the corpus size distribution and the
physical-relay timing result as the same traffic.

**A3 — The size leakage numbers were generated at parent commit a42c9c5, committed at 7c4a5a7.**
`leakage-measurements.md:92` records "Repo commit `a42c9c554…`". HEAD is `7c4a5a7` ("Add size/timing
co-residency leakage measurement study"). Expected — the study was authored under the parent and committed as the
tip — but worth noting so the provenance line in a paper is exact.

**A4 — Statistical power floor.** With six flows and three labels the flow-level permutation null bottoms out at
p = 7/91 = 0.0769 (`leakage-measurements.md:530-535`). `mi_stack_vs_device.p_value = 0.07692` in
`out/m1_oracle.json` is that floor, not a weak effect; the stack result rests on injectivity + leave-one-flow-out
CV. `MI_obsA_vs_device.p_value ≈ 0.198` (m2) is likewise underpowered. Any device-anonymity claim needs more
independent capture sessions, which the report flags as cheap (`:617-618`).

**A5 — The software-twin exclusion changes several prior numbers.** The primary analysis drops the `10.0.0.2`
software outstation present in all six captures; pooling it (as prior work did) reads stack 0.5000 vs 1.0000 and
full-metadata 0.6207 vs 1.0000 (`leakage-measurements.md:561-565`). Not a defect, but any cross-reference to
older published values must state which labelling (D-REAL vs D-ALL) it uses.

**A6 — Corroboration of the ACK-mode refutation.** `dnp3_split_harness/reports/attacker_eval_results.json`:
`device_id.native.ackmode_only.{logreg,random_forest,gradient_boosting}.recall_macro = 0.6665833` and
`nearest_centroid = 0.6666667`, and identically across the timing-defense arms (`uniform_10_15`, `uniform_15_25`,
`constant_25`); `size_only.*.recall_macro = 0.4999166`. This independently supports the report's refutation of
"ACK mode at 1.000" (`leakage-measurements.md:196-202`) and the size-only ≈0.50 ceiling (Finding relates to M5).

---

## Cross-cutting discrepancies (ranked)

1. **CHARTER / auto-memory "defect OPEN" vs verified Finding 2 (major).** See A1. Two same-commit documents give
   opposite verdicts on whether the timing core shapes. Raw evidence sides with Finding 2 (0 bypass, 240/240 deadline-released).
2. **Finding 6 normalization (minor).** "~1.06 bits" (raw MI, 68.3% of H) and "60.6%" (excess-over-null / H) are
   two normalizations; the report prose pairs them as if one. See Finding 6.
3. **"Zero bypass" scope (minor).** True for D2/D4; D3 shows 39 counter "bypass" increments reframed as its
   D_R=0 design. See Finding 2 caveat.
4. **SDE version (minor).** Resource-audit compiles are bf-p4c 9.13.1; the deployed timing binary is 9.13.2. The
   audit is offline resource-only, so not a contradiction, but note it when quoting stage counts. See Finding 14.
