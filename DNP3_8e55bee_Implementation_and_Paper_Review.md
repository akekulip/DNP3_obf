# Review of DNP3_obf at 6fbf351

Reviewed 16 September 2026. Exact commit: `6fbf3519c9b31f141579fcdc94d0be7fe6b23c4e`.

**The merge improves several earlier defects, but it does not yet warrant an implementation-correctness sign-off.** The normal-case campaign still supports the timing result. There are remaining active-code defects, a newly identified loss-recovery failure path in the frozen OPERATE implementation, and inconsistencies between the corrected analysis, the figures, the paper source and the published PDF.

This was a read-only repository review. No hardware was accessed, no firewall rule was applied, no traffic was generated, and no repository file was changed. Active execution paths were exercised only through repository test doubles. Findings about untested P4 packet-loss paths are identified as source-level reasoning, not hardware observations.

## Verification performed

| Item | Independent review result |
|---|---|
| Remote revision | Confirmed `main` at the exact commit above. |
| Active control/harness/probe and timing tests | **179 passed**, reproduced. |
| Protected introduction | **PASS:** all three supplied paragraphs are word-for-word intact. |
| Frozen implementation and protected raw captures versus `8278346` | No tracked-file differences on the protected paths. |
| Campaign | Fresh extraction: **132 captures, 63,360 exchanges, zero validator problems**, including the new CRC and ACK-range checks. |
| Policy sweep | Fresh validation: **19 points, 5,860 transactions, zero problems**. |
| Statistics and classifiers | Regenerated using the committed dependency lock. Combined-feature adaptive balanced accuracy remains about **0.651**. |
| Campaign reproduction tests | **130 passed, one failed**. The failed test compares `fig_distributions.pdf` with its published copy. |
| Publication gate | Three errors from that same PDF mismatch; the numerical figure CSV comparison passes. |
| Epsilon decode | Reproduced the corrected twelve-row summaries: ACK median **1,706 ns**, RESPONSE median **1,705 ns**. |
| New master capture | Independently extracted first repeated request after **200.822046 ms**, followed by **208.011398 ms** and **408.014548 ms** gaps. |
| Current manuscript source | Independently compiled with `latexmk`/pdfLaTeX and BibTeX; **17 pages**. This was an alternative build, not the repository's Tectonic build. |
| Lin source gate on current text and fresh PDF | **PASS**, with warnings; the optional voice checker is unavailable. |
| Venue preflight | **FAIL**. Its page counter also has a logic error described below. |
| Tracked `paper/rewrite/main.pdf` | Still the earlier PDF, byte-identical to the version at `5ce71ba`. |

The 179 passing tests are useful regression evidence. They do not exercise all admission/profile combinations, interruption behavior, or the actual P4 loss-recovery state machine.

## Priority 1: implementation correctness

### 1. A lost OPERATE can have its legitimate TCP retries discarded

**Location:** `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`, especially `gen_arm`/`gen_clear` at lines 1774–1781, the retained generation at 3201–3209, duplicate classification at 3224–3225, and `OUT_OP_DUP` at 3264 and 2340.

This is a newly identified issue in the frozen implementation, not a regression introduced by this merge.

The program deliberately retains an OPERATE generation as a spent marker after releasing the command. A later OPERATE carrying that generation is classified as `V_OP_DUP` and committed to `cmt_drop()`. The marker is cleared by the next SELECT, not by successful end-to-end delivery of the current OPERATE.

A concrete source-level failure sequence is:

1. SELECT completes normally.
2. The switch holds and then releases the first OPERATE toward the relay.
3. That released packet is lost between the switch and relay. The relay has never received these TCP bytes.
4. The master retransmits the OPERATE with the same TCP sequence and application-control byte.
5. The stored spent generation makes the switch drop this copy, and subsequent equivalent copies, before they can repair the loss.

The relay cannot acknowledge bytes it never received. Forwarding from the switch is not proof of delivery to the relay. TCP retransmissions must be able to repair missing sequence ranges; suppressing them solely because the switch previously forwarded the packet defeats that recovery path. TCP itself distinguishes newly delivered bytes from duplicate sequence ranges. [TCP specification, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html).

The archived READ response-loss test does not exercise this case. It drops an outstation RESPONSE on the master side; this case loses a master OPERATE on the relay side. The argument comparing a roughly 24 ms hold with a roughly 3 s relay timer is irrelevant to the spent marker, because the marker persists after release.

**Required correction:** preserve the evaluated source as historical evidence, but treat post-release OPERATE suppression as a correctness defect in the future implementation. Specify separate behavior for a duplicate while an original is retained and a retransmission after the original has been forwarded. A correction must allow transport recovery without replaying the command as new application bytes. Do not claim general loss recovery, exactly-once execution or unconditional delivery preservation from the current campaign.

**Confidence:** high from the explicit state transitions. This failure was not reproduced on hardware during this review.

### 2. Activation does not enforce admission for the policy being installed

**Location:** `defense4/timing/active_control/timing_only_profile.py`, `activate()`, lines 317–388, particularly the admission check before `build_plan()`.

The non-mock path rejects only two verdict strings, `refused` and `rejected`. It accepts an empty dictionary, an unknown verdict and a provisional verdict. It also never checks whether an otherwise valid admission record describes the requested profile.

Offline reproductions using only `RecordingDevice`:

| Supplied admission | Result |
|---|---|
| `{}` | `activated`, nine writes |
| `{"verdict": "banana"}` | `activated`, nine writes |
| `{"verdict": "provisional"}` | `activated`, nine writes |
| Real evaluator result for `D_A = 5 ms`, policy cap `10 ms`, supplied to a profile with `D_A = 20 ms` and target `4 ms` | `activated` |

Thus the code can install a 24 ms combined schedule using admission for a different 9 ms schedule. This is an admission bypass through ordinary API input, not a speculative race.

**Required correction:** accept only an explicitly supported admitted state, validate the result schema, and bind the decision to the exact requested/quantized timing values, configuration identity and applicable bounds. Recompute admission from typed inputs or verify a complete bound record; a verdict string alone is insufficient. If provisional activation is intentionally supported, it needs a separate explicit policy rather than implicit acceptance by exclusion.

The module correctly states that it lacks a hardware adapter. That limits its current deployment status but does not make this check correct for the adapter interface it exposes.

### 3. The probe watchdog detects overruns after they finish; it cannot bound them

**Location:** `defense4/timing/active_probe/rto_probe_plan.py`, `run_steps()`, lines 329–419.

The ordinary sleeping path now actually waits, which fixes the earlier defect. The optional workload is still called synchronously. The watchdog is checked only after that call returns. A blocked workload therefore holds the rule indefinitely until something outside this function releases it.

Offline reproduction: requested hold 10 ms, watchdog 20 ms, workload blocked on a local event. After 60 ms, the worker was still blocked and the fake rule still installed. Releasing the event finally allowed cleanup and a watchdog error. The existing test advances a fake clock and then returns, so it tests late detection rather than interruption.

Other reproduced outcomes:

- A workload returning immediately produces `status: completed`, requested hold 40 seconds, elapsed hold 0 seconds.
- A workload exception escapes as plain `OSError` without the promised execution record.
- A cleanup-runner exception escapes without the record and can leave the fake rule installed; the later absence check is not attempted.
- A NaN hold passes plan validation and produces a completed zero-duration run.

**Required correction:** use a genuinely bounded, cancellable observation process or an explicitly supervised lifecycle. Define what completion requires. Preserve primary and cleanup errors together, validate finite durations and slice values, and ensure cleanup attempts and their verification survive runner failures. Do not rename an after-the-fact overrun check a watchdog.

### 4. The activation plan can be invalid for the frozen P4 while its validator passes

**Locations:** `timing_only_profile.py`, `validate()` at 148–219, `build_plan()` at 222–300, and `_assert_shaping_off()` at 303–314. Frozen P4 constants are near lines 350–382.

The P4 uses fixed ports and queue IDs. The profile validator accepts alternative queue IDs without any corresponding data-plane remapping. It even accepts empty queue plans.

Verified examples:

- Empty RRC and BOR queue plans: no validation errors.
- RRC queue IDs changed from 7/6/5/4 to 27/26/25/24: no validation errors.

Configuring those new queues would not change the queues to which the frozen P4 sends packets. The same distinction matters for fixed data-plane ports. Queue identifiers and priorities are different properties, but that does not make identifiers freely configurable for a fixed binary.

Failure handling is also incomplete. A simulated final shaping readback error after pktgen was enabled escaped as plain `OSError`, without the promised record, while pktgen remained enabled in the test double. Stopping later writes is not an atomic rollback or proof that the device has been left inactive.

**Required correction:** validate the required queue roles and their binding to the selected build, including port mappings. Either make activation transactional with a documented recovery state or explicitly report a partial configuration and retain its record. Bring existing activity to a known state before clearing transaction registers or changing queues. Keep the adapter limitation explicit; do not treat generic success flags as actual hardware verification.

## Priority 2: admission semantics and evidence

### 5. Bound applicability can still confuse the two timers

**Location:** `active_control/delay_admission.py`, `Applicability.matches()` at 90–99, `_authoritative()` at 147–148, and `evaluate()`.

The metadata now contains direction and timer identity, but `matches()` ignores both. Empty policy context is also accepted. Authority is decided using the caller-provided `Bound.name`, rather than the role of the field containing the bound.

Reproduced results, all `admitted_conditional`:

- A master-RTO input explicitly tagged `direction=outstation_to_master`, `timer=outstation_rto`.
- A completely empty `PolicyContext`.
- An operator-supplied timer placed in the master-RTO field but named `application_deadline_ms`.

These are precisely the identity mistakes the new module intends to prevent.

**Required correction:** validate required context fields, compare timer and direction by role, require bound names to agree with their typed fields, and validate observation-time/source applicability. Do not let labels substitute for those comparisons.

There is also an unresolved distinction between upper and lower bounds. The result describes every bound as a finite observed maximum, yet the response hold subtracts `clrt_original_ms`. For a conservative future hold, subtracting a maximum original CLRT is the wrong direction; a justified lower bound or zero gives the largest hold. Similarly, a timer allowance needs an appropriate minimum/headroom, not a maximum observed RTO.

Illustration with the same policy and a 10 ms outstation allowance: native interval 20 ms yields a 4 ms hold and admission; native interval 1 ms yields a 23 ms hold and refusal. Both transactions can belong to a dataset with a maximum native interval of 20 ms. The API must distinguish exact per-exchange analysis from policy admission over a population.

Finally, `master_feedback_path_ms` is documented as the complete native request-to-ACK interval, but the calculation adds `ack_latency_bound_ms` separately. If the documented full interval is supplied, that counts the outstation ACK latency twice. Correct the endpoints and tests; counting the number of keys containing “path” does not establish non-overlapping intervals.

### 6. The READ histograms bypass the corrected extractor

**Location:** `audit_current/tools/clrt_distribution_and_variance.py`, `load_campaign_reads()` at 100 onward, and `paper/rewrite/figures/clrt/`.

The campaign analysis now correctly subtracts integer timestamps. The histogram generator still reads the frozen floating-point `campaign_v1/derived/transactions.csv`. Only the NDSS figure family was regenerated by the merged correction.

For the obfuscated READ data, the existing and corrected 1 ms bin counts are:

| Bin | Published histogram | Corrected integer extraction |
|---|---:|---:|
| `[3, 4)` ms | 13,508 | 11,043 |
| `[4, 5)` ms | 12,868 | 15,333 |

That moves **2,465 of 26,400 observations**, or **9.34 percentage points**, across the 4 ms boundary. The small timestamp correction has a visible bin-count consequence because the target lies exactly on that boundary. The overall concentration near 4 ms and variance-reduction conclusion remain; the plotted bars must nevertheless agree with the authoritative extraction.

**Required correction:** feed all active figure families from the same versioned extraction. Keep the old CSV as archived evidence. Regenerate main, zoom, full-range, run statistics and manifests. Use integer-unit bin boundaries where possible so floating-point construction of a 5 µs edge does not introduce a second boundary ambiguity.

The current histogram `--check` can pass because it reproduces the old input. That does not establish consistency with the corrected campaign.

### 7. The new master capture is useful evidence, but the timer claim is too strong

**Locations:** `audit_current/master_rto_20260916/RESULT.md`, its script and PCAP; Design and Evaluation timeout paragraphs.

I reproduced these successive request-repetition gaps from the 23-frame capture:

`200.822, 208.011, 408.015, 855.997, 1663.992, 3263.998, 6720.006, 13312.000 ms`.

The first observation supports “the first repeated request appeared after approximately 201 ms on this connection.” The source does not collect `TCP_INFO`, the sender's current RTO, or the event/counter identifying the cause of the first repeat. TCP can send a retransmitted tail-loss probe before RTO recovery. The nearly equal first two intervals make it especially important not to call every event simple exponential RTO backoff. This is an alternative consistent with the capture, not a claim that TLP has been proved here. [RFC 8985, TLP and RTO timers](https://www.rfc-editor.org/rfc/rfc8985.html).

The paper's “each subsequent attempt roughly doubles” is numerically false for the first pair. Nor does a later diagnostic prove that the old campaign's socket had exactly this timer value. Describe a measured repetition threshold on the diagnostic connection; retain the broader RTO inference as qualified unless contemporaneous socket/event evidence exists.

The archived script also records firewall return codes but does not branch on failed installation or verification. It does not collect the missing timer state. Preserve it as the script that ran, and do not describe its controls as enforced merely because variables named `install_rc` and `verify_installed_rc` exist.

This does not undo the useful distinction established in the meeting: the master's timer governs its request; the outstation's governs its response. [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html).

### 8. The claim that live-window duplicates are unreachable is not established

**Location:** `audit_current/duplicate_test_20260915/LIVE_WINDOW_20260916.md`.

The note treats `D_A + CLRT_new` as the transaction lifetime, although the corrected implementation discussion expressly distinguishes the lifetime from the nominal schedule. It also treats 4 ms as a universal target when deriving a 44 ms maximum window, although the active profile permits other targets. It uses a measured roughly 2.97 s repeat interval as if no response copy can occur sooner.

The new master capture itself contains an outstation response copy about **0.793 s** after the original response, near a repeated request. The cause requires analysis, but this is already enough to show that 2.97 s is not a universal lower bound on every response copy in the available evidence. Loss recovery and network duplication are not governed by a single measured relay timeout.

Most decisively, the OPERATE spent-marker issue above is not restricted to the live holding window at all.

**Required correction:** retain the observed separation of timescales for the specific READ test. Do not promote it to a proof that all relevant duplicate paths are unreachable. State which path was exercised, which remains a source-level risk, and which requires a separate controlled test if deployment assurance is desired.

### 9. Epsilon arithmetic is fixed; complete attribution and the claimed bound still need evidence

**Locations:** `epsilon_candidate/BUILD_ATTRIBUTION_20260916.md`, `ATTRIBUTION_AND_DECODE_20260916.md`, the decode script and Evaluation limitations.

The armed-marker correction is sound and the new medians reproduce. The record also describes recovery of the v2 build tree and matching normalized binary hashes, which is a useful reported investigation.

However, the merged directory `compile_20260916/` contains only the loader configuration. The `table_summary.log` files described as preserved beside the report, the referenced loader log, and a normalization script are not present in the committed tree. The ignore rules exclude compile logs. Consequently, this GitHub review can verify the reported hash table as text, but cannot independently verify the newly claimed source/build/load chain from those missing files.

**Required correction:** preserve a small, sanitized provenance package: the relevant allocator output, exact source and binary hashes, loader event, commands/flags, normalization procedure and a manifest. Raw binary hashes remain useful identifiers of exact build artifacts; a normalized hash is an additional comparison method, not a reason to discard exact build identity. Scope reproducibility claims to the builds actually compared.

The recorded endpoint is still the ingress timestamp of a recirculated blocker that terminates. It is not directly a queue-empty or held-packet-departure timestamp. Calling it a **lower bound on epsilon** requires an event-order argument for the chosen epsilon endpoint; it does not follow merely because the register is in ingress. In particular, the blocker's last traffic-manager service precedes its return to ingress. Preserve the neutral description “internal blocker-termination interval” until that ordering/calibration is established.

The paper should also avoid declaring detection immaterial from the raw ingress timestamp alone. It does not directly timestamp the later decision or gate-removal event. Twelve transactions remain a diagnostic, not an all-load bound.

## Paper review against Dr. Lin's guidance

### 10. Several explicit contradictions remain in the edited prose

The broad section order is closer to the meeting blueprint: timing model, parameter constraints, queue realization and evaluation questions. The protected introduction is retained. The paper still repeatedly explains its scope instead of stating it once and then making precise local claims.

The following are concrete corrections, not a request for another broad rewrite:

| Location | Remaining problem | Required correction |
|---|---|---|
| Abstract, lines 10–11 | “Neither release depends on how long the device took.” Absolute releases still inherit the native ACK anchor. | Describe control of the on-time ACK-to-response interval. |
| Background, lines 35–38 | CLRT is presented as device processing “rather than the network path.” | State the feature's relationship to processing and the differential path/queue assumptions. |
| Threat model, around line 69 | Retraining is said to assume more access. The same passive plaintext observer can collect labeled obfuscated traffic. | Treat fixed and adaptive models as evaluation conditions without inventing extra access requirements. |
| Evaluation, lines 282–285 versus 311–312 | One paragraph says CLRT-only adaptive classification remains at chance; the closing sentence says the targeted feature is not suppressed against retraining. | Remove the contradictory sentence and distinguish CLRT-only from combined-feature results. |
| Design, around line 94 versus Implementation walkthrough | Design says a late response is forwarded immediately; Implementation correctly says it enters the hold queue and waits for service. | Use the actual release-path description consistently. |
| Design, equations and surrounding text | Actual `e_A/e_R` and realized `D_A` are used as exact configured deadlines before drain/service is discussed. | Mark the ideal scheduling model and distinguish realized departure. |
| Design, around lines 107–115 | `m_R - t_R` is called an observed portion although `t_R` was not captured. | Call it a modeled partial journey, not a measured one. Full `D_R` remains unmeasured. |
| Design and Implementation admission claims | They say the horizon-derived 24.8 ms policy is enforced while the sweep executes larger values and the hardware note reports a distinct 40 ms clamp. | Name the actual writer, guard and any experimental override. Do not present different control paths as one enforced policy. |
| Evaluation tail paragraph | “Nothing can place one early” and “forwarded on arrival” ignore differential release effects and the queue path. | Explain measured tails without claiming an impossible sign or zero service time. |
| Design boundary | Moving packets is said to change no ordering feature. | Limit byte preservation to bytes; establish any packet-order claim separately. |
| Related Work, first paragraph | “Their cross-layer response-time method” grammatically attributes Formby's method to Kohno/GTID. | Attribute each method to its actual source. |
| Conclusion | Baseline CLRT classification is still 0.651 rather than the corrected approximately 0.652; epsilon is again stated as if its physical bound were established. | Synchronize with the corrected analysis and diagnostic endpoints. |
| Evaluation perturbation comparison | Candidate mean uses the old float result 4.000285 while the frozen mean uses integer extraction 3.999470; “indistinguishable spread” remains too strong. | Use one extractor for both: means approximately 4.000282235 and 3.999470130 ms. Report the limited comparison without claiming equivalence. |

The explicit `PARTIAL` configuration-provenance status is still absent from manuscript prose. Missing per-point sweep readbacks are mentioned, but the full configuration qualification should be stated concisely at the testbed definition.

Respectful treatment of prior work still needs attention. “Defenses in this setting have so far worked at the content and connectivity layer” is broader than the cited examples establish. The passage contrasting this setting with the “soundness” of previous methods is unnecessary. Describe what each method targets and the relevant difference, without a general verdict on its quality.

Dr. Lin asked for a framework explanation that readers can follow without knowing P4. Keep the four queue roles explicit, but do not imply independent per-transaction state. The current busy-path paragraph also deserves caution: shared sequence/ACK trackers are written before the eventual busy forwarding outcome. Busy forwarding alone does not prove that every piece of existing transaction state is unaffected. Retain the evaluated serialized assumption rather than add an untested concurrency guarantee.

The verbatim checker covers only the three supplied introduction paragraphs. It does not establish authorship or protection for any other paragraph. Preserve any additional passages designated by Dr. Lin; include their exact reference text in the protection mechanism if they are intended to be immutable. Applying his voice elsewhere is a separate editorial requirement.

### 11. The source, published PDF and publication gate are not synchronized

The tracked PDF hash remains:

`944995ad5a289f156c1e72bce114ebc29e312ee23a62eb7e2c09f6a398a1b8a9`

That is the earlier PDF from the previous review. `build.sh` writes to `pipeline/build/main.pdf`; it does not update the tracked `paper/rewrite/main.pdf` or its checksum. A successful local build therefore does not mean the GitHub PDF shows the merged corrections.

I independently compiled the current source and inspected the 17-page result. Its scientific text, including the conclusion, continues onto page 15. It remains over the current 13-page NDSS limit even before resolving treatment of Open Science material. [NDSS 2027 paper-format rules](https://www.ndss-symposium.org/ndss2027/submissions/call-for-papers/).

`ndss_preflight.py` now counts `ethics_page - 1`. In this PDF Ethics begins on page 15 after scientific text, so the gate reports 14 body pages and loses the scientific portion of page 15. It also says Open Science is counted, although stopping at Ethics excludes the Open Science text that follows. The present build still fails, but after a small cut this logic could incorrectly pass a paper that remains too long.

**Required correction:** make page accounting match actual content and venue rules. Shorten repeated threat/limitation explanations, long captions and redundant distribution discussion. Preserve Dr. Lin's text. Do not weaken a gate merely to pass the document. Publish the current compiled PDF with a source/build manifest after the checks succeed.

The hard Lin gate passes with warnings and no available voice fingerprint module. That is not proof of conformity to the meeting's writing philosophy.

### 12. Reproducibility still has a real, small rendering failure

Fresh pinned reproduction completed extraction, statistics, classifiers and figure generation, then failed one of 131 campaign tests:

`test_regenerated_figure_matches_committed[fig_distributions]`

Published PDF hash:

`8f7f38c91e793ccd2e7587c4549896017ecca37d5eb72ada14b8b40df986e75c`

Rebuilt PDF hash:

`f4eccae26f41760a23539d9f294da2d2d1600b3191f652deb8200cae92601cac`

The decoded page stream differs at one ECDF vertex: y-coordinate `145.40523` versus `145.376162`, a difference of about 0.029 PDF points. This is tiny visually, but it is content rather than only metadata. It is also different from the previous review's 1e-10-coordinate overlap-figure mismatch. Do not reuse the old explanation unchanged.

The statistical and summary-CSV checks pass. Treat the remaining mismatch as a rendering/reproducibility issue and inspect the path simplification/export contract. Preserve strict checks for numerical inputs and published artifact identity; if a content tolerance is introduced, define and justify it narrowly against the full plotted data.

### 13. The repository's current-status documents disagree

`CORRECTION_REPORT_20260916.md` still says the master's timer was never measured and describes the session as compile-only, while the later master capture and hardware notes document additional activity. It reports 178 tests rather than the current 179. The duplicate note declares the live-window question resolved; the correction report and manuscript leave it open. The latter is the more defensible disposition given the limitations above.

`CLAUDE.md` still describes the response-loss diagnostic as “loss recovery working” and as demonstrating the opposite of exactly-once. That conflicts with the corrected description: the receiver filter dropped every response, so application recovery was not demonstrated. Duplicate wire copies are not by themselves an exactly-once application result.

Consolidate one current status with dated historical notes. Missing compiler logs and a stale public PDF are more consequential than branch cleanup. Do not prune additional evidence during this correction.

## Recommended next pass

1. Treat the frozen OPERATE loss case as a separate correctness issue. Keep the historical binary/source intact; specify a correction candidate and a focused loss-recovery test before making deployment claims.
2. Repair admission binding, role validation, build-specific queue validation and partial-activation reporting. Add the reproduced counterexamples as focused tests.
3. Implement a genuinely supervised probe duration/cleanup lifecycle and correct its selection contract. The inbound “drop RESPONSE” rule currently also matches pure ACKs; name or implement its actual scope accurately. Reject subnet strings if the promised scope is one host tuple.
4. Feed every active plot from the corrected extraction and regenerate the READ histograms and all dependent statistics/manifests.
5. Archive the compact missing provenance records. Distinguish observed retransmissions from directly observed TCP timer state, and an internal epsilon proxy from a proven physical bound.
6. Apply the specific manuscript consistency fixes and editorial cuts. Preserve Dr. Lin's protected text and use his model → design constraints → queue implementation → evaluation structure.
7. Rebuild, inspect, synchronize the tracked PDF, and run the complete publication path. Report any remaining failure honestly rather than presenting the 179 unit tests as a substitute.

These are bounded corrections to the current work. They do not require adding size obfuscation, new fingerprinting objectives, new classifiers, or a general multi-flow redesign.

## Reproduction notes

The active tests were run with:

```bash
defense4/timing/evidence/campaign_v1/repro/.venv/bin/python -m pytest \
  defense4/timing/active_control/tests \
  defense4/timing/active_harness/tests \
  defense4/timing/active_probe/tests \
  defense4/timing/tests -q
```

The campaign was regenerated using its own `reproduce.sh` after `uv sync --frozen --python 3.13`. This resolved CPython 3.13.15 and the committed dependency versions. The script stopped at the one failed PDF test; the publication gate was then run separately to inspect its diagnostics. No failure was bypassed or converted to a pass.

The source was additionally compiled using installed pdfLaTeX/BibTeX with the standard IEEEtran bibliography style obtained from CTAN into the review scratch directory. This independently establishes that the current source compiles under that engine; it does not reproduce the unavailable Tectonic executable or its exact PDF bytes. The report's layout observations refer to this fresh alternative build.

The companion `DNP3_6fbf351_Offline_Review_Probes.py` reproduces the active-code counterexamples using only the repository's test doubles. Run it against a checkout of the reviewed commit. Its results are not measurements of hardware behavior.
