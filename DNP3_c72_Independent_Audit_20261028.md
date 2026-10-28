# c72: independent implementation and evaluation audit

Reviewed revision: [`akekulip/DNP3_obf@032df7989`](https://github.com/akekulip/DNP3_obf/tree/032df7989). Date: 28 October 2026.

**Assessment:** the retained evaluation genuinely demonstrates the selected padding constructions and response timing on the physical SEL-751/Tofino path. It does **not** yet demonstrate broadly reduced device-fingerprinting ability. The strongest new concern is that a classifier using another visible timing interval remains highly accurate. There are also reproducible checker defects and unresolved recovery cases. These are different findings; neither “everything works” nor “the results are worthless” is justified.

No repository files, hardware settings or historical evidence were changed. No new switch/model run was launched. Offline experiments below were performed on an isolated snapshot.

## 1. Meeting direction and what can be established

I located the October 5 transcript excerpt and its derived meeting record, and reviewed the later instructions in this conversation. I did **not** locate authenticated transcripts of the two most recent meetings in the accessible current repository or the searched files. Consequently, the following is a provisional requirements mapping, not a claim to have verified the latest two meetings word for word. Those two records are the remaining input needed to close the meeting comparison.

The October 5 material supports an operation-aware, programmable-switch framework; selected timing/size cases; showing the traffic patterns and relevant classifiers; and showing that transformed exchanges remain acceptable to endpoints. The later user directions require the physical SEL-751, two READ workloads/targets, preserved measurements/control information, and controlled overhead. The current repository explicitly uses response-ready ACK timing followed by a response gap D, **without an OPERATE-J hold**. Older J, fixed-61-byte and software-outstation requirements must not be silently reintroduced.

| Objective | Evidence needed | Present position |
|---|---|---|
| Apply timing and size transformations together | Exact source/artifact identity; four arms on one image; actual relay exchanges | Strong evidence for the declared c72 profile; raw evaluation captures independently reproduced |
| Preserve legitimate communication | Complete application fragments; CRC/checksum/sequence/ACK checks; exact original measurements and command echoes; endpoint success | Capture/application checks reproduce; hardware equality to original READ values is not established by a single downstream capture |
| Reduce useful fingerprinting information | Explicit observer, prediction label and visible features; baseline and adaptive attackers; held-out sessions/devices | CLRT-based **operation classification** is evaluated; device identity is not; other timing channels remain informative |
| Limit overhead | Added latency/tails, bytes and packets, recovery costs, deadline misses, workload rate; resource/traversal accounting | Payload overhead and sequential exchange-rate results exist; total link overhead and load/scalability evidence are incomplete |
| Support the selected timing cases | A separate observable and test for each claimed case | Current D=5/10/15/20 ms response-ready case is exercised; this is not evidence for every earlier case, zero-gap ACK release or physical-operation-time protection |

I checked the original Formby et al. paper as well. Its histogram/naïve Bayes, FF-ANN and mean/variance GMM methods are relevant precedents, but its device/software-type labels differ from this repository’s READ/SELECT/OPERATE labels. Its physical-fingerprinting method uses event/operation evidence; a successful OPERATE response alone does not evaluate that attack. [Formby et al., NDSS 2016](https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf).

## 2. What I independently reproduced

The evidence chain is substantially stronger than the earlier agent summaries alone suggested.

- Downloaded the pinned source, analysis/checker code, retained tables/classifier results, all **512 evaluation PCAPs**, and the associated master/result/offload records and block artifact manifests.
- Re-ran `relay_check.analyze` on **all 256 evaluation connections**: **49,408 exchanges**, all passing its checks. Recomputed request/response spans, operation/workload, CLRT, request-to-ACK time, complete response time, lengths, segment counts, application verdicts, CROB statuses and retransmission counts agree with the published CSV. The five downloaded trial inputs per connection match their block artifact-manifest hashes.
- Also re-parsed all four arms of the qualification reference block: another **772 exchanges**, agreeing with the retained checker results.
- Re-ran the analysis suite: **35 passed**, with 14 neural-network convergence warnings. Passing these tests does not cover the counterexamples below.
- Rebuilt all eight main and 39 supplementary figures from the retained rows/classifier results. T1–T4, figure notes, sufficiency and verdict JSON files reproduced **byte-identically**. Visual inspection covered the main timing, size, classifier and latency figures. The local font fallback prevents a claim of byte-identical rendered images across environments.
- Recomputed all **288 naïve Bayes configurations** from the rows. **276 confusion matrices match exactly**. Twelve have discrepancies discussed in §4.5. All K=64 retrained values used in the headline comparison match.
- The canonical P4 source hashes to `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`, matching the design/build metadata. The CSV hashes to `29b028228c69245e73c3472ec662ba53f77f144632920a8b8f9e9aeb69ba3c75`, matching its manifest and classifier record.
- Inspected the P4 READ prefix actions, admission/checksum treatment and current profile, plus model-driver coverage and retained compiler manifests. Those manifests report SDK 9.13.2, N10/E10/T8/pipe-1 egress4. **I did not freshly compile P4, rerun the 17-driver SDK gate, or independently verify every compiler binary.**

The current evaluation’s observed mapping is:

| Response | Native encoded DNP3/TCP payload | Padded payload | Added payload |
|---|---:|---:|---:|
| Mixed READ | 91 B | 141 B | 50 B |
| Integrity READ | 134 B | 158 B | 24 B |
| SELECT | 49 B | 60 B | 11 B |
| OPERATE | 49 B | 60 B | 11 B |

All evaluation responses occupied one captured TCP segment. This observation is separate from their internal DNP3 link-frame splitting. The current profile explicitly supports whole TCP input, not arbitrary segmentation or general READ sizes.

## 3. The main research gap: the observer can change features

The preregistered experiment deliberately trains classifiers on CLRT, aggregate response size and their concatenation. Request-to-ACK and request-to-complete-response time are descriptive only in `DESIGN.json`. That is a legitimate scoped experiment, but it cannot establish protection against an observer who uses those other available intervals.

I performed an **exploratory audit stress test**, without new traffic or a new classifier family. I reused the repository’s multinomial naïve Bayes, K=64 same-operation windows, training-only histogram range, first-eight-block training/last-eight-block testing and class labels. The sole feature change was to substitute request-to-ACK or request-to-complete-response time for CLRT.

| D | Combined: CLRT BA | Combined: request→ACK BA | Combined: request→complete response BA | Off: request→complete response BA |
|---:|---:|---:|---:|---:|
| 5 ms | 0.375 | 0.750 | 0.917 | 0.875 |
| 10 ms | 0.458 | 0.917 | 1.000 | 0.833 |
| 15 ms | 0.458 | 0.917 | 1.000 | 0.917 |
| 20 ms | 0.250 | 0.833 | 0.958 | 1.000 |

BA means balanced accuracy; three-class chance is 1/3. Each K=64 test cell has only **24 windows from eight test blocks**. These are post-hoc, same-campaign operation-class results, not a new preregistered device-fingerprinting experiment or proof of a causal mechanism. Nevertheless, they are a concrete counterexample to inferring general observer confusion from the low CLRT score.

A plausible mechanism, requiring its own causal check, is that waiting for response readiness moves processing-related information into the request-to-ACK interval. Adding a nearly constant D then leaves that information available in total response time. The data establish the classifier result; they do not independently locate the delay inside the switch.

The already-retained joint CLRT+size result is also important: combined-arm K=64 BA is **0.667, 0.833, 0.833 and 0.875** for D=5,10,15,20, compared with 1.0 natively. This should be on the main results slide, not only in a caption/supplement.

### Size changes are not yet demonstrated size concealment

For this observed profile, the mapping `49→60, 91→141, 134→158` is one-to-one. It relabels the three native size categories without merging them. An adaptive observer can still distinguish mixed READ, integrity READ and SBO from aggregate response size. SELECT and OPERATE were already equal-sized natively. The size-only three-operation classifier remains at 2/3 BA both before and after padding.

Thus, “every response reached its configured target” is a successful **implementation** result. It is not evidence that the size feature now carries less class information. The pre-deployment size classifier’s chance score is already correctly identified in the report as histogram overflow caused by a native-only feature range.

The two READ targets can remain the engineering scope. To claim security benefit from them, show which devices/workloads become more confusable under that policy and measure the trade-off. Do not infer a distribution-derived privacy benefit merely from two target constants.

### Operation classification is not device identification

The labels in `formby_eval.py` are READ, SELECT and OPERATE. All data come from one SEL-751. In plaintext traffic, an observer may already read the operation code, so obscuring that label is not the same objective as hiding the device that produced a known operation. Keep this experiment as a mechanism/leakage proxy. A device-fingerprinting claim needs multiple actual device identities/types—or an explicitly narrower, controlled configuration-identification experiment—and matched operations across labels. No software outstation should be substituted for the required physical-device evidence.

## 4. Reproducible code and evidence findings

### 4.1 TCP reassembly miscounts overlapping retransmissions and mishandles coalescing

**Priority: high before extending recovery/packetization claims.**

In [`relay_check.stream_contains`](https://github.com/akekulip/DNP3_obf/blob/032df7989/scripts/checks/relay_check.py#L142), byte coverage is reconstructed, but timestamps and `actual_payload_lengths` are then derived from every distinct `(seq, payload)` packet. They are not derived from the earliest coverage of each unique byte.

Reproduced witnesses:

| Input | Correct result | Current result |
|---|---|---|
| `abcdef` at t=100, then overlapping retransmission `abc` at the same sequence at t=200 | 6 delivered bytes; complete at 100 | 9 summed bytes; complete at 200 |
| One packet contains consecutive fragments `abc` + `def`; search first fragment | 3 fragment bytes | 6 packet bytes attributed to it |
| Then search `def` within that same packet | Second fragment found at its byte offset | Not found |

Retransmission counting also uses identical `(seq,payload)` duplication, so differently segmented retransmissions are not counted correctly. This is a checker defect, **not evidence that c72 corrupts traffic**. All 49,408 current evaluation spans were one captured response segment and had no byte-span overcount; the defect did not change their published rows.

Correction: separate unique stream bytes, packet bytes and retransmitted bytes; track first-arrival timestamps per byte range; allow fragment starts within a segment; stop at the first complete coverage time. Add overlap, resegmentation, coalesced-fragment, wrap and conflicting-byte tests. Re-run the retained captures unchanged.

### 4.2 Hardware READ checks do not prove original values were preserved

**Priority: high for the preservation claim.**

[`dnp3_codec.validate_response`](https://github.com/akekulip/DNP3_obf/blob/032df7989/scripts/hardware/active_harness/dnp3_codec.py#L364) checks group/variation/index coverage and declared zero padding. It does not compare live original READ values/flags against the relay-side pre-transform response, and it sorts native indices when checking coverage. The custom master and capture checker share this codec.

A validator-level witness changed a decoded analog point from **11 to 305,419,896**, while retaining the permitted object/index and well-formed raw representation. The validator returned no failures before or after the change. This is not an ASIC corruption finding: both values can be valid readings. It establishes that downstream structural acceptance cannot prove equality to the upstream value.

The P4 prefix actions preserve live app/IIN fields in the prefix, rewrite the first block, derive its CRC and leave the unparsed native tail in place. Model tests compare known native bytes to encoded output. Those are useful, separate evidence tiers. For hardware preservation, capture the **same transaction** before and after transformation and compare every original group, variation, qualifier, index, value, flags and order after removing only declared padding. Two polls taken at different times are not a value-preservation oracle for changing measurements.

Also validate the exact current padded responses with an independent master/parser implementation. Acceptance by the custom test master alone is narrower than compatibility with unmodified deployed masters. This does not require a software outstation.

### 4.3 Neural-network evaluation shares sessions and does not record convergence per fit

**Priority: medium; do not use FF-ANN as the strongest independent generalization result.**

[`ann_evaluate`](https://github.com/akekulip/DNP3_obf/blob/032df7989/scripts/analysis/formby_eval.py#L167) randomly splits windows, then uses grouped folds only inside training. At D=5/combined, **every test block is also represented in training**: 16/16 at K=8, 11/11 at K=32 and 9/9 at K=64. This follows the declared historical random-split comparison, but is not a held-out-session test. K=64 has only 12 ANN test windows.

The histogram range H is fitted on all outer-training windows before inner cross-validation, so each validation fold influences that preprocessing. Fit it inside each training fold for the revised grouped evaluation. The retained `formby.stderr` contains **1,140 ConvergenceWarning occurrences**; individual final fits are not annotated with convergence state, so the log count cannot tell us which plotted model failed to converge.

Keep the historical random-split results labelled as such. Add the same chronological/grouped outer split for all classifiers, fold-local preprocessing, fitted-model/prediction retention and convergence reporting. Fit/predict success is not evidence of convergence. GMM is already near chance on native traffic, so its poor defended score demonstrates little security benefit.

### 4.4 Figure generation accepts incompatible input artifacts

**Priority: medium, latent integrity defect.**

[`eval_figures.main`](https://github.com/akekulip/DNP3_obf/blob/032df7989/scripts/analysis/eval_figures.py#L44) reads the CSV and classifier JSON but does not verify the JSON’s `rows_sha256` against the supplied CSV. Its exit code depends on sample sufficiency, not artifact consistency. A stale classifier file can therefore produce apparently valid figures beside current distribution tables. The current pair’s hashes do match; this is not a finding that these figures use mismatched data.

Add input-hash/schema/split/class checks and fail on a deliberately mismatched classifier artifact. Preserve an explicit distinction between “sufficient data,” “transformation correct,” and “security hypothesis supported.”

### 4.5 Classifier reruns are not fully reproducible across the audit environment

The same source and CSV reproduced 276/288 NB confusion matrices. Twelve differed, mostly pre-deployment cells, with BA changes up to **0.0417**; one retrained D=5/timing-only/K=8 cell changed from **0.322917 to 0.317708**. Near-tied class log scores (<1e-10 margin) occur in all examined discrepant cells. Changing this audit process from one to eight BLAS threads did not restore the retained matrices. Numerical/library differences are a lead, not a fully isolated cause.

All K=64 retrained headline results match. This does not overturn the main CLRT finding, but it prevents claiming universal exact reproduction of the classifier fits. Retain Python/NumPy/SciPy/scikit-learn/BLAS versions, the fitted parameters, split membership and per-window predictions. Specify tie handling and test it without silently rewriting historical predictions. The audit environment was Python 3.12.14, NumPy 2.3.5, SciPy 1.17.0 and scikit-learn 1.8.0.

### 4.6 Known failures remain real qualification gaps

The 64-block evaluation has successful exchanges; it does not erase failures in a different recovery workload. The retained qualification reports **9/10 blocks**, including a lost SELECT response followed by CROB TIMEOUT during `loss_full`. First-request retransmissions also occur in **16/256 evaluation connections** (off 3, size 3, timing 6, combined 4). Their location/cause is unresolved; this audit does not attribute them to Vision, the relay or Tofino.

`model_abandon.py` defaults to `ABANDON_T=0`. The model summary says 17/17 passed and has empty unresolved lists, while HANDOVER separately says timing-enabled abandoned SELECT remains uncharacterized. Make that coverage distinction machine-readable; a timing-off pass does not establish timing-enabled recovery.

[`replay.py`](https://github.com/akekulip/DNP3_obf/blob/032df7989/scripts/checks/replay.py#L101) unconditionally reads top-level `result.json` even for three-connection scenario trials that retain `scenario.json`. The source confirms the documented replay defect. Repair replay as a separately versioned analysis tool and preserve the original checker/hardware bindings. Changing the historical verdicts is unnecessary.

## 5. What the figures should show

The current figures are numerically faithful to their supplied inputs. The important changes are analytical, not cosmetic.

1. **Main attacker figure:** show CLRT, request→ACK, request→first response, request→complete response, size and joint features together. Clearly distinguish preregistered results from this exploratory check. Keep native, timing-only, size-only and combined arms visible somewhere easy to compare.
2. **Main timing figure:** retain the CLRT distribution but add tails/CCDF and per-class request-response distributions. Figure 1 truncates the combined axis to D±3 ms; its caption discloses four omitted exchanges at D=5. Keep that disclosure visible and use comparable axes where a direct visual comparison is intended.
3. **Size figure:** keep the exact mapping bars as construction evidence. Add adaptive-attack or separability evidence; the bar chart alone does not show concealment. Separate aggregate DNP3 response bytes, individual link frames, TCP packets and link bytes.
4. **Trade-off figure:** strongest held-out attacker score against added latency and byte overhead, across D. A larger D is not automatically better: joint leakage remains high even when CLRT-only BA is low. D=5 is a defensible reference/worst-supported setting, not a demonstrated optimum.
5. **Correctness/recovery figure or table:** show nominal evaluation, loss, persistence/reconnect, timeout and abandoned-SELECT results separately, with denominators and failures.

T4’s **18.2086%** is the increase in request-plus-response **payload bytes** for this workload. Response payload alone rises **28.2091%**. Neither includes all Ethernet/IP/TCP headers, ACKs, retransmissions, preamble/IFG or internal recirculation. Do not label 18.2% total wire or switch-bandwidth overhead. The reported exchanges/second is the throughput of this sequential master schedule, not Tofino capacity.

The eight-block CIs and 12-window ANN results also deserve visible sample counts. The exploratory 45/64 SELECT/OPERATE binomial result in the existing report treats windows as independent; use block-clustered uncertainty before relying on its p-value.

## 6. Evaluations needed next, in priority order

| Priority | Evaluation | Minimum useful design | What success would establish |
|---|---|---|---|
| 1 — offline | Audit the full visible timing feature set | Existing captures; same grouped chronological splits; CLRT, ACK latency, first/complete response latency, response size/packet count and joint features; retain predictions | Whether leakage was reduced or moved to another measured channel |
| 1 — offline | Repair reassembly, artifact binding and replay | Red/green counterexamples above; all retained captures still reproduce; old failures remain failures | Trustworthy analysis and recovery readout |
| 1 — hardware correctness | Same-transaction preservation | Relay-side and master-side observation matched by connection/request/sequence; compare complete original objects and CROB echoes | Actual preservation of relay-produced content through transformation |
| 1 — recovery | Close recorded failure cases | Reproduce first-request loss and SELECT-expiry failure; test timing-on abandoned SELECT; missing/late response; reconnect/reset/FIN; both READ workloads | Correct bounded recovery, not merely nominal delivery |
| 2 — security claim | Actual device/configuration fingerprinting | Multiple real devices, or explicitly labelled controlled SEL configurations; same operations per label; held-out sessions/day; adaptive and pre-deployment models; no endpoint/address/filename shortcuts | Reduced device/configuration inference within the declared observer model |
| 2 — size policy | Demonstrate confusion at acceptable cost | Compare current two targets with an attainable overlapping/distribution-based policy on retained/native sizes; enforce protocol/fragment limits; retrain observer | Security benefit of padding, rather than just larger packets |
| 2 — robustness | Remove traffic-generator shortcuts | Additional held-out session with justified READ mix and request spacing changes; preserve SELECT-before-OPERATE semantics | Generalization beyond one deterministic workload and one overnight session |
| 2 — overhead | End-to-end cost and headroom | All transmitted bytes/packets, latency p50/p95/p99/max, deadline misses, retransmission cost, internal traversal/resource counts; bounded load sweep if scalability is claimed | A defensible latency/bandwidth/resource trade-off |
| Conditional | Additional timing cases/physical fingerprints | Only if claimed: zero-gap/ACK-only/response-only cases; or genuine unsolicited/event/SER timing | Evidence for those separate capabilities; the present runs do not provide it |

For the next fresh experiment, declare a **minimum meaningful reduction** in the relevant attacker metric and acceptable overhead/deadline limits beforehand. Report the effect and confidence interval. An interval crossing chance does not prove indistinguishability; a statistically detectable drop can still leave an effective attacker. Use the experimental unit—connection/block/device/session—for uncertainty, not thousands of correlated packets as independent trials.

Do not launch another large campaign simply to obtain a cleaner-looking graph. Fix the checker counterexamples and assess the existing alternative timing channels first. Then run only the hardware experiments needed to resolve the identified gaps, using the physical SEL-751 and the current restoration controls.

## 7. Recommended statement for the next meeting

“On the physical SEL-751 and Tofino, the selected two READ workloads and SELECT/OPERATE exchanges reach their configured padded sizes, and the response-ready timing mechanism changes the observed CLRT distribution. We independently reproduced the complete 49,408-exchange evaluation. CLRT-based operation classification decreases, but joint and alternative timing features retain substantial information. Device-fingerprinting reduction, same-transaction hardware measurement preservation, and the remaining recovery cases are the next validation targets.”

This statement preserves the demonstrated engineering progress without turning a feature-specific result into a general security claim.

## 8. Reproduction and audit boundaries

Principal pinned files: `scripts/analysis/{eval_rows,formby_eval,eval_tables,eval_figures,figs_main,figs_supp}.py`, `scripts/checks/relay_check.py`, `scripts/hardware/active_harness/dnp3_codec.py`, `p4/response_only.p4`, `results/builds/c72/{supported_profile,model_summary_v3}.json`, and `results/analysis/evaluation/`.

The exploratory timing test is reproducible with the existing classifier functions: load `rows.csv`; select D and arm; replace each copied row’s `clrt_ms` with `ack_ms` or `rt_ms`; call `make_windows(..., 'clrt', 64)`; train on `split=='train'` and test on `split=='test'`; compute H using training rows only; call `nb_predict` and `metrics`. No labels, windows, requests or hardware timings were changed. Keep this analysis labelled exploratory.

The raw-capture replay used the repository checker plus independent field-by-field CSV comparisons and input-hash checks. It is not a second independent DNP3 decoder; the shared-codec limitation is explicitly included in §4.2. The aggregate data table checks use retained GMM/ANN results; those full fits were not all retrained in this audit. The P4 review was scoped to the selected construction, admission and timing/profile interfaces, not a proof of every state transition. A current source audit must not be represented as new SDK or silicon evidence.

Outstanding source material: the actual two most recent meeting transcripts/notes. Their absence limits attribution to Dr. Lin, not the reproducible code and data findings above.
