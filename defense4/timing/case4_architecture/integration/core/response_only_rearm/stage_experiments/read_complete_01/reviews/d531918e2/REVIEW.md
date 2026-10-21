# Independent implementation review: d531918e2

Reviewed commit: `d531918e2197df404401847f0c8244bb8d61a8b7`, akekulip/DNP3_obf.

**Verdict: the pushed implementation does not yet establish generalized READ padding and timing together on hardware.** There is useful working software and a reproducible fixed-shape P4 build, but hardware coverage, ACK-boundary correctness, and validation completeness remain open.

This review fetched the commit, inspected implementation and assertions, regenerated the selected P4, executed source-interpreter counterexamples, ran focused Python tests, and reanalysed retained hardware captures. It did not rerun a compiler, the compiled Tofino model, live endpoints, or physical hardware. Source-interpreter findings are labelled accordingly; compiler/model records are retained evidence, not new executions.

Path abbreviations below:

- `STAGE`: `defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`
- `CORE`: `defense4/timing/case4_architecture/integration/core/response_only_rearm`
- `HW`: `defense4/timing/case4_architecture/integration/evidence/rearm_01/hw`

## 1. High: selected b08 omits full/integrity and segmented READ support

`STAGE/m12_fullsize/make_m12.py:806–834` starts from m11_09. Its `--policy` branch applies `mapper_var`, `read_prefix_p1`, and `read_prepadded_e`, with native READ length 49 and output 141. It does not include the separate full-READ transform. Lines 865–867 explicitly exclude analog, Class-0, integrity and segmented READ classes.

The generated N parser's IP-length dispatch lacks 67, the length of the retained 27-byte integrity request. Feeding that real captured request into the repository's source interpreter ends parsing at the IP header: no TCP extraction, `m.parsed=0`. Parser acceptance here only means the P4 parser terminated without reject; it does not mean protection or timing admission succeeded.

Consequently, the selected P4 does not implement the software policy 141/247/401 across READ shapes. The completion record's suggestion that other shapes simply pass through at their target size does not establish delivery or timing through N/E/T. The 377→401 segmented case is also absent.

**Required:** implement the declared hardware READ profile through request recognition, sequence accounting, transformation, timing and recovery. Until then label b08 precisely as range READ 49→141 plus SBO 37→61. Keep the separate software coverage claim separate.

## 2. High: the SBO committed-image boundary is too permissive

`make_m12.py:192–218` uses the largest image's reverse-ACK window. In b08 that is 141 bytes, even when the committed image is the 61-byte SBO response.

Executing the actual generated `classify_rev` table in the repository's source interpreter gives:

| Distance before committed wire end | b08, SBO length 61 | m11_09, SBO length 61 |
|---|---|---|
| 61 | withhold | withhold |
| 62 | withhold | stale drop |
| 100 | withhold | stale drop |
| 141 | withhold | stale drop |
| 142 | stale drop | stale drop |

The retained compiled-model boundary evidence agrees: `SBO61_LIMITATION_prestart_withheld_d62` records outcome 10. `STAGE/seg61_02/model_policy.py:125–137` deliberately expects that limitation, so its passing count does not establish the approved per-image stale-ACK contract. The limitation is disclosed in the code; it is not a hidden finding. However, no supplied approval waives that contract.

**Required:** enforce the actual committed image boundary and preserve the stale-ACK regression. Verify both transition directions and eventual ACK/recovery disposition. This review establishes misclassification, not a demonstrated exploit or a complete end-to-end failure.

## 3. High: the new hardware readout can pass incomplete evidence

`STAGE/read_complete_01/analysis/hw_read_readout.py:130` pairs requests and responses with `zip`, silently truncating unmatched entries. Lines 183–196 discover only capture pairs that exist and accept them when the generated failure list is empty. Missing outstation-side requests can also be substituted with master-side requests at line 139.

Two counterexamples run against the unmodified checker:

- Two valid but empty capture files: exit 0, `ok=true`, zero transactions.
- A copy of the retained native capture with its final response packet removed: exit 0, `ok=true`, 64 exact READs instead of 65; total transactions fall from 193 to 192. The missing packet also produces apparently negative wire overhead.

Original evidence was not modified. These findings concern this new readout, not a claim that every existing hardware checker has the same defect.

Related issues: stream grouping omits TCP ports/connection incarnation, timestamp conversion truncates nanoseconds, and response latency uses the first frame rather than necessarily the complete response. `read_complete_01/reproduce.sh:50–56` catches readout failure with an echo and subsequently announces success.

**Required:** reuse existing exchange/capture identities and attempted counts; fail missing, extra and incomplete exchanges; retain timestamp precision and distinguish first-frame from complete-response timing; propagate readout failure to the reproduction command.

## 4. High for reproducibility: the pushed model gate recomputes as blocked

Running the existing `model_summary.py --v3 --enforce` on `m12p_b08` exits 1. It requires `model_contention_m12p_b08_02/reset_application.json`, which is absent from the commit. The Git tree was checked, so this is not merely a selective-export omission.

The stored summary says the gate passed, but its required reset evidence cannot be verified from this push. This does not prove the original execution failed.

**Required:** retain and commit the original missing reset evidence and dependency bindings, then recompute the existing gate. Do not manufacture an equivalent result or weaken the gate. See `evidence/recomputed_model_gate.txt` in this package.

## 5. Medium: fresh-checkout target-policy reproduction needs an untracked path

`STAGE/read_complete_01/policy/select_policy.py:32` reads inputs under `handoff/Claude_READ_Complete_Handoff/reference/target_selection/inputs`. That directory is not tracked; the handoff directory contains only the overnight instruction file. Policy-coverage tests consequently fail before running in a fresh export.

The inputs are already retained elsewhere under `evidence/m1_software_pinned_01/target_selection/inputs`. After pointing the missing path there in the audit copy, the coverage tests and selector succeeded. The selector reproduced 141/247/401, 10.933% added bytes versus 19.039% for the comparator, and an unchanged policy file SHA-256. This validates that calculation on the retained distribution, not fingerprinting resistance or global optimality.

**Required:** use the tracked inputs directly or provide an explicit, hash-verified setup step.

## 6. Medium: the C5 test does not demonstrate corrected forward mapping

`STAGE/seg61_02/model_policy.py:139–158` accepts `all(...)` over emitted frames. The retained C5 result has zero frames and no E outcome-counter change, yet passes. This supports “no incorrectly mapped output observed”; it does not demonstrate that the delayed ACK reached the mapper and was translated correctly.

**Required:** retain that narrow observation, exercise the mapping fix at component level, and establish the intended reachable end-to-end disposition and recovery. Do not call an unexercised mapping path validated.

## What independently checked out

- Regenerated `--policy` P4 is byte-identical to b08: SHA-256 `7b1281bc4aa73950b33088adc9d9ae5bbd827422ec702c71d1d3b791f352214f`.
- The old READ transformation is disabled in the selected path; it is not simply running alongside the replacement. SBO framing remains intentionally separate.
- 65 initial focused encoder/installer/checker tests passed. Another batch produced 44 passes and one failure caused by missing Git metadata in the audit export; that test passed with the real repository metadata supplied. Policy tests required the input-path repair described above. These 110 focused passes do not invalidate the counterexamples.
- Retained compiler manifests report successful builds on SDKs 9.13.1 and 9.13.2. Reports show N11/E12/T11 plus a new seven-stage pipe-1 egress padder: 34→41 occupied stages summed across controls. This is additional resource use, even though existing controls did not grow. It is not itself proof of added recirculation or measured latency. Compiler placement was not independently rebuilt here.
- Retained off, timing-only and size-only hardware captures each contain 65 READ, 64 SELECT and 64 OPERATE responses, with no decoded DNP3 CRC failures. READ remains 49 bytes in these captures. The combined arm was not collected after the size-only failure.
- Reanalysis confirms a 1,229 µs median READ absolute timing error against the 950 µs target in the timing-only capture. Attribution to host or build remains unresolved. Percentiles need a stated estimator; different p99 conventions yield different values on 65 samples.

## Bounded continuation

Correct the readout and reproducibility defects first. Resolve the committed-image contract and C5 evidence. Finish the declared READ shapes in the existing implementation, then validate timing and size together on the selected exact source. Run the already-authorized controlled hardware comparison only after restoration is independently verified. Preserve prior failed blocks and stop on unverified restoration. No new main campaign, endpoint redesign, or broad optimization study is needed to address these findings.

## Reproduce these findings

Use a checkout at the exact reviewed commit. Python 3.12 was used for this audit. Run:

```bash
python3 reproduce_findings.py --repo /absolute/path/to/DNP3_obf --out /absolute/path/to/new-audit-output
```

The script runs the repository source interpreter and Python capture checker, uses the retained captures, and writes only to the output directory. It asserts the reviewed P4 hash. It does not load hardware or run the compiled model. Its counterexamples are evidence tests: success means the documented defects were reproduced.

To reproduce the gate-evidence finding, run the existing `STAGE/ctl_timing_01/model_summary.py` against the absolute path of `STAGE/ctl_timing_01/evidence/m12p_b08`, with `--v3 --enforce`.
