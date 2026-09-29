# September 29 verification and corrections

Philip approved offline verification and correction of the supplied audit. The paper,
its figures, historical source snapshots, captures, and measured binary stay frozen
pending Dr. Lin's acceptance. No hardware access, traffic, model training, or push is
part of this work. A repaired P4 candidate is separate from every measured build.

## Work sequence and acceptance

1. Record hashes before edits; preserve paper and historical evidence byte-for-byte.
2. Verify findings against the specific build and measurement, not an older warning.
3. Add failing behavioral checks before any candidate implementation repair.
4. Correct supported engineering claims and provenance; defer paper-only issues.
5. Verify source/data/model recovery, compile and test candidates offline, and report
   precisely which claims remain unproven.

`frozen_inputs.json` records current hashes, not contemporaneous collection proof.
The final finding ledger and validation evidence are kept in this directory. The
analysis and P4 candidate subdirectories have separate ownership during this audit.

## Evidence recovery

`recovery_manifest.json` identifies 14,291 directly versioned files and 904
compressed artifacts. The latter preserve their original paths and byte hashes;
original files remain in place and are explicitly ignored only after their
compressed replacements have been verified. No model is deserialized by this tool.
Intermediate training copies/checkpoint previews are listed separately, not deleted.
Canonical captures, final predictions, selected model artifacts, analysis source,
and tests are retained. The archive is local Git content, not an external upload.

```sh
python3 defense4/timing/audit_current/verification_20260929/recovery.py verify
python3 defense4/timing/audit_current/verification_20260929/recovery.py restore --destination /path/to/recovered-checkout
python3 defense4/timing/audit_current/verification_20260929/recovery.py frozen
```

`restore` reconstructs compressed artifacts in the named destination, validates
hashes before writing, and refuses conflicting files. Direct files come from the
Git checkout. `frozen` checks this workspace's full start-of-audit snapshot, including
local-only references and build outputs; it is a preservation check, not a promise
that every local cache or copyrighted reference PDF is distributed by Git.

The snapshot includes campaign readbacks and derived transaction tables missing
from older manifests. These supplemental hashes were recorded on September 29;
original collection manifests are preserved and no historical verification is implied.

## Finding ledger

The identifiers below preserve the supplied audit's numbering. “Deferred” means
paper text is intentionally unchanged, not that the finding was dismissed.

| ID | Finding and evidence | Disposition |
|---|---|---|
| 1 / A2 | Evaluation already contains later engineering results, while the publication authority remains campaign_v2. | Engineering instructions/maps now explicitly identify the conflict. Paper reconciliation deferred until acceptance. |
| 2 | The old blanket experimentation ban conflicted with Philip's subsequent, specific run authorizations. | CLAUDE.md now distinguishes completed authorized runs from the present offline-only permission. No future hardware permission inferred. |
| 3 | The abstract's fixed 8 ms campaign and later seven-stage/randomized experiments are different builds and datasets. | Keep their identities separate; manuscript attribution changes deferred. No new candidate result is attributed to a measured build. |
| 4 | Older review items include a released OPERATE retry limitation and an early hold-decision dependency. | Rechecked against the hash-matched randomized source in `p4_candidate/`; final candidate disposition is recorded below. Older warnings are not automatically current findings. |
| 5 | Raw grid evidence, final results, and Formby scripts/models were unversioned. | Recovery commit `d7a904c3d` retains direct files and compressed originals. All 15,195 input/archive blobs matched Git's index; the largest model restored identically from the commit. Intermediate copies remain local and explicitly listed. |
| A1 | Abstract says timing identifies the device and operation; this evaluation uses operation labels on one relay. | Confirmed wording and scope mismatch. Paper correction deferred; no device-identification success claim is added to engineering documentation. |
| A3 | Campaign params readbacks do not establish the J codebook or each transaction's J. | Checked 159 readback files. Preserve configured/source-derived J versus observed intervals; paper wording deferred. |
| A4 | Fixed ACK+CLRT classifier's 0.3333 balanced accuracy accompanies READ predictions for 95.45% of each class. | Engineering claim ledger now gives the collapsed prediction behavior and distinguishes model failure from absence of information. Abstract/conclusion correction deferred. |
| A5 | Publication gate compares regenerated artifacts/JSON, not every number in manuscript prose. | Corrected the engineering ledger's claim about gate coverage. A manuscript-wide numeric gate and prose reconciliation are deferred, rather than claiming existing checks cover them. |
| A6 | C3 used superseded sweep medians; C7 called a 200.8 ms repeat a timer firing. | Corrected C3 from current values and narrowed its 6 microsecond bound to READ. C7 now states observed first repeat on a separate connection; timer mechanism and universal RTO bound remain unproved. |
| A7 | Abstract/conclusion omit the master-facing observation boundary. | Engineering C7 now states it explicitly. Paper edits deferred. |
| A8a | SELECT added median is recorded as 25.4825 ms; manuscript displays 25.482. | Engineering ledger retains 25.4825 ms to avoid ambiguous tie rounding. Paper formatting deferred. |
| A8b | “Within 6 microseconds” does not cover SELECT's 8.012 ms sweep median. The 2–26 ms sweep has eight tested settings. | Corrected both qualifiers in engineering C3. No continuous-range guarantee claimed. |
| A8c | Earlier acquisition defects were discarded: campaign truncation lost 1,107 Timing OFF exchanges; the initial sweep stopped after one point. | Verified their disclosure in campaign_v2/FINDINGS.md. These are different collection defects, not evidence that both failed in the same way. Historical records preserved; paper disclosure deferred. |
| A8d | Older manifests omit campaign params readbacks and the derived transaction table. | Supplemental start-of-audit hashes now cover these files. They establish current integrity, not retrospectively complete collection provenance. Original manifests untouched. |
| A8e | Paper-facing figure provenance predates later figures and still overstates numeric coverage. | Confirmed its limited figure inventory. Deferred under the paper freeze; engineering ledger states the current boundary. |
| A8f | Equal frame/byte totals do not prove unchanged DNP3 payload bytes. | Engineering C7 now distinguishes captured volume from byte-for-byte equality. No payload-equality test is falsely claimed. |
| A8g | Branch name says eight stages; the measured build's final allocation uses stages 0–6. | Branch names are identifiers, not resource evidence. Keep the branch; use the final compiler allocation and artifact hashes. Intermediate allocator attempts must not replace the final count. |

## P4 disposition

The measured randomized source retains the released OPERATE generation as held.
A matching retry is therefore classified as a held duplicate and dropped. This is
verified source behavior, not an observed relay-facing loss experiment. The older
early `hold_ok` dependency is not present in this source: admission and deadline
arming use the current register readbacks in `tbl_hold_ok`.

The isolated released-domain candidate distinguishes immediate post-release retries
from held duplicates. Local SDE 9.13.1 compilation succeeds at **seven ingress
stages**, confirmed by the final allocation and the build helper's context extraction.
The first allocator attempt is superseded and must not be cited as eight stages.

**The candidate is experimental, not a completed safe replacement.** A later
`PREPARE` clears the released marker, so an old retry arriving during a later ready
transaction can still be held again. The tests expose this as an expected failure;
it is an unresolved correctness case, not a passed requirement. The clear-on-release
attempt is rejected. No candidate was deployed or used to reinterpret existing data.
Details and reproduction commands are in [p4_candidate/README.md](p4_candidate/README.md).

The checks are a small source-informed transition model, not a P4 interpreter or
packet-level simulation. They do not prove shared TCP tracking, same-class concurrent
transactions, application-generation reuse, or exactly-once receiver delivery.
Local compilation also does not establish switch SDE 9.13.2 acceptance. Completing
loss recovery requires a reviewed transaction-identity design and packet-level
regression evidence before hardware validation; a seven-stage compile alone is
insufficient.

## Validation completed

- Targeted verification: 14 tests passed; one expected failure records the unresolved
  late OPERATE retry. Candidate source/context hashes and final allocation agree on seven stages.
- Existing campaign/figure integrity: 31 manifests, 401 entries checked without rewriting them.
- Grid: 240,000 exchanges, 10,813 raw-input hashes, 720 model artifacts,
  1,008 scored attacks, and 6,300,000 prediction signatures verified by the retained auditor.
- Exact training rounds 0–39 and held-out rounds 40–99 remain separated.
- Confusion matrices, class recall, and per-round balanced accuracy recomputed from
  prediction ledgers. Simultaneous bounds were re-evaluated with the frozen implementation;
  this is a consistency check, not independent statistical-method validation.
- Model bytes are recoverable; this audit does not refit or deserialize them.
- Recovery rejects corrupt archives, path escapes, and conflicting destination files.
- All 42,295 files in the pre-edit snapshot remain byte-identical, including manuscript,
  figures, measured sources, and original evidence. No hardware or remote push was used.
- Numerical/report findings and commands are in `analysis/REPORT.md`; they are subordinate
  evidence for this ledger, not a second publication authority.
