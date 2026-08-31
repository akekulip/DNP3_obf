> **Historical.** Written before the campaign_v1 correction of 2026-08-28. It describes the
> `final_read_sbo` evidence and the five-figure manuscript that preceded it. The active
> evidence authority is `defense4/timing/evidence/campaign_v1/` and the active claim
> authority is `defense4/timing/CLAIMS_AND_LIMITATIONS.md`. Kept for provenance.

# Pre-rewrite reconciliation — 2026-08-26

Every `ASSUMED`, `CONFLICT` and `UNKNOWN` item of `PRE_REWRITE_KNOWLEDGE.md`, with the question,
the evidence inspected this session, the result, and how it constrains the manuscript. All
commands were run from `/home/philip/Projects/DNP3` after `git fetch --all --prune`.

Status values: `RESOLVED`, `PARTIAL`, `UNRESOLVED`, `CONTRADICTED`.

---

## R1 — Do the auxiliary worktrees still exist? (§1, §2 CONFLICT/ASSUMED)

**Evidence.** `git worktree list --porcelain` lists exactly one worktree,
`/home/philip/Projects/DNP3` on `refs/heads/final/timing-paper-20260824`. `ls -d
/home/philip/Projects/DNP3*` returns only the main checkout, four `.bundle` files, and the
unrelated separate repository `DNP3_fixed_transcript`. None of `DNP3-size-probe`,
`DNP3-timing-core`, `DNP3-timing-cleanup`, `DNP3-paper-timing-figures` exists on disk.

**Result.** The brief's §18 (worktree consolidation) was completed on 2026-08-24. The unique
uncommitted material of the retired worktrees is preserved on `wip/size-probe-uncommitted-20260824`
(`9b9cb2c`) and `wip/caseA-uncommitted-20260824` (`348999e`), both reachable from the main
checkout (`git branch -vv`). The bundle `DNP3-before-final-timing-prune-20260824.bundle` records
`worktrees/DNP3-size-probe/HEAD` at `d06ca8b`, matching `defense4-real-size-normalization`.

**Status.** RESOLVED. No worktree removal remains to be done; disk space recovered was reported
by the 2026-08-24 session (`VERIFICATION_REPORT.md` §8: 303 MB → 6.6 MB checkout; the retired
worktrees are gone). **Constraint:** `/home/philip/Projects/DNP3` is the sole active worktree.

## R2 — Branch and commit checkpoints (§3 ASSUMED)

**Evidence.** `git branch -vv`, `git log --graph --decorate --oneline --all`, `git tag`.

| expectation | found |
|---|---|
| `origin/main` = `883d8cd5d83eb283aac905d8398e0c5f97d219a7` | `main` at `883d8cd` tracking `origin/main`, matches |
| `origin/defense4-size-native-parity-crc-split` = `8a6896e…` | local branch at `02923cb`, "ahead 10" of origin; tag `archive/defense4-full-before-timing-cleanup-20260824` marks `8a6896e`; tag `archive/defense4-local-unpushed-paper-20260824` marks `02923cb` |
| E_FINAL freeze `5a0fb73` | reachable from the archive tag (`REPOSITORY_AUDIT.md` 2026-08-24 confirmed its date 2026-08-13 21:21:39 −0400) |
| source commit `c1871384` | blob at that commit hashes to `7ce30494…` (`EVIDENCE_AUDIT.md` §7; the copy in the timing tree hashes identically this session) |
| `06f472c` | on `final/timing-paper-20260824`, "timing figures: the five paper figures" |
| `cleanup/timing-read-sbo-20260824` | `2ea2daf`, also tagged `checkpoint/timing-read-sbo-20260824` and `archive/pre-final-timing-prune-20260824` |
| `paper/timing-figures-20260824` | `0095923` |

**Which branch holds all four things.** `final/timing-paper-20260824` at `22db6e0` is the only
branch that contains the verified cleanup (`372b221`…`2ea2daf`), the self-contained reproduction
(`0da6f00`), the five final figures (`06f472c`, `860efc1`) and the manuscript (`82d954b`…`860efc1`
merged by `28158d4`). The final branch `paper/final-timing-rewrite-20260826` was therefore created
from `22db6e0` and nothing else was merged.

**Status.** RESOLVED.

## R3 — READ/SELECT release rule and the meaning of A, R, D_A, D_R, G, J (§8 CONFLICT)

**Evidence.**

* `implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4` lines 2358–2360:
  "d_ticks = D_A (ACK offset, T_A = t_A + D_A); da_dr = precomputed (D_A + D_R) so
  T_RESP = t_A + D_A + D_R"; line 1706: "T_RESP = t_A + D_A + D_R, armed once at the native
  ACK"; line 2549 `build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }` and line 2586
  `dec_ack_arm() { meta.dl_val = meta.dl_cand; meta.dl_val_resp = meta.tresp_cand; }`, where
  `now_word` is the ingress timestamp of the relay's ACK. The READ/SELECT deadlines are anchored
  to the **relay ACK's arrival**, not to the request.
* Same file lines 403–411 and 2966–2971 and 3139–3147: for a held OPERATE, `reg_deadline = T0 +
  A_DEFAULT_TICKS` and `reg_tresp = T0 + R_DEFAULT_TICKS`, "where T0 is the ORIGINAL OPERATE's own
  ingress timestamp — NOT the relay ACK's arrival"; lines 368–395: the OPERATE itself is held on
  qid2 of the BOR loopback and released to the relay at `T0 + J`. The OPERATE deadlines are
  anchored to the **request**.
* `implementation/control/defense4_rrc_bor_unified12_setup.py` lines 487–488 and 1083–1084:
  `tbl_params.d_ticks = (d_a_ms or 20) ms`, `da_dr = ((d_a_ms or 20) + (d_r_ms or 4)) ms`,
  argparse defaults `--d-a-ms 20.0`, `--d-r-ms 4.0`; lines 144–145: `A_DEFAULT_TICKS = 20 ms`,
  `R_DEFAULT_TICKS = 24 ms`. `defense4_caseA_setup.py` line 66: `MODE = {"OFF":0, …, "D4":4}`;
  lines 106–110: D4 requires D_A > 0 and D_R > 0, and "effective D_R == da_dr − D_A".
* `analysis/dnp3_timing.py` lines 9–14: the extractor's `A` is `T_ack − T_req` and `R` is
  `T_resp − T_req`, both master-visible; CLRT is `T_resp − T_ack`.
* Wire data (`derived_csv/*.csv`, cold rows excluded): Timing OFF request-to-ACK median 0.627 ms
  (READ) / 0.492 ms (SELECT); Obfuscated request-to-ACK median 20.661 / 20.510 ms and
  request-to-response 24.663 / 24.514 ms; CLRT 4.001 ms in both classes. OPERATE: request-to-ACK
  median 21.03 / 21.02 / 21.03 ms and request-to-echo 25.03 / 25.03 / 25.03 ms at J = 2 / 6 / 12.
* `LIN_STYLE_CONTRACT.md` §7 "G (a.k.a. J)": `LIN_WRITING_GUIDANCE.md` §0 records that Dr. Lin
  called the operate-hold delay G; the implementation, the E0 record, the readback rows and the
  manifest all call it J. No file uses G.

**Result.** Two release rules coexist in the one program, and the wire data confirm both:

| class | anchor | ACK to master | response/echo to master | packet to relay | master-visible interval |
|---|---|---|---|---|---|
| READ (1), SELECT (3) | relay ACK arrival `t_A` | `t_A + D_A`, D_A = 20 ms | `t_A + D_A + D_R`, D_R = 4 ms | request forwarded immediately | CLRT = D_R = 4 ms |
| OPERATE (4) | request arrival `T0` | `T0 + A`, A = 20 ms | `T0 + R`, R = 24 ms | `T0 + J`, J ∈ {2, 6, 12} ms | echo − ACK = R − A = 4 ms |

The measured request-to-ACK of about 20.5–20.7 ms in the Obfuscated arm is D_A plus the relay's
own ACK latency (0.5–0.6 ms), which is what an ACK-anchored rule predicts and a request-anchored
rule would not. The pre-campaign snapshot showing D_A ≈ 2 ms, D_R = 20 ms
(`hw_campaign_20260813T172014Z/h3_prep/rollback_verify/…`, archive tag) is an earlier phase's
configuration; the E-phase values follow from the setup defaults, which the frozen configure line
(`--mode D4 --op-a-ms 20 --op-r-ms 24 --j-set "<J>" --read-len 0`, `E_FINAL/README.md`) did not
override, and are corroborated by the wire.

**Status.** RESOLVED for the rules and the values; the E-phase D_A/D_R rest on the setup defaults
plus wire corroboration, with no readback of `tbl_params` archived for the E phase, so their
provenance is PARTIAL (recorded as such in the corrected `CAPTURE_MANIFEST`).

**Constraints on the manuscript.**

1. The Design section's read-path equations `t_ack = T0 + A`, `t_resp = T0 + R` are wrong for
   READ and SELECT and must be replaced by the ACK-anchored rule; the "security argument" that
   anchoring reads to `T0` removes dependence on the relay's ACK is CONTRADICTED by the
   implementation and is removed. The honest statement is: CLRT is pinned to D_R; request-to-ACK
   is shifted by D_A and still carries the relay's sub-millisecond ACK latency.
2. The OPERATE path is request-anchored, which is the anti-subtraction property the paper
   claims: echo − ACK = R − A regardless of J.
3. One notation: D_A, D_R for the read path; A, R, J for the control path. G is not used.
4. `CAPTURE_MANIFEST.csv/.json` filed D_A/D_R under "no OPERATE transactions"; corrected in this
   session (see `EVENT_SEMANTICS_TRUTH_TABLE.md`).

## R4 — E-phase D_A and D_R (§9 UNKNOWN)

Covered by R3. Values: D_A = 20 ms, D_R = 4 ms. Status PARTIAL (setup defaults + wire).

## R5 — The failed readback assertion (§12 KNOWN, re-checked as the brief requires)

**Evidence.** `git grep -l 'n_fail=1 ' archive/pre-final-timing-prune-20260824` finds the string
only in the two frozen copies of `hw_config_readback.txt`, the timing tree's copy, the audit that
discusses it, and two dry-run transcripts (`h3_live/v2_setup_dryrun_onswitch.txt`,
`rrc_bor_unified12_hwfix/setup_dryrun_transcript.txt`) whose `n_fail=1` lines belong to offline
dry runs of an earlier program state, not to a configure-all readback of the E phase. Every
configure-all transcript in `hw_campaign_20260813T172014Z/` ends `PASS (0 failures)` or
`PASS (n_fail=0 n_warn=0)`, except one mid-campaign retry that reports `n_fail=28 n_warn=1`. The
four `reg_bor_*` rows appear in no archived log. The same search over
`/home/philip/Archives/DNP3_nonfinal_20260824/` finds nothing further.

**Status.** UNRESOLVED, as before. Configuration provenance stays PARTIAL; the file is not edited.
**Constraint:** the paper states the limitation in Evaluation, not in a footnote.

## R6 — Legend labels "Timing ON" versus "Obfuscated" (§11 CONFLICT)

**Evidence.** `analysis/figstyle.py` lines 66–67: `LABEL_OFF = "Timing OFF"`, `LABEL_ON = "Timing
ON"`; all five PNGs render those labels. The brief §8 and §15 require the public-facing conditions
`Timing OFF` and `Obfuscated`; `LIN_WRITING_GUIDANCE.md` §0 records Dr. Lin correcting the figure
label to "obfuscated".

**Result.** A verified labeling difference from the required terminology, which the brief allows as
grounds to regenerate. The five figures are regenerated with `LABEL_ON = "Obfuscated"` under the
same interpreter that produced the committed copies (Python 3.8.10, matplotlib 3.7.5), and the
hashes in `FIGURE_PROVENANCE.md` and `FINAL_FIGURES.md` are refreshed. No data or method changes.

**Status.** RESOLVED (action taken later in this session, recorded in the figure commit).

## R7 — Section order and the firstness claim (§13 CONFLICT)

**Evidence.** `LIN_STYLE_CONTRACT.md` §2 and §4; `pipeline/lin_check.py` `check_structure`
(threat model must not follow Background) and `check_contribution_grammar` (firstness claim
required); the brief §3 ("Firstness must not be a mandatory claim", "Do not use style linting to
force unsupported technical content"), §22 (Background and Motivation before Threat Model and
Research Objectives), §31 ("Do not use 'to the best of our knowledge' as a substitute for
evidence").

**Result.** The brief is the newer and more specific instruction and it wins over the 2026-08-19
contract. Dr. Lin's own guidance (`LIN_WRITING_GUIDANCE.md`) asks for the threat model "early" and
does not mention firstness at all; the mandatory firstness rule was added by the contract's
"completeness pass", not by him. `lin_check.py` is corrected: the firstness requirement and the
Background/Threat-Model ordering rule are removed, and the checks the brief lists are added.

**Status.** RESOLVED. **Constraint:** section order per brief §22; no firstness claim.

## R8 — Venue and page limit (§13 UNKNOWN)

**Evidence.** `git grep` over `*.md`/`*.tex` for page limits and venues: `TITLE_OPTIONS_2026-08-24.md`
line 1 names "NDSS 2028"; `WRITING_PIPELINE_AUDIT.md` lines 70–77 quote a 2026-07 meeting note
("double-column IEEE template, ~12 pages before references, shared Overleaf") and flag the
NDSS-versus-IEEE ambiguity as unresolved. The repository holds no venue call, template notes or
page budget; `main.tex` uses `\documentclass[conference]{IEEEtran}`.

**Status.** UNRESOLVED. The page limit cannot be established from the repository. **Constraint:**
the IEEEtran conference template is preserved; the length is reported, not forced to a guessed
limit; the open venue decision is listed for Philip.

## R9 — Author metadata (§13 KNOWN placeholder)

**Evidence.** `\author` blocks in every `.tex` reachable from `main`, the archive tag, the two `wip`
branches and `final/manuscript-20260824`: all read `Author Name(s) / Affiliation / Email address`
or `Anonymous submission`. `git log --format='%an <%ae>'` gives only the committer identity, which
is not an author block. No file in the repository or the external archive records the author list,
affiliation or email for this manuscript.

**Status.** UNRESOLVED. **Constraint:** the placeholder is replaced by an explicit, visible
`AUTHOR BLOCK PENDING` marker rather than an invented name, and the item is listed as unresolved
in the final report.

## R10 — Dr. Lin's original text and the transcript (§14)

**Evidence.** `/home/philip/Archives/DNP3_nonfinal_20260824/unused_code/lin.png` (also tracked as
`lin.png` at the archive tag) is the annotated introduction. The two red boxes contain, verbatim:

* Paragraph 1: "Device fingerprinting has been an essential step in cyber reconnaissance,
  allowing adversaries to reveal unique features of target networks and design effective, stealthy
  attack strategies. These techniques are becoming increasingly critical in industrial control
  systems (ICSs) such as power grids, where adversaries often use IP-based control networks and
  computing devices within as entry points to inflict physical damage. Consequently, fingerprinting
  shifts the focus from visited web sites, user biometric behavior to device models and types of
  control operations that are critical to ICS attacks. In the 2015 attack that disrupted Ukrainian
  power grids and the Stuxnet attack that disrupted Iranian nuclear power facilities, it is widely
  believed that adversaries stay in their systems for at least 6 months to perform cyber
  reconnaissance."
* Obfuscation-trend paragraph: "To disrupt device fingerprinting, many studies present network
  traffic obfuscation. Because device fingerprinting targeting general computing environments
  generally relies on network-level features such as packet size and/or inter-packet latency
  observed from communication patterns, traffic obfuscation often focuses on (i) padding and
  splitting network packets, which hide or change the distribution of network packet sizes, and
  (ii) delaying network packets and adding dummy ones, which disrupt the inter-packet timing
  pattern. Since manipulating communication networks can introduce runtime overhead, recent works
  have begun to offload traffic obfuscation onto programmable network switches, which change
  communication patterns at much higher line rates than CPUs."
* Immediately below the second box, unboxed but discussed by him in the meeting: "Unfortunately,
  it is challenging, if not impossible, to apply these methods to device fingerprinting in ICS
  environments."

`introduction_pipeline_v1.tex` carries both paragraphs with edits already applied on 2026-08-19
(e.g. "has been" → "is", "letting adversaries", "identifying visited websites and user behavior",
"nuclear facilities", "stayed in the target systems", "Since manipulating traffic at the host adds
runtime overhead"). Those edits predate this session and are recorded in `LIN_TEXT_CHANGELOG.md`
together with this session's.

The meeting transcript is not in the repository or the archive; only the extraction
`LIN_WRITING_GUIDANCE.md` exists.

**Status.** RESOLVED for the protected text (verbatim source recovered); PARTIAL for the
transcript (extraction only). **Constraint:** the two paragraphs and the pivot sentence keep their
sentence roles and logic; every departure from the `lin.png` wording is logged.

## R11 — Bibliography authority (§15 ASSUMED/UNKNOWN)

**Evidence.** `library.bib` (134,922 bytes) is a Zotero/BetterBibTeX export with about 160 keys,
most unrelated to this paper (event studies, GDPR, data-breach costs). `refs.bib` (16,139 bytes)
holds 41 hand-written keys from the reader-first lineage, whose metadata was verified against DBLP,
ACM DL, IEEE Xplore and the NDSS/USENIX pages on 2026-08-14 (`paper/rewrite/CITATION_AUDIT.md`
at the archive tag). Every key cited by the current sections resolves in `library.bib`.

**Status.** PARTIAL. `library.bib` remains the active bibliography; the entries actually cited are
verified individually in `CLAIM_CITATION_MATRIX.md`; `refs.bib` is archived after the matrix shows
no required citation depends on it.

## R12 — Files proposed for removal (§18 ASSUMED)

Handled in `CLEANUP_PLAN.md` (root). Nothing is removed before that plan is written and the
external archive `/home/philip/Projects/DNP3-local-archive-20260826/` exists with manifests.

## R13 — Reproduction and tests (re-verified rather than remembered)

**Evidence.** This session: `tests/test_timing.py` → `RESULT: PASS (102 checks, 0 failed)` under
Python 3.8.10 and under Python 3.12.13. `reproduce.sh --outdir <scratch>` (interpreter resolved to
`uv run`, Python 3.13.12, numpy 2.5.2, scipy 1.18.1, scikit-learn 1.9.0, matplotlib 3.11.1):
every regenerated CSV agrees with the frozen CSVs within 0.001 ms (1489 + 600 + 500 + 30 + 30 + 30
rows); statistics `CLRT native READ n=999 med=1.272 std=1.354 max=12.274 >12ms=2`, `SELECT n=488
med=2.107 std=2.530 max=18.178 >12ms=11`, `defended READ n=599 med=4.001 std=0.022`, `SELECT n=499
med=4.001 std=0.021`, `MI 0.424356 → 0.002085 bits (null 0.0000–0.0033)`, `BA 0.5921 → 0.5000`,
echo−ACK medians 4.001 / 4.002 / 4.003 ms. Obfuscated maxima: READ 4.098 ms, SELECT 4.124 ms.
`MANIFEST.sha256`: 24 of 24 OK after the run. All four bundles verify.

**Status.** RESOLVED. The expected-results table of the brief §13 is met; the "verify from data"
cells are 4.098 ms and 4.124 ms.

## Summary of what changed in understanding

* Reads are ACK-anchored; only OPERATE is request-anchored. The current Design section has the
  read rule wrong and must be rewritten (R3).
* The E-phase read-path deadlines are D_A = 20 ms and D_R = 4 ms, from setup defaults, corroborated
  by the wire, not read back (R3, R4).
* The worktree consolidation is already complete (R1).
* The firstness rule and the threat-model-before-Background rule come from the 2026-08-19 contract,
  not from Dr. Lin, and are dropped per the brief (R7).
* Venue/page limit and author metadata cannot be recovered from the repository (R8, R9).
