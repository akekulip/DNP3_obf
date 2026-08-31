> **Historical.** Written before the campaign_v1 correction of 2026-08-28. It describes the
> `final_read_sbo` evidence and the five-figure manuscript that preceded it. The active
> evidence authority is `defense4/timing/evidence/campaign_v1/` and the active claim
> authority is `defense4/timing/CLAIMS_AND_LIMITATIONS.md`. Kept for provenance.

# Pre-rewrite knowledge — what was understood before the 2026-08-26 rewrite began

Written before any manuscript prose was modified. Every item carries one of four states:

* `KNOWN` — held from the previous sessions and confirmed by a file, hash or commit read this session
* `ASSUMED` — held from memory or from an older document, not yet confirmed this session
* `CONFLICT` — two sources disagree, or memory disagrees with the brief
* `UNKNOWN` — not known at all before this session

Every `ASSUMED`, `CONFLICT` and `UNKNOWN` item is taken up in `PRE_REWRITE_RECONCILIATION.md`,
which records the evidence inspected and the result.

## 1. Repository locations

| item | state | what was understood |
|---|---|---|
| Authoritative checkout | KNOWN | `/home/philip/Projects/DNP3`, remote `https://github.com/akekulip/DNP3_obf.git`; `git rev-parse --show-toplevel` returns exactly that path |
| Manuscript location | KNOWN | `paper/rewrite/`, entry point `main.tex`; the only manuscript on the branch |
| Timing authority | KNOWN | `defense4/timing/` with `implementation/`, `evidence/final_read_sbo/`, `analysis/`, `figures/{source,publication}/`, `tests/` |
| External archive of removed material | KNOWN | `/home/philip/Archives/DNP3_nonfinal_20260824/` (776 MB, untracked, with `MANIFEST.sha256` and `archive_index.csv`) |
| `DNP3-size-probe`, `DNP3-timing-core`, `DNP3-timing-cleanup`, `DNP3-paper-timing-figures` | CONFLICT | the brief treats them as existing auxiliary worktrees; memory from 2026-08-24 says they were retired |

## 2. Worktree relationships

| item | state | what was understood |
|---|---|---|
| Registered worktrees | ASSUMED | one, the main checkout, since the 2026-08-24 consolidation |
| Dirty or untracked work in other worktrees | ASSUMED | preserved on `wip/size-probe-uncommitted-20260824` (9b9cb2c) and `wip/caseA-uncommitted-20260824` (348999e) |

## 3. Authoritative branches and commits

| item | state | what was understood |
|---|---|---|
| Current branch at session start | KNOWN | `final/timing-paper-20260824` at `22db6e0`, clean apart from the untracked brief `corrections.md` |
| `origin/main` | ASSUMED | `883d8cd5…`, predates the 2026-08-13 campaign, contains none of the final evidence |
| Frozen evidence branch | ASSUMED | `origin/defense4-size-native-parity-crc-split` at `8a6896e`; local tip `02923cb` ten manuscript commits ahead |
| E_FINAL freeze commit | ASSUMED | `5a0fb73` |
| Exact experiment source commit | KNOWN | `c18713840e8376c065909749d451a6bc9e6c5c4d` |
| Figure/analysis commit recorded in provenance | KNOWN | `06f472c` |
| Cleanup branch | KNOWN | `cleanup/timing-read-sbo-20260824` at `2ea2daf` |
| Figure-handoff branch | KNOWN | `paper/timing-figures-20260824` at `0095923` |
| Final branch requested by the brief | UNKNOWN | `paper/final-timing-rewrite-20260826` — did not exist before this session |
| Which branch holds cleanup + reproduction + figures + manuscript together | ASSUMED | all four on `final/timing-paper-20260824` (merge commit `28158d4` brought `final/manuscript-20260824` onto the timing branch) |

## 4. Experiment source and binary

| item | state | what was understood |
|---|---|---|
| P4 source file | KNOWN | `defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`, sha256 `7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` |
| Loaded binary | KNOWN (recorded, not re-derivable) | sha256 `33fa3a77c732f4cfc138e21486d26c239e275b22d739f7e9e8d1b4abadb0a3aa`; no binary is kept in the repository; the value rests on `E0_testbed_preservation.md` and the build summary |
| Combined implementation | KNOWN | one program carrying the timing mechanism and the size carve; `shape_enable=1` in both arms |
| Compiler | KNOWN | bf-p4c, SDE 9.13.2, `--target tofino --arch tna -DU_BOR`, 12/12 ingress stages |

## 5. Raw captures

| item | state | what was understood |
|---|---|---|
| Six captures | KNOWN | `e1_native.pcap`, `e2_def_read.pcap`, `e2_def.pcap`, `sbo_j2.pcap`, `sbo_j6.pcap`, `sbo_j12.pcap`, 2026-08-13 19:53–19:57 local, master-facing on Vision |
| Hashes | KNOWN | all 24 entries of `evidence/final_read_sbo/MANIFEST.sha256` verify this session |
| `off_probe.pcap`, `e1_native_size_shapeoff.pcap` | KNOWN | excluded; the second is a size capture taken with the timing mechanism active (CLRT 4.000 ms) |
| pcapng despite `.pcap` extension | KNOWN | parsed by `analysis/pcap_reader.py` with integer nanoseconds |

## 6. Extraction scripts

| item | state | what was understood |
|---|---|---|
| Transaction definition | KNOWN | `analysis/dnp3_timing.py`: request (func 1/3/4) → first ACK-bearing relay packet → relay response (0x81); CLRT = T_resp − T_ack |
| Cold-start rule | KNOWN | first transaction of each TCP connection excluded and counted |
| `sbo_all.csv` | KNOWN | concatenation of the three J files, header kept once |

## 7. Final sample counts

| item | state | what was understood |
|---|---|---|
| Timing OFF READ 999, SELECT 488; Obfuscated READ 599, SELECT 499; OPERATE 30 per J | KNOWN | reproduced this session from the raw captures (`reproduce.sh`, `timing_stats.json`) |

## 8. Timing equations

| item | state | what was understood |
|---|---|---|
| READ/SELECT release rule | CONFLICT | the Design section states `t_ack = T0 + A`, `t_resp = T0 + R` for reads; the P4 header describes an ACK-anchored hold `t_ACK + D`; `CAPTURE_MANIFEST` carries D_A/D_R columns filed under OPERATE |
| OPERATE release rule | ASSUMED | ACK at `T0 + A`, echo at `T0 + R`, OPERATE to relay at `T0 + J`; echo − ACK = R − A |
| Meaning of A, R, D_A, D_R, G, J | CONFLICT | the brief forbids treating them as settled; `LIN_STYLE_CONTRACT.md` §7 calls G "a.k.a. J" and A/R "configurable" |

## 9. Configured values

| item | state | what was understood |
|---|---|---|
| A = 20 ms, R = 24 ms (OPERATE) | KNOWN | `A_DEFAULT_TICKS`/`R_DEFAULT_TICKS` in P4 and setup; E0 record; readback rows |
| J codebook {2, 6, 12} ms fixed passes | KNOWN | E0 record; readback rows `J[2]…J[12]` |
| D_A, D_R for the READ path in the E phase | UNKNOWN | not recorded in `CAPTURE_MANIFEST`; a pre-campaign snapshot shows D_A ≈ 2 ms, D_R = 20 ms, which cannot have produced the E-phase wire timing |
| `shape_enable = 1` in both arms | KNOWN | every relay response in every capture is two payloads of 28 and 21 bytes |
| Mode | KNOWN | `OFF` for the Timing OFF arm, `D4` for the Obfuscated arm (frozen README; corroborated by CLRT) |

## 10. Observation points

| item | state | what was understood |
|---|---|---|
| All captures master-facing, on the master host, interface `enp59s0f0np0`, switch dp9 side | KNOWN | `CAPTURE_MANIFEST.json` |
| Relay-facing port dp64 and internal port dp68 never captured | KNOWN | E0 record; no relay-facing evidence exists |

## 11. Figure provenance

| item | state | what was understood |
|---|---|---|
| Five figures, hashes in `FIGURE_PROVENANCE.md` and `FINAL_FIGURES.md` | KNOWN | manuscript copies under `paper/rewrite/figures/timing/` are byte-identical to `defense4/timing/figures/publication/` |
| Legend labels | CONFLICT | figures say `Timing OFF` / `Timing ON`; the brief requires `Timing OFF` / `Obfuscated`; Dr. Lin's own correction of the figure label was "obfuscated" |
| Committed figures built under matplotlib 3.7.5 / Python 3.8.10 | KNOWN | `figures/publication/ENVIRONMENT.txt` |

## 12. Known limitations

| item | state | what was understood |
|---|---|---|
| L1–L10 of `CLAIMS_AND_LIMITATIONS.md` | KNOWN | size shaping active in both arms; J unobserved relay-facing; exactly-once not shown; one device; transaction-disjoint split; MI unstable at the fourth decimal; configuration proof PARTIAL; driver logs absent; binary not read back at capture time; scope |
| The readback that reports `RESULT: FAIL (n_fail=1)` | KNOWN | hand-assembled excerpt; failing assertion unrecoverable from anything archived |

## 13. Manuscript structure

| item | state | what was understood |
|---|---|---|
| Existing sections | KNOWN | Introduction, Background, Threat Model and Objectives, Design; Evaluation is a figure scaffold; Abstract, Implementation, Related Work, Conclusion absent |
| Required order | CONFLICT | `LIN_STYLE_CONTRACT.md` and `lin_check` demand the threat model in or before Background; the brief's §22 puts Background before Threat Model |
| Firstness claim | CONFLICT | contract and `lin_check` make "To the best of our knowledge, first…" mandatory; the brief forbids requiring it |
| `\sysname` macro | KNOWN | renders `SysName`; the brief forbids inventing a system name |
| Title | KNOWN | `DNP3 In-Network Fingerprint Normalization` placeholder; `TITLE_OPTIONS_2026-08-24.md` lists size+timing titles that are stale |
| Author block | KNOWN | placeholder `Author Name(s) / Affiliation / Email address` |
| Venue and page limit | UNKNOWN | `TITLE_OPTIONS` says NDSS 2028; `WRITING_PIPELINE_AUDIT.md` reports a meeting note saying IEEE double column, about 12 pages; no venue file in the repository |

## 14. Dr. Lin's protected text

| item | state | what was understood |
|---|---|---|
| Paragraph 1 (device fingerprinting) and the obfuscation-trend paragraph | KNOWN | red-boxed in the annotated introduction `lin.png` (archived); transcribed verbatim in `pipeline/samples/lin_intro.txt` and `LIN_VS_PHILIP_DIFF.md`; carried with light edits in `introduction_pipeline_v1.tex` |
| The pivot sentence "Unfortunately, it is challenging, if not impossible…" | KNOWN | discussed by Dr. Lin in the meeting; present in `lin.png` just below the red box |
| The power-grid / plaintext DNP3 / false-data-injection paragraph | KNOWN | Philip's paragraph 2, not Dr. Lin's |
| The meeting transcript itself | UNKNOWN | only the extraction `LIN_WRITING_GUIDANCE.md` (2026-08-19) is in the repository |

## 15. Bibliography authority

| item | state | what was understood |
|---|---|---|
| `library.bib` | ASSUMED | Zotero export with BetterBibTeX keys; resolves every citation in the current sections |
| `refs.bib` | KNOWN | legacy keys from the reader-first draft lineage |
| Citation correctness of individual entries | UNKNOWN | never verified entry by entry in the pipeline lineage |

## 16. Pending Git operations

| item | state | what was understood |
|---|---|---|
| Nothing pushed; `final/*`, `cleanup/*`, `wip/*`, `paper/timing-figures-*` local only | KNOWN | `git branch -vv` |
| Bundles | KNOWN | four under `/home/philip/Projects/*.bundle`, all four verify "records a complete history" this session |
| Tags | KNOWN | `archive/defense4-full-before-timing-cleanup-20260824`, `archive/defense4-local-unpushed-paper-20260824`, `archive/pre-final-timing-prune-20260824`, two `checkpoint/*` tags |

## 17. Uncommitted files

| item | state | what was understood |
|---|---|---|
| `corrections.md` | KNOWN | the brief for this session, untracked at the root |
| `defense4/timing/uv.lock` | KNOWN | created by this session's `reproduce.sh` run through `uv`; a build product |
| `paper/rewrite/pipeline/reports/` | KNOWN | ignored by `.gitignore` at session start, which would have hidden the reports the brief requires |

## 18. Local files proposed for removal

| item | state | what was understood |
|---|---|---|
| Stale writing-pipeline documents (`WRITING_PIPELINE_AUDIT.md`, `WRITING_PIPELINE_REBUILD_PLAN.md`, `PIPELINE_AUDIT_VERDICT.md`, `TITLE_OPTIONS_2026-08-24.md`) | ASSUMED | superseded once their unique content is folded into one writing guide |
| `refs.bib` | ASSUMED | legacy; removable once no required citation depends on it |
| Auxiliary worktree directories | ASSUMED | already gone |
