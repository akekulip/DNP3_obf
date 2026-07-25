# Repo cleanup audit — 2026-07-25

After consolidating the three worktrees back into this one folder, I audited the repo for obsolete /
superseded / redundant content. This records **what I already removed** (safe, done) and **what needs
your decision** (I did not touch it).

Repo before: 616 MB (68 MB `.git`, 548 MB working tree). After the safe pass: ~457 MB working tree.

---

## A. Already removed — safe, regenerable, done

| item | size | why safe |
|---|---:|---|
| 9 untracked bf-p4c build-output trees (`compile*/`, `*_telem/out/`, `shadow/out/`, `compile_trace_v1/`) | ~92 MB | pure compiler output, 0 `.p4` sources, regenerable; manifest in `docs/cleanup/BUILD_OUTPUT_REMOVED_20260725.md` |
| 8 tracked compile logs inside those dirs (`*.stderr.log`, `table_summary.log`) | small | build artifacts, recoverable from git history; results captured in the committed compile notes |
| 2 redundant zip snapshots (`dnp3_queue_microbench_snapshot.zip`, `size_pattern_builder_v1.zip`) | ~0.4 MB | contents already tracked in the repo |
| the two extra worktree directories (`../DNP3-part13`, `../DNP3-stagereclaim`) | — | branches merged in and preserved; only the checkouts removed |

Added `.gitignore` rules so bf-p4c `out/` trees and compile logs are not re-committed. Committed as
`e34e32e`.

**Preserved deliberately** (found untracked, now committed): `research/unified_queue_release/direction.md`
— the governing IBSPG direction doc (548 lines). Also kept the `shadow/gate1_dp11_dp9_evidence/` data.

---

## B. Needs your decision — I did NOT touch these

### B1. Your 15 pre-existing root-doc deletions (all recoverable from git history)

These were already deleted in the working tree when this session began; I was asked repeatedly not to
touch them, and a forensic snapshot is committed at
`research/ibspg_hold_response/evidence/preexisting-uncommitted-state/`.

- **Task/direction docs, now superseded:** `acj_delay2.md`, `corrective.md`, `test_cases.md`,
  `ack_delay.md`, `when_how.md`, `CROb.md`, `week8.md`, `week8_next.md`,
  `ASSUMPTIONS_AND_UNKNOWNS.md`. — *Recommend: finalize the deletions* (they are superseded by the
  committed reports and `RESUME_STATE.md`), but they are yours to keep if you want the raw history.
- **`PAPER_OUTLINE.md`** — *Recommend: RESTORE*. We are about to write the paper; this is the outline.
- **Weekly decks `7. Week 7.pptx`, `8. Week 8.pptx`** — *Recommend: keep/restore* (presentation record).
- **`OVERNIGHT_RUN_…md`, `OVERNIGHT_FINAL_REPORT_…md`** — *Recommend: finalize deletion* (superseded run logs).
- **`Claude Code Prompt- General DNP3 Experiment Harness.md`** — the original task prompt; CLAUDE.md
  references it as the style/naming constraint source. *Recommend: keep/restore.*

**Decision needed:** which to finalize-delete vs restore. I will do exactly what you say and nothing more.

### B2. `dnp3_split_harness/split_server.py` — uncommitted modification

The `--response-readiness-ms` addition from the 2026-07-20 C3 work, never committed. Diff preserved in
the forensic snapshot. *Recommend: commit it* (it is a clean, self-contained, documented feature), or
revert if it was abandoned. Your call.

### B3. Committed bf-p4c build output — 22.2 MB, regenerable

37 files under `research/stage_reclamation/variants/p13_size_do8/probe_widen/o_k*/` (`context.json`,
`tofino.bin`, `*.bfa`, `frontend-ir.json`, …) — compile probes from the size `data_offset=8` widening,
now a **characterized negative**. Recoverable from history, regenerable from the `.p4`. *Recommend:
`git rm` the generated files, keep the `.p4` + compile notes + the small resource/`table_summary`
logs that carry the actual result.* I held off because it edits a committed research record.

### B4. Small odds and ends

- `research/tofino_dcrn_feasibility/p4/queue_microbench/autonomous_run_20260722/ChatGPT Image ….png`
  (1.75 MB, untracked) — an AI-generated illustration in an evidence dir, not measurement data.
  *Recommend: remove* unless a report references it.

---

## C. Explicitly NOT candidates (protected / needed)

- `dnp3_split_harness/archive_original/`, `archive_experiments/`, `future_work/` — CLAUDE.md marks these
  "preserved, never delete" / "kept for reference." Left intact.
- Reference PDFs (Ditto NDSS, device-fingerprinting) — literature, kept.
- `Traffic Trace/*.pcap`, `corpus_audit.json`, `ack_trace_characterization.*` — experimental data, kept.
- All committed reports and evidence for Parts 9–13, the stage-reclamation campaign, and the relay work.

---

## Recommendation

The safe pass (A) is done and reclaimed ~92 MB. For B, the fastest clean end state is: **restore
`PAPER_OUTLINE.md`, the two decks, and the original prompt; finalize the other deletions; commit
`split_server.py`; `git rm` the 22 MB of probe build output; remove the ChatGPT image.** Say the word
and I will execute exactly that (or any subset), keeping the forensic snapshot as the safety net.
