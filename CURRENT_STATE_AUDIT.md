# CURRENT_STATE_AUDIT.md — Phase 0 Repository Audit

_Produced 2026-07-21 per `meeting_direction.md` §7 Phase 0 / §17 First Action. **No code was changed,
no switch was touched, no hardware assumption was treated as fact; all findings come from verified
repository/source evidence.**_

## 0. Scope & method
Audit of the DNP3 timing/size-obfuscation repo against the master direction (`meeting_direction.md`)
and meeting minutes (`meeting.md`, 2026-07-21). Read: git state, the ack-delay tree, the Ditto/Formby
PDFs, the `paper/` tree, and the real device captures. Confirms terminology, flags errors, separates
frozen-vs-stale, and lists the next off-switch actions.

## 1. Verified repository state
- **Branch:** `research/ack-timing-phased` · **HEAD** `c0e4105` · **in sync with** `origin/…` (pushed).
  (Master direction §11 suggests a *new* branch `research/caseA-ditto-queue` for the queue work — NOT
  yet created; queue work has not started.)
- **Frozen tag:** `ack-delay-caseA-c3-pass` → `bf4acdff` (the recirculation Case-A / Defense-1 pass).
- **Recent commits:** c0e4105 (this session's report+design), 47cca2b/4250198/cb2e2ed (the ackB /
  "Case B" response-delay work), 16f43d1 (meeting deck), 37bd708 (Netronome brief).

## 2. Terminology verification — CONFIRMED direction, and the ERROR to fix
The master direction (§1) and meeting (§2–3) **confirm the taxonomy locked this session**
(`memory/dnp3-clrt-case-taxonomy.md`): **Case A = separate-ACK (SEL-751)** with **Defense 1 = delay
ACK** and **Defense 2 = delay response**; **Case B = combined-ACK (AB1400/ION7550), OUT OF SCOPE now.**
CLRT is used correctly (separate-ACK only) in the policy/report docs.

**★ ERROR (master direction §13 "Never call Defense 2 'Case B'", §17 item 3):** a large set of
artifacts predate the lock and use "B / ackB / caseB" to mean **Defense 2 (response-delay) on
separate-ACK data** — that is exactly the forbidden mislabel. They must be **renamed Defense-2**, not
deleted (they are valid Defense-2 evidence). Rename map (a gated Phase-1 task, NOT done in Phase 0):

| Current (mislabelled "B/caseB" = Defense 2) | Should be |
|---|---|
| `dcrn_defense2.p4`, `defense2_setup.py`, `launch_defense2.sh`, `dcrn_defense2.conf` | `dcrn_defense2.*` / `defense2_setup.py` … |
| `ACK_DELAY_DEFENSE2_DESIGN.md` | `ACK_DELAY_DEFENSE2_DESIGN.md` |
| `evidence/defense2_hardware/`, `evidence/defense2_9.13.1/` | `evidence/defense2_hardware/`, `evidence/defense2_9.13.1/` |
| `evidence/pcap_clean/defense2_clean.pcap`, `pcap_raw/defense2_raw.pcap` | `defense2_clean.pcap`, `defense2_raw.pcap` |
| `refmodel/defense2_state_machine.py`, `tests/test_defense2.py` | `defense2_state_machine.py`, `test_defense2.py` |

**NOT an error (keep as-is):** `case_b_defense_design.md` — this one is *correctly* the combined-ACK
**Case B** design study (a deferred later extension, master direction §1/§2 "Case B remains a later
extension"). Keep it; mark it clearly as OUT-OF-SCOPE-for-now in its header.

## 3. SEL-751 native baseline — VERIFIED (meeting §4 correction)
Real device captures (`Traffic Trace/`), master 10.0.0.3 → SEL-751 10.0.0.1, ACK→response gap:

| Capture | n | median | IQR | p10–p90 | min–max | outliers>p90 |
|---|---|---|---|---|---|---|
| `SEL751.pcap` | 299 | **12.90 ms** | [11.98, 14.39] | 11.64–15.83 | 10.50–165.98 | 30 |
| `SEL751L.pcap` | 3999 | **12.18 ms** | [11.77, 13.46] | 11.48–15.78 | 0.74–160.71 | 400 |

**Paper statement (correct):** "SEL-751 native ACK-to-response timing forms a stable cluster around
**12–13 ms** (median 12.90 ms / 12.18 ms across the two captures), IQR ~12–14 ms, with a small heavy
tail to ~166 ms." **Units = milliseconds** ✓. Both captures agree.

**★ Figure-consistency flag:** the *defense* figures use the **rig** value **17.35 ms** (dev1 native
on the single-host loopback), which is ~4.5 ms above the real 12.9 ms (loopback/replay overhead). Per
master direction §12, the rig is **"SEL-751 capture-derived live-TCP replay,"** not the live device.
The paper's *baseline* must use the real **12.9 ms**; the defense before/after may use the replay value
but must be labelled as replay. Reconcile before the paper uses a number.

## 4. FROZEN — preserve, do not delete/overwrite/rewrite (master direction §4)
- **Recirculation Case-A implementation:** `dcrn_defense1.p4` (Defense 1) + `dcrn_defense2.p4` (Defense 2) —
  the valid feasibility baseline; the meeting (§6) explicitly says keep it as the comparison baseline.
- **Tagged evidence** `ack-delay-caseA-c3-pass` (`bf4acdff`).
- **Hardware-evidence dirs (RESULT.md-bearing):** `evidence/{formby_eval, defense2_hardware,
  sel751_replay, continuous_campaign_PASS}/` — the PASS_MEASURED_ON_TOFINO proofs.
- **Raw captures:** `Traffic Trace/*.pcap`, `evidence/pcap_raw/`, the continuous-campaign pcaps.
- **Reference PDFs:** `2022_NDSS_ditto…pdf`, `who-control-your-control-system…pdf` (Formby).
- **Archives** (`dnp3_split_harness/archive_*`, `future_work/`) per repo CLAUDE.md.

## 5. Queue / Ditto / paper status
- **Ditto paper present:** `./2022_NDSS_ditto WAN Traffic Obfuscation at Line Rate.pdf` → next task is
  `DITTO_QUEUE_RECONSTRUCTION.md` + `DITTO_TO_DNP3_MAPPING.md` (master direction Phase 2, deliverable
  §16). **No queue/TM microbenchmark P4 exists yet** (Phase 4, not started).
- **Paper started:** `paper/dnp3_obfuscation_paper.tex` (+ `_desmoothed.tex`, `_idiom.md`, `.md`,
  `.pdf`, `HUMANIZE_NOTES.md`). Multiple near-duplicate variants → consolidation candidate (§6).
  Overleaf/URI-email setup NOT confirmed (master direction §15/action-items — a Philip task).
- **Missing required deliverables** (§16): `ASSUMPTIONS_AND_UNKNOWNS.md`, `DITTO_QUEUE_RECONSTRUCTION.md`,
  `DITTO_TO_DNP3_MAPPING.md`, `CASE_A_TERMINOLOGY.md`, `CASE_A_QUEUE_DESIGN.md`, `QUEUE_MICROBENCH_PLAN.md`,
  `QUEUE_VS_RECIRC_EVALUATION_PLAN.md`, `SEL751_DIRECT_CONNECTIVITY_PLAN.md`, `PAPER_OUTLINE.md`.

## 6. STALE / safe to delete (regenerable, zero information loss) — the cleanup set
| Item | Size | Why safe |
|---|---|---|
| `build_defense1_9.13.1/`, `build_defense2_9.13.1/` | 27 MB | bf-p4c outputs, gitignored, regenerable; facts saved in `COMPILE_FACTS.md` + `evidence/*_9.13.1/*.log` |
| `__pycache__/` (10 dirs) | 1.3 MB | gitignored, regenerable |
| `evidence/dnp3_ack_delay_artifacts_2026-07-21.zip` | 653 KB | untracked delivery bundle, regenerates from tracked files |
| `/tmp/*.pcap` scratch | — | session temp; durable copies live in `evidence/` |
| Superseded THIS-SESSION figures: `pcap_screenshots.png`, `dnp3_slides_draft.html`, `response_time_clustering.png` | ~340 KB | tracked → `git rm`; replaced by `pcap_before_after.png`, `dnp3_slides_meeting.html`, `clustering_before_after.png` |
| Superseded render scripts: `render_clustering_before_after.py`, `render_clustering_real_devices.py` | — | tracked → `git rm`; replaced by `render_defenses_sel.py` + `render_clustering_separate.py` |

**NOT deleting** (needs decision, not "cleanup"): the mislabelled Defense-2 files (§2 — those get
**renamed**, not removed) and the `dnp3_split_harness/runs/` 143 MB experiment history (review
individually).

## 7. Assumptions & unknowns (seed for `ASSUMPTIONS_AND_UNKNOWNS.md`)
1. **Rig ≠ physical device.** All Tofino results are single-host loopback **replay** of SEL-751; the
   live-physical SEL-751 experiment (master direction Phase 5) is NOT done. [status: open, gated]
2. **Recirc timing is load-dependent** (Defense-2 "constant" 107 ms = 60 ms Gᵢ + ~47 ms drain offset).
   The meeting (§6/§9) wants this compared against a **queue-based** mechanism under load. [open]
3. **Defense-2 60 ms target is a calibration value, not a defensible policy** (meeting §10). [open]
4. **Switch state not verified this session** (Phase 0 = no hardware). Last known = RESUME_STATE. [open]
5. **Queue/TM behaviour on our silicon unmeasured** — Ditto shapers are "correct on average"; must be
   measured (master direction Phase 4). [open]

## 8. Requires explicit hardware authorization (master direction §10)
Any switch load/compile-on-switch/wire test; the physical SEL-751 connection (Phase 5); the queue
microbenchmark on hardware (Phase 4). Local inspection/compile/reference-models/tests are authorized.

## 9. Next off-switch actions (file-by-file, Phase 1/2 — no hardware)
1. **Safe cleanup** (§6) — do now.
2. **Rename Defense-2 mislabels** (§2) — gated, cross-reference-careful; new commit.
3. **Consolidate `paper/` variants**; create `PAPER_OUTLINE.md` from meeting §16 outline.
4. **Read Ditto** → `DITTO_QUEUE_RECONSTRUCTION.md` + `DITTO_TO_DNP3_MAPPING.md`.
5. `ASSUMPTIONS_AND_UNKNOWNS.md` + `CASE_A_TERMINOLOGY.md`.
6. Reconcile the 12.9-vs-17.35 ms figure/baseline discrepancy (§3).

**CURRENT STATUS: Phase 0 audit = COMPLETE. No code changed, no switch touched.**
