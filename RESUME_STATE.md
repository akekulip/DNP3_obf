# RESUME STATE — DNP3 project

**Reflects the tree through the release-hardening pass (2026-07-30/31); this status file was
committed immediately afterward.** For the exact current commit, run `git rev-parse HEAD` — do
not rely on a SHA written here (it goes stale the moment this file is committed).

Read this first, then `CLAUDE.md` for the rules and layout, and `defense3/REPORT.pdf` for the
work itself.

---

## Current headline

**Case A Defense 3 (predetermined in-network ACK delay) is complete, hardware-validated, and
release-hardened.** Everything lives in `defense3/`. The canonical program is
`defense3/p4/case_a_defense3.p4` (R1/R2/R3 unconditional — a no-flag build is the safe
repaired program). It was compiled on the deploy compiler (bf-p4c 9.13.2), the parser
`uninitialized_out_param` warning is eliminated, the R2 note predicate is present in the
assembly, `setup --config` passes 43/43 on silicon, and Gate 2 passes end-to-end. The switch
is restored to the frozen Defense 2 baseline.

## Repository / git state

- **Single branch `main`**, work committed and pushed in the same pass (no feature branches).
  Commits in Philip's name only.
- The release-hardening pass (CORRECTIONS.md) is complete for the release-blocking items and
  hardware-verified; see the audit response below.

## Switch state

- Restored to **Defense 2** (`dnp3_timing_normalizer_pktgen`, the frozen silicon-proven
  baseline), one `bf_switchd`. Verified.
- The final confs on the switch: `d3_final.conf` (core), `d3_final_synth.conf` (synthetic).
  Safe restore targets are the final repaired build or Defense 2 — **never** the unrepaired
  program, which loads only behind `--load-unrepaired-control` (CORRECTIONS.md §2.3).
- Hardware/switch changes remain gated on explicit Philip authorization.

## What the release-hardening pass did (CORRECTIONS.md)

- §2.1 canonical `case_a_defense3.p4` (R1/R2/R3 unconditional); pre-audit sources archived.
- §2.2 default program = `case_a_defense3` everywhere; a final-repair arm-guard refuses a
  non-final build. §2.3 safe restore baseline.
- §3 `control/parameter_policy.py` — one D/H/RTO/poll-rate authority (dropped the impossible
  40 ms clamp and the stale 22 ms guard); §4.2 `control/counter_map.py` (CF_BLOCK_REJECT=17
  now reset). §3.4 reg_failopen in clean/cleanup. §4.1 SyncCounters. §4.3 campaign fail-closed.
- §5.6 parser warning eliminated; §5.2/§5.3 duplicate-suppression wording qualified.
- §6.1 ledger link fix; §6.2 assert_salu_asm `--require-r2`; final artifacts under
  `artifacts/final/`. §7 report/README claim corrections. §8 pruning + archiving.
- Hardware: 9.13.2 compile (all targets, 0 warnings) + Gate 2 PASS + restore, in
  `defense3/evidence/final_silicon/`. A regression the run caught (out['D'] keys) was fixed.

## Open items (deferred / lab-blocked)

- **(B) §5.5 TCP-sequence-zero sentinel** — DONE: writer/reader split applied to the canonical
  P4, 9.13.2 resource-neutral, Gate 2 PASS, seq-0 store proven in the assembly.
- §10.B hardware (assessed 2026-07-31, `defense3/evidence/final_silicon/*/remaining_10B_assessment.md`):
  #13 core-vs-telemetry parity DONE at artifact level (full physical core campaign = larger open
  part); #14 hardware-timestamped capture and #12 egress sweep are **achievable** (Vision's NIC
  supports hardware RX timestamps) — ready experiments, not hard blocks; external-wire R1/R3
  injection is genuinely topology-blocked (dp64 faces the SEL-751); K-minimization is post-freeze
  optimization gated by the intentional K==64 safety pin (KVAL now wired into gate2).
- Defect-2 cross-transaction generation-wrap: model-checked, not physically reproduced.

## Key pointers

- `defense3/REPORT.pdf` / `REPORT.md` — the full report. `defense3/README.md` — directory map.
- `defense3/MANIFEST.yaml` — claims bound to source/artifact/evidence/analyzer.
- `defense3/evidence/INDEX.md` — what each evidence directory holds.
- `defense3/AUDIT_RESPONSE.md` — the audit resolution record.
- `defense3/archive/audit/ORIGINAL_AUDIT.md` — the original audit text (was `CORRECTIONS.md`).
- `CLAUDE.md` — rules and layout; `meeting.md` and archived directions under `defense3/archive/`.

## Report figures (2026-07-31)

Three high-value figures ADDED and integrated (REPORT 40pp, 12 figures): **Fig 10** end-to-end
lifecycle + repair placement (§7, the main 'how it works' diagram), **Fig 11** safe operating
region for D (§6.3), **Fig 12** three-campaign READ->ACK non-regression (§10.5). A shared
visual-language module `defense3/figures/src/d3_style.py` encodes the reviewer's global colour
rules (ACK=blue, RESPONSE=orange, native=black, blocker=gray, pass=green, fail=red).

Figure retrofit DONE (2026-07-31, same day): all 9 pre-d3_style figures (fig1–fig9) now
import `d3_style` — no `paper_palettes` positional colors remain — with the per-figure
redesigns applied: **Fig 1** 95% CIs (Wilson for the panel-b proportion, 1000-resample
bootstrap for the panel-c AUROC, seeded rng(0)) + labelled 0.1 ms collapse threshold and
drift floor; **Fig 3** horizontal grouped AUROC bars (D=1 on top, chance + drift-floor
reference lines, legend in its own band); **Fig 5** three tinted state-domains (ACK-tint
armed / RESPONSE-tint queued, STATE-purple encodings); **Fig 8** IEEE systems style, squared
nodes, bold port 9/port 64 labels + speeds on the links, red dashed adversary; **Fig 9**
stacked-bar fail-open accounting (share-of-K stacks, green budget = 1 vs red stale = K−1;
absolute stacks for the R2 before/after). Data invariance proven by unchanged printed stat
lines on figs 1/3/7/9; every output visually inspected; report-width variants (D3_FIG_W=4.35)
regenerated. Captions synced: Fig 1's tex caption was STALE (still described the pre-audit
two-panel layout) and was rewritten to the current three-panel form; Fig 1/Fig 3 md captions
updated (gray-line disambiguation, CI sentence, horizontal-bar phrasing).

Stage-G language pass (2026-07-31): academic-humanizer catalog audit over the whole report —
the prose is already clean (1 hit fixed: "Crucially" boilerplate emphasis; "robust to X",
"more importantly", "not merely" kept as legitimate per the skill's Layer 3). The apparent
long-sentence flags were markdown block-boundary parsing artifacts, not real run-ons. No
deeper stylistic rewrite done: no identified defect, and the teaching voice is deliberate.

## Paper reframe — research-pipeline Stage F (2026-07-31)

Parts 1–3 done, all in `defense3/`:
- **Part 1** Introduction + contributions, de-audit tone. **Part 2** explicit Threat model
  subsection (passive on-path CLRT adversary).
- **Part 3** Related work: new **§4** in REPORT.md/tex (5 themes, 27 verified references) with
  a full `thebibliography` in the tex; sections 4→15 renumbered throughout. Supporting files:
  `related_work_map.md` (theme map, positioning lines, provenance), `related_work_draft.md`
  (prose draft), `references.bib` (27 entries, no fabricated citations),
  `objection_ledger.md` (per-claim adversarial objections + responses for pre-review).
- md↔tex §4 verified word-identical by a normalized word-level diff; PDF rebuilt with
  tectonic and phrase/bibliography presence verified via pdftotext.
- Spelling convention: report prose is British (-ise, acknowledgement) except the project
  term "Defense"; §4 was brought in line.
- Zotero: all 27 references were already in the library; the literature-reviewer agent
  organized them into collection "DNP3 Defense 3 — Related Work" (nested under "Defense 3 —
  DNP3 CLRT ACK-delay (Tofino)", 27/27 verified). **PDF coverage is now 27/27** (2026-07-31):
  10 arXiv + 2 local anchors (agent), 3 fetched from open archives (Song '01, Walkie-Talkie
  '17, Traffic Morphing '09 — each verified against its first page), and 12 supplied by
  Philip in `D3/` (all first-page-verified before attaching). `D3/` is gitignored — the
  publisher PDFs must not reach public GitHub; Zotero holds imported copies, so the folder
  is deletable.
- Zotero semantic search: WORKING (2026-07-31) — persistent `uv tool install
  'zotero-mcp-server[semantic]'`, MCP entry in `~/.claude.json` repointed to the installed
  binary, local MiniLM embeddings, full-text index of all 113 library items. Two gotchas
  (bare-uvx env strips the extra; plain `update-db` embeds metadata only — body text needs
  `--fulltext`) are in project memory: `zotero-semantic-search-setup.md`.
