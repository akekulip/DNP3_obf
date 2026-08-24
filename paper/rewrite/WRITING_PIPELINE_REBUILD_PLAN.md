# Writing-pipeline rebuild plan — make "write like Dr. Lin" reproducible

Goal: encode everything Dr. Lin expects into the writing pipeline (spec + skills + routing +
doctrine + a re-runnable check) so **every** future drafting/revision pass reproduces his
structure and voice, instead of the current generic-by-default behavior the audit found. Proposal
for Philip's approval — repo-local parts I can build now; global-config parts need your go.
2026-08-19.

## Why this is needed (from the audit)

The tooling is healthy; the failure is **wiring + no durable spec + no enforcement**:
- The two skills that encode Dr. Lin's own voice/genre (`paper-voice`, mined from his papers, and
  `security-paper-writing`) sit **outside the default routing**; defaults pull a security paper to
  the generic `academic-paper` / `systems-paper-writing` writer and the generic `humanizer`.
- Two routing surfaces disagree → **inconsistent output run to run**.
- Nothing **checks** a draft against his style, so drift is invisible until he reads it.

## The four layers to build (each: what / where / risk)

### A. SPEC — the single source of truth (REPO-LOCAL, safe, build now)
`paper/LIN_STYLE_CONTRACT.md`: consolidate every key from `LIN_WRITING_GUIDANCE.md` (transcript),
`LIN_STYLE_PROFILE.md` (his papers), `LIN_VS_PHILIP_DIFF.md` (annotated intro), plus the
completeness-pass additions, into one enforceable contract: scope/framing rules, section-order +
**section-placement** contract (incl. "design content lives in a distinct Design section, not the
intro"), the introduction blueprint (4-sentence funnel + gap-paragraph-that-premaps-contributions),
contribution grammar (verb-first headlines + mandatory "to the best of our knowledge, first"),
sentence-level rules (connective spine, one-idea-per-sentence, plain words, consistent terms,
motivation-first, examples-serve-thesis), and the threat-model contract (passive/proactive/active,
define-and-use-consistently, passive focus).

### B. ENFORCEMENT — a re-runnable check = the "reproducible" core (REPO-LOCAL, safe, build now)
`paper/pipeline/lin_check.py`: wraps `paper-voice`'s existing `voice_check.py` and ADDS the checks
for exactly the divergences the profile found:
- **connective-spine density** (Consequently/However/Because/Since/For example per paragraph ≥ target);
- **contribution grammar** (verb-first bold headlines; a first-ness claim present);
- **structure** (threat model appears early; a distinct Design section exists; goals RO-labelled and
  those labels reused in Evaluation);
- **readability** (flesch_reading_ease / fk_grade within band — the "too dense" guard he flagged);
- **sentence health** (flag fragments / sentences with no main clause — the "By learning…, because…"
  class);
- **fact-hygiene** (duplicate marquee examples, obvious date slips) as warnings.
Output: a pass/fail report per section. Plus `paper/pipeline/build.sh`: `tectonic` build → run
`lin_check` → emit report — one reproducible "draft → checked PDF + score" command, mirroring the
repo's existing conformance-gate pattern.

### C. ROUTING — wire the right skills onto the default path (GLOBAL, needs your approval)
Itemized edits (I will show diffs before applying):
1. `~/.claude/CLAUDE.md` "Automatic skill invocation" table: security-venue manuscripts →
   `security-paper-writing` (not `systems-paper-writing`); academic manuscripts →
   `academic-humanizer` (not generic `humanizer`); add `paper-voice` as the mandatory voice pass;
   review gate → `ieee-journal-reviewer` agent.
2. `~/.claude/agents/principal-investigator.md` delegation map: add `paper-voice` +
   `security-paper-writing` (currently omitted).
3. `~/.claude/skills/research-pipeline/SKILL.md` Stage F list: name `security-paper-writing` +
   `paper-voice` explicitly.

### D. SKILL + DOCTRINE — make the reproduction durable (GLOBAL, needs your approval)
1. `~/.claude/skills/paper-voice/` Voice Card: add the section-ORDER contract, the verb-first
   contribution rule, and the transcript-derived method (the profile noted these are the pieces
   paper-voice lacks). This upgrades the skill itself so it reproduces his structure, not just his
   sentences.
2. `~/Projects/research-philosophy/WRITING-SYSTEM.md` doctrine: record the "Lin/ICS-security
   manuscript" profile so it's the standing reference.

## The reproducible end-to-end flow (after the rebuild)

`draft in Lin's method (contract A)` → `security-paper-writing` (structure) → `paper-voice`
(his voice) → `academic-humanizer` (AI-tell sweep, preserve scholarly voice) → **`lin_check` gate
(B)** → `remove-ai-marks` Layer A (final) → `build.sh` → PDF + score. Same inputs → same
Lin-aligned output, and the gate makes drift visible and fixable every run.

## Scope decision for you

- **Repo-local (A + B)**: safe, immediately useful, reproducible for THIS paper. I can build it now.
- **Global (C + D)**: the durable fix so it holds across sessions/repos — but it edits your global
  `~/.claude` config, the PI agent, and the philosophy doctrine. I will show every diff and apply
  only what you approve; nothing global changes without your explicit go.

**Recommendation:** build A + B now (repo-local, reproducible), and approve C + D as itemized diffs
so the behavior is durable and not just this-paper. Also: start Zotero once so `refresh-bib.sh`
closes the citation loop the audit flagged.

## First actions on approval
1. Fold the completeness-pass keys into `LIN_STYLE_CONTRACT.md` (A).
2. Build `lin_check.py` + `build.sh` and run it on the current draft to get the baseline score (B).
3. Present the C + D diffs for approval.
Only then (separately) apply the rewrite of the manuscript to the contract.
