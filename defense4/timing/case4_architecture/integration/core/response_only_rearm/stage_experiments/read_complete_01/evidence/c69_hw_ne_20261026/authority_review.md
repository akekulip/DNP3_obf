# Directive and evidence review — 2026-10-26 (c69 hardware verification and N/E experiments)

## Specification

`CLAUDE_NEXT_TASK_C69_HW_NE.md` (repository root) was written by Codex as the task brief. It is an agent-written
specification; its own statements about user intent are not authority by themselves.

## Direct decisions in this thread

- 2026-10-26, question asked directly in this Claude session: "Do you authorize this hardware scope as the
  brief writes it?" (c69 baseline 10-block matrix plus at most one final-candidate matrix, live SEL-751
  SELECT/OPERATE on guarded points {1,3}, existing guarded/freeze/restoration gates, brief stop rules).
  Answer: **"Yes, as written"**.
- The user subsequently stated that they verified this answer in the native Claude session and that the
  authorization claim is genuine, and required five plan corrections (single shared validation entry point with
  capture rehashing; boundary wording "Preserve software-profile boundary requirements. For the explicit SEL-751
  receiver-visible scope, report emission proof as NOT EVALUATED."; do not reuse the c69 resource comparator
  unchanged; no exact-IIN 80 00 gate, use established test selection with baseline-failure distinction; manifest
  generator path is RC/hw/make_hw_manifest.py). The corrected plan was approved.

## Superseded statements

- Root CLAUDE.md and CLAUDE_HANDOVER_20261026_C69.md state that c69 permits no hardware. That described the
  completed offline milestone; the direct decision above defines the present task.

## Not authorized by this task

J variants, new timing criteria, mirroring/timestamping, SER/unsolicited support, classifiers, relay-timeout or
production-default changes, relay setting changes or event clearing to force a profile match, unrelated cleanup,
speculative diagnosis, manuscript edits, additional hardware campaigns, push or history rewrite.

## Decision after the smoke FAIL (2026-10-26, direct answer in this session)

Asked whether to repair the switch gate (a demonstrated integration defect: it requires counters for the OPERATE
generator and the hb_return loop port that c69 removed by design) and rerun the smoke, apply the stop rule strictly,
or stop hardware and do only the offline experiments. Answer: **"Repair gate, rerun smoke (Recommended)"** — a no-J
switch-gate rule derived from the c69 contract/model (not from the failed run), regression tests, freeze v3_02, the
smoke rerun under a new run ID, the matrix continuing only if it passes; the first smoke FAIL stays recorded.
