> # ⚠️ HISTORICAL CHECKPOINT — SUPERSEDED
> **Do not use as the current Phase 03A status.** This file captured an in-progress state
> (commit `04f02fe`, capture unfinished, crc-split labeled OTHER) that no longer holds: wire
> capture, the delay sweep, the 1 ms refinement, the socket-option factorial, and the crc-split
> `ack_mode`/`response_delivery` decomposition are all complete.
> **Current authority:** `reports/phases/phase_03/phase_03_ack_separation.md` (report) +
> `phase_status.json` (machine status). Phase 03A is CONDITIONAL PASS; human gate 0/13;
> `next_phase_allowed = false`. Kept only for history.

---

# Phase 03A — Resume Checkpoint (2026-07-16) [HISTORICAL]

State saved so Phase 03A is resumable. Branch `research/ack-timing-phased`. Tooling committed
at **`04f02fe`** (clean tree at checkpoint time).

## Phased-plan status (acj_delay2.md)

- **Phase 00** (repo audit) — done; closeout commit `22baf96`/`c69e07e`, CONDITIONAL PASS.
- **Phase 01** (real-device trace characterization) — CONDITIONAL PASS; closeout `eed83ce`/`ed75767`.
  Open: genuine HUMAN packet validation (worksheet prepared, verdicts blank — an AI can't do it).
- **Phase 02** (combined-response timing normalization) — CONDITIONAL PASS; corrected closeout
  chain `c1bf4f6 → a7f1ae7 → 233bcef → 3306bbaa → 62b7e97 → c5bb597 → c87aa88 → 8b4a95d → bacc850`.
  Experiment run `20260716T123500Z_...` (dirty_tree=false). Open: **wire PCAP + ACK-mode-after**.
- **Phase 03A** (wire capture + ACK-separation) — **IN PROGRESS** (this checkpoint). Restricted
  scope: NO ACK synthesis, NO independent ACK delay, Phase 02 scheduler untouched.

## Capture is ENABLED (this is the key unblock)

`philip` was added to the `wireshark` group. The current shell's group cache may be stale
(`groups` may omit wireshark), so **run all capture under `sg wireshark -c '...'`** — a group
switch, **NOT sudo** (the user said: do not use sudo for experiment execution). Verify:

```bash
sg wireshark -c 'groups; dumpcap -D'      # should list lo; NOT permission-denied
```

## In-flight run

- **Matrix capture running:** `runs/20260716T134719Z_phase_03a_wire_matrix/` (manifest commit
  `04f02fe`, dirty_tree=false, dumpcap 4.4.9). If it finished, `pcaps/` has 7 config pcaps and
  `manifest.json` has exit_status 0; if interrupted, just re-run the matrix (runs/ is git-ignored
  / regenerable).

## Resume commands (from a clean committed state)

```bash
cd dnp3_split_harness
# 1. matrix (7 configs, 25 reps x 5 groups = 125 txns/config):
sg wireshark -c 'python3 phase03_capture.py --mode matrix --reps 25'
python3 phase03_analyze.py --run-dir <run> --pcap-dir <run>/pcaps
# 2. controlled app-write delay sweep (0..100 ms via fixed timing; refine transition at 1 ms):
sg wireshark -c 'python3 phase03_capture.py --mode sweep --reps 20'
python3 phase03_analyze.py --run-dir <run> --pcap-dir <run>/pcaps
```

## Findings so far (from the reps=2 smoke — confirm at reps=25)

- The **first request of each TCP connection** gets a separate pure ACK — a **post-handshake
  quickack artifact present even in native mode**, NOT a timing effect. The analyzer flags it and
  reports the timing-relevant separation over **non-first requests**.
- **fixed25 / bounded20-30 holds (<40 ms) stay COMBINED** for non-first requests — holding below
  the ~40 ms delayed-ACK timer does NOT induce separation. Expect the **sweep to show separation
  appear around ~40 ms** (delayed-ACK timeout) — measure it, do not assume.
- **crc-split** chunked responses (multiple writes with chunk-delay) classify as OTHER/ambiguous
  (~12 B first chunk, req_to_resp ~190 ms) — a chunk-delivery reconstruction nuance to document.

## Remaining Phase 03A work

1. Finish/redo the matrix at reps=25; `phase03_analyze` it (COMBINED/SEPARATE/OTHER + Wilson95;
   overall AND non-first separation fraction).
2. Run + analyze the delay sweep; if a transition appears, refine at 1 ms with repeated trials;
   estimate P(SEPARATE | app-write delay) with CIs.
3. **Manual packet validation** (frame numbers + reviewer verdict): native combined, fixed25,
   bounded20-30, first separate-ACK observation, transition-region, retransmission/ambiguous.
   `validation/phase03_human_packet_validation.csv`.
4. Figures + metadata sidecars: `ack_mode_by_config`, `separation_probability_by_delay`,
   `request_to_ack_cdf`, `ack_to_response_cdf`, `request_to_response_cdf`.
5. Reports: `reports/phases/phase_03/phase_03_ack_separation.md` (rewrite from BLOCKED →
   measured), `phase_status.json`; and `reports/phases/phase_02/phase_02_wire_validation_addendum.md`
   — state whether Phase 02 moves CONDITIONAL PASS → PASS.
6. Tables: `phase03_ack_transactions.csv`, `phase03_ack_summary.csv`, `phase03_delay_sweep.csv`.

## Hard constraints

- Label ALL findings: **"Measured on the gambit loopback interface, Linux kernel
  5.15.0-139-generic, in the tested socket and application configuration."** Do NOT generalize to
  other kernels, Vision/Hulk, OpenDNP3 generally, SEL/AB1400/ION devices, or physical Ethernet.
- Do NOT begin independent ACK-delay manipulation. `next_phase_allowed = false`. Stop after wire
  characterization for human review.
- No sudo for experiment execution; capture only via `sg wireshark`.
- `git commit --amend` is blocked by the fable5 guard — use forward commits; for self-referential
  commit SHAs, commit-then-fill-in-a-second-commit.
