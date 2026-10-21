# Response to the independent review of d531918e2

Review package: `reviews/d531918e2/` (SHA256SUMS verified). Its `reproduce_findings.py`, run against a clean worktree
at d531918e2, reproduced all four counterexamples (SBO boundary d=62 withheld on b08 vs stale on m11_09; the 27-octet
integrity request not parsed; the old readout accepting empty captures and a capture missing its final response), and
the model gate recomputed there as blocked (exit 1).

| # | finding | status | evidence |
|---|---|---|---|
| 1 | b08 implements only range READ 49→141 + SBO 37→61 | **open — in progress**. b08 is labelled "range 49→141 + SBO 37→61 only". Pass-through shapes (analog 141, class0/integrity 247) and their requests are being added to the generator; the segmented 377→401 case is under design study | this file, STATUS.md |
| 2 | SBO committed-image boundary too permissive | **fixed at source/compiler tier**: per-committed-image boundary (`make_m12.py --c3 cimg`), m12p_c04 compiles in 12 stages, classify_rev 15 entries (was 284). Contract tests on the source interpreter, incl. m11_09 parity for the 61 image and both transition directions; b08's ladder finding pinned as a test. Compiled-model and hardware runs on the final image: pending | commit 2c5f81211; `m12_fullsize/tests/test_mapper_contract.py` |
| 3 | hardware readout can pass incomplete evidence | **fixed**: rewritten fail-closed readout; 11 regressions incl. both counterexamples and a positive padded control; reproduce.sh propagates failure | commit 5be733630 |
| 4 | pushed model gate recomputes as blocked | **fixed**: the missing reset evidence existed on disk; every file was checked against the hashes its run pinned at launch and committed unchanged (the ~300 MB bound logs as byte-exact xz with a hash-verified restore); the checker binding made checkout-location independent (hash binding unchanged). Fresh worktree: `model_gate_passed` | commits 3e47e9b06, 7dae3ed39 |
| 5 | policy selection read an untracked path | **fixed**: tracked inputs, incomplete set refused; policy.json unchanged on rerun; coverage tests 25 pass on a fresh worktree | commit 3e47e9b06 |
| 6 | C5 test passed with zero frames | **resolved, narrowly**: (a) E's mapping exercised directly — a pure ACK at the committed image's native start maps to its wire start (images 61, 141, virtual 61); (b) the integrated-path disposition traced in the retained b08 model log: the delayed pure ACK (byte-identical to the outstation's earlier ACK of the request) enters N, loops through N's work passes, fails the sequence check (no `seq_ok`) and is dropped by `n_Ingress.terminal_abort`; it never reaches E. The connection is unaffected (the following native-end control ACK is forwarded at the wire end and the READ retires). Recovery if such an ACK were the only copy: the master's TCP retransmission of the request, re-acknowledged at the current sequence — **inference, not measured**. The old probe's "zero frames" is therefore a correct observation of a drop, not evidence of correct mapping | commit 49e927f98; model log `ctl_timing_01/evidence/model_policy_boundary_m12p_b08_02/model_20261021_043410.log` lines 467098–469990 |

## Corrections to earlier records

- The model gate was reported as passed while its reset evidence was not in the pushed tree (unverifiable from the
  push until 3e47e9b06).
- COMPLETION_RECORD stated that other READ shapes "pass through at target size untouched": N does not recognise them;
  they were unsupported in b08.
- b08 adds a 7-stage pipe-1 egress control (34 → 41 occupied stages summed across controls).
- The earlier C5 note "refused upstream" was not traced; it is now (finding 6).

## Timing discrepancy (raised by the review as unattributed)

Attributed to the environment, not the build: the unchanged m11_09 build, run on 2026-10-21 in the same frozen
wrapper (campaign rc01_hw_b08_20261021_03), fails the same precision gate (READ p99 absolute CLRT error 3551 µs; 63 µs
on 18 Oct). Details and the open environment issue are in STATUS.md.
