# c75: c72 plus the request retries only

**c75 is MODEL-QUALIFIED ONLY.** It has not run on the switch, Vision or the SEL-751. It is not canonical:
`p4/response_only.p4` is still c74 in this tree. Integration and hardware are plan Step 6.

- c75 source SHA-256: `5ca9168d366a1faf662ecaa53db224b6a814357f5bc37df88ec513cdb6edde49`
- c72 source SHA-256 (base): `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`
- c74 source SHA-256 (H1 + H2): `c7e37eff347f09c30af3a46f566cf41069df2d9c099e0227a102c16733116efd`

## The change

c75 is c74's H1 (the request retries) without c74's H2 (the four late-handshake-ACK `first_event` rows).
`derive_c75.py` is `derive_c74.py` without the H2 edit and without the `first_event` size change. It produces c75 from
`results/builds/c72/response_only.p4` byte for byte, and each edit asserts its exact match count:

    python3 results/builds/c75/derive_c75.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json

- Against c72, two lines change: 519 (`busy_t`, 22 to 28 rows) and 529 (`guard`, 54 to 57 rows). The rows are
  c74's exactly; `c72_to_c75_rows.json` lists them with their positions and equals c74's record for these two tables.
- Against c74, two lines differ: 404 and 405 (`first_event` size and entries), which are c72's. So c75 equals c74 with
  lines 404-405 taken from c72. The `busy_t` trailing comment keeps c74's text (`/* c74: READ/SELECT/OPERATE retry
  ... */`) so that line 519 is byte-identical to c74's.
- No action body, key, register, header, metadata field or control-flow line changes. Line numbers, and the bf-p4c
  table names derived from them, equal c72's.
- What H1 does, why SYN keeps `busy_drop`, and why the guard rows do not depend on the `first_event` rows:
  `results/builds/c74/README.md` ("H1"). A retried request is re-admitted by the same stage-0 rows as on first arrival;
  a late handshake ACK takes c72's path (default `NoAction`, event code 255, abort).

`tests/p4/test_c75_derivation.py` (7 tests, written first and seen failing with the c75 files absent) checks the
byte-exact derivation, the changed lines against c72 ([519, 529]) and against c74 ([404, 405], equal to c72's), the
absence of the four `forward_original` rows, the retry tables against c74's, that nothing outside const entries
changes, and the row record. Mutation runs on scratch copies (an H2 row added, the comment edited, a guard row removed,
a `first_event` size edit in the derivation, a row dropped from the record) each fail at least one test.

## Compile and pinned artifacts

Packaged and compiled once: `python3 scripts/profile.py results/builds/c75 --source <derived c75> --compile`, which
runs `scripts/build.py`'s compile with c72's command (`bf-p4c --target tofino --arch tna -g -o OUT SOURCE`, no
defines; p4c 9.13.2, SHA 1baf055; compiler SHA-256 `787631a6...`), then pins the artifacts. Exit 0, 93 s.

- Pinned artifact manifest: `supported_profile.json` (`candidate.artifact_sha256.compile_local`, the same block in
  `response_only.inputs.json`): `bfrt.json`, `manifest.json`, p0/p1 `context.json`, `response_only.bfa`,
  `tofino.bin`, `response_only.conf`, `response_only.p4pp`.
- `compile_local/manifest.json` and `compile_local/compiler_evidence.json` hash every compiler output and log;
  `compiler_evidence.tar.xz` retains the exact bytes. Every later model run uses these artifacts; nothing recompiles.

| artifact | SHA-256 |
|---|---|
| p0/tofino.bin | `3e11043af08a3e7de7e89956ec20d2b86d50199afdebc3d71a6d79c2adcb45b3` |
| p1/tofino.bin | `f52aaedd35c0c737de1b90f6914f3825dd19f87e4738e6fe09d9c8c1c7a12b99` |
| p0/context.json | `03221ae2b4790c567a9ad75743b417c910129886fc696b1e81dae499aa1d10db` |
| p1/context.json | `8a74333d702e107cb95fc568dbf4d460ae26ea74853c7ccb633488bdaa61f3da` |
| bfrt.json | `dcf9853796834df7c73b9071dae30f87bc0942868562d53e814107db99fad8b9` |

## Resources

`resource_comparison.json` (baseline c72): every delta is 0, and the stage target is met.

| | c72 | c75 |
|---|---|---|
| p0 ingress / egress stages | 10 / 10 | 10 / 10 |
| p1 ingress / egress stages | 8 / 4 | 8 / 4 |
| p0 SRAM / TCAM blocks | 158 / 96 | 158 / 96 |
| p0 VLIW instructions / Meter ALUs / gateways | 119 / 19 / 57 | 119 / 19 / 57 |
| p0 exact / ternary xbar bytes, hash bits, hash dist units | 436 / 363, 1,017, 22 | 436 / 363, 1,017, 22 |
| p0 PHV containers / bits used | 174 / 3,381 | 174 / 3,381 |
| p1 SRAM / TCAM / VLIW / hash bits | 36 / 36 / 44 / 142 | 36 / 36 / 44 / 142 |
| per-stage table IDs, SRAM, TCAM, gateways, VLIW, Meter ALUs | | identical |

- `phv_allocation_0.log` and both pipes' `table_summary.log` are byte-identical to c72's.
- p0 `response_only.bfa` differs from c72's only in the two table sizes, their const-entry listings and the run_id.
  p1 equals c74's apart from the run_id (and c74's p1 equals c72's apart from the run_id).
- `resource_review.json` (baseline c69) has the same deltas as c72's and c74's reviews.

## Model gate (17 drivers)

All 17 drivers ran once on the pinned c75 through `scripts/model/run_model.py` (attempt 01 each); every launch
record has exit code 0. `scripts/model/model_summary.py results/builds/c75 --write --enforce` gives
`model_gate_passed` with no blocked reasons (`model_summary_v3.json`).

**Observation overlay.** The runs need `scripts/model/action_observations.json` to bind the c75 source. Only
`source_sha256` was changed for the c75 runs (file SHA-256 `d7732fdd...`); all 61 action-body hashes verify unchanged,
since no action body differs from c72 or c74. The committed file still binds c74, the canonical source, so recomputing
the summary in this tree reports the c75 runs as blocked on that library binding until c75 is integrated (plan Step 6),
as with c73.

**Against c72.** `results/models/c75/gate_vs_c72.json` (comparator `results/models/c75/gate_compare_c75.py`, the c74
comparator with the build name changed and c74's runs added to the cross table): case names and verdicts are
identical to c72's latest runs for all 6,339 cases. The observed differences are the three classes c73 and c74
showed, in the same drivers: control_timing 23 T timestamps, 17 T re-wait counts and 17 old-epoch counts;
response_ready 23 T timestamps and 17 T re-wait counts; rearm 2 T timestamps. Pipe 1 of c75 equals c72's in
`response_only.bfa` apart from the run_id line, and the T cells (cell 1, cell 14) in control_timing are (24, 3) on c72,
(25, 2) on c72_diag_mirror, (26, 2) on c74 and (25, 2) on c75: run-to-run variation of one T binary.
`only_run_to_run_variation` is true; `only_stated_allowed_differences` is false for the old-epoch class, as for c73
and c74.

## 40-case connection-fix driver, c72 / c74 / c75

The unchanged driver (`scripts/model/model_connection_fix.py`, SHA-256 `5715abf9...`) ran on all three builds:
`results/models/c72_connection_fix/model_connection_fix_c72_03` (new, exit 1: the RED baseline),
`results/models/c74_connection_fix/model_connection_fix_c74_03` (retained, exit 0) and
`results/models/c75_connection_fix/model_connection_fix_c75_01` (exit 1, because the H2-family checks expect c74's
forwarding). The comparison is `results/models/c75_connection_fix/compare_c72_c74_c75.json` (comparator
`compare_connection_fix_3way.py`, source embedded; it imports c74's outcome digest).

| group | cases | result |
|---|---|---|
| as c74 (retries): H1, H1_sbo, collision, collision_causal, H1prime, exhaust, stale_retry, dup_during_retry, operate_retry_before_select_response | 17 | all pass on c75 with the c74 outcome; all fail on c72 |
| as c72 (late ACK): H2, H2r, stale_ack, residual_class_mismatch, residual_later_read | 10 | c75 outcome and verdict equal c72's: the late ACK, R1 and R2 are refused (`NoAction`, abort) |
| as c72 per the plan: reconnect | 2 | **not met**: c75 equals c74 (pass) |
| unchanged: dup_after_admit, rst_read_outstanding, fin_after_exchange, rst_at_start, fin_at_start, operate_without_select, operate_mismatched_crob, syn_busy | 11 | identical outcome on all three builds, pass on all three |

- **reconnect.** Connection B's final ACK and first READ are sent back to back, which is the H1 path: B's READ is
  dropped by `busy_drop` on c72 and retried then admitted on c74 and c75. The H2 part of the case, connection A's old
  handshake ACK, is refused on all three builds. This was written into the comparator's docstring before the c75 run.
- **Normalisation.** The comparator ignores `busy_retry_rst_next` entries (a retry pass that found the cell still
  held), whose number follows model timing: c74's own attempts 02 and 03 differ in it (stale_retry_mixed 9 and 0).
  Raw digests differ only there (collision_causal_integrity, dup_during_retry_*, stale_retry_mixed: c75 10 against
  c74_03's 0). The first comparator version only collapsed repeats; it was changed after the preliminary comparison
  against c72_02 and before the final one.
- c72_03 and c72_02 have identical normalised outcomes and verdicts on all 40 cases.

## Master-ACK behaviour (c72, c74, c75)

The rule, its operational definitions, predictions and decision gate were registered first in
`results/analysis/ack_behaviour/DESIGN.json` (six dated amendments, five before any run, one after the smoke run).
The rule is `scripts/model/ack_rule.py`; the driver `scripts/model/model_ack_behaviour.py` (runner
`run_ack_behaviour.py`) runs 11 case families for both READ classes with T on and off: 44 cases per build. The tests
`tests/model/test_ack_behaviour.py` (14) were seen failing before the module existed; 12 mutations of the rule module
each fail at least one test.

Runs (driver SHA-256 `332b4f7f...`, all exit 0): `results/models/c72_ack_behaviour/model_ack_behaviour_c72_01`,
`results/models/c74_ack_behaviour/model_ack_behaviour_c74_01`, `results/models/c75_ack_behaviour/model_ack_behaviour_c75_02`.
Table: `results/analysis/ack_behaviour/summary.json` (`summarize_ack_behaviour.py`, source embedded). Every probe's
disposition matched the row-based prediction (0 misses). N state (owner, client, server, epoch, application state,
retry epoch, work phase) was unchanged by every probe on every build, forwarded or not.

| case (4 variants each) | c72 | c74 | c75 |
|---|---|---|---|
| late handshake ACK, wire order | not reached | not reached | not reached |
| late handshake ACK, reverse order | suppressed, obsolete: meets by suppressing | forwarded: meets | as c72 |
| R1, ACK of response 1 behind READ 2 | suppressed, obsolete: meets by suppressing | forwarded: meets | as c72 |
| R2 offset (not a conforming master) | suppressed: mixed meets by suppressing, integrity violates | forwarded: meets | as c72 |
| window increase, READ outstanding | suppressed, new window: **violates** | **violates** | **violates** |
| window increase at idle (control) | forwarded, window 4608 reaches the relay: meets | meets | meets |
| zero window then reopen, READ outstanding | both suppressed: **violates** | **violates** | **violates** |
| keepalive 0 and 1 octet at idle | both suppressed: **violates** | **violates** | **violates** |
| keepalive 0 and 1 octet, READ outstanding | both suppressed: **violates** | **violates** | **violates** |
| duplicate ACK at idle (control) | both copies forwarded: meets | meets | meets |
| ACK of a delivered response (control) | forwarded, ACK mapped to the native end: meets | meets | meets |

**End-to-end consequence, observed.** In every reached case on every build the current response reached the master
at the class image size (141 mixed, 158 integrity), with T counts (1, 1, 0, 0) when T was on; the next transaction
(the other READ class) was admitted once and delivered at its image size; the FIN close completed. A suppressed probe
(`first_event` default `NoAction`, then the abort laps) consumed one generation, the same as a forwarded one; a 1-octet
keepalive is not parsed into a packet kind and is dropped before the stage-0 claim (no generation consumed). Decision
gate: no valid window update or keepalive broke a later transaction, a response or T on c75 or c72, so the gate did
not stop the work and no rows were added.

What the violations mean, and what the model cannot show (inferred, not observed):
- While a READ is outstanding (owner 0xe) N has no kind-3 row for differences (0, 0) or a client difference of -1, on
  any build. A window update, a zero-window advertisement, the reopening update and keepalives are dropped there. The
  relay never sees them. The scripted model relay ignores windows, so delivery cannot fail in the model. A real relay
  that is told nothing of a closed window may send into it; the master then drops the data, and recovery rests on the
  relay's retransmission (RTO about 3 s on the SEL-751) and on the next forwarded ACK at idle.
- Keepalives are dropped in every state, so a master that keeps an idle connection alive with TCP keepalives gets no
  reply; after its probe limit its TCP aborts the connection. Polling traffic resets that timer, so a polling master
  is not affected. Whether the supported master uses TCP keepalives during idle periods was not checked.
- c74's forwarded late ACK, R1 ACK and R2 ACK draw the relay's RFC 9293 reply. With T off the reply reached the master
  once after the late ACK and after R2, and not at all after R1; with T on, sent ahead of the relay's ACK and response,
  the master received exactly one ACK and the response, with T counts (1, 1, 0, 0). The reply and the ACK were
  byte-identical in the model; on hardware the TSval may differ (open item H-1).

**Not tested.** The wire-order overtake (a fresh READ claiming before a retrying handshake ACK) was not reached in 4
attempts per case on any build, with either construction: the retrying ACK always claimed first. Its claim key equals
the reverse-order case's, which is tested. Also untested: window or keepalive probes while a SELECT or OPERATE is
outstanding (owners 9 and 0xc have a (0, 0) row and would forward; a -1 client difference has none), relay-side
keepalives, SACK and other options, and any real-TCP reaction to a suppressed window update.

## Attempts and environment, disclosed

- `model_ack_behaviour_c75_01` is the smoke run (5 cases, `ACK_CASES` filter, earlier driver `b0ea0998...`, exit 1
  because its wire-order case had no progress and the earlier version counted that as a failure). It showed the
  wire-order construction never reaching its state, which led to amendment 6.
- The first c74 ACK launch stopped at the precondition "model requires a verified compile" before writing evidence:
  the worktree had c74's ignored `compile_local/out` but not `compile_local/source`. The source snapshot (and those of
  c72_diag_mirror, c74_diag_mirror and c69_baseline, for the tests) was restored from each build's retained
  `compiler_evidence.tar.xz` by `scripts/build.py restore_evidence`, which only creates missing files and checks every
  hash; nothing was recompiled.
- The status file of the gate wrapper read `$?` after `$(date)` and so always printed exit 0; the exit codes quoted
  here come from each run's `launch_command.json`.

## Tests (this worktree)

- `tests/p4` 42 passed (7 new in `test_c75_derivation.py`), `tests/model` 151 passed (14 new), `tests/build` 53
  passed, `tests/analysis` (research Python) 145 passed and 2 skipped.
- `python3 -m pytest -q -p no:cacheprovider tests --ignore=tests/analysis`: 733 passed, 2 failed. The 2 are
  `tests/hardware/test_diag_runtime.py::test_unit_commands_are_unchanged_without_diag_mirror[Campaign|CandidateCampaign]`,
  whose goldens hash absolute paths; with the worktree path replaced by `/home/philip/Projects/DNP3` both hashes equal
  their goldens (the same two as in c74's worktree). Before the source snapshots were restored, 19 more
  diagnostic-build tests failed on the missing snapshots.
- `python3 -m pyflakes scripts tests` and the new result scripts: clean.
