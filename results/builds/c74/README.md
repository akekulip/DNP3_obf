# c74: c72 plus the connection-start loss correction

**c74 is MODEL-QUALIFIED ONLY.** It has not run on the switch, Vision or the SEL-751. Every hardware result in this
repository was taken with c72 (source SHA-256 `97812585d64146dd5de65b8fd42d19c1471e2c5d80da85dacaae68b4083d887e`),
and none of it transfers to c74. The focused hardware confirmation is plan Step 4 and needs its own registration.

- c74 source SHA-256: `c7e37eff347f09c30af3a46f566cf41069df2d9c099e0227a102c16733116efd`
- **Canonical in this worktree** (integration below): `p4/response_only.p4` is c74; c72 stays the reference at tag
  `c72-validation-final`. The diagnostic build is `results/builds/c74_diag_mirror`.
- Built in a detached worktree of `8bac68cb4`, then moved to `e4a876dfa` (main after the strict-cycle commit) for the
  integration; none of the commits in between touch c74's files or the 58 files its gate runs bind.

## The change

c74 differs from c72 only in the const entries of three N tables. `derive_c74.py` produces it from
`results/builds/c72/response_only.p4` byte for byte, and each edit asserts its exact match count:

    python3 results/builds/c74/derive_c74.py results/builds/c72/response_only.p4 OUT.p4 MANIFEST.json

No action body, key, register, header, metadata field or control-flow line changes. All edits stay inside existing
lines, so line numbers, and the bf-p4c table names derived from them, equal c72's. Four lines change: 404 and 405
(`first_event` size and entries), 519 (`busy_t`) and 529 (`guard`). `c72_to_c74_rows.json` lists every added and
removed row with its position. `tests/p4/test_c74_derivation.py` checks all of this, and a mutation run showed that each
of its row checks fails when its row is broken.

**H1: requests retry instead of `busy_drop`.** N has one work cell (`n_ExpectedWorkRecord`, `Register(1)`). In c72 a
READ, SELECT or OPERATE whose stage-0 claim found the cell held went to `busy_drop`.
- `busy_t` (22 to 28 rows): the rows `(5|7|9,_,_):busy_drop()` become, for each of kinds 5, 7 and 9,
  `(k,2w0,_):busy_retry_ack()`, `(k,2w1,6w1):busy_exhausted()` and `(k,2w1,_):busy_retry_rst_next()`. These are the
  rows the master pure ACK (kind 3) already has. Row 1, `(_,2w2,_):retry_stale()`, still comes first.
- `guard` (54 to 57 rows): `go_retry(8w9)`, `go_retry(8w5)` and `go_retry(8w7)` for the retry pass (`m.retry == 1`).
  Each copies its kind's `go_new` row column for column, with the retry column 2w1, and sits before the catch-all
  `go_stale` rows.

The master-direction retry action is used, not `busy_retry` (kinds 6 and 11), because a master frame reaches stage 0
from the ACK-normalization loop. Its normalized epoch and wire ACK must survive the retry: `busy_retry_ack` carries them
in the origin header, and on the claiming pass `snapshot_t` selects `snapshot_lap_retry` (direction 1), which restores
the lap epoch from them. A retry pass runs the whole stage 0 again (owner, client, server, application compare,
`first_event`), so a retried request is admitted only by the same rows that admit it on first arrival. A failed claim
writes no connection state; it consumes one generation, as the existing retries do. The budget is `n_RETRY_BUDGET` (32)
and the staleness rule is the existing `retry_epoch` check.

**SYN (kind 1) is deliberately left on `busy_drop`**, together with SYN-ACK (2) and replay (12). A SYN creates the
epoch that the retry staleness rule compares against. `retry_epoch` is noted at the SYN's publish and cleared on close,
while the epoch register keeps the old epoch until the next SYN. A busy-retried SYN would therefore carry the previous
epoch: after a close it fails `retry_epoch_check` and is dropped as stale, and before the first connection its
envelope epoch is 0, which the port-68 parser does not decode as a retry. A SYN retry needs a different staleness rule,
which is a logic change, not a row. The master's own SYN retransmission recovers a dropped SYN, and the plan's
observable counts the handshake ACK and the first request. The `syn_busy` regression shows the SYN still dropped on c74.

**H2: the late handshake ACK is forwarded as an old ACK.** `first_event` (401 to 405 rows) gains four
`forward_original()` rows:

    kind 3, matched 0, owner state 0xd or 0xe, client_diff exactly 0xffffffe7 (-25) or 0xffffffe5 (-27),
    server_diff exactly 0, direction 1 (master to relay), TCP flags exactly 0x10, same_syn 0

`forward_original` is the existing old-ACK forward (event code 8): the laps verify that epoch and owner are unchanged,
nothing writes owner, client or server, and `terminal_ack` sends the frame on through E like any other forwarded old
ACK. The ACK has already passed ACK normalization before stage 0, so sequence mapping is not bypassed. Every other
kind-3 miss keeps the default `NoAction`, event code 255 and the abort path. No other kind-3 row matches owner 0xd or
0xe, so the new rows neither shadow nor are shadowed.

What each key establishes, and what it cannot (corrected after the independent review):
- same incarnation: proven only by the ISNs, through the exact 32-bit `client_diff` and `server_diff` matches against
  this connection's client and server registers. The lap epoch check cannot reject an old-connection ACK: on the
  ACK-normalization pass E stamps the slot's current epoch (`epoch_normalize` returns `v & 0x7fffffff`,
  `response_only.p4` line 895), so an old ACK carries the current epoch. In the `reconnect` regression the old
  incarnation's ACK is refused before N's stage 0 only because of the chosen ISNs: E's `classify_rev` drops it when it
  falls below the current image end. With other ISNs it reaches N's stage 0, where no `first_event` row matches its
  differences, so N refuses it;
- sequence = client ISN+1: `client_diff` of exactly minus the admitted READ length means the ACK's sequence is the
  first octet of the READ that moved the client register;
- ACK = server ISN+1: `server_diff` 0 means the ACK equals the relay's current native sequence, which is the server
  ISN+1 while no response has been seen;
- first request admitted: owner 0xe means a READ was published. The owner 0xd rows are effectively unreachable: the
  READ holds the work cell from its claim to its phase-3 return, so its publish (0xe) precedes the ACK's claim unless
  the READ aborts after claiming;
- direction 1, flags 0x10 and `same_syn` 0 are not independent legitimacy keys: the parser gives packet kind 3 only to
  a pure ACK (flags exactly 0x10), the guard turns a relay-direction pure ACK into kind 10, and an ACK at the SYN's own
  sequence (`same_syn` 1) would differ from the client register by -26 or -28, not -25 or -27.

**Two residuals, measured.** N keeps no record of whether a response has been seen, and at the ACK's claim it does not
know which READ length was admitted. The rows therefore also accept:
- **R1, an old ACK behind a later READ.** The master's pure ACK of response k, delayed behind READ k+1 of length 25 or
  27, has the same differences. `residual_later_read` measures it: accepted on c74, refused on c72.
- **R2, a sequence inside or just before the READ.** A pure ACK at the client register minus the other READ length:
  sequence ISN-1 while a mixed READ is outstanding, ISN+3 while an integrity READ is. `residual_class_mismatch`
  measures both: accepted on c74. The master's TCP never sends these sequences.

Both are forwarded unchanged and change no N state. Excluding them needs new state or a new `first_event` key (for
example "no response yet", or the admitted READ's class), and that breaks the no-new-PHV/SALU/stage constraint.
**Philip's decision:** keep these rows, or narrow them with such state in a later candidate.

## Resources (SDK 9.13.2, c72's exact command, no defines)

`resource_comparison.json` (baseline c72): every delta is 0.

| | c72 | c74 |
|---|---|---|
| p0 ingress / egress stages | 10 / 10 | 10 / 10 |
| p1 ingress / egress stages | 8 / 4 | 8 / 4 |
| p0 SRAM / TCAM blocks | 158 / 96 | 158 / 96 |
| p0 VLIW instructions / Meter ALUs / gateways | 119 / 19 / 57 | 119 / 19 / 57 |
| p0 exact / ternary xbar bytes, hash bits | 436 / 363, 1,017 | 436 / 363, 1,017 |
| PHV, per-stage table IDs, SRAM, TCAM, gateways, VLIW | | identical |

- The command is `bf-p4c --target tofino --arch tna -g -o OUT SOURCE`, the same as c72's manifest except for paths;
  the compiler is p4c 9.13.2 (SHA 1baf055).
- `phv_allocation_0.log` and `table_summary.log` are byte-identical to c72's.
- In p0 `response_only.bfa`, outside the const-entry listings, the only differences are the three table sizes and the
  compiler run_id. p1 differs from c72 only in the run_id line.

## Model gate

**All 17 drivers ran on c74 through `scripts/model/run_model.py`, attempt 01 each, every one exit 0.** The case names
and verdicts are identical to c72's latest runs (`results/builds/c72/model_summary_v3.json` `latest_by_driver`) for
all 6,339 cases. The comparison is `results/models/c74/gate_vs_c72.json`, with its comparator source embedded and the
script kept as `results/models/c74/gate_compare_c74.py` (the c73 comparator with the build name changed).

| driver | c74 cases | c72 run | observed differences |
|---|---|---|---|
| abandon, abort, contention, dup, fin_busy, packets, policy, policy_boundary, relay_sbo, repeat, select_lifecycle, smoke, smoke_sizeoff, two_read_robust | 12, 84, 457, 308, 193, 763, 281, 206, 1069, 526, 146, 30, 30, 181 | latest c72 run each | none |
| control_timing | 417 | model_control_timing_c72_01 | 23 T timestamps, 17 T re-wait counts, 17 old-epoch drop counts |
| response_ready | 838 | model_response_ready_c72_01 | 23 T timestamps, 17 T re-wait counts |
| rearm | 798 | model_rearm_c72_01 | 2 T timestamps |

These are the same three classes c73 showed. Pipe 1 (T and x) of c74 equals c72's byte for byte apart from the run_id,
so they are run-to-run variation of one T binary: the T re-wait and old-epoch cells (cell 1, cell 14) are (24, 3) on
c72, (25, 2) on c72_diag_mirror and (26, 2) on c74 in control_timing. `only_run_to_run_variation` is true;
`only_stated_allowed_differences` is false for the old-epoch class, exactly as for c73.

**Observation overlay.** The gate needs `scripts/model/action_observations.json` to bind c74's source. Only
`source_sha256` changes. No action body changed, so all 61 recorded action-body hashes verify unchanged against c74
(`telemetry_from_log.verified_observations`). With that overlay, `scripts/model/model_summary.py results/builds/c74
--write --enforce` gives `model_gate_passed` with no blocked reasons (`model_summary_v3.json`, 17 runs).

**The gate does not exercise the new rows.** In the c74 gate logs `busy_t` was hit only for kinds 4, 6, 10 and 11
(independent review), so no gate driver sent a request into a held cell and none took a late-ACK `forward_original`.
Identical verdicts show that the rows disturb nothing else. The H1/H2 evidence is the labelled 40-case driver only.

**No gate expectation changed.** No gate driver asserts a request `busy_drop` as correct. The only gate references to
busy drops are in `model_control_timing.py`: the race section accepts a `busy_drop_retransmitted` path for the relay
response, not for a request. That section did not run in this milestone (`race_path` is absent on both c72 and c74).

## Regressions (labelled scenarios, outside the gate)

Two drivers, both run through the `run_model` launch path and preconditions:

**1. The unchanged c72 reproduction driver on c74** (`scripts/model/run_connection_start.py`,
`results/models/c74_connection_start/model_connection_start_c74_01`, exit 0). Its verdict rule reads "state reached and
no loss" as falsified.
- H1, H2 and H2r, both READ lengths: state reached, the frame reached port 64, verdict `falsified_for_this_path`. The
  READ took `busy_retry_ack` where c72 took `busy_drop`; the late ACK hit `forward_original` where c72 missed.
- H1′: still lost, now by `busy_exhausted`. This driver holds the forced cell for its whole capture, so the READ uses
  up its 32 retries; the new driver releases the cell after the first retry. The retransmitted READ was then delivered.
- collision: still lost, now by `count_refused`, not `busy_drop`. The c72 construction sends the OPERATE with an ACK
  for image octets that the master has not received. Normalized, that ACK is 11 octets (image 60 minus native 49)
  ahead of the relay's sequence, so `first_event` refuses it after the retry. This is a property of the non-causal
  stimulus. The causal variant below delivers the OPERATE.

**2. The c74 regression driver** `scripts/model/model_connection_fix.py` (runner `run_connection_fix.py`, unit tests
`tests/model/test_connection_fix.py`). 40 cases: 17 scenarios for both READ lengths and 6 single cases, each on a fresh
connection of the same 4-tuple. Each case checks the state it needs before it reads the outcome. Forced-register cases
are labelled. `as_before` cases carry only build-independent checks and are compared with the same driver on c72.

Runs: `results/models/c74_connection_fix/model_connection_fix_c74_02` (40/40 pass, 599 report rows, exit 0) and
the same driver on c72, `results/models/c72_connection_fix/model_connection_fix_c72_02` (the RED baseline, exit 1). The
case-by-case comparison is `results/models/c74_connection_fix/compare_c72_c74.json` (comparator
`compare_connection_fix.py`, source embedded): no problems; 25 `fix` cases fail on c72 and pass on c74; all 11
`as_before` cases pass on both builds with an identical outcome digest; the 4 `residual` cases are refused on c72 and
accepted on c74.

| scenario | kind | c72 | c74 |
|---|---|---|---|
| H1: final ACK + READ back to back | genuine | READ `busy_drop` | READ busy on arrival, 2 failed retry passes, admitted once; port 64 gets ACK then READ; T ingress once; then a timed SELECT, OPERATE, other READ and FIN close |
| H2: READ at owner 4, then the final ACK | genuine | ACK `NoAction`, abort | ACK `forward_original`, `terminal_ack` once, no abort; port 64 gets READ then ACK; owner/client/server/epoch unchanged by the ACK |
| H2r: READ + final ACK back to back | genuine | ACK busy-retried, then abort | ACK busy-retried, then `forward_original`; timed cycle follows |
| collision (c72 construction, non-causal ACK) | genuine | OPERATE `busy_drop` | OPERATE retried, then `count_refused`: its normalized ACK is 11 octets ahead of the relay sequence; not on port 64 |
| collision_causal: relay retransmits the SELECT response + master OPERATE | genuine | OPERATE `busy_drop` | the retransmission (`first_response_dup`) holds the cell; OPERATE retried, admitted once by `first_operate`, on port 64 once |
| H1′: cell forced busy, released after the first retry | forced | READ `busy_drop` | READ admitted on its first retry pass; timed cycle follows |
| H1_sbo: mapped ACK + SELECT, then mapped ACK + OPERATE, back to back | genuine | SELECT `busy_drop` | each command 2 failed retry passes, admitted once, T ingress once, on port 64 once after its ACK; timed responses |
| exhaust: cell held past the budget | forced | `busy_drop` | exactly `busy_retry_ack`, 31 `busy_retry_rst_next`, `busy_exhausted`; never admitted; no later pass; the master retransmission is then delivered once |
| stale_retry: `retry_epoch` changed under a retrying READ | forced | `busy_drop` | `busy_retry_ack` then `retry_stale` once; never admitted; register restored; retransmission delivered |
| dup_during_retry: TCP retransmission while the first copy retries | forced | both copies dropped | 1 `first_read_request` + 1 `first_request_dup`, no loss action; 2 READ copies on port 64 and 2 T ingress passes, one per master copy, as dup_after_admit forwards a retransmission |
| stale_ack: wrong seq (+1), wrong ack (+1, -1), then the exact late ACK and its duplicate | genuine | all five refused | the three wrong ACKs refused (`NoAction`, abort); the exact late ACK and its duplicate forwarded once each; N state unchanged throughout |
| reconnect: A closed by FIN, B on the same 4-tuple with ACK + READ back to back, then A's handshake ACK | genuine | B's READ `busy_drop` | B's READ delivered; A's ACK refused before N's stage-0 claim on both builds |
| operate_retry_before_select_response: OPERATE retried at owner 9 | forced | OPERATE `busy_drop` | retried, then `count_refused`; not on port 64 (no SELECT state bypassed) |
| dup_after_admit, rst_read_outstanding, fin_after_exchange, rst_at_start, fin_at_start, operate_without_select, operate_mismatched_crob, syn_busy | as_before | pass | pass, identical digest |
| residual_class_mismatch (seq ISN-1 / ISN+3), residual_later_read (R1) | residual | refused | forwarded once (`forward_original`) |

Padding and timing on the fixed paths: every timed case (H1, H2r, H1′, H1_sbo) checks that the master receives the
response-ready wire ACK then the complete response, with T's outcome counts ACK_COMMIT +1, RESP_RELEASE +1 and no
fallback, as `model_relay_sbo` checks. The padded images are 141 octets (mixed READ), 158 (integrity READ) and 60
(SELECT and OPERATE) on every path that delivered them. The model does not measure D; the gate's `response_ready` and
`control_timing` drivers cover the timing contract and pass unchanged.

SELECT/OPERATE association: no internal retry produced a second copy of a command on port 64 (each command once in
H1_sbo and collision_causal); an OPERATE without a SELECT, an OPERATE whose CROB differs (on-time 200 to 201 ms), and
an OPERATE retried while the SELECT is outstanding are all refused. In `operate_mismatched_crob` the matching
OPERATE is then admitted once.

Attempt 03 on c74 (`model_connection_fix_c74_03`, 599/599, exit 0) ran the final driver (SHA-256 `5715abf9...`),
which differs from attempt 02's by one removed unused local variable (pyflakes). Against c72 attempt 02 it has no
problems either (`compare_c72_02_c74_03.json`). Its case digests equal attempt 02's except the number of failed retry
passes in three cases (collision_causal_integrity, dup_during_retry_mixed, stale_retry_mixed), which follows model
timing.

Earlier attempts, disclosed: `model_connection_fix_c74_01` (40/40 pass) and `model_connection_fix_c72_01` ran an
earlier driver version whose cleanup RST used the first connection's ACK in the `reconnect` case. On c72 that RST was
refused, connection B stayed open, and every later SYN was refused, so c72_01's last 27 cases are a cascade, not
evidence. The driver now tracks the master's wire ACK per case; both builds were rerun as attempt 02.

## Tests (after the integration, in this worktree)

The gitignored compile outputs of c72_diag_mirror and c69_baseline were copied in from main, as the tests read them.
- `python3 -m pytest tests --ignore=tests/analysis`: 646 passed, 2 failed. The 2 are
  `tests/hardware/test_diag_runtime.py::test_unit_commands_are_unchanged_without_diag_mirror[Campaign|CandidateCampaign]`,
  whose goldens hash absolute paths. With the worktree path replaced by `/home/philip/Projects/DNP3`, both hashes equal
  their goldens, so they pass in the main checkout. They failed the same way before any c74 change.
- `python3 -m pytest tests/build`: 53 passed. `$RESEARCH_PYTHON -m pytest tests/analysis`: 138 passed, 2 skipped.
- `python3 -m pyflakes scripts tests`: clean.

Tests changed for the canonical switch (retargeted where the intent is "the current candidate"; retained c72 evidence
tests unchanged):
- `tests/model/test_abandon_timed.py`: `test_c72_gate_summary_has_no_blocked_abandon_closure` became
  `test_canonical_gate_summary_has_no_blocked_abandon_closure` (the canonical build's live gate summary).
- `tests/build/test_diag_mirror.py`: the diagnostic build under test is the canonical candidate's
  (`BASE_diag_mirror`); `test_canonical_source_is_still_c72` became `test_canonical_source_is_the_current_candidate`;
  added the retained c72_diag_mirror identity check and generator-refusal cases.
- `tests/hardware/test_freeze_gate_diagnostic.py`: admission, evidence, binding and canonical-freeze tests run on the
  canonical candidate and its diagnostic build (configs rebound from the retained c72 config); added the historical
  c72_diag_mirror check (evidence valid, build refused), the name-form refusal and the `gate_other_baseline` defect.
- `tests/hardware/test_e4b_definition.py`, `test_diag_definitions.py`, `test_strict_cycle_definition.py`: the c72
  diagnostic definitions are prepared and frozen in the reinstated c72-canonical context
  (`tests/hardware/historical_c72.py`); the c74 definitions are listed as later additions.
- `tests/p4/test_stage_target.py` needed no change: it reads the canonical source and the stage target.
- New: `tests/hardware/test_c74_confirmation_definition.py` (24), `tests/p4/test_c74_derivation.py` (6),
  `tests/model/test_connection_fix.py` (8).

## What this does not show

- **No hardware.** Nothing here says the hardware losses are fixed. The model shows that the two reproduced paths no
  longer drop; it does not show that these paths caused every observed hardware loss.
- **Model timing only.** The retry counts (one busy pass on arrival and two failed retry passes behind one ACK hold,
  0.33 to 0.34 s of model wall-clock to exhaust 32 retries) are not switch latency. How long 32 recirculations last on
  silicon, against how long a real holder keeps the cell, was not measured. A cell held past the budget still ends in
  `busy_exhausted`, and the master's TCP retransmission then recovers, as `exhaust` shows.
- **Retry reordering (review M-2).** A retried frame is one copy looping through port 68, and a later fresh frame can
  overtake it. With one outstanding DNP3 request only two pairs can invert: (pure ACK, request) and (request, the
  master's own TCP retransmission). The H2/H2r stimuli send the READ before the ACK, which is not the master's wire
  order; the hardware route to H2 (a busy-retried handshake ACK overtaken by the fresh READ) was not built causally in
  the model.
- **Open (review H-1): the relay's reply to the forwarded late ACK.** c74 forwards the late handshake ACK (sequence =
  master ISN+1) after the READ. Under RFC 9293 the relay should answer that out-of-window segment with an ACK. That reply
  is a kind-10 relay ACK at owner 0xe with differences (0, 0); it hits `first_event` `first_read_ack` and goes to T as an
  extra response-ready ACK. This is untested: the duplicate-relay-ACK cases cover only SELECT/OPERATE
  (`model_control_timing.py` lines 311-312), and the model relay never answers old ACKs. The confirmation design
  (`results/analysis/c74_confirmation/DESIGN.json`) registers an observable and a falsifier for it.
- **The H2 residuals** (R1, R2 above) are accepted.
- **SYN** busy drops are unchanged by design.
- **Hardware.** Focused guarded confirmation is registered (`results/analysis/c74_confirmation/DESIGN.json`) and waits
  for the merge to main and a fresh freeze.

## Integration (c74 canonical)

Tracked changes that make c74 the canonical candidate:
- `p4/response_only.p4` = `results/builds/c74/response_only.p4`; `results/analysis/stage_cut/current_build.json`
  names c74 (status `model_gate_passed`); `scripts/model/action_observations.json` binds c74's source (no action body
  changed). `results/builds/c74/resource_review.json` (baseline c69) has the same deltas as c72's review.
- The diagnostic tooling no longer assumes c72. `scripts/build_diag_mirror.py` derives `BASE_diag_mirror` only when
  `results/builds/BASE/response_only.p4` is the canonical source. `freeze_gate.py` admits a diagnostic build only under
  that name form and with its canonical base, and binds its evidence as `gate_vs_BASE_01.json` (checking
  `baseline == BASE`). `diag_gate_compare.py` and `diag_mirror_checks.py` derive the base from the build name. The
  identity schema string `c72-diag-mirror-v1` is kept as a format name, so c72_diag_mirror's retained evidence reads
  unchanged.
- c72_diag_mirror is historical: its retained evidence still passes `diagnostic_evidence_problems`, but the build is no
  longer admitted (its canonical base is no longer `p4/response_only.p4`). Tests of the c72 diagnostic definitions
  reinstate the c72-canonical context (`tests/hardware/historical_c72.py`: the c72 source and the generator at
  `c78363905`, sha256-checked against the identity) rather than being weakened.
- Confirmation definitions (matrix.py and `lab_strict_cycle_c74.json`, `lab_diag_c74.json`, `lab_recovery_c74.json`,
  `lab_e4b_c74.json`): `strict_cycle_c74_d20/_d5`, `diag_e2_combined_c74`, `diag_e2_off_c74`, `recovery_c74_r1/r2/r3`
  and `e4b_select_only_c74`, each its c72 counterpart except the block id and the master ports (60300-60415, disjoint
  from every other definition).

Freeze admission, run with the real `freeze_gate.py write` and `check` on prepared configs: c74 is admitted with
`model_gate_passed` and its strict-cycle block qualifies; c74_diag_mirror is admitted as diagnostic and its E2 block
never qualifies. Both checks report 0 changed and 0 missing.
