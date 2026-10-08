# Case4 continuation checkpoint — 2026-10-07 (size pattern updated 2026-10-08, same day, twice)

**Read first, in order:**
1. [`integration/INTEGRATION_CONTRACT.md`](integration/INTEGRATION_CONTRACT.md) — the decision record
   for the whole timing+size integration effort.
2. [`integration/size/SELECTED_PATTERN.md`](integration/size/SELECTED_PATTERN.md) — **the active
   pattern is Option B as of 2026-10-08**: a single uniform 58-byte TCP-payload pad for READ,
   SELECT, and OPERATE responses, no splitting (MI = 0 exactly, the cleanest measured leakage of any
   option scored). Option A (converge on a 49-byte pre-carve payload via a request-side qualifier
   `0x28`→`0x17` rewrite) was selected earlier the same day and then **failed real-master
   endpoint-compliance validation** — the real OpenDNP3 master correctly rejects the rewritten echo —
   so it is dead, not just superseded; see the document's own "UPDATE 2026-10-08" section for the
   full story. This supersedes the `35→55`/`57→[28,29]` separate-header plan named below in
   "Remaining core work" item 2 a second time, in a different direction (padding, not a cut-to-49
   carve).
3. [`integration/read/TIMING_QUEUE_MIGRATION_STATUS.md`](integration/read/TIMING_QUEUE_MIGRATION_STATUS.md)
   — T's queue-resident timing role (`read_queue_timing.p4`): all 7 invariants pass, 18/18, at the
   source-level interpreter. The real `bf-p4c` compile (both local SDK 9.13.1 and the switch's
   installed 9.13.2, compile-only) hits a reproducible internal compiler crash in PHV allocation
   (table placement itself succeeds at 8 of 12 stages) that four independent, substantive attempts
   did not resolve — read the document before attempting a fifth; its own recommendation is to
   bisect by register count or escalate, not to keep varying the P4 source the same way again.

**Separately, read [`integration/core/M_RECIRCULATION_VERDICT.md`](integration/core/M_RECIRCULATION_VERDICT.md).**
M's extended ACK/window mapper does not fit in 12 ingress stages. Eight compiler-verified attempts
(m13 through m23, `LEDGER.md`) narrowed this to a genuine four-register hardware placement limit;
the most promising fix (a second ingress pass via recirculation) was implemented in full and refuted
by the compiler itself, not just argued. The two remaining options (move the registers to egress, or
redesign M from scratch around this limit) are each a real project, not a quick follow-up, and the
verdict document asks Philip to choose before more engineering time goes into either. Everything
below this point continues to describe work that does NOT depend on that decision.

Continue directly from [PLAN.md](PLAN.md#execution-checklist--2026-10-07).
Core transport is the active step: ACK/window normalization, SELECT response,
then OPERATE padding/carving and replay. Full Case4 remains incomplete.

SDK constraint: use the switch's existing version; no updates. Read-only
inspection confirms `p4c9.13.2 (SHA:1baf055)` at
`/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c` on `decps@10.10.54.81`.
`installed_sdk_build.py` compiles in private temporary directories without chip
activation or software changes. Older local9.13.1 results remain development
evidence, not installed-version qualification.

## Accepted first SELECT milestone — existing switch SDK9.13.2

Normal100, zero0 and wrapped0xfffffff0 each pass6/6 in the isolated SDK9.13.2
software model on the switch CPU. External handshake and SELECT35 produce one
exact109-byte Ethernet frame with55-byte padded payload. Independent IPv4/TCP
checksums and every DNP3 CRC pass. Genuine packet-driven completion leaves
N9/M4/E4; no ownership/cache/register proof presets. This covers first SELECT only.
[Current verification](integration/core/ordinary/evidence/installed_select_verification_01/verification.json)
binds saved raw logs, driver, source copies, configuration and compiler artifacts.

| Device0 role | Exact source SHA prefix | Installed-SDK build | Ingress / egress | Critical path |
| --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `ca695e97ea67` | `installed_nf_05` |12 /4 |11 |
| M preparation/activation, pipe1 | `c8820a1f7f14` | `installed_m_baseline_01` |10 /0 |9 |
| E cache + typed bridge, pipe3 | `dae2efee6c5e` | `installed_e_01` |1 /10 |7 |

Each pipe has its own12 ingress stages: N has none spare, baseline M has two,
and E's ingress bridge has11. E's cache consumes10 egress stages. Pipe2 remains
reserved for T. Recirculation reuses stages and adds passes; it does not add stage
capacity. These counts do not establish extended mapper fit.
Fresh SDK model traces confirm19 SELECT ingress visits and18 private TX records
totaling2346 Ethernet bytes, excluding4-byte model trailers; the internal24-byte
completion header and unmeasured physical costs remain separate. Fresh source
suite71/71 and static-scanner3/3 pass. No SDK updates or chip activation.

## Historical first SELECT milestone — local SDK9.13.1

External SYN/SYNACK/ACK then SELECT35 produce one exact109-byte Ethernet frame
with55-byte padded payload in the isolated local model. Genuine completion leaves
N Work9, M4 and E4; no ownership/cache/register proof presets were configured.
Normal100, zero0 and wrapped0xfffffff0 coordinates each pass6/6 checks:
[verification and packet identities](integration/core/ordinary/evidence/split_verification_01/verification.json).
Lead freshly reran52 source/config tests successfully. IP/TCP checksums and DNP3
CRCs independently pass for all three retained endpoint frames.

| Same modeled device0 role | Exact source SHA prefix | Build | Ingress / egress | Critical path |
| --- | --- | --- | --- | --- |
| N + final emitter, pipe0 | `610d129d7446` | `nf_02` |12 /4 |11 |
| M preparation/activation, pipe1 | `c8820a1f7f14` | `m3_01` |10 /0 |9 |
| E cache + typed bridge, pipe3 | `dae2efee6c5e` | `e3_02` |1 /10 |7 |

All three programs loaded together using
[the source-bound split configuration](integration/core/ordinary/evidence/model_config_split_01/bindings.json).
Pipe2 is reserved for the T join. N still uses all12 ingress stages; M now has two
spare stages. NF's normal32 PHV is62/64, SALUs4/4 at7–9 and table IDs16/16
at1 and10. M peaks at2/4 SALUs and5/16 table IDs. E image SALUs occupy4/4
at4–6; retain the full image instead of narrowing identity checks for capacity. Failed coupled N/E14-stage compositions are retained, not fit claims.
The split retains all14 image banks, full owner/epoch/generation checks, actual
publication/completion returns and a full32 current-generation emission receipt.
Component sources and rendering are in [ordinary/README.md](integration/core/ordinary/README.md).

Observed first-SELECT model accounting:19 ingress visits,6 service egress visits,
18 private TX records totaling2346 Ethernet bytes excluding model trailers,
plus an internal24-byte completion header. This is functional model accounting;
TM/fabric and physical wire service are not measured. Successful runs omit the
model's `--int-port-loop` flag; front ports remain cold-added with loopback NONE.
Failed front-loop attempts and the SYN-only controlled comparison are preserved.

## Installed-SDK transport checkpoint

The switch's existing9.13.2 compiler now builds the extended N/F source
`ca695e97…b950c` in `installed_nf_05`:12 ingress/4 egress, critical11.
Source/snapshot/compiler/artifact checks pass. This reduces the failed15-stage
extension to12 by fusing dependent writers and mutually exclusive result tables,
then moving private-admission refusal before Work/state access. Full identity,
FIN quarantine and malformed-return checks remain. N still has no spare stage.
The exact E cache also builds in `installed_e_01`:1 ingress/10 egress, critical7.
All compiler pipeline contexts, including `p0`, pass the corrected static-entry
capacity scanner; its3 CLI regression tests pass after2 witnessed failures.
The first-SELECT-only model result above now covers this exact N, baseline M
and E on9.13.2. It does not qualify reverse normalization or the full transport.

Fresh source regression passes71/71, including19 focused transport methods and
168 independent ACK/window pairs. The readonly M path snapshots actual generation
and owner plus actual full32 boundary/position in a20-byte typed record, then
independently rereads full generation/epoch/owner/phase and BOTH coordinates in a
second visit before external release. The source-only paired-coordinate forgery
witness rejects even when boundary-position remains35; removing the two reread
comparisons makes its retained negative canary fail. M10/M11 failed bank placement.
M12 (`deceea36…94cd`, next14) still fails PHV allocation with36 unallocated slices;
it has no fit/model claim. Preserve failed logs and freeze each replacement.
The baseline10-stage M in the first-SELECT table has no ACK/window mapper.
Latest source next15 (`081b4122…fea25`) moves both full32 coordinate comparisons
inside readonly scalar actions and requires both genuine grants. Reviewer approves
source only; fresh71/71 tests pass. Installed M13 resolves the PHV failure but
still fails table placement with no more placeable tables. Inspect that dependency
before another change; unused M egress arithmetic is a possible bounded alternative,
not an implemented or accepted layout.

2026-10-07 continuation: both diagnosed stage-fit fixes (role-dispatch flattening, then
register co-location hoist of the read-only `inspect_reservation`/`context_check` halves) are
now implemented in the real generator (`transport_candidate_next17/m3.p4`, sha
`6788aa92…93a6`), not a scratch copy, and still do not fit. Fresh regression across every suite
this session has used (`ordinary` 71/71, root `tests` 33/33, `connection/binding` 84/84,
`controller` 17/17, `core/harness` 42/42, `core/m` 33/33, `read` 103/103) stays green. Local
9.13.1 compile (`evidence/stage_fit_m17_01`) improves the dependency-graph critical path 9 -> 8
but still FAILS table placement; the compiler's own placement log now names the exact
remaining constraint ("dependency between inspect_reservation_t_0 and activation_reservation_t_0
requiring more than one stage") -- `Ingress.reservation`'s single-stage pinning is not resolved
by hoisting only the role==1 read, because `activation_reservation_t` (role==2's
`retire_reservation`) and `reserve_t` (role==0, deep in the native path) still touch the same
register far later. A parallel, now-explicit conflict exists on `Ingress.ledger_position`
(`mapping_position_t` vs `activate_position_t`) and a further one on `Ingress.ledger_tag`
(`activate_geometry_t` vs `activate_ledger_t`). `ledger_position`'s write side has no read-only
half to extract, unlike `reservation`'s. See `LEDGER.md`'s 2026-10-07 "Both diagnosed fixes
implemented" entry for the full compiler quotes and unplaced-table list. No mapper fit, model,
SDK update, hardware action or push.

2026-10-07 continuation 2: merged `inspect_reservation_t`/`activation_reservation_t` into one
table (`transport_candidate_next18/m3.p4`, sha `fccac9016d…905a4`), keyed on
`(role,enabled,profile)` so `Ingress.reservation` has exactly one apply() site instead of two --
this removes m17's named wall (`inspect_reservation_t`/`activation_reservation_t` no longer
conflict; confirmed 0 occurrences in the placement log). Needed hoisting
`reference_differences_t`/`activation_identity_t` to the same early call site (pure header math,
no new dependency); `qualify_context_t`/`claim_once_t`/`activate_geometry_t`/`activate_position_t`/
`activate_ledger_t`/`dirty_return_t`/`terminal_result_t` are unchanged from m17. Fresh regression
(same 7 suites as m17's entry) stays green. Compile
(`evidence/stage_fit_m18_01`, local 9.13.1, exit 2, FAILS): critical path **10** (worse than m17's
8 -- `activation_reservation_t` now carries a real dependency it didn't have before). The sole
repeated, final "requiring more than one stage" conflict across every retry log is now
`dependency between activate_geometry_t_0 and activate_ledger_t_0` -- the task's named
`Ingress.ledger_tag` conflict. `Ingress.ledger_position` does not appear as an active blocker in
this attempt. A broader variant that also hoisted `claim_once_t`/`activate_geometry_t`/
`activate_position_t`/`activate_ledger_t`/`dirty_return_t`/`terminal_result_t` the same way was
tried, tests passed, but compiled to critical path **14** with a NEW conflict against `construct_t`
(role==0's native admission chain, out of scope) -- reverted, not in `transport.py`. Resolving
`ledger_position`/`ledger_tag` properly needs hoisting `claim_once_t`'s own MUTATION
(`activation_receipt`) ahead of its validation gate, which this task's gating-preservation
constraint rules out without a larger restructuring of role==0's admission chain (already deferred
above); not attempted further. See `LEDGER.md`'s 2026-10-07 "Applied the same merge technique to
the m17 wall itself" entry for the full compiler quotes, unplaced-table list and the reverted
variant's evidence. No mapper fit, model, SDK update, hardware action or push.

Source-counted ACK mapping uses N5+M2 ingress visits and408 private Ethernet bytes;
response57 uses the same7 visits and750 bytes. Endpoint54/111 bytes are separate.
These counts remain unmeasured until the exact installed-SDK model runs.
Source parser consumption is bounded by153 bytes across roles; the20-byte snapshot
with111-byte response consumes147 including intrinsic/port metadata. No compiled
parse-depth claim. Next: obtain extended M fit, load that exact9.13.2 N/M/E split,
compare external
normal/zero/wrap ACK/window and uncarved57 response frames, then continue OPERATE.

## Remaining core work, in execution order

1. ACK/window inverse before N association, including inside-insertion clamps,
   both edges, zero-window and full32 wrap; completed SELECT owner18 and its57-byte
   matching response. Avoid the older N response's second20-byte subtraction.
2. **SUPERSEDED 2026-10-08 by `integration/size/SELECTED_PATTERN.md`**: this item originally read
   "OPERATE 35→55, matching 57-byte response carved into exactly ordered 28/29, both insertions, every
   subsequent packet mapped, sender-driven cached-tail repair." The selected pattern instead targets a
   shared 49-byte pre-carve payload split `[28,21]` for both SELECT and OPERATE, via a request-side
   qualifier-rewrite codec (`0x28`→`0x17`, count 1→2) rather than the separate-header insertion this item
   described — the old 55/57 separate-header codec (`case4_padding.expand_control()`) is kept as a
   working reference and as the documented fallback (Option B, 58-byte uniform pad) if the qualifier-
   rewrite codec fails endpoint-compliance validation, but it is not the current target.
3. Actual READ/T timing join and current-association OPERATE deadlines; finite
   fallback, independent heartbeat and genuine credits.
4. Post-M cancellation, duplicate/stale emission model witnesses, loss/lifecycle,
   fragments/resegmentation, reset/FIN/reconnect/exhaustion and complete retirement.
5. Complete exact9.13.2 offline build/model/schema/controller inventory and rollback
   package. The qualification registry stays empty until the complete target passes.

Full transport, timing and hardware gates in [PLAN.md](PLAN.md) remain unchecked.
The current18 model checks qualify first SELECT only; the71 source tests do not
qualify the mapper on the SDK model. Earlier
590,976-case results include no-leak-only branches and are not that many full
state/packet equivalences. Original N/T prerequisite model evidence is retained
with its own exact sources; it does not qualify the new full target.

## Continuation boundaries

Use one continuing implementer and one bounded reviewer. Lead integrates and
commits on `main` as `akekulip <akekulip@gmail.com>` for author AND committer,
without contributor trailers. No push. Preserve unrelated `CLAUDE.md`, frozen
sources/evidence and the paper. Local isolated model/source work is authorized;
live loading and physical port/TM/PRE/mirror/pktgen changes or traffic retain their
separate gates. Physical OPERATE is attended-only. No hardware action occurred.

## Historical continuation notes

The following notes retain earlier identities and limits. Their old words
"current" and "not yet" describe those checkpoints; the accepted split milestone
above and [PLAN.md](PLAN.md) define the present execution state.

The following continuation details retain pre-review historical identities;
the current facts above and the linked PLAN supersede their role and completion claims.

**Resume from the [core functionality and testing plan](PLAN.md).** This checkpoint replaces the
2026-10-06 one in full: historical step1/2 prerequisite results below do not close
the current connection/timing acceptance gates; step3 remains unfinished.
The complete target is still absent (no 9.13.2 build, no hardware run); everything here is
source-fragment, whole-program-harness or local-Tofino-model evidence, never hardware-measured.

Historical base: `388f78a33`; current base is stated above, branch `main`, unpushed. Work directly on `main`; preserve frozen sources,
evidence, the paper and unrelated local changes. Lead alone commits, `akekulip <akekulip@gmail.com>`
as author AND committer, no contributor trailers. This checkpoint does not authorize a push or any
hardware action (physical OPERATE is attended-only per repo `CLAUDE.md`).

## What changed since 2026-10-06

- **A restricted N source packet harness exists**: `integration/core/harness/` runs the parser,
  ingress control and deparser of a generated TNA source, with recirculation through the private
  return port, up to 8 passes. It is source-level (a restricted interpreter), not the target; its
  README says so. It does not implement the composed M/T/egress/TM path. Tests: `integration/core/harness/tests` (`python3 -m unittest discover -s
  integration/core/harness/tests -p 'test_*.py'`, 42 tests).
- **The local Tofino-1 model runs** inside `unshare -Urn` with an LD_PRELOAD pagemap shim (DMA
  physical addresses are otherwise unavailable to an unprivileged process). Setup, the shim, and a
  reusable launcher/driver are in `integration/core/launch_model.sh`, `integration/core/
  model_driver.py`, `integration/evidence/model_02/RESULT.md`. This is **functional** evidence
  only: the model's clock is not wall time, and it is not hardware. It has independently verified:
  validator, forward/reverse mapping, the selected-wire composition, cross-pipe forwarding
  (4-pipe probe, `model_28`), the e2e mirror, and the packet generator.
- **Native connection binding (`integration/connection/binding/`)** was restructured (a merged
  guard table, banks keyed directly, folded event rows) to fit stage limits. The
  historical590,976-case grid reports zero failures, but includes guard-miss
  branches that check only private-header refusal; it is not590,976 full state/
  packet equivalences. READ is outside that grid and has separate invariant and
  direct tests. The frozen oracle is `tests/oracle_35bf9aa3_native_binding.p4`.
  The baseline also carries the step-1 retry/ACK forwarding fix,
  READ kinds 9 (request), 10 (ACK), 11 (response) with a `tev` handoff, the step-3 OPERATE-response
  exchange with per-exchange ACK offset, busy-WorkRecord drop-and-count, whole-segment-resend
  counting, and fixes for three real bugs the model/review found: an epoch-0 endless-recirculation
  wedge, a guard-miss private-envelope leak, and a flow-miss WorkRecord pin. **Previous baseline: `native_18`,
  source sha `642dfe54…`, 12 of 12 ingress stages, no spare stage.**
  **Correction (found by the 2026-10-07 acceptance audit): the 68/71-step model agreement
  (`model_24`–`model_27`) ran against `native_11` (sha `c2352572…`), one commit before the
  flow-miss fix and two before the port renumbering. `native_18` itself carries only a bare
  `primitive_compiled` manifest — it has NOT been loaded on the model or diffed against the
  harness. Do not read "model-verified" as applying to the committed `native_18` source until
  that rerun exists.**
- **A separate READ timing role** `integration/read/read_timing.p4` (copy-evolved from the
  `held_timing_expected_probe.p4`; the probe itself is untouched) implements D_A-parametrized
  ADMIT/hold/release/fallback/policy-off/reset, checked against an independent schedule oracle
  `integration/read/join_reference.py`. **Previous baseline: `read_timing_05`, 12 of 12 ingress stages.**
  **Correction (same audit): the one passing held-path model run (`read_timing_model_05`) was
  launched against `read_timing_04` (sha `01b93f01…`), not `read_timing_05` (sha `d2b35563…`,
  the port-renumbered current source, different hash). `read_timing_05` has not been run on the
  model either.**
- **A step-3 design note** `integration/core/STEP3_DESIGN.md` places roles across Tofino-1's four
  pipes: N (connection) pipe 0 ingress, M (padding/mapping/carve, not yet built) pipe 1, T (timing)
  pipe 2, pipe 3 reserved for step 4. The model's cross-pipe probe confirms the placement is
  physically possible; it does not confirm the pipe-0/pipe-1/pipe-2 port numbers until gate
  G-PORTS runs on the switch (`integration/evidence/model_28/PORTS_PROPOSAL.md` has the current
  device-port table; `ports.p4` and `read_timing.p4`/`native_binding.p4` already use it).
- **A resource canary for role M** (`integration/core/m/m_skeleton.p4`) compiles the mapping,
  geometry and ledger core at exactly 12 of 12 ingress stages in pipe 1, with sequence translation
  checked against the independent transport oracle (`framework/size/case4_transport.py`). The full
  M (padding construct, descriptor build, carve decision, exact-byte replay) is **not yet built** —
  see "Open / stopped" below.

## Open / stopped

- **Role M beyond the canary is unfinished (plan step3).** Task1 only normalizes
  parser/apply receiving ports196/197. The historical canary occupies12 stages;
  current admission/replay repairs fail15 stages and require protected staged integration;
  actual35→55 production, descriptor/carve decisions and exact replay must be
  integrated and measured before any complete-target claim. Earlier planning
  interruptions remain historical evidence, not a qualification result.
- **The supported-tuple catch-all** (an unparsed-but-matched IP length forwarded natively) needs
  M's mapping-only path and is a documented gap in N until M exists.
- **Foreign-epoch client/server stores and terminal leakage are repaired in Task1.**
  The exact current build stays within12 stages; see the current evidence index above.
- **Step 4 (loss/lifecycle, fragment assembly)** is not started; the old assembly layouts
  (`integration/assembly_passes/REPORT.md`) still fail PHV and were not revisited this session.
- **Step 5 (qualification: 9.13.2 build, schema/inventory, hardware package)** is not started.
  `candidate_bringup.py`'s SDE path (`SETUP_DIR`) and controller registry are from the earlier
  framework track and have not been re-verified against the Case 4 sources.
- **No hardware action of any kind occurred.** Every verified claim above is source-fragment,
  whole-program-harness, or local-model evidence; the model's own clock is explicitly not timing
  evidence (`read_timing_model_07`, `model_02/RESULT.md`).

## Reproduce

From this directory:
```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s integration/connection/binding/tests -p 'test_*.py'
python3 -m unittest discover -s integration/controller/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/harness/tests -p 'test_*.py'
python3 -m unittest discover -s integration/core/m/tests -p 'test_*.py'
python3 -m unittest discover -s integration/read/tests -p 'test_*.py'
```
Compile a changed candidate to a NEW evidence directory with `build.py`; never overwrite retained
evidence. `build.verify_evidence` checks source/compiler/schema identity. `python3 integration/
core/scan_static_entries.py <out>` catches a table whose const entries exceed its declared size
(the defect that stopped `native_04`/retained `handshake_14` loading on the model). The local
model is driven via `integration/core/launch_model.sh` (see `model_17/RESULT.md` and
`model_28/RESULT.md` for usage and what each prior run proved); it needs `unshare -Urn` and the
pagemap shim built once (`integration/evidence/model_02/shim/`).

See `LEDGER.md` for the full dated history of this session's findings and fixes.
