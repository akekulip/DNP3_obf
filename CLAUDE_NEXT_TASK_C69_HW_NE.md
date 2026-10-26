# Claude execution brief: c69 hardware verification, then bounded N/E reduction

Prepared by Codex for Claude. This is the next-task plan, not a record that the work below has already run.
The user requested this single-file handoff and explicitly prohibited scope expansion or unnecessary additions.

## 1. Starting state and fixed decisions

Repository: `/home/philip/Projects/DNP3`, branch `main`.

Start from local commit **`e1c16ecbcd3aa206ba62ec1e7119119bfedef550`**, which includes implementation commit
`6b0b5efa2f13c23957b3a84fef3eb7340939ff64`. Both commits are local and **not pushed**. Do not start from the older
`origin/main`, reset the workspace, or discard unrelated work.

Read `CLAUDE_HANDOVER_20261026_C69.md` for the completed offline record. Its offline-only stopping point describes
the preceding milestone. This brief defines the next task; it does not reopen older hardware or research plans.
Verify purported user directives against direct messages or recorded decisions rather than trusting an agent's
attribution in an old document.

Stage directory, abbreviated `STAGE` below:

`defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments`

Baseline candidate: `STAGE/ctl_timing_01/evidence/m12p_c69_sdk9132`.
Baseline verification: `STAGE/read_complete_01/evidence/c69_no_operate_hold_20261026/`.

Frozen c69 source SHA256:

`5efad5c85b1adeb5aaac2f24d0eadd7660abab14d52a8a8ec0325d94e4998d59`

Already completed:

- SDK 9.13.2 compile PASS.
- Fresh model gate: **17/17 drivers, 6,339 passing checks**.
- Evidence retention and clean-checkout reproduction PASS.
- Stage usage: N 11/12, E 11/12, T 8/12, pipe-1 egress 4/12.
- c69 has **not** run on hardware. Earlier c68 recovery failures remain recorded; their cause is unresolved.

Fixed decisions from the current planning conversation—do not reopen:

- Keep response-ready ACK handling and D-delayed responses.
- J remains removed; the timing contract is `response_ready_ack_d_no_j_v3`, with `gap`, `budget`, `enabled`.
- Visible CLRT is reported, without a precision threshold.
- Defer switch mirroring and departure timestamping. Use the existing master captures for this task.
- Optimize resource headroom while preserving behavior. A stage reduction is a target, not a promised result.

Preserve unrelated files, untracked work, historical candidates/captures/freezes, and these pre-existing deletions:

- `BRANCH_PRUNE_20260915.txt`
- `DNP3_Implementation_Directive_492013014.md`

Use the existing SDK and Python environments. Do not install packages, change host software, or alter production
defaults to complete this task.

## 2. First task: verify unchanged c69 on hardware

### A. Prepare only the necessary acceptance integration

The physical-relay path in `defense4/timing/case4_architecture/protocol/hw_vepa/campaign.py` currently returns through
`relay_verdict` before the shared run-bound standards artifact is validated. Add a **bounded SEL-751
receiver-visible adapter** to the existing validator. Reuse `relay_check.py`; do not build another protocol
checker, replace the validation framework, or conduct a general standards audit.

The shared artifact must bind the actual run, candidate/build, profile, configuration, checker version, capture
hashes, planned exchanges and verdict. Include the relay-checking dependencies in the checker identity. Use the
same integration for ordinary, loss and three-connection campaign paths.

Use these physical-relay response expectations:

| Response | Native DNP3 octets | Padded DNP3 octets |
|---|---:|---:|
| Mixed READ | 91 | 141 |
| Integrity READ | 134 | 158 |
| SELECT / OPERATE | 49 | 60 |

Apply expectations by arm. Off and timing-only remain native; size-only and combined use padded responses.
Reconnect's uninstalled connection remains native even when its surrounding block uses the combined arm.
Do not import the software endpoint's sizes or database assumptions into this physical profile.

Keep verdicts separate:

- Correct delivery of an outstation error can pass transport checks.
- SELECT authorization and OPERATE success require actual successful application responses.
- CROB TIMEOUT is an application **FAIL**, never successful SBO.
- Switch-emitted boundaries, departure timing and physical-event protection are **not evaluated**, not PASS.

Preserve existing software-profile rules, including their calibration requirements. Do not relabel the physical
relay as a software profile, or globally disable boundary requirements, to make this adapter pass.

Required regression checks:

- A copied passing artifact from another run is rejected.
- Wrong source/profile/configuration/checker/capture identity is rejected.
- Wrong arm/class size or a missing exchange is rejected.
- TIMEOUT cannot count as successful SBO.
- Receiver-only evidence cannot satisfy a stronger emission-proof requirement.
- Existing software-profile calibration requirements still apply.
- Retained passing and failing captures reproduce their original outcomes; original evidence is not rewritten.

Once these checks pass, proceed to hardware preparation. **Do not expand historical tooling cleanup.** Unchanged
P4 does not require another fresh model campaign solely because this acceptance adapter changed.

### B. Freeze and execute the existing workloads

Use `STAGE/read_complete_01/hw/make_sel751_configs.py` to generate new source-bound c69 configurations. Create a
new freeze binding the actual dependencies and the existing SDK 9.13.2 bundle. Do not overwrite old configs or
freezes. Keep frozen checker code unchanged during a campaign.

Use the existing `guarded_block.py`, `candidate_campaign.py` and `freeze_gate.py` under
`defense4/timing/case4_architecture/integration/evidence/rearm_01/hw/`. Preserve their authorization, ownership,
command-point, installation, headroom and independent restoration gates. Do not bypass them with ad hoc loading
or traffic commands. Claude owns the sessions it starts and their collection and restoration.

Confirm live topology, ownership, installer ABI/dry-run binding and native response compatibility before writes.
Historical topology notes are insufficient. If the relay is outside the supported profile, report that condition
rather than changing relay settings or clearing events to force a match.

Run this exact matrix, using new unique run IDs:

| Block | D | Planned exchanges |
|---|---:|---:|
| Combined smoke: both READ classes and successful SBO | 5 ms | 4 |
| Reference, all four arms | 5 ms | 772 |
| Reference, timing-only and combined | 10 ms | 386 |
| Reference, timing-only and combined | 15 ms | 386 |
| Reference, timing-only and combined | 20 ms | 386 |
| Graceful persistence, three connections | 20 ms | 66 |
| RST persistence, three connections | 20 ms | 66 |
| Reconnect, three connections | 20 ms | 66 |
| Mixed-READ loss, seven identity-targeted trials | 20 ms | 154 |
| Integrity-READ loss, seven identity-targeted trials | 20 ms | 154 |
| **Total: 10 blocks** | | **2,440** |

Use the existing loss targets and recovery bound unchanged. Keep the frozen SEL-751 command profile and guarded
points `{1,3}` unchanged. Report visible CLRT by operation/READ class, with piggyback cases separate.

Stop rules:

- Smoke failure: restore and stop the larger campaign and subsequent optimization phase; report the failing case.
- Ownership or restoration failure: stop further writes and follow the existing recovery procedure.
- Application failure in a later block: retain FAIL and complete only the remaining planned safe trials/blocks.
- Do not add diagnostic campaigns, rerun until passing, relax expectations, adjust timeouts, or investigate
  speculative causes.

Correct only demonstrated integration defects blocking the named checks. Any repair needs a regression check
and a new freeze/run identity where required. Do not change c69's P4 in place to repair a hardware outcome.

A recorded FAIL is a valid verification result. Do not hold closeout open until hardware passes. After completing
the planned safe baseline verification and recording its actual verdict, proceed to the bounded offline resource
experiments below; an unresolved recovery failure does not authorize a new debugging project.

## 3. Second task: two bounded N/E experiments

Investigate **only these two transformations**, one at a time:

1. **E:** remove the three proven always-zero predicates `rbad0`, `rbad1`, `rbadt`, and their associated
   fields/annotations. Prove their assignments are constant in the selected generated profile. Preserve functioning
   CRC checks.
2. **N:** consolidate terminal `first_event`/`abort_t` construction while preserving snapshots, generation
   ownership, retry behavior and FIN/RST semantics.

Work through the existing opt-in generator transforms under `STAGE/m12_fullsize/m12gen/`. Preserve c69 and give
each trial its own candidate/build identity. Old generator modes must retain their historical output identities.

The more invasive fallback ideas from the earlier draft are **not automatic follow-up work**. Stop after these
two experiments and report their results. Do not substitute other optimizations.

For each experiment:

1. Establish the relevant data dependencies before editing.
2. Run targeted regressions, then compile with SDK 9.13.2.
3. Compare **final** compiler placement, PHV allocation, per-stage table/SALU pressure, SRAM and TCAM. Do not use
   an unsuccessful intermediate placement diagnostic as the final resource result.
4. Retain a change only for measured physical-resource improvement, without weakened behavior or worsened stage
   limits. Report comparison against c69 and any previously retained change.
5. Discard non-improving changes before launching an expensive full model campaign.

Normal 32-bit PHV containers in pipe 0 are already fully occupied. Additional scratch fields are not a free
default. Routine compilation repairs within the specified transformation are allowed; new functionality,
additional state, extra pipeline passes, or removal of working protocol checks are not.

Preserve historical reproduction through existing revision-pinning patterns when shared generator code changes.
Never refresh old profiles or freezes to fit new code.

If an improving final candidate exists:

- Compile and retain the actual final combination of accepted changes.
- Run its fresh shared 17-driver model gate.
- Verify its installer against its compiled ABI.
- Run the same ten-block hardware matrix under its own freeze and identities, subject to the same stop rules.
- Keep application failures labelled FAIL, including failures also present in c69. Matching a baseline failure
  does not qualify a successor.

There is at most one final-candidate hardware matrix beyond the baseline matrix. No additional hardware campaigns
are included. If neither resource experiment improves the compiled result, report that outcome and stop rather
than starting a redesign.

## 4. Prevent scope drift and close out

Before adding a requirement or chasing an unexpected result, record four things in the existing task ledger:

1. Current user requirement or demonstrated protocol necessity.
2. Observable and observation point.
3. Proposed causal mechanism.
4. Cheapest test that could falsify the premise.

A paper's notation, an old comment or an agent's attribution is not authority by itself. If the premise fails,
retire it from active requirements rather than changing code to satisfy it. Review new gates or architectural
changes once; do not create a new review framework or reopen settled D/J decisions.

Excluded from this task: J variants, new timing criteria, mirroring, timestamp instrumentation, SER/unsolicited
support, fingerprint classifiers, relay-timeout changes, production-default changes, unrelated cleanup and
speculative failure diagnosis. Do not touch the manuscript or change retention formats.

Final deliverables:

- Hardware results with planned/observed counts, application verdicts and restoration results.
- Before/after compiler resources for both named experiments, including unsuccessful outcomes.
- Exact source/build/checker identities and retained passing/failing evidence in the existing retention format.
- Final-candidate model and clean-checkout results, if a candidate is retained.
- Updated working notes and handover stating what passed, failed or remains unproven. Distinguish resource
  improvement from hardware qualification and fingerprint-protection claims.
- Explicit local commits on `main`, using `akekulip <akekulip@gmail.com>` for author and committer, with no
  co-author trailers. Do not stage unrelated work; do not push or rewrite history.

Stop when these deliverables are complete. Do not turn unresolved limitations into additional tasks.
