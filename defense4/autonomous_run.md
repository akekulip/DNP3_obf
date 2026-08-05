Run the fixed-(K) Defense 4 emulator experiment autonomously overnight. Continue until the implementation, full campaign, independent review, documentation, commit, and push are complete. Do not stop after producing a plan or after a smoke test.

## Authority and baseline

Work from `main` at:

`272220a2bfb8ac97b3ab1edc9fef3899ec368803`

Before changing anything:

1. Run `git fetch` and verify local and remote state.
2. Read:

   * `CLAUDE.md`
   * `RESUME_STATE.md`
   * `defense4/DEFENSE4_CHECKPOINT_2026-08-04.md`, especially §5–§9
   * `dnp3_multicrob_harness/README.md`
   * The existing master, outstation, sweep, analyzer, and control-backend tests.
3. Preserve any unrelated user changes. Never reset, overwrite, or discard them.

This phase is limited to the fixed-(K) emulator size experiment. Do not implement the unified P4 timing core yet.

## Hard safety boundaries

The experiment must remain entirely on the OpenDNP3 emulator.

* Do not touch, load, configure, restart, or query the Tofino switch.
* Do not contact the physical SEL-751.
* Do not send SELECT, OPERATE, or DIRECT_OPERATE to the physical relay.
* Do not change relay settings, SELOGIC, outputs, alarms, networking, or switch configuration.
* Verify that the destination is Hulk running `run_outstation.py --control-test`.
* If the expected emulator readiness evidence is absent, do not send a control command.
* Add a fail-closed target guard to the new runner so it cannot be redirected accidentally to the physical relay.
* The Tofino must never fabricate or modify CROBs.

## Use specialist agents

Use an agent team or parallel subagents where available. Assign at least these independent roles:

1. An OpenDNP3 and harness specialist to inspect the master/outstation lifecycle and persistent-session implementation.
2. A DNP3 protocol and PCAP specialist to design the wire-level oracle and TCP checks.
3. A statistics and traffic-analysis specialist to preregister the timing-side-channel analysis.
4. An adversarial reviewer to inspect the final code, raw evidence, claims, and safety boundaries.

Keep reviewer agents read-only. The main agent owns integration and repository edits. Do not allow agents to make conflicting edits to the same files.

If external research is necessary, use installed OpenDNP3 source, official OpenDNP3 documentation, IEEE 1815 material already available, or other primary sources. Record the source and version used. Do not substitute assumptions or blog posts for source inspection.

## Critical distinction

The existing `run_multicrob_sweep.py` is not the required experiment. It varies the total number of all-real CROBs and treats every valid point as actuating.

Do not rerun (N=4,8,16) and call that fixed-(K).

The required experiment varies the number of real CROBs (R) while keeping the transmitted count fixed:

[
K=R+D
]

Run:

* (K=4,\ R=1,2,3,4)
* (K=8,\ R=1,\ldots,8)
* (K=16,\ R=1,\ldots,16)

This produces 28 distinct ((K,R)) cells.

## Preregister the experiment

Before examining full-campaign results, create a timestamped experiment protocol under:

`defense4/evidence/fixed_k_emulator/`

The protocol must freeze:

* Point-role mapping
* Command-list construction and ordering
* Number of repetitions
* Random seed
* Timing features
* Statistical tests
* Pass, fail, and inconclusive rules
* Retry policy
* Artifact layout
* Safety checks

Use at least 30 valid repetitions per ((K,R)) cell unless a stronger sample count is justified before looking at the results. Do not change the sample count or thresholds after seeing the results merely to obtain a pass.

Commit and push the harness plus preregistered protocol before the full campaign if practical.

## Emulator point model

Implement explicit, protocol-valid inert decoy points. Preserve existing behavior unless the new fixed-(K) mode is selected.

Use a stable disjoint point map such as:

* Real-point pool: indexes `0..15`
* Inert-decoy pool: indexes `16..31`

For a cell ((K,R)):

* Select (R) indexes from the real pool.
* Select (K-R) indexes from the inert-decoy pool.
* Transmit exactly (K) valid CROBs.
* Use the same ordered object list in SELECT and OPERATE.
* Keep every index valid so all object statuses can be `SUCCESS`.
* Never use nonexistent indexes as decoys.
* Record the exact role and transmitted order of every index.

Use deterministic seeded ordering or balanced seeded permutations. Record every seed and plan. Do not create a visible “real” or “decoy” marker in the DNP3 transaction.

The emulator backend must distinguish protocol acceptance from physical effect:

* A real CROB returns `SUCCESS` and invokes the simulated actuation hook.
* An inert decoy returns `SUCCESS` but does not invoke the actuation hook.
* An inert decoy must not change simulated output state.
* An inert decoy must not invoke the emulator alarm, automation, or side-effect surrogate hooks.
* Record SELECT, OPERATE, status, role, timestamps, initial state, final state, and actuation count per index.

Alternate control codes across repetitions when necessary so every intended real operation causes an observable state transition. Decoys must remain unchanged.

State clearly that this proves inertness only inside the emulator model. It does not prove that any SEL-751 point is physically inert.

## Persistent TCP requirement

Use one persistent TCP connection per ((K,R)) capture, containing all repetitions for that cell, followed by one teardown at the end.

Requirements:

* One connection setup before the first transaction.
* No FIN or RST between transactions.
* One teardown only after the last transaction.
* A terminal ACK must acknowledge each final OPERATE response.
* Exclude connection establishment and teardown from transaction timing.

The current `--hold-open-ms` behavior only delays teardown after one transaction. It is not by itself proof of a multi-transaction persistent session.

Investigate the existing pydnp3 callback limitation carefully. If the Python binding cannot safely run repeated SBO tasks on one connection, implement a small emulator-only persistent master using the installed OpenDNP3 C++ API or another source-grounded solution. Do not weaken the criterion silently and do not mislabel multiple short-lived connections as persistent.

If a true persistent implementation proves impossible after source-level investigation, mark criterion 6.7 `BLOCKED`, preserve the evidence, and explain the exact binding limitation. Never fabricate a pass.

## Dedicated tooling

Prefer adding dedicated fixed-(K) tools instead of changing the meaning of the historical highest-(N) sweep. Suggested components are:

* A fixed-(K) campaign runner
* Fixed-(K) master plan support
* Explicit inert-point support in the emulator backend
* A multi-transaction PCAP analyzer
* A summary and statistical analyzer
* Focused unit and regression tests

The campaign runner must be restartable. It must write progress after every cell and safely resume without overwriting completed raw evidence.

Use a timestamped run ID. Run long jobs inside `tmux` or another durable mechanism and preserve the complete console transcript.

## Required verification for every K

### 1. SELECT request size

Measure the reassembled DNP3/TCP payload length and observed TCP segment length.

Pass only if SELECT request size has exactly one value across every (R) and repetition for the same (K).

### 2. OPERATE request size

Pass only if OPERATE request size has exactly one value across every (R) and repetition for the same (K).

### 3. Response sizes

Measure SELECT-response and OPERATE-response sizes separately.

Pass only if each response type has exactly one size across every (R) and repetition for the same (K).

Do not use packet count alone as a size metric. Account for TCP reassembly and capture offload.

### 4. Status and transaction correctness

Verify from raw wire evidence and outstation evidence:

* Exactly (K) objects in SELECT
* Exactly (K) objects in OPERATE
* Identical ordered SELECT and OPERATE lists
* Exactly (K) success statuses in each response
* Clean master task completion
* No timeout
* No partial SELECT
* No suppressed OPERATE
* Valid DNP3 CRCs

### 5. Real effects

For every transaction, exactly (R) real points must invoke the simulated actuation hook and reach the intended state.

### 6. Decoy inertness

For every transaction:

* Exactly (K-R) decoy CROBs must be accepted.
* Every decoy must return `SUCCESS`.
* No decoy state may change.
* No decoy actuation hook may run.
* No emulator alarm, automation, or side-effect surrogate may run.

### 7. TCP correctness

For every per-cell PCAP:

* One persistent connection
* No per-transaction SYN or FIN
* No RST
* No retransmission
* No unexplained duplicate data
* No sequence gap
* No malformed acknowledgment
* Teardown only after the final transaction

### 8. Timing leakage

Extract at least:

* SELECT request to SELECT response
* SELECT response to OPERATE request
* OPERATE request to OPERATE response
* Total SBO duration
* Relevant packet inter-arrival gaps

For each (K), test whether timing features recover (R). The statistics agent must preregister suitable analyses before the full run. Include:

* Effect sizes and confidence intervals
* Rank correlation between (R) and timing
* Distribution comparison across (R)
* A timing-only cross-validated classifier
* Permutation-based chance comparison
* A leakage measure such as mutual information when defensible

Do not declare “no side channel” merely because a p-value exceeds 0.05. Report uncertainty. Use `PASS`, `FAIL`, or `INCONCLUSIVE` according to the preregistered rule.

## Execution sequence

1. Inspect and document the current harness limitations.
2. Have the specialist agents review the experiment design.
3. Write and commit the preregistered protocol.
4. Implement the dedicated fixed-(K) tooling.
5. Run syntax, unit, parser, and existing corpus regression tests.
6. Verify that historical all-real and invalid-index behavior remains unchanged.
7. Run smoke cells:

   * ((4,1))
   * ((4,4))
   * ((16,1))
   * ((16,16))
8. Independently inspect their PCAPs and JSON before starting the full campaign.
9. Run all 28 cells in randomized campaign order with the preregistered repetitions.
10. Preserve every failed attempt.
11. Retry only clear infrastructure failures, at most twice.
12. Do not rerun a scientific failure merely to obtain a pass.
13. If an implementation defect is found, preserve the failed run, fix it, assign a new run ID, and rerun the complete affected (K), not only the failed cell.
14. Run the statistical analysis.
15. Have the protocol, statistics, and adversarial-review agents independently inspect the final evidence.
16. Correct every confirmed defect they identify.
17. Update the controlling documentation.
18. Commit and push all final code, evidence, and documentation.

## Evidence package

Create a timestamped evidence directory containing:

* Preregistered protocol
* Environment and tool-version manifest
* Exact commands
* Git SHA
* Host-role confirmation
* Random seeds and run order
* One PCAP per ((K,R)) cell
* Master JSON and logs
* Outstation JSON and logs
* Analyzer JSON per cell
* Per-transaction feature CSV
* Complete 28-cell summary CSV and JSON
* Statistical results
* Agent review notes
* Complete campaign transcript
* SHA-256 manifest for every evidence artifact
* `RESULTS.md` with claims tied to specific raw files

The summary matrix must show, for every ((K,R)):

* Repetitions attempted and valid
* Four message sizes
* Status counts
* Real actuation count
* Decoy acceptance and inertness
* TCP checks
* Timing-leakage result
* Overall `PASS`, `FAIL`, or `INCONCLUSIVE`

## Documentation and claims

Update at least:

* `defense4/DEFENSE4_EVIDENCE_LEDGER.md`
* `defense4/DEFENSE4_IMPLEMENTATION_AND_TEST_PLAN.md`
* `RESUME_STATE.md`
* `CLAUDE.md`
* The multi-CROB harness README and relevant test documentation

Do not rewrite historical evidence. Link the new result from the controlling documents.

Use only claims supported by committed evidence.

If every size and correctness gate passes, the strongest allowed statement is:

“The fixed-(K), real-plus-inert-decoy CROB construction normalized SELECT, OPERATE, and response sizes across (R=1\ldots K) for (K=4,8,16) on the OpenDNP3 emulator.”

Do not claim:

* Physical relay inertness
* Physical relay safety
* Complete Defense 4
* Unified timing-engine validation
* READ-versus-SBO indistinguishability
* Protection against every plaintext DNP3 semantic feature
* A universal OpenDNP3 or DNP3 CROB limit

Complete Defense 4 must remain `NOT DEMONSTRATED`.

## Git and return requirements

Use clear, reviewable commits. Do not force-push.

Push the final work to the remote. Verify that local `main` and remote `main` match. If branch protection or an unrelated remote change prevents a safe push, push a clearly named review branch and report it. Never overwrite someone else’s work.

Return:

1. Final commit SHA or SHAs
2. Branch and remote synchronization status
3. Files changed
4. Exact campaign run ID
5. Number of cells and transactions completed
6. Full fixed-(K) summary matrix
7. Criteria 6.1–6.8 verdicts
8. Timing-side-channel statistics
9. Regressions and agent-review results
10. Failures, retries, and preserved negative evidence
11. Remaining unresolved decisions
12. Exact evidence-directory path

Remain autonomous throughout the night. Debug recoverable failures, use agents for independent review, and continue through implementation, campaign execution, analysis, documentation, commit, and push. Ask me only if blocked by missing credentials, unavailable emulator hosts, a safety ambiguity, or a change that would require contacting the Tofino or physical SEL-751.

Stop after the fixed-(K) emulator phase is committed and pushed. Do not begin the unified P4 timing-core implementation.
