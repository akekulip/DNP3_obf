# Timing-only ingress stage reduction

Recovery checkpoint: `eb8f0ae7d51a0a0eed9f1e9b5472fe427b118ed4`.
The pre-existing untracked manuscript/reference assets are outside this checkpoint.

## Contract

Target at most eight ingress stages, with no size shaping. Preserve the request-
anchored baseline's timing modes, supported parameters, packet bytes, queue and
recirculation behavior, fail-open paths, and modular deadline semantics. Keep
bug corrections separate. Historical source and evidence stay immutable.

## Execution and verification

1. Rebuild the anchor_fix source with local SDE 9.13.1; archive hashes and reports.
2. Establish source-driven behavioral checks and negative controls before changes.
3. Port the archived size-removal patch and update the isolated control plane.
4. Independently test SALU first-ACK/readiness predicate returns, BOR decision
   consolidation, direct masked age matching, and earlier candidate selection.
5. Compile each candidate and retain equivalent improvements; inspect dependencies,
   stage assignments, PHV and warnings. Combine only independently checked changes.
6. Validate generated BFRT interfaces, setup self-tests and compiled local-model
   behavior. Distinguish model/compile evidence from hardware timing evidence.
7. Report the best verified stage count and remaining constraints honestly; eight
   stages is the target, never a reason to weaken behavior.

`tbl_commit` remains a single terminal const table. Direct unsigned deadline
comparison is prohibited because it changes behavior at timestamp wrap.
No hardware mutation is included in this local implementation branch. The live
switch was inspected read-only and runs the unrelated `mvm_tna` program.

## Review separation

The parent owns candidate P4 and compiler experiments. Independent agents own
source-driven verification, timing-only setup, and isolated model validation.
An independent final review checks the retained diff and evidence.
