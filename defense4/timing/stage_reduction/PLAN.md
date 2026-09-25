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

## Seven-stage follow-up

Eight-stage recovery commit: `29feefaa` (SDE 9.13.1 and 9.13.2, 41 tests pass).
Keep the terminal commit table and all runtime behavior. Test two redundant
head dependencies independently: select expected-ACK read/write from the class
driver's original raw predicates, and use budget_zero directly inside the
TOKEN-only epoch action while making non-TOKEN epoch reads unconditional reads.
Add differential selector/watchdog checks before retaining either change; compile
against both SDEs and retain eight stages if seven cannot be verified.

The retained candidate also groups the mutually exclusive response-authorize and
fail-open operand writers after the session trackers. A 32-bit first-ACK predicate
container and explicit placement hints let the final PHV pass retain seven stages.
Both SDE 9.13.1 and 9.13.2 compile and assemble the identical source to 7 ingress /
0 egress stages, critical path 7, and 73 allocated tables. Evidence is in
`evidence/candidate` and `evidence/candidate_sde9132`; `29feefaa` retains the
eight-stage source and reports. Packet execution remains unverified because the
isolated model needs privileges unavailable in this environment.
