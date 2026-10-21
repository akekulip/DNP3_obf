# Autonomous overnight directive: close the integrated READ padding mechanism

This is an execution task, not another planning exercise. Work autonomously on
Gambit through software reproduction, target-policy selection, P4 implementation,
compiler/model validation and the authorized physical-Tofino tests. The goal is
one integrated candidate whose READ sizing and timing work together, while
preserving existing SELECT/OPERATE size behavior, timing and OPERATE hold J.

Read START_HERE.md for evidence, technical details and the recorded defects.
This directive takes precedence over its stopping/checkpoint language. All
existing evidence-preservation, review, ownership and restoration requirements
remain in force. Do not stop merely because a task is a substantial rewrite,
an intermediate compile passes, or the software reference works.

## Autonomy and scope

Make routine implementation, target-policy and test-fixture decisions yourself,
using the supplied evidence and the current code. Record the reason and proceed.
Do not repeatedly ask Philip to choose between ordinary engineering alternatives.
An initial failed approach requires diagnosis and a materially justified next
approach, not a claim that the goal is impossible. Preserve failed attempts.

Keep the existing N/E/T architecture and timing mechanism. Replace the obsolete
READ size transform rather than accumulating old and new paths. Make the N/E,
mapper, profile and harness changes actually needed for the integrated behavior.
Use the fewest practical stages/traversals, but do not reopen an unrelated stage-
optimization project. Do not add a new scheduler, dummy-traffic system, encryption,
second switch, qualification framework, physical-relay OPERATE, manuscript work,
or the main adversary/D/J campaign. Preserve the existing supported SBO contract;
do not insert measurement objects into control responses based on permissive
parser acceptance.

## Milestone 1 — establish and reproduce the starting point

Verify the bundle manifest, current HEAD, uncommitted changes, active runs and
testbed ownership. Reconcile current corrections with the source-specific review;
do not reset main or overwrite Philip's work. Preserve the baseline.

Run the 51-test suite and live software checks from the package. Repeat endpoint
acceptance on the actual pinned deployment stack, retaining source/library/binary
hashes. The supplied upstream OpenDNP3 results are reference evidence only.
Use the existing build/runtime environment and unique output directories.

## Milestone 2 — settle the distribution, targets and supported coverage

Read Ditto's pattern-selection and shaping sections and inspect relevant author
code where needed to settle an implementation detail. Use the retained READ
captures as the initial dataset; do not start an unrelated collection study.

Declare exactly what the attacker measures: individual TCP packet length,
DNP3 link-frame length or aggregate response length. Extract the distribution
at that layer from the captures with request/response identities retained.
Count segmentation correctly. The sample is a fixture workload, not a field
population; the earlier 157-byte constructed example is not a captured sample.

Compare two- and three-target policies using empirical percentiles as seeds,
then adapt them to valid DNP3 encodings. Resolve repeated percentile states,
reachability, overhead and remaining size distinctions explicitly. Select and
record a concrete policy autonomously; do not ask Philip to select numbers.
The historical 163/269/399 aggregate-response policy is a useful comparator,
not a mandated final policy or an implemented Ditto packet schedule.

Freeze the policy, units, input-size/object profile, reserved padding indices,
endpoint capacity, selection rule and explicit out-of-profile behavior. Establish
coverage across the declared supported size range, not only captured examples.
If targets change, repeat the software coverage argument/tests for those targets.
No finite target set supports unbounded responses. Do not hide an unreachable
case, silently bypass padding as a pass, or force all responses to the maximum.

Keep runtime timing behavior as already specified. Borrowing percentile selection
does not imply Ditto's complete fixed-rate/chaff protection. If using aggregate
targets, label that adaptation and verify the actual packet sizes separately.

## Milestone 3 — complete the software mechanism for the selected policy

Use the generalized encoder as a reference, not a capture template. Verify small,
medium, full and naturally segmented READs; relevant alignment/CRC/index-width
boundaries; and previously unreachable gaps. Preserve every original measurement,
index, value, flag, application header and control status. Validate exact output
lengths, reassembly, CRCs, master task outcomes and IIN behavior.

Keep synthetic padding explicitly identified. A reserved index range must be
valid for the fixture/profile, not simply absent from one captured response.
Do not claim universal protocol conformance from one master's acceptance.

## Milestone 4 — implement the integrated P4 candidate

Port the selected mechanism into the existing generator and actual READ path.
Generalize request recognition, sequence accounting and per-response image
length wherever necessary. Resolve the current mapper/admission defects from
the review, including READ/SBO transitions, ACK boundaries and normalization.

The software full-reserialization fallback is not a demonstrated ASIC solution.
Investigate how to realize its byte construction within the existing pipelines,
using the existing prefix, segmentation, CRC and checksum techniques. Compile
small concrete alternatives and inspect emitted bytes. Do not infer integrated
fit from isolated placement probes, or claim all solutions impossible from one
failed parser/PHV approach. Do not hardcode live packet values or fabricate
successful checksum residues.

Batch related corrections into reviewable compile/model checkpoints. Integrate
one consistent generator/profile/manifest/config source. Resolve contradictions
such as a runnable flag or image length that describes an intermediate candidate.

## Milestone 5 — exact-source compiler and model gates

Build the selected source on SDKs 9.13.1 and 9.13.2. Record actual placement,
resource usage and traversals against m11_09; distinguish occupied stages from
span. Obtain the existing required code review before hardware.

Run focused encoding/mapping regressions, then all nine existing model drivers
and the dependency-bound v3 gate. Exercise actual READ requests and repeatedly
interleave READ->SELECT->OPERATE->READ on one connection with timing/J enabled.
Update retired fixture-size assumptions while preserving the assertions' purpose.
Unchanged T source does not prove integrated timing. Check corrupted first-block
CRC, bad TCP checksum and bad tail CRC with valid TCP separately, including actual
recovery. Trace withheld ACK disposition rather than relying only on a counter.

Do not repeat the full suite after every minor edit. Run it on the selected source;
if a failure requires a correction, preserve it and rerun the affected required
gates with a new identity. Never rerun solely to obtain a favorable outcome.

## Milestone 6 — authorized physical-switch execution

After review, both compiles and required model gates pass, continue directly to
the focused hardware work already authorized by Philip. Do not ask again simply
because software validation has finished. Use software endpoints through physical
Tofino, existing source/config freezes, wrappers and restoration mechanisms.

Check the current ownership/restore state. Diagnose any restoration problem using
the existing process. An unresolved unsafe-restoration condition blocks loading;
do not simply clear the flag or weaken comparisons. If that blocks hardware,
complete the remaining offline deliverables and report the exact blocker.

Run the selected READ policy on representative small/full/segmented responses,
including the fallback construction where supported. Check actual master-facing
packet sizes AND aggregate response bytes, original measurements, CRCs, IIN,
TCP mapping and application completion. Verify configured timing and OPERATE J
on the same image and repeated mixed READ/SBO connection. Reuse the existing
five recovery configurations and required matched reference/mixed block, adapting
only what the new READ profile needs and refreezing those exact configurations.

Record counters, captures, endpoint logs, delivery, tails, failures and independent
restoration after each block. Stop further hardware loads after unverified restore.
Do not substitute software/model evidence for silicon results, skip unfavorable
observations, or promote the image by default.

## Overnight execution and completion

Use the existing detached execution on Gambit so active compiler/model/hardware
runs survive monitoring-terminal disconnection. Persist the current milestone,
source identity, exact command, run directory, process/service identity and next
step. Check existing active runs before resuming. No automatic replay of ambiguous
hardware attempts. Do not build a new orchestration framework for this task.

Continue across normal checkpoints while the execution session permits. A detached
job can survive disconnection; this does not guarantee that an LLM session will
remain active. Leave precise resume instructions if a hard session/time limit
interrupts work, and let active hardware restoration finish safely.

Commit coherent reviewed milestones via the existing gated workflow as
akekulip <akekulip@gmail.com>, without co-author trailers. Keep WORKING_NOTES
per repo convention. No push unless explicitly authorized.

The intended closeout is one reproducible, tested integrated candidate, a frozen
distribution/target policy, and physical evidence that sizing and timing coexist
correctly. Report exactly which milestone completed, measured stages/resources,
software/model/hardware results, artifact hashes, commands and remaining limits.
If a specific blocker prevents that closeout, provide its reproducible evidence
and completed work. Do not present a software pass, design or compile checkpoint
as the hardware deliverable.
