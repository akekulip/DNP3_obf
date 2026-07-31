> **ARCHIVED (2026-07-30) — the original external audit text.** Its findings drove the
> release-hardening pass; the resolution record is `../../AUDIT_RESPONSE.md` and
> `../../MANIFEST.yaml`, and the fixes are in the report §7 and the git history. Kept for
> provenance.

Repository audit verdict

I reviewed the current main branch, including the final repaired P4, report, README, setup code, campaign harness, analyzers, resource artifacts, state files, project instructions, evidence structure, and recent commits. I did not rerun bf-p4c or independently replay every PCAP.

The six documentation concerns from my previous review have been addressed. However, the repository is not yet release-ready. The principal remaining risks are now in build selection, control-plane consistency, measurement reliability, and stale project guidance, rather than the central R1–R3 state-machine design.

The most serious current finding is:

A reader following the published reproduction instructions will build the original unrepaired Defense 3, not the final R1+R2+R3 implementation.

A second serious finding is:

The campaign harness reads Tofino counters without the counter synchronization that the repository’s own setup code says is required.

1. Status of my previous concerns

All six were corrected in the current tree:

Previous concern	Current status
P4 still said it was never loaded	Corrected
P4 claimed only one new register despite R2	Corrected
P4 said every response takes one loopback pass	Corrected for late responses
Report duplicated the state-ordering paragraph and mis-scoped repaired campaigns	Corrected
Figure 8 claimed the host capture was exactly the attacker’s wire view	Corrected to “master-interface proxy”
README claimed whole-state correctness	Replaced with “all known audit defects repaired,” with appropriate caveats

The current P4 identifies itself as the final repaired build, distinguishes reg_ack_rel from R2’s reg_failopen, and now says that a response arriving after ACK retirement forwards directly. The current report correctly qualifies the master-side capture as a proxy and separates the original and repaired resource generations. The README also now uses the more defensible “all known audit defects repaired” wording.

So the earlier six concerns can be considered closed.

2. Critical release and reproducibility problems
2.1 The published build command compiles the wrong P4

Report §13 currently tells the reader to compile:

p4/case_a_defense3_fixed_ack_delay.p4

and describes the resulting variants as:

core       9/12, path 8
telemetry 10/12, path 8
synthetic  9/12, path 8

Those are the original unrepaired build and its resource figures.

The README correctly says that the final implementation is:

p4/case_a_defense3_repair_candidate.p4

with the original file retained as the unrepaired historical baseline.

The final build should instead reproduce:

core       10/12, path 10
telemetry 11/12, path 10
synthetic 11/12, path 10
Required correction

Replace §13 with exact commands for the repaired source and flags. More importantly, do not leave R1, R2 and R3 optional in the production file.

The ideal arrangement is:

p4/case_a_defense3.p4
    R1, R2 and R3 unconditional

archive/pre_audit/case_a_defense3_unrepaired.p4
    historical control only

Keep defect toggles only in a dedicated test/probe source. A production build must not silently become vulnerable because someone omitted:

-DD3_REPAIR_R1
-DD3_REPAIR_R2
-DD3_REPAIR_R3
2.2 The default control plane still targets the unrepaired program

The main setup script still contains:

PROG_DEFAULT = "case_a_defense3_fixed_ack_delay"

Its module documentation says it was authored off-switch, never executed, and that the switch still runs Defense 2. Its emitted metadata initializes:

"authored_off_switch": True
"silicon_validated": False

Those statements and defaults are now false.

The physical campaign scripts have the same unsafe default:

D3_PROG=${D3_PROG:-case_a_defense3_fixed_ack_delay}

and setarm.py likewise defaults to the unrepaired program.

This means the repaired build works only when the operator remembers to export the correct D3_PROG.

Required correction

Make the final repaired program the only default:

PROG_DEFAULT = "case_a_defense3"

Better still, require an exact expected program and source hash:

expected p4_name
expected source SHA-256
expected artifact SHA-256
required BFRT objects:
    tbl_resp_authorise
    reg_failopen
    CF_BLOCK_REJECT

The setup should refuse to arm if any final-repair object is absent.

2.3 The “restore baseline” is a known-defective program

The README and current state documentation describe the original unrepaired Defense 3 as the frozen restore baseline, and the switch is reportedly restored to that configuration after experiments.

A known-defective program can be retained as an experimental control, but it should not be called a safe baseline.

Use one of these:

safe operational restore:
    final repaired Defense 3
or:
    frozen silicon-proven Defense 2

historical experimental control:
    original unrepaired Defense 3

Loading the historical version should require an explicit option such as:

--load-unrepaired-control
3. Control-plane correctness problems
3.1 The 40 ms clamp remains implemented even though the report proves it is impossible

The setup still defines:

D_MAX_MS = 40.0

and quantize_d() accepts values up to 40 ms.

The P4 comment also still says the control plane refuses only values greater than 40 ms.

But the report correctly establishes:

H≈30.802 ms

and therefore D=40 ms causes budget expiry before the deadline even with an instantaneous ACK.

Correct implementation

Do not use a fixed D_MAX_MS. Compute the admissible range:

D
max
	​

=H−a
bound
	​

−t
detect
	​

−t
drain
	​

−t
tail
	​

−M

where M is a configured safety margin.

Alternatively, compute the required budget from D:

B
min
	​

=⌈
K/r
a
bound
	​

+D+t
overhead
	​

+M
	​

⌉

while also enforcing:

H<RTO
min
	​

−M
RTO
	​

.
3.2 The setup guard and campaign setter implement different safety policies

The general setup uses a hardcoded:

a_worst = 22 ms

and rejects configurations for which:

H≤22 ms+D.

That would reject the normal D=16 ms campaign because 30.8<38 ms.

The campaign does not use that guard. setarm.py writes D, read_len=18, and budget=18000 directly, with no:

D maximum check;
fail-open-horizon check;
RTO check;
poll-rate/generation-wrap check.

This creates two different parameter authorities.

Required correction

Create one shared module:

defense3/control/parameter_policy.py

Both setup and campaign code must call it. It should return:

D requested
D realized
budget
H
ACK-latency bound
poll-rate bound
RTO margin
verdict

No harness should write tbl_params directly.

3.3 The generation-wrap guard is documented but not implemented

The report correctly says R2’s safety depends on:

H+t
drain
	​

<16T
poll,min
	​

.

But no control-plane code currently enforces it.

Add:

--min-poll-interval-ms

and reject any configuration where:

16T
poll,min
	​

≤H+t
drain
	​

+M.
3.4 Generic cleanup does not include reg_failopen

The campaign-specific setarm.py clears reg_failopen conditionally, which is correct.

The general setup’s REGS_ZERO, clean-state test, and cleanup path do not include reg_failopen. A stale R2 note can therefore survive a generic cleanup or verification run.

Add reg_failopen to:

initialization;
clean-start verification;
cleanup;
post-cleanup readback.
4. Campaign measurement problems
4.1 Counter reads do not perform SyncCounters

The repository’s own ctr_read() helper states that Tofino Stats-ALU counters require:

operations_execute(..., "SyncCounters")

before reading, and that from_hw=True alone can return stale zero.

The campaign’s inline counter reader calls only:

entry_get(..., {"from_hw": True})

with no synchronization.

That weakens the reproducibility of claims such as:

exactly 64 tokens admitted;
all tokens deadline-terminated;
zero stale terminations;
zero fail-open;
zero duplicate suppression.

The archived results may still be correct because other synchronization or elapsed time may have made values visible, but the code does not guarantee it.

Required correction

Replace the inline reader with the tested shared ctr_read() helper, or explicitly call:

tb.operations_execute(tgt, "SyncCounters")

once before reading each counter object.

4.2 BLOCK_REJECT is not reset by setarm.py

The final P4 defines:

CF_RESP_DUP_SUPP = 16
CF_BLOCK_REJECT  = 17

But setarm.py clears:

for i in range(17):

which resets only indices 0 through 16. Index 17 remains cumulative across blocks.

Use a shared generated counter map and derive the range from it. Do not duplicate counter numbers across:

P4;
setup;
campaign shell;
injector;
analyzers.
4.3 The campaign does not fail closed on harness errors

campaign.sh:

does not use set -euo pipefail;
extracts output with grep;
converts missing output to parse_error;
continues to later arms;
truncates the destination file immediately with : > "$OUT".

A failed setarm.py, failed SSH operation, missing capture, or empty BLOCK result can therefore become a row rather than aborting the campaign.

Required policy:

setarm unsuccessful        → abort arm
program/hash mismatch      → abort campaign
capture process failed     → abort block
attempted != requested     → invalid block
responded != attempted     → retain evidence, abort next arm
counter read parse error   → invalid block
4.4 block.py is too permissive for transaction reconstruction

The capture parser identifies traffic using only:

direction;
payload length 18 for READ;
zero payload and flags "." for ACK;
any relay payload as RESPONSE.

It does not bind rows using the TCP connection’s port, sequence or acknowledgment numbers, and it does not validate the DNP3 application sequence.

Other problems include:

hardcoded interface and IP addresses;
no verification that dumpcap started successfully;
no wait() to guarantee capture flush;
float timestamps;
ack_before_resp accepts equality, although equal software timestamps do not prove strict order;
first response segment is treated as the complete response;
no explicit exclusion of keepalives or unrelated relay sessions.

This is adequate for the controlled single-connection laboratory run, but not a robust publication-grade transaction reconstructor.

5. Final P4 implementation assessment
What is strong

The final construction is technically coherent within its narrow scope:

R1 authorizes the response marker before the reg_tag write.
E1 stores inactive, live-unmarked and live-pending state in one byte without a second-register dependency cycle.
R2 replaces destructive producer-side fail-open retirement with a generation-labelled note and consumer-side authorization.
R3 prevents fresh non-pktgen blocker frames from entering Q_BLOCK.
Early ACK and RESPONSE packets share Q_HOLD, preserving original-packet order structurally.
Assembly assertions and mutation-tested state models are appropriate responses to the SALU behavior encountered.

The repaired physical campaign reports 960/960 responses and 800 defended transactions with the expected 51,200 token admissions.

Remaining implementation gaps
5.1 ACK-retirement-to-egress race

The narrow interval remains untested:

ACK retires reg_tag
    ↓
late response sees inactive state and forwards directly
    ↓
ACK has not yet committed at master-facing egress

The report correctly records this as open.

This is the most important remaining data-plane correctness test. It requires actual egress ordering at offsets around:

0, 32, 64, 128, 256, 512 ns, 1 µs

Do not solve it with additional state until the race is physically measured.

5.2 Duplicate suppression is not an “exact retransmission” test

The code compares:

TCP sequence position;
TCP acknowledgment;
learned port;
DNP3 response framing;
pending-state domain.

It explicitly does not compare payload length or payload bytes.

It also does not independently compare the response’s DNP3 application-sequence nibble with the active request generation. Calling the DNP3 framing gates “the DNP3 transaction identity” is too strong.

Use:

current-session, TCP-position-matched response suppression

rather than:

exact or transaction-identity-matched retransmission suppression.

5.3 A legitimate TCP retransmission is deliberately dropped

The P4 header says no legitimate protected-session packet is dropped, but TCP retransmission is legitimate network behavior. The first matching retransmission during the pending window is intentionally suppressed.

That is a defensible tradeoff for preserving ACK-before-RESPONSE order, but it is still a reliability change.

The accurate claim is:

No original request, ACK or first response is intentionally dropped. A matching response retransmission may be suppressed while the first copy is queue-resident.

5.4 One global connection, not merely one transaction

All relevant registers are size one. The limitation is therefore:

one protected TCP connection
one active transaction on that connection

A second matching connection can overwrite session trackers. The report now acknowledges this, but the control plane does not explicitly prevent it.

At minimum:

learn the master ephemeral port once;
then replace the wildcard session entry with an exact 4-tuple;
reject or count any second connection.
5.5 TCP sequence zero remains a sentinel

The sequence tracker does not write when the candidate value is zero. TCP sequence zero is valid after wrap-around. This is rare but structurally wrong.

Use a separate write-enable bit derived from packet class instead of using zero as “no write.”

5.6 Parser metadata warning remains open

The parser deliberately leaves load-bearing fields unassigned on some paths and relies on compiler-provided zero initialization.

Every compile still reports uninitialized_out_param. This should be fixed using path-specific finalization states or parser-local metadata. Do not suppress the warning.

5.7 Protocol coverage remains narrow

The current implementation bypasses:

VLAN-tagged Ethernet;
IPv6;
IPv4 options;
fragmented IPv4;
DNP3-bearing TCP packets with more than 12 bytes of TCP options;
segmented or fragmented DNP3 responses;
encrypted DNP3 not visible at a plaintext point.

These are acceptable paper scope limits, but VLAN support is likely the first practical extension for an actual substation network.

5.8 The mechanism consumes almost the entire internal loopback

The report states approximately 24 Gbit/s of the 25 Gbit/s loopback and one active transaction capacity.

Do not reduce K inside the final artifact without a dedicated reservoir-continuity sweep. But after the release artifact is frozen, testing K=64,48,32,24,16,… is the main route to improving scalability.

6. Resource and artifact provenance problems
6.1 The superseded ledger links to the wrong “final” resource logs

The pre-audit ledger tells readers that:

artifacts/resources/bx_core.table_summary.log
artifacts/resources/bx_fulltel.table_summary.log
artifacts/resources/bx_synth.table_summary.log

are the repaired build’s logs.

But bx_core.table_summary.log is clearly the original build:

9 ingress stages
critical path 8
table names: case_a_defense3_fixed_ack_delay

The repaired logs live under artifacts/resources_repair/, with repaired table names and 10/11-stage results.

Correct the links and give every artifact a semantic name:

final_core_sde9131.table_summary.log
final_core_sde9132.table_summary.log
final_telemetry_sde9132.table_summary.log
final_synthetic_sde9132.table_summary.log
6.2 The default assembly checker does not prove the final R2 build

With no arguments, assert_salu_asm.py scans:

artifacts/assembly/*.bfa

Its R2 check runs only when it detects R2-specific instructions; it intentionally remains silent on a build without R2.

The archived assembly directory appears to contain the original build_* and bx_* assemblies, while repaired resource logs are stored separately. Therefore a default PASS can occur without checking the final repaired R2 assembly.

Require the final manifest to name the exact BFA:

python3 analysis/assert_salu_asm.py \
    artifacts/final/final_r1r2r3_core_9.13.2.bfa

The checker should fail if R2 is expected but absent.

7. Report and claim corrections still needed
Page count

README and REPORT say 36 pages. The current state file says the rebuilt PDF is 37 pages.

Use pdfinfo REPORT.pdf in CI and update both automatically.

The equation needs more precise notation

The useful conceptual approximation is:

CLRT
out
	​

≈max(c−D,δ).

But the measured δ is not a universal constant. It is a capture-dependent distribution incorporating FIFO release, egress scheduling, serialization, NIC handling and host timestamping.

A more precise statement is:

CLRT
out
	​

=
⎩
⎨
⎧
	​

c−D+ϵ
direct
	​

,
Δ
release
	​

,
	​

c>D,
c≤D,
	​


where Δ
release
	​

 is the measured residual ACK-to-RESPONSE distribution. In this campaign its median was about 32 µs, not an architectural constant.

Likewise:

READ→ACK
out
	​

=a+D
realized
	​

+ϵ
release
	​

,

not exactly a+D.

README opening overstates the security result

The README says Defense 3 makes the delay no longer reveal the device. The same README later correctly says device anonymity was not demonstrated.

Use:

Defense 3 compresses the SEL-751’s CLRT distribution under the tested conditions.

Also replace “trivially visible” with:

readily detectable in the measured sessions.

The experiment establishes detection in this dataset, not universal trivial detection.

8. Files that should be removed, archived or replaced
Remove or replace immediately
defense3/RESUME_DEFENSE3.md

It still says:

feature branch active;
live build never loaded;
Gate 4C failed;
physical validation not started;
D=1 ms is a null control.

It is completely superseded.

Replace it with a two-line pointer to RESUME_STATE.md, or delete it.

Empty evidence directories

The repository inventory contains many aborted check2_* and gate2_* directories containing zero-byte JSON, logs and summaries. Delete those. They provide no negative evidence because they contain no record.

Duplicate compiler artifacts

The current build_*, bx_*, and repair_* naming is ambiguous and partially duplicated. Retain one canonical artifact for each final variant and move historic resources under an explicitly labelled archive.

Archive rather than delete
meeting_direction.md

It is a mid-run CHECK1/CHECK2/Gate2 directive, not the current project direction.

Move it to:

defense3/archive/directions/meeting_direction_2026-07-29.md
research/queue_backpressure_release/PIVOT_TO_ENDPOINT_TIMING.md

It says the in-network hold is impossible and directs the project to stop and pivot to endpoint timing. That is superseded by the completed Defense 3 result.

Move it to:

archive/superseded_decisions/

with a clear header stating that later Defense 3 evidence superseded the decision.

WORKING_NOTES.md

It contains a current summary followed by extensive contradictory historical states, including 25 pages/eight figures and Gate 4C failure.

Keep history, but move it to:

archive/worklogs/WORKING_NOTES_2026-07.md
CORRECTIONS.md

This is the original audit text, while AUDIT_RESPONSE.md, REPAIR_HISTORY.md, report §14 and commit history now repeat much of it.

Move it to:

defense3/archive/audit/ORIGINAL_AUDIT.md

Keep AUDIT_RESPONSE.md as the active resolution record.

Original unrepaired P4 and pre-audit ledger

Keep them for scientific provenance, but place them under:

defense3/archive/pre_audit/

They should not sit beside the production source.

Rewrite urgently
CLAUDE.md

This is currently the most dangerous stale file in the repository. It says:

fixed-D Defense 3 failed its gates;
the next direction is READ-anchored release;
a self-timed single-packet hold should replace the blocker reservoir;
old “no P4/no proxy” phase constraints remain governing.

Future agents reading RESUME_STATE.md are explicitly told to read this file next, so they will receive contradictory instructions. Rewrite it around the current state and move historical directions into an archive.

RESUME_STATE.md

It embeds a precise Git SHA that becomes stale as soon as the file itself is committed. It also points to the obsolete RESUME_DEFENSE3.md.

Do not store “current HEAD” literally. Use:

Run: git rev-parse HEAD

or:

State reflects the tree through commit X;
this status document was committed immediately afterward.
9. Recommended final repository structure
defense3/
├── README.md
├── REPORT.md
├── REPORT.tex
├── REPORT.pdf
├── Makefile
├── MANIFEST.yaml
├── p4/
│   ├── case_a_defense3.p4
│   └── probes/
├── setup/
│   ├── d3_setup.py
│   └── parameter_policy.py
├── harness/
├── analysis/
├── artifacts/
│   └── final/
│       ├── core/
│       ├── telemetry/
│       ├── synthetic/
│       └── injector/
├── evidence/
│   ├── INDEX.md
│   ├── physical_original/
│   ├── physical_repaired/
│   ├── synthetic_final/
│   └── negative_results/
└── archive/
    ├── pre_audit/
    ├── superseded_designs/
    ├── worklogs/
    └── audit/

MANIFEST.yaml should bind every major claim to:

commit:
p4_source:
p4_sha256:
compiler_version:
compile_flags:
artifact_sha256:
resource_report:
assembly_file:
setup_script:
evidence_directory:
analyzer:
analyzer_sha256:
verdict:
10. Ordered action plan
Release-blocking, no hardware required
Make R1–R3 unconditional in a canonical final P4.
Change every default program name to the final repaired program.
Correct report §13 to compile and run the final source.
Centralize D, B, H, ACK-bound and poll-rate validation.
Add reg_failopen to generic clean/reset verification.
Add SyncCounters to campaign reads.
Fix range(17) to include CF_BLOCK_REJECT.
Archive the final repaired BFA and correct resource-ledger links.
Rewrite CLAUDE.md, remove or replace RESUME_DEFENSE3.md, and archive the pivot note.
Delete empty evidence runs and create an evidence index.
Valuable hardware work, after release hardening
Final 10-stage core versus 11-stage telemetry parity run.
ACK-retirement boundary egress sweep.
Hardware-timestamped observer capture.
External-port R1/R3 injection when the topology permits it.
K-minimization sweep after the current K=64 result is frozen.
Final technical verdict

The central Defense 3 implementation is now a credible Tofino-1 research prototype for one plaintext, single-segment, separate-ACK DNP3 session. R1, E1, R2 and R3 form a coherent state machine, and the physical results are valuable.

The repository, however, still makes it too easy to:

compile the unrepaired program;
configure the unrepaired program by default;
bypass the parameter safety policy;
read unsynchronized counters;
follow obsolete project instructions;
mistake historical artifacts for final ones.

The next work should be a release-hardening and repository-pruning pass, not another broad relay campaign.