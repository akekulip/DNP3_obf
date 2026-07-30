1. Critical P4 defect: a RESPONSE marks the transaction before it is validated

This is the most serious finding.

What the code does

For any packet parsed as a solicited single-fragment DNP3 response on the relay-facing configured session, the class driver immediately prepares the pending-state transition:

meta.pkt_class = CLASS_RESP;
meta.tag_val   = TAG_PENDING_DELTA;

This occurs at P4 lines 1924–1932.

The stateful action then executes before the TCP sequence, acknowledgment and learned-port validation table:

meta.cur_gen = tag_read_or_mark.execute(0);

at lines 1973–1978.

tag_read_or_mark adds 0x50 whenever the current tag has its MSB set, converting:

0xCn→0x1n

The actual response-validation table is applied later:

tbl_state_decode.apply();

at line 1990.

Therefore, response state is mutated before the switch knows whether the response has:

the expected TCP sequence number;
the expected TCP acknowledgment number;
the learned master port;
the current transaction identity.
Consequence

A stale or mismatching response can cause this sequence:

Current transaction N+1 is active: reg_tag = 0xCn

Stale response N arrives with a wrong TCP sequence
    ↓
tag_read_or_mark changes reg_tag to 0x1n
    ↓
state_decode notices the sequence mismatch
    ↓
stale response is bypassed
    ↓
but the false pending marker remains

The legitimate response for N+1 can then arrive and find txn_active == 2. The implementation will treat it as a duplicate and suppress it at lines 2088–2122.

The delayed ACK later sees the pending marker and declines to retire the transaction. There may now be:

no response in Q_HOLD;
no future packet capable of retiring the transaction;
a legitimate response that was incorrectly discarded.

This can leave Defense 3 stuck.

Why the reported stale-response PASS is invalid

The report says that a stale response arrived during transaction N+1 and left the pending state unchanged. It claims this was established because the ACK later found the pending marker.

That inference is backwards.

The ACK finding a pending marker proves only that some response set the marker. It does not prove that the stale response left it unchanged.

Given the source order, the stale response itself can set the marker before being rejected. The reported test can pass only if one of these occurred:

the legitimate response had already marked the transaction before the stale response arrived;
packet-generator serialization changed the actual event order;
the stale packet did not traverse CLASS_RESP;
the analyzer failed to distinguish which response created the marker.

The report provides no raw event timestamps to resolve this contradiction.

Required repair

The marker write must be authorized by the complete response predicate.

Conceptually:

classify response
    ↓
validate seq + ack + learned port + DNP3 identity
    ↓
only if valid:
    atomically read/mark reg_tag

The current architecture performs the last two steps in the reverse order.

This defect invalidates the present claims for:

stale-response isolation;
exact duplicate identification;
pending-state integrity;
the “state machine is correct across its whole domain” conclusion.
2. Critical P4 defect: a stale zero-budget token can retire the current transaction

The report claims blocker termination priority is:

stale > deadline > budget

The action block uses that order at lines 2201–2212. But the state write occurs earlier, before this priority is evaluated.

What the code does

For every dequeued blocker with hdr.ib.seq == 0, the class driver sets:

meta.tag_val = TAG_INACTIVE;

at lines 1936–1940.

Then tag_rmw runs at line 1985 and writes TAG_INACTIVE into reg_tag.

Only later does tbl_state_decode determine whether the token belongs to the active generation. The action block may then correctly count it as stale, but the active transaction has already been retired.

Consequence

A blocker with:

foreign generation
budget == 0

can clear an unrelated current transaction.

The counter may report:

BLOCK_TERM_STALE

while the packet has already performed the budget-expiry state transition.

That violates:

generation isolation;
the documented stale-before-budget priority;
exact ownership of fail-open retirement;
the claim that only a current-generation token can affect current state.
Required repair

Fail-open retirement must be generation-qualified inside the atomic register operation:

if token_generation == stored_generation
and token_budget == 0:
    retire
else:
    do not write

A later MAU table cannot safely undo an earlier SALU write.

3. The legacy host-injected blocker path is an unnecessary attack surface

The final live implementation still contains:

else {
    /* legacy host-injected token path */
    to_block();
    ctr_fresh.count(CF_BLOCK_ENQ);
}

at lines 2053–2057.

The parser forces every frame with EtherType 0x88C1 into ROLE_BLOCK, regardless of whether it arrived from:

the packet-generator port;
the master port;
the relay port;
the replay port.

Therefore, an externally supplied 0x88C1 frame can enter the strict-priority blocker queue.

Combined with the zero-budget defect, an injected token can potentially:

clear the active generation;
disrupt an ACK hold;
create internal high-priority traffic;
force premature fail-open behavior;
interfere with subsequent transactions.

The report’s threat model is passive, but final defensive code should not retain a known active injection path merely for “A/B rollback.”

Required change

For the production build:

ROLE_BLOCK is admissible only when:
    ingress_port == PORT_PGEN
or:
    ingress_port == PORT_L for a returning token

Remove the legacy fresh host-token branch or compile it only under a separate microbenchmark flag.

4. The fail-open horizon is sized incorrectly for the tested D range

The report defines:

H=
r
BK
	​

=30.802 ms

This is the approximate time from blocker generation until budget exhaustion.

But the blocker reservoir starts shortly after the READ, while its deadline is:

t
ACK
	​

+D

Therefore, the correct normal-path constraint is approximately:

H>(t
ACK
	​

−t
READ
	​

)+D+t
detection
	​

+t
drain
	​

+t
tail
	​


The report compares H primarily against D, omitting the pre-ACK interval.

Direct contradiction

The source says the budget was sized around:

D = 3 ms

but the physical campaign uses:

D = 1, 2, 4, 8 and 16 ms

The report also says the control plane permits:

D <= 40 ms

At D=40 ms, a 30.8 ms budget must expire before the deadline even if the ACK arrives immediately.

Therefore, the advertised 40 ms operating range is not merely untested. It is incompatible with the configured budget.

Effect at D=16 ms

With H=30.8 ms, the remaining allowance for READ-to-ACK latency is approximately:

30.8−16=14.8 ms

before considering drain and safety margin.

The P4 source itself mentions a previously observed READ-to-ACK value around 22 ms. Under such a transaction:

22+16>30.8 ms

and fail-open would pre-empt the configured deadline.

The 80 transactions at D=16 apparently did not contain that extreme, but the configuration is not robust against the previously observed timing range.

Required correction

The control plane must enforce:

D
max
	​

<H−a
max
	​

−ϵ

or compute B from the selected D, a pre-registered ACK-latency bound and an RTO margin.

The report’s statement that the 40 ms boundary “blocks nothing already claimed” is wrong. It blocks correctness of the supported parameter range.

5. The reported stale-response test is not the only untested boundary race

E1 retires the transaction when the delayed ACK returns from the loopback and no response is pending.

A response arriving just after that register operation takes the direct forwarding path.

The implementation has not demonstrated the most dangerous narrow interval:

ACK has retired reg_tag
but ACK has not yet entered or left the master-facing output queue

A response arriving during this interval can be sent directly to the same output queue. Whether it can overtake the ACK depends on:

relative pipeline traversal;
output queue admission order;
ingress arbitration;
the distinction between ACK loopback-ingress time and actual egress commitment.

Gate 4B placed the response roughly 500 µs after ACK release. It did not test the nanosecond-scale retirement boundary.

A targeted sweep is still required around:

ACK release + 0 ns
ACK release + 32 ns
ACK release + 64 ns
ACK release + 128 ns
ACK release + 256 ns
ACK release + 512 ns
ACK release + 1 µs

The required measurement is the actual master-facing egress order, not only ingress timestamps.

6. The compiler warning is load-bearing, not cosmetic

Every supplied compile log reports:

out parameter 'meta' may be uninitialized when 'IgParser' terminates

along with two parser-loop warnings.

The parser intentionally does not initialize several fields in start, including:

role;
dir;
fwd_port;
port_ok;
gen_in;
dequeued;
is_pktgen;
synthetic state where applicable.

The source says it relies on “the compiler’s own metadata init” to supply zeros. But the compiler explicitly declines to prove this.

This is safety-critical because zero means:

bypass role;
inactive/default direction;
off-topology;
not dequeued;
not packet generated.

For a default or malformed parser path, undefined port_ok and fwd_port can determine whether a packet is dropped or forwarded.

Silicon success on the expected ports does not establish safe behavior for every parser exit.

Required repair

Assign every load-bearing field exactly once on every terminal parser path. A clean construction would use:

parser-local fields;
path-specific finalization states;
one final metadata assignment before accept.

The final build should not retain uninitialized_out_param.

The other two warnings about loop unrolling are explainable, but should still be documented.

7. The report miscounts the physically protected transactions

The campaign is described as:

6 arms×4 rounds×20 polls=480

The six arms are:

native;
D=1;
D=2;
D=4;
D=8;
D=16.

Only five arms run Defense 3.

Therefore:

5×80=400

transactions were protected by the mechanism.

The native 80 had no blocker reservoir and no ACK hold.

Yet §12.1 says:

“480 of 480 transactions, exactly 64 tokens each.”

That is impossible under the stated campaign.

The correct totals are:

480/480 campaign transactions responded;
400/400 defended transactions used Defense 3;
64 tokens per defended transaction;
5,120 tokens per defended arm;
25,600 admitted tokens across all five defended arms.

The report’s own state-machine partition correctly totals 400, confirming the counting error.

This error also appears in the title-page framing and final summary.

8. “All 80 transactions land on the same 32 µs constant” is false

For D=16 ms, the report gives:

median CLRT: 0.032 ms;
standard deviation: 0.012 ms;
maximum: 0.047 ms.

A sample with a 12 µs standard deviation and a 47 µs maximum is not 80 identical observations at 32 µs.

The defensible claim is:

The CLRT distribution compressed sharply around a median of approximately 32 µs.

The statements:

“all 80 land on the same constant”;
“flattened to a constant”;
“the entire cloud collapsed onto 32 µs”;

are rhetorical overclaims contradicted by the table.

The standard-deviation reduction is real:

0.012
2.854
	​

≈238

but compression is not equality.

9. Two different quantities are both called “release tail”

The report defines an internal release tail of approximately:

26 ns

This is measured between:

last blocker termination ingress timestamp
and
ACK loopback-return ingress timestamp

Later, the report calls the approximately:

32 µs

master-capture ACK-to-RESPONSE gap the “release tail.”

These differ by about three orders of magnitude and are not the same event.

They should be named separately:

internal post-drain ACK-return tail: approximately 26 ns;
externally captured ACK-to-RESPONSE gap: approximately 32–42 µs.

The second can include:

switch output queuing;
frame serialization;
link traversal;
NIC processing;
host capture timestamp behavior;
timestamp resolution or batching.

Calling both “release tail” makes the central timing result ambiguous.

10. The measurement point is not demonstrated to be the attacker’s wire view

Figure 1 says capture occurs “at exactly” the attacker’s observation point and that every number is what the attacker would obtain.

But the reproduction section says harness/block.py runs on the master and captures there. A host-side PCAP timestamp is not automatically a port-9 wire egress timestamp.

It can differ because:

outgoing READ timestamps may be recorded before NIC transmission;
incoming timestamps are recorded after NIC reception;
driver or kernel timestamping can introduce delay;
receive coalescing can alter apparent packet spacing;
the report says the capture has only approximately 1 µs resolution.

The internal registers are also not attacker-visible.

This matters because the report’s observed “32 µs floor” may partly be a capture-system artifact. A capable passive observer using a hardware tap or NIC hardware timestamps may observe a different distribution.

Required validation

Use at least one of:

a hardware-timestamped passive tap;
switch egress timestamps;
a calibrated external capture NIC;
a comparison of host software timestamps against hardware timestamps.

Until then, the report should say:

Measurements were taken at the master host interface, used as a proxy for the port-9 observer.

Not:

Every number is exactly what the attacker gets.

11. The core 9-stage implementation is not the implementation that produced the complete physical timing results

The report lists:

Build	Ingress
Core	9/12
Full telemetry	10/12
Synthetic	9/12

The physical decomposition requires reg_ts_last_block and reg_ts_last_term. Those exist only in the 10-stage full-telemetry build.

Therefore:

the 9-stage core has a compile/resource result;
the 10-stage instrumented build has the complete physical validation result.

The P4 says the added registers “cannot change behaviour” because they are write-only. That is too absolute for a timing system. Additional stateful operations can alter:

placement;
stage occupancy;
internal dependencies;
pipeline timing;
resource contention.

The critical path reportedly remained 8, which supports functional similarity, but it is not a proof of timing identity.

The publication must state:

Physical timing results were collected with the 10/12 instrumented variant. The functionally stripped variant compiles at 9/12 but was not used for the full timing decomposition.

A short physical parity run on the 9-stage core would close this gap.

12. The supplied compile logs do not prove the reported resource numbers

The supplied compile logs contain only:

source-line warnings;
parser-loop warnings;
0 errors, 3 warnings.

They do not include:

compiler version;
ingress stage count;
egress stage count;
critical path;
table count;
PHV use;
SALU instructions;
artifact hash.

Therefore, the package as supplied does not independently substantiate:

core: 9/12
full telemetry: 10/12
synthetic: 9/12
critical path: 8
SALU assembly identical across SDE versions

Those results may exist elsewhere, but they are not in these logs.

The report must package the corresponding:

mau.characterize.log;
resources.json;
context.json;
BFA sections;
compiler version output;
source and artifact hashes.
13. The statistical analysis uses transactions as though they were independent

The campaign has:

4 rounds per arm;
one TCP connection per 20-poll block;
80 transactions per arm.

The 80 observations are not 80 independent experimental units. Polls within one connection can share:

TCP state;
relay scheduler state;
cache state;
queue state;
clock drift;
host load;
connection-cold versus warm behavior.

The effective independent replication is closer to four blocks per arm, not 80 transactions.

Consequences

The report provides no:

block-clustered confidence intervals;
connection-level bootstrap;
repeated round-held-out validation;
mixed-effects model;
sensitivity analysis with the cold first poll excluded.

The single train/test split:

train on rounds 1–2
test on rounds 3–4

is better than fitting and scoring on the same data, but one split does not quantify uncertainty.

A more defensible analysis would use:

leave-one-round-out evaluation;
block bootstrap with connection as the resampling unit;
confidence intervals for AUROC and balanced accuracy;
per-round results.
14. Figure 7 compares quantities that are not commensurate

The figure plots on one percentage axis:

percentage of samples with CLRT below 0.1 ms;
AUROC-derived separability multiplied by 100.

These are not the same kind of metric.

For example:

25% collapsed
71.9% separability

does not justify the arithmetic statement that “detectability exceeds concealment.” One is a thresholded sample proportion; the other is a ranking statistic.

The qualitative conclusion that defended traffic is detectable can stand on the AUROC and held-out classifier alone. But the two values should not be compared numerically on one scale.

Recommended presentation:

Panel A: collapse proportion under a clearly justified threshold;
Panel B: AUROC with confidence intervals;
Panel C: held-out balanced accuracy.
15. “Concealment” is defined using an arbitrary 0.1 ms threshold

The report counts a transaction as concealed when:

CLRT<0.1 ms

This establishes that ACK and response are close together. It does not establish that device identity is concealed.

At D=4:

63/80 are called concealed;
CLRT separability from native is 0.966.

A feature that is 96.6% rank-separable from its native distribution is not concealed in the statistical sense. It has been transformed into a different, highly recognizable distribution.

Use more precise terms:

clamped or collapsed below the threshold for the 0.1 ms count;
device-fingerprint concealment only when a cross-device classifier fails.
16. The report cannot claim that the threat-model objective is met

The report correctly admits that it has:

one separate-ACK device;
no second device under the same defense;
no device confusion set;
no device-model classifier.

Yet it also says:

“The objective the threat model sets is met.”

and opens with:

“the timing fingerprint is genuinely destroyed.”

These claims are unsupported.

What is established is narrower:

The SEL-751’s CLRT distribution was strongly compressed under a sufficiently large fixed ACK delay.

What is not established:

whether two separate-ACK device models become indistinguishable;
whether ACK latency reveals the model;
whether other timing or size features preserve identification;
whether the same D works across devices;
whether a classifier trained across devices fails.

The report’s own §12.2 correctly says device anonymity cannot be answered. That caveat contradicts the headline and §11.2 conclusion.

17. Defense detectability is not the same as device identifiability

The report finds that native and defended SEL-751 traffic are readily separable. That proves the defense is detectable.

It does not prove that the relay model remains identifiable after every device uses the same defense.

These are different classification tasks:

Task A:
native SEL-751 versus defended SEL-751

Task B:
defended SEL-751 versus defended relay model X

The campaign measures Task A. The threat model concerns Task B.

The report criticizes the mechanism using a broader criterion after explicitly recording that doing so was an earlier project mistake.

Detection of a defense may still matter operationally, but it must be presented as a secondary leakage result, not as a direct refutation of device concealment.

18. D=1 ms is not a null control

A null intervention should have no treatment effect, such as:

defense disabled;
D=0;
native forwarding.

At D=1, the expected transformation is:

CLRT
out
	​

≈CLRT
native
	​

−1 ms

for transactions whose native CLRT exceeds 1 ms.

The table confirms an effect:

native median: 2.828 ms;
D=1 median: 1.799 ms.

That is approximately a 1 ms shift.

Therefore, D=1 is a:

sub-threshold or low-dose control for full collapse,

not a null control.

The actual null arm is the native arm.

19. The direct drain model has an off-by-one issue

The report compares the measured interval from the first token termination to the last token termination against:

r
K
	​


But the time between the first and last events in a sequence of K evenly spaced packets contains K−1 interpacket intervals:

t
last
	​

−t
first
	​

≈
r
K−1
	​


For K=64 and r=37.4 Mpps:

r
64
	​

=1711.2 ns

while:

r
63
	​

=1684.5 ns

The measured 1692–1696 ns is closer to the 63/r model.

This does not invalidate the measured drain. It means the report’s claim that the measurement independently verifies exactly K/r is mathematically imprecise.

Use:

drain≈
r
K−1
	​

+ϵ

while K/r can remain the approximate full reservoir circulation period.

20. “All four hardware traps were accepted without complaint” is false

Section 7 introduces four traps and says the compiler accepted all four without complaint.

But Trap 3 is:

a fifth RegisterAction produced a hard compiler error.

Therefore, it was not silently accepted.

Also, the unsigned sign test is not necessarily a compiler miscompile:

v < 8w0

where v is unsigned is semantically an unsigned comparison against zero. It should be false.

The problem is a type error in the program and insufficient diagnostics, not necessarily incorrect compiler semantics.

The report should distinguish:

confirmed silent target/compiler anomaly for the large constant;
programmer type error accepted as valid P4 for the unsigned comparison;
explicit hard compiler resource error for the fifth RegisterAction;
packet-generator scope behavior for the two-pipe timer.
21. The response is not bound to the DNP3 application sequence

The report calls the response marker “generation-bound” and says duplicate matching includes the DNP3 transaction identity.

However, for supported responses:

app_control is extracted;
its low-nibble sequence is stored in meta.gen_in;
but the response path does not compare it with reg_tag.

Instead, it performs a raw read of reg_tag and relies on:

TCP sequence;
TCP acknowledgment;
learned port;
active-domain state.

The code comment says application sequence cannot be used because a response may set CON and become 0xEn. But the parser rejects CON=1 as unsupported and admits only the 0xCn high-nibble domain.

Therefore, for the supported response subset, the low-nibble application sequence is available and could be checked.

The current report should not claim that DNP3 transaction identity is compared. It checks DNP3 framing class, not the request-response application sequence match.

22. The implementation is not specifically a Class-0 READ defense

The P4 parser checks:

function code == READ
application high nibble == 0xC
single transport segment
fixed configured TCP payload length

It does not parse or verify:

object group 60;
variation 1;
qualifier “all objects”;
DNP3 source or destination address for the protected operation.

Therefore, any supported DNP3 READ with the expected TCP payload length may arm Defense 3.

The physical harness may send only Class-0 READs, but the implementation is broader and less semantically specific than the report title suggests.

Correct wording:

Evaluated using Class-0 READ transactions.

Not:

The P4 identifies Class-0 READs.

23. Important unreported protocol constraints

The implementation is limited to:

Ethernet II without VLAN tags;
IPv4 only;
IPv4 IHL 5, no IP options;
no IP fragmentation;
TCP options up to 12 bytes for DNP3-bearing packets;
single DNP3 transport segment;
single application fragment;
solicited CON=0, UNS=0 responses;
one configured TCP session;
one active transaction globally;
fixed configured READ TCP payload length.

The report discusses segmentation but does not clearly disclose all the others.

Notably, pure ACK parsing supports TCP data offsets 5–15, but DNP3-bearing packets support only offsets 5–8. A valid response with more than 12 bytes of TCP options will bypass protection.

VLAN-tagged substation traffic will also bypass because the parser expects IPv4 directly after Ethernet.

24. The implementation does not support encrypted DNP3 traffic

The report argues that encryption does not remove timing leakage. That general observation can be correct, but the implementation requires plaintext access to:

DNP3 function code;
application control byte;
transport FIR/FIN bits;
response framing;
TCP fields.

End-to-end TLS, IPsec or another encapsulation prevents this P4 parser from identifying the Class-0 exchange unless the switch is placed at a trusted plaintext point.

The report must state:

Defense 3 operates on plaintext DNP3/TCP or at a point before encryption/after decryption.

It cannot simultaneously motivate the defense using encrypted traffic and imply that this implementation directly handles that traffic.

25. Session state is global and zero is a valid TCP sequence value

Every state register has size one. The mechanism therefore supports:

one configured session state;
one active protected transaction;
no independent per-flow indexing.

A second TCP connection matching the wildcard session entries can overwrite:

the learned master port;
the expected relay sequence;
the expected acknowledgment.

The concurrency limitation is broader than “one active transaction.” It is effectively one protected TCP connection at a time.

There is also a sentinel problem:

if (meta.seq_w != 32w0) { v = meta.seq_w; }

TCP sequence and acknowledgment numbers are modulo 2
32
. Zero is a valid sequence position after wrap-around. At that point, reg_exp_relay_seq silently refuses to update.

This is rare, but it contradicts claims of full-width exact tracking.

26. Duplicate-response suppression changes TCP reliability behavior

The repair deliberately drops a response retransmission while the first copy is parked.

That preserves ordering but creates a reliability tradeoff:

if the original queued response is later lost on the master-facing link;
and the duplicate was suppressed while the original was still queued;

the retransmission opportunity has been discarded.

TCP will eventually retransmit again after the transaction retires, but recovery can be delayed.

The report should explicitly state that the mechanism:

preserves bytes of forwarded original packets;
intentionally suppresses selected matching retransmissions;
does not preserve all packet-delivery behavior.

This also means the P4 header’s statement that “nothing on a protected session is ever dropped” is obsolete.

27. “Zero dropped packets” is imprecise

The mechanism deliberately drops:

blocker tokens at deadline;
tagged trigger clones;
stale tokens;
matching duplicate responses;
malformed/off-topology packets.

The campaign may have experienced:

zero queue drops;
zero unintended original host-packet drops;
zero duplicate-response suppressions on real relay traffic.

Those are defensible.

“Zero dropped packets” without qualification is false.

28. The source comments are materially out of date

The P4 header still says:

the program has never been loaded;
Defense 2 remains loaded;
the file answers only a compile-fit question;
every early and late response takes the hold queue;
no protected packet is ever dropped;
exactly one new register was added.

Later comments and the report describe physical validation, E1, direct late-response forwarding and duplicate suppression.

Specific stale statements include:

lines 27–29 and 108–113: never loaded;
lines 5–7, 50–53, 70–76: late responses always take the same loopback path;
lines 101–105: nothing is dropped;
lines 1093–1095: inactive is “not 0,” although it is 0;
lines 1822–1827: duplicate response forwarded as bypass, although it is now suppressed;
lines 1342–1359: unresolved TODO(silicon) items that have been measured.

This is not cosmetic. The comments currently make mutually incompatible architectural claims.

The implementation should be reduced to a clean final source file, with historical diagnostics moved into a separate engineering log.

This matters particularly because the project has already observed that source line changes can affect generated names and force artifact rebuilds.

29. The baseline file contains known-invalid data without a supersession warning

The supplied baseline still calls the n=100 corpus “steady” and reports:

maximum CLRT = 21.695 ms

The project later established that this maximum was a connection-cold first poll and that the corrected steady maximum was much lower. The PDF records that correction in its mistakes section, but the baseline file itself remains authoritative-looking.

It also uses “release tail” for an approximately 1.72 µs quantity, while the report uses that term for 26 ns and later 32 µs.

The baseline should be either:

corrected;
renamed SUPERSEDED_DEFENSE3_BASELINE.md;
or headed with a prominent supersession notice.

Otherwise, future analysis can silently reuse invalid calibration values.

30. The report’s strongest claims must be rewritten
Current claim

The timing fingerprint is genuinely destroyed.

Supported claim

On one SEL-751, a fixed ACK delay larger than the observed native CLRT compressed the observed CLRT distribution from an SD of 2.854 ms to 0.012 ms under the tested session and capture configuration.

Current claim

480 of 480 transactions, exactly 64 tokens each.

Supported claim

The campaign contained 480 completed transactions. Defense 3 was active for 400 transactions, with 64 admitted tokens per defended transaction.

Current claim

All 80 transactions landed on the same 32 µs constant.

Supported claim

At D=16 ms, the CLRT median was approximately 32 µs, with SD 12 µs and maximum 47 µs.

Current claim

The state machine is correct across its whole domain.

Supported claim

The Python state model passed 2,256 assertions and the observed normal-path physical exit counts were internally consistent. Full compiled-state correctness is not established, and two state-ordering defects remain in the supplied P4.

Current claim

Non-transaction traffic is not disturbed.

Supported claim

Three observed physical keepalive ACKs, and 61 prior captured examples used in offline predicate analysis, were not held.

Current claim

The hold is governed by D and nothing else.

Supported claim

Under the normal deadline path, the dominant hold component tracks D; the realized release also includes quantization, detection, blocker drain, output scheduling and capture-path effects.

31. Reproducibility and possible fabrication assessment

The PDF references a substantial evidence tree, but the supplied package does not include:

dsweep_blocks.jsonl;
per-transaction CSVs;
PCAP files;
physical smoke-test records;
analyze_dsweep.py;
analyze_observer.py;
test_tag_domain.py;
assert_salu_asm.py;
control-plane setup code;
setarm.py;
block.py;
queue and port readbacks;
BFA;
bfrt.json;
resource reports.

Therefore, I cannot independently confirm:

480 responses;
64 tokens per defended transaction;
0 fail-open events;
0 queue drops;
the AUROC values;
the held-out thresholds;
the exact compiler resources;
the stated SALU instructions;
the 2,256 assertions.

That absence is not evidence of fabrication. It means the report’s results are presently unsupported by the shared artifact.

The closest issue to a potentially fabricated or mis-scored conclusion is the stale-response PASS, because its interpretation conflicts directly with the P4 execution order. Raw packet and register timestamps are required before that claim can be retained.

32. What remains credible and valuable

Several parts are strong:

The central queue construction is plausible and well motivated. The original ACK is preserved in Traffic Manager memory rather than reconstructed.
The trigger-latency investigation is strong. Separating generator-run occupancy from production request-trigger latency was the correct diagnosis.
The E1 single-register state encoding is elegant. Encoding inactive, active-unmarked and active-pending in disjoint domains is resource-efficient.
The report records negative evidence. The SALU constant issue, unsigned comparison, duplicate overtaking, missing-response state leak and first physical failure are documented rather than hidden.
The campaign design interleaves arms. That is better than running each D in a separate long session.
The report correctly admits major scope limits. It does not claim multi-segment support, minimal K, concurrency or device anonymity in its limitations section.

The normal-path finding can likely survive:

A Tofino-1 strict-priority blocker reservoir can hold the original SEL-751 pure ACK for a configurable deadline and preserve ACK-before-RESPONSE ordering in sequential, single-segment Class-0 polling under the tested laboratory conditions.

That is already a meaningful result. The stronger security and whole-state correctness conclusions do not survive the current audit.

Required disposition

Do not use the current report as a final paper source until these are completed, in order:

Fix response marking so no state changes before full response validation.
Make fail-open retirement atomically generation-qualified.
Remove the host-injected production token path.
eliminate the uninitialized metadata warning.
Re-run stale-response-before-current-response, wrong-port response and wrong-ACK response tests.
Test the ACK-retirement boundary at sub-microsecond offsets.
Recalculate the budget from a
max
	​

+D, and remove or reduce the 40 ms claim.
Validate a short physical subset using the stripped 9-stage core build.
Package the raw campaign data, PCAPs, analyzers, BFA and resource reports.
Rewrite the conclusions around CLRT compression, not destruction or device anonymity.
Correct the 400-versus-480 count and the 32 µs “constant” claim.
Reanalyze statistics with connection-level blocking and confidence intervals.
Reconcile the report’s “outstation 0” with the previously established SEL configuration of outstation address 10.
Add a complete bibliography and source every prior-work, protocol and deployment claim.