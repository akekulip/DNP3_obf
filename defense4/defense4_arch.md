Defense 4: Unified READ and SBO Size-and-Timing Obfuscation Architecture

Defense 4 should be defined as a transaction-level obfuscation system, not simply another timing defense.

It combines:

The response-event ACK gate from Defense 1.
The ACK-relative RESPONSE gate from Defense 2.
The deadline-based ACK gate from Defense 3.
A size-transformation plane.
A canonical transaction schedule that makes READ and full CROB Select-Before-Operate produce the same observable size, timing, count, and direction pattern.

The critical target is:

Obs(READ)≈Obs(SBO)

where:

Obs(x)=[(d
i
	​

,S
i
	​

,t
i
	​

)]
i=0
L−1
	​


and each visible unit has:

Direction d
i
	​

Observer-visible size S
i
	​

Release time t
i
	​

A fixed position within the public transaction template

Padding alone cannot satisfy this requirement. READ and SBO differ in packet count and direction sequence, even if every individual packet has the same size.

1. Supported DNP3 workflows

Defense 4 must recognize and protect both operation families as complete workflows.

READ

A READ exchange may contain:

Master-to-outstation DNP3 READ request.
Optional outstation-to-master pure TCP ACK.
One or more DNP3 RESPONSE fragments.
Master-to-outstation TCP acknowledgments.
An optional DNP3 CONFIRM only if the response requests application confirmation.
CROB Select-Before-Operate

A full SBO transaction contains:

Master-to-outstation SELECT request.
Optional pure TCP ACK.
Outstation-to-master SELECT RESPONSE.
Master-to-outstation OPERATE request.
Optional pure TCP ACK.
Outstation-to-master OPERATE RESPONSE.
Optional DNP3 application confirmations when requested.

A SELECT RESPONSE is not itself a DNP3 CONFIRM. CONFIRM is a separate optional application function.

The current DIRECT_OPERATE corpus cannot stand in for SBO. We need real:

SELECT→SELECT RESPONSE→OPERATE→OPERATE RESPONSE

traffic.

2. Complete architecture

The system has six major components.

A. Protocol classifier

The classifier identifies:

DNP3 READ
DNP3 SELECT
DNP3 OPERATE
DNP3 RESPONSE
Optional DNP3 CONFIRM
Pure TCP ACK
TCP ACK combined with DNP3 data
DNP3 transport and application fragments
Direction of communication

It also extracts the fields needed to associate packets with the correct operation and phase.

B. Transaction manager

The transaction manager maintains one logical transaction across all related packets.

For READ, it records:

READ request→ACK→READ response fragments

For SBO, it records:

SELECT phase→OPERATE phase

The SELECT and OPERATE requests may have different application sequence numbers. Therefore, the architecture needs a higher-level SBO transaction identifier that links both phases.

C. Canonical transaction mapper

The mapper assigns real packets to a public slot pattern that is identical for READ and SBO.

D. Size encoder

The encoder converts every real packet or fragment into a selected public size state.

E. Timing scheduler

The scheduler releases each public unit according to an event, deadline, predecessor, or immediate-release rule.

F. Trusted decoder

The decoder:

Removes the outer encapsulation.
Discards filler cells.
Reassembles supported cell sequences.
Restores the original packet.
Delivers only real DNP3/TCP traffic to the endpoint.

Dummy traffic must never reach the relay or master as fake DNP3 commands.

3. The canonical READ/SBO transaction template

A useful abstract template contains eight public slot groups.

A slot group can contain one or more fixed-size cells. We should not assume that every group maps to exactly one Ethernet packet.

Slot	Direction	READ mapping	SBO mapping
0	Master → Outstation	READ request	SELECT request
1	Outstation → Master	Real ACK or filler	Real ACK or filler
2	Outstation → Master	READ response block	SELECT response
3	Master → Outstation	TCP ACK, optional CONFIRM, or filler	TCP ACK, optional CONFIRM, or filler
4	Master → Outstation	Filler	OPERATE request
5	Outstation → Master	Filler	Real ACK or filler
6	Outstation → Master	Filler or additional READ-response capacity	OPERATE response
7	Master → Outstation	TCP ACK, optional CONFIRM, or filler	TCP ACK, optional CONFIRM, or filler

The observer should see the same:

Number of slot groups
Number of cells per group
Direction sequence
Cell sizes
Nominal release times

Unused READ slots must contain outer filler traffic. The receiving trusted edge recognizes and discards this filler.

This provides bounded transaction-level cover. It does not require continuous chaff when no transaction exists. Consequently, transaction occurrence and transaction frequency remain visible unless continuous cover is added later.

Causality constraint

The schedule cannot release the OPERATE request before the master actually generates it.

Therefore:

t
slot,OPERATE
	​

≥t
SELECT-RESP,delivered
	​

+t
master processing
	​


If the actual OPERATE arrives after its assigned slot, the architecture needs an explicit policy:

Use the next compatible slot.
Abort the protected template and fail open.
Start a new template and record a schedule miss.

It must never invent or replay a real OPERATE command.

4. Generalizing Defenses 1, 2, and 3

Defense 4 should implement a common release-gate primitive rather than three hard-coded P4 paths.

For each protected phase p, configure:

Θ
p
	​

=(M
A,p
	​

,D
A,p
	​

,G
R,p
	​

,T
FO,p
	​

)

where:

M
A
	​

 selects the ACK release mode.
D
A
	​

 is the desired ACK hold when deadline mode is selected.
G
R
	​

 is the post-ACK response-delay parameter.
T
FO
	​

 is the bounded fail-open deadline.

The ACK release modes are:

IMMEDIATE
MATCHING_RESPONSE_EVENT
ABSOLUTE_DEADLINE
Defense mapping
Configuration	ACK gate	RESPONSE gate
No timing shaping	Immediate	Immediate, subject to order
Defense 1	Matching RESPONSE event	Release after ACK
Defense 2	Immediate	ACK-relative deadline G
Defense 3	Deadline D	Release after ACK
Defense 4 combined mode	Event or deadline	Slot deadline and/or ACK-relative deadline

Defense 4 does not add the three delays together. It supports their release conditions through one configurable engine.

ACK release predicate

Conceptually:

ACK
release
	​

=match∧[
	​

M
A
	​

=IMMEDIATE
∨(M
A
	​

=EVENT∧response_seen)
∨(M
A
	​

=DEADLINE∧now≥T
A
	​

)
∨now≥T
FO,A
	​

]
	​


For Defense 1, the fail-open deadline prevents an ACK from remaining held forever if the matching response never arrives.

RESPONSE release predicate
RESP
release
	​

=match∧ack_gone∧[now≥T
R
	​

∨M
R
	​

=IMMEDIATE∨now≥T
FO,R
	​

]

The ack_gone condition maintains ACK-before-RESPONSE ordering.

Timing equations

For phase p:

t
ACK,out,p
	​

≈max(t
ACK,ready,p
	​

,T
A,p
	​

)+ϵ
A,p
	​

t
RESP,out,p
	​

≈max(t
RESP,ready,p
	​

,T
R,p
	​

,t
ACK,out,p
	​

+δ
ord
	​

)+ϵ
R,p
	​


where:

ϵ
A
	​

 and ϵ
R
	​

 include residual blocker drain and pipeline delay.
δ
ord
	​

 is the minimum ordering guard.
Neither release should be described as occurring “exactly” at the deadline.
Response anchor

For combined shaping, the clean semantic definition is:

T
R
	​

=A
ref
	​

+G
R
	​


The preferred A
ref
	​

 is either:

The actual ACK release event, or
The scheduled ACK release point plus a characterized drain correction.

Using the native ACK arrival timestamp is acceptable as a compatibility mode for Defense 2, where the ACK is forwarded immediately. It is not automatically equivalent when Defense 3 also delays the ACK.

Determining whether Tofino-1 can observe the true ACK dequeue event economically is a major research item.

5. Queue-resident timing subarchitecture

For one reverse-path phase and one scheduler domain, the proposed order remains:

Q
ACK-BLOCK
	​

>Q
ACK-HOLD
	​

>Q
RESP-BLOCK
	​

>Q
RESP-HOLD
	​


Its behavior is:

Q_ACK_BLOCK keeps the ACK gate closed.
The real ACK stays queue-resident in Q_ACK_HOLD.
Q_RESP_BLOCK is already populated but cannot receive service while the ACK blocker is active.
The real response stays in Q_RESP_HOLD.
When the ACK condition becomes true, ACK blocker tokens terminate.
The ACK leaves.
The response blocker becomes dominant.
When the response condition becomes true, the response leaves.
Important implementation rules
The response blocker must be primed before the ACK blocker ends.
Deadlines must use absolute timestamps.
Pass counts should only provide bounded fail-open behavior.
Internal blocker tokens must never leave the internal scheduler path.
Real ACKs and responses remain in hold queues. They do not continuously recirculate.
Every token must carry a generation or equivalent transaction-isolation value.
Stale tokens must not affect a later transaction.
The controller may install policy and initialize the system, but it must not participate in per-packet release.
Four queues are not the complete Defense 4

These four queues schedule the reverse-path ACK and RESPONSE for one phase.

Full READ-versus-SBO shaping also needs master-to-outstation scheduling for:

Initial READ or SELECT
OPERATE
TCP acknowledgments
Optional application CONFIRMs
Master-direction filler cells

Because the two directions use different output ports, the design can use a scheduler bank on each protected egress direction. We should formally derive the smallest forward-path queue structure rather than assuming that all eight logical queues must share one port.

Concurrency limitation

Shared FIFO queues cannot selectively release Transaction 1 while leaving Transaction 2 held behind it.

The first Defense 4 implementation should therefore declare:

One active protected transaction per scheduler domain.

For additional concurrency, we must investigate:

Admission control and serialization
Multiple queue banks
Queue-bank allocation
Per-flow scheduler domains
Safe bypass when no bank is available

Registers alone cannot remove a specific packet from the middle of a shared FIFO.

6. Size transformation for READ and SBO
Public size pattern

Defense 4 should use:

P=[S
0
	​

,S
1
	​

,…,S
L−1
	​

]

where S
i
	​

 is the visible size assigned to public slot i.

A multi-size public pattern can reduce overhead compared with padding every unit to one extremely large size. However, READ and SBO must use the same public pattern within the declared protection profile.

Padding formula

For a public cell of size S
i
	​

:

C
i
	​

=S
i
	​

−H
outer
	​


where C
i
	​

 is the payload capacity and H
outer
	​

 is the outer encapsulation overhead.

For an inner unit of length L
i
	​

:

pad
i
	​

=C
i
	​

−L
i
	​


This is valid only when:

0≤L
i
	​

≤C
i
	​

What SBO padding must cover

SBO padding must include all of the following:

SELECT request
SELECT RESPONSE
OPERATE request
OPERATE RESPONSE
Pure TCP ACKs
TCP ACKs carrying data
Optional DNP3 CONFIRMs
Multiple-CROB request and response sizes

Padding only the OPERATE response would leave the SELECT and OPERATE request sizes exposed.

The number of CROBs must also fall within a declared envelope:

1≤C
CROB
	​

≤C
max
	​


All supported CROB counts should produce the same public slot capacity and cell count. Otherwise, the number of CROBs remains inferable.

READ size support

READ responses can be substantially larger than SBO responses. The architecture must declare a supported READ envelope, such as:

Maximum inner size
Maximum DNP3 application fragments
Maximum DNP3 link frames
Maximum TCP segments
Maximum outer cells per response window

The previously tested 128-byte state cannot be treated as universal. The physical SEL response was already larger than that state, and large READ responses can be much larger.

Frames that exceed a size state

Padding cannot shrink a packet.

If:

L
i
	​

>C
i
	​


Defense 4 needs one of these policies:

Map the packet to a larger public size state.
Use packet boundaries already produced by TCP/DNP3 and pad each existing segment.
Cellize the inner packet across multiple outer cells.
Fail open or use a declared overflow profile.

The first implementation should not claim arbitrary splitting. Tofino-1 cannot be assumed to provide general payload segmentation and reassembly without dedicated feasibility work.

Fixed cell size is not enough

If a READ response uses six cells and an SBO response uses one cell, the cell count reveals the operation.

Therefore, the template must also normalize the number of public cells:

N
visible,i
	​

=N
i
∗
	​


Unused capacity is filled with outer dummy cells.

Why outer encapsulation is required

Adding bytes after the original IP packet does not hide:

ip.len
TCP payload length
DNP3 length
Potentially the original application structure

True size concealment requires an outer representation whose visible length is independent of the inner packet length.

This implies:

trusted encoder→observable link→trusted decoder

For the lab, one Tofino can potentially emulate the two boundaries using separate physical ports and an observable external loop. A deployment would normally require a trusted function at each end of the protected link.

7. Plaintext limitation

If an observer can read unencrypted DNP3 function codes, the observer can directly see:

READ
SELECT
OPERATE
RESPONSE
Object groups and variations
CROB contents and count
Link and application addresses

In that case, Defense 4 hides side-channel fingerprints but not operation semantics.

Therefore, the strong claim:

“The observer cannot distinguish READ from SBO”

requires an encrypted or otherwise opaque inner representation on the protected link.

Without confidentiality, the defensible claim is:

Defense 4 reduces the size, timing, packet-count, and direction-pattern differences associated with READ and SBO.

This distinction must appear in the threat model and paper claims.

8. Transaction state required in Tofino

A bounded transaction entry should contain at least:

State	Purpose
valid	Indicates an active entry
generation	Prevents stale packet and token reuse
flow_tag	Validates the bidirectional flow
operation	READ or SBO
phase	READ, SELECT, or OPERATE
app_seq	Correlates DNP3 request and response
tcp_marker	Correlates pure or combined ACK behavior
size_profile	Selects P and cell capacities
slot_bitmap	Tracks filled and transmitted slots
ack_seen	Records ACK arrival
response_seen	Drives Defense 1
ack_gone	Enforces ordering
T_A	ACK deadline
T_R	RESPONSE deadline
fail_open_time	Bounds state and packet residence
error_flags	Records collision, timeout, or overflow
Matching requirements

The key should combine, as feasible:

Canonicalized TCP flow
DNP3 master and outstation addresses
DNP3 application sequence
Direction
Operation phase
TCP sequence or ACK evidence
Generation identifier

For SBO, the architecture must link SELECT and OPERATE using transaction state. Application sequence alone is insufficient.

For multiple CROBs, we must determine whether Tofino can safely parse and validate the complete object list. A bounded maximum may be necessary.

9. Cases that the primitive must handle

The implementation and evaluation must include:

Pure TCP ACK present
Pure ACK absent
ACK combined with DNP3 data
Response arrives before ACK release
Multiple response fragments
Multiple TCP segments
TCP retransmission
Duplicate request
Duplicate response
Out-of-order packet
SELECT failure
No OPERATE after successful SELECT
OPERATE arrives after its public slot
Optional DNP3 CONFIRM
TCP FIN or RST during a transaction
State-table collision
Unsupported size
Fail-open deadline
Token expiry
Stale-generation token
Queue overflow
Concurrent transaction attempt

When no native pure ACK exists, the public template may still transmit a filler ACK slot. The response gate must then anchor to the scheduled public ACK slot or another configured predecessor, not wait forever for a nonexistent native ACK.

10. SBO-specific timing safety

SBO adds a critical timing constraint. The outstation may expire the SELECT state before the OPERATE reaches it.

The total path must satisfy:

D
SELECT-response
	​

+D
master processing
	​

+D
OPERATE scheduling
	​

+D
network
	​

<T
select timeout
	​


The exact timeout is device and configuration dependent. We must measure or obtain it for each test target.

This means a single D or G value should not automatically apply to every phase. Defense 4 needs phase-specific settings:

(D
A,READ
	​

,G
R,READ
	​

)
(D
A,SELECT
	​

,G
R,SELECT
	​

)
(D
A,OPERATE
	​

,G
R,OPERATE
	​

)

The public slot schedule must also remain below:

TCP retransmission thresholds
Master application timeouts
Outstation response timeouts
SBO selection timeout
Operational latency requirements
11. What we must research before freezing the design
Research question 1: Exact threat model

We must specify:

Observer location
Whether DNP3 content is encrypted
Visible protocol layers
Whether the observer sees both directions
Whether transaction start times may remain visible
Whether we hide only READ versus SBO or also CROB count and device identity
Research question 2: Real READ and SBO corpus

Collect true traces for:

READ with different object groups and response sizes
SELECT with 1, 2, 4, 8, and other supported CROB counts
OPERATE with the same CROB sets
Successful and rejected SELECT
Successful and rejected OPERATE
Optional application confirmation
Different devices and TCP stacks
Pure, delayed, and piggybacked ACK behavior
Fragmented and multi-segment responses

The existing DIRECT_OPERATE corpus is not sufficient.

Research question 3: Public template design

Determine:

Minimum number of slot groups
Direction of each slot
Size S
i
	​

 of each slot
Number of cells in each slot
Slot offsets τ
i
	​

Acceptable filler overhead
Overflow behavior
Missed-slot behavior

We should optimize the template from measured traces rather than select arbitrary sizes.

Research question 4: Padding mechanism

Test whether Tofino-1 can:

Add the necessary outer headers
Produce exact observable frame sizes
Recalculate required checksums
Preserve original bytes
Remove padding at the trusted decoder
Stay within MTU
Support several size states without excessive stages or PHV use
Research question 5: Larger-packet handling

Determine whether Defense 4 will support:

Only existing packet segmentation
A finite set of larger size states
True outer cellization
Reassembly
A declared maximum READ profile

True switch-based splitting should remain unclaimed until implemented.

Research question 6: Release anchor

Compare:

Native ACK arrival
Scheduled ACK deadline
ack_gone transition
Actual dequeue observation, if feasible

The evaluation should quantify how each anchor affects output CLRT and jitter.

Research question 7: Concurrency

Measure:

Natural transaction concurrency per DNP3 association
Head-of-line blocking
Required number of scheduler banks
Queue and register cost per bank
Behavior when all banks are occupied
Research question 8: External filler generation

Determine whether bounded filler should use:

Packet generator templates
Triggered clones
Recirculated outer templates

Pktgen-generated filler must carry safe session and slot information. Internal blocker tokens must remain separate from externally visible filler.

Research question 9: Two-edge coordination

If the encoder and decoder use different switches, determine:

How they share transaction IDs
Whether clocks require synchronization
Whether schedules use absolute or event-relative time
How the decoder distinguishes real and filler cells
How loss and reordering affect restoration
Research question 10: Resource feasibility

Compile and measure:

Ingress and egress stages
SRAM and Map RAM
Stateful ALUs
PHV containers
Queue count
Priority levels
Register width and depth
Recirculation bandwidth
Token rate
Queue occupancy
External filler bandwidth

The stripped Defense 2 core should remain the resource baseline.

12. Implementation sequence
Phase 0: Freeze the contract

Before changing P4, write a Defense 4 specification containing:

Threat model
Supported READ/SBO envelope
Public template P,τ
ACK and response release modes
Concurrency assumption
Failure policy
Exact observer-visible length definition
Phase 1: Obtain the missing corpus

Generate and capture real READ and full SBO traffic.

Do not run an actual OPERATE on the physical SEL relay unless the selected control point is approved and safely isolated. Start with an OpenDNP3 or equivalent controlled outstation, then use authorized physical equipment.

Phase 2: Build an offline transaction oracle

Create a parser that annotates each captured packet with:

Transaction ID
READ, SELECT, or OPERATE phase
Packet role
Direction
Inner and outer lengths
ACK association
Fragment number
Expected public slot

Use it to test candidate templates before consuming Tofino resources.

Phase 3: Produce the stripped Defense 2 baseline

Retain:

ACK-relative deadline
Queue-resident response hold
Blocker expiry
Fail open
Exact transaction matching
Cleanup
Token isolation
Lightweight counters

Compile it and record the actual resource baseline.

Phase 4: Implement the unified release engine

Create one P4 program that selects:

Immediate release
Response-event release
Deadline release
Predecessor-plus-offset release

First reproduce Defense 1, Defense 2, and Defense 3 individually from the same binary.

Phase 5: Implement size encoding

Start with a bounded padding profile:

No arbitrary splitting
No universal 128-byte claim
Exact outer size states derived from corpus
Decoder restores byte-identical original packets
Unsupported frames use an explicit fallback
Phase 6: Implement the READ/SBO template

Add:

Slot tracking
Phase progression
Master- and outstation-direction scheduling
Bounded filler slots
SELECT-to-OPERATE linkage
Missing-phase handling
Slot-miss handling
Phase 7: Integrate size and timing

Test the actual order:

classify→map to slot→encode size→hold→release→decode

This produces the first real Defense 4 implementation.

Phase 8: Add robustness and limited concurrency

Only after the single-transaction design passes should we add:

Multiple scheduler banks
Admission control
Retransmission handling
Collision handling
Larger response profiles
More devices
13. Required evaluation
Functional correctness

Verify:

READ returns identical measurements.
SBO preserves SELECT and OPERATE semantics.
Decoded bytes match the original packets.
No filler reaches an endpoint.
ACK always precedes its matching response.
SELECT response precedes OPERATE.
No transaction crosses generations.
Fail-open releases traffic without corruption.
Size protection

Measure at the protected-link observer:

Ethernet frame length
IP length
TCP payload length
Cell count
Burst size
Direction sequence
Total bytes per transaction

READ and SBO should follow the same declared public pattern.

Timing protection

Measure:

Request-to-ACK delay
ACK-to-response CLRT
SELECT-response-to-OPERATE delay
Inter-cell spacing
Release jitter
Deadline miss rate
Residual blocker-drain offset
Cold and warm behavior
Joint leakage

Do not evaluate size and timing separately only.

Train an attacker using:

Sizes
Directions
Packet counts
Interarrival times
Burst lengths
Transaction duration
TCP flags
Fragment counts

Report:

Classification accuracy
ROC-AUC
Mutual information estimates
Confidence intervals
Cross-device generalization

Use these configurations as ablations:

Unprotected
Size only
Defense 1 only
Defense 2 only
Defense 3 only
Defense 4 without filler
Full Defense 4
Performance and safety

Report:

Added latency
Bandwidth overhead
Filler overhead
Retransmissions
DNP3 timeouts
SBO selection failures
Throughput
Packet loss
Queue occupancy
Recirculation load
Tofino resources
14. Exact current evidence boundary

At present:

Defense 1 has a controlled Tofino feasibility result.
Defense 2 has the queue-resident HOLD_RESPONSE result, including the Part 12 200/200 campaigns and a narrow live-inline result.
Defense 3 still requires a clean evidence chain before strong claims.
The 128-byte size work is a synthetic pad-only microbenchmark.
The size corpus did not contain true SELECT-to-OPERATE SBO.
Arbitrary splitting, reassembly, public filler scheduling, two-edge restoration, and full READ-versus-SBO normalization are not yet implemented.

Therefore, none of the existing results alone constitutes Defense 4.

Defense 4 becomes demonstrated only when:

A real READ and a real full SBO transaction pass through the same implementation, preserve their original endpoint behavior, and produce the same declared observer-visible size, count, direction, and timing template within a defined workload envelope.

The immediate next step should be to freeze the Defense 4 contract and collect the missing true SBO corpus. Without those traces, we cannot defensibly choose the padding sizes, slot count, direction template, phase deadlines, or supported CROB envelope.