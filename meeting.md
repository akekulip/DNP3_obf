Weekly Research Meeting Notes

Date: July 21, 2026
Attendees: Dr. Hui Lin and Philip Akekudaga
Project focus: Timing and packet-size obfuscation for DNP3 traffic using a Tofino programmable switch

1. Main outcome of the meeting

The research direction is now:

Focus only on Case A, where the pure TCP ACK and the DNP3 response are separate.
Use the SEL-751 as the primary device.
Continue implementation on the Tofino switch.
Keep the existing recirculation implementation as a valid feasibility result.
Develop a more defensible queue-based timing mechanism inspired by ditto: WAN Traffic Obfuscation at Line Rate.
Begin writing the paper immediately.
Move from capture replay to the physical SEL-751 as soon as the device connection is working.
2. Device traffic cases
Case A: Separate ACK and response

Observed in the SEL-751 traffic.

DNP3 request
      ↓
Pure TCP ACK
      ↓
DNP3 response

This case provides two packets whose timing difference can be measured and manipulated.

The Formby fingerprinting feature is:

ACK-to-response time

This is the only case where the term CLRT should be used.

Case B: Combined ACK-bearing response

Observed mainly in:

AB1400
ION7550
DNP3 request
      ↓
One packet containing:
TCP ACK + DNP3 response

There is no separate ACK.

Case B will not be implemented now. It remains a later extension.

3. The two defenses under Case A

Dr. Lin confirmed that these are the two scenarios to study.

Defense 1: Delay the ACK

Native behavior:

Request → ACK ───────── Response

Defended behavior:

Request ───────── ACK → Response

Mechanism:

The switch identifies the pure TCP ACK.
The ACK is delayed.
The DNP3 response remains close to its natural release time.
The ACK-to-response gap becomes smaller.

Purpose:

Reduce the timing feature used by the Georgia Tech/Formby fingerprinting method.
Avoid adding a large delay to the DNP3 response.

Your current Tofino implementation already proves this mechanism using recirculation.

Defense 2: Delay the response

Native behavior:

Request → ACK ───── Response

Defended behavior:

Request → ACK ───────────────── Response

Mechanism:

The switch forwards the pure ACK normally.
The DNP3 response is delayed.
The response is released according to a selected timing pattern or target.

Purpose:

Increase or normalize the visible ACK-to-response timing.
Make the output timing less dependent on the native SEL-751 processing time.

Limitation:

It adds response latency.
The timing target must be supported by a defensible policy, not selected arbitrarily.
4. Baseline SEL-751 analysis

You showed the native SEL-751 timing cluster extracted from the original device traces.

The main cluster appeared around:

approximately 13 ms;
measured between the pure TCP ACK and the DNP3 response.

Dr. Lin asked you to verify the units carefully.

Required correction

The unit is:

milliseconds

Not microseconds.

The slide and paper should state:

The SEL-751 native ACK-to-response timing forms a stable cluster around 12 to 13 ms.

Before using the value in the paper, verify:

the number of transactions;
the median;
the interquartile range;
the 10th and 90th percentiles;
outliers;
whether both SEL-751 captures produce the same distribution.
5. Decision about the software implementation

You initially investigated TCP sockets, eBPF, and kernel-level packet timing.

Dr. Lin’s direction is now clear:

Do not spend more time modifying Linux TCP ACK behavior.
Do not attempt to make the final defense dependent on a particular operating system or kernel.
Do not continue kernel configuration work.
Use the Tofino switch as the implementation platform.

The software work is still useful as:

an early feasibility study;
a debugging environment;
a way to understand TCP behavior;
a reference implementation.

It is not the final deployment design.

A correct paper statement is:

We first evaluated the timing policies using live TCP replay and host-based packet scheduling. We then moved the defense into the network data plane to avoid requiring changes to legacy industrial devices or their operating systems.

6. Current Tofino recirculation result

You explained that the Tofino currently performs Defense 1 by recirculating the pure ACK.

Current workflow:

The master sends a DNP3 request.
The outstation sends a pure TCP ACK.
The Tofino identifies the matching ACK using TCP acknowledgment information.
The ACK enters a recirculation loop.
The corresponding DNP3 response arrives.
The switch releases the ACK.
The response follows immediately afterward.

This reduces the ACK-to-response gap to a very small hardware delay.

What Dr. Lin accepted
Recirculation is a valid way to demonstrate feasibility.
The implementation is useful and should not be deleted.
The current results show that the packet timing can be changed in the Tofino data plane.
What Dr. Lin questioned

He does not consider recirculation the final preferred timing mechanism because:

its delay may vary with switch load;
the number of passes is not necessarily deterministic;
recirculation consumes internal bandwidth;
latency may change when other traffic uses the switch;
it is harder to justify as a predictable timing policy.

The current recirculation implementation should therefore remain as:

Feasibility implementation and comparison baseline

It should not be discarded.

7. Queue-based direction from Ditto

Dr. Lin wants the next implementation to study the queue and scheduling mechanism used by Ditto.

Ditto does not delay traffic by repeatedly circulating every real packet until a timer expires. It shapes outgoing traffic according to a predefined pattern using:

Traffic Manager queues;
priority scheduling;
round-robin scheduling;
fixed output rates;
loopback for the second queueing stage;
chaff packets when no real packet is available.

Each pattern state has:

a high-priority queue for real packets;
a low-priority queue containing chaff packets.

The outputs are then scheduled in round-robin order so that outgoing packet sizes and timing follow the predefined pattern. Ditto implements the two-level queue structure by sending traffic through the switch twice using loopback ports.

Important distinction

Your current implementation:

Recirculates the same ACK or response repeatedly
until an event or deadline is reached.

Ditto:

Places packets into Traffic Manager queues
and releases packets according to a predefined output pattern.

These are related but different approaches.

8. What needs to be adapted from Ditto

You should not reproduce the whole Ditto system.

The required task is to extract the relevant timing principles and adapt them to DNP3 Case A.

Relevant Ditto components

Study these parts:

pattern definition;
queue selection;
priority queues;
fixed queue rates;
round-robin scheduling;
two-pass loopback architecture;
timing behavior under different traffic loads;
packet delay and reordering;
resource use;
the effect of queue-rate accuracy.
Components that may not be required initially

The first timing prototype may not need:

full packet padding;
full chaff generation;
multiple packet-size states;
several WAN links;
100 Gbps traffic shaping.

Begin with the smallest queue pattern that can demonstrate predictable DNP3 timing.

9. Important issue found in the Ditto paper

The queue approach is likely more defensible than uncontrolled recirculation, but it is not automatically perfectly deterministic.

Ditto states that current switch shapers maintain their configured rates on average, and short bursts can still occur. The paper observed that inaccurate queue-rate control could contribute to packet drops at high loads.

Therefore, the new work must experimentally compare:

recirculation delay;
queue-based delay;
queue delay under background traffic;
timing variance;
packet loss;
reordering;
operational latency.

Do not assume that the queue is deterministic merely because it uses the Traffic Manager. Measure it.

10. Timing-pattern research question

The current 60 ms target for Defense 2 is provisional.

It was selected because:

the slowest profile observed in the earlier rig was approximately 40 ms;
additional margin was needed;
the target remained below the TCP retransmission timeout.

Dr. Lin’s concern was:

What defensible principle determines the selected timing?

This remains an open research question.

The final target should not be justified only as:

The slowest response was 40 ms, so I selected 60 ms.

The target or pattern should be supported by:

native SEL-751 timing distribution;
operational DNP3 response requirements;
TCP retransmission limits;
queue scheduling accuracy;
acceptable latency overhead;
classifier performance;
a device-independent timing policy;
related work such as Ditto.
11. Candidate timing-pattern strategies to evaluate
Pattern 1: Fixed common gap

Example:

Every response leaves 40 ms after the pure ACK.

Advantages:

simple;
easy to implement;
easy to explain.

Disadvantages:

creates a new constant fingerprint;
may add unnecessary latency;
can reveal that the traffic is defended.

Use only as a calibration baseline.

Pattern 2: Common bounded distribution

Example:

Responses are released using values selected from
a common range shared by all protected devices.

Advantages:

avoids one perfectly constant timing value;
can reduce device-specific timing;
more difficult for a passive attacker to model.

Disadvantages:

requires a defensible range and distribution;
may add more implementation complexity.
Pattern 3: Repeating Ditto-style schedule

Example:

The output follows a predefined sequence of timing slots.
Real ACKs or responses occupy available slots.

Advantages:

directly follows Ditto’s design philosophy;
timing becomes independent of individual device readiness;
easier to explain as traffic shaping.

Disadvantages:

may require chaff or empty-slot handling;
may increase latency;
may require loopback ports and additional queues;
must preserve ACK-before-response ordering.

These strategies should be compared before selecting the final paper design.

12. Major unresolved design question

The most important technical issue is:

How should the event-driven Defense 1 mechanism map onto a periodic Ditto-style queue schedule?

Defense 1 currently releases the ACK when the response arrives.

Ditto releases packets according to predefined queue slots.

Those are not identical.

Possible directions to evaluate:

keep event detection in ingress and place the ACK into the next valid queue slot once the response is observed;
place the ACK and response into adjacent scheduled slots;
use a hybrid mechanism where recirculation detects the event and the queue provides controlled final release;
use a short periodic timing pattern with real packets prioritized over chaff.

This should be treated as an explicit design question, not assumed to be solved.

13. Physical SEL-751 experiment

Dr. Lin wants the project to move from replayed traces to the physical SEL-751.

Proposed connection sequence
Step 1: Learn the SEL-751 configuration

Connect the SEL-751 to the normal laboratory Ethernet switch.

Use Hulk or Vision as the DNP3 master.

Configure:

the master IP address;
the same subnet as the SEL-751;
DNP3 TCP port;
outstation address;
master address;
Class-0 polling;
unsolicited-response behavior.

Do not change the SEL-751 IP address unless necessary.

Step 2: Verify direct communication

Confirm:

ping, if enabled;
TCP port 20000 connectivity;
DNP3 session establishment;
Class-0 READ response;
separate pure ACK behavior;
native ACK-to-response timing;
no write or control operation.
Step 3: Insert the Tofino

After direct communication works:

DNP3 master
      |
Tofino switch
      |
SEL-751
Step 4: Run native traffic

Collect:

master-side PCAP;
outstation-side PCAP;
ACK-to-response timing;
response sizes;
TCP behavior;
DNP3 response correctness.
Step 5: Enable the defense

Run:

Defense 1 using recirculation;
queue-based Defense 1 when available;
Defense 2;
background-load experiments.
14. Paper scope confirmed by Dr. Lin

The paper contains two major technical areas:

Part 1: Packet-size obfuscation

This includes the earlier work on:

packet padding;
packet-size patterns;
packet splitting or segmentation where applicable;
hiding device-specific response sizes.
Part 2: Timing obfuscation

This includes:

Formby ACK-to-response fingerprinting;
Case A traffic;
Defense 1;
Defense 2;
software feasibility;
Tofino recirculation;
queue-based implementation;
physical SEL-751 evaluation.

The paper should explain how size and timing features complement each other.

15. Paper writing decision

Dr. Lin wants writing to start immediately.

Required setup
Change the Overleaf account email to your URI email or create a URI-linked account.
Share the account or project with Dr. Lin.
Use a double-column IEEE-style template.
Plan for approximately 12 pages before references.
Use writing to organize the remaining experiments.
Dr. Lin’s intended contribution

Dr. Lin will:

create or help create the paper structure;
add paragraph-level ideas;
capture his reasoning before it is lost;
collaborate on the technical narrative.
Your responsibility

You will:

fill the structure with technical content;
add results and figures;
use related work to improve the argument;
update sections as the implementation evolves;
maintain the bibliography and evidence.
16. Recommended paper outline
1. Introduction
Industrial device fingerprinting remains possible through encrypted traffic metadata.
Existing work exposes packet-size and timing features.
Legacy devices cannot easily be modified.
Programmable switches provide an inline defense point.
Contributions.
2. Background and motivation
DNP3 communication.
Pure TCP ACK versus ACK-bearing response.
Formby fingerprinting.
Programmable switch constraints.
Traffic Manager queues and recirculation.
3. Device trace analysis
SEL-751 separate ACK and response.
AB1400 and ION7550 combined response.
Native packet-size distributions.
Native timing distributions.
4. Threat model and goals
Passive WAN observer.
Encrypted payloads.
Visible timing, sizes, and direction.
No device modification.
Byte-preserving inline operation.
5. Design
Packet-size defense.
Case A timing defense.
Defense 1.
Defense 2.
Timing-pattern selection.
Fail-open behavior.
6. Implementation
Software feasibility study.
Tofino parsing and state.
Recirculation implementation.
Queue-based Ditto-inspired implementation.
Resource constraints.
7. Evaluation
Original traces.
Physical SEL-751.
Timing distributions.
Packet-size distributions.
Classifier evaluation.
Added latency.
Packet loss and retransmissions.
Background-load sensitivity.
Resource use.
8. Security analysis
Residual timing channels.
Request-to-ACK leakage.
ACK-mode leakage.
Packet-size leakage.
Adaptive attackers.
Limitations.
9. Related work
Formby.
Ditto.
BuFLO and CS-BuFLO.
TARANET.
Programmable data-plane traffic shaping.
10. Conclusion
17. Action items for Philip
Immediate actions
Set up Overleaf
Use URI email.
Share with Dr. Lin.
Add the IEEE double-column template.
Create the initial section structure.
Review Ditto in detail
Focus on Sections IV, V, VI, VIII, and IX.
Extract the queue hierarchy.
Extract how patterns are computed.
Extract how queue rates are configured.
Extract loopback requirements.
Extract performance and security metrics.
Write a Ditto adaptation note
What Ditto does.
Which parts apply to DNP3.
Which parts are unnecessary.
How Defense 1 could use scheduled slots.
How Defense 2 could use scheduled slots.
Expected queue and port requirements.
Verify the SEL-751 baseline
Confirm milliseconds.
Confirm median and percentiles.
Confirm transaction count.
Confirm the ACK and response matching logic.
Prepare the physical SEL-751 connection
Identify its IP address.
Identify subnet and gateway.
Confirm DNP3 addresses.
Locate cabling and switch ports.
Identify whether Hulk or Vision will initially act as master.
Technical development actions
Build a minimal Traffic Manager queue microbenchmark.
Measure queue delay under:
no background traffic;
low background traffic;
moderate background traffic;
high background traffic.
Compare queue timing against recirculation timing.
Implement the smallest Ditto-inspired pattern first.
Preserve the existing recirculation implementation as a baseline.
Avoid adding packet padding and timing scheduling to one binary until the queue mechanism is understood.
18. Suggested queue microbenchmark

Before modifying the full DNP3 program, build a small Tofino experiment.

Input

Packets marked with one of two classes:

immediate;
delayed.
Queues
Queue 0: normal traffic.
Queue 1: delayed test traffic.
Measurements
configured shaper rate;
queue depth;
packet residence time;
output timing;
jitter;
packet loss;
ordering;
effect of background traffic.
Test loads
one sparse packet;
one packet every 10 ms;
burst of ten packets;
constant background UDP traffic;
mixed packet sizes.
Goal

Determine whether the queue provides:

lower timing variance than recirculation;
stable delay under load;
acceptable packet loss;
predictable queue drain behavior.

Do not integrate the mechanism into the DNP3 program until this microbenchmark is complete.

19. Action items for Dr. Lin

Based on the meeting, Dr. Lin will likely:

help establish access to the physical SEL-751;
help decide where to place the relay and how to connect it;
share or create the Overleaf project structure;
add paragraph-level paper ideas;
review the queue design after the Ditto analysis;
help decide the final timing-pattern justification.

These are inferred responsibilities and should be treated as collaborative items rather than formal assignments unless he confirms them.

20. Deliverables for the next weekly meeting

You should aim to present:

A one-slide summary of Ditto’s queue architecture.
A clear comparison between Ditto and the current recirculation method.
The proposed queue design for Defense 1.
The proposed queue design for Defense 2.
A justified list of timing-pattern candidates.
Initial queue microbenchmark results.
The SEL-751 physical connection plan.
The Overleaf paper outline.
Confirmed SEL-751 baseline statistics.
A list of remaining technical risks.
21. Updated project roadmap
Phase 1: Consolidate the current work
Freeze current recirculation results.
Verify figures and timing units.
Document software and Tofino feasibility.
Phase 2: Study Ditto
Reconstruct its queue architecture.
Reproduce a basic queue schedule.
Understand timing and load sensitivity.
Phase 3: Design DNP3 queue timing
Define the timing pattern.
Map ACK and response packets to slots.
Preserve ACK-before-response ordering.
Define fail-open behavior.
Phase 4: Validate with the physical SEL-751
Direct master-to-relay communication.
Native capture.
Tofino insertion.
Recirculation comparison.
Queue-based defense.
Phase 5: Complete evaluation
Timing distributions.
Packet-size distributions.
Classifier performance.
Background load.
Operational overhead.
Tofino resources.
Phase 6: Complete paper
Integrate results continuously.
Refine contributions.
Finalize figures.
Review with Dr. Lin.