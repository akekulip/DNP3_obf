# Glossary — DNP3, TCP, P4, TM, RRC, BOR

Plain definitions first, then the precise meaning as used in this project.

## Protocol and device terms

**DNP3 (Distributed Network Protocol 3).** The SCADA protocol a control-center *master*
uses to poll and command a field device (*outstation*) such as a protective relay. Runs over
TCP/IP (port 20000 here). It has three stacked layers: **link**, **transport**, **application**.

**Master.** The polling/commanding station. In this testbed it is the host *Vision*.

**Outstation.** The field device that answers. Here it is a physical **SEL-751** feeder
protection relay. It is kept READ-only for safety except in the one authorized, guarded
SELECT→OPERATE gate.

**DNP3 link layer.** The outermost DNP3 frame: a start (0x0564), length, control, destination
and source link addresses, and a header CRC. The payload is then chopped into **16-byte data
blocks, each followed by its own 2-byte CRC**. (Master link address = 1, outstation = 0 on the
physical SEL-751.)

**DNP3 transport layer.** A single byte carrying FIN/FIR/sequence that reassembles application
data spread across multiple link frames.

**DNP3 application layer.** The actual request/response: an application control byte, a
**function code**, and object data.

**READ (function code 0x01).** The master asks for data (e.g., a Class 0/1/2/3 poll). The
outstation answers with a **RESPONSE (function 0x81)**.

**SELECT (0x03) and OPERATE (0x04).** The two halves of a control command.

**Select-Before-Operate (SBO).** A two-step safety handshake for control: the master first
**SELECT**s a control point (the outstation arms and echoes it back), then **OPERATE**s to
actually actuate. A stray or replayed OPERATE without a matching prior SELECT must not act.

**CROB (Control Relay Output Block).** The DNP3 object (group 12) that carries a control
command to a binary output point (e.g., trip/close a breaker).

**DNP3 link confirmation vs TCP ACK.** Two different "acknowledgements." A **DNP3 link
confirmation** is an application-visible DNP3 frame. A **TCP ACK** is a transport-layer
acknowledgement in the TCP header, invisible to DNP3. This project's timing channel is built on
the **TCP ACK**, not the DNP3 confirmation.

**Case A vs Case B (device taxonomy).** **Case A = separate-ACK device**: it sends a pure TCP
ACK first, then the DNP3 response as a later segment — so there is a measurable gap between them
(the SEL-751 behaves this way, and *has* a CLRT). **Case B = combined-ACK device**: the ACK
rides on the response segment, so there is no gap and **no CLRT** (the ION7550 behaves this way).
This defense targets **Case A**.

## Fingerprinting and the attacker

**Fingerprinting.** A passive observer identifying *which* device / *what* it is doing from
traffic features alone (sizes, segmentation, timing), without reading payloads.

**CLRT (Cross-Layer Response Time).** Formby et al.'s device-fingerprinting feature: the delay
between the transport-layer ACK and the application-layer response,

> CLRT = T_response − T_TCP-ACK

Because it is set by the device's internal firmware timing, it is a stable per-device
signature. Normalizing it hides that signature.

**Mutual information (MI).** How many bits a feature (e.g., CLRT) reveals about the label
(device / transaction). Lower is better for the defender. Measured here with **common bins** and
a **permutation null** (the MI you'd see by chance if the feature carried no information).

**Balanced accuracy (BA).** A classifier's accuracy averaged over classes, so 0.5 = chance for
two equally likely classes. Driving an attacker's BA down to 0.5 means the feature is useless.

## Switch, dataplane, and scheduler terms

**Tofino-1.** Intel's programmable switch ASIC. Its ingress pipeline has **12 match-action
(MAU) stages**; a program that does not fit in 12 stages will not compile for one pipe.

**P4 / P4_16 (TNA).** The language used to program the Tofino dataplane (Tofino Native
Architecture). A P4 program defines a **parser**, **match-action tables**, and a **deparser**.

**MAU stage.** One match-action stage of the pipeline. Stages are the scarce resource; fitting
the whole defense in ≤12 ingress stages is a central engineering constraint.

**Decision-table flattening.** The technique that let RRC + BOR share one pipe: instead of many
dependent tables (which consume stages serially), the logic collapses into **one computed
outcome** (`meta.outcome`) applied by **one terminal commit table** (`tbl_commit`).

**Deparser.** The pipeline stage that re-serializes headers onto the wire — where the response
is emitted as the two TCP segments of the size split.

**Traffic Manager (TM).** The Tofino block that holds **egress queues** and their **schedulers**
between ingress and egress. Holding a packet in a TM queue is how the dataplane *delays* it.

**Queue / qid.** A numbered egress queue. Packets in a higher **strict-priority** queue always
leave before packets in a lower one on the same port — this is how a queue acts as a timing gate.

**Strict-priority scheduler.** A scheduler that fully drains a high-priority queue before
serving a lower one. Two mechanisms sharing one such scheduler can starve each other — the
reason RRC and BOR needed **two independent scheduling domains** (see below).

**Loopback / recirculation port.** A switch-internal port that feeds a packet back into the
pipeline. **dp8** and **dp10** are internal loopbacks (not cables) that give RRC and BOR their
own scheduling domains inside the one switch.

**pktgen (packet generator).** An on-chip generator that emits internal packets. Used here to
pre-load **blocker/token** packets into hold queues — it does **not** generate normal
master/relay traffic.

**Blocker / token / reservoir.** A small internal packet parked in a high-priority queue that
"blocks" a lower-priority held packet from leaving until the blocker expires or is consumed — the
timing gate. A **reservoir** is the pool of such blockers pre-seeded for a transaction.

**Clone / mirror.** Dataplane copy of a packet (e.g., to produce the master-facing **echo**),
identified by a mirror **session id** and a **clone marker**.

**Fail-open.** If the mechanism cannot act (state missing, timeout), the packet is forwarded
**unmodified** rather than dropped — safe for availability, but it means a protection gap is a
silent pass-through, which is why the campaign hunts for unintended fail-opens.

## The two primitives (project-specific)

**RRC (Response Recirculate + Carve).** The **segmentation + CLRT** primitive for READ/SELECT
responses: recirculate the response on **dp8**, **carve** it at a block-aligned point (an existing
DNP3 CRC block boundary, chosen for a clean deterministic cut — not a TCP requirement) into a fixed
per-packet segmentation ([28, 21] bytes for the SEL's 49-byte response, byte-preserving, no CRC
recompute, total length unchanged), and **hold** it so the master-visible CLRT is a fixed policy
value instead of the device's native one.

**BOR (Bounded OPERATE Release).** The **timing** primitive for the SBO OPERATE: by design admit
one matching OPERATE, **hold** it on **dp10**, and **release** it once at a secret internal delay
**T0 + J**, while the master-visible ACK (at **T0 + A**) and echo (at **T0 + R**) stay anchored
to the original arrival **T0** — so echo − ACK = R − A is constant and **independent of J**
(the *anti-subtraction* property). The master-facing invariance was measured on silicon; the
relay-facing T0 + J and release multiplicity were not observed.

**T0, A, R, J (and the knobs D_A, D_R).** T0 = OPERATE/request arrival time. A = master-visible ACK
offset (= control-plane knob `D_A`). R = master-visible response/echo offset (= `D_A + D_R`, where
`D_R` is the response gap after the ACK). J = secret release delay (bounded codebook). Normalized
**CLRT = R − A**; in the final campaign A = 20 ms, R = 24 ms, so CLRT = 4 ms.
