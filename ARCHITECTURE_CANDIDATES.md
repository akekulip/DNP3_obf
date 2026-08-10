# Architecture candidates (native, one-Tofino)

Revised for the binding testbed `Master <-> Tofino-1 <-> Outstation` (`CORRECTION_LOG.md`). This
evaluates the native mechanisms that need neither encryption nor a second endpoint, reconciles the three
investigation notes under `analysis/`, and states which axes each closes. The encrypted paired-gateway
families are retained only as excluded alternatives. Every verdict here is backed by
`analysis/native_dnp3_mechanisms.md` (DNP3/relay-safety), `analysis/tcp_segmentation_and_headers.md`
(TCP/traffic-analysis), and `analysis/tofino_native_scheduling.md` (Tofino/TM).

## The checklist every candidate must answer

Is packet count independent of `X`; are all sizes independent of `X`; is the direction sequence
independent of `X`; is the release schedule independent of `X`; can the observer label real versus cover;
does a late/large response change the epoch; what under loss/retransmission/overlap; does the master
receive exactly the semantics it requested; does the outstation receive only safe operations; does any
decoy alter control/event/diagnostic state; what on overflow, and which counter records a privacy or
safety failure.

## The two arguments the constraint imposes (reclassified)

These were previously stated as "structural walls." They are reclassified here (documentation correction)
to their correct epistemic status.

1. **`ignore-rule = strip-rule` — a design hypothesis / conditional lemma.** The claim is that in
   self-describing, CRC-checked plaintext DNP3, the rule by which the receiver ignores a filler packet
   coincides with the rule by which a passive observer strips it, so the only cover an observer cannot
   strip is cover a genuine endpoint actually produces. This is plausible and useful, but it holds only
   under a stated adversary, endpoint, and semantic model that this phase has not yet formalized, so it is
   a hypothesis to be formalized, not a settled fact. The relevant hardware limitation behind it is that a
   Tofino-1 does bounded per-packet parsing and state, without arbitrary TCP-stream reassembly or
   application-level store-and-forward transformation (Defense 4 is DNP3-aware, so this is a capability
   bound, not "DNP3-blindness"). **[design hypothesis, analysis/native_dnp3_mechanisms.md]**
2. **General size/count closure without a decoding peer — the strongest no-go candidate.** The switch can
   rewrite parsed headers and truncate to a fixed prefix, but excising an interior byte range or
   re-slicing an object spanning several TCP segments needs store-and-forward reassembly, which is a
   proxy. Distinguish two claims the prior version conflated: (a) no such mechanism is present in the
   frozen implementation or in any construction the internal analysis found (well supported); versus (b)
   no such mechanism can exist on this architecture (an architectural-impossibility claim that is **not**
   established). The verdict rests on (a). The upstream `split_server.py` that "preserves bytes" is a
   TCP-terminating socket proxy, which is evidence that the known byte-preserving construction is a proxy,
   not evidence that no non-proxy construction exists. **[strongest no-go candidate (2a); architectural
   impossibility NOT established, analysis/tcp_segmentation_and_headers.md]**

These two arguments shape the family verdicts below. Neither is a completed impossibility proof.

## Native families evaluated

### Family 1 — Fixed DNP3 request/response templates — FALSIFIED as device-independence
A master will protocol-accept extra requested or returned objects, but producing a fixed templated
response means either switch-side DNP3 object surgery (barred by the governing spec, and outside the
Tofino-1's bounded per-packet parsing and state, which do not support arbitrary application-level
store-and-forward object construction) or an endpoint change (barred), and switch-fabricated objects are
a false-data injection into the master's data model. Removing objects to shrink drops real measurements
to the EMS and only hides the original from a strictly master-facing vantage while re-introducing the
size leak once removal happens before the observed link. The only safe fragment is treating the fixed
public READ class as `C` on the request side, which hides nothing about the device.

### Family 2 — SBO and decoy CROBs — REJECT for the physical relay
Fixed real-plus-decoy SELECT/OPERATE patterns pass only count-independence. They are observer-labelable
(a ~37 B `g12v1` control echo versus a ~134 B `g30` READ), they assert Remote Bits, write to the
Sequential-Events Recorder, pressure the event buffer toward IIN2.3, couple to SELECT arm-state, and
turn the switch into an in-network control-injection appliance in front of a protection relay. The
upstream multi-CROB evidence is a valid protocol/API characterization on a simulator only. A decoy point
is not safe merely because it lacks a physical conductor.

### Family 3 — Fixed-K segmentation — NOT correct on an unchanged master (needs a proxy)
Argument 2 applies directly. A fixed count of non-overlapping correct slices, or padding the ~47 B response
up to a large fixed shape, requires per-flow store-and-forward TCP reassembly and a growing seq/ack
translation, i.e. a proxy. On-switch truncation yields nested prefixes (data loss or corruption).
Overhead for one `K` covering both ~47 B and the measured 12,204 B READ runs about two orders of
magnitude, but correctness fails before overhead matters. Count `K` and epoch duration remain a size
channel for any size-adaptive split; only fixed `K` removes the 60.6% size-to-timing re-encoding, and
fixed `K` is not producible on this switch.

### Family 4 — Native chaff / duplication — no safe-and-indistinguishable option (under argument 1)
Under the `ignore = strip` hypothesis, the safe subset (a bare pure-ACK, a prepended black-hole link
frame) is trivially labelable (the black-hole frame is removed by the observer in one subtraction), and
the indistinguishable subset (real DNP3 objects, application confirmations, unsolicited responses,
injected application frames) is barred or a safety hazard. The most dangerous candidate is an injected
**valid but premature application-layer confirmation**: it can retire acknowledged events from the
outstation's **DNP3 event buffer** and prevent their later delivery to the master (once confirmed, the
outstation need not resend them). This is a real integrity hazard and reason enough to bar injected
confirmations. Whether it affects SEL-specific stores (the SEL Sequential-Events-Recorder storage or the
SEL event-report storage) is a separate question requiring SEL-specific evidence this phase does not
have; do not conflate the protocol-level DNP3 event buffer with those SEL stores.

### Family 5 — Same-switch scheduling techniques — implementation, not security
pktgen, TM shaping, strict-priority and round-robin queues, multicast, mirror, recirculation, loopback,
egress replica ID, and calendar/slot tokens are implementation techniques. The TM never manufactures a
packet for an empty queue, so every slot a real packet does not fill needs a cover packet, and by
arguments 1 and 2 the only byte-transparent, TCP/DNP3-safe cover the switch can send the master is a
fixed-size pure-ACK-shaped token, which carries the release offset but not size. pktgen can hold a
byte-exact DNP3 template and fire it indefinitely (8 apps/pipe, D4 uses 3), but its TCP seq/ack are
frozen at author time, so a pktgen frame is a stale-seq segment on the master's live connection unless a
per-flow ingress seq/ack rewrite is added, which does not fit the saturated tail. The cadence of the
only usable low-rate metronome (the pktgen periodic timer) is undocumented and unmeasured (risk R13); the
TM max-rate shaper is falsified as a low-rate metronome (clumps at or below 600 pps).

### Family 6 — Header normalization — partly reachable now, the rest UNRESOLVED (not an impossibility)
One switch can statelessly normalize Ethernet, IP version/IHL/DSCP/DF/frag, `ip.id`, TTL, IP and TCP
checksums, TCP urgent and PSH, and (with a rate/scale caveat) the TCP window value; normalizing TTL and
`ip.id` to class constants closes those tells (and leaves no `ip.id`-progression residual). The remaining
TCP-stack fields — `tcp.data_offset` / option layout / window-scale (the SYN-negotiated fingerprint), TCP
timestamps, and the sequence/acknowledgment progression — were previously called unreachable. That
assertion is **withdrawn**. Concrete counterexamples exist and have not been compiled or tested:
suppressing the Timestamps option, window scale, and SACK-permitted negotiation during SYN/SYN-ACK;
replacing removed options with a canonical NOP/EOL layout and padding to a public `data_offset`;
translating the outstation TSval by a fixed per-flow offset with the matching TSecr reversed on the
opposite direction; and a per-flow sequence/acknowledgment delta for ISN normalization, all with IPv4/TCP
checksum correction and a full retransmission / reuse / wraparound / PAWS / RTTM correctness analysis. So
the TCP-header axis is **unresolved**: whether these mechanisms compile on the target and survive
endpoint-safety testing is exactly what Experiments 1-3 (`EXPERIMENT_PLAN.md`, `DECISION_MEMO.md`) must
decide. No header-level no-go is claimed. DNP3 content and per-block CRC remain out of scope (CRC recompute
is spec-barred; content is placed in `C`, not `X` — see `THREAT_MODEL.md`).

## The surviving native mechanism and its open extension

Reconciling the three notes, one mechanism is native, endpoint-safe, and realizable today, and a header
extension of it is open:

**Request-synchronized, real-packet-only release at public offsets, plus a stateless header-scrub.** The
switch classifies the public transaction, releases the genuine ACK and RESPONSE at public
request-anchored offsets `t_wire = min{tau_i : tau_i >= t_eligible}` with the deadline a public runtime
constant (the frozen Defense 4 timing mechanism, generalized to a public slot offset), and statelessly
rewrites the reachable header subset (TTL, `ip.id`, DF, checksums, window) to class constants. No DNP3
byte is changed, no cover is injected, no control or premature confirmation reaches the relay, and the
master receives exactly what it requested. Within the tested Defense 4 scope this is a **positive bounded
defense** on the **timing** axis, plus normalization of the two reachable header tells. It does not close
**size** or, for multi-segment responses, **count** (the strongest no-go candidate, argument 2a). The
rest of the **TCP-stack header** axis (data-offset, timestamps, window-scale, sequence) is **open**: the
Experiment 1-3 counterexamples (`EXPERIMENT_PLAN.md`) would, if they compile and pass endpoint-safety
testing, extend the defense to those fields, and that extension is the strongest prospective bounded
result. Header closure is not asserted and not ruled out.

## Excluded alternatives (retained, not recommended)

- **Paired software gateways with an encrypted fixed-cell tunnel** (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`):
  the strongest design for full invariance, excluded by the constraint (needs a second endpoint and
  encryption). It is the correct account of what full invariance would require and is now used as an
  impossibility argument, not a recommendation.
- **IP-TFS / NetShaper / Pacer / Ditto-with-encryption**: all need encryption and cooperating endpoints
  the testbed forbids; imported only for what they establish (`PRIOR_WORK_MATRIX.md`). Only Ditto's TM
  scheduling discipline transfers.

## Where the candidates stand going into the decision

Universal plaintext fixed-transcript invariance is not reachable under the hard architecture on the basis
established so far: general size/count closure for varying plaintext responses without a decoding peer is
the strongest no-go candidate (argument 2a; architectural impossibility not proven), and native cover is
not both safe and indistinguishable under the `ignore = strip` hypothesis. This is a conditional
analytical no-go for *universal* invariance, not a completed impossibility proof, and it rests on a
correlated internal analysis that found no counterexample, not on independent evidence. The TCP-header
axis is unresolved. The positive result today is the frozen Defense 4 timing normalization within its
tested scope; the strongest prospective bounded extension is that plus TCP/IP-header normalization if the
counterexamples survive. Whether that increment
is a real contribution or cosmetic is a sharp question for the decision memo and the skeptical review. The
current defensible contribution is a **provisional** analytical result: a protocol-plus-TCP-plus-hardware
argument that this class of defense does not reach size or count closure for varying plaintext responses
without a decoding peer, in the frozen implementation or in any construction the internal analysis found.
Its status is provisional until the `ignore = strip` assumptions are formalized and the TCP-header
counterexample analysis is complete.
