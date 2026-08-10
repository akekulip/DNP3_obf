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

## The two structural walls the constraint imposes

1. **No indistinguishable native cover.** In self-describing plaintext DNP3, the receiver's "ignore
   this" rule and the observer's "strip this" rule are the same rule, written in the packet (group
   codes, lengths, TCP seq/ack). So the only cover a passive observer cannot strip is cover a genuine
   endpoint actually produces, which a stock endpoint plus a DNP3-blind Tofino-1 (DNP3 bytes are the
   unparsed deparser residual, never in the PHV) cannot synthesize. **[verified fact,
   analysis/native_dnp3_mechanisms.md]**
2. **No correct on-switch re-slicing or padding of the TCP stream.** The switch can rewrite parsed
   headers and truncate to a fixed prefix, but it cannot excise an interior byte range or re-slice an
   application object spanning several TCP segments. Correct TCP reassembly on the unchanged master
   needs each segment to carry a non-overlapping contiguous slice at its exact sequence offset;
   mirror/multicast plus per-copy truncation yields nested prefixes that the master treats as
   overlapping retransmissions (data loss) or, with bumped sequence, a corrupted stream. Correct slicing
   or padding requires store-and-forward reassembly, which is a proxy. The upstream `split_server.py`
   that "preserves bytes" is in fact a TCP-terminating proxy, so that byte-preservation result does not
   port to the switch. **[falsification result, analysis/tcp_segmentation_and_headers.md]**

These two walls decide most of the families below.

## Native families evaluated

### Family 1 — Fixed DNP3 request/response templates — FALSIFIED as device-independence
A master will protocol-accept extra requested or returned objects, but producing a fixed templated
response means either switch-side DNP3 object surgery (barred by the governing spec and structurally
impossible on the DNP3-blind Tofino-1) or an endpoint change (barred), and switch-fabricated objects are
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
Wall 2 applies directly. A fixed count of non-overlapping correct slices, or padding the ~47 B response
up to a large fixed shape, requires per-flow store-and-forward TCP reassembly and a growing seq/ack
translation, i.e. a proxy. On-switch truncation yields nested prefixes (data loss or corruption).
Overhead for one `K` covering both ~47 B and the measured 12,204 B READ runs about two orders of
magnitude, but correctness fails before overhead matters. Count `K` and epoch duration remain a size
channel for any size-adaptive split; only fixed `K` removes the 60.6% size-to-timing re-encoding, and
fixed `K` is not producible on this switch.

### Family 4 — Native chaff / duplication — no safe-and-indistinguishable option
By Wall 1, the safe subset (a bare pure-ACK, a prepended black-hole link frame) is trivially labelable
(the black-hole frame is removed by the observer in one subtraction), and the indistinguishable subset
(real DNP3 objects, CONFIRMs, unsolicited responses, injected application frames) is barred or dangerous.
A fabricated DNP3 CONFIRM is the most dangerous candidate of all: it makes the outstation permanently
delete SER/event-buffer records the real master never received.

### Family 5 — Same-switch scheduling techniques — implementation, not security
pktgen, TM shaping, strict-priority and round-robin queues, multicast, mirror, recirculation, loopback,
egress replica ID, and calendar/slot tokens are implementation techniques. The TM never manufactures a
packet for an empty queue, so every slot a real packet does not fill needs a cover packet, and by
Walls 1 and 2 the only byte-transparent, TCP/DNP3-safe cover the switch can send the master is a
fixed-size pure-ACK-shaped token, which carries the release offset but not size. pktgen can hold a
byte-exact DNP3 template and fire it indefinitely (8 apps/pipe, D4 uses 3), but its TCP seq/ack are
frozen at author time, so a pktgen frame is a stale-seq segment on the master's live connection unless a
per-flow ingress seq/ack rewrite is added, which does not fit the saturated tail. The cadence of the
only usable low-rate metronome (the pktgen periodic timer) is undocumented and unmeasured (risk R13); the
TM max-rate shaper is falsified as a low-rate metronome (clumps at or below 600 pps).

### Family 6 — Header normalization — partial, bounded by the endpoint-stamped fields
One switch can statelessly normalize Ethernet, IP version/IHL/DSCP/DF/frag, `ip.id`, TTL, IP and TCP
checksums, TCP urgent and PSH, and (with a rate/scale caveat) the TCP window value. It cannot rewrite
`tcp.seq`/`tcp.ack` and their progression (a constant causes RST; only a per-flow bijection is possible,
which still leaks size), TCP timestamps (the PAWS-bound device clock, which survives shaping),
`tcp.data_offset` / option layout / window-scale (the SYN-negotiated device fingerprint), or DNP3
content and per-block CRC (the secret itself; CRC recompute is spec-barred). Normalizing TTL and `ip.id`
closes those two tells, but TTL's fingerprint partner `data_offset` is on the wrong side of the boundary,
so device identity via the TCP-stack fingerprint survives.

## The one surviving bounded native mechanism

Reconciling the three notes, exactly one mechanism is native, endpoint-safe, and realizable, and it
closes only part of the pattern:

**Request-synchronized, real-packet-only release at public offsets, plus a stateless header-scrub.** The
switch classifies the public transaction, releases the genuine ACK and RESPONSE at public
request-anchored offsets `t_wire = min{tau_i : tau_i >= t_eligible}` with the deadline a public runtime
constant (the frozen Defense 4 timing mechanism, generalized to a public slot offset), and statelessly
rewrites the reachable header subset (TTL, `ip.id`, DF, checksums, window) to class constants. No DNP3
byte is changed, no cover is injected, no control reaches the relay, and the master receives exactly what
it requested. This closes the **release-schedule (timing)** axis and part of the **header** axis. It does
not close **count**, **size-aggregate**, or the **endpoint-stamped headers** (TSval, seq/ack, data-offset),
which are declared measured residuals that provably require a proxy the testbed forbids.

## Excluded alternatives (retained, not recommended)

- **Paired software gateways with an encrypted fixed-cell tunnel** (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`):
  the strongest design for full invariance, excluded by the constraint (needs a second endpoint and
  encryption). It is the correct account of what full invariance would require and is now used as an
  impossibility argument, not a recommendation.
- **IP-TFS / NetShaper / Pacer / Ditto-with-encryption**: all need encryption and cooperating endpoints
  the testbed forbids; imported only for what they establish (`PRIOR_WORK_MATRIX.md`). Only Ditto's TM
  scheduling discipline transfers.

## Where the candidates stand going into the decision

Full plaintext fixed-transcript invariance is unattainable under the hard architecture: the two
structural walls make correct native size and count closure and indistinguishable native cover
impossible on one DNP3-blind switch, and the endpoint-stamped header fields keep device identity visible.
The strongest bounded native defense is the timing-plus-header-scrub mechanism above, whose increment
over frozen Defense 4 is the stateless header-scrub and the public-offset framing; whether that increment
is a real contribution or cosmetic is the sharpest question for the decision memo and the skeptical
review. The genuine, defensible result is the **impossibility boundary**: a grounded protocol-plus-TCP-
plus-hardware argument that this class of defense cannot reach size or count closure without a proxy.
