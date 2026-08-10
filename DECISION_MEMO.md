# Decision memo — DNP3 fixed-transcript research phase

**Decision: `GO_WITH_BOUNDED_CLAIM`.**

There is a real, honest, publishable result here, but it is not the headline the charter opened with.
The full claim, "make the whole observable wire transcript independent of the device and response, and
prove it on hardware," is not reachable as first framed: single-edge and plaintext, it is infeasible
(the project's own transport and safety analysis proves it); realized as paired encrypting gateways, it
is largely off-the-shelf IP-TFS applied to DNP3; and the one part that would be uniquely the switch's,
a low-jitter release grid, is not yet measured on silicon. What is genuinely defensible now is a
different and still strong result: an impossibility boundary for self-describing correctness-critical
protocols, the measured floor of what a single outstation-edge switch can actually shape, and a
first-time closure of the TCP-timestamp channel. This memo states that bounded claim, resolves the two
internal contradictions the skeptical review caught, and sets the experiments that would either lift
the bound or terminate the design.

This memo consumes the full combined draft and the adversarial review in `SKEPTICAL_REVIEW.md`. Where
the review's objections O1 and O3 touched the novelty framing, they are resolved here and the
superseded framing is banner-flagged in `PRIOR_WORK_MATRIX.md`.

## The bounded claim, stated precisely

Under continuous protected operation in `PATTERN_NORMAL`, on the master-facing WAN segment, a defense
built as specified can make the transcript sub-vector `(K, S_i, d_i, t_i, h_rw)` statistically
independent of the protected secret, where `h_rw` is the set of outer-header fields a device-plane
function can rewrite (TTL, DF, IP-ID). It cannot, at a single outstation edge without a decrypting
peer, make the endpoint-stamped header fields (`TSval/TSecr`, `ip.id` progression, advertised-window
trajectory, `data_offset`) or the request-direction size independent of the secret; those are declared,
measured residual channels. The claim holds only over intervals that stayed in `PATTERN_NORMAL`; any
`AVAILABILITY_BYPASS` interval is excluded, not averaged in.

## 1. The strongest candidate architecture

Two answers, because the question splits along "reaches the full property" versus "is defensible now."

- **Strongest architecture for the full property: paired software gateways with the Tofino as
  metronome and header-scrubber (Architecture 4).** One gateway local to the outstation and one at the
  master own an encrypted, fixed-size, constant-rate cell tunnel with split-TCP termination; the switch
  enforces the release grid on opaque cells and rewrites the outer header, staying outside the
  confidentiality trust boundary. This is the only design in the study that meets size, count, timing,
  and rewritable-header independence and also closes the request-direction leak. Its weakness is
  decisive for the contribution: once the gateways exist, the design is Ditto's shape with a software
  peer, or IP-TFS at a substation crypto gateway, and the switch's only unique addition, a low-jitter
  line-rate grid, is exactly the unmeasured quantity R13. So Architecture 4 is the strongest
  *engineering* answer but is not, by itself, a strong *contribution* until R13 is retired positive.
- **Strongest defensible contribution now: the single outstation-edge floor plus the impossibility
  boundary (Architecture 5).** With no second endpoint and no encryption, the switch can still deliver
  a content-independent timing grid (the frozen Defense 4 primitive) and rewrite the header fields it
  can reach, and it can be proven that this is provably short of a fixed transcript for a
  self-describing protocol. This is the honest, buildable-and-measurable result that does not depend on
  a second box or an unproven cadence.

The recommendation is to pursue Architecture 4 as the engineering target, but to gate the paper's claim
on the Architecture-5 floor plus the impossibility result plus the timestamp closure, and to promote to
the full Architecture-4 claim only if the cadence measurement (R13) comes back positive.

## 2. The strongest alternative

**IP-TFS (RFC 9347), a fixed-rate aggregation-and-fragmentation tunnel inside IPsec, terminated at a
substation crypto gateway.** It delivers size, count, timing, and occurrence independence with
byte-exact reassembly, using standardized, deployed technology. It is the bar the bespoke design must
clear, and for most of the target property it already clears it. The only things it does not natively
give are line-rate low-jitter release without a software pacer and DNP3-aware eligibility, and the
second of those mostly dissolves once TCP is terminated at the gateway and cover is continuous. Any
"we built a switch defense" claim has to be stated as a measured improvement over this alternative, not
as a new capability.

## 3. Why the other candidates fail

- **Continuous constant-rate single-size cells (A) and request-epoch families (B, C)** are correct in
  the abstract but inherit the encryption precondition; without the encrypted outer layer their chaff
  and padding are stripped or dangerous. As mechanisms they are subsumed by Architecture 4 (A) or are
  strictly weaker because they reveal transaction occurrence (B, C).
- **Ditto two-pass shaping (D)** is the mechanism twin but its security rests on MACsec encryption and a
  peer switch that strips padding, and it cannot split a packet, so it fails the 12,204-byte READ. It
  contributes the in-switch shaping discipline, not the DNP3 solution.
- **Native protocol-valid cover / decoy CROBs (F)** fails on both privacy and safety: plaintext
  CRC-valid chaff is either detectable (bad CRC, illegal frame) or acts on the endpoints (the master's
  DNP3 stack runs `ProcessIIN` even on rejected frames; a fabricated CONFIRM can delete relay SOE
  records), and decoy reads still elicit the real device's real headers and timing. Rejected as a
  privacy mechanism; kept only as the reason encryption is required.
- **Slot-token / calendar scheduler (E)** is the right *mechanism* for holding the grid (its
  always-backlogged chaff reservoir is the confirmed answer to the empty-slot problem) but is not a
  standalone architecture; it is how Architecture 4's grid is implemented on the switch, and Tofino-1
  has no native calendar primitive.

## 4. The exact novelty candidate (reconciled)

The skeptical review's objections O1 and O3 are accepted. The earlier novelty pillars "plaintext-safe
CRC-valid chaff" and "single-edge, endpoint-preserving" are **struck**: the first is unsafe or
detectable, the second is infeasible for a fixed transcript. The reconciled novelty is:

1. **An impossibility boundary.** A single-edge, plaintext, endpoint-preserving defense cannot make the
   wire transcript independent of the device for a self-describing, CRC-checked, correctness-critical
   protocol observed on the WAN, because padding is strippable, chaff is detectable or dangerous, and
   the endpoint-stamped headers cannot be rewritten without terminating the connection. This is grounded
   in protocol, topology, and hardware, and it is the most novel and defensible statement in the work.
2. **The measured achievable floor** at that single edge: content-independent timing plus rewritable-
   header normalization, with the surviving channels (endpoint-stamped headers, request size) quantified
   rather than asserted.
3. **A first-time closure of the TCP-timestamp channel (N2, TSval/TSecr rewrite)** in the data plane,
   which no prior DNP3 or ICS shaping work has done, gated on a runtime-delta TCP-checksum compile that
   must be confirmed.
4. **Conditional, and only if R13 retires positive:** a measured line-rate low-jitter release advantage
   of a switch metronome over a software IP-TFS pacer within the DNP3 latency budget. This is the one
   thing that would make a switch-centered contribution, and it does not exist yet.

The novelty is stated as a recombination and a boundary, not as "no one has done DNP3." Hu et al.
(SmartGridComm 2023) already paired P4 with DNP3, for integrity and DoS filtering, not shaping.

## 5. What is inherited from Ditto and other work

- From **Ditto (NDSS 2022):** the fixed-pattern transcript idea, in-switch chaff by recirculate-and-
  clone, and the priority-plus-round-robin loopback scheduler on one Tofino. Inherited wholesale as the
  shaping mechanism.
- From **IP-TFS (RFC 9347):** carrying a variable payload inside fixed-size, constant-rate cells whose
  size and rate are independent of the inner traffic, with byte-exact reassembly by block-offset and a
  monotonic sequence number. Inherited as the fragmentation-and-recovery discipline.
- From **Securitas (NSDI 2026):** the switch-side fragmentation-into-fixed-slots realization, with the
  caveat that Securitas still relies on a reassembling server and downstream drop of small-TTL fakes.
- From **NetShaper / Pacer:** the differential-privacy and constant-rate framing for defining and
  bounding what "indistinguishable" means, feeding the equivalence-testing proof obligations.
- From **frozen upstream Defense 4:** the separate-ACK CLRT normalization primitive and its interface,
  as fixed in `D4_UPSTREAM_CONTRACT.md`.

## 6. What is genuinely DNP3-specific

- The protected observable is the **separate-ACK cross-layer response time**, the Formby fingerprint,
  which the general obfuscation literature does not target.
- The **self-describing, CRC-checked plaintext frame** is what makes padding strippable and chaff
  unsafe; this is the property that forces encryption and drives the impossibility result. It is
  specific to legacy ICS protocols, not to encrypted web traffic.
- The **unmodifiable protection relay and the read-only, no-control safety constraint** are what rule
  out endpoint cooperation and native decoys, and what make a fabricated CONFIRM a safety event rather
  than a benign dummy.
- The **12,204-byte integrity READ against tiny routine polls** is the DNP3-specific reason a fixed cell
  count is expensive and a single K is not a general bound.

## 7. The minimum viable proof

For the bounded claim, three separate proofs, per `PROOF_OBLIGATIONS.md`:
- **Functional correctness:** byte-identical recovery of every inner DNP3/TCP byte across READ,
  DIRECT_OPERATE, SELECT/OPERATE, multi-segment (the 12,204-byte READ), concurrency, loss,
  retransmission, wraparound, and timeout, using the paired-gateway split-TCP path. These regimes are
  *not* inherited from Defense 4 (its live envelope excludes them) and must be established directly.
- **Transcript invariance in `PATTERN_NORMAL`:** equivalence (two-one-sided-tests, not mere non-
  significance) of `(K, S_i, d_i, t_i, h_rw)` across secrets, with the analytic `1/C` and Bayes-optimal
  chance baselines, and with the endpoint-stamped and request channels declared as residuals.
- **Privacy-failure accounting:** the five pattern states with auditable counters; no privacy claimed
  over any interval containing an `AVAILABILITY_BYPASS`.

The proof is credible only with a data campaign that has real power: at least five independent capture
sessions per device and at least two physical units per model, because the present corpus (six flows,
permutation-null floor p = 0.0769, one unit per model, size and timing on two different datasets)
supports a negative or impossibility claim but no affirmative invariance claim.

## 8. The first falsification experiment

The cheapest decisive test of the bounded claim's boundary: on the existing SEL-751 and D-sweep pcaps,
run the deterministic mutual-information plus matched-null equivalence test on the endpoint-stamped
outer-header sub-vector (`ΔTSval`, `ip.id` increments, advertised-window trajectory) against the secret.
The switch cannot rewrite these without terminating the connection, so if any carries the secret above
its null, the fixed-transcript claim over the full header vector is falsified for the cost of one
read-only tshark pass. Caveat, from the review: the upstream measurements strongly predict this will
confirm the leak (`ΔTSval` rejecting near 10^-51, `ip.id` 82/82, window `W(n) = W0 - s·n`), so this
experiment *scopes* the claim rather than surprising it. It is run first because it formally fixes the
residual, but it is not the decision-critical unknown; the hardware probes below are.

## 9. The first resource-only compile probe

The one place the measured "size axis co-resides at zero ingress cost" result does **not** transfer:
compile a probe that adds the packet-replication path CRC-boundary splitting would need (ingress mirror
or multicast plus per-copy truncation) on top of the live timing core, and read whether it fits given
that ingress stages 8-11 are at 16/16 logical tables and the 32-bit PHV group is at 100%. This settles,
compile-only and with no functional claim, whether any size work can live on-chip or must live entirely
in the software gateways. It is cheap, it needs no switch, and it directly prices the co-residency
question the upstream audit left open.

## 10. Conditions that would terminate the design

- **R13 returns negative.** If the Tofino pktgen grid cannot deliver a low-jitter release that a
  software pacer cannot match within the DNP3 latency budget, the switch has no unique role and the work
  collapses to "IP-TFS in software," which is not a contribution. Terminate the switch-centered framing
  and fall back to the impossibility-plus-floor paper.
- **Philip cannot deploy a local encapsulation function** near the outstation. Then the full property is
  unreachable (R1), and only the Architecture-5 floor and the impossibility result remain; that is a
  paper, but not the fixed-transcript system.
- **The runtime-delta TCP-checksum rewrite does not compile.** Then the in-data-plane TSval closure (N2)
  is dead, one of the three defensible novelties is lost, and header normalization must move entirely
  into the gateways (which the split-TCP design already prefers), further shrinking the switch's role.
- **The data campaign cannot get more than one unit per model or more than one session.** Then no
  affirmative device-identity invariance claim is provable, and the work stays a negative result.
- **The fixed-K / continuous-cover overhead against the real polling profile (including the 12,204-byte
  READ) exceeds the DNP3 timing and bandwidth budget.** Then the defense is not deployable as a fixed
  transcript and only a bounded, higher-overhead or partial-coverage variant survives.

## Path forward

The immediate next phase, if Philip approves, is measurement, not building: run the first falsification
experiment (element 8, read-only, now), then the R13 cadence probe and the resource-only replication
compile (elements 9 and the R13 probe, both gated on Philip's hardware authorization). The answers to
those three decide whether this becomes the full Architecture-4 system, the bounded impossibility-plus-
floor paper, or a no-go. The decisions that gate everything are in `OPEN_QUESTIONS_FOR_PHILIP.md`, and
the single most consequential is whether a local encapsulation function near the outstation is
deployable at all.
