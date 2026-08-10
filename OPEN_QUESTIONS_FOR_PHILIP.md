# Open questions for Philip

Revised for the one-Tofino testbed (`CORRECTION_LOG.md`). These decisions set the goal, the deployment
reality, or the acceptable cost, and each changes the recommendation. The earlier pivotal question,
whether a local encryption box near the outstation is deployable, is now **closed by the hard
constraint**: no gateway or encryption is permitted, so full transcript invariance is off the table and
the project pursues a bounded native defense. Ordered by how much they move the design.

## 1. Confirm the secret and public split

Phase 1 assumes Secret `X` = physical outstation identity plus response-dependent size, timing, count,
and stack behavior; Public `C` = transaction occurrence and operation class (READ or SBO). This makes
operation type and activity public, so no hiding of either is claimed. Please confirm, and in particular
confirm that **operation class (READ vs SBO) is public** and may key different patterns.

## 2. Decoy-point configuration on the outstation (the crux for SBO cover)

The native SBO/decoy-CROB mechanism needs the outstation configured with points that are explicitly
**non-physical** (cannot operate a real breaker) so decoy SELECT/OPERATE traffic is safe. Can the relay
be configured with such decoy points, and what relay configuration is permissible? A decoy point is not
assumed safe merely because it lacks a physical conductor, so we also need to know what SELECT/OPERATE,
IIN, event-buffer, and SOE behavior on those points is acceptable. If no safe decoy points are
available, the SBO cover family is out.

## 3. Native template acceptance on the master (the crux for READ cover)

The native READ-template mechanism needs the unchanged master to accept a fixed templated response (a
fixed object set / count) as correct. Is the master's DNP3 configuration fixed and known, and will it
accept the templated responses without error or class mismatch? If the master rejects extra objects and
the switch would have to remove them before the observed link, the original size leak returns, which
would kill the template family.

## 4. Acceptable overhead

A fixed pattern sized to the worst case (the 12,204-byte READ) is expensive on the common tiny poll.
What is the acceptable ceiling on (a) bandwidth overhead and (b) added response latency, given DNP3's
retransmission and quality-of-service timers? This bounds which native mechanism survives.

## 5. Is a residual endpoint-stamped-header leak acceptable?

One switch cannot rewrite TCP timestamps, the sequence/acknowledgment clock, the window trajectory, or
the data-offset/option layout without breaking the endpoints' TCP. These identified devices in the
corpus. If the bounded claim closes size, count, and timing of the DNP3 payload but declares those
header fields as a measured residual, is that an acceptable contribution, or must device-identity hiding
be complete (which the constraint makes unreachable)?

## 6. Claim ambition and venue

A bounded claim (one SEL-751, READ and a safe SBO template, the master-facing vantage) is defensible
now. A broader claim needs more hardware and more capture sessions. What is the intended claim and venue?

## 7. A second physical device for cross-device validation

Credible device-identity evidence needs more than one physical device and eventually more than one unit
per model. The corpus has SEL-751 (Case A), ION7550 and AB1400 (Case B). Which can be used, and can a
second unit of a model be obtained?

## 8. Hardware-authorization posture

This phase is compile-only and touches no switch. The silicon experiments (the cadence grid, the
endpoint-safety live test) are gated on your explicit authorization. Confirm the standing rule holds:
physical SEL-751 stays read-only, any SELECT/OPERATE goes only to an isolated software outstation or a
configured non-physical decoy point, and any hardware step waits for authorization.

## 9. Experiment 2 authorization (new, after Experiment 1)

Experiment 1 returned `PROMISING` for the TCP-header axis offline: a canonical-option-layout transform
removes the dominant header fingerprint with byte-exact DNP3 preservation
(`experiments/exp1_tcp_header_attribution/VERDICT.md`). Per the pre-registered rule this authorizes only
a *request* for Experiment 2, a compile-only, standalone Tofino TCP-header normalizer, before any Defense
4 co-residency. The design (Experiment 2A) is now written
(`experiments/exp2_handshake_normalizer/EXPERIMENT_2A_DESIGN.md`): a **handshake normalizer** that
suppresses TS/WScale/SACK in the SYN and SYN-ACK, canonicalizes MSS/TTL/IP-ID, and recomputes checksums
— stateless / packet-bounded, endpoint-safe *if* the real stacks honor the RFC negotiation fallback (an
Experiment-3 question). Do you want the standalone Experiment 2 compile authorized once the design
survives review? Residual to note: the TCP window value.

## 10. A second unit per model (reinforced by Experiment 1)

Experiment 1's device separation is exploratory: one physical unit per model, ~2 real-device sessions
each. Any device-family claim (that the transform generalizes across units of the same model) needs at
least two units per model and more independent capture sessions. Can a second SEL-751 (and, ideally, a
second ION7550 / AB1400) be captured, read-only?
