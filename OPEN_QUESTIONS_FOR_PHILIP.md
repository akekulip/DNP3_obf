# Open questions for Philip

These are decisions this phase cannot make from the code or the evidence because they set the goal,
the deployment reality, or the acceptable cost. Each one changes the recommendation. They are ordered
by how much they move the design.

## 1. What is the protected secret, and what is public? (sets everything)

The target property hides `X` given public `C`. The candidates for `X` are device identity, response
value, response size, operation type, and transaction occurrence. Working assumption this phase:
`X` = identity + value + size + operation type; `C` = the existence and cadence of a public polling
class. Please confirm or correct. In particular, is **operation type (READ versus SELECT/OPERATE)**
secret, or is it public and allowed to key the pattern?

## 2. Must the system hide that a transaction happened at all? (sets the cost class)

Hiding transaction occurrence requires continuous, constant-rate cover traffic in both directions,
even when the link is idle. This is the expensive class (Candidates A / G). If occurrence is public,
and we only need to hide value / size / type within a public polling class, then request-triggered
epochs (Candidates B / C / E) pay overhead only when polls happen. This one answer roughly doubles or
halves the standing cost of the system. Which is required?

## 3. Where does the observer sit relative to a WAN encryptor?

If the monitored segment is already inside an IPsec or MACsec tunnel to the control center, the
observable transcript is the tunnel's, and the shaping must be co-designed with that tunnel. If the
segment is bare wire (the Defense 4 vantage), the switch shapes it directly. Which vantage must the
design defeat: bare master-facing wire, post-encryptor tunnel, or both?

## 4. Is a local encapsulation / encryption function near the outstation deployable?

The analysis is converging on the conclusion that hiding size, count, and outer headers requires an
encrypted outer layer, which needs an endpoint near the outstation (a small gateway or the switch
acting as a MACsec endpoint) plus a peer near the master. One Tofino alone cannot perform arbitrary
encryption. Is adding a local encapsulation box (or enabling MACsec on the relay-facing link)
acceptable in the target deployment, or is the hard constraint "one Tofino and nothing else near the
relay"? If it is the latter, the achievable claim shrinks substantially and the decision leans toward
`GO_WITH_BOUNDED_CLAIM` or `NO_GO`.

## 5. What overhead is acceptable?

Fixed-transcript designs cost bandwidth (chaff cells) and latency (waiting for the next slot). The
measured fixed-K=3 size result already cost about 287.3% bandwidth on the corpus, and a continuous
cover design costs constant bandwidth even when idle. DNP3 also has retransmission and
quality-of-service timers the added latency must stay under. What is the acceptable ceiling on (a)
bandwidth overhead and (b) added response latency? This bounds which candidates survive.

## 6. What is the claim ambition and the target venue?

A bounded claim (one SEL-751, READ polling, the master-facing vantage) is defensible now and matches
the Defense 4 precedent. A broader claim (cross-vendor, control operations, occurrence-hiding) needs
more hardware and more capture sessions. What is the intended claim and venue, so the experiment plan
is sized to it rather than over- or under-built?

## 7. Is a second physical device (and a second unit of a model) available?

The evaluation needs more than one capture session and, to be credible on device-identity hiding,
more than one physical device and eventually more than one unit per model. The corpus has SEL-751,
ION7550, and AB1400. Which physical devices can be used, and can we get a second unit of any single
model for within-model generalization?

## 8. Authorization posture for later hardware probes

This phase is compile-only and touches no switch. A prototype (only if the decision is GO) would need
switch access and, for correctness testing, an isolated software outstation, never the physical relay
for control. Confirm that the standing rule holds: physical SEL-751 stays read-only, any
SELECT/OPERATE goes only to an isolated software outstation, and any hardware step waits for explicit
authorization.
