# Experiment 2A — handshake TCP-header normalizer (design only)

Design-phase deliverable. **No P4 implementation, no compile, no hardware, no endpoint testing.** This
directory specifies a standalone Tofino handshake normalizer that would remove the TCP-option-layout
device fingerprint attributed in Experiment 1, and it defines the criteria under which the actual compile
(Experiment 2) may be authorized.

## Files

- `EXPERIMENT_2A_DESIGN.md` — the exact specification: mechanism, per-packet transformations, flow-state
  machine, failure behavior, resource estimate, and compile success criteria.
- `REVIEW.md` — the adversarial review outcome (TCP/RFC safety + Tofino/P4 feasibility) and how the design
  was reconciled.

## The mechanism in one paragraph

The device fingerprint lives in the TCP option layout (Experiment 1). Instead of stripping options from
every segment (Experiment 1's offline shortcut, unsafe live), this normalizer rewrites **only the
handshake**: it removes Timestamps, Window Scale, and SACK-permitted from the SYN and SYN-ACK and forces
a public MSS, so both endpoints negotiate a canonical minimal option set and, per RFC 7323 / RFC 2018
fallback, emit no options on established segments on their own. It also canonicalizes TTL and IP-ID and
recomputes checksums. It never touches TCP sequence numbers or payload, so it is stateless / packet-bounded
and needs no per-flow translation registers. Its endpoint safety is argued from RFC negotiation semantics
and is to be **proven in Experiment 3**, not here.

## Gate

Per Philip's instruction, the design must survive review before the standalone Experiment 2 compile is
authorized. See `REVIEW.md` for the outcome. A passing compile would authorize only the next gate
(endpoint-safety Experiment 3), never hardware implementation.
