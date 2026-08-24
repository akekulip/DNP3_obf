# Title options for the NDSS 2028 submission (2026-08-24)

Current: *Normalizing DNP3 Response Timing and Segment Shape in the Network to Resist
Outstation Fingerprinting*. Accurate, but it reads as a protocol-specific defense paper and
buries the mechanism a systems reader (or a Google host-networking reader) would care about: a
single programmable-switch pipeline enforcing a timing and shape policy at line rate, measured
on real hardware, without touching endpoints.

Every option below is checked against the abstract's actual claims: one P4 program, one
Tofino-1 pipeline, one physical SEL-751 relay, fixed 4.001 ms response time, [28,21] shape on
1,280/1,280 responses, classifier at chance, evaluation bounded to one outstation and one
response class. None promises more than that.

## Recommended

**1. One Switch, One Clock: In-Network Timing and Shape Normalization Against Outstation Fingerprinting**
Short, memorable, honest. "One switch" is the deployment claim; "one clock" is the fixed-offset
release mechanism. Names both leak features. A Google reader sees a single-pipeline P4 system;
an NDSS reader sees the fingerprinting threat.

**2. Fingerprint at the Edge: Line-Rate Normalization of Field-Device Timing and Segment Shape on a Programmable Switch**
"Line-rate" and "programmable switch" are the systems hooks; "edge" locates the deployment.
Drops "DNP3" from the title on purpose so the paper reads as a mechanism generalizable beyond
one protocol, with DNP3 as the case study in the abstract. Use only if the Design section
actually argues the mechanism is protocol-agnostic; if the paper stays DNP3-specific, keep the
protocol in the title (options 3–4).

## Strong, protocol in the title

**3. Holding the Line: In-Network Normalization of DNP3 Timing and Segment Shape on a Single Tofino Pipeline**
"Holding" is literally what the switch does to the acknowledgment and response before release.
"Single Tofino pipeline" is a concrete implementation claim NDSS reviewers reward.

**4. Same Time, Same Shape: Defeating DNP3 Outstation Fingerprinting from the Data Plane**
Plainest statement of the result. "Defeating" is strong; it is backed by the classifier-at-chance
result, but soften to "Resisting" if the evaluation scope (one outstation, one response class)
makes a reviewer flinch.

## Systems-forward, for a Google-facing pitch

**5. Policy-Timed Responses: Enforcing Fixed Response Latency and Segment Shape for Industrial Devices in the Data Plane**
Reads like a host-networking paper (policy, latency, enforcement, data plane). Good for talking
to Dukkipati's group; slightly cold for NDSS.

## Notes

- Avoid "Obfuscation" in the title. The paper's own mechanism is normalization (one policy
  value), not randomization; "obfuscation" invites the wrong reviewer expectations.
- Avoid "Novel", "Robust", "Comprehensive" (banned by the paper-voice lexicon and by taste).
- Whichever title is chosen, the "To the best of our knowledge, this is the first ..." claim
  in the intro should match it exactly (first in-network normalization of both timing and
  segment shape for DNP3 on a single programmable switch, measured on real hardware).
- Not edited: the manuscript itself. This file is notes only.
