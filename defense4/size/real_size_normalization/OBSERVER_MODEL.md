# Observer Model

Gate: S0
Status: reviewed S0 model

## Primary observer

The protected observer is passive, protocol-aware, TCP-aware, and positioned on the current Vision-to-Tofino link identified in `defense4/README.md` as the observed WAN side of `dp9`.

The observer can capture the complete outer transcript in both directions and can:

- measure every frame and packet length under one consistent convention;
- count packets and total bytes;
- identify direction, flow boundaries, and concurrent flows;
- measure timestamps and inter-packet gaps at capture resolution;
- parse every unencrypted link, network, transport, and DNP3 field;
- reconstruct TCP sequence space, ACK progression, retransmissions, and duplicate bytes;
- identify and reassemble IP fragments;
- filter invalid checksums, out-of-window segments, recognizable retransmissions, and unrelated flows;
- compare many transactions and train on the complete transcript;
- know the design, source, policy, format, and procedure, but not keys or fresh nonces.

The observer is passive for the primary confidentiality claim: it does not need to drop, delay, inject, or modify traffic to defeat a leaking design.

## Captured features

| Feature family | Examples |
| --- | --- |
| Size | frame length, IP total length, payload length, total novel bytes |
| Count | packets or cells per direction and slot |
| Direction | request/ACK/response sequence |
| Timing | slot offsets, inter-cell gaps, epoch duration |
| Transport | sequence/ACK deltas, retransmissions, fragmentation |
| Flow | protocol, 5-tuple, grouping, concurrency |
| Clear metadata | length, function, type, final marker, cover flag, padding delimiter |

The attack feature is the whole ordered transcript, not an unordered packet-length histogram.

## Required trust boundaries

The property requires two trusted transformations around the observed link:

1. a Vision-side shim converts clear endpoint traffic to the protected cell transcript and reverses the response path;
2. a relay-edge shim converts cells back to clear DNP3 before relay delivery and cellizes clear return traffic after the timing release.

S0 does not assert that the second boundary exists. S1 must verify whether the installed Tofino control CPU and CPU-port path can serve it. If not, the current testbed has no verified two-boundary architecture and real size normalization is blocked.

## Active robustness cases

Active injection, loss, replay, reordering, and denial of service are not required to infer leaking length. They remain integrity and safe-failure tests:

- forged or modified cells fail authentication;
- duplicate or stale cells are never delivered as new bytes;
- missing or reordered cells do not cause unbounded buffering or unsafe fail-open delivery;
- recovery behavior does not depend on whether a missing cell held data or cover.

Availability against an on-path active attacker is not promised; bounded, fail-closed behavior is required.

## Non-capabilities and out-of-scope compromise

The primary observer cannot compromise Vision, the Tofino control CPU/data plane, or relay; read keys or trusted memory; change P4/control state; or obtain a separate cleartext oracle inside a trusted zone. Endpoint compromise, key extraction, malicious administration, supply-chain compromise, and physical tampering invalidate the confidentiality boundary and require separate controls.

## Public information

Kerckhoffs's principle applies. Cell size/count, schedule, algorithms, implementation source, public headers, and corpus may be known. Security depends on standard cryptographic keys and the fixed outer invariant, not obscurity.

## Scope assumptions already confirmed

- This is the isolated current lab testbed, not an Internet-facing service.
- No new host, SmartNIC, relay, or gateway may be introduced.
- Only Vision, the installed UFISpace Tofino-1/onboard CPU, and current relay leg are candidates.
- The primary attacker is passive; active faults are robustness tests.
- S0-S2 are design-only and do not mutate the live dataplane.

These constraints were supplied by the user and directive, satisfying the threat-model context check for this tranche. Remaining questions concern measurable capabilities, not missing deployment context.

## Evidence anchors

- `defense4/CODEX_NEXT_PHASE_REAL_SIZE_NORMALIZATION.md`
- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/E0_testbed_preservation.md`
