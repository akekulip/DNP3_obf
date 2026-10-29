# D3, E1 and E2 on the diagnostic mirror build (2026-10-29)

**Diagnostic-build evidence.** Build `c72_diag_mirror`, source SHA-256 `a46cc55a…`, derived from c72 by 13 pipe-0
insertions (`results/builds/c72_diag_mirror/README.md`). Nothing here establishes anything about the exact c72
binary. The design, observables and falsifiers were registered before traffic in `DESIGN.json`.

## Runs

| Campaign | Block | Trials | Mirror sessions | Result | Restoration |
|---|---|---:|---|---|---|
| `rc01_hw_c72diag_d3on_20261028_01` | `d3_mirror_on_d20` | 8 (4 arms × 2) | on | rc 0, 8/8 trials and verdicts pass | ok |
| `rc01_hw_c72diag_d3off_20261028_01` | `d3_mirror_off_d20` | 8 (4 arms × 2) | off (present, disabled) | rc 0, 8/8; 0 copies captured | ok |
| `rc01_hw_c72diag_e2_20261028_01` | `e2_first_request_d20` | 32 (off arm, 8 READs) | on | rc 0, 32/32 | ok |

Each block ran as its own single-block campaign under the freeze-gate diagnostic admission: the build regenerates
byte-for-byte from the canonical source, and its blocks never qualify. The freeze, freeze check, dry-run and init
logs are in `runs/<campaign>/`. The analysis is `diag_mirror_d3.json`; the E1 per-connection reports are in
`diag_mirror_d3_e1/`.

## Verdicts against the registered design

| Check | Registered falsifier | Result |
|---|---|---|
| D3a port mapping | no relay-leg copies on `enp59s0f1np1` while dev10 TX advances | **pass**, 8/8 trials |
| D3b copy fidelity (off arm) | any byte difference, short copy, or unexplained missing copy | **pass**: 1,173/1,173 copies byte-identical to the master-NIC reference |
| D3c completeness | unexplained missing copies, kernel drops, caplen below frame length | **pass**: 8/8 mirror-on trials, 32/32 E2 trials |
| D3d mirror on vs off | any delivery or size difference; timed-arm median CLRT difference above 50 µs | **fail** (4 timed cells exceed 50 µs) |
| E1 preservation | any content difference after removing only the declared padding; any unmatched transaction | **pass**: 4/4 padded connections |
| E2 first request | none for the location itself | 3 of 40 mirror-on fresh connections retransmitted the first request; all 3 lost inside the switch |

**D3a.** Copies arrive on Vision `enp59s0f1np1` (i40e, bus `0000:3b:00.1`). The D1 inference that dev10 is
cabled to that port is now confirmed. In every trial the interface RX count equals the copies captured, and
tcpdump reported 0 kernel drops.

**D3b.** In the two off-arm trials (T = 0, padding = 0) every request sent by the master equals its egress copy and
every relay response delivered to the master equals its ingress copy, frame for frame: 395 requests and 778
responses. The comparison restores the NIC-computed TCP checksum on the master's transmit capture, because it was
taken before checksum offload.

**D3c.** In every trial the switch counters satisfy dev10 TX = dev64 RX + TX, so every frame on the relay leg was
copied. Copies against counters are bounds: the switch snapshots bracket the whole Vision step, which is longer
than the capture.
- **Third device on the relay segment:** a device with MAC `70:49:a2:6b:6c:89` broadcasts DHCP Discover there. Its
  frames are counted in dev64 RX and mirrored as ingress copies. Copy direction is therefore attributed by source:
  the master's MAC means an egress copy, any other source an ingress copy.
- **Missing copies are switch non-forwarding:** 8 master frames have no egress copy (3 in d3on, 5 in the E2 block).
  Each is matched one-for-one by a frame the switch received on dev9 and never transmitted on dev64
  (dev9 RX − dev64 TX). The capture missed nothing.
- **Gate refined during analysis:** the first implementation gated on equality of connection frames, which
  counted these frames as capture loss. The refined gate follows the registered "unexplained" wording, and its
  tests cover both cases (switch did not emit: explained; switch emitted, no copy: failure).

**D3d.** Delivery and response sizes are identical with the mirror on and off in every arm and class.
- **The failing cells:** the median CLRT (relay ACK to complete response at the master) differs by −231 µs
  (combined READ mixed), +80.5 µs (combined SELECT), +139.5 µs (combined OPERATE) and +142.5 µs (timing_only
  SELECT). These exceed the registered 50 µs bound, so D3d fails as registered.
- **Context:** in the c72 evaluation at D = 20 ms, the per-repetition median CLRT of the timed arms spans 266–1,085 µs
  across 16 repetitions (within-arm IQR 1.3–1.6 ms). The registered bound was tighter than the system's own
  block-to-block variation, and the observed shifts lie inside it.
- **Consequence:** no mirror effect is detectable at 2 trials per arm, and no equivalence is claimed. D3d gates only
  uses of mirror timing; E1 uses content, and E2 uses only which copies exist and their order.

**E1.** Over the 4 padded mirror-on connections (size_only and combined, 2 each), every relay response is identical
in application content (groups, variations, qualifiers, indices, values, flags, IIN, CROB echo) to the padded
response the master received, once only the declared padding and declared header changes are removed: 772/772
responses. Every master request equals the request that left toward the relay: 772/772. The TCP sequence
translation agrees with the declared padding growth at all 776 points.
- In combined t0 the relay-side copy of the first request is the master's retransmission (E2 below). Its IPv4 ID
  identifies it, and pairing on that ID removed three spurious header differences found in the first pass.

**E2.** 3 of the 40 mirror-on fresh connections retransmitted the first request, at 217.7, 206.3 and 213.4 ms
(combined t0 in d3on; t19 and t22 in the E2 block). In all three:
- **Never left the switch:** there is no egress copy of the original request, only of the retransmission.
- **Did reach it:** dev9 RX equals every frame the master sent in the window, and dev64 TX is one lower.

The narrowest supported location is inside the switch: the request was received on dev9 and never emitted on
dev64. The 8 mirror-off connections show no retransmission, so 3 of all 48 fresh connections retransmitted.

**A related observation at connection start.** In 5 further fresh connections (d3on off t1 and size_only t0; E2 t0,
t17 and t27)
the switch received the master's final handshake ACK and did not forward it. TCP does not notice, because the
next data segment carries the same acknowledgement. In every one of these 8 connections (8 of 40), the frame the switch did
not forward is one of the first two master frames after the relay's SYN-ACK. The mechanism inside the pipeline is
not identified here. A model reproduction (ACK and first request right after the SYN-ACK) is the next check.

## Limits

- 2 trials per arm in D3/E1; E2 is a bounded diagnostic, not a rate.
- The mirror shows what the switch emitted toward the relay and received from it; it does not show what the relay
  did with a frame. No E2 case needed that, since no loss fell after switch egress.
- Relay-side timestamps from the mirror are not used for any timing claim, because D3d did not pass.
