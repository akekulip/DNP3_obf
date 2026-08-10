# Risk register

Revised for the one-Tofino testbed (`CORRECTION_LOG.md`). Ranked by how much each threatens a useful
outcome. Likelihood and impact are High/Medium/Low. Several former "risks" are now settled findings
(marked CONFIRMED) that bound the claim rather than open items to retire. Backed by the three
`analysis/` notes and the frozen upstream evidence.

| # | Risk / finding | Likelihood | Impact | Status / mitigation |
|---|---|-----------|--------|--------------------|
| R1 | **Full transcript invariance is unreachable natively.** Correct on-switch size and count closure requires store-and-forward TCP reassembly (a proxy), and indistinguishable native cover is impossible in self-describing plaintext. The forbidden proxy/encryption is exactly what full invariance needs. | CONFIRMED | High | Not retirable; it is the impossibility boundary. The claim is bounded to timing plus a partial header-scrub; size/count/endpoint-headers are declared residuals. `analysis/tcp_segmentation_and_headers.md`, `analysis/native_dnp3_mechanisms.md`. |
| R2 | **Fabricated DNP3 CONFIRM is a catastrophic relay-safety hazard.** It makes the outstation permanently delete Sequential-Events-Recorder / event-buffer records the real master never received — silent, irreversible loss of protective-event forensics. Runner-up: an injected application frame triggering an unconditional `ProcessIIN` WRITE (g50 time-sync, clear-restart). | CONFIRMED (if such a packet were used) | High | Barred by rule: no fabricated CONFIRM, no injected application frame, no control to the relay. The surviving mechanism sends no such packet. `analysis/native_dnp3_mechanisms.md`; upstream `adversary-model.md`. |
| R3 | **Decoy CROBs are unsafe on the physical relay.** They assert Remote Bits, write SER, pressure the event buffer, and couple to SELECT arm-state, making the switch a control-injection appliance in front of a protection relay. | CONFIRMED | High | Family 2 rejected for the physical testbed. Any SBO characterization stays on an isolated simulator. |
| R4 | **Device identity survives via the endpoint-stamped TCP-stack fingerprint.** TSval (PAWS clock), data-offset / option layout / window-scale, and seq/ack progression cannot be rewritten on one switch without breaking TCP. TTL and ip.id can be scrubbed, but data-offset (TTL's fingerprint partner) cannot. | CONFIRMED | High | Bounds the claim: header protection is partial. Declared as a measured residual, not a closed axis. `analysis/tcp_segmentation_and_headers.md`. |
| R13 | **The timing grid's cadence is unproven on silicon.** The only usable low-rate metronome is the pktgen periodic timer, whose inter-packet-gap floor and jitter are undocumented in the SDE and never measured; the TM max-rate shaper is falsified as a low-rate metronome (clumps at/below 600 pps). The frozen D4 deadline-release jitter cannot be borrowed (reactive, event-anchored, different mechanism). | High | High | The first silicon experiment (Experiment 2) measures slot jitter p50/p95/p99/p99.9, missed/duplicated/silent slots, exhaustion, clumping, eligibility latency, overlap, sustained + competing traffic. Hardware-gated. |
| R5 | **The bounded claim may be cosmetic over frozen Defense 4.** D4 already normalizes timing; the native increment is a stateless header-scrub (TTL/ip.id/window) plus public-offset framing. If that increment is thin, the verdict is closer to NO_GO than to a positive bounded claim. | Medium | High | Resolve in the decision memo and skeptical review: state precisely what is new over D4 and whether it clears a venue bar; lead the contribution with the impossibility boundary. |
| R6 | **On-switch size mechanisms do not fit the resources.** A functional (non-strippable) size mechanism needs per-flow seq translation = 32-bit ingress state on the saturated tail (stages 8-11 at 16/16 LTIDs, W0-15 at 512/512). The only size axis that fits (egress-only) is the strippable one already falsified. | CONFIRMED | High | Do not attempt on-switch size normalization. `analysis/tofino_native_scheduling.md`, upstream `p4-resource-audit.md`. |
| R7 | **Correctness under adverse regimes is inherited untested from D4.** The surviving timing mechanism releases real packets, but D4's live envelope excludes loss, retransmission, overlap, multi-segment, and the 12,204-byte response. | Medium | High | The functional-correctness proof class must re-establish these live; do not inherit them. `PROOF_OBLIGATIONS.md`. |
| R8 | **Native cover is always observer-labelable.** The safe cover (pure ACK, black-hole frame) is trivially stripped; the indistinguishable cover is barred or dangerous. So a cover-filled slot grid cannot hide size. | CONFIRMED | Medium | The surviving mechanism uses no cover; it releases only real packets on a public schedule. |
| R9 | **Overflow / large response leaks.** The 12,204-byte READ does not fit a small pattern; any size-adaptive continuation re-encodes size into count/duration. | Medium | Medium | Since size is not closed natively, overflow is handled by honest declaration (size is a residual), and `PATTERN_OVERFLOW` is counted. |
| R10 | **Scope creep into implementation.** A compiling probe is not a result. | Medium | Medium | No production P4/controller/pktgen/test code this phase; probes are resource measurements only. |

## The three that decide the project

- **R1 (CONFIRMED impossibility).** Full invariance is out of reach natively. The project's value is now
  the impossibility boundary plus whatever bounded defense survives, not a full fixed transcript.
- **R13 (cadence, unproven).** Whether even the timing-only bounded defense delivers a regular public
  grid on silicon is the one open technical unknown; it is the first hardware experiment.
- **R5 (novelty over D4).** Whether the bounded increment over the frozen timing result is a real
  contribution or cosmetic determines whether the honest verdict is a bounded claim or a no-go with an
  impossibility contribution.

## The two safety absolutes

R2 (fabricated CONFIRM) and R3 (decoy CROBs) are not trade-offs. The surviving mechanism sends no
fabricated application frame and no control to the relay, and any SBO or decoy characterization stays on
an isolated simulator. No privacy value justifies touching relay control, event, or SOE state.
