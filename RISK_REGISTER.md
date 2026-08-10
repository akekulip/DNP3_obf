# Risk register

Revised for the one-Tofino testbed (`CORRECTION_LOG.md`). Ranked by how much each threatens a useful
outcome. Likelihood and impact are High/Medium/Low. Several former "risks" are now settled findings
(marked CONFIRMED) that bound the claim rather than open items to retire. Backed by the three
`analysis/` notes and the frozen upstream evidence.

| # | Risk / finding | Likelihood | Impact | Status / mitigation |
|---|---|-----------|--------|--------------------|
| R1 | **Universal size/count invariance is the strongest no-go candidate (not a proven impossibility).** Correct on-switch fixed-K re-slicing/padding of the byte stream needs store-and-forward reassembly (a proxy); the `ignore = strip` coupling makes safe indistinguishable native cover a design hypothesis. Distinguish absence-from-the-frozen-implementation (well supported) from architectural impossibility (not established). | CONDITIONAL (analytical) | High | Not a completed proof; a provisional analytical no-go for *universal* invariance resting on correlated internal analysis that found no counterexample. `analysis/tcp_segmentation_and_headers.md`, `analysis/native_dnp3_mechanisms.md`; reframed in `DECISION_MEMO.md`. |
| R2 | **A premature application-layer confirmation is a DNP3 integrity hazard.** A valid-but-premature confirmation injected toward the outstation can retire acknowledged events from the **DNP3 event buffer** and prevent their later delivery to the master (once confirmed, the outstation need not resend them). Do NOT claim it permanently deletes the SEL-751's SER/SOE records without SEL-specific evidence; keep the DNP3 event buffer, SEL SER storage, and SEL event-report storage distinct. Runner-up: an injected application frame triggering a `ProcessIIN` action. | Real hazard (if such a packet were used) | High | Barred by rule: no injected confirmation, no injected application frame, no control to the relay. The surviving mechanism sends no such packet. `analysis/native_dnp3_mechanisms.md`; upstream `adversary-model.md`. |
| R3 | **Decoy CROBs are unsafe on the physical relay.** They assert Remote Bits, write SER, pressure the event buffer, and couple to SELECT arm-state, making the switch a control-injection appliance in front of a protection relay. | CONFIRMED | High | Family 2 rejected for the physical testbed. Any SBO characterization stays on an isolated simulator. |
| R4 | **TCP-stack-header normalization is UNRESOLVED (open, not a proven leak).** TSval, data-offset / option layout / window-scale, and seq/ack progression fingerprint the device. Whether one switch can normalize them (handshake option suppression, canonical data offset, TSval/ISN translation with checksum correction) without breaking TCP is untested. TTL and ip.id are scrubbable now. | OPEN | High | Not a settled residual: concrete counterexamples must be compiled and endpoint-safety-tested (Experiments 1-3). No header-level no-go is asserted. `analysis/tcp_segmentation_and_headers.md`, `EXPERIMENT_PLAN.md`. |
| R13 | **The periodic-cadence grid is unproven on silicon (now DEFERRED).** The only usable low-rate metronome is the pktgen periodic timer, whose inter-packet-gap floor and jitter are undocumented and unmeasured; the TM max-rate shaper clumps at/below 600 pps. The frozen D4 deadline-release jitter cannot be borrowed (reactive, event-anchored, different mechanism). | Medium (deferred) | Medium | Deferred off the critical path: the cadence experiment is decision-relevant only if a fixed number of safe real or cover packets can actually populate the slots. Until such a slot-population mechanism exists, cadence is not measured. `EXPERIMENT_PLAN.md`. |
| R5 | **The bounded claim may be cosmetic over frozen Defense 4.** D4 already normalizes timing; the native increment is a stateless header-scrub (TTL/ip.id/window) plus public-offset framing. If that increment is thin, the verdict is closer to NO_GO than to a positive bounded claim. | Medium | High | Resolve in the decision memo and skeptical review: state precisely what is new over D4 and whether it clears a venue bar; lead the contribution with the impossibility boundary. |
| R6 | **On-switch size mechanisms do not fit the resources.** A functional (non-strippable) size mechanism needs per-flow seq translation = 32-bit ingress state on the saturated tail (stages 8-11 at 16/16 LTIDs, W0-15 at 512/512). The only size axis that fits (egress-only) is the strippable one already falsified. | CONFIRMED | High | Do not attempt on-switch size normalization. `analysis/tofino_native_scheduling.md`, upstream `p4-resource-audit.md`. |
| R7 | **Correctness under adverse regimes is inherited untested from D4.** The surviving timing mechanism releases real packets, but D4's live envelope excludes loss, retransmission, overlap, multi-segment, and the 12,204-byte response. | Medium | High | The functional-correctness proof class must re-establish these live; do not inherit them. `PROOF_OBLIGATIONS.md`. |
| R8 | **Native cover is always observer-labelable.** The safe cover (pure ACK, black-hole frame) is trivially stripped; the indistinguishable cover is barred or dangerous. So a cover-filled slot grid cannot hide size. | CONFIRMED | Medium | The surviving mechanism uses no cover; it releases only real packets on a public schedule. |
| R9 | **Overflow / large response leaks.** The 12,204-byte READ does not fit a small pattern; any size-adaptive continuation re-encodes size into count/duration. | Medium | Medium | Since size is not closed natively, overflow is handled by honest declaration (size is a residual), and `PATTERN_OVERFLOW` is counted. |
| R10 | **Scope creep into implementation.** A compiling probe is not a result. | Medium | Medium | No production P4/controller/pktgen/test code this phase; probes are resource measurements only. |

## The three that decide the project

- **R1 (conditional analytical no-go).** Universal size/count invariance is the strongest no-go candidate,
  provisional and not a completed proof. The project's value is the frozen D4 positive result plus the
  provisional no-go plus the open header extension, not a full fixed transcript and not an impossibility
  proof.
- **R4 (TCP-header, open).** Whether the TCP-stack header can be normalized on one switch is unresolved;
  its counterexamples (Experiments 1-3) are the first work and decide whether a broader bounded defense
  exists.
- **R5 (novelty over D4).** Whether the header extension, if it survives, is a real contribution over the
  frozen timing result determines whether the honest verdict is a positive bounded claim or the provisional
  no-go plus a bounded floor.

## The two safety absolutes

R2 (premature application confirmation) and R3 (decoy CROBs) are not trade-offs. The surviving mechanism
injects no application frame and sends no control to the relay, and any SBO or decoy characterization
stays on an isolated simulator. No privacy value justifies injecting a confirmation (which can retire
events from the DNP3 event buffer) or asserting control state on the relay.
