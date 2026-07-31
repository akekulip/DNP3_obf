# §10.B remaining items — concrete assessment (2026-07-31)

After the release-hardening pass, each §10.B item was probed to replace "lab-blocked"
assumptions with a checked verdict.

| item | verdict | basis |
|---|---|---|
| #13 core-vs-telemetry parity | **done (artifact level)** | `PARITY_core_vs_telemetry.md`: the final 10/12 core and 11/12 telemetry 9.13.2 assemblies share bit-identical SALU logic; telemetry adds only the two write-only timestamp registers. A full **physical** core-build campaign is the gold-standard open part. |
| #14 hardware-timestamped observer capture | **ACHIEVABLE (was mis-labeled infeasible)** | Vision's capture NIC `enp59s0f0np0` reports `ethtool -T` **hardware-transmit / hardware-receive / hardware-raw-clock**. So a capture with `SO_TIMESTAMPING` hardware RX timestamps at the master interface would resolve the ACK/RESPONSE arrival order and the ~32 us release-tail at nanosecond resolution — the earlier "~1 us host PCAP, cannot resolve" limit was a software-timestamp limit, not a hardware one. This is ready future work: swap `block.py` to a hardware-timestamped capture and re-run one campaign. |
| #12 ACK-retirement egress sweep | **partially unblocked by #14** | the retirement-to-egress order, as seen at the master, is exactly the ACK-vs-RESPONSE arrival order the hardware RX timestamps above can measure; the sweep at 0/32/.../512 ns offsets becomes measurable with hardware timestamps rather than needing switch-internal egress instrumentation. Still an experiment to run, no longer a hard block. |
| external-wire R1/R3 injection | **genuinely blocked** | the relay-facing switch port dp64 (PORT_RELAY) connects **directly to the physical SEL-751**; there is no host on that port to forge frames from. The in-switch injector remains the stand-in. |
| K-minimization sweep (§5.8) | **future optimization; harness gap identified** | KVAL is now wired into the gate2 driver, but reduced-K **hold** trials are refused by the setup's deliberate `K==64` safety pin in `offline_checks` (it only opens for READ-only fail-open trials). Running the continuity sweep requires explicitly relaxing that pin — a dedicated post-freeze experiment. The release artifact stays K=64, as the audit requires. |

**Bottom line:** the release-hardening (the audit's actual deliverable) is complete and
hardware-validated. Of the "valuable after release" §10.B items: #13 is done at the artifact
level; #14 and #12 are **achievable** (Vision has a hardware-timestamping NIC) and are ready
future experiments, not hard blocks; external injection is genuinely topology-blocked; and
K-minimization is future optimization gated by an intentional safety pin.
