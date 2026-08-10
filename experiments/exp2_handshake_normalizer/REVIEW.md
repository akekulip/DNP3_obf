# Experiment 2A — review outcome and reconciliation

Two independent adversarial reviews of `EXPERIMENT_2A_DESIGN.md`, one on TCP/RFC endpoint-safety, one on
Tofino-1 / bf-p4c feasibility. Both were read-only and tried to break the design. **Both passed it, with
required fixes, all of which have been applied to the design.**

## Verdicts

- **TCP / RFC endpoint-safety review: survives with caveats.** The RFC negotiation-fallback backbone is
  sound for compliant stacks: Timestamps and Window Scale (RFC 7323), SACK-permitted (RFC 2018) are used
  only if both SYN and SYN-ACK carry them, and RFC 1122 tolerates absent options without error; the
  sequence-space reasoning is correct.
- **Tofino / bf-p4c feasibility review: ready-with-fixes.** The mechanism fits comfortably standalone once
  respecified to the idioms the frozen codebase already compiles; the two risks the first draft named were
  over-specification artifacts, not target limits.

## Fixes applied (TCP / RFC review)

1. **Never strip a SYN-ACK.** The SYN-ACK path now canonicalizes the MSS value only when the option set is
   already minimal, and **fails open** (forwards unchanged, counts `noncompliant_bypass`) if a negotiated
   option is present — stripping it would desynchronize window scale between the ends. This reconciles the
   original §2/§4 contradiction the reviewer caught.
2. **MSS is clamped `min(orig, 1460)`, never set** — a set could raise an endpoint's advertised MSS and,
   with DF, create a PMTU blackhole.
3. **DF is preserved, not forced;** IP-ID is zeroed only when DF is set (RFC 6864).
4. **Option allow/deny list with fail-open on unknown kinds;** TCP-MD5 / TCP-AO are explicitly excluded
   (they ride every segment as a security association and must never be stripped).
5. **Fail-open any SYN/SYN-ACK carrying payload or a TFO cookie** (RFC 7413) — payload in a SYN is in the
   sequence space.
6. **MPTCP / simultaneous-open explicitly excluded** (DNP3 is client/server).
7. **The Experiment-1 overclaim is removed:** the design no longer asserts Experiment 1 showed devices
   falling back to a stripped SYN (it showed replies to a full SYN); that is Experiment 3's job.
8. **The in-path-from-setup + symmetric-routing assumption is written down** as load-bearing; the stateless
   non-compliance test is sound only under it, otherwise per-flow SYN-seen state is needed.
9. **SACK removal now carries a required Experiment-3 induced-loss availability test** against the DNP3
   master application response timeout (correctness is never at risk; availability under multi-segment loss
   is the open question).

## Fixes applied (Tofino / bf-p4c review)

1. **Deleted the variable-length TLV option parser.** Option handling is now fixed-width extraction keyed
   on `data_offset` (extending the frozen `opt4/8/12` chain to `data_offset` 6..15, ~10 fixed states, no
   kind/length decode, no runtime advance — the frozen program documents "the TNA parser cannot advance by
   a runtime amount"). Established segments just read `data_offset` and count if != 5.
2. **Whole-region suppression via `setInvalid` + a fresh 4-byte MSS header,** not in-place rewrite —
   avoids pulling <=40 old option bytes into normal PHV (the frozen program keeps `tcp_opt*` in tagalong
   precisely because it never writes them).
3. **Full deparser `Checksum.update()` over the no-payload handshake, not an incremental delta** — the
   entire covered region is in PHV for a SYN/SYN-ACK, so no old bytes or payload read are needed.
4. **Retracted the false attribution** that "the resource audit flagged the TCP checksum" — the frozen
   audit never mentions checksum; the claim came from an assertion in Experiment 1's `TOFINO_REQUIREMENTS.md`.
   The TNA checksum extern is lab-proven on this testbed.
5. **Removed Ethernet minimum-length padding from P4** — the Tofino MAC auto-pads runt frames on transmit.
6. **First compile probe uses global counters and no flow table,** to isolate the parser/checksum
   questions.
7. **Corrected the functional-check tool** in the success criteria: the Tofino behavioral model
   (`tofino-model` + PTF/scapy, or p4testgen/STF), not BMv2 (which does not run TNA) and not bf-p4c alone
   (which does no simulation).
8. **Corrected the resource expectation** from "likely fits" to "fits comfortably," with the only
   non-trivial resource being the `data_offset`-keyed fixed option-extraction parser states.

## Net outcome

The design **survives review** and is **compile-probe-ready**. The mechanism (handshake-only option
suppression with clamped MSS, canonicalized L3, full checksum recompute, fail-open everywhere) is
stateless / packet-bounded, needs no per-flow 32-bit registers, and maps onto idioms the frozen codebase
already compiles; its residual uncertainties are (a) the `data_offset`-keyed parser fit (a compile
question, Experiment 2) and (b) whether real device stacks honor the negotiation fallback and tolerate the
loss of PAWS/RTTM/SACK within the DNP3 timing budget (an endpoint-safety question, Experiment 3).

**Gate:** per Philip's instruction, "after that design survives review, authorize the standalone
Experiment 2 compile." The design has survived review. The standalone Experiment 2 compile is therefore
the authorized next step, pending Philip's go-ahead; it remains compile-only, standalone, no hardware, no
Defense 4 co-residency, and its success criteria are §6 of the design.
