# Decision memo — one-Tofino native revision

**Decision: `NO_GO_FULL_TRANSCRIPT` — a conditional analytical verdict, not a completed impossibility
proof.** The scope of this verdict is narrow and explicit (correction, this commit): it applies only to
**universal plaintext size/count/timing/header invariance** on the binding testbed
`Master <-> Tofino-1 <-> Outstation`, with no decoding peer and no encryption. It is the current working
conclusion of an internal analysis, and it is provisional: two of its three supporting arguments are not
settled, and the TCP-header question is explicitly **unresolved**, with concrete counterexamples that must
be compiled and tested before any header-level impossibility can be asserted.

This memo supersedes the baseline decision of `f2bd3e4` (which recommended `GO_WITH_BOUNDED_CLAIM` on the
now-excluded paired gateway). It preserves `f2a0dec` and corrects that commit's overreach: it downgrades
the "impossibility proof" framing to a conditional analytical no-go, reclassifies the three "walls,"
reopens the TCP-header question with a counterexample program, and corrects the relay-safety wording.

## What "evidence" this rests on (correction 1)

The conclusion is supported by an internal, correlated adversarial analysis: three specialist agents
(DNP3/relay-safety, TCP/traffic-analysis, Tofino/TM) and one skeptical reviewer agent, all working from
the same framing, the same frozen upstream artifacts, and shared priors. Their agreement is best
described as **correlated internal analysis that found no counterexample**, not as independent evidence
and not as proof. In particular, the skeptical reviewer's failure to construct a counterexample reduces
but does not eliminate the chance that one exists; it is a search that came up empty, not a demonstration
that the space is empty.

## The relevant hardware limitation (correction 2)

Defense 4 is **DNP3-aware**: it parses DNP3 link and application structure and matches transactions by
generation code. The limitation that matters here is therefore not "DNP3-blindness." It is that a
Tofino-1 pipeline performs **bounded per-packet parsing and bounded per-packet state**, without arbitrary
TCP-stream reassembly and without application-level store-and-forward transformation across packets.
Fixed-`K` re-slicing or padding of a byte stream, and cross-segment object reassembly, fall outside that
bound. This is the precise capability gap, stated as a capability, not as blindness.

## The three arguments, reclassified (correction 3)

1. **`ignore-rule = strip-rule` — design hypothesis / conditional lemma, not a proven wall.** The claim
   is that in self-describing, CRC-checked plaintext DNP3, the rule by which the receiver ignores a
   filler packet coincides with the rule by which a passive observer strips it, so native cover cannot be
   both endpoint-safe and observer-indistinguishable. This is a plausible and useful lemma, but it holds
   only under a stated adversary model, endpoint model, and semantic model that this phase has not yet
   formalized. It is recorded as a **hypothesis to be formalized**, not as a settled fact.
2. **General size/count closure without a decoding peer — the strongest no-go candidate.** This is the
   most solid of the three, but the memo now distinguishes two different claims that the prior version
   conflated: (a) *no such mechanism is present in the frozen implementation or in any construction the
   internal analysis found* (well supported); versus (b) *no such mechanism can exist on this
   architecture* (an architectural-impossibility claim that is **not** established). The verdict rests on
   (a). The upstream `split_server.py` that "preserves bytes" is a TCP-terminating socket proxy, so it is
   evidence that the known byte-preserving construction is a proxy, not evidence that no non-proxy
   construction exists.
3. **Endpoint-stamped TCP headers — UNRESOLVED, not an impossibility.** The prior version asserted that
   TCP-timestamp, sequence/acknowledgment, data-offset, and window-scale normalization is unreachable on
   one switch. That assertion is withdrawn. Concrete counterexamples exist (next section) and have not
   been compiled or tested. Until they are, the TCP-header axis is an **open question**, and no
   header-level no-go is claimed.
   - **Experiment 1 update (2026-08-10, `experiments/exp1_tcp_header_attribution/`, verdict PROMISING):**
     offline, the outstation `data_offset` fingerprint was attributed to exact TCP option bytes over three
     physical stacks, and a canonical-option-layout transform removed the dominant header fingerprint
     (handshake-captured distinct signatures 3 -> 1) with byte-exact DNP3 payload and valid checksums;
     length-only IP normalization and timestamp-origin translation did not. This moves the TCP-header axis
     from "unresolved" to **"offline-removable; live-feasibility and endpoint-safety still open."** The
     offline collapse used option *suppression* (likely endpoint-unsafe live); the live-safe *translation*
     path needs the per-flow 32-bit state the resource audit flags as tight, and the TCP window value
     survives as a residual. This authorizes only a later request for Experiment 2 (a standalone compile
     probe); it does not change the `NO_GO_FULL_TRANSCRIPT` verdict.

## TCP-header normalization: counterexamples to compile and test (correction 4)

These are concrete mechanisms that, if they compile on the target and pass endpoint-safety testing, would
close part of the TCP-stack fingerprint on one switch without a decoding peer. They are **recorded as
counterexamples that must be evaluated before any TCP-header impossibility can be asserted**; none is
claimed to work.

- **Handshake option suppression.** During SYN and SYN-ACK, suppress the TCP Timestamps option, window
  scale, and SACK-permitted negotiation, so the connection never enables the endpoint-stamped behaviors
  that fingerprint the device. Requires rewriting only handshake packets, which are small and parsed.
- **Canonical option layout.** Replace removed or reordered options with a canonical NOP/EOL layout, and
  pad shorter TCP headers up to a single public data offset, so `tcp.data_offset` and the option ordering
  are class constants rather than device tells.
- **Timestamp translation.** If timestamps cannot be suppressed (peer requires them), translate the
  outstation's TSval by a fixed per-flow offset and reverse the corresponding TSecr on the opposite
  direction, so the observed clock is a class constant while PAWS/RTTM still see a consistent series.
- **ISN / sequence normalization.** Evaluate a per-flow sequence and acknowledgment delta so initial
  sequence numbers and their progression are normalized, with the delta applied consistently in both
  directions.
- **Checksum correctness.** Update IPv4 and TCP checksums for every rewrite.
- **Correctness analysis required.** Each mechanism must be analyzed and tested for retransmission,
  connection reuse, sequence wraparound, PAWS, RTTM, and failure handling, on ordinary TCP first and then
  an isolated OpenDNP3 environment. A per-flow bidirectional offset is per-flow state, and whether it fits
  the target and survives these regimes is exactly what the compile and endpoint-safety experiments must
  decide. A compile failure would be a **bounded target result for these mechanisms**, not a universal
  impossibility.

## Relay safety, corrected (correction 5)

A **valid but premature application-layer confirmation** injected toward the outstation can **retire
acknowledged events from the DNP3 event buffer and prevent their later delivery to the master**: once the
outstation treats those events as confirmed, it need not resend them, so the master never receives them.
This is a real integrity hazard and is sufficient reason to bar injected confirmations. The prior wording
that a fabricated CONFIRM "permanently deletes the SEL-751's SER/SOE records" is **withdrawn as
unsupported**: it requires SEL-specific behavior we have not verified. Three distinct stores must be kept
separate and not conflated: the **DNP3 event buffer** (protocol-level, what a premature CONFIRM affects),
the **SEL Sequential-Events-Recorder storage**, and the SEL **event-report storage**; effects on the
latter two require SEL-specific evidence that this phase does not have.

## The security objective, clarified (correction 6)

- **Secret `X`** = physical outstation identity as expressed through timing, size, count, and TCP/IP-stack
  features.
- **Public `C`** = transaction occurrence, operation class, and the plaintext DNP3 semantics of the
  transaction for this bounded phase.
- The invariance claim is **conditional on the same public semantic transaction**: the defense aims to make
  two physical devices executing the same public transaction class look alike, not to hide the transaction
  or its class.
- **Explicitly excluded:** payload confidentiality and activity hiding.

A scoping note that keeps the problem interesting: if the plaintext response *content* itself is placed in
`X`, then the no-go is trivial and scientifically uninteresting, because a passive reader of unencrypted
DNP3 reads the content directly and no in-network shaping can hide it without encryption. The bounded
problem worth studying is device-identity indistinguishability *across devices running the same public
semantic transaction*, with content in `C`.

## The verdict scope and the positive result (correction 7)

`NO_GO_FULL_TRANSCRIPT` is preserved **only** for universal plaintext size/count/timing/header invariance.
Alongside it, two positives stand:
- **A positive bounded defense already exists** for the tested Defense 4 timing scope: on one SEL-751,
  Case-A READ, single-segment, the frozen D4 mechanism normalizes the cross-layer response time (the
  timing axis) with the bounded results in `D4_UPSTREAM_CONTRACT.md`.
- **Broader D4-plus-TCP/IP-header normalization remains open** and is the strongest prospective bounded
  extension, pending the counterexample program above.

## The decision-memo amendment (correction 10)

- **Strongest current full-transcript no-go basis:** generic size/count closure for *varying* plaintext
  responses without a decoding peer (argument 2a).
- **TCP-header closure:** unresolved (counterexamples pending compile and test).
- **Strongest positive result:** the frozen Defense 4 timing normalization, within its tested scope.
- **Strongest prospective bounded extension:** Defense 4 plus tested TCP/IP-header normalization.
- **Impossibility-contribution status:** provisional, until the formal assumptions of the `ignore = strip`
  lemma are stated and the TCP-header counterexample analysis is complete.

## The ten required framing points (retained, corrected)

1. **Strongest one-Tofino candidate:** the frozen Defense 4 timing normalization on the real packets, at a
   public request-anchored offset, plus (prospectively, pending the counterexamples) stateless TCP/IP
   header normalization. Within the tested D4 scope this is a real positive; its extension to headers is
   open.
2. **Strongest rejected candidate:** paired software gateways with an encrypted tunnel
   (`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`), excluded by the hard constraint.
3. **Protected vs leaked observables:** protected today = the timing axis (tested D4 scope), plus TTL and
   ip.id which are statelessly rewritable. Open = the rest of the TCP-stack header set (data-offset,
   timestamps, window-scale, sequence), pending the counterexamples. Leaked without a decoding peer =
   size and, for multi-segment responses, count.
4. **Endpoint-safety argument:** the surviving mechanism forwards genuine bytes, injects no cover, and
   sends no control or premature confirmation; it is proven safe only inside D4's tested envelope
   (single-segment READ, no induced loss/retransmission, sequential polling, R11 margin open), and the
   other regimes must be re-established live, not inherited.
5. **Inherited from Ditto:** its TM scheduling discipline only; its encryption and peer-side de-padding are
   unavailable here.
6. **DNP3-specific:** the separate-ACK cross-layer response time; the (hypothesized) `ignore = strip`
   coupling for self-describing correctness-critical plaintext protocols; and the event-buffer integrity
   hazard of premature confirmations.
7. **First falsification experiment:** Experiment 1, read-only/offline (attribute the data-offset
   fingerprint to exact TCP options across sessions and devices; test PCAP-level canonical
   transformations) — see `EXPERIMENT_PLAN.md`.
8. **First silicon experiment:** Experiment 2, compile-only and separately authorized (a standalone Tofino
   TCP-header normalizer) — see `EXPERIMENT_PLAN.md`. The periodic-cadence experiment is deferred; it
   becomes decision-relevant only if a fixed number of safe real or cover packets can actually populate
   its slots.
9. **First functional compile probe:** the co-residency probe is not specified with a vague "functional
   size mechanism." Either an exact endpoint-safe mechanism with named packet transformations and recovery
   semantics is specified, or this remains an explicit unresolved experiment-selection gate
   (`EXPERIMENT_PLAN.md`).
10. **Condition that would terminate the full-transcript claim:** it is terminated only for universal
    invariance under argument 2a; it would reopen toward a positive bounded result if any of the TCP-header
    counterexamples compiles and passes endpoint-safety testing, or if a non-proxy size/count construction
    is found.

## Path forward

Next, if Philip approves: Experiment 1 (read-only/offline), then Experiment 2 (compile-only, separately
authorized), then Experiment 3 (endpoint safety on ordinary TCP and isolated OpenDNP3, only afterward
read-only SEL-751), with the cadence experiment deferred until a slot-population mechanism exists. Write
the result as a conditional analytical no-go with an open header question, not as an impossibility proof.
Decisions that gate this are in `OPEN_QUESTIONS_FOR_PHILIP.md`.
