# Architecture candidates

This lays out the candidate transcript designs and compares them against the same checklist. The
Ditto-style repeating pattern is treated as the leading hypothesis to beat, not the assumed winner.
Each candidate is scored on the axes from `OBSERVABLE_TRANSCRIPT_SPEC.md` and on the operational
questions the charter requires. Hardware verdicts are cross-checked against `TOFINO_TM_FEASIBILITY.md`
and `RESOURCE_BUDGET.md`; transport and encryption verdicts against
`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`. Where those specialist documents refine a verdict here, they
win and this file is updated.

## The checklist every candidate must answer

1. Is packet count `K` secret-independent?
2. Are all visible sizes secret-independent?
3. Are release times (or their declared distribution) secret-independent?
4. How do real packets replace chaff?
5. How is a slot emitted when no real packet exists?
6. How does the receiver tell real data from chaff?
7. Do outer headers (`h_i`) remain fingerprintable?
8. Does an empty scheduled slot get skipped (the empty-queue question)?
9. How do late responses, overlap, loss, retransmission, and reordering behave?
10. How are large READs and multiple TCP segments accommodated (the 12,204-byte case)?
11. What happens under overload?
12. Which behavior fails open, fails closed, drops, or records a privacy violation?

A design that cannot answer 4, 5, 6, and 8 concretely is not a candidate, because those four are
where naive "just pad it" ideas fail on real hardware.

## The encryption precondition

Questions 4 and 6 have one honest answer across every mixed real/chaff design: the observer can tell
real from chaff unless the outer bytes are encrypted, because plaintext DNP3 is readable and
CRC-checked. So any design that emits chaff cells and swaps in real cells requires an encrypted outer
layer whose ciphertext block lengths are exactly the fixed visible sizes. This is not optional and it
is the pivot of the whole project: it decides whether one Tofino plus one remote endpoint is enough
or whether a local encapsulation function near the outstation is unavoidable
(`TRANSPORT_AND_ENCRYPTION_OPTIONS.md`). Candidates are grouped by whether they need this.

---

## Candidate A — continuous constant-rate single-size cells

The link carries a steady stream of equal-size encrypted cells at a fixed rate in both directions,
whether or not a real exchange is happening. Real DNP3 bytes are fragmented and packed into cell
payloads; empty cells carry padding. This is the link-padding / IP-TFS shape.

- Count: secret-independent by construction (fixed rate, so `K` over a window is fixed).
- Sizes: secret-independent (one cell size).
- Timing: secret-independent (fixed rate; the release schedule is a public constant).
- Real replaces chaff: the encapsulator fills the next scheduled cell with real bytes when available,
  otherwise with padding; the observer cannot tell which because both are ciphertext.
- Empty slot: the slot is still emitted, as a padding cell. Nothing is skipped.
- Receiver disambiguation: the decapsulator decrypts and reads an inner length/type field to separate
  real bytes from padding.
- Outer headers: neutralized, because the outer header is the tunnel's own and is identical for every
  cell.
- Empty-queue behavior: not applicable in the dangerous sense, because chaff is always available to
  fill the slot; this is the design that most cleanly sidesteps the empty-queue trap, but it needs a
  continuous chaff source.
- Late/loss/retransmission/reorder: handled by the inner TCP stream inside the tunnel; the tunnel
  itself is a constant-rate pipe, so inner retransmissions just occupy more cells and do not change
  the transcript.
- Large READ / multi-segment: fragmented across many cells; the 12,204-byte READ simply takes more
  cells at the fixed rate, which lengthens delivery but does not change any visible size.
- Overload: if real bytes arrive faster than the cell rate, they queue inside the encapsulator and
  latency grows; the transcript stays fixed. This is a latency-versus-privacy knob, not a leak.
- Failure mode: fails closed on privacy (it never emits a non-cell), and the availability risk is
  added latency, which must be bounded against DNP3 timers.
- Hides transaction occurrence: yes. This is the only family that closes the occurrence channel.
- Cost: highest. Constant bandwidth even when idle. This is the price of hiding occurrence.

## Candidate B — request-synchronized fixed epoch, one cell size

Cover traffic is not continuous. When a request is recognized, the switch runs a fixed epoch: a fixed
number of equal-size cells on a fixed schedule, the same for every protected secret. Outside an epoch
the link is idle.

- Count: secret-independent within an epoch (fixed cell count), but the existence of an epoch reveals
  that a poll happened. So this protects value/size/type but not occurrence.
- Sizes: secret-independent (one size).
- Timing: secret-independent within the epoch.
- Real replaces chaff / disambiguation / headers: same encryption precondition as A.
- Empty slot: within an epoch, unused cells are padding cells, still emitted.
- Large READ: if the response exceeds the epoch's provisioned cells, the epoch must either extend in a
  secret-independent way (a fixed larger epoch class) or declare `PATTERN_OVERFLOW`. Choosing the
  epoch size is a public parameter, not a function of the response.
- Overload / failure: same shape as A but only during epochs; fails closed on privacy, availability
  risk is bounded epoch latency.
- Cost: pays overhead only when polls happen. Good fit if occurrence is public (in `C`).

## Candidate C — request-synchronized fixed epoch, static multi-size pattern

Like B, but the epoch is a fixed pattern of several cell sizes (for example a small cell then two
medium cells) chosen once and public. Motivation: a single cell size can be wasteful for a protocol
with a few characteristic response shapes; a fixed multi-size template can cut overhead while still
being secret-independent.

- Count/sizes/timing: secret-independent as long as the template is fixed and public and identical
  across secrets. The risk is that a multi-size template invites making the template depend on the
  response, which is exactly the barred adaptive-K failure. The template must be keyed only on `C`.
- Everything else: as B.
- Trade: lower overhead than B for a known response-shape distribution, at the cost of a harder
  invariance argument (more sizes to hold constant) and a real temptation toward adaptivity that must
  be resisted.

## Candidate D — Ditto-style two-pass scheduling (the leading hypothesis)

Ditto shapes traffic in-network on a programmable switch by rewriting each packet to one of a small
set of sizes and emitting a fixed pattern, using a second pass (recirculation) so the pattern is
produced in the data plane. Applied here: the switch enforces a public repeating pattern of cell
sizes and gaps, filling with real shaped packets when present and chaff otherwise.

- Count/sizes/timing: secret-independent, by the same fixed-pattern logic as A/B/C. Ditto's specific
  contribution is doing the shaping at line rate in the data plane rather than in a host.
- Real replaces chaff / disambiguation: Ditto in its original setting shapes encrypted tunnel traffic,
  so the encryption precondition is inherited, not solved by Ditto.
- Empty slot: Ditto's design keeps chaff available so the pattern never stalls; the exact mechanism on
  Tofino (a dedicated chaff source that is always non-empty, plus strict-priority selection of real
  over chaff) is the crux and is analyzed in `TOFINO_TM_FEASIBILITY.md`.
- Outer headers: Ditto shapes size and timing; header normalization still needs the encrypted outer
  layer.
- Large READ / multi-segment: handled by fragmenting into the pattern's cells, same as A.
- What Ditto gives us: a proven in-switch two-pass shaping mechanism and a size-rewriting discipline.
  What Ditto does not give us: the DNP3 transaction semantics, the separate-ACK Case-A timing, the
  exact-byte recovery requirement, and the specific chaff-availability construction on Tofino-1 with
  the Defense 4 queues already present. The novelty question (`PRIOR_WORK_MATRIX.md`) is precisely
  what must be added to Ditto for DNP3, not whether DNP3 has been done.

## Candidate E — slot-token / calendar scheduler on Tofino

A new construction: the control plane defines a public calendar of slots; the data plane holds a
reservoir of slot tokens (as in the Defense 4 blocker-token design) and emits one cell per slot,
choosing a real shaped packet if one is eligible and a chaff cell otherwise, with the token reservoir
guaranteeing a slot is always fillable. This generalizes the Defense 4 in-switch token mechanism from
timing-only to full-transcript shaping.

- Count/sizes/timing: secret-independent if the calendar is public and fixed.
- Empty slot: the token reservoir is the answer to the empty-queue problem: a slot never depends on a
  real packet being present, because a chaff cell is always available from the reservoir. This is the
  most direct reuse of what Defense 4 already proved works on silicon.
- Interaction with Defense 4 queues: this design shares the queue and token machinery with Defense 4,
  so the resource and queue-ID interactions must be budgeted jointly (`RESOURCE_BUDGET.md`).
- This is the strongest data-plane-native candidate and the one most worth prototyping if the decision
  is GO, because it inherits a silicon-proven primitive.

## Candidate F — native protocol-valid cover traffic (decoy CROBs / reads)

Instead of an encrypted tunnel, the cover traffic is real, protocol-valid DNP3 that the observer
cannot distinguish from genuine polling: decoy reads or decoy controls that look legitimate.

- The fatal problem: the scope discipline bars sending control commands to the physical relay, and
  more fundamentally, plaintext decoys are distinguishable from real exchanges by content and by the
  device's genuine responses, and a decoy that elicits a real device response changes device state or
  reveals the device. This family cannot hide device identity (the real device still answers with its
  real headers and timing) and cannot be made byte-indistinguishable without encryption. It also
  risks violating the read-only and no-control constraints.
- Verdict: rejected as a privacy solution for this threat model. Kept only as a comparison point for
  why encryption is needed. It is not adaptive CRC splitting and not the old fixed-K emulator; it is
  simply the "no encryption" corner, and it fails the real-versus-chaff test.

## Candidate G — fixed-rate encrypted tunnel (IP-TFS-like)

Standardized fixed-rate tunneling: IP-TFS (RFC 9347) aggregates and fragments inner IP traffic into
constant-size, constant-rate tunnel packets inside IPsec. This is Candidate A realized with an
existing standard rather than a bespoke switch program.

- Count/sizes/timing/occurrence: all secret-independent, by the standard's design.
- Where the switch fits: the tunnel does the privacy work; the Tofino's role shrinks to enforcing the
  schedule precisely and to any DNP3-aware eligibility. This is the "buy, don't build" baseline and it
  must be beaten, not ignored: if an off-the-shelf IP-TFS tunnel already gives the target property,
  the project's contribution has to be what IP-TFS cannot do (for example, line-rate DNP3-aware
  eligibility, or avoiding a second endpoint, or lower latency for the ICS timing budget).
- This candidate is the sharpest test of novelty and belongs in the decision memo as the strongest
  alternative to a bespoke design.

---

## Defense 4 as an eligibility engine

The upstream Defense 4 result is treated as a frozen input, not code to rewrite. Its exact contract
is in `D4_UPSTREAM_CONTRACT.md`. For a fixed-transcript design, D4's role changes from "the defense"
to "the eligibility engine": it tells the transcript scheduler when a real ACK or RESPONSE is eligible
to be placed into a slot, and it provides the fail-open guarantee for correctness. The wire time of a
real packet becomes

```
t_wire = min { tau_i : tau_i >= t_eligible }
```

the first public slot at or after the packet becomes eligible. Four options for how much of D4 to
keep, to be decided in the decision memo:

1. **D4 before the scheduler, unchanged.** The scheduler consumes D4's shaped release as the
   eligibility time. Simple, but D4's own timing normalization becomes redundant once the public slot
   schedule dominates.
2. **D4 reduced to eligibility and transaction matching.** Keep D4's DNP3 generation-code matching and
   its ACK/RESPONSE recognition, drop its deadline-based timing normalization, and let the public slot
   calendar set the wire time. This is the cleanest division of labor and the most likely
   recommendation.
3. **D4 partly replaced by the slot schedule.** The slot calendar subsumes timing; D4 keeps only
   correctness and fail-open.
4. **D4 as a correctness/fail-open reference only.** The scheduler does everything; D4 remains as the
   availability backstop and the source of the privacy-failure counters.

The exact interface the scheduler needs from D4: (a) DNP3 transaction recognition on plaintext, (b)
ACK eligibility and RESPONSE eligibility signals, (c) transaction matching so a response is bound to
its request, (d) TM release timing, and (e) privacy-failure and fail-open accounting so an
`AVAILABILITY_BYPASS` is counted rather than hidden. This interface is defined once in
`D4_UPSTREAM_CONTRACT.md` and consumed here.

## Confirmed specialist verdicts (transport and Tofino)

These update the candidate verdicts above with measured/structural findings from the transport and
Tofino specialists. Where they sharpen a verdict, they win.

- **The empty-slot question is settled: an empty scheduled slot is skipped, not idled.** Tofino-1 TM
  scheduling is work-conserving; both priority passes serve only backlogged queues and pass over empty
  ones, corroborated on this testbed's silicon. Consequence: the fixed grid cannot come from the
  scheduler reserving time for an absent packet. It must come from an **always-backlogged chaff queue
  kept full by pktgen**, with a real cell winning its slot by strict priority. This confirms the
  chaff-reservoir construction (Candidate E) is the only way to hold the grid, and it retires the
  naive "schedule a slot and fill it later" idea for every candidate.
- **One cell size is decisive on this hardware.** With one cell size the scheduler collapses to a
  single (real-high, chaff-low) strict-priority pair on one flat port scheduler. Multiple cell sizes
  need a two-level scheduler Tofino-1 does not have (no L1 nodes), which forces a Ditto-style two-pass
  loopback. So Candidate A (one-size constant-rate) is materially simpler on silicon than Candidate C
  (multi-size) or Candidate D (Ditto two-pass). This is a strong reason to prefer one-size families.
- **The biggest hardware risk is cadence jitter, not resources.** Tofino-1's max-rate shaper clumps
  below roughly 600 pps (bursts after silence) while hitting the correct average, and a fixed
  transcript is a cadence property, not an average-rate property. The alternative is a pktgen periodic
  timer (steady ~100 pps), but its inter-packet-gap floor and jitter are undocumented in the SDE and
  must be characterized on the actual switch. Until that measurement exists, the regularity of
  `release_time`, which is the whole point of the defense, is unproven. This is added as risk R13 and
  is decision-critical alongside R1.
- **Resources: Candidate A fits, Candidate D/E with size normalization must be priced.** Family A
  (constant-rate one-size) fits the current 12/12 timing core without touching the two exhausted
  ingress resources (the 16/16 ingress tail stages 8-11 and the 100% 32-bit PHV group). Any design
  that adds size normalization or TCP-sequence translation on-chip lands on that saturated tail and
  must be priced with its own compile; that work belongs in the software gateways, not the switch.
  The packet buffer is never the limit (the 12,204-byte READ is about 153 cells, roughly 0.06% of the
  buffer).
- **The encryption precondition is confirmed unavoidable, and it names the architecture.** The
  transport analysis establishes that plaintext DNP3 is self-describing, so padding is strippable and
  chaff is either detectable or dangerous; only an encrypted fixed-cell outer layer closes size and
  count, and Tofino-1 cannot produce it (payload never enters the PHV). The minimal viable design is
  **paired software gateways (one local to the outstation, one at the master) that own the encrypted
  fixed-cell envelope, with the Tofino as metronome (grid release) and header-scrubber (TTL/DF/IP-ID,
  and TSval on an in-band tunnel), kept outside the confidentiality trust boundary.** Split-TCP
  termination at the gateways subsumes sequence translation and hides the relay's inner-stack loss and
  window fingerprints. This is Candidate A / G realized as an architecture, and it also closes the
  request-direction leak that a single outstation-edge switch structurally cannot touch.

## Where the candidates stand going into the decision

- The occurrence-hiding requirement, if Philip sets it, forces the continuous-cover families
  (Candidate A / G, or E driven continuously) and rules out the epoch-only families (B / C), which
  fail the count axis across epochs.
- The encryption precondition is unavoidable for every candidate except F, and F fails the threat
  model. A local encapsulation function near the outstation is required, not merely likely.
- The strongest design is now clear in shape: **continuous one-size encrypted cells (Candidate A),
  held on a Tofino chaff-reservoir grid (the Candidate E mechanism), inside paired software
  gateways.** Candidate G (IP-TFS) is the strongest off-the-shelf alternative and the novelty bar to
  clear; the decision memo must state exactly what the switch-plus-gateway design adds over an IP-TFS
  tunnel (line-rate low-jitter DNP3-aware release and header scrubbing at the edge), and whether that
  addition survives the unproven cadence measurement (R13).
