# Defense 4 — adversarial review and disposition

**2026-08-04. Venue-standard (NDSS/CCS/TDSC) adversarial review of the feasibility deliverables, with
the lead's disposition of each objection. The review verified the two novelty-critical prior works
(Ditto NDSS'22, NetShaper USENIX Sec'24). Objections are integrated, not argued away; the corrections
below are applied to the deliverables.**

## Verdict of the review

As an internal feasibility study: sound engineering, unusually disciplined evidence hygiene, real
safety analysis, the right gate experiment (E0) actually run. **As the basis for a "Defense 4" paper:
MAJOR REVISION WITH REFRAME.** The GO-WITH-CONSTRAINTS verdict is **one level too generous.** Honest
verdict: **GO on the timing grid only; the size plane is a non-contribution on this device (0-bit
target, no corpus, k=1); the strong `Obs(READ)≈Obs(SBO)` claim is Ditto-for-DNP3 under crypto and is
not evaluable in the single-switch topology.**

## Disposition of the five attacks

| # | objection | severity | disposition |
|---|---|---|---|
| A1 | **Why not just encrypt?** The motivation is argued backwards — the study frames MACsec as what "closes the strong claim" and shaping as needing MACsec, when the correct framing is that **encryption is porous to size/timing/count/direction, so shaping COMPLEMENTS encryption.** And the Tofino platform is undefended against a 5-pps host-edge encrypt-and-shape box (IPsec-TFC / NetShaper endpoint), since at 5 pps the line-rate advantage is irrelevant. | MUST-FIX (not a hard blocker) | **ACCEPTED.** The correct motivation (802.1AE preserves plaintext length modulo a fixed overhead → traffic-analysis side channels survive encryption) is now the framing. The platform choice must be defended or the design ported off the "Tofino-1 only" constraint — flagged as an open decision for Philip. |
| A2 | **Ditto subsumes you.** The strong claim needs the same ingredients as Ditto (two operator edges + link crypto + in-network shaping). The study benchmarks against Defense 3, never against Ditto — the field's baseline. Schedule-anchored release IS Ditto's principle. Real deltas: the `a/T` one-sided-quantisation lemma (not in Ditto), bidirectional request-response coupling with the SBO select-timeout bound, and the DNP3 safety envelope. | GENUINE NEAR-BLOCKER for the strong framing | **ACCEPTED.** The baseline is Ditto/NetShaper, not Defense 3. Under the crypto regime the contribution is a systematization/applications result → TDSC/TIFS/ICS-track, not an NDSS full paper. The novel deltas are the surviving thesis (below). |
| A3 | **Two-edge topology.** The single-box loopback shares the generation/slot register and has ONE pktgen epoch counter; two real switches share neither. Cross-switch grid epoch sync (arch RQ9) is never answered. Worse: the only realizable single-box deployment (inline bump-in-the-wire) has NO observable protected link — the loopback DAC manufactures the very observable link the threat model needs. | GENUINE BLOCKER for any two-edge / distance-link claim | **ACCEPTED.** Every two-edge claim is now scoped to "single-box, observer-on-one-cable," and the cross-switch epoch-sync problem (RQ9) is named as an unanswered blocker for the deployment case. A real two-edge claim requires two switches + a data-plane epoch-sync mechanism, which is future work. |
| A4 | **"Size is free."** Egress only APPLIES padding to a length ingress chose. `size_profile` selection, slot assignment, encap-header field writes, and filler tagging are ingress state (the spec's own state table). MB-1 excludes "the size plane" but includes the slot bitmap — incoherent; the ≤12 verdict on that skeleton is a lower bound, not decisive. | MUST-FIX | **ACCEPTED.** "Free egress application, non-free ingress control." MB-1 is re-scoped to include the full size-plane ingress control surface. The "size plane is essentially free" claim is corrected. |
| A5 | **Profile-A retreat.** Remove the strong claim and the MVP is: CLRT normalization (already Defense 3), close a 0.65-bit READ→ACK residual with an UNBUILT grid (n=4, k=1), within-operation size normalization on a **0-bit-entropy** response, and decoy-CROB concealment that is master-side (forbidden by the "endpoints unmodified" rule), safety-BLOCKED (V1), and n=1-per-N. | GENUINE BLOCKER for the "unified size+timing Defense 4" framing | **ACCEPTED.** Size is demoted to future work; the evaluable contribution is the timing grid + the `a/T` result + the ICS safety envelope. |

## The single most damaging unaddressed objection (now addressed)

**The contribution sits in a scissors, benchmarked against the wrong baseline.** With crypto → Ditto-for-DNP3, novelty must be argued against Ditto (never done), in exactly the two-edge regime the single-switch evaluation cannot test. Without crypto → Profile A has a 0-bit size target, k=1, and a 0.65-bit timing residual at n=4 as its entire new result — an increment over the authors' own prior defense. **Disposition:** the framing is changed to the timing result against the Ditto/NetShaper baseline, with size and the strong claim as future work.

## Claims corrected (evidence did not support them)

1. ~~"The size plane is essentially free on Tofino-1."~~ → **"Egress *application* of padding is free (egress 0/12 empty); the size plane's ingress *control* (`size_profile` selection, slot bitmap, encap-header writes, filler tagging) competes for the same 2 free ingress dependency levels as the timing additions, and MB-1 must include it."**
2. ~~"a switch-clock grid … is the mechanism that closes that residual"~~ (stated as the "strongest claim the evidence supports") → **"the grid is *predicted* to close the residual (the load-bearing rung 5→6 of the ablation ladder); this is a prediction gated on E1/E3, not a result. The grid is unbuilt and unmeasured."**
3. Subsystem verdict "Size plane … GO" now reads **"GO for the mechanism; NO measurable security benefit on this device (0-bit response-size entropy, no SBO corpus) — the size plane is future work, not a v1 contribution."**

## Unsafe step corrected (highest priority)

The Feasibility MVP advertised *"CROB-count concealment via master-side decoy padding"* as a delivered
feature. Normalizing **response-side** CROB size relies on the relay **echoing** the decoy CROBs — which
requires the relay to **OPERATE** them, i.e. actuation of valid-but-unwired points on a live protection
relay, whose inertness (V1) is BLOCKED and which R8 rates "unauthorized control on a protection relay."
This contradicts the plan's own V1 gate. **Correction:** the MVP removes response-side CROB concealment;
until V1 closes, decoy work is **request-side padding only, SELECT observe-only, never OPERATE.**

## The surviving thesis (what a defensible minimum paper claims)

> On real ICS hardware against a physical relay, an event-anchored timing defense (release at
> `t_ACK + D`) provably **relocates** the device's ACK-latency fingerprint into a residual READ→ACK
> channel (measured: 0.65 bits after Defense 3), while a schedule-anchored switch-clock grid — released
> on the defender's own clock and gridded in **both** directions to kill the `a/T` one-sided-quantisation
> leak — drives that residual to the measurement floor. This is a same-hardware event-vs-schedule
> comparison on real request-response ICS traffic that prior in-network shapers (Ditto, NetShaper) do
> not provide, because they are schedule-anchored by construction and never measured against an
> event-anchored baseline. The DNP3 SBO select-timeout admissibility bound and the OT safety envelope
> are the systematization contribution.

Size, the strong `Obs(READ)≈Obs(SBO)` claim, and any anonymity claim are explicit future work
(blocked on a real physical-SBO corpus, a second separate-ACK device, and — for the strong claim — an
external link-crypto boundary and a genuine two-switch deployment).

## Shortest path to acceptance (changes the outcome)

1. **Build and measure the grid** — turn the rung 5→6 prediction (0.65 → ≤0.60 AUROC) into a result.
   Without it there is a plan, not a paper.
2. **Reframe around timing + `a/T` + the ICS safety envelope; move size to future work;** state the
   delta against **Ditto/NetShaper**, not Defense 3.
3. **Fix the Ditto positioning** (encryption porous → shaping complements) and **defend or drop the
   Tofino platform** against a 5-pps host-edge encrypt-and-shape box.
4. **Two-edge honesty** — evaluate on two switches with real cross-switch epoch sync, or scope every
   claim to single-box / observer-on-one-cable and stop calling it a two-edge defense.
5. **Re-scope MB-1** to include the size-plane ingress control surface; **remove decoy-CROB
   response concealment from the MVP** until V1.
6. **Cap anonymity language** — n=4 effective, k=1 — "necessary not sufficient for fingerprinting."
