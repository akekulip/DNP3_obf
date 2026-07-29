# Panel G — Skeptical systems-paper reviewer

**Role:** attack novelty, assumptions, unsupported claims and unnecessary architecture, before
implementation. Analysis only. *(Memo returned as text by the reviewing agent, which had no write
access; persisted here by the PI. All numbers are quoted from repo artifacts, none newly computed.)*

Reviewed: `meeting_direction.md` §1/§6/§7/§14/§15/§16; `research/case_a_fixed_ack_delay/` study and
its three evidence files; `fixed_d_negative_result/README.md`;
`research/defense2_pktgen/evidence/REQUEST_TRIGGERED_PKTGEN_IMPLEMENTATION_REPORT.md`;
`FOUR_QUEUE_ORACLE_CLOSED.md`.

---

## 0. Summary

Defense 3 holds the pure ACK for a constant `D` and releases it independent of the RESPONSE, so
observed CLRT becomes `max(c − D, δ)` and READ→ACK becomes `a + D`. Stated crisply, it is **one
parameterisation of an already-proven mechanism**, its security value is negative at the prescribed
operating points, and the §14 evaluation cannot produce the one figure that would make it a
contribution.

## 1. Novelty vs Defense 1 — real, small, measurable only in aggregate

Master-side observables (n=100, `envelope_analysis_result.txt`):

| | READ→ACK | CLRT | READ→RESP |
|---|---|---|---|
| Native | 0.819 b (median 0.505, sd 0.391) | 1.750 b | 2.047 b |
| Defense 1 | **2.047 b (sd 2.826)** | 0.000 b | 2.047 b |
| Defense 3, D=2 | 0.819 b (sd 0.391) | **1.038 b** | 1.689 b |
| Defense 3, D=3 | 0.819 b (sd 0.391) | **0.803 b** | 1.522 b |
| Defense 2, G=25 | 0.819 b | 0.000 b | 0.819 b |

**The single separator is the SPREAD of READ→ACK.** Under Defense 1 the hold duration *is* `c`, so
READ→ACK carries sd 2.826 ms. Under Defense 3 the hold is constant `D`, so READ→ACK is `a + D` with
sd 0.391 ms — **7.2× tighter at every D**. Worth 2.047 − 1.689 = **0.358 bits** at D=2 ms.

1. **Distributional, not per-packet.** For the 61/100 with `c < D` at D=2, Defense 1 and Defense 3
   produce the *same* per-transaction pattern. An observer needs tens of transactions.
2. **The gain is bought by giving CLRT entropy back.** Defense 3 trades 1.228 bits off READ→ACK for
   1.038 bits onto CLRT. **"Strictly better than Defense 1" holds only at `D ≥ max(c)`** and must be
   qualified everywhere else.
3. **The hold duration is not attacker-observable** — the ACK is held and dp64 is untappable. The
   slope-0-vs-slope-1 regression is a *lab* instrument, not an attacker capability.

**Defensible novelty nobody has stated:** under tail mismatch Defense 3 degrades *gracefully*
(escape emits `c − D`) where Defense 2 degrades *catastrophically* (escape emits native `c` intact).
Worth claiming against attacker model A only; worthless against model B (K1: an adversary knowing D
recovers 38/100 at D=2, 15/100 at D=3).

## 2. §16 claim boundary — honest in letter, evasive in substance

"Entirely on Tofino-1", "no endpoint changes", "no host blockers", "no controller fast path" are
**all already established by `research/defense2_pktgen/` on silicon**. What remains is *we built a
variant*. A reviewer writes "the authors themselves decline to make a security claim" and stops.

The "possible empirical" claim **conditions on the dependent variable** — it selects the 61% that
were going to collapse. The primary result must be the **unconditional** CLRT distribution over all
attempted transactions with the escape fraction adjacent.

Demanded before any fingerprinting claim from one relay: a **non-empty confusion set** (the corpus's
other devices are combined-ACK — one packet, no CLRT — so packet count separates them
deterministically and **the confusion set is currently empty**); ≥3 labelled separate-ACK devices or
explicit scoping in the abstract; the **full feature vector** (ACK mode and TCP stack fingerprint sit
at accuracy 1.000 under prior defenses — a CLRT-only evaluation is a strawman); both relay timing
states separately; and a **detector baseline**, which will be near-perfect.

## 3. D = 1 ms — keep as a pre-registered null control, not a treatment arm

K1 measures ΔH = 0.000 bits, 0/100 collapsed, sd ratio 1.000, adversary recovers 98/100. Its only
legitimate function is **measurement-pipeline validation**: collapse there means the pipeline is
broken, not the defense working.

Two label corrections: **"below the native minimum" is corpus-dependent** — n=100 min is 1.0208 ms
but the **n=300 campaign min is 0.905 ms**, where D=1 *would* collapse a small fraction. Pre-register
the expected count as a number. And carry the **D=0.5 ms row**: entropy *rose* 0.260 bits under a
provably information-preserving transform — the cleanest available caution against binned entropy.

## 4. Architecture — K=64 is inherited, and it caps the system at one flow

The reservoir is required by the decision to reuse Defense 2's artifact, not by the mechanism.
37.4 Mpps ≈ 25 Gbps sustained on dp8 for the whole hold; the reservoir spins from READ through the
ACK deadline (`a + D` ≈ 0.5 ms + D): ~94,000 token passes at D=2 ms, ~840,000 at D=22 ms — to delay
one 54-byte ACK.

**Honest answer to "why 25 Gbps for one ACK":** a fixed-function pipeline has no timer that can hold
a packet. The only primitives are (i) recirculate and poll, (ii) occupy the queue, (iii) shape it.
The reservoir is (ii), chosen because it is silicon-proven here, not because it is efficient.

**Construction C** (held packet recirculates and checks its own deadline) is **1.43 Mpps, 26×
cheaper**, one queue, no pktgen/mirror/value-set/priority, and risk R1 cannot exist. The only thing
the reservoir buys is FIFO ordering, obtainable from a generation-bound check instead.

> **"One active protected transaction" is not a prototype simplification. It is the measured
> capacity of the chosen construction.** ~24 Gbps of a 25G loopback per hold. Any "extension is
> straightforward" wording is falsifiable from the repo's own numbers.

**K=64 fix (~1 h silicon):** sweep K ∈ {1,2,4,8,16,32,64} once and report the empty-gap/escape
threshold curve. Converts the weakest number in the design section into a result.

**Fail-open hazard:** the inherited 100,000-pass budget gives ~171 ms. If D is swept upward the
budget must scale, and a too-small budget **fails open silently** — the ACK releases early and the
arm is quietly invalid. Require per arm: measured on-chip hold ≈ D, `fail_open_count == 0`,
`escape == 0`. Hold duration is measurable **only** on-chip and the 32-bit ns counter wraps every
~4.3 s — a plain subtraction fabricates the headline rather than measuring it.

## 5. ★ The detectability trap — already measured, needs no new experiment

**K1 already reports AUROC of protected vs native on CLRT alone:**

| D (ms) | 0.5 | 1.0 | 2.0 | 3.0 | 5.0 | 10.0 | 22.0 |
|---|---|---|---|---|---|---|---|
| collapsed | 0/100 | 0/100 | 61/100 | 84/100 | 88/100 | 97/100 | 100/100 |
| **AUROC vs native** | 0.689 | 0.778 | **0.878** | **0.894** | 0.936 | 0.984 | **1.000** |

**Concealment and detectability rise together; at full collapse detection is perfect.** That is the
central tension of the mechanism, not a footnote.

1. **A sub-µs CLRT with ~23 ns spread is not a device value** — three orders below the smallest
   native value, five below its spread.
2. **It does not mimic a combined-ACK device** — that emits ONE packet, this emits TWO. Packet count
   separates them deterministically, and §2 forbids touching size. Defense 3 **creates a new class**:
   "separate-ACK device with sub-µs near-deterministic CLRT", population one.
3. **★ At large D the output is physically implausible.** At D=22 ms the master sees a device that
   took 22.5 ms to ACK a 20-byte read then answered 1.7 µs later, 100/100, with 23 ns spread. ACK
   generation is cheap and application response expensive; **the observed ordering inverts that,
   consistently.** Defense 2 has no such problem — ACK in 0.5 ms then respond 25 ms later is an
   ordinary slow device. **Defense 2's output stays inside the manifold of real device behaviour;
   Defense 3's, at the D that actually conceals, leaves it.** Strongest single argument against
   Defense 3's security value.

**Only compatible fix:** draw D per transaction from a plausible target-class distribution
conditioned on `D ≥ c` — a many-to-many stochastic map. Constant D is unforgeable by any real device
and therefore announces itself.

## 6. Evaluation — as specified it cannot produce the only publishable figure

**6.1 MUST-FIX — the sweep is on the wrong side of the boundary.** D ∈ {1,2,3} ms is one inert null,
one at 61%, one at 84%. The regime boundary is D ≈ 22 ms and the interesting region (7–22 ms:
95%→100% concealment, 4.81→19.57 ms latency) is **entirely unsampled**. D is a register write.
**Sweep D ∈ {1 (null), 2, 3, 7, 12, 22} ms.**

**6.2 MUST-FIX — the Defense 2 comparison is unfair in both directions.** D3 at ≤3 ms (1.25 ms
latency) against D2 at G=25 ms (22.57 ms) means nothing. **Sweep G over the same added-latency
budgets and plot both as entropy-versus-added-latency curves on one axis.**

**6.3 SHOULD-FIX — the native baseline is confounded by program swaps.** Each swap is a reload with
a **cold TCP connection at the start of every arm** (25.3 ms vs 1.4 ms). Defense 2's campaign got
this right — native and protected differed *only* by the `app_enable` toggle. Mirror that.

**6.4 MUST-FIX wording — "100 successful transactions" conditions on the outcome.** Failed, escaped,
failed-open and retransmitted transactions must stay in the denominator or the escape fraction
becomes unmeasurable. Use "100 **attempted** transactions per arm, disposition reported for all".

**Nit, load-bearing:** the headline protected CLRT (~1.7 µs) may be below host libpcap timestamp
resolution on Vision. Characterise it or report from on-chip release registers.

## 7. What would make this publishable

**Defense 3 is not a paper. It is one row in a table.**

**P1 (security venue): "Where does the leak go?"** — the anchor taxonomy plus the relocation result:
*any release conditioned on a device-generated event preserves total envelope entropy; it relocates
the leak rather than destroying it.* Explains Defense 1/2/3 and READ-anchored as one family.
Missing: ≥3 devices or explicit scoping, the defense-aware attacker, a randomised-D arm, the
iso-latency Defense 2 curve.

**P2 (systems venue): "Millisecond packet holds on a fixed-function switch ASIC."** — three
constructions measured for internal bandwidth, release precision (23 ns), concurrency ceiling and
failure modes, including the silent fail-open as a genuine negative result. Missing: the K sweep, the
reservoir-vs-C head-to-head, a concurrency measurement.

**Do not claim:** anonymity/indistinguishability/"defeats Formby"; that near-zero CLRT mimics a
combined-ACK device; "strictly better than Defense 1" (true only at `D ≥ 21.7 ms`); binned-entropy
reduction as security; the conditional collapse number without its denominator; K=64 minimality;
straightforward concurrency extension; multi-segment/multi-device/production readiness; or
protection at any D without the corresponding AUROC-versus-native.

## 8. Verdict

**As a standalone submission: REJECT.** The delta over Defense 1 is 0.358 bits at the prescribed
point, bought by restoring 1.038 bits elsewhere; the Defense 2 comparison is not iso-latency; §16
declines the security claim; the confusion set is empty; the architecture is inherited and caps the
system at one flow; and the specified sweep cannot draw the one curve that would be a contribution.
**The project's own K1 gate already measures AUROC 1.000 at the D where the defense works — the
mechanism is at its most detectable exactly where it is most effective.**

**As an engineering task: PROCEED**, with a reduced silicon budget and pre-registration.

**Shortest path to defensible:** (1) re-centre the sweep and add iso-latency Defense 2 arms —
*without this there is no result*; (2) report AUROC-vs-native alongside every concealment number and
address detectability in the abstract; (3) add a randomised-D arm; (4) fix the two known correctness
defects **before** any measurement — the ~10 s keepalive satisfying the ACK predicate (fails
*silently*) and the release-tail overtake race; (5) sweep K once; (6) reframe the paper as the design
space with Defense 3 as one row. **Items 1 and 4 must precede silicon time.**
