# Case A ACK-delay release — mechanism study and recommendation

**Status: DESIGN ROUND COMPLETE. No P4 written, no compile run, no switch touched.**
Date: 2026-07-28. Governing input: `meeting_direction.md` (new direction, commit `df9a2b9`).

This document answers the question the direction poses — build a Tofino-1 mechanism that
holds the pure TCP ACK until `t_release = t_ACK + D` — with a design-stage verdict backed
by measurements taken this session from data already on disk.

**The verdict has two parts.** The mechanism as specified is sound engineering that does not
produce a defensible security result, and the reason is arithmetic, not opinion (§2). A small
change to the *anchor* — from the ACK to the READ — turns the same machinery into a mechanism
that removes the leak entirely, at one fifth of Defense 2's latency cost (§3). Everything in §2
was computed offline from existing captures, so this verdict cost no silicon time.

---

## 1. What was asked, and what was checked

The direction prescribes: reuse the proven request-triggered pktgen blocker reservoir; when the
pure ACK arrives, stamp `ack_deadline = t_ACK + D`, put the ACK in a low-priority `Q_HOLD`, and
let the blockers self-terminate at the deadline so the traffic manager releases the ACK. Sweep
`D ∈ {0.5, 1, 2, 3}` ms. Predicted observable (direction §11):

```
CLRT_out ≈ max(CLRT_native − D, δ_release)
```

Six domain experts reviewed the proposal independently (research scoping, Tofino data-plane
construction, network-architecture simplicity, DNP3/TCP protocol correctness, evaluation
methodology, adversarial venue review). Three cheap gates were then run directly against the
measured corpus. Scripts are in `../analysis/`, raw outputs in `../evidence/`.

Data used, all pre-existing:

| Corpus | n | Content |
|---|---|---|
| `evidence/corrected_v2/cwi/out_C3/native_transactions.csv` | 100 | steady-state native transactions, physical SEL-751 |
| `research/physical_sel751/clrt_300poll_20260723T152242/per_poll.csv` | 300 | 1 Hz native poll campaign |
| `evidence/corrected_v2/cwi/pcaps/cwi_C3.pcap` | — | raw capture, used for the TCP-timestamp check |

Native steady-state CLRT (n=100): min **1.0208 ms**, median **1.401 ms**, mean 2.431 ms,
sd 2.807 ms, max 21.695 ms. The n=300 campaign agrees (min 0.905, median 1.899 ms).

---

## 2. Gate results — why the prescribed mechanism does not produce a defense

### Gate K1 — the offline transform (dispositive, zero hardware)

Applying the direction's own model to the measured n=100 vector, with `δ_release = 50 µs`:

| D (ms) | collapsed | sd ratio | H @1 ms bins | ΔH | adversary knowing D recovers exactly |
|---|---|---|---|---|---|
| 0.5 | **0/100** | 1.000 | 2.010 | **+0.260** | **100/100** |
| 1.0 | **0/100** | 1.000 | 1.750 | **0.000** | 98/100 |
| 2.0 | 61/100 | 0.928 | 1.038 | −0.711 | 38/100 |
| 3.0 | 84/100 | 0.842 | 0.803 | −0.946 | 15/100 |
| 22.0 | 100/100 | 0.000 | 0.000 | −1.750 | 0/100 |

Two of the four prescribed operating points sit **below the measured minimum native CLRT**
(1.0208 ms). At D ≤ 1 ms the transform is `y = x − D`, a bijection on the observed support: it
destroys exactly zero information, and an adversary who knows D inverts it perfectly. The
D=1 ms row measures ΔH = 0.000 bits — an information no-op, confirmed rather than argued.

The D=0.5 ms row is worth keeping in the report for a second reason: entropy *increased* by
0.260 bits under a transform that provably cannot add information. That is a pure binning
artifact (values crossing bin edges), and it is the cleanest available demonstration that binned
entropy must not be the headline metric — a caution this project has already been bitten by.

At D=2 and 3 ms the mechanism does censor, but weakly: standard deviation falls by 7% and 16%
respectively, against Defense 2's measured 21× (8.383 → 0.401 ms). Full collapse requires
D ≈ 22 ms and 19.6 ms of mean added latency — i.e. paying Defense 2's latency bill to obtain
Defense 1's outcome.

### Gate K0 — TCP timestamp side channel (PASS: not a kill)

If the relay's TCP timestamp option were fine-grained, `ΔTSval` between ACK and RESPONSE would
recover the native CLRT through *any* hold, breaking Defense 1, Defense 2 and this variant at
once. Measured on `cwi_C3.pcap`: the relay's TS clock advances only in 30-unit granules
(~30 ms effective resolution), so ΔTSval is 0 in 74/100 transactions and 30 in the remainder,
carrying **0.144 bits — 6.1% of the CLRT's 2.374 bits**.

Not a kill. It is, however, a genuine residual channel that survives every byte-preserving
timing defense in this project, and it should be disclosed rather than discovered by a reviewer.

### Gate K2 — where the leak actually lives (the decisive result)

CLRT is one of three observables a master-side observer sees. Measuring all three on the same
n=100 corpus, in bits at 1 ms bins:

| Mechanism | READ→ACK | ACK→RESPONSE (CLRT) | READ→RESPONSE |
|---|---|---|---|
| Native | 0.819 | 1.750 | 2.047 |
| Defense 1 (hold ACK, release on RESPONSE) | **2.047** | 0.000 | **2.047** |
| Defense 2 (hold RESPONSE to `t_ACK + G`) | **0.819** | 0.000 | **0.819** |
| Fixed-D ACK hold, D = 2 ms (**proposed**) | **0.819** | **1.038** | **1.689** |
| Fixed-D ACK hold, D = 3 ms | **0.819** | **0.803** | **1.522** |
| **READ-anchored (§3)** | **0.000** | **0.000** | **0.000** |

Defense 1 does not destroy the CLRT information — it **relocates** it. READ→ACK becomes
`a + c`, carrying the full 2.047 bits; total observable entropy is unchanged. Defense 2 leaves
READ→ACK untouched at 0.819 bits. The proposed fixed-D variant is the weakest of the three: it
leaks on *both* axes at once, because a constant shift preserves the READ→ACK distribution's
shape exactly (sd stays 0.391 ms, entropy stays 0.819 bits).

**This is the finding that should drive the next build.** Every mechanism in the portfolio so
far conditions its release on a device-generated event or a device-generated timestamp, and so
carries device timing into some output observable.

---

## 3. The recommended mechanism — anchor on the READ

**One change: derive both release deadlines from `t_READ`, which the switch generates, rather
than from `t_ACK`, which the device generates.**

```
ACK      released at  t_READ + A
RESPONSE released at  t_READ + A + S      (S ≥ 0)
```

Both output observables are switch-chosen constants. Neither the relay's ACK latency `a` nor
its CLRT `c` appears in any observable — so there is nothing left to shift, invert or retrain
against. Measured on the same corpus (`../evidence/envelope_analysis_result.txt`):

| Policy | READ→ACK | CLRT | READ→RESPONSE | coverage | mean added latency |
|---|---|---|---|---|---|
| A=3 ms, S=1 ms | 0.000 bits | 0.000 bits | 0.000 bits | 86/100 | ~4 ms |
| **A=5 ms, S=3 ms** | **0.000** | **0.000** | **0.000** | **96/100** | **5.08 ms** |
| A=10 ms, S=5 ms | 0.000 | 0.000 | 0.000 | 99/100 | 11.93 ms |
| A=22 ms, S=3 ms | 0.000 | 0.000 | 0.000 | 100/100 | 21.86 ms |

At **A=5 ms, S=3 ms** the mechanism covers 96% of transactions at 5.08 ms of added latency —
against Defense 2's 25 ms for an outcome that still leaks 0.819 bits on READ→ACK.

Why this is also the *simpler* design, not merely the stronger one:

- **The anchor is already free.** The switch timestamps the READ today; that timestamp is what
  triggers the existing pktgen. No new state is needed to obtain it.
- **The pre-arm problem disappears.** The direction's §5 "blockers circulating before the ACK
  arrives" phase exists only because the reservoir cannot arm itself from the packet it must
  hold: arming takes ~2–4 µs while the traffic manager dequeues in ~100–300 ns. With a READ
  anchor the arming window is the full native READ→ACK interval (~0.5 ms measured), and with the
  self-timed construction below there is no reservoir to arm at all.
- **It strictly generalizes the portfolio.** Defense 1 is the response-triggered limit,
  Defense 2 is `A = a` with `S = G`, and fixed-D is `A = a + D` with `S` unconstrained. One
  mechanism, three prior results as special cases.

**Honest limit.** A switch can delay but never advance. Coverage is the fraction of transactions
with `a ≤ A` **and** `a + c ≤ A + S`; the remainder pass through with native timing and must be
counted and reported as escapes, exactly as Defense 2's G-escape is. The connection-cold first
poll (median 25.3 ms) escapes at every practical A and remains the device's loudest feature.

**Randomize the offsets for the security claim.** A *constant* A and S makes every transaction
identical, which is unforgeable by any real device and therefore announces the defense. Drawing
`(A, S)` per transaction from a target device class's measured distribution — conditioned on
being reachable, i.e. `A ≥ a` and `A + S ≥ a + c` — converts a deterministic invertible map into
a many-to-many stochastic one. That is the version that can claim to defeat a retrained
classifier, and it costs one randomized deadline register on top of the same machinery.

---

## 4. Construction — do not use the blocker reservoir here

Measured from the repo's own artifacts, the prescribed reservoir runs the dp8 loopback at
**37.4 Mpps ≈ 25 Gbps for the entire hold** (derived from `ibspg_hold_response` pass counts:
1,460,066 additional passes over 39 ms). With READ-triggering it spins for `(READ→ACK) + D`, so
roughly 225,000 token passes to delay one 54-byte ACK by 2 ms.

Two cheaper constructions produce the same primitive:

| Construction | In flight | Internal load | Extra machinery | Risk |
|---|---|---|---|---|
| Prescribed reservoir | 64 tokens | 37.4 Mpps | pktgen + mirror + value-set + 2 queues + strict priority | proven, but heavy |
| **C — self-timed hold** | **1 packet** | **1.43 Mpps** | one loopback queue | **low; graft of two proven files** |
| D — shaped replication | N copies, drained | ~64 kpps | 1 mcast group + 1 egress table | one unverified TM property |

**Construction C (recommended first build).** The held packet carries its own deadline: it
recirculates on the dp8 MAC-near loopback, and on each ~408 ns pass ingress compares
`ingress_mac_tstamp` against the stored deadline, forwarding it byte-identically once expired.
This is `dcrn_defense1.p4`'s existing ACK-hold loop with Part 12's deadline comparison
substituted for its response-seen predicate — a predicate swap, not a new architecture. The
"does the timestamp refresh on recirculation" question that led `dcrn_defense1.p4` to choose an
event-governed release is already answered for dp8: Part 12 measured 0–26 ns detection latency
over 200/200 reps on that loopback.

**Construction D (higher upside, one open question).** Replicate the held packet into N copies
on a queue shaped to R packets/s, drop the first N−1 as they dequeue in egress, and the last
copy — the real packet — leaves at `(N−1)/R`. The delay is then two static numbers with no
timers, no polling and nothing re-entering the pipeline, and it explains in one sentence. The
open question is whether Tofino-1's queue shaper in pps mode grants an idle burst credit that
would let the first copies dequeue instantly; this needs an SDE read plus a bounded microbench
before committing. The earlier repo finding that "a shaper cannot pace a lone packet" does not
apply, because D deliberately makes the packet non-lone.

**Dead weight identified.** Per-stage placement read from
`research/defense2_pktgen/p4/build_local_9.13.1/pipe/dnp3_timing_normalizer_pktgen.bfa`: ingress
stage 9 contains only telemetry (`reg_native_clrt`, `reg_protection`, four `ctr_response_*`),
stage 8 is ~90% telemetry (four timeline registers plus `tbl_clrt_guard`), and stage 7 holds
four counters and no logic. Those are the three stages the direction believes are dispensable.
The final count remains a compiler question and must not be claimed before bf-p4c confirms it.

---

## 5. Correctness defect that must be fixed regardless of mechanism

**The relay's TCP keepalive satisfies every condition of the current ACK classifier.** Measured
in `evidence/corrected_v2/COLD_WARM_IDLE_CHARACTERIZATION.md`: the SEL-751 emits keepalives every
~10.02 s carrying `seq = SND.NXT − 1`, and they caused ambiguity in 20 of 23 transactions in the
15 s and 30 s idle cells. In `dnp3_timing_normalizer_pktgen.p4` they pass the `parse_tcp` role
test (flags mask `0x17`, zero payload, `ihl == 5`) and the `tbl_state_decode` qualification.

Today they are rejected only by arm-once idempotence — an accident, not a classification. Under
the proposed variant a qualifying ACK *enqueues a packet and installs a deadline*, so a keepalive
between transactions leaves a stale valid deadline already in the past, and the next real ACK is
never held. That is **silent loss of protection**: no crash, no counter, a result that does not
replicate. Any deployment polling slower than ~10 s meets this constantly, and real integrity-poll
cadences are 15 s to 15 min.

Required predicate additions:

1. `tcp.seq == EXP_RELAY_SEQ` (tracked as `prev_response.seq + prev_response.len`, seeded from
   `SYN-ACK.ISN + 1`). This is the **decisive** discriminator — the keepalive is retrograde by
   exactly one.
2. `tcp.ack_no == EXP_ACK` where `EXP_ACK = READ.tcp.seq + READ.tcp.payload_len`.
3. Tighten the flags mask from `0x17` to **`0x3F`** so SYN/RST/FIN/PSH/URG are all rejected.
4. A one-shot `AWAITING_ACK` state cleared on response release **and** on a watchdog timeout.

There is no purely header-field predicate separating the transaction ACK from a window update;
transaction state is load-bearing and cannot be engineered away.

---

## 6. Safety and protocol correctness (checked, clean)

At D or A in the 0.5–20 ms range there is roughly two orders of magnitude of margin against
every binding timer. The master's RTO is pinned at the ~200 ms Linux floor (measured 211 ms,
loopback — re-measure on the wire before publishing it as a bound); a constant delay raises SRTT
by D and leaves RTTVAR unchanged, so the RTO does not move. Delayed-ACK timers are never engaged
(the relay ACKs in ~0.5 ms). Fast retransmit is unreachable: it needs three duplicate ACKs with
data outstanding, and there is one ACK per transaction with nothing outstanding.

Two effects the direction under-states and the report must state:

- **The early-response case holds the RESPONSE too**, putting the hold on the *relay's*
  retransmission timer, not only the master's. At D = 2 ms this is ~60% of transactions. Safe at
  these values, but the relay's `RTO_min` has never been measured.
- **Nagle is active** — opendnp3 does not set `TCP_NODELAY`. Inert for a single outstanding
  request with `CON=0`, but it becomes live with multi-fragment responses or pipelining.

DNP3 application layer is untouched: IEEE 1815 treats TCP as an opaque byte stream, responses
carry `CON=0` (no application confirm), and link function 4 is unconfirmed user data (no link
confirm timer). Measured 300/300. Nothing here can reach protection functions — no control
commands, no settings writes, function code 1 only. The real operational hazard is not the
milliseconds: it is being inline at all, plus the demonstrated reconnect storm (434 SYNs in
~7.9 s ≈ 55 connections/s) if the master ever times out and retries.

**Residual leak to disclose:** against a master that schedules its next poll relative to the
last response, the inter-poll interval lengthens by exactly the added delay, revealing both the
defense's presence and its parameter. Run all campaigns on an absolute monotonic poll schedule.

---

## 7. Evaluation design

- **n = 100 per configuration, not 30.** At n=30 the collapse-fraction CI is ±0.18, which cannot
  distinguish the D=2 prediction (52–61%) from the D=3 prediction (76–84%). Cost is ~35 s of
  polling per session; the expensive resource is switch reconfiguration, not polls.
- **Randomized complete blocks**, three blocks across the day, order randomized within block,
  seed recorded. Native must be the *same loaded program with the defense disabled*, never a
  different program, so the baseline is not confounded by forwarding differences.
- **Fix the poll period** — the existing corpus is contaminated on exactly this point
  (campaign A ~303 ms vs campaign B ~402 ms).
- **Metrics:** Hodges–Lehmann shift estimator with a TOST equivalence test against the
  configured offset; the quantile-difference function against the predicted model curve; the
  collapse fraction against `F_native(D)`; and a Formby-style template-matching identification
  rate over the device library. Binned entropy goes in an appendix with bin width, origin, edge
  convention and n stated — never as the headline.
- **The falsification test:** regress per-transaction ACK hold duration on native CLRT for
  transactions with `CLRT_native > D`. A predetermined deadline gives slope 0 and intercept D; a
  response-triggered mechanism gives slope 1. Any significant positive slope falsifies the
  central claim. The in-vivo probe needing no crafted traffic is the connection-cold poll, whose
  native CLRT (~25 ms) far exceeds any D.
- **Add microbenchmarks** beyond the direction's A–G: a qualifying pure ACK with no active
  transaction, a keepalive mid-hold, and a keepalive between ACK release and response arrival.
- **Report cold and steady states separately and never pool them.**

---

## 8. Recommendation

1. **Do not build the fixed-D ACK hold as a defense.** Publish §2 as a negative result and
   ablation — "a deterministic constant shift cannot defeat a distribution-based fingerprint,
   and here is the measurement showing variance is invariant below the native minimum." It is
   already fully computed from data on disk and costs no further silicon time.
2. **Build the READ-anchored dual-deadline release** using construction C, with the §5 predicate
   fixes. It removes the leak from all three observables rather than moving it between them, at
   ~5 ms of added latency for 96% coverage.
3. **Randomize the offsets** once the deterministic version is measured, which is what converts
   the result from normalization into a mimicry claim that survives a retrained adversary.
4. **Test construction D's shaper question in parallel** — half a day of SDE reading plus a
   bounded microbench. If it passes, it is the version to publish, because it explains in one
   paragraph and consumes ~585× less internal bandwidth than the reservoir.

All hardware steps remain gated on explicit authorization. Nothing in this study touched the
switch.
