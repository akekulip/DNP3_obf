# Defense 4, explained from the ground up

This is the plain-language tour of what we built, why, and exactly how far it is proven. It is written
for someone who has never seen this project. Every strong claim is tagged with where the evidence comes
from — **[silicon]** measured on the real switch and relay, **[compile]** proven by the Tofino compiler,
**[offline]** proven by a software model, **[synthetic]** a labelled what-if using made-up-but-plausible
numbers. If a sentence is not tagged, it is background, not a result. Figures live in `defense4/figures/`.

---

## 1. The problem: fingerprinting a control-system device

Industrial control systems (power substations, water, gas) run field devices — protective relays,
meters, PLCs — that talk a simple protocol over the network. An attacker who can watch that network
traffic, even without decrypting anything, can often tell **what kind of device** is sitting at an IP
address just from *timing patterns* in the traffic. Once you know it is, say, an SEL-751 relay, you know
its vulnerabilities and how to attack it. The paper that made this concrete is Formby et al., *"Who's in
Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems"* (NDSS 2016). It gives
two timing fingerprints:

- **CLRT — Cross-Layer Response Time.** When a master polls a device for data, the device sends a
  low-level TCP acknowledgement and then, a moment later, the actual response. The gap between those two
  is the device's *processing time*. Every device model has a characteristic CLRT distribution (mean and
  variance), and those distributions are cleanly separable — the paper classifies device types at up to
  99% accuracy from CLRT alone.
- **Physical-operation-time.** When the master commands a device to physically actuate (open/close a
  breaker or relay), the *mechanical* operation takes a device-specific amount of time. The device
  reports *when* the event happened via an embedded timestamp. The gap between the command and that
  timestamp fingerprints the physical hardware itself.

Both fingerprints are **timing**, and both are passive (the attacker just watches). Our job: make a
single device on a single programmable switch (an Intel Tofino-1) *reshape its own traffic* so a passive
observer can no longer read these fingerprints — without a proxy, without changing any protocol byte,
without a second switch.

## 2. The protocol, in three messages

The devices here speak **DNP3** (IEEE 1815) over TCP. Three message types matter:

- **READ** — the master asks for data. Request ≈ **20 bytes**.
- **SELECT** — the first half of a control. The master says "I am *about to* operate this output."
  Request ≈ **45 bytes**. The device echoes it back.
- **OPERATE** — the second half. "Now actually do it." Request ≈ **45 bytes**. The device echoes it back
  *and* physically actuates.

A full control command is **SELECT then OPERATE** — two separate request/response exchanges. This is
"Select-Before-Operate" (SBO), a safety feature so a control can't fire by accident. Keep this in mind:
**an SBO is two exchanges; a READ is one.** That difference never fully goes away (see §11).

## 3. Making READ and SELECT the same size

Formby's fingerprints are timing, but there is a simpler leak too: **response size**. If a READ response
and a control response are different sizes, an observer separates them trivially. We close that at the
*endpoint*, not by padding on the switch (padding creates a bookkeeping problem the switch can't sustain
— that was an earlier dead end, recorded in the project memory). Instead we configure the relay's data
points so that a 23-point status READ and a 2-CROB SELECT both produce a **49-byte** response natively.
Same size, no byte added.

```
READ request:  20 B     SELECT request: 45 B     OPERATE request: 45 B
Native eligible response: 49 B (both READ and SELECT)
```

## 4. RRC: normalizing the response (the proven half)

**RRC = Release–Replicate–Carve.** It runs on the switch and reshapes the *response* the device sends
back. Two things happen to an eligible 49-byte response:

- **Timing (fixes the CLRT).** The switch *holds* the response and releases it at a fixed deadline
  instead of the device's natural moment. Every response now leaves at the same time relative to the
  request, so the device's natural processing-time signature is replaced by a switch-chosen constant.
- **Size/segmentation.** The switch splits the 49-byte response into two TCP segments of **28 and 21
  bytes** — written `[28,21]`. It does this *without inserting or changing a single byte*: it uses the
  Tofino's Packet Replication Engine (PRE) to make two copies of the same packet, one carrying bytes
  `[0:28]` and one carrying bytes `[28:49]`, with correct TCP sequence numbers. The master's TCP stack
  reassembles them back into the exact original 49 bytes (Fig. `fig_size_silicon`). Because it is pure
  segmentation, the DNP3 checksums stay valid — nothing is rewritten. (Byte 28 happens to land on a DNP3
  block boundary, but that is incidental; TCP reassembly would restore the frame from any split point.)

**This half is proven on the physical SEL-751 relay [silicon].** With the timing hold on, a READ and a
non-actuating SELECT both come out as `[28,21]`, both reassemble to 49 bytes, and the CLRT that Formby's
classifier reads collapses:

```
Native  ACK→response CLRT:  READ ≈ 2.11 ms,  SELECT ≈ 1.06 ms   (separable, ~1 ms apart)
Defended ACK→response CLRT: READ ≈ 20.00 ms, SELECT ≈ 20.00 ms  (merged, 0.002 ms apart)
```

Figures `fig01_clrt_native_vs_defended` and `fig_clrt_silicon` show the two native clouds sitting apart
and the defended ones landing on a single tight line. That is the CLRT fingerprint being erased, on real
hardware. (Honest caveats, always in force: this hides device *type* via CLRT, not the request sizes,
and a deep-packet-inspection observer that reads the DNP3 object types still tells READ from a control.)

## 5. BOR: normalizing the physical-operation time

RRC does nothing for Formby's *second* fingerprint, the physical-operation time — because that timing is
carried in an application-layer timestamp the device stamps when the breaker actually moves, and RRC is
byte-preserving so it cannot touch that value. To attack that fingerprint we need a *different* lever:
**BOR = Bounded OPERATE Release.**

BOR holds the master's **OPERATE request** for a small, bounded delay `J` *before* the relay receives it.
The observer measures the operation as `T_SER_event − T_OPERATE_seen`. Because the switch delayed the
OPERATE by `J`, that measured value becomes `J + T_physical`. If `J` is chosen well, the device's own
`T_physical` is buried inside a switch-controlled distribution.

Four moments define the OPERATE lifecycle, and — this is the load-bearing rule — **every one is anchored
to `T0`, the moment the *original* OPERATE first arrived**, never to when the delayed copy was released:

```
T0            the original OPERATE arrives (its ingress timestamp)
T0 + J        the switch releases the (byte-identical) OPERATE to the relay
T0 + A        the relay's ACK is released to the master
T0 + R        the relay's OPERATE echo is released, carved [28,21]
```

with the control plane enforcing `A > J_max + native_ACK`, `R > J_max + native_response`, and `R ≥ A`
(the relay cannot acknowledge a request it has not received yet — so the old 2 ms ACK deadline could not
survive BOR and had to be recomputed).

**Why anchor to `T0`?** If the ACK/echo timing depended on `J`, an observer could measure `J` from the
response timing and subtract it back out, recovering the true `T_physical`. Anchoring to `T0` makes the
response timing carry no information about `J`.

**Why a *random* `J`, not a fixed one?** A fixed delay just *shifts* every operation time by the same
amount — the device classes stay exactly as far apart, so the fingerprint survives. A per-transaction
**random** `J`, drawn fresh for each OPERATE, *convolves* (blurs) the operation-time distribution. We
draw `J` from the Tofino's hardware random-number generator, one draw per OPERATE, indexing a bounded
codebook of delay buckets — never from anything an observer can see on the wire, and never from the DNP3
sequence number (which the observer *can* read). Fig. `fig04_j_convolution` illustrates the blur.

**One more leak we had to close.** The relay's ACK carries a TCP *timestamp option* that records when the
relay actually received the (delayed) OPERATE. That timestamp leaks `J` even with perfect `T0`-anchoring.
So the honest rule is: the anti-subtraction claim only holds on a connection with TCP timestamps
**disabled**; the control plane checks for the option at connection setup and refuses to claim
timestamp-safety otherwise.

## 6. How the switch prepares itself: SELECT primes BOR

To hold the OPERATE the instant it arrives, the switch needs a "reservoir" of blocker packets already in
place in a low-priority queue. Where does it get the time to build that reservoir? From the SELECT.
Because an SBO always sends SELECT *before* OPERATE, the switch treats the SELECT as a **preparation
event**: it opens an internal **BOR epoch** (a private identity, deliberately *not* tied to the DNP3
sequence number, which is only 4 bits and wraps), seeds the blocker reservoir for that epoch, and
confirms it is resident. When the OPERATE arrives, the switch checks that a matching, confirmed epoch
exists; if so it holds the OPERATE on its *first* try. If not, it forwards the OPERATE immediately and
counts a failure — it **never** holds on a stale flag.

This matters because our first attempt got it wrong, and the honest record keeps the mistake: an earlier
version checked "is the reservoir ready?" *before* it started building the reservoir, so the very first
real OPERATE always found it not-ready and **failed open** (passed through unshaped), and a retry was
suppressed as a duplicate. That is *safe bypass*, not *protection* — and we relabelled that result a
"resource probe," not a working BOR. The SELECT-prepares-the-epoch design is the real fix, and the
offline model proves the first OPERATE is now genuinely held [offline].

The queues form a strict-priority ladder, split across the two pipes (see §7): `qid7` ACK-blocker,
`qid6` ACK-hold, `qid5` response-blocker, `qid4` response-hold, `qid3` OPERATE-blocker, `qid2`
OPERATE-hold.

## 7. Why it takes two pipes (and the compiler decided that)

The Tofino processes packets in a pipeline of exactly **12 stages**. The proven RRC program already uses
all 12. When we added BOR to the same program, the compiler said 14 — two over. We spent real effort
recovering stages (merging tables into a single dispatch, folding parameter tables), and got the
*faithful* one-pipe build down to **13** — still one over. The last stage is not table clutter; it is the
OPERATE hold's dependency chain, which cannot be shortened. `[compile]`

So we used the **second physical pipe** the chip already has (it is a two-pipe part, `num_pipes = 2`),
splitting the one logical defense across both:

- **Pipe 0 — 12 stages [compile]:** the frozen RRC (response timing + `[28,21]` carve), plus recording
  the original OPERATE's `T0`, plus sending the OPERATE across to pipe 1.
- **Pipe 1 — 10 stages [compile]:** the BOR hold/release only — build the epoch, hold the OPERATE to
  `T0+J`, release it exactly once to the relay.

The OPERATE crosses from pipe 0 to pipe 1 over an *internal* loopback (no cable), carrying `T0` in a
tiny internal header that is stripped before the packet reaches the relay, so the released OPERATE is
byte-for-byte the original. The relay's ACK and echo come back as *fresh* packets into pipe 0 — they are
not a "second pass" of the OPERATE. Both programs compile clean on our local compiler (bf-p4c 9.13.1)
**and** the switch's own compiler (9.13.2). Fig. `fig07_compiler_resources` shows the stage story.

**We say two pipes, not one pipe.** That is the honest architecture. And faithful readiness was not free:
adding the real epoch machinery grew pipe 1 from 6 stages (the broken fail-open version) to 10.

## 8. Safety: exactly-once and fail-open

A held OPERATE is a *real control command*. Two rules are absolute and proven in the model [offline]:

- **Exactly-once.** The original OPERATE reaches the relay exactly one time. A TCP retransmission while
  the OPERATE is held must **not** cause a second physical operation — deduplication guards this at
  *both* pipes.
- **Fail-open, never fail-closed.** If anything is not ready — reservoir missing, no matching epoch, an
  abort, a connection reset — the switch forwards the original OPERATE immediately and counts it. It
  never drops or stalls a control. Every abort path (failed SELECT, missing OPERATE, timeout, FIN/RST,
  connection replacement, invalid profile) retires cleanly with no change to any output.

## 9. How well does it actually hide the physical fingerprint?

Here is where we are most careful, because **we have no physical OPERATE measurements** — actuating the
real relay was not authorized (there is no proof the decoy output point is electrically isolated), so
that gate is **BLOCKED**, and we will not invent physical data. What we *can* show is the **mechanism**,
using a labelled **[synthetic]** model: take the two device classes from Formby's own measured ranges
(≈14–38 ms operation times), convolve each with our bounded random `J` (0–12 ms), and see how much the
classes blur together.

The result is honest and partial (Fig. `fig03_operation_synth`, `fig05_classifier`):

- Class-separation (Jensen–Shannon divergence) falls from **0.163 to 0.060 bits — about a 63% reduction**.
- A classifier's accuracy drops by up to **5.5 points** (random-forest 0.588 → 0.533; chance is 0.50).

But the classes are **not** merged to chance. The reason is fundamental and worth stating plainly: our
delay `J` is capped at 12 ms, while the two device classes are ≈24 ms apart. **A bounded random delay can
only blur classes that are closer together than its own range.** To actually merge these two, `J_max`
would have to be at least as large as the inter-class spread — which costs actuation latency. So the
honest claim is: **BOR is a real, per-transaction, random convolution of the physical-operation timing
that measurably reduces separability; it is not a demonstrated defeat of the fingerprint, and it is shown
here only in a single-mechanism, single-class, offline model.** Anyone reading this should not call it
"defeated."

## 10. What it costs (latency)

BOR delays the *actuation* by `J` (worst case 12 ms in our profile); RRC delays only *when the master
sees* the response, not the physical operation. Combined worst-case added time is ≈35.7 ms, which sits
far inside the master's 2-second response timeout (≈1.96 s of margin) [silicon hold + model J]
(Fig. `fig06_added_latency`). The delay is a tunable knob: you pick the smallest `J` profile that blurs
the fingerprint enough while staying inside the utility's command-latency budget. Protection-critical
trips should bypass BOR entirely.

## 11. What is proven, and what is not

**Proven on hardware [silicon]:** RRC normalizes the CLRT (2.1/1.1 ms native → 20.00 ms both) and makes
READ and SELECT responses byte-identical in size and segmentation (`[28,21]` → 49 B), on the physical
SEL-751.

**Proven by the compiler [compile]:** the faithful unified BOR+RRC fits the two on-chip pipes
(pipe 0 = 12, pipe 1 = 10), on both compiler versions, with the frozen RRC kernel untouched.

**Proven by model [offline]:** the first OPERATE is genuinely held (not fail-opened); exactly-once across
the cross-pipe handoff; `T0`-anchoring; fail-open; every one of ~20 attack mutants killed; the 24-gate
acceptance suite passes; 1000+ transactions and sequence-wraps hold.

**Not proven / limited (stated plainly):**
- The two-program *silicon load* is prepared and gated on a watched deployment window — it is a novel
  deployment (cross-pipe loopback, per-pipe packet-generator and mirror-session scoping, pipe-1 port
  bring-up) with dependencies we could not confirm without changing the running switch, so we did not
  load it blind.
- **Physical OPERATE is BLOCKED** — no electrical-isolation proof for the decoy output. The OPERATE
  lifecycle is meant to be exercised on software (OpenDNP3) endpoints through the switch, which was not
  run here.
- The physical-fingerprint result is the **synthetic** convolution model above — a mechanism
  demonstration, single device class family, not a multi-device silicon campaign, and not a defeat.
- The SBO is still *two* exchanges where a READ is *one*, and the request sizes still differ (20 vs
  45 B) — this defense shapes the outstation's *responses and its physical timing*, not the master's
  requests. It is not DPI-equivalence.

## 12. Reproduce and glossary

Exact commands to rebuild every proven result (compile both pipes, run the emulators and the 24-gate
acceptance suite, re-derive the CLRT numbers from the pcaps) are in `defense4/REPRODUCE.md`. The artifact
index with provenance labels is `defense4/PROJECT_MAP.md`.

**Glossary.** *CLRT* — cross-layer response time (ACK→response gap). *RRC* — Release–Replicate–Carve, the
response-side defense. *BOR* — Bounded OPERATE Release, the request-side defense. *PRE* — Packet
Replication Engine, the Tofino hardware that makes the two `[28,21]` copies. *SBO* — Select-Before-Operate
(SELECT then OPERATE). *T0/J/A/R* — original-OPERATE arrival, the random hold, the ACK deadline, the echo
deadline. *Epoch* — the switch's internal identity for one prepared BOR reservoir. *Fail-open* — on any
doubt, forward the control unshaped rather than drop it. *Stage* — one of the Tofino's 12 pipeline steps.
*Pipe* — one physical pipeline; this chip has two.
