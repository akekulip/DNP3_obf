# TIMING_MECHANISM_EXPLAINED.md (directive §9)

A plain-language walkthrough of the in-network DNP3 timing normalizer: the threat it addresses, how
it works on Tofino-1, and exactly what it does and does not conceal. Every quantitative statement
here traces to a file under `evidence/` (see `evidence/MANIFEST.md`).

---

## 1. The fingerprinting threat

A passive observer on the SCADA LAN — someone who can see packet headers and timing but never touches
the endpoints — can often tell *which* outstation model is answering a master. This "device
fingerprinting" is a reconnaissance step: once an attacker knows a feeder is served by, say, a
particular relay model, they can look up that model's known vulnerabilities and its expected
behaviour before acting. The defender's goal is to make the wire look the same regardless of which
device is behind it, so passive observation yields no free identification.

Fingerprints come from several independent channels: the response *size*, the *ACK mode* (does the
device send a separate TCP ACK before its DNP3 response, or piggyback the ACK on the response?), the
*TCP-stack* signature (initial TTL, MSS, window), and the *timing* between the transport ACK and the
DNP3 application response. This mechanism attacks exactly one of those channels: the timing one.

## 2. Why CLRT leaks device behaviour

Formby et al. named the **Cross-Layer Response Time (CLRT)**: the interval between a device's
transport-layer ACK of a request and its application-layer DNP3 response to that request. The ACK is
produced by the TCP stack the moment the segment is received; the response is produced later, after
the device's application firmware has read its I/O, assembled the DNP3 objects, and handed the frame
back down. That gap is a direct measurement of the device's internal processing latency — its CPU
speed, its scan cycle, its firmware path — and it is remarkably stable per device and distinct across
devices.

On our physical SEL-751 relay the native CLRT has a median of 2.03 ms and a standard deviation of
10.33 ms (`evidence/native/`, n=120). Measured as observer entropy at 1 ms resolution it carries
**2.73 bits** (`evidence/fingerprinting/fingerprint_eval.json`). That is the leak we close.

## 3. Why endpoints and controllers are not used

The obvious way to normalize timing would be to change the outstation firmware, or to have an SDN
controller intercept and re-time each response. We deliberately use neither:

- **Endpoints are untouchable.** In a real utility the outstation is a certified relay; you cannot
  reflash its firmware to add a delay, and you cannot install a shim on it. The defense has to work on
  a device it does not control and cannot modify — it must be *non-cooperative*.
- **The controller is too slow and not in the fast path.** A control-plane loop that sees each
  response, decides a delay, and re-injects it adds milliseconds of software latency and jitter — the
  very thing we are trying to remove — and it would put a general-purpose CPU in the critical path of
  every SCADA transaction. Our mechanism runs entirely in the switch data plane; the control plane
  sets one policy value (the guard interval G) *once* and is never consulted per transaction.

## 4. Why the original response stays queue-resident

The core idea is to **never copy or rebuild the response**. When the real DNP3 response arrives from
the outstation, the switch does not parse it into a buffer, hold it in software, and re-emit it later.
Instead it steers the *original packet* into a low-priority Traffic-Manager (TM) queue and simply
declines to schedule that queue until the deadline. The packet sits in silicon exactly as it arrived.
When it is finally released it is byte-for-byte identical to what the device sent — we verified
byte-identity on every one of the 100 protected transactions (`evidence/packet_identity/`). This is
what keeps the mechanism **byte-preserving**: no CRC recompute, no field edits, no reserialization.

## 5. What blocker tokens are

To hold a queue "closed" we need something to occupy the switch's scheduler so the response queue
never wins arbitration. That something is a **blocker token**: a tiny internal packet (EtherType
0x88c1, never a real DNP3 frame) that lives only inside the switch, recirculating on an internal
loopback port (dp8). A small reservoir of these tokens is kept churning through a *high*-priority TM
queue (Q_BLOCK, qid 7). They never leave the switch — the observer on the LAN sees zero blocker
frames (`evidence/` STAGE_B_RESULT.md confirms 0×0x88c1 frames at the master). They are pure internal
scheduling pressure.

## 6. How strict priority provides holding

The TM is configured with **strict priority**: Q_BLOCK (qid 7) outranks the response queue Q_RESP
(qid 1). As long as at least one blocker token is eligible in Q_BLOCK, the scheduler always serves it
first and Q_RESP is starved — the response cannot egress. Holding the response is therefore not a
timer in software; it is an emergent property of keeping the high-priority queue non-empty. The
earlier IBSPG work established that this requires a *reservoir* of blocker tokens (K ≥ 64), not a
single token, because a lone token can drain between arbitration cycles and briefly open the gate.

## 7. How the ACK arms the deadline

When the classifier sees the transport ACK for a DNP3 request, it computes the release deadline
**t_ack + G**, where G is the policy guard interval, and writes it into per-transaction state. Arming
is **idempotent on the first ACK**: a `RegisterAction` writes the deadline only if the slot is still
in the UNARMED sentinel state (`deadline_arm_once`: `rv = now_word − v; if (v == UNARMED_WORD) v =
dl_val;`), so a retransmitted ACK cannot move the deadline. The deadline is stored tick-aligned (low
byte zero, 256 ns granularity) because the packed state word carries the "armed" marker in its
lowest bit — G is rounded down to a tick boundary by the control plane (`p13_guard.py`).

## 8. How blocker termination releases the response

Each blocker token, as it recirculates, checks the current time against the armed deadline. While
`now < deadline` the token is kept alive and re-injected — the reservoir stays full and Q_RESP stays
starved. Once `now ≥ deadline` the token is **terminated** instead of re-injected (the comparison is
a sign-bit ternary match on `now_word − deadline`, which avoids a 32-bit magnitude compare the target
cannot do in one gateway). As the reservoir drains, Q_BLOCK empties, strict priority no longer favours
it, and the TM finally schedules Q_RESP — the original response egresses. Release is thus driven
entirely by the data plane; no control-plane message is involved.

## 9. Why the release has a stable implementation tail

Release is not instantaneous — there is a small, *constant* lag between the deadline instant and the
response actually leaving the wire. We decomposed it (Part 12, n=100, `evidence/` release-tail data,
Fig 8): c1, the time from deadline to the first blocker token observing it and terminating, averages
**14.4 ns** (sd 7.16 ns); c2, from that termination to the response egressing, averages **1720.1 ns**
(sd 1.14 ns); the total tail is **1734.5 ns** with sd **7.34 ns**. This ~1.7 µs tail is a fixed
property of the recirculation loop, *not* device behaviour — it is identical regardless of which
device is behind the switch, so it carries no fingerprint. It is why the protected CLRT sits at
25.000 ms + ~1.7 µs rather than exactly 25.000 ms, and why the residual protected entropy is 0 bits
at ms resolution and only appears at all below 100 µs.

## 10. How fail-open works

If anything goes wrong with the blocker loop — the reservoir cannot be sustained, or a token
recirculates more than MAX_PASS times without the deadline arriving — the mechanism **fails open**:
the response is released rather than held indefinitely. A stuck-closed queue would drop a real SCADA
response, which is operationally unacceptable (it could hide a genuine fault indication from the
operator). The `budget_zero` path guarantees that a token which exhausts its pass budget releases the
response instead of black-holing it. Fail-open trades a moment of reduced obfuscation for never
losing a real response.

## 11. How G must be selected

G is the single policy knob: the constant every protected CLRT is normalized to. It must be chosen
**strictly greater than the device's native CLRT**, otherwise the response is already late by the time
the deadline passes and there is nothing to hold — the mechanism degenerates to a pass-through. The
**G-selection guard** (§3 of the directive) enforces this: it measures `native_clrt = t_response −
t_ack`, flags `protection = native_clrt < G`, and increments a `zero_hold` counter whenever a
transaction arrives with G below native. Fig 9 shows the guard firing: at G = 1 ms (below the SEL-751's
~2 ms native CLRT) every transaction is flagged zero-hold; at G = 25 ms every transaction is genuinely
held. A deployer therefore sets G above the p99 native CLRT of the slowest device in the anonymity set
(here we used 25 ms, comfortably above the 11.42 ms native p99).

## 12. What the mechanism does and does not conceal

**Conceals:** the CLRT-magnitude channel. After normalization the ACK→response interval carries
0.00 bits at ms resolution (down from 2.73 bits), on the physical SEL-751's real traffic. Every
observed protected transaction sits at G within a fixed ~1.7 µs implementation tail.

**Does NOT conceal** (stated plainly, per directive §10):

- **ACK mode.** The SEL-751 still emits a *separate* TCP ACK before its DNP3 response; the AB1400 and
  ION7550 piggyback. That structural difference is untouched and, on our 3-device corpus, is alone
  enough to identify the SEL-751 (device-ID balanced accuracy 1.000).
- **TCP-stack signature.** TTL, MSS, and window differ per device and are untouched (accuracy 1.000).
- **Response size.** Size normalization is a *separate, unproven* line and is explicitly out of scope
  this week — this mechanism does not pad or split.
- **Device anonymity.** Because only the SEL-751 has a CLRT at all in this corpus (the others have no
  separate ACK), closing the CLRT channel yields an *anonymity set of one* — there is no other
  separate-ACK device for it to be confused with. Closing CLRT is a genuine *within-channel* entropy
  reduction and a working *mechanism*, but on this corpus it does not by itself reduce a real
  multi-channel device classifier. Turning the mechanism into a demonstrated *security* result needs a
  fleet of separate-ACK devices all normalized to a shared G, with ACK-mode and TCP-stack held
  constant (future work).

This mechanism is one component — the timing axis — of a larger obfuscation design. It is the axis we
can prove works on real hardware today.
