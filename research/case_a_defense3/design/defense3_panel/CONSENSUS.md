# Defense 3 — panel synthesis and chosen implementation

PI synthesis of memos 01–07. **Advisory input closed; implementation proceeds from here.**

---

## 1. Essential functionality

Hold the original pure TCP ACK until `d_ACK = t_ACK + D`; release independent of RESPONSE arrival.
An early RESPONSE queues behind the ACK in the same FIFO; a late one forwards normally. Two queues
(`Q_BLOCK` 7 > `Q_HOLD` 1), one deadline, one K=64 request-triggered blocker class, one active
transaction. All decisions in ingress.

## 2. Unnecessary functionality — cut

Second deadline · second expiry table · second blocker role/budget · four production queues ·
`Q_FINAL` · READ-relative targets · response blockers · dual-release telemetry · per-branch counter
sets. **No new register beyond `ack_release_gen`** (Panel A): the deadline-valid marker is already
bit 0 of the deadline word, `awaiting_ack` is already enforced inside `deadline_arm_once`,
`transaction_active` is already `cur_gen ∈ 0xC0..0xCF`, and `response_queued` is derivable.

## 3. Ingress vs egress — **Variant A, all ingress** (Panel A, adopted)

Panel A dissents from §10's premise and the PI accepts the dissent: there is **no internal marker to
clean up** (the parser re-derives role on the loopback pass; blockers set `bypass_egress=1` and never
reach egress), queue selection cannot move (the TM consumes it first), an egress release counter
cannot identify the released ACK without bridged metadata on a byte-preserving pass, and an **egress
timestamp is strictly worse than the ingress one** because the true dequeue instant is the loopback
pass's `ingress_mac_tstamp`. Probe compiles A/B/C will still be run because §10 asks for the
numbers, with **A pre-registered as the selection**.

## 4. Minimum persistent state

`reg_tag` (generation + liveness) · `reg_deadline` (24-bit ticks + armed marker in bit 0) ·
**`reg_ack_release_gen`** (new, 8-bit SALU difference `rv = cur_gen − v`, placed at L4 in parallel
with `reg_deadline`) · `reg_exp_relay_seq` · `reg_exp_ack` · session 5-tuple state. PHV: reuse the
provably-dead `meta.tag_val` / `meta.tag_diff` on the paths that touch the new register — MAU group
B0-15 is at **16/16 containers** despite 16.5% overall PHV, and that is what breaks a new SALU's
operand placement.

## 5. Expected stage use

**Predicted 8 ingress / 0 egress / critical path 8** (Panel A), 8–9 with the full §8 predicates.
Only the ACT block binds: stages 5 and 6 are already 16/16 logical table IDs, so **the only reachable
budget is the 10 free slots at stage 7** — the 61 free slots in stages 0–4 are unreachable by that
work. **Held reserve:** the inline lever has not been applied to this baseline (15 bare-action
tables, ~12 LTIDs) — that is the recovery if the first compile lands at 9.

---

## 6. RESOLVED DISAGREEMENTS

### 6.1 Fail-open budget — Panel B (100 000) vs Panel F (18 000) → **PI: 18 000**

Both measured different quantities and both were right about theirs. The budget must never fire
during a legitimate hold **and** must never approach the TCP RTO. Using **Panel B's model**
`H = B × K / rate_dp8`:

| | passes | horizon | vs longest legitimate hold (D=3) | vs 211 ms RTO |
|---|---|---|---|---|
| inherited | 100 000 | 171.5 ms | 98× | **0.81×** — too close |
| **adopted** | **18 000** | **30.9 ms** | **8.8×** | **6.8× clear** |

Panel F's number, derived by Panel B's formula. The inherited comment (10 µs/pass) is ~5.8× wrong
and is replaced by the formula, because the wrong model gives the wrong answer the moment D, K or
port speed changes.

### 6.2 §10 egress migration → **rejected on Panel A's evidence** (see §3).

### 6.3 §7 LATE RESPONSE `if (expired) to_fwd()` → **rejected** (Panels C and prior work agree).
It races the 1 736 ns release tail and inverts wire order. **Route every in-transaction RESPONSE to
`Q_HOLD` unconditionally**; if the deadline has passed, `Q_BLOCK` is already empty so it costs one
408 ns loopback traversal.

---

## 7. PRIMARY RISKS AND THEIR CONTROLS

| # | Risk | Control |
|---|---|---|
| R1 | **dp8 `$SPEED` is a correctness parameter.** K=64 margin is 10.5× at 10G, 4.2× at 25G, 1.05× at 100G. A prior run was already invalidated by dp8 silently at 10G — the same failure that voided the Control A re-run. | Read back and **assert `BF_SPEED_25G`** before every trial; abort otherwise. |
| R2 | **Reservoir not standing when the ACK arrives.** The ACK arrives **min 0.400 ms** after the READ — ~4× sooner than the packet Defense 2 held. A late reservoir is a *silent* zero-hold that reads as a working run. | Instrument `t_first_ABLOCK_admitted − t_READ`; require < 100 µs. Blocking gate. |
| R3 | **Keepalive installs a stale deadline** — silent loss of protection. | `tcp.seq == EXP_RELAY_SEQ` (§8.1). Blocking. |
| R4 | **Silent fail-open** — ACK releases early, run looks fine. | `ACK_RELEASE_FAILOPEN == 0` required in every valid trial. |
| R5 | **Deadline instant ≠ release instant.** They differ by a deterministic `K/rate` = **1.711 µs** bias. | Gate 2 scores against **`D + K/rate`**, not `D`. Misreading this as jitter is the default failure. |
| R6 | Per-queue shaper or the dp8 **port** shaper left armed by prior oracle work → `Q_BLOCK` goes shaping-ineligible, indistinguishable from an empty gap. | Setup must explicitly disable both and read back. |
| R7 | Response generation test built naively from the READ's `gen_in` **silently mis-fires** — the response's `app_control` has CON set (`0xEn`, not `0xCn`). | Derive the response's generation test from the tracked session, not from the READ's app-control byte. |

---

## 8. CHOSEN IMPLEMENTATION

### 8.1 ACK predicate — Panel C, empirically derived (622 txns, 56 connections, 8 PCAPs)

**The load-bearing conjunct is the SEQUENCE, not the acknowledgment.** Measured: the expected-ack
test accepts **61/61** keepalives; the expected-seq test rejects **61/61**.

```
ingress_port == PORT_RELAY
reverse 5-tuple matches the learned session
ipv4.ihl == 5  AND  frag_offset == 0  AND  MF == 0        <- new, was untested
(tcp.flags & 0x3F) == 0x10                                 <- 0x17 admits zero-payload PSH|ACK;
                                                              all 56 FIN frames are FIN|PSH|ACK
ip.total_len == 4*ihl + 4*data_offset                      (zero payload)
tcp.seq  == EXP_RELAY_SEQ                                  <- REJECTS 61/61 keepalives
tcp.ack_no == EXP_ACK                                      (defence in depth)
generation active AND txn_state == AWAITING_ACK            (one-shot)
```

**`EXP_RELAY_SEQ` needs NO arithmetic**: set it from the master's pure ACK —
`EXP_RELAY_SEQ := master_pure_ack.tcp.ack_no`. Validated **679/679** relay ACKs and **622/622**
responses, zero mismatches, seeded free by the handshake. No `seq + len`, no payload-length
computation, no SALU add. Learn the master's ephemeral port on SYN (it changes per connection).

### 8.2 RESPONSE predicate and segmentation

Relay-facing · reverse session · active generation · expected seq/ack relationship ·
`tp_ctrl & 0xC0 == 0xC0` and `app_control & 0xF0 == 0xC0` (FIR/FIN set, CON=0, UNS=0) · one-shot.
**The transport-control mask must be `0xC0`** — the low 6 bits are a sequence counter spanning
`0x00–0x3F`. Segmentation confirmed **single-segment 622/622**; anything else increments
`UNSUPPORTED_SEGMENTATION` and bypasses. **A retransmitted RESPONSE or a second qualifying ACK is
FORWARDED, never dropped** — one-shot state rejects the *hold*, not the *packet*.

### 8.3 Ordering invariant (Panel B)

Strict priority buys the **hold**, not the ordering. Ordering requires every protected packet to
share: same ingress port, same dp8 qid, **same number of loopback passes**, same dp9 qid. Unequal
pass count is what bit the prior design.

### 8.4 Operating envelope

`D` is a **runtime-writable register** (Panel E) so the D arms become a within-program factor and
three reload boundaries collapse to zero. **Clamp `D ≤ 40 ms`** (Panel C: poll-period overlap at
~40 ms; genuinely dangerous only at ≳200 ms).

---

## 9. EVALUATION — binding constraints

- **The session-to-session drift exceeds the effect.** C1/C2/C3 share labels yet have medians
  25.25 / 2.31 / 1.40 ms and native-vs-native AUROC to 0.985. Calibration and evaluation must be
  **blocked within session**, and no D may be fitted and tested on the same campaign.
- **D = 1 ms is a pre-registered NULL CONTROL**, not a treatment arm — 0/100 concealed, sd ratio
  1.0000, adversary recovers 98–100/100. Collapse there means the pipeline is broken.
- **Sweep across the regime boundary**, not just {1,2,3}: the interesting region is unsampled.
- **Iso-latency Defense 2 arms** — comparing D≤3 ms (1.25 ms added) against G=25 ms (22.57 ms) is
  uninterpretable in both directions.
- **Count ATTEMPTED, not successful, transactions**; report disposition for all.
- **Report AUROC-vs-native beside every concealment number.** Our own K1 gate already measures it
  rising *with* concealment: 0.878 at D=2, 0.894 at D=3, **1.000 at D=22**.
- Binned entropy never as a headline (a proven bijection raised it 0.260 bits).
- Guard the **KDE-degeneracy trap**: a fully clamped feature returns accuracy 1.000 through density
  degeneracy — a bogus "the defense made classification perfect" result.

## 10. CLAIM POSITION (Panel G, adopted)

Supportable: the implementation claim, plus **graceful tail degradation** — a Defense 3 escape emits
`c − D` where a Defense 2 escape emits native `c` intact. Scope it to the native-trained attacker.

**Not claimed:** anonymity or "defeats Formby" (the confusion set is empty — the corpus's other
devices are combined-ACK, separable by packet count); that near-zero CLRT mimics a combined-ACK
device; "strictly better than Defense 1" (true only at `D ≥ max(c)`); K=64 minimality; that
concurrency extension is straightforward — **one active transaction is the measured capacity of the
reservoir** (~24 Gbps of a 25G loopback per hold), not a prototype simplification.

**Stated head-on, not in limitations:** concealment and detectability rise together, and at large D
the output is *physically implausible* — a device that took 22.5 ms to ACK a 20-byte read then
answered 1.7 µs later, consistently. ACK generation is cheap and application response expensive;
the ordering inverts. Defense 2's output stays inside the manifold of real device behaviour;
Defense 3's, at the D that actually conceals, leaves it.
