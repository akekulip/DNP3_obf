# §13 GATE 2 — PASS

`evidence/gate2/gate2_20260729T231747Z/` · scenario `gate2-2timer` · D = 2 ms · K = 64 ·
B = 18 000 · dp8 `BF_SPEED_25G` on both the MAC and the TM.

**17 of 17 requirements PASS.** This is the first Defense 3 hold that is a hold: the ACK
was retained for its predetermined deadline, released before the RESPONSE, and the
transaction returned clean — with a valid timing precondition and **no fail-open**.

---

## 1. The direction's Gate-2 requirement list

| requirement | result |
|---|---|
| exactly one 64-token burst | `PKTGEN_ADMIT = 64`, `PKTGEN_DROP = 0`, app 1 `trigger/batch/pkt = 1/1/64` |
| reservoir effective before ACK admission | **678 ns** vs the ACK at 500 010 ns — 738× margin |
| ACK enters Q_HOLD only after Q_BLOCK is effective | `ACK_HOLD = 1`, `ACK_DUP_HOLD = 0`, `ACK_REJECT = 0` |
| RESPONSE enters behind ACK | `RESP_HOLD_EARLY = 1`, `RESP_HOLD_LATE = 0`, `RESP_BYPASS = 0` |
| `ACK_RELEASE_FAILOPEN = 0` | **0** |
| blocker budget expiry = 0 | `BLOCK_TERM_TMO = 0` |
| stale termination = 0 | `BLOCK_TERM_STALE = 0` |
| all 64 blockers terminate due to deadline | `BLOCK_TERM_DL = 64` |
| no ACK forwarding before `t_ACK + D` | hold 2 001 505 ns ≥ D 1 999 872 ns |
| ACK forwarded before RESPONSE | separation **+28 ns** (positive = correct order) |
| transaction state clean | `reg_tag = 0x00`, `BAD_PORT = 0`, queue drops 0 |

## 2. Measured separately, as the direction asks

| quantity | value |
|---|---|
| `t_ACK` (deadline armed) | 1 286 574 958 ns |
| `d_ACK` (the armed deadline word) | 1 288 574 721 ns |
| first deadline termination | 1 288 574 744 ns |
| final deadline termination | 1 288 576 436 ns |
| ACK forward commitment | 1 288 576 463 ns |
| RESPONSE forward commitment | 1 288 576 491 ns |
| **actual ACK hold** | **2 001 505 ns** |
| **drain** (first → final termination) | **1 692 ns** |
| **drain tail** (final termination → ACK out) | **27 ns** |
| ACK → RESPONSE separation | 28 ns |
| READ → pktgen trigger | 667 ns |
| READ → full K reservoir | 1 195 ns |

### The mechanism, decomposed rather than asserted

`d_ACK − t_ACK = 1 999 763 ns`, i.e. **D to within the 256 ns tick quantization**. The
first blocker notices the deadline **23 ns** after it passes. The reservoir then drains
in **1 692 ns**, against the R5 model's prediction of `K / rate_dp8 = 1 711 ns`. The
held ACK leaves **27 ns** after the last blocker dies, and the RESPONSE **28 ns** after
that.

So the hold is `D + drain + tail`, and every term is now a **measurement**:

```
2 001 505  =  1 999 763 (D, quantized)  +  1 692 (drain)  +  27 (tail)  +  23 (detect)
```

That matters for the R5 correction. Before this run the `K/rate` bias was a model whose
only evidence was the residual it removed — circular. Now the drain is measured
directly, independently of the residual, and it agrees with the prediction to 19 ns
(1.1%). The corrected deadline error is **−78 ns** against a ±1 000 ns bound.

## 3. The schedule, and why it is this one

```
app 2  one-shot timer T          {READ}         run ends at once -> the generator is
                                                free when the clone arrives, which is
                                                the condition production has
app 1  recirculation pattern     K=64 blockers  fired by the READ's own 0xE1 clone
app 3  one-shot timer T + 500us  {ACK, RESP}    ipg 500 us = the ACK->RESPONSE gap
```

Both timers are armed in **one `entry_mod` carrying both keys**, so the inter-write
skew cannot leak into the offset. Realised **READ→ACK = 500 010 ns** — 10 ns from the
intended 500 µs, and inside the relay's measured band (0.400 ms minimum / 0.505 ms
median). That is what the direction means by "a synthetic schedule consistent with the
physical READ→ACK timing, not an artificially delayed ACK". With two separate writes
the skew measured ~1.15 ms and pushed READ→ACK to 1.65 ms; batching fixed it.

**Three schedules were ruled out by measurement, not by argument:**

1. **All three events in ONE generator run** (the original). CHECK 2: the blocker burst
   is withheld for the run's whole span, so the reservoir is late by `ipg + 1215 ns` at
   *every* ipg. No re-ordering of the roles inside one run helps — an ACK placed last is
   still admitted at the batch end, 1215 ns before the reservoir.
2. **A recirculation-pattern app for the ACK/RESPONSE, fired by the READ's own clone.**
   Two independent failures, both observed on silicon:
   - its packets **cannot be told apart** — with `(3,0)→RESP, (3,1)→ACK, (3,2)→RESP`
     installed, all three packets took `synth_ack`, giving `ACK_HOLD=1 ACK_DUP_HOLD=2`
     and **zero** RESPONSE and **zero** bypass. `packet_id` decodes as the same value
     for every packet of a pattern-triggered app, so a leading DUMMY is impossible and
     roles collapse onto one entry. (The frozen Defense 2 never exposed this: it only
     `advance()`s over the generator header, and its 64 tokens are identical.)
   - it was **served before app 1**, so the reservoir waited for app 3's whole run span
     (1 000 689 ns). Two apps on one trigger cannot be ordered from the control plane.
3. **Two timer apps armed by two separate writes** — works, but the control-plane skew
   lands in `READ→ACK` and put it 3.3× above the physical band.

`packet_id` discrimination **is** proven for timer apps — it is what decoded
READ/ACK/RESP in every earlier run — which is why the surviving design uses two of them.

## 4. Cost

| | ingress | egress | critical path | errors |
|---|---|---|---|---|
| local `bf-p4c 9.13.1` | 9 / 12 | 0 | 8 | 0 |
| switch `bf-p4c 9.13.2` | 9 / 12 | 0 | 8 | 0 |

The split schedule itself *reduced* the program to 8 ingress stages (the dependency-graph
floor); adding `reg_ts_last_term` — the final-deadline-termination instrument the
direction's measurement list requires — spent one stage to get back to 9. That is the
honest trade: one stage for the drain becoming a measurement instead of a model.

## 5. What Gate 2 does NOT establish

- **One transaction.** Gate 3 (five transactions) and Gate 4 (three boundary cases) are
  separate and have not run.
- **Synthetic events.** The ACK and RESPONSE are generated in-chip. §14 physical
  validation against the real SEL-751 is what replaces them with a relay's own timing,
  and it has not run.
- **No claim about concealment.** Gate 2 is a mechanism gate. Nothing here measures
  what an adversary sees; CONSENSUS §9's evaluation constraints (block within session,
  D=1 ms as a null control, AUROC beside every concealment number) still apply and are
  untouched.
- The keepalive re-arm hazard (`tcp.seq == EXP_RELAY_SEQ`) is implemented but is
  **not exercised by this gate** — it needs an injected keepalive, which the synthetic
  build cannot produce.
