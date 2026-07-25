# Part 12 — HOLD_RESPONSE deadline branch: RESULT

**Measured on Tofino-1 (switch `10.10.54.81`, SDE 9.13.2), 2026-07-25.** Program
`ibspg_hold_response` (source sha `fa073cf6`). Synthetic markers only — no DNP3 traffic and no
physical SEL-751, per the Part 12 scope.

## Headline

A response held queue-resident in a low-priority TM queue is released on a **data-plane deadline**
`t_ack + G`, with **no controller in the fast path, no drain packet, and no external chaff**. Across
G from 1 ms to 40 ms the observed ACK→response interval tracked the target to within
**1.72–1.74 µs**, and the spread of that error across the whole sweep was **23 ns**.

The error is not noise — it is the reservoir drain, and it is accounted for: in every trial the
deadline error equalled the independently measured release tail (the time from the first blocker
termination to the response leaving) to within tens of nanoseconds. Release happens at
`deadline + one loopback RTT`, and that RTT is constant.

This is the CLRT-normalization mechanism the line has been building toward: the emitted interval is
set by policy, not by the device. Part 11's ordering result is its substrate.

## Gate results

| Gate | Result | Evidence |
|---|---|---|
| 12.1 compile + fit | **PASS** | 0 errors, 12/12 ingress stages, identical resources on local 9.13.1 and on-switch 9.13.2 |
| 12.2 load + TM config | **PASS** | binds as `ibspg_hold_response`; `strict_priority_verified: true`; all 18 bfrt objects resolve; dp8/dp9/dp11 up at 25G |
| 12.3 pass-through control | **PASS** | K=0: response egresses in **2.10 ms** (≈ the injector's own delay), byte-identical — without a blocker ring nothing holds it |
| 12.4 hold without a deadline | **PASS** | K=64, no ACK: **128.0 M** blocker passes with no release, then fail-open |
| 12.5 deadline release | **PASS** | G=20 ms → observed **20.0017 ms**; all 64 blockers terminated by deadline |
| 12.6 accuracy sweep | **PASS** | 7 values of G, error 1721–1744 ns, spread 23 ns |
| 12.7 negative controls | **PASS** | stale-generation and unrelated-slot ACKs arm nothing |
| 12.8 byte-identity + isolation | **PASS** | 11/11 verifier checks; zero blocker frames at Vision; dp11 TX = 0 |
| 12.9 repetition campaign | see below | 100 reps at G=20 ms |

## 12.6 — the sweep

`K=64`, response injected 0.5 ms after the ACK, one trial per point.

| G (ms) | observed (ns) | deadline error (ns) | release tail (ns) | blocker passes | terminated by |
|---:|---:|---:|---:|---:|---|
| 1 | 1,001,744 | +1,744 | 1,719 | 1,901,830 | deadline ×64 |
| 2 | 2,001,736 | +1,736 | 1,719 | 1,948,627 | deadline ×64 |
| 5 | 5,001,742 | +1,742 | 1,721 | 2,059,773 | deadline ×64 |
| 10 | 10,001,724 | +1,724 | 1,720 | 2,246,934 | deadline ×64 |
| **17** | 17,001,743 | +1,743 | 1,720 | 2,506,597 | deadline ×64 |
| **25** | 25,001,721 | +1,721 | 1,721 | 2,803,872 | deadline ×64 |
| 40 | 40,001,731 | +1,731 | 1,721 | 3,361,896 | deadline ×64 |

17 ms and 25 ms are the measured SEL-751 native CLRT p95 and p99, so they are the operationally
interesting points; both are hit as precisely as every other value. In all seven trials
`ctr_block_term_timeout = 0` and `ctr_block_term_stale = 0` — every blocker died on the deadline, so
no result here is contaminated by the fail-open path.

**Comparison with the mechanism this replaces.** The earlier recirculation-hold reached its targets
with millisecond-scale error and jitter (17 ms → 19.67 ± 1.44, 25 → 23.25 ± 1.22, 40 → 36.94 ± 0.45,
and calibration-sensitive besides). The queue-resident deadline release is roughly **three orders of
magnitude more precise** and is calibration-free: nothing was tuned per G, and the same constant
1.72 µs tail appears at every point.

## 12.4 and 12.7 — the negative controls

Three scenarios in which the deadline must never arm. All three produce the same signature, which is
the point: the response is held for the **entire** budget and then fails open, rather than being
released early by something that should not have that power.

| scenario | ACK armed | blocker passes | terminated by | released |
|---|---|---:|---|---|
| no ACK at all | no (`ctr_ack_arm=0`) | 127,989,373 | budget ×1, then stale ×63 | fail-open |
| stale generation | no — forwarded as `ctr_ack_bypass=1` | 127,989,314 | budget ×1, then stale ×63 | fail-open |
| unrelated slot | no — forwarded as `ctr_ack_bypass=1` | 127,991,713 | budget ×1, then stale ×63 | fail-open |
| **qualifying ACK (12.5)** | **yes** | **2,618,914** | **deadline ×64** | **at t_ack + G** |

The contrast between the last row and the rest is the causal claim: a qualifying ACK, and only a
qualifying ACK, sets the release time. A non-qualifying ACK is still forwarded — transparency is
preserved — it simply arms nothing.

The fail-open cascade is worth recording because it explains the counter attribution: the first
blocker to exhaust its pass budget clears `reg_active`, so the remaining 63 terminate as *stale* on
their next pass rather than each burning its own budget. One budget termination plus K−1 stale
terminations is the expected fingerprint of a fail-open, not an anomaly. The same 1.72 µs tail then
applies.

## 12.8 — byte-identity and internal-token isolation

Every trial's verifier run passed all checks, including byte-identity of the released response
against its reconstructed injected twin, byte-identity of the ACK, ACK-before-response on the wire,
and the on-chip stamp cross-check.

Isolation is evidenced two ways, because the two host ports admit different methods:

- **dp9 (Vision)** — captured directly. The capture filter admits **both** `0x88c0` (ACK/response)
  and `0x88c1` (blocker token); the Gate 12.5 capture contains exactly two frames, both `0x88c0`,
  and **zero** `0x88c1`. This matters: the filter originally admitted only `0x88c0`, which would
  have made "no tokens seen" a statement about the filter rather than about the switch. It was
  widened, and a `b3_no_blocker_escape` check added, before any trial was run.
- **dp11 (Hulk)** — cannot be captured on, since it is the injection interface and a concurrent
  tcpdump fights the AF_PACKET inject. Switch-side counters settle it instead: **dp11
  `FramesTransmittedOK = 0`**. Nothing whatsoever has been transmitted toward Hulk, so no token can
  have reached it.
- **dp8 (internal loopback)** — `TX = RX = 411,276,249` frames. The blocker circulation is entirely
  internal, which is where the ~128 M passes per fail-open trial went.

## Scope and what is not claimed

- Synthetic role markers, one fixed slot, one flow. **Not** DNP3 traffic, **not** the physical
  SEL-751. DNP3 integration is the next part and is gated on this one.
- The guard interval `G` is carried in the ACK's `hdr.ib.seq` (TEST_ONLY) so a sweep needs no
  control-plane write. In a deployment `G` is policy and belongs in a register or table; the
  mechanism under test does not depend on which.
- `G` must satisfy `G < 2^31` ns (~2.1 s) for the sign-bit expiry test, and the 32-bit nanosecond
  clock wraps every ~4.29 s. Both bounds are far above any interval of interest here.
- The fail-open bound is a **pass budget**, not a wall-clock timeout. At K=64 a 2,000,000-pass budget
  worked out to roughly 3.4 s of hold. A deployment wanting a wall-clock fail-open would arm a second
  deadline rather than rely on the pass count.
