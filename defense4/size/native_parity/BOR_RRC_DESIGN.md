# BOR-in-RRC design — Bounded OPERATE Release as an OPERATE-request phase of RRC

Goal: **solve** the Formby physical-operation-time fingerprint (not scope around it) by adding a
bounded, profile-selected hold on the master's OPERATE *request* before the relay receives it, so
the observer-measured operation time `M = T_SER_event − T_OPERATE_observed = J + T_physical` is shaped
toward a common target across devices. BOR is a **phase of the existing RRC transaction engine**, not a
second program: the final hardware artifact stays one `defense4_rrc_kernel`. This document is the spec;
the compile probe `defense4_rrc_bor_compile_probe.p4` is a byte-for-byte-derived copy of the proven
kernel with the phase added, so the proven baseline is never edited.

## 0. Why one program, one transaction

One P4 program can hold many logical primitives; a single TF1 pipe runs exactly one program. BOR and
RRC are integrated because they **share** transaction state, the loopback hold ring, the blocker-
reservoir mechanism, the deadline comparator, the PRE carve, and the fail-open/retransmit guards — and,
decisively, because the anti-subtraction invariant (below) is only structural when **one** transaction,
anchored at a single `T0`, spans request-hold → ACK-hold → response-hold. Two primitives handing `T0`
across a boundary would re-open the leak.

RRC becomes: **Admit → bounded request release → ACK/response release → replicate → carve.**

## 1. Deadline semantics — everything anchored to T0

`T0` = the **ingress MAC timestamp of the original protected OPERATE request**, observed on the
master-facing side (the kernel already parses `ig_intr_md.ingress_mac_tstamp` into PHV). For an OPERATE
admitted at `T0`:

```
  T_OP_RELEASE  = T0 + J     (release the held OPERATE to the relay, dp64)
  T_ACK_RELEASE = T0 + A     (release the relay's pure ACK to the master, dp9)
  T_ECHO_RELEASE= T0 + R     (release the 49 B OPERATE echo, carved [28,21], dp9)
```

Constraints the control plane MUST validate before install (a bad set is rejected, never silently
defaulted):

```
  A > J_max + native_ACK_bound            (the relay cannot ACK an OPERATE it has not yet received)
  R > J_max + native_response_bound
  R >= A
  A, R, J_max  all < min( operational_command_to_actuation_limit,
                          master_response_timeout − guard,
                          TCP_retransmit_bound − guard,
                          BOR_fail_open_horizon )
```

**The old D_A = 2 ms ACK target does NOT survive.** With BOR delaying OPERATE up to `J_max` (~10–12 ms),
the relay's ACK does not exist until `T0 + J + native_ACK`. The OPERATE lifecycle therefore uses fresh
`A`/`R` totals-from-T0, distinct from the READ/SELECT deadlines. READ/SELECT are unchanged.

**ACK and echo release targets are NEVER re-anchored** to the delayed OPERATE release (`T0+J`) or to the
relay's native ACK arrival. Re-anchoring re-introduces the subtraction attack (§2).

## 2. Anti-subtraction invariant (the load-bearing security property)

The attack: a passive observer that learns `J` subtracts it from the SER measurement and recovers the
native `T_physical`. Two independent channels can leak `J`:

1. **Response-timing channel.** If the echo/ACK are released relative to `T0+J`, then
   `echo − OPERATE = J + const`, and a known `const` yields `J`. **Closed by T0-anchoring** (§1): with
   `echo − OPERATE = R` constant, this channel carries no `J`.
2. **TCP timestamp channel (this is NOT closed by T0-anchoring).** The SEL negotiates TCP timestamp
   options. Its pure ACK carries a `TSval` generated when the relay **actually received** the released
   OPERATE (`≈ T0 + J`). Even if the switch holds that ACK until `T0 + A`, the observer reads the stale
   `TSval` and recovers `J` from the timestamp clock, not from packet arrival.

**Therefore the anti-subtraction claim is INVALID whenever relay TCP timestamps are negotiated.**
Resolution:
- **MVP (this campaign): require a no-TCP-timestamp connection** on the dedicated protected master
  flow (timestamps disabled before connection establishment). Add a **parser + counter gate**: detect
  the TCP timestamp option on the protected flow and **report a violation counter**; the design must
  refuse to assert timestamp-safe behavior when the counter is non-zero. Never silently claim it.
- **Future:** full TCP timestamp normalization with correct reverse `TSecr` handling (a distinct,
  heavier primitive with its own correctness obligations).

## 3. Queue plan (strict-priority ladder, one loopback domain)

| priority | qid | role |
|---|---|---|
| 7 | qid7 | ACK blocker reservoir |
| 6 | qid6 | held original ACK |
| 5 | qid5 | RESPONSE blocker reservoir |
| 4 | qid4 | held original RESPONSE |
| 3 | qid3 | **OPERATE blocker reservoir (new)** |
| 2 | qid2 | **held original OPERATE request (new)** |

Reservoir-residency obligation (stronger and more accurate than a "fill within 0.408 ms" claim): the
qid3 OPERATE reservoir must be **resident before the OPERATE arms**, and because qids 4–7 have higher
priority it stays queue-resident (not consuming its loop budget) while higher queues are active.

**Correction from the compile probe (generation-binding).** Seeding qid3 *at SELECT admission* (the
original idea) conflicts with generation-binding: SELECT and OPERATE are **different DNP3 transactions
with different generations**, so a token stamped with the SELECT generation reads **stale** the moment
the OPERATE arms, and the reservoir would be rejected. The probe therefore seeds qid3 at the
**OPERATE's own pktgen burst** (generation-consistent, resource-identical).

**READINESS RACE — unresolved, a critical correctness gap (2026-08-12).** In the current probe the
OPERATE is queued into qid2 in the **same admission pass** that `arm_clone` *starts* the qid3 pktgen
burst. There is **no proof the qid3 blocker reservoir is resident before qid2 begins draining** — the
pktgen tokens arrive asynchronously (a later TM event), so the held OPERATE could dequeue from qid2
*before* its blocker exists and **escape early / release unshaped**. This is a **critical mutant**
(`early_qid2_release`), modelled with an **asynchronous pktgen/TM arrival** in the emulator.

**Known non-solution (relabel, do not claim as BOR):** the current SR4 probe reads an `op_ready` flag
on the OPERATE *before* it arms the qid3 burst, so the FIRST real OPERATE always reads 0 → **fails open**
(bypasses BOR) → arms qid3 async → an exact retry is `V_ARM_DUP`-suppressed. That is *safe bypass*, not
*successful shaping*; the SR4 stage number is a **resource probe**, not a faithful-BOR result. It also
never clears `op_ready`, so a 4-bit DNP3 sequence wrap can match a stale ready value.

**Faithful readiness — SELECT prepares a BOR epoch (the resolution).** SBO always sends SELECT before
OPERATE, so the reservoir is prepared during SELECT, and the OPERATE is held on its *first* try:

```
SELECT admitted
  → create a BOR EPOCH  (a separate internal preparation identity — NOT the DNP3 generation, since
                         SELECT and OPERATE are independent DNP3 transactions)
  → seed qid3 for that BOR epoch
  → confirm qid3 residency
  → retain BOR_PENDING(epoch) across SELECT completion
OPERATE arrives at original upstream T0
  → REQUIRE matching BOR_PENDING(epoch) AND confirmed residency  (else forward immediately + count;
                                                                   never enqueue on a stale flag)
  → select leak-safe J (Random<T> / bounded selector; the epoch is NEVER the source of J)
  → arm T0+J, T0+A, T0+R ; enqueue the original OPERATE into qid2 ; qid3 blocks qid2 until T0+J
  → release the original byte-identically EXACTLY ONCE to dp64
ACK, echo arrive later → release at absolute T0+A, T0+R ; carve [28,21] ; retire the BOR epoch + RRC state
```

Cleanup / abort paths (each must retire the epoch with no output change unless it releases the original):
failed SELECT, missing-OPERATE watchdog, preparation timeout, unready reservoir, OPERATE release,
ACK/response completion, FIN/RST, connection replacement, invalid profile, fail-open, every abort. A
**stale-ready after a 4-bit sequence wrap must NOT** revalidate readiness — the BOR epoch identity, not
the public sequence, gates the hold. Until the P4 shapes the FIRST eligible OPERATE after a clean start
via this mechanism, the BOR core is not faithful.

## 4. Lifecycle (the OPERATE_REQUEST_HOLD phase)

```
SELECT admitted           → seed the usual ACK/RESP reservoirs + the qid3 OPERATE reservoir
                            → qid3 stays resident behind active qids 4–7
SELECT ACK + response      → complete through the existing RRC path (unchanged)
OPERATE arrives at T0      → record T0 (ingress_mac_tstamp), select J (codebook), phase = OP_REQUEST_HELD,
                            → send the ORIGINAL OPERATE to qid2 (byte-identical, held)
qid3 drains at T0 + J      → the qid2 original re-enters with an internal OP_RELEASE marker and is
                            → forwarded byte-identically to dp64 (relay). Exactly one release.
OP_RELEASE pass            → transitions THIS SAME transaction into WAIT_ACK using the stored T0
relay ACK                  → held, released at T0 + A (dp9)      [anchored to T0, not to T0+J]
relay OPERATE echo (49 B)  → held, released at T0 + R, into PRE → carved [28,21] (dp9)
retire                     → exactly once
SELECT fails / OPERATE     → qid3 retires by a bounded watchdog, NO output change
  never arrives
```

## 5. Byte-identical, exactly-once release

The held OPERATE that leaves toward dp64 is the **original bytes**: no padding, no CRC rewrite, no TCP
sequence translation, no fabricated request, no controller fast path. **Exactly one** original OPERATE
may reach the relay. The OP_RELEASE marker is an internal recirculation tag, stripped before egress.

## 6. Failure table (a real control request — never silently drop or duplicate)

| condition | behavior |
|---|---|
| reservoir (qid3) not ready | immediate fail-open forward of the OPERATE (no hold) |
| unsupported function / size | immediate bypass |
| profile missing for the flow | immediate bypass |
| concurrent transaction (already OP_REQUEST_HELD) | bypass + count |
| wrong flow / not the protected session | bypass |
| missing SELECT (OPERATE with no prior SELECT) | bypass + count |
| failed SELECT | qid3 watchdog retires; no output change |
| OPERATE never arrives | qid3 watchdog retires; no output change |
| exact TCP retransmit while OPERATE is held | recognize the same TCP seq; **must not** cause a second release / second physical operation |
| deadline / budget exhaustion | release the original (fail toward delivery, never drop) |
| FIN / RST | release or retire safely, transaction torn down once |

## 7. Delay selector

The compile probe exposes a **bounded codebook interface** (a control-plane table of admissible delays,
e.g. `J ∈ {0,2,4,6,8,10,12} ms`, with per-profile probabilities). The eventual selector uses a
**leak-safe** source — a Tofino random extern if it places, else low hardware-timestamp bits plus a
secret startup salt. It must **never** derive `J` from public DNP3 application-sequence values (an
observer would learn and subtract the mapping). For the single-SEL MVP, flow ownership keys the profile;
later a fixed G12V1 parse can key on the real CROB index + control code.

## 8. What the compile probe answers (and what it does not)

The probe reports, from bf-p4c 9.13.1 vs the proven RRC binary: fit / no-fit on one TF1; ingress+egress
stages; PHV allocation; table/SALU/register delta; pktgen app/batch delta; TM queue config; and, if it
does not fit, the **first placement failure and the minimum responsible feature**. Because the proven
ingress is already 12/12, no-fit is a legitimate, informative outcome.

NOT in scope for the probe: the physical divergence floor (needs real per-device operation-time
distributions from an authorized physical campaign — synthetic distributions validate the *math* only),
any switch load, and any physical OPERATE.

## 9. Threat-model boundary

BOR shapes `J + T_physical` for a **passive observer upstream of the switch** (WAN-side; the switch is
at the outstation edge). A downstream, in-substation observer that sees the *released* OPERATE measures
`T_physical` directly (the `J` cancels) — out of scope, same boundary as RRC, and stated explicitly.
