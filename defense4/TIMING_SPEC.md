# Defense 4 — timing specification (Gate 1, corrected 2026-08-05)

The unified timing core. One P4 program (`timing/p4/defense4_timing.p4`) with selectable modes. Grounded
in the frozen D1/D2/D3/Part-11/Part-12/four-queue sources (`EVIDENCE_BASELINE.md`).

## 1. Mode truth table

Mode is selected per transaction from a params table (control plane).

| Mode | ACK behavior | RESPONSE behavior |
|---|---|---|
| `OFF` | immediate | immediate |
| `D1_EVENT` | hold until the matching RESPONSE is observed | release only after ACK commitment |
| `D2_RESPONSE_DEADLINE` | immediate (via `Q_ACK_HOLD`, no active ACK blocker — §3) | hold until the ACK-relative response deadline |
| `D3_ACK_DEADLINE` | hold until the ACK deadline `T_A` | release after ACK commitment |
| `D4_DUAL_DEADLINE` | hold until the ACK deadline `T_A` | hold until its **separately parameterized successor deadline** `T_RESP` and after ACK commitment |
| `FAIL_OPEN` | bounded release | bounded release |

`FAIL_OPEN` is primarily a **safety transition and outcome**, not an ordinary configured timing policy; it
may remain externally triggerable only for testing.

## 2. Deadline equations

```
t_A     = native ACK arrival timestamp at the switch (does NOT exist until the ACK arrives)
t_R     = native RESPONSE arrival timestamp at the switch
D_A     = ACK hold offset      (params)
D_R     = successor interval   (params)
T_A     = t_A + D_A                        (the ACK's single absolute deadline)
T_RESP  = T_A + D_R = t_A + D_A + D_R       (the RESPONSE's single absolute deadline)
```

`D_A` and `D_R` **are mathematically combined** when computing the single RESPONSE deadline `T_RESP`;
they are not two serially-executed delays and not "never summed." The accurate distinction:

- The defense mechanisms are **not executed serially**. The ACK carries **one** absolute deadline `T_A`;
  the RESPONSE carries **one** absolute deadline `T_RESP`.
- **`D_A` positions the scheduled ACK.** **`D_R` specifies the target interval after that scheduled ACK.**
- `T_RESP` is a **separately parameterized successor deadline** — it depends on `T_A` (not "independent").
- **`D_A = 0` reproduces the Defense 2 release policy** (`T_RESP = t_A + D_R = t_ack + G`).
- **`D_R = 0` reproduces the Defense 3 release policy and ACK-before-RESPONSE ordering**
  (`T_RESP = T_A = t_ACK + D`, RESPONSE released after ACK commitment).
- This is **semantic policy equivalence**, **not** identical queue mechanics or identical release tails.

**Verified against the frozen sources** (`EVIDENCE_BASELINE.md`): D2 deadline is `t_ack + G`
(`research/ibspg_hold_response/…`, Part-12 200/200 @ `f00a5fd`); D3 deadline is `t_ACK + D`
(`defense3/p4/case_a_defense3.p4`). **Decision:** adopt `T_RESP = T_A + D_R` (computed at native ACK
arrival — a single arm). If Tofino dependency/PHV placement refutes it, use **only** the bounded
alternative `T_RESP = t_ACK_commit + D_R` and record it here. Do not reopen READ-relative grids, tunnels,
fillers, or size work.

## 3. Per-mode blocker-reservoir contract (both roles, every mode)

Two isolated blocker reservoirs — one starving `Q_ACK_HOLD`, one starving `Q_RESP_HOLD` — control release.
Both are seeded before the earliest eligible ACK can escape and must not develop a pre-deadline empty gap.

| Mode | ACK blocker | RESPONSE blocker |
|---|---|---|
| `OFF` | inactive | inactive |
| `D1_EVENT` | terminates on matching-RESPONSE observation | terminates only after ACK commitment **and** the event condition |
| `D2_RESPONSE_DEADLINE` | inactive | terminates when `now >= T_RESP` **and** ACK commitment holds |
| `D3_ACK_DEADLINE` | terminates at `T_A` | enforces ACK commitment before RESPONSE release |
| `D4_DUAL_DEADLINE` | terminates at `T_A` | terminates when `now >= T_RESP` **and** ACK commitment holds |
| fail-open transition | terminate safely | terminate safely |

**D2's "immediate" ACK still obtains an observable commitment:** the original ACK traverses `Q_ACK_HOLD`
with **no active ACK blocker**, then `ack_committed_to_master` is set when it **returns from the internal
loopback and is assigned to the master-facing output FIFO**. This carries the unavoidable **loopback
release tail** — it is not exact zero-delay forwarding, and the tail is reported (§5).

## 4. RESPONSE release predicate

A held RESPONSE is released only when ALL hold:

```
matching_generation           (belongs to the active transaction's internal generation)
AND response_present          (the real RESPONSE is queue-resident, not synthesized)
AND predecessor_satisfied     (see §6 — ACK commitment for separate-ACK; true only for the matching
                               combined-response packet itself)
AND deadline_or_event_condition   (now >= T_RESP for deadline modes; the D1 event; or the FAIL_OPEN budget)
```

`predecessor_satisfied` replaces a bare `ack_committed_to_master` so the predicate is not circular for the
ACK-bearing RESPONSE case (§6).

## 5. Effective output model (characterize the tails; do NOT claim exact wire timestamps)

```
t_ACK,out   ≈ max(t_A, T_A) + release_error_A       (release_error_A includes the loopback tail, incl. D2)
t_RESP,out  ≈ max( t_R, T_RESP, t_ACK,commit + ordering_gap ) + release_error_R
```

`release_error_A`, `release_error_R`, and `ordering_gap` are reservoir/loopback release tails, **measured**
by the hardware campaign, not asserted. Offline they are model-level.

## 6. Transaction state machine (the request does NOT arm `T_A`)

The native ACK timestamp does not exist at request time, so `T_A` cannot be computed on the request. Keyed
by a **canonical bidirectional flow identity** + an **internal per-transaction generation** (not DNP3
app-seq). ACK and RESPONSE may arrive in **either order**.

```
IDLE
  -> REQUEST_ARMED
  -> ACK_SEEN and/or RESP_SEEN   (either arrival order)
  -> ACK_COMMITTED
  -> RESP_RELEASED
  -> RETIRED
```

**On the eligible request** (REQUEST_ARMED): allocate the generation; record the canonical flow +
transaction expectations (expected TCP ACK number, expected relay sequence, master/relay ports, collision
fingerprint); **seed both blocker reservoirs**. **Do not calculate `T_A` yet.**

**On native ACK arrival** (ACK_SEEN → ACK_COMMITTED): validate the complete pure-ACK predicate (flow +
generation + expected ack + relay seq + port); **calculate `T_A = t_A + D_A` and `T_RESP = T_A + D_R`**;
apply one-shot admission; enqueue the original ACK (`Q_ACK_HOLD`) or release it through the defined
loopback path; ACK commitment = returned-from-loopback + assigned-to-master-FIFO.

**On matching RESPONSE arrival** (RESP_SEEN): validate the transaction + generation; set `response_present`;
enqueue the original RESPONSE **exactly once** (`Q_RESP_HOLD`); if mode is `D1_EVENT`, terminate the ACK
blocker; otherwise preserve the RESPONSE behind its blocker until ACK commitment.

**RESPONSE-before-ACK (explicit):** the original RESPONSE enters `Q_RESP_HOLD`; `response_present` is
recorded; in `D1_EVENT` its arrival opens the ACK gate; in the deadline modes the RESPONSE **remains held**
until the ACK arrives and establishes `T_A`/`T_RESP`; a missing ACK eventually invokes bounded fail-open.

**Concurrency:** one active protected transaction per scheduler domain; a concurrent eligible transaction
**fails open** (bounded release) **without overwriting** the active generation's state.

## 7. Failure + cleanup semantics (generation-qualified)

For **FIN, RST, watchdog expiry, collision, missing ACK, missing RESPONSE, or blocker-budget expiry**:

- **terminate BOTH blocker roles** for the affected generation;
- **forward any original held ACK or RESPONSE byte-identically** (never strand an original packet);
- kill stale internal tokens (no external token escape);
- **clear state only with generation qualification** — cleanup from an old generation must never clear a
  new transaction;
- duplicate/retransmitted ACK or RESPONSE bind idempotently to the existing generation.

This includes **asymmetric expiry**: the ACK blocker may expire while the RESPONSE blocker is still active,
and the reverse; both are handled safely (Gate-3 tests cover both directions).

## 8. Timestamp wrap safety

The deadline/watchdog comparisons use the frozen implementation's **modular difference on a 32-bit
timestamp** (Defense 3 / Part-12 arm `now_word + D`/`+ G` and compare via the sign bit of `now − deadline`,
mask `0x800000FF`). Requirements: every configured deadline and watchdog horizon must remain **below half
the 32-bit timestamp range** (< 2^31 ticks) so the sign-bit/modular-difference comparison is unambiguous;
the control plane clamps the configured horizon accordingly. Gate-3 tests exercise deadlines and watchdogs
**immediately before, across, and immediately after** a timestamp wrap.

## 9. Queue IDs vs scheduler priorities (two distinct properties)

```
role           qid        max_priority
Q_ACK_BLOCK     7            7
Q_ACK_HOLD      6            6
Q_RESP_BLOCK    5            5
Q_RESP_HOLD     4            4
```

The numbers coincide here, but **queue ID and `max_priority` are different configuration properties.** In
the closed four-queue oracle the causal ordering result came from reversing only `max_priority` while
keeping queue IDs fixed — the P4 queue assignment alone does **not** establish strict priority. The control
plane (`timing/control/defense4_timing_setup.py`) must **configure and read back `max_priority`** for each
queue.

## 10. ACK-bearing RESPONSE (combined-response case)

Some outstations piggyback the TCP ACK on the RESPONSE — no separate ACK packet. The universal predicate
`ack_committed_to_master AND …` would be **circular** here (there is no separate ACK to commit before the
combined packet leaves). Define:

```
predecessor_satisfied =
    ack_committed_to_master       for separate-ACK transactions
    true                          for the matching combined-response packet only
```

and use `predecessor_satisfied` in §4. For this case: classify it as combined-response; **bypass
`Q_ACK_HOLD`**; hold/release the existing RESPONSE per its response policy; **never fabricate an ACK**.

**Combined-response deadline (separate equation, not silently `T_RESP`):** the only anchor available on the
switch is the combined packet's own arrival, so if a protected hold is applied it is arrival-relative:

```
T_COMBINED = t_combined_arrival + D_combined
```

This adds a **controlled hold** but **does not create or normalize CLRT** — CLRT is **undefined** because
there is no separate ACK. Since the frozen evidence provides no separate-ACK anchor for this case,
**protected combined-response timing is labeled `PROPOSED`**: the safe default is fail-open/bypass (no
protected hold). Do not fabricate an ACK or claim D1/D2/D3 equivalence for the combined case.

## 11. Source-to-mechanism provenance

| mechanism | frozen source |
|---|---|
| event-governed ACK hold (D1) | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1_hardened_dp9_dp11.p4` |
| ACK-before-RESPONSE ordering (3-level strict priority) | `research/ibspg_paired/` (Part 11) |
| queue-resident RESPONSE deadline `t_ack+G` (D2) | `research/ibspg_hold_response/` (Part 12, 200/200, `f00a5fd`) |
| predetermined ACK deadline `t_ACK+D` (D3), modular-difference wrap comparison | `defense3/p4/case_a_defense3.p4` |
| four-level strict-priority behaviour | `research/case_a_read_anchored_dual_release/reports/FOUR_QUEUE_ORACLE_CLOSED.md` (`6ffd5e5`) |

The deleted MB-1 programs are historical compile probes only — none is copied wholesale or renamed.

## 12. Claim boundary (exact)

A successful **compile** + **offline synthetic tests** provide **offline compiler-fit evidence and
model-level functional evidence**. They do **NOT** prove complete logical correctness on Tofino-1 silicon.

**Only the authorized hardware phase** can establish: actual dual-reservoir readiness; absence of
pre-deadline empty gaps; Traffic Manager timing; external ACK-before-RESPONSE ordering; real release-tail
distributions; end-to-end DNP3 behaviour. The four-queue oracle proves finite-backlog **priority ordering**
only. **Complete Defense 4 is NOT demonstrated.**
