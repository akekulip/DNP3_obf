# Defense 4 — timing specification (Gate 1)

The unified timing core. One P4 program (`timing/p4/defense4_timing.p4`) with selectable modes. Grounded
in the frozen D1/D2/D3/Part-11/Part-12/four-queue sources (`EVIDENCE_BASELINE.md`).

## 1. Mode truth table

Mode is selected per transaction from a params table (control plane). Delays are **never summed across
one packet**; a packet carries at most one deadline.

| Mode | ACK behavior | RESPONSE behavior |
|---|---|---|
| `OFF` | immediate | immediate |
| `D1_EVENT` | hold until the matching RESPONSE is observed | release only after ACK commitment |
| `D2_RESPONSE_DEADLINE` | immediate | hold until the ACK-relative response deadline |
| `D3_ACK_DEADLINE` | hold until the ACK deadline | release after ACK commitment |
| `D4_DUAL_DEADLINE` | hold until the ACK deadline | hold until its independent response deadline **and** after ACK commitment |
| `FAIL_OPEN` | bounded release | bounded release |

## 2. Deadline equations

```
t_A     = native ACK arrival at the switch
t_R     = native RESPONSE arrival at the switch
D_A     = ACK hold offset      (params)
D_R     = RESPONSE hold offset (params)
T_A     = t_A + D_A            (ACK deadline)
T_RESP  = T_A + D_R            (RESPONSE deadline — the PRIMARY combined construction)
```

**Why `T_RESP = T_A + D_R` is the primary construction:** it is computable when the native ACK arrives
(a single arm event), and it reproduces both deadline modes **without a second deadline-arm event** at
ACK-release. Verified against the frozen sources this gate:

| setting | recovers | frozen check |
|---|---|---|
| `D_A = 0, D_R > 0` | **Defense 2** — `T_RESP = t_A + D_R = t_ack + G` | D2 deadline is `t_ack + G` (`research/ibspg_hold_response/…/ibspg_hold_response.p4` L13; Part-12 200/200 releases, commit `f00a5fd`) |
| `D_A > 0, D_R = 0` | **Defense 3** — `T_RESP = T_A = t_ACK + D`, RESPONSE released after ACK commitment | D3 deadline is `t_ACK + D` (`defense3/p4/case_a_defense3.p4` `dl_cand = now_word + D`, `D_DEFAULT_TICKS`) |
| `D_A > 0, D_R > 0` | combined shaping (normalized ACK schedule + normalized ACK→RESPONSE interval) | superset of the above |
| event mode | **Defense 1** — event-release, NOT a deadline sum (`research/tofino_dcrn_feasibility/…/dcrn_defense1_hardened_dp9_dp11.p4`; ordering `research/ibspg_paired/`) | |

**Decision (recorded):** adopt `T_RESP = T_A + D_R` as the primary combined construction. **If Tofino
dependency placement refutes it** (the arm cannot be computed in the available stage/PHV budget), test
**only** the bounded alternative `T_RESP = t_ACK_commit + D_R` (arm the response deadline at ACK
commitment). Do **not** reopen READ-relative grids, tunnels, fillers, or size work.

## 3. RESPONSE release predicate

A held RESPONSE is released only when ALL hold:

```
matching_generation           (this RESPONSE belongs to the active transaction's internal generation)
AND response_present          (the real RESPONSE is queue-resident, not synthesized)
AND ack_committed_to_master   (the ACK returned from loopback and was assigned to the master-facing FIFO)
AND deadline_or_event_condition   (now >= T_RESP  for the deadline modes, or the D1 event, or FAIL_OPEN budget)
```

`ack_committed_to_master` is the strict commitment defined in `ARCHITECTURE.md` — ACK arrival or blocker
expiry alone is insufficient.

## 4. Effective output model (characterize tails; do NOT claim exact wire timestamps)

```
t_ACK,out   ≈ max(t_A, T_A) + release_error_A
t_RESP,out  ≈ max( t_R, T_RESP, t_ACK,commit + ordering_gap ) + release_error_R
```

`release_error_A`, `release_error_R`, and `ordering_gap` are the reservoir/loopback release tails — they
are **characterized** by the Gate-3 synthetic tests and the hardware campaign, not asserted. Prior
mechanisms measured release tails at the ~µs scale (Part-12; D3 report); the Defense-4 tails are
re-measured for this program.

## 5. ACK-bearing RESPONSE (combined-response case)

Some outstations piggyback the TCP ACK on the RESPONSE (no separate ACK packet). For such a transaction:

- classify it as a **combined-response** case;
- **bypass `Q_ACK_HOLD`** (there is no separate ACK to hold);
- hold or release the **existing** RESPONSE per its response policy (D2/D4 deadline, D1 event, or OFF);
- **never fabricate an ACK**;
- **CLRT (ACK→RESPONSE interval) is undefined** for this case and is not reported.

## 6. Transaction state machine (one active transaction per scheduler domain)

States: `IDLE → ARMED(ACK deadline) → ACK_COMMITTED → RESP_RELEASED → RETIRED`, with fail-open and
cleanup edges. Keyed by a **canonical bidirectional flow identity** + an **internal per-transaction
generation** (not DNP3 app-seq). Transitions:

| from | trigger | to | action |
|---|---|---|---|
| IDLE | eligible request (pure-ACK-arming READ/SELECT/OPERATE per mode) matched by flow+seq+ack+port | ARMED | new generation; arm `T_A`; seed BOTH blocker reservoirs |
| IDLE | concurrent second eligible txn while one is active | (unchanged) | **fail open** the concurrent one; do NOT overwrite active state |
| ARMED | ACK returns from loopback → assigned to master FIFO | ACK_COMMITTED | set `ack_committed_to_master`; (D3/D4) arm/keep `T_RESP` |
| ACK_COMMITTED | RESPONSE release predicate (§3) holds | RESP_RELEASED | release the queue-resident RESPONSE |
| RESP_RELEASED | — | RETIRED | retire generation; free reservoirs/slot; ready for reuse |
| any | FIN / RST | RETIRED | cleanup (see §7) |
| any | budget/watchdog expiry | RETIRED | fail-open bounded release + cleanup |

## 7. Failure + cleanup table

| condition | handling |
|---|---|
| stale generation (a token/packet from a retired generation) | reject; never actuate held state |
| missing ACK (never commits) | bounded transaction watchdog → fail-open release of any held RESPONSE + retire |
| missing RESPONSE (never arrives) | ACK released on its deadline; watchdog retires the transaction |
| blocker-budget expiry | bounded fail-open release of the held packet; retire; token dies (no external escape) |
| duplicate / retransmitted ACK or RESPONSE | idempotent — bind to the existing generation, never open a new one or double-hold |
| FIN / RST | retire the generation, free reservoirs + slot, drop in-flight tokens |
| concurrent protected transaction | fail open (unshaped), do not overwrite the active transaction |
| collision on the flow-identity hash | detect (stored fingerprint mismatch) → fail open, do not corrupt another flow's state |

## 8. Source-to-mechanism provenance

| mechanism | frozen source (cite in place) |
|---|---|
| event-governed ACK hold (D1) | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1_hardened_dp9_dp11.p4` |
| ACK-before-RESPONSE ordering (3-level strict priority) | `research/ibspg_paired/` (Part 11) |
| queue-resident RESPONSE deadline `t_ack+G` (D2) | `research/ibspg_hold_response/` (Part 12, 200/200, commit `f00a5fd`) |
| predetermined ACK deadline `t_ACK+D` (D3) | `defense3/p4/case_a_defense3.p4` |
| four-level strict-priority behaviour | `research/case_a_read_anchored_dual_release/reports/FOUR_QUEUE_ORACLE_CLOSED.md` (commit `6ffd5e5`) |

The deleted MB-1 programs are historical compile probes only — none is copied wholesale or renamed.

## 9. Claim boundary (exact)

- This spec + a successful **compile** + **synthetic** validation prove **resource feasibility and
  logical correctness** of the unified timing core on Tofino-1 — **not** silicon behaviour, **not**
  physical-relay timing, **not** complete Defense 4.
- The four-queue oracle proves finite-backlog **priority ordering** only — it does **not** prove
  dual-reservoir readiness, recirculation continuity, deadline correctness, or DNP3 transaction
  correctness. Those are established (offline) by Gate 3 and (on silicon) only by the authorized
  hardware phase.
- No exact wire-timestamp claim; release tails are characterized, not asserted.
- **Complete Defense 4 is NOT demonstrated.**
