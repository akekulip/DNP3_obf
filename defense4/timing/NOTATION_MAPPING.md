# Notation mapping: the paper's convention, the code, and the archived evidence

Written 2026-09-08 for the post-meeting revision and rewritten 2026-09-09 after the follow-up
corrections. Two symbols changed meaning between the code and the paper, so this file exists to
make the difference explicit before any equation, figure caption, or configuration field is read.

**Nothing in `implementation/`, in the archived captures, or in the frozen CSV headers is
renamed.** Those record what ran. Only the paper's prose, equations, and figure labels adopt the
convention below, and this file is the bridge.

## 0. What changed on 2026-09-09

| symbol | earlier revision | now |
|---|---|---|
| `CLRT_target` | the configured acknowledgment-to-response gap | **withdrawn.** That quantity is now the *configured* `CLRT_new` |
| `D_R` | the RESPONSE hold, `e_R - t_R` | **the response latency,** `m_R - t_R`. The hold keeps no symbol and is written from its endpoints |

There is no `X`, `Y`, or `C` for any of these quantities anywhere in the manuscript.

## 1. Timeline endpoints

All are defined at one observation boundary. Naming an endpoint here is not a claim that it was
captured; the right-hand column says which were actually observed.

| Symbol | Event | Observed in `campaign_v1`? |
|---|---|---|
| `m_0` | the request leaves the master host NIC | **yes**, `t_req` |
| `t_0` | the request arrives at the switch | no, switch-side |
| `t_A` | the outstation's transport acknowledgment arrives at the switch | no, switch-side |
| `t_R` | the outstation's application response arrives at the switch | no, switch-side |
| `e_A` | the acknowledgment leaves the switch toward the master | no, switch-side |
| `e_R` | the response leaves the switch toward the master | no, switch-side |
| `m_A` | the acknowledgment arrives at the master host NIC | **yes**, `t_ack` |
| `m_R` | the response arrives at the master host NIC | **yes**, `t_resp` |

The evaluated CLRT is `m_R - m_A`, measured on the master-facing link. It equals `e_R - e_A`
plus the differential path and capture delay between the two packets, which was not measured.

## 2. The quantities, in the paper's convention

| Paper symbol | Definition by endpoints | What constrains it |
|---|---|---|
| `CLRT_original` | `t_R - t_A`, the outstation's own acknowledgment-to-response interval | the device; not chosen by us |
| `CLRT_new` | `e_R - e_A`, the acknowledgment-to-response interval after obfuscation | the obfuscation objective |
| `D_A` | `e_A - t_A`, the **ACK hold** | transport feedback and retransmission timing |
| response hold | `e_R - t_R`; **no symbol of its own** | not chosen; implied by the schedule |
| `D_R` | `m_R - t_R`, the **response latency** | the operation, through whatever latency requirement the deployment carries |

`CLRT_new` is used with one of two adjectives and never bare where the distinction matters:

* **configured `CLRT_new`** — the policy value installed in the switch. In `campaign_v1` this is
  4 ms, and it is the field named `D_R_ms`.
* **measured `CLRT_new`** — what the master records, `m_R - m_A`, in the Obfuscated arm.

Identity, from the definitions alone:

    CLRT_new = e_R - e_A = CLRT_original + (e_R - t_R) - D_A

For ideal constant replacement the switch releases at

    e_A = t_A + D_A,    e_R = t_A + D_A + CLRT_new       (CLRT_new configured)

so the response hold that results is

    e_R - t_R = D_A + CLRT_new - CLRT_original

**These are coupled, not three independent constants.** Once `CLRT_original`, `D_A` and the
configured `CLRT_new` are fixed, the response hold follows. A constant pair of holds would leave
`CLRT_original`'s variation in place; replacement requires the response hold to vary with arrival
time.

Ideal replacement also has a domain of validity: the response must exist before its scheduled
release,

    t_R <= t_A + D_A + CLRT_new

The acknowledgment may leave before the response arrives while this still holds. That event order
alone does not imply packet loss.

### `D_R` is the response latency, not the hold and not the configured gap

`D_R = m_R - t_R` is the latency of the response itself on its way to the master. Its start event
is the response's arrival at the switch from the outstation and its end event is the response's
arrival at the master host NIC. The outstation's own emission lies one hop earlier and was never
captured, so `D_R` as defined omits that hop.

Three terms compose it:

1. **baseline path latency** — what the response would have cost with the mechanism disabled:
   switch forwarding plus propagation to the master;
2. **switch holding** — `e_R - t_R`, which the schedule above fixes when the response is early
   and which is nothing when the response is late and is forwarded on arrival;
3. **blocker draining** — the interval between the response's release deadline expiring and the
   packet actually leaving, because the program stops blocking a queued packet only once the
   blocker queue gating it has drained. This term is **not measured** on the loaded program; see
   §4 and `audit_current/RELEASE_MEASUREMENT_STATUS.md`.

`D_R` is not `e_R - t_R`, and it is not the configured `CLRT_new`. The constraint on `D_R` is
operational — how long the answer may take — and is distinct from the transport constraint on
`D_A`, which exists because the master's retransmission timer runs on the acknowledgment. No
numeric response-latency requirement for a DNP3 poll or a select-before-operate control on a
distribution relay could be verified from primary documentation; the only verified numeric
deadline on the evaluated relay is its own select-to-operate timeout, documented default 1.0 s,
which governs how long a select stays armed rather than how quickly a response must return.

## 3. The collision: the field named `D_R_ms`

| | meaning | value in `campaign_v1` |
|---|---|---|
| Paper | `D_R`, the response latency `m_R - t_R` | per transaction; not directly observed |
| Code and archived evidence, field `D_R_ms` | the configured acknowledgment-to-response gap | 4 ms, constant |

So **the code's `D_R_ms` maps to the paper's configured `CLRT_new`**, and the paper's `D_R` has no
archived counterpart of its own.

| Code / evidence field | Where | Paper meaning under this convention |
|---|---|---|
| `D_A_ms` = 20.0 | `repro/policy_config.json` | `D_A`, the ACK hold. Same meaning in both conventions. |
| `D_R_ms` = 4.0 | `repro/policy_config.json`, `sweep/sweep_points.csv` | **the configured `CLRT_new`**, not `D_R` and not the response hold |
| `scheduled_release_interval_ms` = 4.0 | `repro/policy_config.json` | the configured `CLRT_new`, the same quantity under a second name |
| `release_budget_D_ms` = 24.0 | `repro/policy_config.json` | `D = D_A + CLRT_new`, the schedulability budget |
| `d_ticks` | `defense4_rrc_bor_unified12.p4:2369` | `D_A` in 256 ns ticks |
| `da_dr` | `defense4_rrc_bor_unified12.p4:2369` | `D_A + CLRT_new` in ticks, precomputed so one MAU addition arms the response deadline |
| `reg_deadline` | `defense4_rrc_bor_unified12.p4` | the ACK release deadline `t_A + D_A` |
| `reg_tresp` | `defense4_rrc_bor_unified12.p4:1706` | the response release deadline `t_A + D_A + CLRT_new` |
| `clrt_ms` | `derived/transactions.csv` | measured `m_R - m_A`: `CLRT_original` in the Timing OFF arm, `CLRT_new` in the Obfuscated arm |
| `ack_ms` | `derived/transactions.csv` | measured request-to-acknowledgment latency, `m_A - m_0` |
| `rt_ms` / `resp_ms` | `derived/transactions.csv` | measured request-to-response latency, `m_R - m_0`. **Not** `D_R`, which starts at `t_R` |
| `CLRT_new_configured`, `response_hold_eR_minus_tR`, `CLRT_new_measured` | `figures/model/fig_m01_release_timeline_data.csv` | the drawn schematic values, already in this convention |
| `A_ms`, `R_ms`, `J` | control lane, retired tree | request-anchored OPERATE quantities; see §5 |

Figure-data CSVs generated before 2026-09-09 carry the older row names `CLRT_target` and
`D_R_response_hold` for the last group above. They are regenerated, not edited in place.

## 4. Scheduled release is not actual release

`defense4_rrc_bor_unified12.p4:1706` arms the response deadline as `t_A + da_dr`, at the same
`now_word` as the acknowledgment deadline. Both deadlines therefore hang off one instant, the
acknowledgment's arrival.

The implementation does **not** start a response timer at the measured acknowledgment departure.
`e_R = e_A + CLRT_new` is the ideal relation implied by the two deadlines, not evidence that the
hardware uses `e_A` as its anchor. Actual release trails the deadline by the blocker-queue drain
interval, which the preserved evidence does not measure; see
`audit_current/INSTRUMENTATION_AUDIT.md` and `audit_current/RELEASE_MEASUREMENT_STATUS.md`.

Because both deadlines share the same instant, the measured CLRT carries the **net** residual, the
response release delay minus the acknowledgment release delay, plus differential path and capture
effects. It is a signed net quantity, not a single non-negative queueing delay, and it is not a
measurement of the drain interval.

## 5. The control lane keeps its own convention

READ and SELECT use the acknowledgment-arrival reference above. OPERATE is request-anchored and
keeps the established `A`, `R`, and `J` quantities of the implementation; its master-visible
observable is `R - A`. Do not apply the read-lane model to the whole select-before-operate
exchange without deriving the mapping. `J` is a configured codebook `{2, 6, 12}` ms; the
per-transaction draw was never observed.

## 6. Terms to use in prose

Write **`CLRT_original`** and **`CLRT_new`**, typeset `\mathrm{CLRT}_{\mathrm{original}}` and
`\mathrm{CLRT}_{\mathrm{new}}`. Say **configured `CLRT_new`** for the policy value and **measured
`CLRT_new`** for what the master records. Say **ACK hold** for `D_A` and **response hold** for
`e_R - t_R`, which has no symbol. Say **response latency** for `D_R`. Do not write *target*,
*target CLRT*, or `CLRT_target`; do not introduce `X`, `Y`, or `C` for any of these quantities;
and do not use `D_R` for the configured gap or for the hold.
