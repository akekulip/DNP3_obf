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
| `D_R` | the RESPONSE hold, `e_R - t_R` | **the response latency:** the response's whole journey, outstation transmission to master receipt, which is unmeasured here. The hold keeps no symbol and is written from its endpoints |

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
| `D_R` | the **response latency**: outstation transmission to master receipt, **unmeasured** | the operation, through whatever latency requirement the deployment carries |

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

**`D_R` is the response's whole journey, from the outstation to the master.** It starts when the
outstation transmits the response and ends when the response reaches the master host NIC, and the
range it may take is set by whatever latency the operation requires. That is the quantity a
deployment cares about, and it is the sense the notation carries.

**It is not measured here, and `m_R - t_R` is not it.** There is no recorded timestamp for the
outstation's transmission: the earliest observation of a response is `t_R`, its arrival at the
switch, one hop later. Everything between the outstation putting the response on the wire and
`t_R` — the outstation's own emission and the relay-facing link — is outside every capture in
this repository, because only the master-facing link was instrumented.

So three different intervals must be kept apart, and only the second is observed:

| | interval | status |
|---|---|---|
| the full response latency, `D_R` | outstation transmission to master receipt | **unmeasured** |
| the partial journey | `m_R - t_R`, switch arrival to master receipt | **not measured either:** `m_R` is captured, `t_R` is not |
| the switch's own contribution | `e_R - t_R`, the response hold | derived, see below |

`m_R - t_R` is a *modelled* partial journey and a lower bound on `D_R`. It is written from the
model's endpoints rather than from timestamps this repository holds, because `t_R` is the
response's arrival at the switch and no capture records it. Calling it measured, which an earlier
revision of this file did, overstates what exists. Reporting added latency, or a master-side CLRT,
as a measurement of `D_R` would assert a quantity no capture here contains.

Writing `o` for the instant the outstation puts the response on the wire, the identity is

    D_R = (t_R - o) + (e_R - t_R) + (m_R - e_R)

that is, the relay-facing hop, then the actual hold, then the path from the switch to the master.
The first term is not observed at all, which is the reason `D_R` is unmeasured; an earlier
revision omitted it and so defined `D_R` as something smaller than it is. A second earlier
revision listed the hold and a separate blocker-draining term side by side, which double-counts:
an actual departure already includes whatever post-deadline waiting preceded it, so the drain
cannot be added again beside it.

If the hold is to be broken down further, it decomposes **once**, into three disjoint intervals:

1. **scheduled waiting** — from the response's arrival `t_R` to its release deadline
   `t_A + D_A + CLRT_new`. This is nothing when the response is late and is forwarded on arrival;
2. **post-deadline blocking** — from that deadline to the last blocking action, because the
   program stops blocking a queued packet only once the blocker queue gating it has drained.
   This is the quantity written as epsilon. It is **not measured on the loaded program**, whose
   timestamp registers are never written. An instrumented build on 2026-09-15 measured the
   interval from the deadline to the last blocking action at 1,706 ns on the acknowledgment lane
   and 1,705 ns on the response lane, medians over twelve transactions, after decoding the armed
   marker in the deadline word; see
   `audit_current/epsilon_candidate/ATTRIBUTION_AND_DECODE_20260916.md`, which also records that
   the build's identity is now attributed. That interval ends at the last blocking action, and
   both of its timestamps are taken in ingress on a recirculating blocker token, so it is
   reported as an **internal blocker-termination interval** and is **not** claimed to bound
   epsilon in either direction: the blocker's last traffic-manager service precedes its return to
   ingress, and the ordering of the two endpoints has not been established. An earlier revision
   of this file called it a lower bound on epsilon; that claim is withdrawn. It characterizes the
   mechanism and not any exchange in `campaign_v1`;
3. **subsequent service** — from the end of blocking to the packet actually leaving.

The three sum to `e_R - t_R`. They are not additional to it.

`D_R` is not `e_R - t_R`, and it is not the configured `CLRT_new`. Nor are the three quantities
independently selectable: fixing `D_A` and the configured `CLRT_new` fixes the response hold
through `e_R - t_R = D_A + CLRT_new - CLRT_original`, which in turn consumes part of whatever
budget the application deadline allows for `D_R`. Choosing any two constrains the third. The
constraint on `D_R` is operational — how long the answer may take — and is distinct from the transport constraint on
`D_A`, which exists because the master's retransmission timer runs on the acknowledgment. No
numeric response-latency requirement for a DNP3 poll or a select-before-operate control on a
distribution relay could be verified from primary documentation; the only verified numeric
deadline on the evaluated relay is its own select-to-operate timeout, documented default 1.0 s,
which governs how long a select stays armed rather than how quickly a response must return.

## 3. The collision: the field named `D_R_ms`

| | meaning | value in `campaign_v1` |
|---|---|---|
| Paper | `D_R`, the response latency, outstation transmission to master receipt | per transaction; **unmeasured** |
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
