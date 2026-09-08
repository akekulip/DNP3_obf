# Notation mapping: Dr. Lin's convention, the code, and the archived evidence

Written 2026-09-08 for the post-meeting revision. The meeting changed what `D_R` means. The
same three letters now denote a different interval in the paper than in the code and in every
archived CSV, so this table exists to make the difference explicit before any equation, figure
caption, or configuration field is touched.

**Nothing in `implementation/`, in the archived captures, or in the frozen CSV headers is
renamed.** Those record what ran. Only the paper's prose, equations, and figure labels adopt the
new convention, and this file is the bridge.

## 1. Timeline endpoints

All four are defined at one observation boundary. Naming an endpoint here is not a claim that it
was captured; §3 says which were actually observed.

| Symbol | Event | Observed in `campaign_v1`? |
|---|---|---|
| `t_A` | the outstation's transport acknowledgment arrives at the switch | no, switch-side |
| `t_R` | the outstation's application response arrives at the switch | no, switch-side |
| `e_A` | the acknowledgment leaves the switch toward the master | no, switch-side |
| `e_R` | the response leaves the switch toward the master | no, switch-side |
| `m_A` | the acknowledgment arrives at the master host NIC | **yes**, `t_ack` |
| `m_R` | the response arrives at the master host NIC | **yes**, `t_resp` |

The evaluated CLRT is `m_R - m_A`, measured on the master-facing link. It equals `e_R - e_A`
plus the differential path and capture delay between the two packets, which was not measured.

## 2. The three design quantities, in the meeting's convention

| Paper symbol | Definition | What constrains it |
|---|---|---|
| `CLRT_original` | `t_R - t_A`, the outstation's own acknowledgment-to-response interval | the device; not chosen by us |
| `D_A` | `e_A - t_A`, the **ACK hold** | transport feedback and retransmission timing |
| `D_R` | `e_R - t_R`, the **RESPONSE hold** | the operation's latency requirement |
| `CLRT_target` | the configured acknowledgment-to-response gap the master should observe | the obfuscation objective |

Identity, from the definitions alone:

    CLRT_new = e_R - e_A = CLRT_original + D_R - D_A

For ideal constant replacement the switch releases at

    e_A = t_A + D_A,    e_R = t_A + D_A + CLRT_target

so the required RESPONSE hold is

    D_R = D_A + CLRT_target - CLRT_original

**These are coupled, not three independent constants.** Once `CLRT_original`, `D_A` and
`CLRT_target` are fixed, `D_R` follows. A constant pair of native-relative holds would leave
`CLRT_original`'s variation in place; replacement requires `D_R` to vary with arrival time.

Ideal replacement also has a domain of validity: the response must exist before its scheduled
release,

    t_R <= t_A + D_A + CLRT_target

The acknowledgment may leave before the native response arrives while this still holds. That
event order alone does not imply packet loss.

## 3. The collision: `D_R` means two different things

| | meaning | value in `campaign_v1` |
|---|---|---|
| Paper, meeting convention | RESPONSE hold, `e_R - t_R` | varies per transaction; not directly observed |
| Code and archived evidence | the configured target gap | 4 ms, constant |

So **the code's `D_R` maps to the paper's `CLRT_target`**, and the paper's `D_R` has no single
archived counterpart because it is a per-transaction quantity the switch never records.

| Code / evidence field | Where | Paper meaning under the new convention |
|---|---|---|
| `D_A_ms` = 20.0 | `repro/policy_config.json` | `D_A`, the ACK hold. Same meaning in both conventions. |
| `D_R_ms` = 4.0 | `repro/policy_config.json` | **`CLRT_target`**, not the RESPONSE hold |
| `scheduled_release_interval_ms` = 4.0 | `repro/policy_config.json` | `CLRT_target`, the same quantity under a second name |
| `release_budget_D_ms` = 24.0 | `repro/policy_config.json` | `D = D_A + CLRT_target`, the schedulability budget |
| `d_ticks` | `defense4_rrc_bor_unified12.p4:2369` | `D_A` in 256 ns ticks |
| `da_dr` | `defense4_rrc_bor_unified12.p4:2369` | `D_A + CLRT_target` in ticks, precomputed so one MAU addition arms the response deadline |
| `reg_deadline` | `defense4_rrc_bor_unified12.p4` | the ACK release deadline `t_A + D_A` |
| `reg_tresp` | `defense4_rrc_bor_unified12.p4:1706` | the response release deadline `t_A + D_A + CLRT_target` |
| `clrt_ms` | `derived/transactions.csv` | measured `m_R - m_A` |
| `ack_ms` | `derived/transactions.csv` | measured request-to-acknowledgment latency |
| `A_ms`, `R_ms`, `J` | control lane, retired tree | request-anchored OPERATE quantities; see §5 |

## 4. Scheduled release is not actual release

`defense4_rrc_bor_unified12.p4:1706` arms the response deadline as `t_A + da_dr`, at the same
`now_word` as the acknowledgment deadline. Both deadlines therefore hang off one anchor, the
native acknowledgment arrival.

The implementation does **not** start a response timer at the measured acknowledgment departure.
`e_R = e_A + CLRT_target` is the ideal relation implied by the two deadlines, not evidence that
the hardware uses `e_A` as its anchor. Actual release trails the deadline by a post-deadline
release delay that the preserved evidence does not measure; see
`audit_current/INSTRUMENTATION_AUDIT.md` and the release-measurement note.

Because both deadlines share the anchor, the measured CLRT carries the **net** residual, the
response release delay minus the acknowledgment release delay, plus differential path and
capture effects. It is a signed net quantity, not a single non-negative queueing delay.

## 5. The control lane keeps its own convention

READ and SELECT use the acknowledgment anchor above. OPERATE is request-anchored and keeps the
established `A`, `R`, and `J` quantities of the implementation; its master-visible observable is
`R - A`. Do not apply the read-lane model to the whole select-before-operate exchange without
deriving the mapping. `J` is a configured codebook `{2, 6, 12}` ms; the per-transaction draw was
never observed.

## 6. Terms to use in prose

Prefer **original CLRT**, **target CLRT**, and **measured CLRT**. Use *ACK hold* and *RESPONSE
hold* when the interval matters more than the symbol. Do not introduce a fresh symbol for a
quantity that already has one, and do not reuse `X` for a measured sample: Section 4 already
uses `X` for the outstation's own interval in the shifting comparison.
