# Timing definitions — unambiguous symbols (2026-09-02)

Every symbol used in the timing analysis and the manuscript, with its observation point and
whether it is a delay, an absolute deadline, or a difference of two deadlines. All quantities are
master-facing (observed at dp9) unless a different tap is named explicitly. No relay-facing or
physical quantity was measured in this study.

## Observation points

| symbol | meaning | tap |
|---|---|---|
| `t0` | request observed at the switch | master-facing (dp9) |
| `tA` | native TCP ACK arrival at the switch | master-facing |
| `tR` | native solicited DNP3 application response arrival at the switch | master-facing |
| `eA` | protected ACK egress toward the master | master-facing |
| `eR` | protected solicited response egress toward the master | master-facing |
| `tP` | verified physical breaker/contact transition | **not measured** |

## Derived intervals

| symbol | definition | meaning |
|---|---|---|
| `X = tR − tA` | native CLRT | the outstation's own cross-layer response time |
| `X' = eR − eA` | protected master-visible CLRT | the interval an observer records under the defense |
| `O = eR − eA` (OPERATE) | protected OPERATE response-to-ACK interval | control-lane observable; **replaces "ACK-to-echo"** |

## Configured constants — what each one is

| constant | value | kind | anchor |
|---|---|---|---|
| `D_A` | 20 ms | delay | from native ACK arrival `tA`; ACK released at `tA + D_A` |
| `D_R` | 4 ms | delay | post-ACK; response released at `tA + D_A + D_R` |
| `D = D_A + D_R` | 24 ms | horizon | response-release horizon **from `tA`** (read lane); coverage budget, not the added delay |
| `A` | 20 ms | absolute deadline | from OPERATE request arrival `t0`; ACK at `t0 + A` |
| `R` | 24 ms | absolute deadline | from `t0`; response at `t0 + R` |
| `J` | codebook {2, 6, 12} ms | internal delay | relay-facing release at `t0 + J`; **not observed** |

Read lane: `eA = tA + D_A`, `eR = tA + D_A + D_R`, so `X' = eR − eA = D_R = 4 ms`. Both egress
instants share the anchor `tA`; the native term `X` is absent. This is **deadline-based CLRT
replacement**, valid when `tR ≤ tA + D_A + D_R` (the response arrived before its release horizon).

Control lane: `eA = t0 + A`, `eR = t0 + R`, so `O = R − A = 4 ms`, with `J` absent from the
master-visible observable.

## Shift versus replacement — the formal distinction

Independent packet shifting: `eA = tA + dA`, `eR = tR + dR` ⇒ `X' = X + (dR − dA)`,
`Var(X') = Var(X)` apart from scheduling noise. A shift moves the location and preserves the
centered distribution and variance.

Common-anchor replacement (what the read lane does): both egress instants derive from `tA`, so
`X'` no longer contains `X`; the spread collapses to scheduling/measurement jitter. Established
empirically in `EVIDENCE_AUDIT.md §3` by the variance-ratio collapse against a counterfactual
shifted-native distribution that retains the native spread.

## Terminology corrections (spec §5), applied to active artifacts

| retired | correct |
|---|---|
| "echo" (as a DNP3 message) | solicited OPERATE application response |
| `echo_minus_ack` | `operate_response_minus_ack` |
| `request_to_echo` | `request_to_operate_response` |
| "master-visible OPERATE ACK-to-echo interval" | "master-visible OPERATE response-to-ACK interval" |
| SELECT timing as a "physical-operation fingerprint" | SELECT-phase protocol timing (function 3) |

DNP3 has no "echo" message. The first function-129 paired with an OPERATE is a solicited
application response; it may repeat the control object, but it is named the response, not an echo.
A successful OPERATE application response means the command was accepted/initiated/queued, not
that a breaker completed travel. Physical operation time (`tP`) begins at the actuating command
and ends at a verified state transition; it was not measured here.
