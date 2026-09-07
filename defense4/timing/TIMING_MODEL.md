# Timing model — symbols, observation points, and the mapping to the code

Every timing quantity used in this study, with the point at which it is observed, whether it
is a timestamp or a duration, and whether it was measured at all. Written so that no reader
has to infer which of two nearby quantities a number refers to.

This document supersedes nothing: it extends `audit_current/TIMING_DEFINITIONS.md` by
separating quantities that document merged, and it records the mapping to the names the code
actually uses. Where the code uses a different name, the name in the code governs the code and
the name here governs the prose. No variable and no CSV column was renamed.

---

## 1. There is one tap, and it is on the master host

Every capture in `evidence/campaign_v1/` was taken by `tcpdump` on the master host, on the
interface facing the switch:

```
tcpdump -i enp59s0f0np0 -s0 -w <capture>.pcap 'host 192.168.10.7 and tcp'
```

(`evidence/campaign_v1/_bin/campaign_block.sh`, line 23; the master is Vision, 192.168.10.1.)

The path is

```
master host ── switch (Tofino-1, dp9 master side / dp64 relay side) ── unmanaged switch ── SEL-751A
```

so the capture sees only the two directions of the master-facing link, as they arrive at and
leave the master's own network stack. It does not see the relay-facing link, the switch's
internal loopback ports, or the switch's own ingress and egress instants.

## 2. Symbols

Timestamps are instants; intervals are differences of two instants. The rightmost column is the
one that matters: three of these quantities were measured and the rest are model quantities
recovered from the program, not from the wire.

### Instants

| symbol | meaning | where it happens | observed? |
|---|---|---|---|
| `m_0` | the request leaves the master host | master NIC | **measured** |
| `t_0` | the request arrives at the switch | dp9 ingress | no |
| `t_a` | the relay's TCP acknowledgment of the request arrives at the switch | dp64 ingress | no |
| `t_r` | the relay's solicited application response arrives at the switch | dp64 ingress | no |
| `e_a` | the acknowledgment is emitted toward the master | dp9 egress | no |
| `e_r` | the response is emitted toward the master | dp9 egress | no |
| `m_a` | the acknowledgment arrives at the master host | master NIC | **measured** |
| `m_r` | the response arrives at the master host | master NIC | **measured** |
| `t_P` | a verified physical contact or breaker state transition | relay terminals | **not measured** |

`t_a` and `t_r` are events on the relay-facing side of the switch. A master-facing capture
cannot contain them. In the *Timing OFF* arm the master-facing observation is close to them,
because the switch forwards without holding, but "close" is not "equal" and the difference was
never quantified. In the *Obfuscated* arm they are hidden by construction: that is what the
mechanism does.

### Configured quantities

These are control-plane settings, installed before each block and recorded in
`evidence/campaign_v1/PROVENANCE_CONSTANTS.json`. They are configured values, not measured ones.

| symbol | campaign value | kind | anchored to |
|---|---|---|---|
| `D_A` | 20 ms | delay | `t_a`; the acknowledgment's release deadline is `t_a + D_A` |
| `D_R` | 4 ms | delay | the acknowledgment deadline; the response's deadline is `t_a + D_A + D_R` |
| `D = D_A + D_R` | 24 ms | horizon | `t_a`; the read lane's response-release horizon and coverage budget |
| `A` | 20 ms | absolute deadline | `t_0`; the OPERATE acknowledgment is due at `t_0 + A` |
| `R` | 24 ms | absolute deadline | `t_0`; the OPERATE response is due at `t_0 + R` |
| `J` | codebook {2, 6, 12} ms | internal delay | `t_0`; release toward the relay at `t_0 + J`, **never observed** |
| `H` | 30.8 ms | control-plane horizon | computed from the pass budget and reservoir depth, **not measured and not enforced by the data plane** |

`D` is a horizon, not an added delay. The delay the master actually pays is in §5.

### Intervals, with their exact endpoints

| symbol | definition | name in prose |
|---|---|---|
| `L_A` | `m_a - m_0` | request-to-acknowledgment latency |
| `C_observed` | `m_r - m_a` | the released interval; **this is what the paper calls CLRT** |
| `L_R` | `m_r - m_0` | request-to-response latency, the end-to-end cost |
| `X` | the relay's own `t_r - t_a` | native cross-layer response time, **inferred, never directly measured** |

By construction `L_R = L_A + C_observed`, and the reproduction asserts that identity on every
one of the 63,360 rows to within 1e-6 ms (`repro/validate_campaign.py`, "latency identity").

**The definition that matters.** The measurement the paper reports is

```
CLRT_master = m_r - m_a
```

taken between two frames in the same master-facing capture. It is *not* `e_r - e_a`, and it is
*not* `t_r - t_a`. Under *Timing OFF* it is the relay's own cross-layer response time plus the
switch's forwarding asymmetry; under the mechanism it is the released interval. Calling all
three "CLRT" is what made the shift-versus-replacement question hard to answer, so the three are
kept apart here.

## 3. What the master-facing capture cannot establish

Stated once, and relied on throughout the claim documents:

* switch ingress and egress instants (`t_0`, `t_a`, `t_r`, `e_a`, `e_r`);
* queue residence time of any packet inside the switch;
* the relay-facing release instant `t_0 + J`, and therefore the realized per-transaction `J`;
* release multiplicity toward the relay, and therefore exactly-once delivery;
* mechanical completion time, and any physical state transition `t_P`.

None of these fields is populated anywhere in the evidence. Where a document needs one, it says
so and stops.

## 4. Shifting versus replacement

### Independent per-packet shifting

If the acknowledgment and the response are each delayed by their own amount,

```
e_a = t_a + d_a          e_r = t_r + d_r
```

then

```
e_r - e_a = (t_r - t_a) + (d_r - d_a) = X + (d_r - d_a)
```

The native interval survives inside the output. If `d_r - d_a` is a constant `c`, the output
distribution is the native distribution translated by `c`: same shape, same spread,
`Var(X + c) = Var(X)`. If the delay difference is itself a random variable `Δ`, then

```
Var(X + Δ) = Var(X) + Var(Δ) + 2 Cov(X, Δ)
```

which can be larger or smaller than `Var(X)` depending on `Cov(X, Δ)`. Nothing here says that
shifting preserves variance in general; only that a **constant** shift does. A policy that
delays each packet by an independent random draw is still a shift in this sense and does not
replace anything.

### Common-anchor replacement

The read lane arms both deadlines from the one anchor `t_a`:

```
e_a,target = t_a + D_A                   e_r,target = t_a + D_A + D_R = e_a,target + D_R
```

so

```
e_r,target - e_a,target = D_R
```

and `X` has dropped out of the expression entirely. The output interval is a configured
constant rather than a transformed native quantity. The control lane does the same from `t_0`,
giving `e_r,target - e_a,target = R - A`, in which the internal hold `J` does not appear.

Verified in the program, not assumed: `reg_deadline` holds `t_a + D_A` and `reg_tresp` holds
`t_a + D_A + D_R`, each armed once as an absolute 32-bit timestamp
(`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`, lines 1676 to 1719 and
the comment at line 1705); the OPERATE path arms the same two registers with `t_0 + A` and
`t_0 + R` (line 3140).

### Where `t_r` enters, and why the target is not the emission

A deadline says when a packet *may* leave. It cannot conjure a packet that has not arrived. The
response can only be emitted once it exists and has been processed, so a faithful model of the
emission instant is

```
e_r = max(t_r + ε, e_r,target)
```

with `ε` the switch's own processing and serialization delay. When `t_r + ε ≤ e_r,target` the
deadline governs and the released interval is `D_R`. When the response arrives after its own
deadline the deadline is already past, and the program forwards the packet as soon as it arrives
rather than pinning it: the recovered source takes the `expired` branch to `to_fwd()`
(`audit_current/QUEUE_AND_ANCHOR_AUDIT.md` §3, item 5). Those transactions appear as the upper
tail, not as a hard cap. This `max(...)` form is an explanatory model of the observed behaviour;
it is not a line of the program, and it is labelled as a model wherever it is used.

Two further effects sit inside `ε` and are not separable in this evidence: the strict-priority
scheduler's own drain granularity, and the serialization of a 49-byte payload on a 1 Gb/s link.

### Is the response scheduled from the intended deadline or from the actual departure?

From the program, from the intended deadline: `reg_tresp` is an absolute timestamp armed once
from `t_a`, and it is never rewritten when the acknowledgment actually departs. The two
release instants are therefore siblings of a common anchor rather than a chain.

That distinction has an observable consequence, and the consequence was tested. If the
acknowledgment's own egress were delayed past `t_a + D_A` by queue contention while the
response's absolute deadline stood, the observed interval would *shrink* below `D_R`. It does
not: the smallest `C_observed` in 31,680 obfuscated exchanges is 3.922 ms, 78 µs under target,
and there is no left tail (`audit_current/outputs/timeout_and_tcp_audit.json`). On the 493
obfuscated READ exchanges whose `L_A` exceeds 25 ms, the median `C_observed` is still 4.000 ms
and `L_R` rises to 29.491 ms.

The reason is that a large `L_A` here reflects a late *anchor*, not a late egress: `t_a` itself
arrived late, both deadlines moved together, and the difference between them was untouched. That
is the common-anchor property doing exactly what the algebra says. The case that would shrink
the interval, contention delaying only the acknowledgment past its own deadline, is not
distinguishable from a late anchor in master-facing data and left no visible trace.

### What "replacement" is allowed to mean

**Replacement** here means: the measured timing feature follows the configured target with a
characterized residual error, over a stated operating envelope. For the campaign setting the
measurement is

| class | n | target | median error | 99th percentile absolute error | over 1 ms | worst |
|---|---|---|---|---|---|---|
| READ | 26,400 | 4.0 ms | −0.0001 ms | 0.031 ms | 24 | 53.182 ms |
| SELECT | 2,640 | 4.0 ms | +0.0002 ms | 0.031 ms | 1 | 1.150 ms |
| OPERATE | 2,640 | 4.0 ms | −0.0001 ms | 0.029 ms | 1 | 1.662 ms |

The envelope is the one measured by the 19-point sweep: the target is followed from `D_R` = 1 ms
to 22 ms at a fixed budget, and on the `D_A` ramp up to 30 ms, after which the envelope closes
and the released interval rises above target (`CLAIMS_AND_LIMITATIONS.md` C2).

Replacement does **not** mean, and is never used to mean, that mechanical operation time was
replaced. `t_P` was not measured.

### What reduced variance does and does not establish

A variance ratio of 0.058 (READ) and 0.0001 (SELECT) against a counterfactual shifted-native
distribution that retains the native standard deviation exactly is enough to reject a
constant-shift explanation under comparable conditions. It is not, on its own, evidence that the
output is independent of the native timing, that no leakage remains, or that the queues behaved
as designed. The independence question needs paired ingress and egress measurement, which this
evidence does not contain; the residual-leakage question is answered separately and negatively
in `CLAIMS_AND_LIMITATIONS.md` C6, where an adaptive attacker recovers to 0.651 balanced
accuracy from the acknowledgment interval.

## 5. The cost the master pays

The released interval moves from about 2.1 ms to 4.0 ms, a change of roughly 2 ms. That is not
the cost. The cost is the end-to-end latency `L_R`, which rises because the acknowledgment is
held for `D_A` before the response is released `D_R` later:

| class | Timing OFF median `L_R` | Obfuscated median `L_R` | added |
|---|---|---|---|
| READ | 2.680 ms | 25.337 ms | 22.657 ms |
| SELECT | 2.622 ms | 25.239 ms | 22.617 ms |
| OPERATE | 3.465 ms | 24.650 ms | 21.185 ms |

The mechanism also costs a little more than its configured offset. Subtracting the relay's own
acknowledgment latency on the acknowledgment-anchored read lane, and nothing on the
request-anchored control lane, the excess over the configured 20 ms is 0.781 ms for READ,
0.684 ms for SELECT and 0.650 ms for OPERATE, at the median. The released interval carries no
such excess, because the excess is common to both instants and cancels in the difference. That
cancellation is itself a signature of the common anchor.

## 6. Mapping to the names in the code

The code predates this vocabulary. Nothing was renamed; this is the dictionary.

| symbol here | program / control plane | extractor variable | published column |
|---|---|---|---|
| `t_a` | the anchor of `reg_deadline`, written as `reg_ta` in the source comments but not itself a register | — (not observable) | — |
| `t_a + D_A` | `reg_deadline` (read lane) | — | — |
| `t_a + D_A + D_R` | `reg_tresp`, comment "T_RESP = t_A + D_A + D_R" | — | — |
| `t_0 + A` | `reg_deadline` (control lane), `A_DEFAULT_TICKS` | — | — |
| `t_0 + R` | `reg_tresp` (control lane), `R_DEFAULT_TICKS` | — | — |
| `t_0 + J` | `reg_bor_topj`, `--j-set` | — | — |
| `m_0` | — | `Exchange.t_req`, `pend[0]` | `t_req` |
| `m_a` | — | `Exchange.t_ack`, `t_ack` | `t_ack` |
| `m_r` | — | `Exchange.t_resp` | `t_resp` |
| `L_A` | — | `ack_ms` | `ack_ms` |
| `C_observed` | — | `clrt_ms` | `clrt_ms` |
| `L_R` | — | `rt_ms` | `rt_ms` |
| `C_observed`, OPERATE | — | `echo_ack_ms` (retired tree only) | `echo_ack_ms` |

The last row is the one live mismatch. The retired `final_read_sbo` derived CSVs carry a column
literally named `echo_ack_ms`, and `analysis/dnp3_timing.py` and `analysis/extract_sbo.py` read
it. Those files reproduce a frozen dataset, so the column name is part of the frozen record and
is left alone. In prose the quantity is the **master-visible OPERATE response-to-acknowledgment
interval**. DNP3 has no message called an echo.

## 7. Terminology this study holds to

| do not write | write |
|---|---|
| "echo" as a DNP3 message | solicited OPERATE application response |
| "ACK-to-echo interval" | master-visible OPERATE response-to-acknowledgment interval |
| SBO, of a SELECT-only observation | the SELECT phase of select-before-operate, function 3 |
| SELECT timing as a physical-operation fingerprint | SELECT-phase protocol timing |
| "the response confirms the breaker operated" | the response reports the command was accepted |
| native / defended | Timing OFF / Obfuscated |
| CLRT, without saying which pair of instants | `C_observed = m_r - m_a`, master-facing |

READ is function 1, SELECT is function 3, OPERATE is function 4, and a solicited response is
function 129 (0x81). A TCP acknowledgment proves that the bytes were received by the peer's
transport, and nothing about DNP3 processing or physical operation. A successful OPERATE
application response means the command was accepted, initiated or queued; the CROB status octet
is 0 in all 5,280 SELECT and OPERATE exchanges of the campaign, and that is a protocol status,
not a contact position.

## 8. Provenance of the numbers in this document

Regenerated on 2026-09-07 from the raw captures by
`audit_current/tools/timeout_and_tcp_audit.py` (independent TCP parser, standard library only)
and by `evidence/campaign_v1/repro/reproduce.sh`, which completed with 0 validation problems,
131 passing tests and 0 publication-gate problems. Full output in
`audit_current/outputs/timeout_and_tcp_audit.json`.
