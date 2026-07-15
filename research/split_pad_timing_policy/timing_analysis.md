# Timing Analysis — Which Signals Leak, and the Recommended Policy

_Synthesis of Agent C (traffic analysis), Agent B (transport budgets), and the prior timing study
(`research/ack_timing_normalization/`), 2026-07-13. Timing is the one axis a byte-preserving defense
can close now — but only against the right attacker, and only for the timing leak (not the size
leak that shares the same secret). Evidence tags as elsewhere._

## 1. Which timing signals leak [M][P]
| Signal | Leaks | Evidence |
|---|---|---|
| Request→ACK-bearing-response delay | CROB count / request complexity **[M, this device, n=1/N]**; device/stack class **[P/I — not measurable on one device]** | [M] SELECT/OPERATE 0.179/0.214 ms/CROB, R²≈0.99 (n=1/N); baseline 1.014 ms. The *device-class discrimination* is an inference from Formby CLRT [P], not measured here (one software stack only) |
| Piggyback ratio | **[M]** 9/9 piggyback on this device; **[P/I]** the software-vs-embedded *discrimination* would need ≥2 stacks | [M] 9/9 piggyback (one device); discrimination unmeasured |
| Inter-fragment / CONFIRM→next-fragment gap | Regeneration/CPU behavior | [P] prior brief |
| Inter-chunk gaps (if split) | The split schedule itself (a NEW timing fingerprint) | [I] Agent B/C |
| Complete-transaction duration, SELECT→OPERATE interval | Aggregate processing; SBO behavior | [I] |
| Polling interval, silence duration | Operational state, events vs no-events | [I] Agent H |

**Critical cross-axis fact:** CROB count leaks on the **size** channel too (14.6 B/CROB, R²=0.9999),
*more cleanly* than on timing. So **timing normalization alone cannot hide CROB count** — an observer
reads it off response size. Timing normalization removes the *timing* leak; the *size* leak is a
separate residual (see `padding_analysis.md`).

## 2. Normalization vs jitter (the one positive result, attacker-scoped) [P][I]
Additive i.i.d. jitter is **averageable**: over n repeated polls the sample mean → T_class + μ with
error ∝ σ/√n, so a repeated-poll observer recovers the class (Crosby TISSEC 2009; Brumley–Boneh
2005). **Class-independent normalization is not** — averaging converges to the same target for every
class. Measurable prediction (Agent C/I): attacker AUC-vs-n **rises to 1 under jitter, stays flat at
0.5 under normalization**; the "averaging half-life" M½ is finite for jitter, unbounded for
normalization. The claim is **attacker-model-dependent** (a repeated-poll passive observer — the SCADA
case). Report **conditional** I(T;N|size), never marginal I(T;N), or the size channel inflates the
closure.

## 3. First-response vs inter-chunk timing
Two distinct targets: (a) the **first-response absolute deadline** — `release = max(ready,
request_time + target)` with a class-independent target — kills the request→response leak; (b)
**inter-chunk-gap normalization** — needed whenever splitting is used, so the chunk schedule doesn't
become a new fingerprint. For multi-fragment responses, schedule the **whole logical response to one
completion deadline** (never per-fragment independently), pace to it, and leave every CONFIRM verbatim.

## 4. RTO and operational budgets [S][V][I]
The binding constraint is the master's **effective TCP RTO**, not any DNP3 timer (5–60 s). ~200 ms is
the Linux `TCP_RTO_MIN` floor, **not universal — MEASURE it** (`sysctl net.ipv4.tcp_retries2`,
`ip route … rto_min`, observed request→first-retransmit). Mechanism-dependent (Agent B):
- **Timing-only hold** (hold the whole response) stresses the **master's request-RTO (Vision)**.
- **Split** ACKs the request on chunk 1, so it stresses the **outstation/replay-side tail-RTO
  (Hulk)** — measure both hosts.
The budget is **three separate inequalities** (Agent H), not one sum: initial-hold < RTO; each
inter-chunk/inter-fragment gap < RTO; cumulative added latency < the operational/poll deadline. The
measured 141×10 ms = 1.41 s split ran clean because the binding limit is the *max inter-ACK gap* and
*tail-ACK-wait < Hulk RTO*, not the sum. Overshoot any single inequality → spurious retransmit = the
loudest tell to observer and Zeek IDS alike.

## 5. When NOT to normalize timing (Agent H) [I]
Bypass when: the operation is operator-flagged critical; unsolicited/urgent; the delay budget is
insufficient; the target is already missed; queue occupancy exceeds the limit; ordering could be
violated; the transaction is unsupported; or the effective RTO margin is uncertain. Also skip when the
timing signal is already independent of the secret, or when normalization would create a stronger
artificial fingerprint (a lone shaped device is a beacon — shape fleet-wide + decoy-match). **Safety
dominates privacy; fail open** (= grid-fail-safe).

## 6. Recommended timing policy
A **class-independent bounded normalization** (P4/P6 family — uniform-within-budget or
size/complexity-decorrelation toward a common target) rather than a degenerate constant (which is
itself distinctive) or additive jitter (averageable). Apply to O→M **response** classes only, per an
operator criticality allowlist; leave CONFIRM and M→O frames untouched; watchdog = a fraction (≈0.5×)
of the **measured** RTO. Whether size/complexity-decorrelation (P6) beats jitter (P2) at lower latency
is a **pre-registered test**, not an assumption — and its advantage is partly eroded because a
non-averageable common target must exceed the worst native time. All of this is gated on **replicating
the n=1/N leak** first (evaluation_plan E1/E1′).

_Plain language: we can hide *when* the device answers by releasing every reply on a shared clock that
doesn't depend on the request — and unlike random jitter, a patient attacker can't average it away.
But hiding the timing doesn't hide the size, which leaks the same secret; that needs future padding.
Stay under the (measured) TCP retransmit timer, never delay a critical control, and don't be the only
device on the network that's obviously shaped._
