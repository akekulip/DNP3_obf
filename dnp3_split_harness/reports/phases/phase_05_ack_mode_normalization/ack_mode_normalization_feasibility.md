# Phase 05 — ACK-Mode Normalization Feasibility (separate→combined)

**Status: FEASIBILITY ANALYSIS — no implementation.** Follows the Phase-04 finding that egress
*timing* scheduling cannot conceal the categorical **ACK-mode** fingerprint. This study asks whether
that channel can be closed safely and byte-preservingly, and identifies the realizable mechanism.
`next_phase_allowed = false`. (Reprioritizes the plan's original Phase 05: the comprehensive
attacker evaluation was already done in Phase 04.)

_Scope label: gambit loopback, Linux 5.15.0-139; the effectiveness result is a trace-transformation
on the six real device PCAPs, not a defended-wire capture. Produced by the power-systems and
SDN/data-plane specialists, integrated + environment-verified by the lead._

## 1. Research question

Can a **no-synthesis** mechanism normalize the ACK **mode** (make a naturally separate-ACK device
look combined) safely, so the dominant categorical fingerprint (`ack_only` balanced accuracy 0.759)
is removed — and how much of the joint fingerprint does that actually close?

Preservation semantics (from `ack_control_feasibility.md` §3a): dropping/suppressing a pure ACK is
**DNP3-payload-preserving but NOT packet-presence-preserving** — it is the only no-synthesis route
to the combined look.

## 2. Effectiveness (trace-transformation; balanced accuracy, baseline: majority-class 0.400 / uniform 0.333)

Adding the ACK-mode transforms to the Phase-04 attacker eval (`ack_fingerprint_eval` scenarios
`suppress` = drop the pure ACK; `suppress_edt` = suppress + the Phase-4 EDT timing normalization):

| feature family | native | ebpf_edt (timing only) | **suppress** (mode only) | **suppress_edt** (mode+timing) | plus_ackmode (oracle) |
|---|---:|---:|---:|---:|---:|
| ACK structure | 0.759 | 0.666 | 0.482 | **0.334** | 0.333 |
| timing | 0.482 | 0.334 | 0.482 | **0.334** | 0.333 |
| size | 0.500 | 0.500 | 0.500 | 0.500 | 0.500 |
| all | 0.856 | 0.833 | 0.599 | **0.501** | 0.500 |

- **Suppression closes the ACK-mode channel** the timing normalization could not: `ack_only`
  0.759 → 0.482 (mode only) and the joint `all` 0.856 → 0.599.
- **Suppression + timing normalization reaches the counterfactual oracle** (`all` 0.501 ≈ the
  size-only floor 0.500). So the two Phase-04/05 primitives *together* remove the ACK-mode and
  timing channels; the remaining separability is **purely response size** (out of scope — needs a
  padding primitive that changes the transmitted representation, a separate research line).
- **Scope caveat (from the safety analysis).** This is a trace-transformation over the ack-mode /
  timing / size feature space; it does **not** cover static TCP-header fingerprints. **Verified**
  here: TTL (64), window (29200), MSS (1460), window-scale (7) are **identical across SEL-751 /
  AB1400 / ION7550**, so p0f-style static fingerprinting does not distinguish these devices — the
  eval's feature space is the relevant one. Two residuals the eval does not model remain: the
  **piggyback-ACK timing *distribution* shape** (SEL's ~11 ms natural response is *earlier* than a
  combined device's ~16 ms — normalization must delay *up* and match higher moments/jitter/tail, not
  just the mean) and possible **TCP-timestamp clock-skew** (Kohno-style; the `Traffic Trace` SYNs do
  carry timestamps — verify whether it separates the devices). So the honest claim is **"closes the
  ACK-mode channel,"** not "achieves device anonymity."

## 3. The safe design is not realizable as an egress *drop* — but is realizable as socket coalescing

The two specialist analyses resolve to a single conclusion:

- **Hold-then-decide (buffer the pure ACK, drop it only once the response is seen within a deadline
  < RTO, else release) is the *safe* design** (power-systems): the response's cumulative ACK is a
  strict superset of the pure ACK, a pure ACK is never retransmitted, so the only failure path is
  the master's RTO — which the response beats by a ~200 ms margin.
- **…but hold-then-decide is architecturally impossible as a tc-egress drop** (SDN): a tc program
  decides a packet's fate at one instant (`TC_ACT_OK` ± EDT stamp, or `TC_ACT_SHOT`); it **cannot
  cancel an skb already queued in `fq`** (no `struct_ops`/`bpf_qdisc` on 5.15 — verify), and the
  pure ACK egresses **before** the response, so "drop if the response already left" is never true at
  the decision instant. Holding the ACK and releasing it after the response yields a *delayed
  duplicate ACK* — a separate packet *plus* an anomaly — strictly worse.
- **The only realizable egress drop is immediate, prediction-driven `TC_ACT_SHOT`** gated on
  per-flow/per-device policy. It is **irreversible**, so it can only **fail open proactively**
  (decide not to drop unless confidence is high); a usually-prompt-but-occasionally-slow device
  strands the master for one RTO on the slow transaction — a loud fingerprint *and* an OT
  availability hit that no reactive fail-open can remove.

**Resolution — the safe hold-then-decide behaviour IS available, but at the socket, not the qdisc.**
Where the harness owns the responding socket (the split/replay/decoy server — which it does), the
combined-mode look is obtained with **zero irreversible drops** by **socket-side coalescing**: leave
`TCP_QUICKACK` off and write the response within the kernel's delayed-ACK window (~40 ms) so the
kernel **never emits a separate pure ACK** and the response naturally piggybacks it. This is
already **wire-demonstrated**: Phase-03A's matrix showed native / fixed-25 / bounded-20-30
full-delivery flows stay **COMBINED** for non-first requests (0/100 separate) — precisely because
the app wrote within the delayed-ACK window without forcing quickack. It is perfectly fail-safe (no
packet is ever removed; the kernel does normal TCP), byte-preserving, and needs no BPF.

## 4. Recommended mechanism (by deployment)

| Deployment | Mechanism | Safety |
|---|---|---|
| **Decoy / replay / honeypot we own** (primary) | **socket-side coalescing** (no quickack + response within the delayed-ACK window) | perfect fail-safety; no drops; already wire-demonstrated (Phase 03) |
| **Inline in front of a real device we don't own** (secondary) | egress **immediate predictive `TC_ACT_SHOT`** with proactive gating | irreversible; proactive fail-open only; irreducible slow-transaction residual |

For the inline-drop case the gating is mandatory (SDN): drop **only** the outstation→master
(`sport==20000`) pure ACK (payload_len==0, ACK set, not SYN/RST/FIN) of a **fresh benign READ**
request (function code recorded at request ingress); never the master's ACKs, controls, unsolicited,
dup-ACKs, window updates, or keepalives; **fail open on any miss/ambiguity**; disarm on an observed
master retransmit (in-band, since `bpf_timer` needs BTF maps and is incompatible with the prototype's
legacy `bpf_elf_map` loader — verify).

## 5. P4/Tofino portability (favorable — the inverse of the EDT problem)

A conditional **drop is Tofino-native and line-rate** (`mark_to_drop()`): no buffering, no timer, no
recirculation — unlike the Tofino-hostile EDT multi-ms hold. The decision (payload-length classify +
per-flow SALU registers for device-mode / last-function-code / freshness) ports directly; the
disarm-on-miss must be in-band (observe the master retransmit) or control-plane, not a timer. So
**suppression is the more portable half** of the obfuscation line. (Hand the TNA table/register spec
to `p4-dataplane-engineer` when that phase is authorized.)

## 6. Safety envelope (both mechanisms)

Deadline `D < RTO` (measured RTO ≈ 211 ms; use ~40 ms delayed-ACK-like, ≤ ~105 ms ceiling — recompute
on the real master). Never suppress controls / unsolicited / dup-ACKs / window updates / keepalives /
TCP control. Fail open (deliver the ACK / pass native) on any uncertainty; a dead-man that reverts to
transparent forwarding on mechanism failure, never a black-hole. Socket coalescing sidesteps the
irreversibility entirely; egress drop must carry all of the above.

## 7. Verify-flagged items (before any implementation)

- No queued-skb cancellation / `bpf_qdisc` on 5.15 (expected absent — underpins the "immediate-only"
  conclusion); `TC_ACT_SHOT` egress semantics (silent discard, no socket notification);
  `bpf_timer` arm-ability under the legacy loader (expected incompatible → use in-band disarm).
- Whether TCP timestamps separate the three devices by clock-skew (the SYNs carry TSval).
- The master's real RTO / `rto_min` (211 ms is this setup only).
- That the eval's `ack_only` keys on the request-ACK specifically (confirmed: `is_separate` = whether
  the first reverse packet after the request is a pure ACK — request-anchored).

## 8. Verdict and what comes next

**Feasibility: the ACK-mode channel can be closed.** The *effectiveness* is measured (suppression +
timing normalization reaches the size-only floor for these devices). The *safe, realizable*
mechanism for the harness's own decoy/replay servers is **socket-side coalescing** (no drops,
already wire-demonstrated); egress `TC_ACT_SHOT` suppression is realizable but irreversible and is
reserved for the true inline-real-device case. Response **size** remains the residual (separate
padding line; do not combine).

Recommended next phase (gated): a **socket-coalescing defended-wire demonstration + attacker eval**
on the owned replay/decoy server (turn quickack off, response within the delayed-ACK window; capture;
confirm `is_separate`→0 on the wire and re-run the classifier on the *defended capture*, not a
transform) — answering the safety expert's Q6 directly, with no BPF and no drops.

```
STOP: ACK-mode normalization is feasible; socket-coalescing is the safe realizable path. Awaiting authorization for the defended-wire demonstration.
```
