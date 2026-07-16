# Phase 04 — Separate ACK and Response Manipulation (Closeout)

**Status: CONDITIONAL PASS** — core mechanism complete and evaluated; the full original mode
matrix, combined-mode fail-open test, bridge deployment, and real-device validation are **not**
done and are deferred. `next_phase_allowed = false`.

_Scope label: gambit loopback, Linux kernel 5.15.0-139-generic, tested socket/eBPF configuration.
The attacker evaluation is a trace-transformation on the six real device PCAPs, not a defended-wire
capture. Deep detail in the sub-reports referenced below; this is the consolidation._

## 1. Research question

Can a **no-synthesis, byte-preserving** egress mechanism normalize the ACK and response *timing*
enough to reduce DNP3 **device fingerprinting**?

## 2. Mechanism

A tc-egress eBPF program (`ebpf_prototype/ack_edt.c`) with per-flow state:

- **request observation** — record each DNP3 request's arrival time, keyed by the master side
  (5-tuple; on the loopback prototype one egress program sees both directions — a real bridge/Tofino
  needs the ingress+egress split, `ack_control_feasibility.md` §8a);
- **per-flow state** — an LRU hash map (request arrival → target release times);
- **egress classification** — pure ACK (payload length 0) vs payload-bearing response;
- **EDT scheduling** — write `skb->tstamp` (earliest-departure-time); an `fq` root qdisc enforces it;
- **fail-open safety** — a reverse packet with no recorded request (unknown / combined-mode) is left
  native;
- **no packet synthesis, no DNP3 byte modification** — it only re-times packets that already exist.

## 3. Enforcement evidence (two independent demonstrations)

**netem control-point smoke test** (`netem_smoke_result.md`) — coarse proof that an **existing**
pure ACK can be held independently of the response: request→ACK 0.011 → **30.02 ms** while
request→response stayed ~50 ms (gap 50.45 → 20.31 ms), 40/40 held the `ack < response` invariant,
0 retransmissions/resets, 50/50 byte-identical. It also surfaced (and fixed) the flag-classifier
fragility that motivates payload-length classification.

**eBPF EDT primitive + full mechanism** (`edt_load_release_test.md`, `ebpf_prototype/ebpf_prototype_result.md`):
- **Load-and-release:** a loaded tc-egress BPF program set `skb->tstamp` and `fq` enforced it —
  ping RTT 0.024 → **60.069 ms** (independently corroborated non-sudo via `SO_TXTIME`, 30 ms hold).
- **Full mechanism:** `ack_edt.o` loaded + verifier-accepted (id 152, jited) and **independently
  pinned** the existing pure ACK to **20.047 ms** and the response to **40.355 ms** (gap 20.001 ms)
  per flow; 40/40 separate; **0 retransmissions / duplicate-ACKs / resets**; **50/50 byte-identical**.

## 4. Attacker evaluation (`attacker_eval.md`, statistically rigorous)

Random forest, **capture-level split (leakage-free: train base PCAPs, test L PCAPs)**, bootstrap
95% CIs, repeated stratified CV band (optimistic, noted), per-device precision/recall, confusion
matrices, fixed seed, paired bootstrap vs native. **Baseline = majority class 0.400** (uniform
3-class would be 0.333); classes are unequal, so **balanced accuracy is the headline metric**.

Balanced accuracy by feature family (native → ebpf_edt):

| family | native | ebpf_edt | ebpf_edt_aligned | plus_ackmode (oracle) |
|---|---:|---:|---:|---:|
| ACK structure | 0.759 | 0.666 | 0.666 | 0.333 |
| timing | 0.482 | 0.334 | 0.334 | 0.333 |
| response size | 0.500 | 0.500 | 0.500 | 0.500 |
| all | 0.856 | 0.833 | 0.833 | 0.500 |

`plus_ackmode` is a **counterfactual oracle** — it models what would remain if an ideal mechanism
removed the ACK-mode distinction; it is not byte/packet-preserving and is **not implemented** by
`ack_edt.o`.

## 5. Main result

**Egress scheduling removes timing leakage but cannot conceal the transport-structure (ACK-mode)
and response-size fingerprints.**

- **Timing collapses to baseline** (balanced 0.482 → 0.334), cleanly — no re-encoding of the mode
  into timing.
- **The ACK-mode channel is not closed** (`ack_only` balanced 0.759 → 0.666, far above baseline):
  `is_separate` — a separate-mode device still emits a distinct pure-ACK packet — is categorical and
  the mechanism cannot remove it.
- **The aligned-target ablation changes nothing** (`ebpf_edt_aligned` = `ebpf_edt` on every metric):
  the residual is the ACK-mode and size channels, **not** the choice of timing targets.
- **The small raw-accuracy rise (all 0.889 → 0.900, paired CI excludes 0) is a class-imbalance
  artifact** — balanced accuracy actually *falls* (0.856 → 0.833); normalizing the noisy native
  timing helps the majority classes at the minority's expense. The honest measure shows a modest
  decrease, nowhere near baseline.
- Even the oracle leaves **`all` at 0.500, not baseline**, because **response size still leaks** — so
  do not claim the fingerprint "collapses to the baseline."

## 6. Capability boundary

- **Timing is controllable** (request→ACK, request→response, gap — proven).
- **An existing separate ACK is controllable** (delay it independently — proven).
- **The *existence* of a separate ACK is not universally controllable** under the no-synthesis
  constraint: a combined ACK-bearing response cannot be split into an independent ACK without
  synthesis, TCP splitting, or endpoint (socket) control (§3a).
- **Response size is intentionally unchanged** (byte-preserving design).

## 7. Safety

Across the netem and eBPF runs: **no resets within established replay-client sessions** (the 10
RST/ACK per PCAP are pre-connection readiness probes, excluded); **0 retransmissions**; **0
duplicate-ACK anomalies**; **byte-identical** responses; **ordering** invariant `ack_release ≤
response_release` held in 40/40 transactions; imposed holds (≤ 40 ms) stayed well under the measured
**TCP RTO ≈ 211 ms**; the mechanism **fails open** for combined-mode / unrecorded flows. `fq`
enforced the departure times; nothing was forged or edited.

## 8. Limitations

- **Trace-transformation attacker evaluation**, not a defended-device capture.
- **Loopback / single-kernel** evidence for the mechanism; no two-host rig or physical NIC.
- **No real-device bridge run** (loopback single-egress simplification; ingress+egress bridge not built).
- **No ACK-mode normalization** (suppression) and **no size normalization** — the two residual channels.
- **Incomplete original mode matrix**: only the gap-normalization / independent-delay mode is
  demonstrated; native / ack-delay-only / response-delay-only / bounded-gap and configurable targets
  are not implemented as a full matrix.

## What should come next — ACK-mode normalization feasibility

The strongest remaining categorical leak is the ACK **mode**. The only **no-synthesis** route to
make a naturally separate device resemble a combined one is **separate→combined pure-ACK
suppression** — which is **DNP3-payload-preserving but not packet-presence-preserving** (§3a table).
It preserves the DNP3 bytes and can be studied independently of the much broader size-padding
problem (which changes the transmitted representation and is a separate research line — do not
combine them). A first suppression study should answer:

1. Can the standalone ACK be safely dropped when a later ACK-bearing response arrives within a
   bounded deadline?
2. What response-delay ceiling avoids request retransmission (relative to the master's RTO)?
3. Does the later response always acknowledge the complete request?
4. What happens when the response is absent, late, fragmented, or reset?
5. Can the mechanism fail open before the TCP RTO?
6. Does classifier accuracy actually fall after **defended-wire** suppression (not just a transform)?

## Verdict

**Core mechanism complete; timing channel normalized; full device anonymization not achieved because
the ACK mode and response size remain.** `next_phase_allowed = false`.

```
STOP: Phase 04 consolidated (CONDITIONAL PASS). ACK-mode-normalization feasibility is the recommended next phase; awaiting authorization.
```
