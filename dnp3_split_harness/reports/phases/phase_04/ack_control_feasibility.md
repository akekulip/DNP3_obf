# Phase 04 — ACK/Response Control: Mechanism-Feasibility Analysis

**Status: FEASIBILITY ANALYSIS — CONDITIONAL PASS; no implementation.** Per the plan
(`acj_delay2.md`, PHASE 04) this report must exist *before* implementation, and "do not proceed with
implementation until the feasibility report identifies a real enforcement mechanism." It identifies
one **for separate-mode traffic**, with a scoped capability boundary (§3a: combined-mode flows
cannot be split without synthesis) and one behavioural check still owed (§9: a minimal EDT
load-and-release test). Implementation is **not** started and requires explicit human authorization.
`next_phase_allowed = false`. (Reviewed 2026-07-16: mechanism-feasibility = CONDITIONAL PASS; netem
smoke test = PASS; full eBPF implementation = not approved.)

_Scope label: grounded in the measured Phase 01–03 results (gambit loopback, Linux kernel
5.15.0-139-generic, tested socket configuration). Data-plane target is P4/Intel Tofino 1 on the
Hulk/Vision testbed. Analysis produced by the SDN/data-plane and power-systems specialists and
integrated + environment-verified by the lead._

## 1. Objective

Evaluate whether an existing pure TCP ACK and the later DNP3 response can be delayed
**independently and safely**, without forging any packet (no ACK synthesis) and without changing
DNP3 bytes, and identify a real enforcement mechanism and its P4-readiness.

## 2. Environment (verified this session)

- Kernel `5.15.0-139-generic`; `tc` = iproute2 **ss200127** (Jan-2020 build).
- Qdiscs/classifiers present as modules: `sch_netem`, `sch_fq` (verified `sch_fq.ko` present),
  `cls_u32`, `cls_bpf`, `cls_flower`, `act_bpf`. BPF syscall + JIT compiled in; `clang` + libbpf
  headers present; **`bpftool` is NOT installed** (a gap for eBPF prototyping).
- **Verified favorably** (the SDN analysis flagged these as "verify"): `tc flower` **does** support
  `tcp_flags MASKED-TCP_FLAGS` on this build; `sch_fq` is present (EDT release path available);
  `bpf_timer` symbols are present in the kernel BTF (`/sys/kernel/btf/vmlinux`); `__sk_buff.tstamp`
  exists in the UAPI `bpf.h`. So the eBPF + tc-egress EDT mechanism is supported on this host.
- `timing_policy.plan_ack_response_release()` already computes ACK/response release times for all
  six required modes with the `ack_release ≤ response_release` invariant and clamping — but it is a
  **pure planner, unwired** (it enforces nothing on the wire). Phase 04 is about whether those
  release times can be *enforced*.

## 3. The nine feasibility questions

**Q1. Can the application delay the response?** **Yes (measured).** The response is
application-generated, so user space owns the `write()` moment; a fixed/bounded scheduler pins
request→response to ~25 ms. It is a forward-only delay on the whole response object (never earlier
than ready; no byte/segmentation change). This is the one primitive that already works end-to-end.

**Q2. Can the application delay a kernel ACK after emission?** **No — precisely.** The pure ACK is
built by the kernel TCP state machine (`__tcp_ack_snd_check` → `tcp_send_ack` → `tcp_transmit_skb`)
*below* the socket fd. No socket API retracts or reschedules a segment the stack has decided to
send. `TCP_QUICKACK` changes the *decision* (immediate vs delayed) for the next ACK; it cannot hold
one already sent. Withholding `read()` shifts *when* the stack elects to ACK but cannot recall an
emitted ACK. The load-bearing seam: **"emitted by TCP" ≠ "on the wire"** — between
`tcp_transmit_skb` and the NIC sits the egress traffic-control (qdisc) layer, where the ACK is
still a queued `skb`.

**Q3. What control point is required to hold an already-generated pure ACK?** Any point *below*
where TCP emits it: (1) socket layer — cannot (Q2); (2) **tc egress qdisc on the outstation host**
(`clsact`/egress + netem or eBPF `act`) — the lowest-cost real control point; (3) an **inline
bump-in-the-wire** (two-NIC bridge / user-space proxy / programmable NIC / the eventual P4 switch)
— the ACK is a transit packet, no change to the outstation host; (4) the **NIC** (SO_TXTIME/EDT
hardware pacing). All delay a *real* ACK — none forges one, so all are spec-compliant on
"no ACK synthesis." The choice is a deployment-position/precision trade-off, not a legality one.

**Q4. Can `tc` distinguish a zero-payload pure ACK from a payload-bearing response?** **Yes,
robustly only with eBPF.** The correct discriminator is **TCP payload length**
(`ip.tot_len − ip.ihl×4 − tcp.doff×4 == 0` ⇒ pure ACK), not flags. `u32` reads fixed offsets but
cannot *compute* that subtraction, so it degrades to matching a fixed total length (e.g. 40/52 B) —
fragile, and already wrong on this stack because Linux pure ACKs commonly carry the 12-byte
timestamp option. `flower` can match `tcp_flags` (verified supported here) but flag-based ACK/PSH
discrimination is *advisory only* (PSH is a hint) — **it remains unsafe even with the corrected
`0x10/0x1f` mask**: the netem smoke test's mask worked *only because* the DNP3 responses carried
PSH+ACK; a payload-bearing ACK segment without PSH would still be misclassified as a pure ACK.
**`cls_bpf`/eBPF** parses variable IHL and TCP data-offset and computes payload length exactly — the
production discriminator is `payload_len == 0 AND ACK == 1 AND SYN/RST/FIN == 0`, which needs
header-length parsing and is the only classifier correct under options.

**Q5. Is eBPF required, or does `tc netem` + a classifier suffice?** `netem` + a classful qdisc can
impose delay on whatever a filter steers into a delayed band — including a pure ACK (the Q2/Q3
seam) — so a **coarse version works without eBPF** and is a valid first smoke test. But netem has
**no per-flow state** ("release *this* response T ms after *this* request") and **no per-packet
scheduled departure** (its delay is drawn from a distribution). eBPF (tc `clsact`, ingress+egress)
adds: robust classification (Q4); per-flow state (`BPF_MAP_TYPE_HASH`/`LRU_HASH` on the 5-tuple);
**precise scheduled release via EDT** (an egress program writes `skb->tstamp = now + target`, `fq`
honors earliest-departure-time — this gives *independent* ACK vs response timing, for
separate-mode flows, while forging nothing). **`bpf_timer` is NOT part of the packet-release
design:** a timer callback cannot retain and later emit an arbitrary `skb`; the packet stays in the
qdisc and is released by EDT. `bpf_timer` may serve only state cleanup / watchdog logic, never
packet storage. **XDP is the wrong hook** (ingress-only on the mainline model; the need is egress
release timing). **eBPF is required for the real mechanism.**

**Q6. Is a transparent two-NIC bridge more appropriate than host-local tc/eBPF?** For deployment,
the inline bridge is the better *position*: it **does not touch the outstation host** (critical in
OT, where you often cannot modify/reboot the asset), it sits in the **same position as the eventual
Tofino switch** (findings transfer), it sees both directions, and its state lives on the
middlebox. Costs: it **adds a hop** (sub-ms but nonzero latency — folds into the RTO budget), an
**availability risk** (must fail-open, never black-hole), and doubles NIC/interrupt load. Develop
the logic host-local (faster to a result); re-host the *same* eBPF onto a bridge for the
deployment-realistic run.

**Q7. Which mechanism maps most directly to P4/Tofino — and what does not?** The
**classify-and-mark + per-flow-register** half maps directly: payload-length classification as
match-action; 5-tuple-keyed SALU register arrays; ingress `intrinsic_metadata` ns-timestamp for the
`t_req` reference and elapsed-time compares — textbook Tofino stateful logic. **What Tofino 1 (TNA)
cannot easily do here** (the honest limit): **hold/buffer a packet for a precise multi-ms delay.**
The MAU is run-to-completion; recirculation to emulate 25 ms would need tens of thousands of passes
per packet (each ~hundreds of ns), destroying line rate; the only native "delay" is Traffic-Manager
**queue shaping**, which is rate-based and flow-coarse, not a per-packet target gap. Tofino also has
no "wake me in T ms" timer (only the packet generator, which is coarse and *creates* packets). **So
the mechanism has a Tofino-native half (the decision) and a Tofino-hostile half (the pure-ACK
scheduled multi-ms release).** This split is the single most important P4-readiness fact.

**Q8. What per-flow state is required?** Keyed by the 5-tuple: `t_req` (request-arrival ns);
`last_seq`/`last_ack` (correlate the ACK to its request); `ack_released` / `resp_released` flags;
`target_ack_delay` / `target_response_delay` (per-flow or per-device-class gaps); `t_ack_release` /
`t_resp_release` (computed EDT departure times); and an **RTO-guard** ensuring total imposed delay
stays under the RTO-safe clamp. **No size/segmentation state** is tracked (bytes stay identical).
On eBPF: one small struct per active DNP3 flow in an LRU hash map. On Tofino: register arrays sized
to max concurrent flows, sub-byte flags widened to `bit<8>`, slots controller-seeded (not
zero-sentinel-tested).

**Q9. Ordering and retransmission risks.** The **binding safety timer is TCP, not DNP3.** DNP3
application/link timeouts are seconds-scale (response/confirm ~5 s; data-link confirm typically
`NEVER` over TCP); the master's TCP **RTO ≈ 211 ms** (measured; `TCP_RTO_MIN` 200 ms floor) is ~25×
tighter. So a bounded hold (≤105 ms, realistically ≤~40 ms) cannot threaten DNP3 completion; the
entire risk budget is spent at TCP:
- **Holding the ACK toward RTO → spurious retransmission of the request**, then **RTO backoff**
  (exponential 211→422→844 ms — the real lasting damage), cwnd collapse to 1 MSS, and an extra
  **dup-ACK** (an anomalous packet that itself *adds* fingerprint signal). Reset risk is negligible
  at bounded holds.
- **The invariant `ack_release ≤ response_release` must hold** because the DNP3 response segment
  **piggybacks the ACK** of the request. A pure ACK scheduled *after* the response is a pure
  duplicate ACK; per-transaction repetition risks 3 dup-ACKs → **spurious fast-retransmit** on the
  master. **Design caveat:** the planner's clamp-to-equality must degenerate to *piggyback / suppress
  the redundant pure ACK*, **not** emit a simultaneous pure-ACK + response — the latter *is* the
  SEPARATE mode we are trying to hide.

## 3a. Capability boundary — the most important Phase 04 finding

Independent scheduling of the ACK and the response is possible **only when a separate pure ACK
already exists on the wire.** For a combined-mode device (AB1400 / ION7550-style), the TCP
acknowledgment and the DNP3 response occupy the **same** packet (an ACK-bearing DNP3 response); an
inline `tc`/eBPF program or a Tofino switch can delay that whole packet but **cannot** independently
schedule its ACK and payload components. Creating a separate ACK from a combined packet would
require ACK synthesis, TCP splitting with sequence-aware rewriting, terminating the connection, or
owning the responding socket and inducing the kernel to emit an ACK naturally — all **outside** the
no-synthesis design.

| Native traffic form | Inline eBPF capability |
|---|---|
| Pure ACK **followed by** a response (separate mode) | Can delay both existing packets independently |
| Combined ACK-bearing response | Can delay the **combined packet only** |
| Combined → separate normalization | **Not possible** without synthesis, TCP splitting, or endpoint (socket) control |
| Separate → combined normalization | **Potentially possible** by suppressing the pure ACK and relying on the response's piggybacked ACK (untested; see §6) |

The netem smoke test validated control over an **existing separate ACK** (a separate-mode flow),
**not** universal ACK/response control. The report's earlier "independent release of both the ACK
and the response" is therefore scoped to separate-mode traffic only; for combined-mode traffic the
inline mechanism is a single-packet delay + fail-open.

## 4. Candidate-mechanism comparison

| Mechanism | Holds pure ACK? | Per-flow gap? | No-touch outstation | Maps to P4 | First-prototype verdict |
|---|---|---|---|---|---|
| App response delay | No (ACK uncontrolled) | Response only | n/a (owns socket) | response side only | already works; not sufficient alone |
| `tc netem` + classifier | Coarse (band) | No | host-local | partial | **smoke test only** |
| **eBPF tc `clsact` egress + EDT** | **Yes (real skb)** | **Yes** | host-local→bridge | decision half | **prototype this** |
| Transparent 2-NIC bridge (hosting the eBPF) | Yes | Yes | **Yes** | position match | deployment-realistic re-host |
| Inline user-space proxy | Yes | Yes | Yes | poor | rejected (earlier no-proxy rule; per-packet copy) |
| DPDK / programmable NIC / DPU | Yes | Yes | Yes | heavy | rejected (out of proportion) |
| P4 / Tofino | **decision yes, hold no** | decision yes | — | is the target | final target; hold step is Tofino-hostile |

**Recommendation:** prototype **eBPF on tc `clsact`, ingress AND egress** (host-local for speed,
re-hostable onto a two-NIC bridge). The architecture is two-hook:

```
tc ingress: observe the request; store per-flow request state and target release times
            (the request-arrival timestamp is learned HERE — egress alone cannot know it).
tc egress:  classify pure ACK vs payload response (by payload length); retrieve the flow state;
            assign an EDT departure time, or fail open (bypass) for combined ACK-bearing responses.
```

It satisfies the requirements for **separate-mode** flows — exact zero-payload classification,
per-flow request-correlated state, and EDT-scheduled release of the existing pure ACK and response —
while forging nothing. **For combined-mode flows it delays the single combined packet and fails open
(§3a).** Sequence: (1) the `netem`+classifier smoke test (**done, positive** — see
`netem_smoke_result.md`); (2) a **minimal EDT load-and-release test** (prove a loaded BPF program can
set `skb->tstamp` and that `fq` enforces it on this host — §2/§9) *before* building the state machine;
then (3) the ingress+egress classifier + per-flow map + EDT release, scoped to the narrowed target
in §8a.

## 5. Enforceability of the six required modes

Mapping the plan's required modes onto the (currently unwired) `plan_ack_response_release` planner
and the measured capability boundary:

| Mode | Enforceable where we own the socket | Enforceable in front of a real device |
|---|---|---|
| native | yes | yes |
| response-delay-only | **yes (app write scheduling — measured)** | no (can't delay the device's write) → needs inline hold |
| ack-delay-only | **no from user space** (can't hold the ACK) → needs tc/eBPF | needs tc/eBPF/bridge |
| independent-delay | no from user space → needs tc/eBPF | needs tc/eBPF/bridge |
| fixed-gap / bounded-gap normalization | response-side yes; ACK-side needs tc/eBPF | needs tc/eBPF/bridge |

The planner is correct maths; only `response-delay-only` (and gap normalization *implemented via
response delay*) is enforceable from the application. Every mode that **holds the ACK** needs the
Section-4 mechanism.

## 6. Central research question — gap magnitude vs ACK-mode existence

**Does normalizing only the gap magnitude reduce fingerprinting while the separate ACK still
exists? Trace-transformation evaluation result: gap-only normalization did not reduce ACK-mode
classification accuracy.** (This is a distributional simulation that transforms measured *native*
traces — not a capture of a defended device on the wire; do not read it as a defended-wire
measurement.) From `reports/ack_fingerprint_eval.md`: `ack_only` accuracy is **0.810 before and
0.810 after** gap-normalization (chance 0.400). ACK mode is a **categorical** feature (separate pure
ACK present vs absent) invariant to gap magnitude — pinning SEL-751's ACK→response gap to 20 ms does
not make it *combined*.

**Correction the analysis surfaced (verified against the report's own tables):**
`ack_fingerprint_eval.md` states the `timing` family "collapses (from 0.511 to 0.797)," but 0.511 →
0.797 is an **increase**, and the clustering ARI likewise rises −0.000 → 0.433. The correct reading:
pinning SEL's ACK→response to a **device-correlated 20 ms constant re-encodes the ACK mode into the
timing features, raising timing separability.** Naive gap-normalization can therefore *increase*
some leakage. **This was a factual error in `reports/ack_fingerprint_eval.md` (prose vs its own
numbers); it has since been corrected there (the bullet now reads "rises 0.511 → 0.797 … improves
ARI −0.000 → 0.433").**

Implication for Phase 04: the right target is the **ACK-mode decision**, not the gap. The clean,
byte-preserving, synthesis-free path is to **normalize the mode toward "separate" for all devices by
delaying the response past the delayed-ACK window (~40–50 ms, with margin for the probabilistic
cliff), letting the kernel emit a natural prompt ACK** — but this is only available **where we own
the responding socket** (split/replay/decoy server). In front of a *real* outstation we cannot delay
its app write, so an inline mechanism must instead *buffer existing packets*, which reintroduces the
"hold an existing ACK" regime and its RTO risk. Normalizing toward "combined" (suppressing SEL's
pure ACK) also requires inline packet control and strands the master until the piggyback ACK
arrives. **Size is the irreparable residual:** `size`-family accuracy is 0.500 unchanged (byte
preservation forbids touching it), so joint identity never reaches chance. Honest ceiling for this
line: **ACK+timing channel closable (where we own the socket); joint identity stays above chance via
size.**

## 7. Safety limits any implementation must honor (OT availability first)

1. **Mandatory fail-open bypass** on critical/command traffic, unclassifiable traffic, queue
   overflow, RTO-unknown, or exceeding `max_hold_ms`. Fail-**open** (not fail-closed) is the
   availability-preserving choice on an ICS conduit.
2. **Absolute hold ceiling ≪ RTO and ≪ DNP3 timeouts:** bind holds to
   `min(rto_safe ≈ 105 ms, delayed-ACK ceiling ≈ 40 ms)`; prefer the ~40 ms ceiling (holds above
   the natural window are themselves anomalous). **Bake the clamp into the sampling distribution's
   support** so "resample" is unnecessary and bypass stays rare (every bypass = native = a leaked
   transaction).
3. **Never hold time-critical DNP3** (controls, unsolicited alarms, Class-1 event polls).
4. **Prefer inducing a natural ACK over suppressing an existing one** (the former can never strand
   the master).
5. **Per-flow FIFO, no reordering, strict `ack_release ≤ response_release` degenerating to
   piggyback, no ACK synthesis, no byte edits.**
6. **Bounded buffering / backpressure** and a **watchdog dead-man fail-open** (the shim must never
   become an availability single point of failure).
7. **Full observability** of every clamp/bypass/resample with reason (bypass frequency is itself a
   protection metric). Inline device is a cyber asset on a NERC CIP ESP / IEC 62443 conduit — its
   failure modes must be availability-preserving.

## 8. Does the feasibility report identify a real enforcement mechanism?

**Yes, for separate-mode traffic — with a scoped boundary and one behavioural check outstanding.**
eBPF on tc `clsact` (ingress + egress) with per-flow state and EDT (`skb->tstamp` + `fq`) is a real,
environment-*plausible* mechanism that holds an **existing** pure ACK and response to independently
computed departure times without forging or editing packets. It closes exactly the gap the
application cannot (holding an already-emitted ACK) **for a flow that already has a separate ACK**.
Two honest limits keep this a **CONDITIONAL** finding: (a) for **combined-mode** flows there is no
standalone ACK to schedule, so the mechanism can only delay the single combined packet and fail open
(§3a); (b) EDT support is **plausible but not behaviourally verified on this host** — the presence of
`sch_fq`, `skb->tstamp`, and `bpf_timer` in BTF shows the pieces exist, not that a loaded program can
set EDT and that `fq` enforces it, so a **minimal EDT load-and-release test must pass first** (§9).
Its decision logic ports to P4/Tofino; its scheduled multi-ms release does **not** (Tofino cannot
buffer for precise multi-ms delays) — so the eBPF prototype does double duty: working mechanism *and*
honest scoping of the eventual P4 port.

## 8a. Narrowed target for the eBPF prototype (scope before building)

The prototype's target is explicitly **not** universal ACK/response control. It is:

1. **Robustly classify an existing pure ACK** (payload-length = 0, not flags).
2. **Record request state at ingress** (per-flow arrival timestamp + target release times).
3. **Schedule the existing separate ACK and response packets at egress** (EDT), for separate-mode flows.
4. **Fail open for combined ACK-bearing responses** (single-packet delay at most; never attempt to
   split or synthesize).
5. **Separately investigate pure-ACK *suppression*** as the only no-synthesis route toward
   combined-mode normalization (suppress the existing separate ACK, rely on the response's
   piggybacked ACK) — carefully, because it delays acknowledgment until the response arrives, changes
   packet count, risks retransmission if the response is late, requires confirming every response
   acknowledges the complete request, and needs a fail-open path when the response is not prompt.

## 9. Verify-flagged items before implementation

- **FIRST behavioural check (blocking):** a **minimal EDT load-and-release test** — load a trivial
  tc-egress BPF program that sets `skb->tstamp = now + N ms` on a marked packet, with `fq` on the
  interface, and confirm from a PCAP that the packet actually departs ~N ms late. The BTF/module
  presence checks (§2) show plausibility only; this proves the release primitive works on this host
  *before* any DNP3 state machine is built. (`bpftool` is absent — verify via the load test or
  install bpftool.)
- Exact `TCP_QUICKACK` reset semantics on 5.15 (`tcp(7)`); writability of `__sk_buff->tstamp` in
  tc-egress and `fq` EDT enforcement behavior on 5.15.0-139 (field/module present; **behavior
  untested here — see the load-and-release test above**).
- The real master's **RTO and `rto_min`** (211 ms is this setup only — measure on the actual master
  OS) and the **~36–40 ms delayed-ACK cliff** (kernel/config-specific, loopback only).
- OpenDNP3 timeout defaults on the installed stack; whether the real outstation uses data-link
  confirms; whether physical SEL-751/AB1400/ION7550 change ACK mode under response delay (untested —
  their own stacks govern it).
- **Whether the deployment owns the responding socket or is inline** — this determines whether the
  clean byte-preserving "induce a natural separate ACK" path is available at all.

## 10. Threats to validity

Loopback-only measurements underpin the capability boundary and the ~40 ms cliff; a two-host rig
with real NICs may differ. The fingerprint numbers are a distributional simulation on measured
native timings, not a capture of a defended device. Tofino limits are from the constraint reference
and TNA docs, not a compile on the testbed.

## 11. Verdict and STOP

**Mechanism-feasibility: CONDITIONAL PASS.** The report **identifies a real enforcement mechanism**
(eBPF tc `clsact` ingress+egress + EDT) **for separate-mode traffic**, answers all nine plan
questions, and scopes the P4 port honestly — but with two load-bearing conditions surfaced by
review: the **capability boundary** (§3a — combined-mode flows cannot be split into an independent
ACK without synthesis/splitting/socket-control, so the inline mechanism there is single-packet delay
+ fail-open), and the **outstanding behavioural EDT check** (§9). The netem smoke test (control over
an *existing* separate ACK) is **PASS**. Per the plan, this is the gate to *consider* implementation
— it is **not** implementation, which starts only on explicit human authorization.

**Prerequisites before formal eBPF-implementation authorization:** (1) the Phase 03A human
packet-inspection gate must be genuinely complete (the reviewer has flagged this must be confirmed);
(2) the minimal EDT load-and-release test (§9) must pass; (3) the prototype scope is the narrowed
target in §8a, not universal ACK/response control.

**Recommended next step (for human decision):** authorize a **netem smoke test** (does differential
ACK/response delay move the fingerprint?) followed by the **eBPF tc-egress prototype**, developed
host-local against the replay/decoy server we own, then re-hosted onto a two-NIC bridge. (The
"collapse" wording in `reports/ack_fingerprint_eval.md` has been corrected.)

`next_phase_allowed = false`.

```
STOP: awaiting human review before Phase 04 implementation.
```
