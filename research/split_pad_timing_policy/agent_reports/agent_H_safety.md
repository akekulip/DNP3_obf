# Agent H — Power-System Operations & Safety: 3-Axis Semantics/Safety Taxonomy for Split + Pad + Timing

_Scope: classify DNP3 traffic by physical-operations criticality; for each class, on the three
independent axes (SHAPE/SIZE, TIMING, SEMANTICS/SAFETY), say which axes leak and which of
{split, pad, timing, bypass} may **safely** address them and to what budget; define when shaping
must be **bypassed**; specify **fail-open vs fail-safe**; design the **operator criticality
allowlist**; state **latency/reliability** requirements for control vs monitoring. Analysis only,
no code changed. **Extends** Agent C's timing-only shape/bypass table
(`ack_timing_normalization/agent_reports/agent_C_dnp3_scada.md`) to all three mechanisms — I do not
re-derive the timer stack Agent C verified in the OpenDNP3 fork; I reuse it and cite it as
[V-fork]. Grounded on GROUNDING.md + measured_evidence.md. Label convention: **[M]** measured this
rig · **[S]** standard (IEEE 1815 metadata-level) · **[V-fork]** verified in OpenDNP3 community fork
source (file:line, by Agent C) · **[I]** inference · **[H]** hypothesis._

---

## 1. Findings first (grid-engineering terms)

1. **The three mechanisms are safety-asymmetric across the traffic mix, and the asymmetry is
   clean: shape monitoring hard, leave control alone.** Split and timing normalization are
   byte-preserving and carry near-zero physical-operations risk on the **monitoring/response**
   plane, which is also where the attacker gets the most samples (continuous periodic polling).
   Control traffic (SELECT/OPERATE/DIRECT_OPERATE) is simultaneously the **lowest-privacy-value**
   target (infrequent, bursty → few CROB-count samples to regress) and the **highest-safety-cost**
   class to touch (a delayed or reordered control has physical consequence). The operationally
   correct policy therefore shapes the read/event plane aggressively and **bypasses control by
   default** — privacy is bought where it is cheap and abundant, never where it is expensive and
   scarce.

2. **Splitting is safe on any class but only *useful* on large responses, and it never closes
   the total-byte / total-work leak.** The CRC-boundary splitter is byte-preserving — master
   reassembles identical bytes, 0 TCP retransmits, 0 resets across bpc 1/2/4/8 [M]. But (a) summing
   the chunks recovers the original size, so **total bytes survive splitting** [M] (grounding
   forbids claiming otherwise), and (b) splitting a **37 B** control response (≈1–2 CRC blocks)
   yields 2–3 chunks — negligible reshaping while **adding a packet-count observable** that itself
   can encode CROB count. Split earns its keep on the 12,204 B / 49-link-frame integrity read [M],
   not on control responses.

3. **No safe byte-preserving DNP3 padding exists today — for any class — so the SIZE axis is a
   residual, not a solved axis.** The only padding tested (invalid-index CROBs) is a **negative
   result**: nonexistent G12V1 indexes return OUT_OF_RANGE, over-count returns TOO_MANY_OPS, and a
   partial SELECT failure blocks OPERATE, so padding is **not insertable** into a live control
   transaction [M]. Consequently the measured size leaks — read-plane size ∝ point count
   (5.7 B/analog point [M]) and control-plane size ∝ CROB count (14.6 B/CROB, R²=0.9999 [M]) —
   cannot be closed now. Timing normalization closes the timing leak; the size leak needs a
   **future protocol-modifying padding phase**. State this as an honest residual.

4. **The binding correctness bound is the master's measured effective TCP RTO, and the split
   evidence sharpens the budget hierarchy Agent C stated.** Agent C's rule "keep both per-hold and
   cumulative added latency under RTO" is conservative; the measured split refines it. The correct,
   evidence-backed envelope is **three separate inequalities**: (i) req→first-response hold <
   effective RTO; (ii) each inter-chunk / inter-fragment gap < effective RTO; (iii) cumulative
   transaction latency < DNP3 application response timeout (5 s [V-fork]) and, for SBO, < outstation
   select timeout (10 s [V-fork]). Proof it is the right decomposition: bpc=1 split = **141 chunks
   at 10 ms/chunk ≈ 1.4 s cumulative, 0 retransmits / 0 resets** [M] — cumulative far exceeds any
   200 ms RTO with no ill effect, because each gap is < RTO and the cumulative stays under the 5 s
   app timeout. The RTO caps the *initial hold and each gap*, not the whole transaction.

5. **DNP3 fields reveal operation TYPE, never physical CRITICALITY — this forces an operator
   allowlist and it is the single hardest constraint on the whole design.** Function code +
   object group + point index let the middlebox tell a control from a read and outstation A from
   outstation B, but the protocol nowhere encodes that G12V1 index 5 opens a 115 kV feeder while
   index 6 toggles a status lamp [S]. An in-network element therefore **cannot certify a control is
   non-critical from DNP3 alone**; it needs an operator-supplied
   `(outstation addr, FC, object group, index) → criticality/priority/policy` map, default-
   conservative (all control FCs bypass unless explicitly whitelisted). The default failure mode
   must be "shaped less than possible," never "delayed a critical control."

6. **Protection is not on this wire and must not be delayed.** Sub-cycle protection tripping is
   hardwired or GOOSE, architecturally upstream of a DNP3 supervisory link; IEEE 1815 imposes **no
   minimum-latency requirement** [S], so no spec clause a bounded sub-RTO hold violates — but that
   is precisely why the operator allowlist must exist to catch a **misengineered** site that runs
   an automated control loop through DNP3 OPERATE. Do not recommend delaying protection traffic; do
   not assert any specific relay's latency capability.

_Plain language: shape the constant, high-volume monitoring chatter — it is where the attacker
learns the most and where slowing things down hurts nothing. Leave the occasional control commands
alone unless an operator has explicitly said a specific point is safe to shape. And never rely on
the DNP3 message to tell you whether a control is dangerous — it can't._

---

## 2. Model and assumptions

| Dimension | Setting | Source |
|---|---|---|
| Stack | OpenDNP3 community fork, software outstation (Hulk) / master (Vision), DNP3-over-TCP, single persistent connection, `TCP_NODELAY` | [M]; prior brief |
| Link service | Unconfirmed only (`PRI_UNCONFIRMED_USER_DATA`); no `SEC_ACK` on the wire | [V-fork] LinkContext.cpp:158 (Agent C) |
| Unsolicited | Off by default (`allowUnsolicited=false`, `disableUnsolOnStartup=true`) | [V-fork] (Agent C) |
| Shaping levers this phase | Split at CRC boundaries · control release timing · pace existing packets/chunks · select preapproved policy · bypass | GROUNDING HARD phase rule |
| Padding | **No safe byte-preserving mechanism** (invalid-index = negative) → future phase | [M] measured_evidence §5 |
| Threat model | Passive on-path observer; unencrypted DNP3; may use size, packet/fragment/segment count, req→response delay, inter-packet gaps, TCP behavior, repeated polling; no inject/block | GROUNDING |
| Binding constraint | Master **effective TCP RTO** (Linux `TCP_RTO_MIN` floor ≈200 ms — **MUST be measured on Vision**, not assumed) | GROUNDING; Agent B task |
| Physical model | Comms/protocol study, not power-flow; no balanced/unbalanced or dynamic-stability claim is made | this scope |
| Scope caveat | Single device, single rig, single implementation → **device-configuration/complexity**, not cross-device fingerprint; CROB count, not database size | GROUNDING §17 |

**Assumption flagged:** every budget below is a fraction of the *measured* effective RTO on Vision;
200 ms is a Linux default, not universal, and Agent B measures it. Nothing here should be read as
endorsing 200 ms as a constant.

_Plain language: this is about network timing and packet shapes on one lab rig, not about the grid's
electrical behavior; treat every number as "this device, this setup."_

---

## 3. Axis-3 SEMANTICS/SAFETY taxonomy — the DNP3 traffic classification

Nine operational classes, ordered by ascending safety cost of shaping. "Direction" O→M =
outstation→master (the byte we generate/hold/split); M→O = master-originated (we never originate,
generally never shape).

| # | Class | FC (hex) / object | Dir | Safety cost of shaping | Privacy value to attacker |
|---|---|---|---|---|---|
| 1 | **Routine integrity poll** | READ `0x01` g60v1 (Class 0) → RESPONSE `0x81` | O→M | **Lowest** — no control semantics | **Highest** — continuous, periodic, size ∝ config complexity |
| 2 | **Event poll** | READ `0x01` g60v2/3/4 (Class 1/2/3), event objs g2/g22/g32 → `0x81` | O→M | Low, but defers alarm awareness if over-held | High — frequent; size ∝ event burst magnitude |
| 3 | **Unsolicited event** | UNSOLICITED_RESPONSE `0x82` | O→M | **High** — spontaneous alarm; latency-sensitive | Low here (off by default); arrival time = when the event occurred |
| 4 | **SELECT** | SELECT `0x03` g12v1 (CROB) → `0x81` | O→M (resp) | High — arms a control; ordering-sensitive | **Low** — infrequent/bursty; response size ∝ CROB count |
| 5 | **OPERATE** | OPERATE `0x04` g12v1 → `0x81` | O→M (resp) | **Very high** — executes the control | Low — infrequent; response size ∝ CROB count |
| 6 | **DIRECT_OPERATE / _NR** | `0x05` / `0x06` (no response) g12v1 | O→M / M→O | **Very high** — control without SBO arming | Low |
| 7 | **Critical control** | any control FC on an operator-flagged (outstation, index) | O→M | **Maximum** — physical consequence | Low |
| 8 | **Noncritical supervisory control** | control FC on an operator-flagged-benign (outstation, index) | O→M | Moderate (still a control) | Low |
| 9 | **Protection traffic** | **not DNP3** — hardwired / IEC 61850 GOOSE | — | **Out of scope — never delay** | N/A |

**The load-bearing caveat (repeat in the paper):** classes 4–8 are distinguishable by DNP3 fields
only as *control type*, never as *physical criticality*. The split between class 7 (critical) and
class 8 (noncritical) **cannot be made from the wire** — it comes only from the operator allowlist
(§6). Absent an allowlist entry, every class-4–6 transaction is treated as class 7.

_Plain language: DNP3 tells you a message is a control, and which point it targets, but not whether
that point matters. Only the utility's own configuration knows that, so we default to treating every
control as critical until told otherwise._

---

## 4. The extended per-class × 3-axis × mechanism matrix (the deliverable)

**4a. Which axes leak, per class** (measured leaks in **bold**):

| Class | Axis-1 SHAPE/SIZE leak | Axis-2 TIMING leak | Axis-3 SEMANTICS/SAFETY |
|---|---|---|---|
| Integrity poll | **size ∝ point count (5.7 B/pt); frag/link-frame/TCP-seg counts** [M] | **req→response ∝ config complexity** [M]; poll cadence | benign (monitoring) |
| Event poll | size ∝ #events queued; frag count | processing time; event-arrival/poll cadence | benign, but latency defers awareness |
| Unsolicited | size ∝ #events | **arrival time = event occurrence** | urgent (spontaneous) |
| SELECT | **response size ∝ CROB count (14.6 B/CROB, R²=0.9999)** [M] | **resp ∝ CROB count (0.179 ms/CROB)** [M] | control-arming |
| OPERATE | **response size ∝ CROB count (14.6 B/CROB)** [M] | **resp ∝ CROB count (0.214 ms/CROB)** [M] | control-execute |
| DIRECT_OPERATE | size ∝ CROB count | processing time (`_NR` has no response) | control-execute |
| Critical control | (as above) | (as above) | **maximum consequence** |
| Noncritical control | (as above) | (as above) | operator-flagged benign |
| Protection | N/A (not DNP3) | N/A | out of scope |

**4b. Which mechanism may safely address each, and to what budget:**

| Class | SPLIT | PAD | TIMING | BYPASS trigger | Recommended posture & budget |
|---|---|---|---|---|---|
| **Integrity poll** | **Yes — high value.** Byte-preserving; reshapes frag/seg/packet counts on large responses. Does **not** hide total bytes | **Future only.** No safe pad now; monitoring responses are the *most tractable* future padding target (append inert analogs outside requested range / envelope pad) [H] | **Yes — full normalization.** Fixed N-independent completion deadline kills the processing-time regression | never (benign) | **Fully shape.** Split + fixed completion deadline. Initial hold < RTO; each gap < RTO; cumulative < 5 s app timeout. Fixed 15–20 ms deadline gives huge margin |
| **Event poll** | Yes (byte-preserving) | Future only | **Yes, tighter bound** — events carry alarms; do not defer awareness | if held would exceed an operator alarm-latency SLA | Shape to a **tight** fixed bound (tens of ms, ≪ human alarm SLA of seconds). **Never** touch the CONFIRM that flushes the event buffer |
| **Unsolicited** | Minimal (off by default) | No | **Minimal only** — urgent | **Bypass in this deployment** (off). If enabled: minimal, never > unsolConfirmTimeout (5 s) [V-fork] | Bypass; if enabled treat as event-urgent, near-zero hold |
| **SELECT** | **Low value** (37–256 B ≈ 1–14 chunks); adds packet-count observable | Future only; padding a control response is the **most dangerous** future target (can alter apparent op count) [H] | Response-side shaping safe on *timing* (huge timer margin) but gated by allowlist | **critical control; ordering risk; insufficient budget; unsupported; uncertain RTO margin** | **Bypass by default.** Shape only if operator-whitelisted; then fixed N-independent deadline, SELECT-resp + turnaround + OPERATE-resp cumulative ≪ 10 s select timeout (target < 1 s) |
| **OPERATE** | Low value | Future only; dangerous | Tight budget; command-completion latency dominates | **critical control (always); tight control-loop deadline; any doubt** | **Bypass by default.** If whitelisted: ≤ 20 ms fixed deadline so command latency stays imperceptible for human supervisory control |
| **DIRECT_OPERATE / _NR** | Low value | Future only | `_NR` has no response to shape | **control-side bypass by default** | Treat like OPERATE; `_NR` = nothing to shape anyway |
| **Critical control** | **No** | **No** | **No** | **always bypass** | **Release verbatim, immediately.** No split, no hold, no queue |
| **Noncritical control** | Optional, low value | Future | Tight, if whitelisted | any bypass trigger still forces pass-through | Shape only under an explicit allowlist entry; else bypass |
| **Protection** | **No — not DNP3** | No | **No — never delay** | always | Out of scope; do not delay |

**Reading of the matrix:** apply split + the `max(response_ready, request_time + target)` scheduler
to the **O→M monitoring classes (1, 2)** at full budget; apply timing only, tight, to control
classes (4–6, 8) **only under an allowlist entry**; **bypass** classes 3, 7, 9 and all un-whitelisted
control. Never shape any M→O frame (CONFIRM, requests). Padding is future for every class.

_Plain language: the table says "split and time-smooth the routine readings freely; barely touch
event alarms; and leave control commands untouched unless an operator has explicitly cleared a
specific control point as safe to shape."_

---

## 5. When shaping must be BYPASSED, and fail-open vs fail-safe

**Bypass = release the packet unchanged, immediately (no split, no hold, no queue).** Triggers, any
one sufficient:

1. **Critical / operator-flagged control** — class 7, and every un-whitelisted class-4–6 transaction.
2. **Unsolicited / urgent** — spontaneous alarm (`0x82`); latency-sensitive by construction.
3. **Insufficient deadline budget** — the normalization target cannot be met without an initial
   hold ≥ the measured effective RTO, or a cumulative ≥ the 5 s app timeout / 10 s select timeout.
4. **Target already missed** — the response became ready *after* `request_time + target`; holding
   buys no anonymity and only adds latency → release now.
5. **Queue over limit** — backlog of held packets exceeds the configured depth; draining prevents a
   correctness cascade (per-segment RTO pressure) — release to clear.
6. **Ordering risk** — anything that could reorder SELECT vs OPERATE, reorder multi-fragment
   sequence, or interleave a control ahead/behind its own handshake. SBO ordering is a hard
   correctness invariant; when in doubt, do not reorder.
7. **Unsupported / unknown** — FC or object group not in the classifier's known set → cannot classify
   → cannot certify safe → bypass.
8. **Uncertain RTO margin** — effective RTO not yet measured on this link, or measured with high
   variance → bypass until the budget is known.

**Fail-open, not fail-closed — and this equals fail-safe for the grid.** The privacy filter must
**fail toward delivery**: on any doubt it releases traffic *unshaped and undelayed*. A fail-*closed*
privacy filter (drop or hold when uncertain) would starve the master of monitoring data and could
stall a control — grid-unsafe. So the shaping element is **fail-open with respect to packet
delivery, which is fail-safe with respect to power-system operation.** Safety dominates privacy:
the worst privacy outcome (a transaction shaped less than it could have been) is always preferable
to the worst operations outcome (a delayed/dropped/reordered control or a starved poll). Every
bypass trigger above is an instance of "resolve doubt in favor of delivery."

_Plain language: whenever the shaper is unsure — about the deadline, the queue, the ordering, or
what the message even is — it lets the packet through untouched. Losing a little privacy is always
better than risking a missed reading or a mishandled control._

---

## 6. Operator criticality allowlist — design

**Why it must exist:** §3/§5 — DNP3 fields give operation *type*, never physical *criticality* [S].
The only source of criticality is the utility's own point database, which the operator supplies
out-of-band.

**Key (most specific wins):** `(outstation address, function code, object group, point index)` →
`{criticality: critical|noncritical, priority, shaping_policy: bypass|shape, budget}`. Wildcards
allowed on any field so a rule can be as coarse as "all controls to outstation 10 → bypass" or as
fine as "outstation 10, OPERATE, g12v1, index 3 → shape, 20 ms."

**Default-conservative resolution (fail-safe):**
- All **control** function codes (`0x03` SELECT, `0x04` OPERATE, `0x05`/`0x06` DIRECT_OPERATE) →
  **bypass** unless an explicit entry whitelists that exact (outstation, FC, object, index) for
  shaping. No entry = treat as critical.
- **Monitoring** function codes (`0x01` READ → `0x81` RESPONSE, event objects) → **shapeable by
  default**; an operator may still add a bypass entry (e.g., a critical event class).
- **Unknown** FC/object → bypass (§5.7).

**Governance (state, don't over-engineer):** the allowlist is trusted configuration — validate it at
load (well-formed keys, known FCs/objects, no contradictory rules), then trust internally per the
trust-boundary rule. It is operational change-controlled data; treat edits with the same rigor a
utility already applies to point-database changes (NERC CIP change-management context [S], cited at
the concept level — no clause asserted). The middlebox itself sits at an IEC 62443 conduit between
the SCADA master zone and the outstation zone [S, concept-level]; the allowlist is that conduit's
policy. Do **not** fabricate specific clause numbers for either standard.

**What the allowlist explicitly does NOT do:** it never *infers* criticality from DNP3 content, never
upgrades a control to shapeable on its own, and never overrides a bypass trigger from §5 (a
whitelisted-for-shaping control is still bypassed if the deadline budget is insufficient, the queue
is over limit, or ordering is at risk).

_Plain language: the operator hands the shaper a list saying "these exact control points are safe to
shape; everything else, leave alone." No list entry means "treat it as critical — don't touch it."_

---

## 7. Latency / reliability requirements: supervisory control vs monitoring

**Monitoring (integrity + event polls).** Periodic, cadence seconds-to-minutes; a single poll
response is one of a continuous stream, so deferring it by tens of ms is operationally invisible
against any monitoring/alarm SLA (human alarm response is seconds). The **binding** cap is not an
operational SLA at all — it is the effective RTO (per §1.4), which sits far below any monitoring
tolerance. So monitoring can absorb the **full** shaping budget: split freely, normalize to a fixed
completion deadline, initial hold and each gap < RTO, cumulative < 5 s. This is the class where
privacy is both most valuable (continuous sampling) and cheapest (zero safety cost) — shape it hard.

**Supervisory control (SELECT/OPERATE/DIRECT_OPERATE).** Infrequent and bursty. Two consequences:
- **Lowest privacy value:** a passive attacker regressing CROB count off size (14.6 B/CROB) or
  timing (0.179–0.214 ms/CROB) gets **few samples** because controls are rare — the leak exists
  per-transaction but is sparsely sampled, unlike the continuously-polled read plane. Shaping
  control buys little marginal anonymity.
- **Highest safety cost:** a control has physical consequence; added latency matters to any
  automated control loop; ordering matters to SBO. Human supervisory control tolerates ms-to-sub-
  second latency easily, but the middlebox **cannot tell** a human-driven control from a tight
  automated loop from DNP3 alone (§3). IEEE 1815 sets **no minimum-latency requirement** [S], so the
  latency budget for a control comes from the *control application*, which the wire does not reveal.

**The resulting asymmetry (core design principle):** control is simultaneously the **lowest-value**
and **highest-cost** class to shape, so the operationally and privacy-optimal choice coincide —
**bypass control by default, shape monitoring aggressively.** You give up almost no privacy (few
control samples) to remove almost all safety risk. This is not a compromise; it is the dominant
strategy on both objectives.

**Reliability envelope (per §1.4, evidence-backed):**
- req→first-response hold < measured effective RTO [S, measure] — else the master retransmits its
  request (loudest passive tell + Zeek `dnp3`/TCP-anomaly flag).
- each inter-chunk / inter-fragment gap < measured effective RTO.
- cumulative transaction latency < 5 s app response timeout [V-fork]; for SBO < 10 s select timeout
  [V-fork].
- **Measured proof the envelope holds:** 141-chunk split at 10 ms/gap ≈ 1.4 s cumulative, 0
  retransmits / 0 resets [M].
- Never suppress or synthesize a CONFIRM; never shape any M→O frame (Agent C §7E, reused).

_Plain language: readings can be slowed a little with no operational downside and big privacy upside,
because they come constantly. Control commands are rare, so shaping them barely helps privacy while
risking a real physical action — so by default we don't shape them at all._

---

## 8. Protection scoping (kept minimal, per instruction)

Sub-cycle protection (bus/line/transformer trips) is carried by **hardwired trip circuits or IEC
61850 GOOSE**, not DNP3; a DNP3 supervisory link is architecturally *upstream* of the protection
path [S/I]. IEEE 1815 has **no minimum-latency requirement** [S], so there is no protection-latency
clause to violate. IEC 61850-5 performance classes are mentioned **only for scoping** (protection is
sub-cycle, not on this wire) — not over-cited, not read this session, no specific figure asserted. Do
**not** delay protection traffic; do **not** assert any specific relay's (e.g. SEL-751A) latency
capability without a vendor doc — none was consulted. Residual risk = a **misengineered** site
running an automated control through DNP3 OPERATE; the operator allowlist (bypass, §6) is the
mitigation, not a protection-timing budget.

_Plain language: the fast, safety-critical trip signals don't travel on this DNP3 link at all, so
this work never touches them; we only guard against a badly-designed site by defaulting controls to
bypass._

---

## 9. Deliverable sections covered & consistency with Agent C

This report authors the content for `safety_and_operations.md` and the Axis-3 SEMANTICS/SAFETY
taxonomy (spec §5 Agent H, §7). It **extends** Agent C's timing-only shape/bypass table to
split + pad + timing (§4b here), keeps every Agent C verdict intact (nothing reversed), reuses Agent
C's [V-fork] timer facts, and **sharpens one thing**: the budget hierarchy is three separate
inequalities (initial hold, per-gap, cumulative), not a single "cumulative < RTO" bound — justified
by the measured 141-chunk/1.4 s/0-retransmit split. No measured fact is contradicted. No new device,
database-size, or padding-solved claim is made.

**Single most important caveat:** the size axis is an **honest residual** — split cannot hide total
bytes and no safe DNP3 padding exists, so CROB count (control plane) and configuration complexity
(read plane) remain readable off response size even after full split + timing normalization; closing
the size axis is explicitly a future protocol-modifying padding phase, and shaping control to chase
that residual is exactly what the safety analysis says **not** to do.

---

## NEW_PAPER_MATRIX_ROWS
_None. All works I rely on (IEEE 1815-2012, IEC 61850-5, Formby 2016, RAINCOAT 2019, Lin 2013 Bro/DNP3
IDS) are already in the 102-paper matrix and in Agent C's rows; NERC CIP and IEC 62443 are referenced
only at the concept level with no clause asserted and are not added as matrix rows to avoid an
unverified citation._

## NEW_BIBTEX
_None._
