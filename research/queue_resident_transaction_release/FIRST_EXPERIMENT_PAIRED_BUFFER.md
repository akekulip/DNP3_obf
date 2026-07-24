# First experiment — paired transaction buffer (Parts 9 + 11)

Objective: buffer ACK-A in a per-slot holding path; admit matching RESPONSE-A into a related path; ensure
neither unrelated RESPONSE-B nor any token releases ACK-A; emit ACK-A before RESPONSE-A; no external chaff;
no controller update; no continuous recirculation of ACK-A. Three alternative constructions are developed;
the lowest-resource defensible one is selected for the microbench.

## Construction review (Part 9 — classification)

| Construction | queue-resident original | exact ownership | evt/deadline coupling | no chaff | no CP fastpath | no continuous orig-recirc | A<R | bounded timeout | byte id | sparse | class |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **α IBSPG single-queue** | yes (Q_HOLD) | slot+gen | drain register | internal token | yes | yes (1-2 pass) | FIFO | pass-cap | yes | yes | **REQUIRES MICROBENCH** |
| **β IBSPG two-stage** | yes (park→release qs) | slot+gen | response transfers to stage-2 | internal token | yes | yes (2 pass) | stage order | pass-cap | yes | yes | **REQUIRES MICROBENCH** |
| **γ recirc-hold (baseline)** | **no (recirc pipe)** | slot+gen | register poll | none | yes | **no (thousands)** | zero-inversion | pass-cap | yes | yes | BASELINE (violates queue-resident + no-recirc) |
| Ditto-no-chaff | yes | — | schedule | — | yes | yes | slot | — | yes | **no** | REFUTED |
| CP queue gate | yes | — | CP write | — | **no** | yes | — | — | yes | yes | REJECTED |

γ is the accepted comparison baseline (the frozen DCRN). α and β are the novel candidates. Ditto-no-chaff,
CP-gate are refuted/rejected as above.

## The three alternatives (Part 11)

### α — IBSPG single hold queue (LEAD, lowest-resource)
- **Queues:** on internal loopback port L, `Q_BLOCK` (high strict) + `Q_HOLD` (low strict). Per slot: one
  (Q_BLOCK, Q_HOLD) pair, or a shared Q_BLOCK gating per-slot Q_HOLDs if a per-slot high queue is too many.
- **Path:** ACK-A → Q_HOLD[A]. Blocker token loops in Q_BLOCK[A] (or the shared blocker) keeping Q_HOLD[A]
  starved. RESPONSE-A → enqueue behind ACK-A in Q_HOLD[A] + set `reg_drain[A]`. Blocker reads `reg_drain[A]`
  → dropped → Q_BLOCK[A] empties → Q_HOLD[A] serviced → ACK-A then RESPONSE-A egress L → 1 loopback pass →
  forwarded to Vision (dp9).
- **State:** slot (exact admission), gen, expack, lc_state, reg_drain. **Metadata:** slot_id, gen, role.
- **Internal token:** blocker on Q_BLOCK, marker ethertype, consumed on drain. **Release:** ACK-then-RESP FIFO.
- **Timeout:** blocker pass-cap OR a per-slot residence cap → force drain + BYPASS the held packets, clear state.
- **Resource est.:** 2 queues/slot on L; 1 exact table + ~3 registers; ≈ frozen defense stages minus the
  hash. **Lowest resource.**
- **Failure mode to test:** empty-gap premature release; drain jitter; starvation totality.

### β — IBSPG two-stage (park → release)
- **Queues:** stage-1 `Q_PARK` (blocked, holds ACK-A alone); stage-2 `Q_REL` (release-ordered). RESPONSE-A
  transfers/admits both into Q_REL in ACK-then-RESP order (a fixed 2nd loopback pass), then Q_REL emits.
- **Path:** ACK-A → Q_PARK[A] (blocked). RESPONSE-A → matches → both ACK-A and RESPONSE-A admitted to Q_REL
  (Ditto-style hierarchy, but transaction-gated, no chaff). Q_REL is serviced at line rate (ordering, not
  timing) OR blocked until deadline (HOLD_RESPONSE).
- **More queues** (2 stages) + a transfer pass; **higher resource** than α, but cleaner ordering separation.
- **Failure mode:** the park stage still needs a blocker (same empty-gap question) → α's unknown is a subset.

### γ — recirc-hold reference (baseline only)
- The frozen DCRN mechanism. Included to A/B against α/β for correctness + latency, NOT as the deliverable.

## Selection

**Select α (IBSPG single hold queue)** for the first microbench — it is the lowest-resource construction
that keeps the original queue-resident, uses one internal blocker token, and gives ACK-before-response by
FIFO. β's core uncertainty (the park-stage blocker) is a subset of α's, so proving/refuting α's blocker
primitive resolves both. γ is the baseline.

## Microbench plan (isolate ONE primitive first — the blocker gate)

Before the full paired buffer, the **single load-bearing primitive** to test on silicon is:

> **Does a continuously-occupied internal high-priority queue (blocker) hold a real packet queue-resident in
> a low-priority queue, and does draining the blocker (a data-plane event) release exactly that packet —
> with no premature release (empty-gap) and no external egress of the blocker?**

- Synthetic transaction-tagged packets (a HELD marker + a DRAIN marker), dp9→dp11 through the switch.
- Measure: Q_HOLD/Q_BLOCK enqueue/dequeue/occupancy counters; the held packet's egress timestamp vs the
  drain event; per-port TX on dp9/dp11 = real count exactly (no blocker escape); capture proof.
- **PASS if:** the held packet stays in Q_HOLD until the drain, leaves promptly after, the blocker never
  egresses a protected port, and the empty-gap does not release it prematurely (test ≥2 phased blocker
  tokens if a single token gaps). **On any FAIL:** record honestly, then test β/backpressure variant before
  any impossibility claim.
- Restore `queue_microbench_abs.conf` after the run.

This is the smallest experiment that decides whether the IBSPG family is viable on Tofino-1 silicon.
