# IBSPG microbench — mechanism, P4 logic, and instrumentation design

Design reasoning fixed BEFORE writing P4, so the code and the measurements are decided together.
Harness-specific API (qid field, bfrt calls, loopback port, pktgen, counters, compile cmd) is filled
in from the existing `queue_microbench` conventions in `IBSPG_TM_CONFIGURATION.md`.

## 1. What is on the same port matters

TM strict priority arbitrates among the **queues of one egress port**. Therefore Q_BLOCK and Q_HOLD
must be two queues on the **same** egress port — the internal loopback port **L** (an unused
front-panel port in MAC-near loopback, or the pipe recirc port). Assignment is per packet at
enqueue via the ingress-to-TM qid field.

- BLOCKER_TOKEN → egress port L, qid = **Q_BLOCK** (high strict priority)
- HELD_REAL     → egress port L, qid = **Q_HOLD** (low strict priority)

While Q_BLOCK is non-empty, the scheduler always picks Q_BLOCK; Q_HOLD (HELD_REAL) is never
dequeued → HELD_REAL is **TM-queue-resident**, making **zero** passes while it waits. That is the
intended steady state.

## 2. The blocker ring

A BLOCKER_TOKEN dequeues from Q_BLOCK → egresses L → loops (L in loopback) → re-ingress → P4
re-enqueues it to Q_BLOCK. Continuous internal ring; never egresses a protected port. Seeded once
(pktgen one-shot if available, else a one-time host seed) with N tokens for slot s, generation g.

**Drain:** when `reg_drain[s]==1`, a returning BLOCKER_TOKEN for slot s is **dropped** (not
re-enqueued). After all N drop, Q_BLOCK empties → strict priority services Q_HOLD → HELD_REAL
dequeues → returns via L → (drain set) → forwarded to the protected destination.

## 3. The empty-gap, and the key instrumentation insight

**Empty-gap:** when a token dequeues and is in flight (egress+loopback+re-ingress latency `T_loop`),
Q_BLOCK is momentarily one shorter. If *all* tokens are simultaneously in flight, Q_BLOCK is empty
and the scheduler can service Q_HOLD before drain — the load-bearing risk. Whether this happens
depends on N vs (tokens dequeued during `T_loop`) and on Q_BLOCK shaping — a **silicon** question.

**Insight — the P4 gate converts a would-be escape into a counted re-hold.** HELD_REAL is released
to a protected port **only if `reg_drain[s]==1`**. So a premature dequeue during an empty-gap does
**not** escape: at re-ingress with drain still 0, the packet is **re-enqueued to Q_HOLD** and a
counter `ctr_held_rehold` increments. Therefore:

- **Premature protected egress before drain is structurally impossible** (gated on reg_drain). We
  still verify it on the wire (capture), but the P4 cannot emit it.
- **`ctr_held_enq − (HELD injected)` is a direct, exact empty-gap detector.** The final P4 routes
  HELD purely by the drain bit (no ingress-port dependency, so on-chip pktgen works), and
  `ctr_held_enq` counts EVERY hold-routing. If 1 HELD is injected and `ctr_held_enq == 1` before
  drain ⇒ HELD never left Q_HOLD ⇒ true zero-pass residency. `ctr_held_enq == 1 + k` ⇒ the gap
  occurred k times ⇒ HELD circulated k times (a bounded, measured violation of "no repeated
  circulation"). This is the quantity Part 5 minimizes over the blocker variants / token counts.

So the honest PASS/PARTIAL framing for the empty-gap experiment:
- **PASS (no-gap):** `ctr_held_rehold == 0` across all trials for a given (variant, N) ⇒ residency is
  true zero-pass. Report the minimum safe N / backlog / shaping that achieves it.
- **PARTIAL (bounded leakage):** `ctr_held_rehold > 0` but bounded and no protected egress ⇒
  measurable empty-gap; HELD_REAL circulates at a low rate. Report the rate.
- **REFUTED:** Q_HOLD serviced (rehold or, worse, escape) even with the largest justified N and
  shaped backlog ⇒ a no-gap blocker cannot be maintained.

## 4. Ingress logic (fixed single slot s=0 for the first prototype)

```
role==BLOCKER_TOKEN:
    if reg_drain[s]==1 : drop            ; ctr_blk_drop++      // ring dies after drain
    else               : to L, qid=Q_BLOCK; ctr_blk_loop++     // keep ring alive
role==HELD_REAL:
    if ig_port != L    : to L, qid=Q_HOLD ; ctr_held_enq++     // fresh host inject -> hold
    else (returned):                                            // dequeued from Q_HOLD
        if reg_drain[s]==1 : to PROTECTED_DEST; ctr_held_release++   // release, bytes intact
        else               : to L, qid=Q_HOLD ; ctr_held_rehold++    // empty-gap -> re-hold (measured)
role==DRAIN_MATCH:
    if slot==s && gen==reg_gen[s] : reg_drain[s]=1 ; ctr_drain_match++
    drop (control event consumed)
role==DRAIN_UNRELATED:            : ctr_drain_unrel++ ; drop      // never sets reg_drain
```

State: `reg_drain[NUM_SLOTS]`, `reg_gen[NUM_SLOTS]` (armed; fixed g for first experiment).
Counters (per role + blk_loop/blk_drop/held_enq/held_release/held_rehold/drain_match/drain_unrel).

## 5. Byte-identity and metadata

The synthetic microbench header rides in its own ethertype; HELD_REAL is released **byte-identical**
(no internal bridge header on a protected egress — same deparser discipline validated in GATE-1). In
the DNP3 integration phase the MB header is replaced by real DNP3 classification; the release path
still strips any internal-only metadata before a protected egress.

## 6. Visibility proof (Part 7) is built in

BLOCKER_TOKEN carries a **private marker** (reserved ethertype + reserved src MAC). Capture on dp9
and dp11 for the whole run must show **zero** frames with that marker; dp9/dp11 TX == REAL-packet
count exactly; the loopback port's internal counters carry the token traffic. Any marker seen on a
protected port = FAIL (not relabeled).

## 7. Why this is not refuted by the direct-primitive audit

No data-plane write to TM config; strict priority is static (set once at init). The response/drain
event changes **queue occupancy** (drops the blocker; the original is admitted to Q_HOLD once), not
TM configuration. The original stays queue-resident; only the internal token rings. Exactly the gap
the capability audit left open.
