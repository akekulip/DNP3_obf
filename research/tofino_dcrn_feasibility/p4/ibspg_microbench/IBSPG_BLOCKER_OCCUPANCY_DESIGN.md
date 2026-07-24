# IBSPG blocker-occupancy variants (Part 3)

The load-bearing risk is the **empty-gap**: an instant when Q_BLOCK is empty lets strict priority
service Q_HOLD before drain. The four variants differ only in *how Q_BLOCK is kept non-empty*. A/B/C
run on the **already-compiled** `ibspg_mb.p4` (they differ only in seed count `N` and an optional
Q_BLOCK shaper — both control-plane); D needs a small P4 extension (`ibspg_mb_ondemand.p4`).

Definitions: `T_loop` = a token's egress+loopback+re-ingress+re-enqueue latency on port L.
`R_deq` = the rate at which the strict-priority scheduler dequeues Q_BLOCK when it is the highest
non-empty queue (≈ line rate of L for small frames, unless shaped). A gap occurs when **all** tokens
are simultaneously in flight, i.e. when `N < R_deq · T_loop` (tokens leave faster than they return).

## A — Single looping blocker token (control experiment)

- **Seed:** `N = 1`. **P4:** existing. **Config:** strict priority only, no shaper.
- **Expectation:** exposes the empty-gap. With one token, every dequeue empties Q_BLOCK for the
  whole `T_loop` round-trip; if the scheduler services Q_HOLD within that window, HELD_REAL dequeues
  prematurely (caught as `ctr_held_rehold`, never an escape). A is expected to **fail** the no-gap
  bar and thereby *measure* `T_loop` and the scheduler's willingness to service during the gap.
- **Purpose:** the control that proves the gap is real and quantifies it, not a candidate to ship.

## B — Multiple phased blocker tokens

- **Seed:** `N ∈ {2, 4, 8, …}`, phased so their dequeue instants are staggered (seed with small
  inter-token spacing, or let the ring self-phase). **P4:** existing. **Config:** strict priority
  only.
- **Mechanism:** with `N ≥ ⌈R_deq · T_loop⌉ + margin`, at least one token is always enqueued in
  Q_BLOCK → depth ≥ 1 at all times → no gap → HELD_REAL never dequeues (true zero-pass residency,
  `ctr_held_rehold == 0`).
- **Test:** sweep N upward; find the **minimum safe N** where `ctr_held_rehold == 0` across repeated
  trials (Part 5). Report N, and the implied `R_deq · T_loop` product.
- **Cost:** N tokens continuously loop → N·(frame) per `T_loop` of loopback bandwidth (Part 8).

## C — Multiple tokens with Q_BLOCK shaping (deliberately backlogged)

- **Seed:** a modest `N`. **P4:** existing. **Config:** add a Q_BLOCK **max-rate shaper**
  (`sched_shaping`, PPS/UPPER) so `R_deq` is *capped below* the token loopback replenish rate.
- **Mechanism:** shaping throttles how fast tokens leave Q_BLOCK; returning tokens then accumulate →
  Q_BLOCK stays **persistently backlogged** (depth grows to a steady backlog), so it is never empty
  even though `T_loop` is nonzero. This decouples no-gap-ness from the exact N↔`T_loop` race of B.
  Explicitly **discards the sparse-flow assumption** — this queue is meant to be backlogged.
- **Trade-off:** the shaped dequeue rate adds **drain latency** — after drain stops replenishment,
  the backlog drains at the shaped rate before Q_HOLD is serviced. Measure drain-to-release vs shape
  rate (Parts 5/6). Also watch Q_BLOCK **overflow → token drop** (self-defeating: ring shrinks);
  cap backlog / size depth if seen (Part 4 note in TM config §4).
- **Test:** find a shape rate + N that gives `ctr_held_rehold == 0` with acceptable drain latency and
  no token drops.

## D — On-demand blocker ring (created at ARM, consumed at drain)

- **Goal:** no permanent loopback cost when idle; the ring exists only while a transaction is armed.
  This is the **preferred** end-state (Part 8) but an optimization *after* the primitive is proven.
- **P4 extension (designed here; file `ibspg_mb_ondemand.p4` to be built at Part 8, NOT yet
  implemented):** on an ARM frame for slot s, replicate the seed into Q_BLOCK **N-fold** using
  packet replication (multicast group `mcast_grp_L_N`, configured once at init, with N members all
  egressing port L at qid Q_BLOCK), instead of pktgen/host seeding. Each replica is rewritten to a
  token (ethertype 0x88C1, role=BLOCKER) in **egress** — the one place D re-enables egress
  processing, which the A/B/C build bypasses — and self-loops (existing blocker logic). On
  DRAIN_MATCH the tokens drop (existing) → ring self-destructs; verify **zero tokens remain** after
  completion.
- **Replication choice:** multicast (deterministic N copies, one configured group) is preferred over
  mirror/clone (one copy per session). If mirror/clone is used instead: configure the session once,
  keep all copies internal, prove none appears on dp9/dp11, do not alter the original.
- **Isolation requirement (same as tokens):** every replica carries the private token marker
  (0x88C1 + reserved MAC); the ARM frame itself is consumed (dropped) after triggering replication.
- **Test:** ARM→ring-forms (Q_BLOCK occupancy rises to ~N), drain→ring-dies (occupancy→0, no token
  on dp9/dp11, no residual loop), then idle loopback cost ≈ 0 (Part 8 confirms).

## Comparison

| Variant | seed | P4 | Q_BLOCK shaper | gap prevention | idle cost | drain latency | first-test role |
|---|---|---|---|---|---|---|---|
| A single | N=1 | existing | no | none (control) | 1 token/loop | ~T_loop | control (expose gap) |
| B phased | N=2,4,8 | existing | no | N ≥ R_deq·T_loop | N tokens/loop | ~T_loop | **primitive candidate** |
| C shaped | small N | existing | yes | persistent backlog | N tokens/loop (shaped) | + shape drain | backlog candidate |
| D on-demand | N via mcast at ARM | `_ondemand` | optional | B or C while armed | **~0 when idle** | as B/C | Part 8 optimization |

## Selection for the first silicon experiments

Parts 4–5 run **A** (control, to measure the gap and `T_loop`) then **B** (sweep N to find the
minimum gap-free token count), then **C** if B needs an impractically large N. **D is deferred to
Part 8** (its gap behavior is identical to B/C while armed; its only new property — on-demand
create/destroy — is a cost optimization that only matters once the primitive itself passes). This
ordering follows the direction's own gate structure (Part 8 evaluates on-demand vs permanent).
