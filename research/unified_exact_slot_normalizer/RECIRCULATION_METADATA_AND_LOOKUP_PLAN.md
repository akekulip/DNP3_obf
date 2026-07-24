# Recirculation metadata & lookup plan (Part 4)

Tofino-1 recirculation is the accepted real-packet hold primitive (per `direction.md`). The exact-slot
design's recirc win: subsequent passes index state by a **carried `slot_id`** and never re-derive the flow,
so the admission lookup happens **once** (first pass only) and recirc passes are cheap and unambiguous.

## First pass (frame enters from dp9/dp11)

1. Parse + prologue (dir, flags, payload_len, DNP3 parse — parser-hardened Phase-1; link-only → LINK_OTHER).
2. Canonicalize the flow key from `dir`; look up `flow_admission` → `slot_id`, `policy_mode`, `enabled`,
   `admitted`. Unadmitted/disabled/BYPASS → forward byte-identical, no state, telemetry++ (done).
3. Read/update packed state at `reg_*[slot_id]` for the packet's role (arm READ / qualify+hold ACK / admit
   RESPONSE), per Part 3.
4. If the frame is to be **held**, push the recirc bridge header (below), set egress = dp68 (recirc),
   `qid = QID_HOLD`.

## Recirc bridge header (only what later passes need)

```
header exact_slot_bridge_h {
    bit<16> original_ethertype;   // restored on release (byte identity)
    bit<SLOT_W> slot_id;          // DIRECT register index on every later pass (no re-hash)
    bit<8>  gen;                  // generation stamped at hold-enter; verified each pass
    bit<8>  role;                 // ROLE_ACK / ROLE_RESP
    bit<32> pass_count;           // fail-open cap (bounded residence); timeout safety
    bit<32> deadline_tick;        // HOLD_RESPONSE only: absolute release time (or 0/omitted for HOLD_ACK)
    bit<8>  event;                // release/flush signal to egress (tally + strip)
}
```

`slot_id`, `gen`, `role` are the load-bearing carry. `deadline_tick` is carried for HOLD_RESPONSE so the
recirc pass compares against `now` without re-reading `reg_deadline` (saves a stage) — OR it is read from
`reg_deadline[slot_id]`; the Part-6 prototype picks whichever places better. `pass_count` carries the
timeout so no separate stored timeout field is needed (Part 3).

## Subsequent recirc passes (frame re-enters on dp68)

1. `pass_count++` (in the bridge).
2. **Index `reg_lc[slot_id]` DIRECTLY** using the carried `slot_id` — **do NOT recompute the flow hash or
   re-run admission** (the canonical identity was resolved on pass 1 and is authoritative).
3. **Verify generation:** read live `reg_lc[slot_id].gen`; if `bridge.gen != live gen`, the held frame was
   superseded by a newer transaction re-arming this slot (rapid re-poll, or slot reuse) → **STALE → flush**
   (release to the master port, strip bridge, do NOT act on the newer transaction). This is the exact-
   ownership check that a hashed design would additionally need a fingerprint for; here the slot is exact, so
   generation alone is sufficient and there is **no collision path** to also guard.
4. If fresh (`gen` matches):
   - **HOLD_ACK / ROLE_ACK:** poll `lc_state` for RESP_ADMITTED; if set → release the ACK (state←ACK_GONE),
     egress master port; else recirc again (until pass_count ≥ MAX → fail-open release).
   - **HOLD_ACK / ROLE_RESP:** release only when `lc_state==ACK_GONE` (+ guard) → zero-inversion; else recirc.
   - **HOLD_RESPONSE / ROLE_RESP:** release when `now >= deadline_tick` (carried or `dl_check`); else recirc;
     `pass_count ≥ RESP_MAX` → fail-open.
5. On release: restore `original_ethertype`, strip the bridge (byte identity to the master), signal `event`
   to egress for telemetry; at completion `lc_clear[slot_id] → IDLE`.

## Invariant enforcement via the carried slot + generation

- **No re-hash on recirc** — direct `slot_id` index; deterministic, cheaper, and immune to any hash drift.
- **Reject stale before acting** — generation mismatch → flush, never a release against a newer transaction
  (task invariant 4). Because the slot is *exact* (one admitted flow ↔ one slot), a mismatch means only
  *reuse* (same flow re-armed), never *collision* (two different flows) — a stronger guarantee than the
  hashed design.
- **Bounded residence** — `pass_count` cap guarantees fail-open; no packet can spin forever, and slot state
  is cleared on the fail-open path (task invariant 5/6).
