# Packed transaction state layout (Part 3)

The smallest correct per-slot state, indexed by `slot_id` (from `flow_admission`). Design goal: minimize
register *width* and the number of *stage-local RegisterActions*, without removing generation or exact
ownership checking. Tofino-1 reality: a `RegisterAction` performs ONE read-modify-write on ONE register
cell with ONE ALU op; fields that need *independent conditional updates in the same packet* generally need
separate registers (this is why frozen `dcrn_defense1.p4` uses 5 registers). Packing is therefore
"minimum register actions," not "one action for everything."

## Logical fields and minimal encoding

| Logical field | Min bits | Notes / reduction |
|---|---|---|
| valid/armed | folded into `lc_state` | not a separate bit |
| generation (epoch) | 8 | mod-256; slot reuse + recirc staleness |
| active policy mode | 0 (in state) | carried from `flow_admission` action (`meta.policy_mode`), NOT stored per-slot — it's static per flow |
| expected TCP ACK | 32 | request end-seq; compare-in-SALU at the pure ACK |
| DNP3 app sequence | 4 | optional intra-flow response↔request tiebreak (0–15 wrap); include only if one-outstanding is not sufficient |
| lifecycle state | 3 | enum: IDLE(0) ARMED(1) ACK_HELD(2) RESP_ADMITTED(3) ACK_GONE(4) COMPLETE(5) — replaces separate resp_seen/ack_released/response_released booleans |
| response_seen | folded into `lc_state` (RESP_ADMITTED) | derived, not stored |
| ack_released | folded into `lc_state` (ACK_GONE) | derived |
| response_released / completion | folded into `lc_state` (COMPLETE) | derived |
| ACK timestamp / deadline (HOLD_RESPONSE) | 32 | store the absolute `deadline_tick = t_ack + G` (one value, not both t_ack and G); HOLD_RESPONSE only |
| timeout / pass-limit | 0 in state | carried in the recirc bridge `pass_count` (Part 4); not a separate stored field |
| held_qid | 0 | ELIMINATED — qid is fixed by packet role (QID_HOLD for held, default for release), not per-slot state |

## Register map (minimum stage-local actions)

Three registers, each `slot_id`-indexed (array size = 2^SLOT_W, e.g. 1024 — **64× smaller than the frozen
65536**):

1. **`reg_lc` : bit<16>** = `{ gen[15:8], lc_state[7:5], reserved[4:0] }`.
   - RegisterActions: `lc_arm` (on READ: `gen++`, set state=ARMED — two sub-updates; realized as one SALU
     that writes `{gen+1, ARMED}` since both are functions of the read value → **one action**), `lc_read`
     (return gen+state), `lc_set_state` (transition), `lc_clear` (→ IDLE at complete/timeout).
   - Packing `gen`(8) and `lc_state`(3) in one 16b word lets a single RegisterAction read both (for the
     generation check) and, where the update is a pure function of the current value, write both at once.
     Transitions that depend on *another* register's result (e.g. ACK match) are a second action.
2. **`reg_expack` : bit<32>** = expected ACK. Actions: `expack_set` (@arm), `expack_match` (compare vs
   `tcp.ack_no` → 1-bit result, @pure-ACK). Separate because 32b compare is its own SALU.
3. **`reg_deadline` : bit<32>** = absolute deadline tick (HOLD_RESPONSE only). Actions: `dl_set` (@ACK:
   `now + G`), `dl_check` (compare `now >= dl` → 1-bit, @recirc). Elided entirely in a HOLD_ACK-only build.

`app_seq` (if used) folds into `reg_lc` reserved bits (4b) or a 4th tiny register; include only if tests
show one-outstanding-per-flow is insufficient.

## Fields read/written per packet class

| Packet class | reg_lc | reg_expack | reg_deadline | notes |
|---|---|---|---|---|
| **READ (arm)** | `lc_arm`: gen++, state←ARMED (W) | `expack_set` (W) | — | slot from admission; only if `enabled` & policy≠BYPASS |
| **PURE ACK** | `lc_read` gen+state (R); if qualify → state←ACK_HELD (HOLD_ACK) (W) | `expack_match` (R, compare) | HOLD_RESPONSE: — (ACK forwarded); `dl_set` (W) | qualify = ARMED ∧ flags_ok ∧ ack==expack |
| **RESPONSE** | `lc_read`; HOLD_ACK → state←RESP_ADMITTED (W); HOLD_RESPONSE → (hold) | — | HOLD_RESPONSE: (enqueue to hold; deadline already set) | not-abort gate |
| **RECIRC pass** | `lc_read` gen (R) → compare to bridge.gen; state read; conditional transition (W) | — | HOLD_RESPONSE: `dl_check` (R) | index by carried `slot_id`, NOT re-derived (Part 4) |
| **Completion** | `lc_clear` → IDLE (W) | (no clear needed; overwritten next arm) | (stale past-deadline reads released) | after confirmed egress of required packet(s) |
| **Timeout / fail-open** | `lc_clear` → IDLE (W) | — | — | pass_count ≥ MAX in bridge → force release + clear |

## Estimated stage placement (confirmed in Part 6)

- `reg_expack` set/match and `reg_lc` arm/read are the frozen defense's own placements (stages ~3–5).
- Removing the CRC flow-hash and using a **direct `slot_id`** index (no hash-to-index) shortens the
  dependency chain into the registers. Removing `flow_has_held_ack`/`reg_ack_gone`/`reg_resp_seen` as
  *separate* registers (folded into `reg_lc.lc_state`) removes register touches — the exact hypothesis for
  fitting generation enforcement (which did NOT fit on the frozen 5-register hash design) within 12 stages.
- **Do NOT** drop `gen` or the `expack` compare to make it fit — those are the ownership/freshness guarantees.
  If the packed design still exceeds 12 stages, reduce `reg_deadline` to a HOLD_ACK-only build first, or fall
  back to the frozen register split, before touching correctness.
