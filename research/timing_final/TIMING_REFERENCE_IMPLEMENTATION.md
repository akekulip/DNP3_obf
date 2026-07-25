# TIMING_REFERENCE_IMPLEMENTATION.md — canonical timing normalizer (directive §2 + §3)

The frozen reference for the one-week timing deliverable. Timing-only: size normalization is removed
(preserved on other branches, not built here). This document is the authority for the mechanism; the
experiment campaign, analysis, and tutorial all refer back to it.

## Provenance

- **Program:** `research/timing_final/p4/dnp3_timing_normalizer.p4`
- **Source SHA-256:** `d6fcd530ef73f9607b73f3f7a34691f0ea06881208cf79f187c28faa0984537c`
- **Derived from:** `research/stage_reclamation/variants/p12_combined/p12_combined.p4` — its ingress kept
  verbatim (packed state + classifier + timing); its egress size path removed; the byte-preserving
  egress pass-through from `research/ibspg_dnp3_replay/p4/ibspg_dnp3/ibspg_dnp3.p4` substituted; the
  §3 G-selection guard added.
- **Base branch:** `research/timing-final-meeting`.
- **Compile (verified independently by the main session, both toolchains):**
  local bf-p4c 9.13.1 and on-switch 9.13.2 (non-destructive, `bf_switchd` left on
  `queue_microbench`) → **0 errors, 3 benign warnings, 10/12 ingress stages, 0 egress stages,
  critical path 8**, byte-identical source on both hosts. No 9.13.1→9.13.2 drift.

## Architecture

An inline Tofino-1 normalizer of the DNP3 ACK→response interval (Formby CLRT). The response is held
**queue-resident** in a low-priority Traffic-Manager queue, starved by a high-priority reservoir of
internal recirculating "blocker" tokens, and released on a **data-plane deadline** `t_ack + G`. No
controller acts in the transaction fast path; no external chaff; the original response never
continuously recirculates. The emitted interval becomes a policy constant `G`.

Ports (compile constants; the run pins measured dev_ports): `PORT_VISION` dp9 (master side, dir 0),
`PORT_HULK` dp11 (outstation side, dir 1), `PORT_L` dp8 (internal MAC-near loopback, blocker/hold).

## Packet roles (parser-assigned)

| role | value | source | action |
|---|---|---|---|
| `ROLE_BYPASS` | 0 | any non-transaction frame | forwarded unchanged |
| `ROLE_BLOCK` | 1 | ethertype `0x88C1` (internal token) | enqueue Q_BLOCK (qid7); deadline-checking |
| `ROLE_RESP` | 2 | DNP3 RESPONSE, fc 129, outstation→master | enqueue Q_RESP (qid1); released later |
| `ROLE_ARM` | 6 | DNP3 READ, fc 1, master→outstation | takes the tag, clears the deadline; forwarded |
| `ROLE_ACK` | 7 | pure TCP ACK, outstation→master | forwarded **now**; arms the deadline |

## State machine

`IDLE → ARMED` (READ) `→ ACK_QUALIFIED` (matching pure ACK arms deadline `t_ack+G`) `→ RESPONSE_HELD`
(response enqueued to Q_RESP, starved by the blocker reservoir) `→ DEADLINE_RELEASE` (blocker tokens
observe `now ≥ deadline`, self-terminate; reservoir drains; strict priority serves Q_RESP) `→ CLEANUP
→ IDLE`. `FAIL_OPEN` is entered instead when a blocker exhausts its pass budget. Stale / unrelated
packets are bypass paths that do not change state.

## Register layout (9)

| register | width | purpose |
|---|---|---|
| `reg_tag` | 8 | packed generation + active bit; difference-SALU (`==0` = "active AND my generation") |
| `reg_deadline` | 32 | `t_ack + G` (ns); bit 0 is the armed marker; expiry via sign-bit ternary |
| `reg_t_ack` | 32 | shadow of `t_ack`, for computing native CLRT (returns `now − v`) |
| `reg_native_clrt` | 32 | **G-guard:** measured `t_response_arrival − t_ack`, control-plane readable |
| `reg_protection` | 8 | **G-guard:** 1 if `native_clrt < G` (protection applied), else 0 (low-G) |
| `reg_ts_first_block` | 32 | timeline: first blocker admitted |
| `reg_ts_ack_arm` | 32 | timeline: t_ack |
| `reg_ts_block_term` | 32 | timeline: first blocker termination |
| `reg_ts_first_resp_release` | 32 | timeline: first response released |

All per-transaction dynamic state is in registers, never in match-action tables (which hold only
static logic: fc allowlist, qid map, policy, and the sign-bit compares).

## Queue mapping (control plane sets strict priority; P4 only sets qid)

`Q_BLOCK` qid7 `max_priority` HIGH (7) > `Q_RESP` qid1 `max_priority` LOW (0), on the dp8 loopback.
Two levels suffice — the ACK is never queued. While the reservoir occupies Q_BLOCK, strict priority
starves Q_RESP; when it drains, Q_RESP is served.

## Release causes (exhaustive)

1. **Deadline** — blocker tokens self-terminate once `now ≥ deadline`; reservoir drains; response
   released. Counted `ctr_release_deadline` (per-release) and `ctr_block_term_deadline` (per-token).
2. **Fail-open** — a blocker exhausts its pass budget (`hdr.ib.seq → 0`); the response is force-released
   and state cleared. Counted `ctr_release_fail_open` / `ctr_block_term_timeout`.
There is **no drain packet and no controller release** — no injected packet can cause a release, only
the deadline or the budget.

## G-selection guard (§3)

At response admit: `native_clrt = now − t_ack` (via `reg_t_ack`'s difference-SALU), stored in
`reg_native_clrt`. `protection = (native_clrt < G)` computed as `native_clrt − G` then a **sign-bit
ternary** `tbl_clrt_guard` (mask `0x80000000`, same technique as the deadline expiry — no bit-slice),
stored in `reg_protection`. Counters:
`ctr_response_before_deadline` / `ctr_response_at_or_after_deadline` (response arrival vs deadline),
`ctr_response_actually_held` / `ctr_response_zero_hold` (protection vs low-G), and
`ctr_release_deadline` / `ctr_release_fail_open`. Semantics enforced: if `native_clrt ≥ G`,
`effective_hold = 0`, `protection_applied = false`, `low_G_warning = true` — **the system does not
pretend a transaction is normalized when the response arrives at or after the deadline.** The guard
added +2 ingress stages (8→10) and did **not** lengthen the critical path (stays 8).

## Parser-hardening rules (carried from the validated classifier)

- A pure TCP ACK (zero payload) is **never** DNP3-extracted — it is classified `ROLE_ACK` and
  forwarded. (This is the historic bug that dropped ACKs; fixed and proven on the live relay.)
- DNP3 magic `0x0564` required before transport/application extraction; two-gate length check
  (`ipv4.total_len ≥ 20 + 4·data_offset + 13`, then DNP3 LEN ≥ 8).
- A `LEN == 5` link-only frame is valid `ROLE_BYPASS`, never dropped.
- TCP `data_offset` **5–8** supported — the live SEL-751 uses 8 (RFC 7323 timestamps).
- The internal token ethertype `0x88C1` is **forced** to `ROLE_BLOCK` in the parser regardless of the
  role byte, so a token can only ever reach `to_block()` or `drop_pkt()`.

## Known limitations (claim discipline, §10)

- Closes / substantially reduces the **CLRT-magnitude** channel only. **ACK mode** (separate vs
  combined) and **TCP-stack features** (TTL/MSS/window/options) remain separate fingerprinting
  channels (both ~1.0 balanced accuracy across the corpus devices). **Not** device anonymity.
- **G must exceed the native interval.** If `native_clrt ≥ G` the hold is zero; the G-guard now
  detects and counts this rather than hiding it.
- Byte-preserving for the DNP3 payload; size is **not** normalized (out of scope this week).
- Validated by replay of real relay frames through the switch and on synthetic markers; a live inline
  relay session (the relay's own TCP stack tolerating the hold in real time) needs physical
  re-cabling and is not claimed.

## Byte preservation

Ingress emits headers in extraction order and writes only `hdr.ib.seq` (the blocker token's own pass
budget). The egress MAU is empty (`apply { }`) and the egress deparser re-emits the frame unchanged,
so a released ACK or RESPONSE egresses byte-identical to what was enqueued.
