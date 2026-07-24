# Unified transaction state machine — GridCloak queue-resident timing normalizer (Part D)

One transaction-aware state machine with three timing branches (BYPASS / HOLD_ACK / HOLD_RESPONSE) plus
COMPLETE and TIMEOUT/FAIL_OPEN. This is the **logical** model — mechanism-agnostic; it defines WHAT must
happen per transaction and the invariants that must hold. Whether a queue-resident release can implement
the release actions is the separate capability question (Parts B/E/F). Grounded in the already-silicon-
tested transaction core (`txncore/`, Phase-2) and the frozen defenses' proven qualification logic.

## Transaction key (derived from the tested transaction core)

The txncore already validated a per-flow key on silicon; the unified model reuses it and adds only fields
that prevent a specific ambiguity:

| Field | Purpose | Prevents |
|---|---|---|
| `flow_id = CRC16{client_ip, server_ip, client_port}` | canonical bidirectional per-flow index (same for req/resp) | cross-flow mixing |
| physical direction (`dir` from ingress port) | master(dir0)=dp9 vs outstation(dir1)=dp11 | mislabeling a response as a request and vice-versa (silicon-proven in GATE-1) |
| DNP3 function code (`d_func`) | READ(1)=arm, RESPONSE(129)=complete | treating a non-READ/RESP as a transaction event |
| `exp_ack = req.seq + req.payload_len` | the pure ACK we hold must ack exactly the request end-seq | releasing on a keepalive / window-update / stale ACK |
| generation / epoch (`gen`, mod 256) | disambiguates flow_id reuse (rapid 2nd request, 16-bit hash collision) | a stale straggler releasing/matching a newer transaction |
| DNP3 application sequence (`d_appseq`) | secondary correlation of response to request (0–15 wrap) | matching a response to the wrong outstanding request within a flow |
| timeout tick | bound on queue residence | permanent queue residence / stale state |

No field is added without a named ambiguity it removes (above). TCP seq/ack give the exact ACK match;
`flow_id`+`gen` give flow identity+freshness; `d_func`+`dir` give role; `d_appseq` is the intra-flow
response↔request tiebreak under the one-outstanding rule.

## States

- **BYPASS** — forward with no timing change. Entered for: non-DNP3 / non-transaction traffic; combined-ACK
  devices (no separate ACK to normalize); any frame once a correction is not required.
- **HOLD_ACK** — the separate pure ACK is held (queue-resident) until its matching DNP3 response is
  available; then the ACK is released, and the response follows it (ACK-before-response). Collapses the
  ACK→response CLRT toward ~0.
- **HOLD_RESPONSE** — the ACK is forwarded immediately (record `t_ack`); the response is held (queue-
  resident) until an ACK-relative deadline `t_ack + G`; then released. Sets a fixed, device-independent CLRT.
- **COMPLETE** — both required releases confirmed to have entered the release/egress path; state cleared.
- **TIMEOUT / FAIL_OPEN** — a bound expired; release/forward safely, clear stale state, record the event.

Exactly one of HOLD_ACK / HOLD_RESPONSE is the active policy per deployment (they are branches of one
machine, selected by a runtime policy register; both cannot hold the same packet).

## Register fields (per `flow_id` index; dynamic state — NOT match-action tables)

| Register | Width | Set | Read/Cleared |
|---|---|---|---|
| `armed` | 1 | on READ arm | read@ACK/response; cleared@complete/abort/timeout |
| `gen` | 8 | bumped@arm | stamped on held frame; compared@release |
| `exp_ack` | 32 | @arm (req end-seq) | matched@pure-ACK |
| `t_ack_tick` | 32 | @ACK (HOLD_RESPONSE) | base for deadline |
| `deadline_tick` | 32 | @ACK (HOLD_RESPONSE: t_ack+G) | compared@response release |
| `resp_seen` | 1 | @response admit | polled@ACK release (HOLD_ACK) |
| `ack_released` | 1 | @ACK egress-confirm | gate for response release (ordering) |
| `response_released` | 1 | @response egress-confirm | gate for completion |
| `held_qid` | 4 | @hold-enter | which TM queue holds the packet (for release/accounting) |

Per-transaction dynamic state lives in these registers (or another documented stateful primitive), never
in match-action tables. Match-action tables carry only static logic (fc allowlist, qid map, policy).

## Lifecycle (transition actions)

- **READ (dir0, dst 20000, fc-allowlisted):** create/arm — `gen++`, `armed=1`, `exp_ack=seq+plen`, clear
  `resp_seen/ack_released/response_released`. Forward the READ unchanged (never held).
- **PURE ACK (dir1, src 20000, payload==0, flags_ok, ack==exp_ack, armed):**
  - HOLD_ACK: enqueue the ACK in `Q_ACK_HOLD` (stamp `gen`, record `held_qid`); do not egress yet.
  - HOLD_RESPONSE: forward the ACK immediately; record `t_ack_tick`, set `deadline_tick=t_ack+G`.
  - a non-qualifying / duplicate / FIN-RST ACK is forwarded unheld (one-shot latch as in the frozen core).
- **RESPONSE (dir1, src 20000, payload>0, armed, not-abort):** associate with the same transaction (same
  `flow_id`+`gen`).
  - HOLD_ACK: set `resp_seen=1` → this must make the held ACK eligible for release; the response is
    ordered to follow the ACK (either enqueued behind it after ACK release, or gated on `ack_released`).
  - HOLD_RESPONSE: enqueue the response in `Q_RESPONSE_HOLD` until `now >= deadline_tick`.
- **ACK release:** confirm the ACK entered the release/egress path → set `ack_released=1`.
- **RESPONSE release:** permitted only when the ordering rule holds — HOLD_ACK: `ack_released==1`;
  HOLD_RESPONSE: `now >= deadline_tick`. Set `response_released=1`.
- **Completion:** clear transaction state ONLY after both required releases are confirmed
  (`ack_released && response_released`, or the single required release for the active branch).
- **Timeout:** on `now - arm_tick > T_max` (or a bounded pass/again check), FAIL OPEN — release/forward any
  held packet, clear `armed`+state, record a timeout event. Never leave a packet queue-resident forever.

## Invariants (must hold; each maps to a test in Part G)

1. An **unrelated response never releases an ACK** — release requires `flow_id`+`gen`+`exp_ack` match.
2. An **unrelated ACK never releases a response** — same keyed match.
3. **ACK is never transmitted after its corresponding response** — response release gated on
   `ack_released==1` (HOLD_ACK) or the ACK already egressed (HOLD_RESPONSE). Zero-inversion, as in the
   frozen defenses.
4. **One transaction cannot release another transaction's packet** — per-`flow_id` state + `gen` +
   per-transaction queue mapping (Part E); a straggler with a stale `gen` is discarded, not released.
5. **Timeout cannot leave stale queue or register state** — the timeout path force-releases the held
   packet and clears the flow's registers.
6. **State is not cleared merely because a match occurred** — clearing requires *confirmed egress* of the
   required packet(s) (`ack_released`/`response_released`), not just a classification.
7. **Valid non-target traffic remains transparent** — BYPASS forwards byte-identically (Phase-1 property),
   including DNP3 link-only frames (the parser-hardening fix), unrelated flows, and combined-ACK devices.

## The one open dependency (answered by Parts B/E/F)

Every branch needs a **release primitive**: a way to make a specific queue-resident packet become eligible
for dequeue on (HOLD_ACK) a data-plane **event** (`resp_seen` set by the matching response) or
(HOLD_RESPONSE) a **deadline** — with no controller in the fast path, no external chaff, and no continuous
recirculation of the original packet. This state machine is correct and testable regardless of the
mechanism; the capability audit (Part B) and feasibility matrix (Part F) decide whether/how a Tofino-1 TM
queue can provide that release. If it cannot, invariants 1–7 still define the target, and the honest
outcome is recorded rather than a mechanism forced.
