# Close-path defect (residency_shape_01/prod_shape): localization, red vector, proposed fix (2026-10-11)

Design and model only. **No production P4 is changed by this record.** The proposed fix was prototyped on
scratch copies (generated text patched in memory, `prototype/prototype_fix.py`), compiled, and model-run; it
is to be applied at the generator and compiled into the full composite only after review.

## What the bytes show (prod_shape, my own parse of out.pcap / in.pcap)

- Last OPERATE response: outstation native seq 507958250, 37 B, so the native frontier is **507958287**. The
  master received every response padded and has ACKed the padded frontier **507958419**; the difference,
  132 B, is the accumulated padding growth.
- Client FIN+ACK was sent twice (out 50, 52; seq 1285095411, ack 507958419). One returned (in 50, ack
  translated to 507958287).
- The outstation's FIN+ACK was sent three times (out 54, 56, 58) and returned three times (in 52-54), **all at
  native seq 507958287**: behind the master's frontier, so the master ignores them.
- The master's three pure ACKs (out 55, 57, 59) were never returned. The outstation's retransmitted OPERATE
  response (out 51) was not returned either.
- `wire_check.py out.pcap in.pcap` exits **1**. Unmatched sent: 51, 52, 54-59. Unmatched returned: 52-54.
  Each one is explained below.

## 1. Trace (file:line, current committed program 8efae4002)

Server FIN (O->M), in the order it happens after the client FIN has put N in phase 7 (`0x70001`).
Reproduced in the model (`model_close_02`, `server_fin_bypass_log_excerpt.txt`, packet `0x27`):

1. It arrives on the outstation port in **a single ingress pass** (no recirculation). `ports` routes it
   (`route`) and `connection` matches `reverse_flow`, so `m.output_port = 9`. `guard` gives `go_keep(4)`.
2. `snapshot_t` (n_response_only.p4:237) **misses**, so its default action `snapshot()` runs
   (**n_response_only.p4:236**; generator: handshake.p4:126, generate.py:306). `snapshot()` prepares a
   recirculation lap: `tm.ucast_egress_port = RETURN_PORT; tm.bypass_egress = 1w1`.
3. `first_event` (stage 11) has `kind = 4, observed = 0x70001` and hits its catch-all row
   **`(8w4,_,_,_):close_forward()`** (n_response_only.p4:258; generator: generate.py:334-368, "first_* rows,
   then forward_original rows, then close_forward").
4. `close_forward()` (**n_response_only.p4:255**, generator **generate.py:368**) strips the envelope and sets
   `tm.ucast_egress_port = m.output_port` (9). **It does not clear `bypass_egress`**, which is still 1 from
   step 2.
5. The frame leaves as **`Tx Pkt to port 9 (Bypass Egress)`**, seq on the wire `0x000003cf` = 975 (native).
   Pipe-0 egress (E) never runs, so E's forward translation never sees it.

E itself handles a FIN correctly when it does see one:
- `leff_t` gives a FIN leff = ip.len - 39 = 1 (e_response_only.p4:238).
- The forward gate admits SH_ACK and SH_NOACK (:539), and a bare FIN+ACK is SH_ACK.
- `classify_fwd` (:401) at front_ret = 0, grant = 0 gives `out_translate`.
- `img_wend_t` (:442) then runs `do_wend_fwd` (:440), so seq = img_wend + q = the padded frontier.
- The software oracle agrees (`case4_response_mapper.py:77`, `leff = length + fin` at :88, translate when q >= 0).

So the bug is routing, not mapping. **N's single-pass `close_forward` departure inherits the recirculation
bypass and skips E.**

Why the client FIN was fine:
- Master packets take the N_ACK_RETURN lap first, and E reverse-maps the ACK on that lap (rev_conn is bound at
  the lap port). In.pcap 50 shows ack 507958419 -> 507958287.
- The client FIN's own seq is native by design, since requests are not padded.
- A bypassed M->O departure is therefore harmless. A bypassed O->M departure is not.

**Which FIN breaks.** Whichever FIN arrives second reaches phase 7 and takes `close_forward`. If the master
closes first, as in prod, the server FIN is second and leaves in native coordinates. *Inference from code,
not model-run:* if the outstation closes first, its FIN takes the emit_reset -> T -> `passthrough_tev_forward`
path. T sets `bypass_egress = 0` (read_queue_timing.p4:851) and forwards to 9 (:497), so E translates it.

Master's ACK of the server FIN (and prod's dup ACKs 55/57/59). Reproduced in the model (`model_close_02`,
final ACK):

- `sequence_diff`/`diff_forward` (n_response_only.p4:191) gives `client_diff = 1, server_diff = 1`.
- N's stored native positions were never advanced for either FIN, and each FIN consumes one sequence number.
- `sequence_guard` (**n_response_only.p4:205**) has only (0,0), (-35,0) and (-1,0), so it misses and
  `sequence_valid = 0`.
- `first_event` has no kind-3 row for phase 7 (its `forward_original` rows cover phases 5, 8, 9, a, b, c), so it
  misses. The `snapshot()` default event `0x01ff` (kind 255) remains.
- After three recirculation passes `read_terminal_t` (n_response_only.p4:340) runs **`terminal_abort`**. The
  ACK is dropped and the outstation never sees its FIN acknowledged, which is why it retransmits the FIN.
- prod's dup ACKs carry ack 507958419, which reverse-maps to native 507958287. That is `(client_diff,
  server_diff) = (1, 0)`, refused the same way.

**First client FIN absent** (unmatched sent 52; prod timing says the first FIN was lost and its ~209 ms
retransmit got through). This is consistent with the RESET-envelope hypothesis below, not proven by it.
- In phase 5 a FIN takes the multi-pass close. The owner CAS to phase 7 happens on the RETURN_PORT 68 passes,
  an internal recirculation port that works on silicon.
- The terminal pass then sends `emit_reset` (n_response_only.p4:338) to T_IN = 180, a front-panel port in MAC
  loopback on the hardware map.
- If the MAC drops that event, N is already in phase 7. The retransmitted FIN then takes `close_forward`
  directly to the outstation (bypass is harmless M->O), with its ACK already mapped on the lap, which matches
  in.pcap 50.
- *Inference.* The outstation's retransmitted OPERATE response (51) is refused by N as a duplicate
  (`count_refused` row for kind 6), consistent with exactly-once delivery. The master already holds the first
  copy. This was not traced on the model.

## 2. FIN sequence accounting and when state may retire

Rules:
- **A FIN consumes one sequence number** in its own direction. RST consumes none.
- **The outstation's FIN** is outstation data: its seq is in native coordinates and must leave translated
  exactly like response data, `seq_out = img_wend + (seq - img_end)` (E's `out_translate`). For the first FIN
  at the native frontier that is the padded frontier. A retransmitted FIN at the same native seq must map to
  the same padded seq; E does this (front_ret < 0, q = 0, `out_translate`).
  - E advances front and acct by leff = 1 on the first copy.
  - **Completing the application data is not a reason to stop translating.** A FIN, and an RST with a
    sequence number, are inside the mapped byte stream.
- **The master's FIN** is native. Its ACK field (and every later master ACK) acknowledges padded positions and
  must be reverse-mapped. The ACK of the outstation's FIN is padded_front + 1, which maps to native_front + 1
  (E `reverse`: r = ack - img_wend = 1, translate). This is why the master's ACKs must still take the lap and
  reach the outstation after the close.
- **N's sequence check must count the FINs.** After the client FIN the master's segments arrive at
  client + 1. After the server FIN the master's ACK covers server + 1. In phase 7 the accepted
  (client_diff, server_diff) are therefore **(1, 0)** before the server FIN is acknowledged and **(1, 1)**
  after. In any other phase these values stay refused.
- **Retire and rearm.** The E slot and N's phase-7 state must stay in place until both FINs are
  acknowledged: the outstation has ACKed client FIN + 1 (native), and the master has ACKed padded server FIN
  + 1. They should also stay through retransmissions: the outstation may resend its FIN until it sees the
  ACK, and the master may resend its final ACK. Until then:
  - every outstation FIN or RST is translated
  - every master ACK is reverse-mapped and forwarded

  After both acknowledgements the slot is retireable. A new connection must re-arm from a fresh SYN-ACK
  (E arms on SYN-ACK). N rearm is the separate open item. RST retires immediately, but an O->M RST's seq must
  still be translated, because the master validates an RST against its receive window (padded).

## 3. RESET-envelope MAC-loopback probe (hypothesis; you run it)

What the model shows leaving on T_IN = 180, hardware map (`model_close_hw`, reflected-frame samples):

| event | frame | first 16 bytes | bytes 12-13 |
|---|---|---|---|
| client close (RESET, dir 1) | 76 B | `00000001 00000001 00000000 0401 0000` | **0x0401** (802.3 length 1025; the frame carries 62 B after offset 14) |
| OPERATE | 105 B | `00000001 00000006 5df5a900 0c00 0000` | 0x0c00 (an ethertype) |

A server close (dir 2) carries 0x0402. READ events carry 0x0900/0x0a00/0x0b00. Only the RESET events are
length-like.

Probe (single close, T off or on; snapshot before and after; dev 180, with dev 48 as the control, since 48
carries ordinary Ethernet frames). Counter names are checked against SDE 9.13.1
`bf_rt_port_tf1.json` `$PORT_STAT`:
- TX side, frames the pipeline sent into the MAC: `$FramesTransmittedOK`, `$FramesTransmittedAll`,
  `$FramesTransmittedLength_65_127`.
- RX side, frames the loopback delivered back: `$FramesReceivedAll`, `$FramesReceivedOK`,
  `$FramesReceivedwithLengthError`, `$FrameswithanyError`, `$FramesReceivedLength_65_127`,
  `$FramesReceivedUndersized`, `$FramesReceivedwithFCSError`.
- Reading:
  - TX +1 with RX OK +1 means the MAC passes it, and the first-FIN loss has another cause.
  - TX +1 with RX All +1 but RX OK +0, and/or LengthError +1, means **the MAC drops the RESET event**
    (hypothesis confirmed).
  - TX +0 means it never left the pipeline.
- Control: one READ request in the same run must show TX +1 and RX OK +1 on 180 (event 0x0900).

If confirmed, the fix is a coordinated change in N and T: give the RESET kind a value >= 6 in N's
`emit_reset` and in T's `KIND_RESET` and `parse_tev` entry, so bytes 12-13 are an ethertype like every
other event. It is not applied here: `read/` belongs to another agent. With the close_forward fix below, a
lost first FIN still recovers on retransmit with correct coordinates.

## 4. Red vector and proposed fix

**Red vector** (`core/response_only/model_drive_sbo_toff.py`, `CLOSE=1`): T off, SELECT and OPERATE
(IIN1 0x90), then the client FIN at the padded frontier, the server FIN at the native seq, and the master's
ACK of the server FIN. Without `CLOSE` the driver is still the 18-check milestone scenario
(`model_milestone_default` 18/18).

| run | program | result |
|---|---|---|
| `model_close_red_default` | sbo_admission_01 default (8efae4002) | **20/23 red**: server FIN 975 (want 1017), still native, final ACK not delivered |
| `model_close_red_hw` | sbo_admission_01 hardware map | **20/23 red**, the same three |
| `prototype_green_default` | prototype, default | **23/23** |
| `prototype_green_hw` | prototype, hardware map | **23/23** |

Earlier runs `model_close` (before the final-ACK check), `model_close_02` and `model_close_hw` used the
driver before the `CLOSE` gate and record the same failures. `model_close_hw` also records the frame
samples on 180.

**Proposed fix**: three edits, all in `make_n.py` as numbered edits, so the legacy native_binding.p4 stays
byte-identical:

1. `close_forward`: append `tm.bypass_egress=1w0;`. Every single-pass close departure then crosses pipe-0
   egress, as `route()` already does in this profile (make_n edit 1). Effect on M->O: E finds no conn row at
   the outstation port and passes the frame unchanged. Effect on O->M: E translates, as shown.
2. `sequence_guard`: add rows `(32w1,32w1):seq_fin()` and `(32w1,32w0):seq_fin()`, and add the action
   `seq_fin(){m.sequence_valid=8w5;}` (size 3 -> 5). Code 5 is new and matches no existing row, so it is
   inert outside phase 7.
3. `first_event`: add `(8w3,8w5,8w0,32w0x70000&&&32w0xffff0000):forward_original()`. The master's ACK after
   both FINs, and its dup ACKs during the half-close, then travel the normal passes and leave unchanged,
   reverse-mapped by the lap.

Prototype results:
- Compiles with stages unchanged: p0 12/11, p1 11/0 on both maps (`prototype/*/logs`). Prototype hardware-map
  build: bfrt.json `be513211...`, p0 `86e28b05...`, p1 `9e93aa84...` (local 9.13.1, not for loading).
- Existing composite scenario 70/70 and response-only suite 71/71 with the patch applied.
- Command-bearing FIN/RST rejection is untouched: it is in native_tcp, before any of this, and
  `fin_operate_retransmission_not_delivered` passes.
- Exactly-once is unchanged: the OPERATE is still delivered once, and nothing re-admits a command.

Not covered by the vector (to add with the fix): an outstation-first close, an O->M RST in phase 7, the
outstation's separate ACK of the client FIN in phase 7, and repeated server FIN retransmissions. The last is
expected to translate via E's front_ret < 0 / q = 0 path.
