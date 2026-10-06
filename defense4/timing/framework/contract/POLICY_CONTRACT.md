# Response-ready policy contract (working draft, 2026-10-06)

Written from the approved sources (`response_ready/README.md`, the 2026-10-05 assignment, the meeting note), not from the
P4. `framework/model/response_ready_model.py` implements it. Where the P4 has not yet been shown to agree, the row is
marked **P4?**. Notation follows `defense4/timing/NOTATION_MAPPING.md`; this file adds none.

## Quantities

| symbol | meaning here |
|---|---|
| t_0 | request arrival at the switch ingress (matching request, supported profile) |
| t_A | native ACK arrival at the switch (held) |
| t_R | arrival of the first byte of the matching complete response (first TCP segment of the single-frame profile) |
| D_A | configured ACK hold. **Reference is declared by `anchor`**: `request` = t_0 + D_A (the approved candidate, `anchor_req=1`); `native_ack` = t_A + D_A (the assignment's formula). Never mixed silently. |
| e_A, e_R | ideal release instants of the held ACK and the response (not wire departures) |
| CLRT_new (configured) | response gap `gap`, floor-quantized to the 256 ns grid (1 ms -> 999,936 ns) |
| H | per-token watchdog horizon = budget x loop period (18,000 passes, about 30.8 ms). An estimate, not a wall-clock guarantee. |

## Release rule

```
anchor = request :  e_A = max(t_0 + D_A, t_R, t_A)          # ACK also cannot leave before it arrived
anchor = native_ack: e_A = max(t_A + D_A, t_R)
e_R = e_A + gap
```

Normal release requires the matching response to be *seen* (pending) before the ACK blocker may expire. An absolute
deadline passing with the response absent does not drain the ACK.

## Matching

A response is the matching one iff connection epoch, TCP ack number (= request seq + request length) and DNP3 application
sequence all equal the armed transaction's. Anything else is *stale*: forwarded unchanged, counted, state unchanged.
Supported profile: single complete DNP3 frame in one TCP segment, READ. Everything else is bypassed unchanged and counted.

## Terminal outcomes (each returns the flow to a reusable state)

| outcome | trigger | ACK | response |
|---|---|---|---|
| NORMAL | response seen before t_0 + H | e_A as above | e_A + gap |
| FALLBACK_NO_RESPONSE | t_0 + H with no response | released at t_0 + H, reason TMO | none |
| LATE_RESPONSE | matching response after fallback | already out | forwarded at arrival, native timing, counted separately |
| BYPASS_BUSY | request while a transaction is armed | unchanged | unchanged; armed transaction untouched |
| BYPASS_UNSUPPORTED | non-READ, multi-segment, options, malformed | unchanged | unchanged |
| STALE_FORWARDED | non-matching response | n/a | forwarded unchanged |
| DUP_ACK_DROPPED | second pure ACK for the armed transaction while the first is held | one released | n/a |
| RESET_FLUSH | FIN/RST for the epoch | any held ACK released unchanged | any held response released unchanged |

**P4 status (2026-10-06, from the source and the pass simulator):** RESET_FLUSH is **model-only** — the P4 has no FIN/RST
handling; a connection that closes mid-hold is cleaned up by the per-token watchdog within H, not immediately. Losing both
blocker tokens leaves the owner armed (nothing runs the timeout pass), so every later READ is bypassed as busy until the
control plane resets state (`test_losing_both_tokens_leaves_the_owner_armed_KNOWN_LIMITATION`). A timeout retires the owner
but does not clear `reg_tag`. DUP_ACK_DROPPED and RESET_FLUSH: chosen as the fail-open reading of the assignment (no permanent suppression of
TCP loss repair). A retransmitted request after release starts a new transaction; it is not dropped as a duplicate.

## Ordering and ties

External events at the same instant are processed before timers. ACK release is processed before the watchdog at the
same instant (a response that makes it in time wins). The response never precedes its ACK: e_R = e_A + gap with gap >= 0.

## Clock

Instants are 32-bit ticks of 256 ns (wrap about 1,099 s). Comparisons decode modularly with half-range:
`due(now, deadline) = ((now - deadline) mod 2^32) < 2^31`. Windows longer than half range are unsupported.
