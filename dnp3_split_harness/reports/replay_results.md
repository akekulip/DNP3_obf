# Exact Replay Results

Live results from the Vision↔Hulk rig. Phase 6: replay a captured response
verbatim from a plain TCP socket and observe the OpenDNP3 master's reaction.

## Setup
- **Replay server:** Hulk `10.10.54.158:20000` (`replay_tools/dnp3_replay_server.py`,
  plain socket, OS handles TCP — no raw packet crafting, no byte modification).
- **Response replayed:** `payloads/replay/replay_response.bin` — 902 bytes, 6 DNP3
  link frames, captured from a real small (5 analog / 5 binary) Class 0 response.
- **Master:** Vision `10.10.54.19` (`experiment_master.py --action scan-class0`).

## Observations
- The socket exchange completed cleanly: server **received 24 request bytes**, **sent
  902 response bytes verbatim**; master ran to a clean exit (no crash).
- The master **fully ingested and parsed the replayed stream** (from its ALL_COMMS log):
  - Link layer accepted every frame (`PRI_UNCONFIRMED_USER_DATA Dest:1 Source:10`).
  - Transport layer **reassembled the multi-frame data APDU** — segments `SEQ 3 (FIR=1,FIN=0)`,
    `SEQ 4 (FIR=0,FIN=0)`, `SEQ 5 (FIR=0,FIN=1)` → one application fragment.
  - Application layer read **every RESPONSE header and IIN** (`OnReceiveIIN` fired 4×).
  - The replayed first response carried a stale **device-restart IIN (0x80)**, and the
    master reacted exactly as the spec dictates — it issued a `WRITE` to clear IIN1.7 and
    re-sent `ENABLE_UNSOLICITED`.
- **But SOE rows delivered = 0.** No measurement values reached the SOE handler.

## Why exact replay parses but delivers no data
The replayed response's **application control / sequence** does not correspond to an
outstanding solicited request from *this* master session. The replayed fragments carry the
sequence numbers from capture time (first response app `SEQ=0`, data APDU app `SEQ=3`),
while the live master assigns its own request sequence. OpenDNP3 parses the frames (link,
transport, IIN) but only dispatches **object data to `ISOEHandler` when a response matches an
in-flight poll task's sequence** — so the measurement data is parsed and then dropped.

## Conclusion
- **Exact byte replay works at the transport level** — the master ingests, reassembles, and
  parses the verbatim bytes without error (proves the socket replay path and that TCP
  delivery of the captured stream is faithful).
- **It does NOT deliver measurements**, because DNP3 gates solicited data on a matching
  **application sequence number**, and a stale **restart IIN** further diverts the master.
- **Implication for Phase 8 / true DNP3-aware work (research Q7):** a replayed-or-modified
  response that must be *accepted as live data* has to rewrite the **application control byte
  (FIR/FIN/CON/UNS + 4-bit sequence)** to match the master's pending request, clear stale IIN
  bits, and then **recompute the per-block CRCs**. These are exactly the fields the field-map
  utility (`dnp3_field_map.py`) extracts.
- This is the expected, correct DNP3 behavior — not a harness bug. The socket replay itself is
  byte-faithful (verified separately: received/sent dumps match the source file).
