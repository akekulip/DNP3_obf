# Physical SEL-751 DNP3 session — SOLVED, two root causes

**2026-07-25.** The relay that had refused every DNP3 session since 2026-07-23 now answers live,
read-only Class-0 polls. Two independent root causes, both found and fixed by measurement.

## Root cause 1 — source-IP allowlist (the "FINs itself in ~1.9 ms" blocker)

Earlier probes came from `192.168.10.100`; the relay accepted the TCP handshake then closed it
itself in ~1.9 ms with zero DNP3 bytes. Connecting instead from **`192.168.10.1`** (the master IP
the relay's DNP3 map expects, which Vision now holds on eno1) the relay **keeps the connection
open** — no self-FIN. Confirmed at TCP level: SYN / SYN-ACK / ACK complete, the READ is delivered
and the relay **TCP-ACKs it** (ack=23), then holds the connection for the full 4 s.

## Root cause 2 — wrong DNP3 link address (the "TCP-ACK but no DNP3 response" blocker)

With the connection stable the relay still sent no DNP3 response. Cause: **the relay's outstation
link address is 0, not 10.** The corpus was captured in a different deployment (10.0.0.x, outstation
addr 10); the relay on the lab uses addr 0.

Found read-only with a DNP3 data-link **Request Link Status** (function 9) scan over
{10,1,100,2,3,247,255,4,5,0}: only **dst=0** answered, with a Link Status (func 11) frame
`0564 05 0b 0100 0000` — src=0, dst=1, i.e. the relay is address 0 replying to master address 1.

Re-addressing the real corpus READ to dst=0 (recomputing only the header-block CRC; data block
untouched) → the relay responded with a **54-byte DNP3 response, function 129, IIN present, in
33 ms**. Live DNP3 from the physical device.

## Live device characterization (8 consecutive read-only polls, captured on Vision)

- **Separate-ACK device.** It emits a pure TCP ACK, then its data response — 9 pure ACKs and 8 data
  frames over 8 polls. So it has a CLRT and the IBSPG timing normalizer applies to it.
- **Native CLRT (pure ACK → response): 1.0–5.07 ms, mean 2.93, sd 1.66 ms** over 8 polls (fast
  direct LAN; the 12.9 ms corpus figure was over a different path).
- **TCP header 32 bytes (`data_offset = 8`) — the relay negotiates RFC 7323 timestamps**, exactly as
  the ICS panel predicted from the corpus. This is why the size normalizer, built for
  `data_offset = 5`, cannot fire on this device: now confirmed on the live relay, not just the corpus.
- Response payload 54 bytes, stable.

## Safety

Everything here was read-only by construction: a telnet allowlist that can only send status
commands, DNP3 Request-Link-Status frames (data-link status queries), and Class-0 READ (function 1)
frames with the function byte asserted. No SET, no control, no SBO, no WRITE, no link reset, no retry
storms — single connects, one poll train. `ACC` (access-level elevation) was attempted, hit a
password prompt, and was NOT guessed (SEL relays lock out).

## What this unblocks

The physical relay is now driveable for both axes. Next: drive the Tofino defense with the relay's
**real `data_offset=8` framing** — the timing path should handle it (classifier covers doff 5–8), and
it will confirm on the live device the size path's doff=8 limitation the panel identified.
