# Evidence: fixed-source-port Class 0 READ client, local loopback only

What this directory records: one passing end-to-end run of `../dnp3_read_client.py`
against `../dnp3_sim_outstation.py` on `127.0.0.1`, verifying that the client binds
the exact caller-specified local source port before `connect()` and that a
correctly framed Class 0 (integrity poll) READ request/response exchange
completes with valid DNP3 link-layer CRCs on both sides.

**No real network host was contacted.** Both processes bound `127.0.0.1`. This is
a software correctness check only, not a hardware or lab-network result.

## What ran

```
python3 dnp3_sim_outstation.py --local-ip 127.0.0.1 --local-port 20501 \
    --accept-timeout 15 --recv-timeout 10        # -> loopback_outstation.log

python3 dnp3_read_client.py --local-ip 127.0.0.1 --local-port 47558 \
    --remote-ip 127.0.0.1 --remote-port 20501 --read-timeout 3    # -> loopback_client.log
```

## What was verified, and how

1. **Fixed local source port actually bound, not OS-assigned.** The client calls
   `socket.bind((local_ip, local_port))` with `SO_REUSEADDR` before `connect()`,
   then reports `getsockname()`. `loopback_client.log` line 1 shows
   `bound local socket to 127.0.0.1:47558 (requested 127.0.0.1:47558)` -- request
   and actual match, and the client treats a mismatch as a hard failure (exit 1),
   not a warning. Independently (outside the script, same bind-then-connect
   pattern), `ss -tn` was read while the socket was open and showed the identical
   established pair on port 47558 from both ends -- the kernel's own connection
   table agrees with `getsockname()`.
2. **Correct DNP3 link framing.** Request hex
   `05640bc40a000100acd1c0c0013c0106ff50` decodes to sync `0564`, length `0x0b`
   (11 = 5 header fields + 6 user-data bytes), control `0xc4` (DIR=1,PRM=1,FC=4,
   unconfirmed user data, master->outstation), dest=10, source=1, a valid header
   CRC, transport header `0xc0` (FIR=1,FIN=1,SEQ=0), application control `0xc0`,
   function code `0x01` (READ), object header `3c 01 06` (group 60, variation 1,
   qualifier 0x06 -- Class 0 data, no range field), and a valid data-block CRC.
   Every CRC was computed with `rrc.dnp3_crc` (polynomial 0x3D65), the one CRC
   implementation already audited in this repository -- not reimplemented.
3. **Correct response and CRC validation on receipt.** Response hex
   `0564114401000a002354c0c0810000010200000181019e4c` decodes to control `0x44`
   (DIR=0, outstation->master -- this is the opposite DIR bit from the request,
   confirmed against this project's own real OpenDNP3 captures, see below),
   dest=1, source=10 (addresses correctly swapped relative to the request),
   function code `0x81` (RESPONSE), IIN `0000`, object header `01 02 00 00 01`
   (group 1 variation 2, qualifier 0x00, start=0, stop=1), and data bytes
   `81 01` -- point 0 flags `0x81` (ONLINE + STATE=1) and point 1 flags `0x01`
   (ONLINE, STATE=0). This matches exactly what `dnp3_sim_outstation.py` was
   configured to report (`POINTS = [(0, True), (1, False)]`, see
   `loopback_outstation.log` line 5: `reported points: [(0, True), (1, False)]`).
   The client independently re-validates every received frame's CRCs via
   `rrc.dnp3_frame_ok` and reports `crc_ok=True`; `PASS` is only printed when
   every received frame's CRC checks out.

## A real bug this verification run caught and fixed

The first loopback run passed CRC validation but the **response frame's control
byte was wrong**: `build_link_frame()` originally hardcoded the request's
control byte (`0xC4`, DIR=1) on every frame it built, including the simulated
outstation's response. CRCs stayed valid either way (CRC covers whatever bytes
are present; it does not know what the control byte *should* be), so this would
not have been caught by CRC checking alone. It was caught by decoding the
response and comparing its control byte against real captured traffic in this
repository: `evidence/campaign_v2/s14/raw_pcaps/s14_b5_native.pcap` shows a
production OpenDNP3 master/outstation pair using control `0xc4` for requests and
control `0x44` for responses (DIR flips, PRM/FC stay the same). Fixed by giving
`build_link_frame()` a `control=` parameter (default `REQUEST_CONTROL`, i.e.
`0xC4`) and having the response builder in `dnp3_sim_outstation.py` pass
`RESPONSE_CONTROL` (`0x44`) explicitly. `loopback_client.log` above is the
post-fix passing run.

## Scope note

`dnp3_sim_outstation.py` is a test fixture only -- it exists so this client can
be exercised safely, and it is not meant for anything beyond that. Nothing in
`dnp3_read_client.py` is loopback-specific; it takes `--local-ip`,
`--local-port`, `--remote-ip`, `--remote-port` as plain required arguments with
no default pointing at any real address, so it is the same binary a human
operator would point at the real lab topology (e.g. the Tofino-fronted
outstation) once that is explicitly authorized -- that authorization has not
been given and this evidence does not claim it.
