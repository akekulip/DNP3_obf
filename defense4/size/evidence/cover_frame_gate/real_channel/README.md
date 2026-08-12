# Real persistent-stack DNP3-over-TCP loopback (Gate C evidence)

This directory adds the evidence class the in-process gate could not: a **real** OpenDNP3
`DNP3Manager` running an asio **TCP server (outstation)** and **TCP client (master)** in one
process over `127.0.0.1`, with the production socket / TCP / data-link / transport / application
layers, captured on the loopback wire with `dumpcap` and dissected with `tshark`. Software only:
no hardware, no relay, no switch. The OpenDNP3 fork is **not modified** — `rt_loopback.cpp` is
compiled out-of-tree against the already-built `libopendnp3.so` (see `src/run_real_channel.sh`).

Stack: OpenDNP3 community fork **3.1.2** (`opendnp3_commit` in `evidence/env.txt`), master
addr 1 / outstation addr 10, one flow. Reproduce: `bash src/run_real_channel.sh`.

## Evidence classes — kept strictly separate

The whole point of this repair is to stop mixing what was measured with what was constructed.

| Class | Where it comes from | What it proves here |
|---|---|---|
| **application-context** | in-process `MContext`/`OContext` state machines (the sibling in-process gate) | an APDU round trip and a link-address filter decision — **not** TCP, transport, or socket |
| **link** | real `LinkLayerParser` + `LinkLayer` address filter (component test) | individual-addressed cover **discarded**, real frame delivered byte-identically |
| **transport** | real transport layer, captured on the wire (`evidence/transport_reassembly_frag.txt`) | genuine **multi-segment reassembly**: one response split into transport SEQ 0..6, `Reassembled DNP length: 1574` |
| **socket / TCP** | real asio sockets on `lo`, captured (`evidence/tcp_flow_baseline.txt`) | real 3-way handshake, advancing seq/ack, pure ACKs, PSH data both ways, orderly **FIN/FIN**, and a **RST** on the post-shutdown reconnect |
| **captured-wire** | `dumpcap` pcapng + `tshark` DNP3 dissection (`evidence/dnp3_baseline.txt`) | the bytes above are on the wire with correct link/transport/app CRCs, not asserted by the harness |

## What the real channel showed (measured)

Baseline (`evidence/rt_baseline.json`, 4 binary inputs, one integrity fragment):

- `channel_open=1`, `read_success=1`, `soe_binaries=8` (4 static + 4 events), `sbo_success=1`,
  `out_num_select=1`, `out_num_operate=1` — the **real outstation** executed exactly one Select
  and one Operate; the **real master** completed the integrity READ and the SBO.
- Wire (`tcp_flow_baseline.txt`): SYN / SYN-ACK / ACK; request (27 B) → response (243 B);
  SBO exchanges; **FIN** frames 18–19; a real **RST** (frame 22) when the master's retry hits the
  closed port after `manager.Shutdown()`. `dnp3_baseline.txt`: link `From 10 To 1`, header CRC
  `[correct]`, transport `0xc0 FIR+FIN seq 0`, application `FIR/FIN/CON seq 0 Response`.

Fragmentation (`evidence/rt_frag.json`, 40 binary inputs → response > one link frame):

- `read_success=1`, `soe_binaries=80`. The response is carried as **7 link frames** (transport
  SEQ 0 FIR … SEQ 6 FIN), reassembled by the real master transport layer to **1574 bytes**, then
  a second application fragment (SEQ 7). This is the persistent transport reassembly the
  in-process substitute (one hand-added `0xC0` octet, no reassembly) cannot exercise.

## Gate C = PARTIAL

- **PASS (this directory):** a real persistent-stack DNP3-over-TCP loopback completes READ and
  SBO in **both directions**, with the byte stream captured and the socket/TCP/transport/app
  layers independently dissected off the wire.
- **BLOCKED-BY-SANDBOX (not a DNP3 result):** the full-stack **cover-injection** case needs a
  forwarding relay on the loopback path (`src/cover_injector.py`). Under this execution
  environment any such relay is killed with **SIGSTKFLT** (signal 16); the native single-process
  stack is unaffected. Root cause and the discriminating probes: `evidence/sigstkflt_root_cause.txt`
  and `evidence/sigstkflt_probe_log.txt`. The `cover_injector.py` is retained as the exact
  instrument that would run in an unsandboxed lab.
- **Consequence:** the individual-address cover-**discard** property is proven in the **bounded
  link-layer component test** (`../src/test_cover_frame_gate.cpp`, real `LinkLayer` address
  filter), and broadcast is retained there as the negative hazard. The live-socket generalization
  of discard is deferred to an unsandboxed run.

## Files

- `src/rt_loopback.cpp` — the real single-process persistent-stack harness (env-configured).
- `src/run_real_channel.sh` — out-of-tree compile + capture + dissect + path-sanitize (no fork edit).
- `src/cover_injector.py` — labeled test instrument; blocked by the sandbox (see root cause).
- `evidence/cap_baseline.pcapng`, `cap_frag.pcapng` — the captured loopback (127.0.0.1 only).
- `evidence/tcp_flow_baseline.txt`, `dnp3_baseline.txt`, `transport_reassembly_frag.txt`,
  `tcp_segments_frag.txt`, `rt_baseline.json`, `rt_frag.json`, `env.txt`, `sha256sums.txt`.
- `evidence/sigstkflt_root_cause.txt`, `sigstkflt_probe_log.txt` — the diagnosis.
