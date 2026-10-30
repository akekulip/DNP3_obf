# P4 dataplane

`response_only.p4` is the one editable dataplane source. It targets an Intel Tofino-1 switch (TNA architecture) and
compiles with `bf-p4c` from SDE 9.13.2. The switch sits inline between a DNP3 master and one outstation (tested on a
SEL-751 relay). It hides two features of the outstation's responses from an on-path observer: their size, by padding
READ responses to a fixed size per class and reframing SELECT/OPERATE responses, and their timing, by releasing every
response a configured gap D after the response-ready ACK. The endpoints are not modified.

`profile_template.json` holds the supported endpoint and encoding data the source is built against. The current
candidate build and its source SHA-256 are named in `HANDOVER.md`.

## Pipeline layout

The program uses both pipes of the switch (`Switch(p0, p1)` at the end of the file).

| Pipe | Part | Controls | Role |
|---|---|---|---|
| p0 ingress | N | `n_IgParser`, `n_Ingress` | Request and connection lifecycle: TCP ACK normalization, the per-connection epoch, client and server sequence banks, owner state, and one work cell (`n_ExpectedWorkRecord`) that admits one unit of work at a time by generation and phase. A frame that finds the cell held is retried through the recirculation port within a fixed budget (`busy_t`); SYN, SYN-ACK and replay frames are dropped instead |
| p0 egress | E | `r_EgParser`, `r_Egress` | Response eligibility, sequence and ACK mapping between the native and padded streams, and the SELECT/OPERATE response images |
| p1 ingress | T | `t_IngressParser`, `t_Ingress` | Timing (`response_ready_ack_d_no_j_v3`): the relay's ACK is committed when the response is ready, and the response leaves after the configured gap D. ACKs and responses are held in queues 6/4, with blockers in queues 7/5, and released by packet-generator timer events |
| p1 egress | x | `x_EgParser`, `x_Egress` | READ padding: the prefix for the two READ classes (mixed and integrity) and the IPv4 and TCP checksum updates |

Device ports are compile-time constants: the master on dev9, the relay on dev64, front-panel loops on dev48, dev180
and dev182 (MAC loopback set by the installer), and internal recirculation on dev68 (pipe 0) and dev196 (pipe 1).
`scripts/hardware/build_ports.py` checks the compiled constants and port roles. The relay cable must sit in the cage
that maps to dev64.

## Runtime settings

The four evaluation arms (off, timing only, size only, timing and size) use one binary. Timing is set at runtime by
its gap, budget and enabled flag (`scripts/hardware/t_config.py`). Padding is set by the installer's `--pad-enable`
on the E connection row.

## Build

```bash
python3 scripts/build.py p4/response_only.p4 results/builds/<label>/compile_local \
    --compiler "$SDE_INSTALL/bin/bf-p4c"
```

`build.py` runs `bf-p4c --target tofino --arch tna -g` and writes a manifest with the compiler version, the SHA-256 of
every artifact, and stage use per pipe. It never loads or configures a device. `scripts/profile.py` packages the
source with its profile. The model gate (`scripts/model/`, 17 drivers on the SDE tofino-model) qualifies a build before
any hardware use.
