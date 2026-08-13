# H3 software-endpoint harness (real networked DNP3, namespace-to-namespace)

This is the H3 stage: a **real networked** DNP3 master and outstation built on real TCP sockets and
validated **namespace-to-namespace first**, before anything is loaded on the switch. It does **not**
load any P4, does **not** touch the Tofino, and does **not** contact the physical relay. It never
actuates a physical output.

The endpoints are raw-socket DNP3 apps (not the pydnp3 library) on purpose: this stage must put the
*exact SEL-751 wire bytes* on the link and control TCP-ACK timing, neither of which a library
outstation exposes. The framing/CRC routines are the ones already proven against the physical
SEL-751 by `hw/relay_read_g10_23.py` and `readsbo_normalizer/relay_sbo_2crob_loop.py`. The built
outstation echo is **byte-identical** to the SEL-751 native echo reassembled from the phase7_h2
`[28,21]` capture (self-checked by `python3 dnp3_wire.py`).

## Files

| File | Role |
|------|------|
| `dnp3_wire.py` | Shared DNP3 CRC/framing, 2-CROB SELECT/OPERATE request builders (qual `0x17`), the 49-byte native echo builder, and a request parser. Self-checks echo byte-identity to the captured SEL-751 native. |
| `h3_outstation.py` | Outstation-facing endpoint. Accepts 2-CROB SELECT/OPERATE, returns the 49-byte native echo, exposes `select_count` / `operate_count` / `callback_count`, and **deliberately separates the TCP ACK from the response** (Case-A) via `TCP_QUICKACK` + a bounded app-processing delay. |
| `h3_master.py` | Master-facing endpoint. Issues N Select-Before-Operate transactions (SELECT then an identical OPERATE, both qual `0x17`) over one persistent connection and logs per-transaction wire timestamps. |
| `run_h3_namespace_validation.sh` | Builds two **separate rootless network namespaces** (veth pair, no sudo), disables TCP timestamps in both, captures both veth ends on **one host clock**, runs outstation + master, collects counters. |
| `analyze_h3.py` | Offline verdict from the pcaps: TCP-timestamps absent (fail-closed), qual `0x17` 2-CROB on every request, separate-ACK-before-response ordering, 49-byte native echo, counters correct. |

## Topology (rootless, no sudo)

```
 master ns (parent)  10.9.0.1  veth_m <====> veth_o  10.9.0.2  outstation ns (PID-held child)
        h3_master.py                                              h3_outstation.py :20000
```

Named `ip netns` cannot be used rootless (it needs a bind-mount under `/run/netns`). Instead the
script creates a user+net namespace with `unshare --map-root-user`, holds a second net namespace open
in a child process, and joins it by PID with `nsenter` — no root, no `/run/netns`. `tcpdump` also
does not work rootless here (its privilege-drop `setgroups` is denied in a single-mapping userns), so
captures use **`dumpcap`**.

## Single-clock capture method

Both `dumpcap` instances run on this one host. Packet timestamps come from the same host **kernel**
clock (`SO_TIMESTAMP`) regardless of namespace, so the master-facing and outstation-facing captures
share one time base. Cross-interface deltas (e.g. ACK→response) are therefore measured on a single
clock — no host-clock synchronisation is involved and none is assumed. The separate-ACK ordering is
read from the master-facing capture (what the master observes on the wire).

## Run

```bash
./run_h3_namespace_validation.sh <OUTDIR> [N=25] [APP_DELAY_MS=5]
python3 analyze_h3.py --master-pcap <OUTDIR>/master_facing.pcap \
    --outstation-pcap <OUTDIR>/outstation_facing.pcap \
    --counters <OUTDIR>/outstation_counters.json \
    --master-log <OUTDIR>/master_txn_log.json --expect-n 25 --out <OUTDIR>/h3_verdict.json
```

## Safety

Software only. The outstation's "physical callback" for an OPERATE increments `callback_count` and
does nothing else — it drives no output and contacts no relay. This stage runs entirely between two
local network namespaces. It is **namespace-validated only**; it has **not** yet been run through the
switch or against the relay.
