# Isolation endpoint: 20 s opt-in pre-READ pause with a local release permit

This software fixture serves the S3 quiet new-incarnation isolation test only. Ordinary campaigns, the
production endpoint and the 10 s barrier (`../endpoint_barrier_10s`, binary `8270132e…`) are unchanged.
The fixture has no device I/O.

## Lineage and the exact change

`../candidate_endpoint/sources/SocketGatePad58B.cpp` (tracked, `08ff3cb7…`, cap 5000) became
`../endpoint_barrier_10s/sources/SocketGatePad58B.cpp` (`f892c9a7…`, cap 10000), and
`isolation_20s.patch` (sha256 in `manifest/build_manifest.json`) turns that file into
`sources/SocketGatePad58B.cpp` (`c99bc20d…`). The header `DecoyGateCommandHandler.h` is
byte-identical to its parent (`e1070d8d…`). The patch makes two changes:

1. `CASE4_PRE_READ_GRACE_MS` accepts 0..20000 instead of 0..10000.
2. An opt-in permission gate sits between the end of the pause and the first `Scan`. It is active
   only when `CASE4_PRE_READ_PERMIT` is set, and it requires `CASE4_PRE_READ_RUN`
   (`[A-Za-z0-9._:-]{1,128}`) and `CASE4_PRE_READ_MARKER`; otherwise the binary exits 64. At the
   scheduled first READ (readiness + grace), the master polls the permit file every 5 ms until
   scheduled + 2000 ms. It sends the first READ only for a strictly parsed flat JSON object with
   exactly these keys:
   `{"run": CASE4_PRE_READ_RUN, "ready_ns": this process's pre_read_ready_ns, "opens": opens at
   readiness, "grant": true, "granted_ns": g}`. The value `g` must satisfy `ready_ns < g <= now`,
   using the endpoint's steady clock on the same host, and the channel must still be open with no
   reconnect. Any other outcome exits before a READ:
   - **rc 75**: no permit before the deadline (absent, or written late). Waiting never times out
     into a READ.
   - **rc 76**: a permit is present but refused (malformed, oversized, unknown or duplicate key,
     wrong run, wrong `ready_ns`, wrong opens or reconnect, `grant` false, or `granted_ns` not
     after readiness).

   On refusal, stdout carries one JSON line, `{"success":false,"pre_read_permit_refused":true,
   "permit_rc":…,"first_read_issued_ns":0,"reads_completed":0}`. On success, the final master JSON
   gains `pre_read_permit:{run, granted_ns, accepted_ns}`. Without `CASE4_PRE_READ_PERMIT` the
   output and behaviour are the parent's.

The writer (`../hw/vision_isolation.py grant-permit`) creates the file atomically: it writes a
temporary file, fsyncs it and hard-links it into place, and it never overwrites. For that reason the
endpoint treats any present-but-invalid file as a final refusal.

## Build (offline; same tree, compiler and flags as the 10 s build)

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 \
  defense4/timing/case4_architecture/integration/evidence/rearm_01/endpoint_isolation_20s/build_endpoint.py
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s defense4/timing/case4_architecture/integration/evidence/rearm_01/endpoint_isolation_20s/tests -v
```

The build runs only if every parent identity matches its pin: the controls tree library and binary,
the framework origin sources, the tracked `08ff` source, the 10 s sources and the `8270` binary. It
also requires that applying `isolation_20s.patch` to the 10 s parent reproduces `sources/` byte for
byte. The build runs `/usr/bin/c++` (g++ 9.4.0) with `-O3 -DNDEBUG` against OpenDNP3
`4648fcb898456d1cb70b5baecc38cc256c859c2e` (`/tmp/dnp3-case4-endpoint-controls-20261012-01`), with
`$ORIGIN/lib` rpath. It writes `build/` (gitignored) and copies `build/build_manifest.json` to the
tracked `manifest/`. Recorded identities: binary `c73290162d0f0b1934f13da77c1354cec110a9d29d38e4a170470432b4bae7c0`
(two builds gave identical bytes), library `6b99199e…`, lib-directory hash `a5f744c0…`, the same
library as the 10 s endpoint. The build checks that all baseline inputs are unchanged.

`evidence/green.log` and the per-test folders hold real loopback OpenDNP3 runs through a
transparent tee. Those runs cover:
- parent-identical behaviour without the permit;
- a permit granted during the pause, which READs at the scheduled time;
- a permit inside the 2 s window, which is accepted;
- absent or late permits (rc 75);
- malformed, wrong-run, wrong-`ready_ns`, wrong-opens, grant-false and stale or future `granted_ns`
  permits (rc 76).

In every negative case, no READ reaches the outstation and no SELECT or OPERATE runs. The runs also
cover the 20000/20001 bounds and permit environment validation. This is software evidence only.

## Deploy (hardware operator; NOT run)

```bash
D=/home/decps/pad58b_isolation_20s_20261016          # new directory; production/10 s directories untouched
B=defense4/timing/case4_architecture/integration/evidence/rearm_01/endpoint_isolation_20s/build
ssh decps@10.10.54.19 "test ! -e $D && mkdir -p $D/lib"
scp -q $B/case4_socket_gate_pad58b decps@10.10.54.19:$D/
scp -q $B/lib/libopendnp3.so decps@10.10.54.19:$D/lib/
ssh decps@10.10.54.19 "cd $D && sha256sum case4_socket_gate_pad58b && \
  (cd lib && find . -type f | sort | xargs sha256sum | sha256sum)"
# expect c73290162d0f0b1934f13da77c1354cec110a9d29d38e4a170470432b4bae7c0 and a5f744c0ce17fa8674e46b9c9bd374c224e57900dfa5c3adafc08dd1c9123cba
```

The block uses `../config/ctl_m5_stale_iso20_950.json`, which declares
`endpoint.max_pause_ms=20000` and `endpoint.permit=true`. `../hw/candidate_isolation.py` accepts
this directory and binary only with that declared capability.
