# Isolated pre-READ endpoint

This fork adds a master-side pause after TCP OPEN is verified and before the
first explicit READ Scan. `CASE4_PRE_READ_GRACE_MS` accepts unsigned decimal
integers in 0..5000, default 0. The existing READ pause, SBO, close grace, point
seed and command handler behavior remain intact. This endpoint is a software
fixture, with no device I/O.

The optional `CASE4_PRE_READ_MARKER` names a caller-controlled local path. Only
the master writes it, once before the pause. Its JSON records
`pre_read_grace_ms`, `pre_read_ready_ns`, `first_read_issued_ns:0`, observed
`tcp_open:true` and `opens`. An open, flush or close failure returns 74 before
any READ. The caller should supply a fresh writable path and poll for complete,
valid JSON, rather than using file existence alone as readiness evidence.

Final master JSON includes the effective grace, readiness timestamp and first
READ issue timestamp. Timestamps use the endpoint's steady clock in nanoseconds,
not Unix time. A zero-READ workload reports `first_read_issued_ns:0`. TCP OPEN
and the marker alone do not prove ASIC mapper state; the hardware owner must
also retain fresh-handshake capture and mapper snapshots. OpenDNP3 startup
messages may occur before the pause; no explicit READ Scan occurs then.

Build from the repository root:

```bash
env PYTHONDONTWRITEBYTECODE=1 python3 \
  defense4/timing/case4_architecture/integration/evidence/rearm_01/candidate_endpoint/build_endpoint.py
env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s defense4/timing/case4_architecture/integration/evidence/rearm_01/candidate_endpoint/tests -v
```

The recipe compiles only this fork against the already pinned OpenDNP3 tree
`/tmp/dnp3-case4-endpoint-controls-20261012-01`. It copies the exact existing
library into `build/lib/`, uses `$ORIGIN/lib` for relocatable library lookup and
records compiler, command, source/header hashes, binary/library pins and unchanged
baseline input hashes in `build/build_manifest.json`.

Deploy `build/case4_socket_gate_pad58b` and `build/lib/` into a new endpoint
directory. The hardware owner supplies any runner/config changes and sets the
two new environment controls for the master. For an isolation window, use
`CASE4_PRE_READ_GRACE_MS=5000` and a unique marker path; the default 0 retains
the ordinary candidate workload. This folder does not change a baseline
endpoint, runner, configuration, ASIC program or fixture.

Evidence uses real OpenDNP3 processes and loopback kernel TCP sockets with a
transparent, unmodified-byte relay. `evidence/green.log` and individual test
folders retain final endpoint JSON, marker observations and independent
timestamped DNP3 byte streams. The 500 ms case verifies no READ during the
pause and first READ arrival after it. Tests also cover default behavior,
exact 23-point seed/SBO results, strict invalid values, bounds and marker
open/flush failure. They supply software evidence only.
