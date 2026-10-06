The endpoint gate uses OpenDNP3 commit
`4648fcb898456d1cb70b5baecc38cc256c859c2e` extracted with `git archive` into a
fresh external build directory. It never checks out or edits the dirty sibling.
Every invocation requires a fresh output directory; existing directories,
files and symlinks are refused before building or creating a namespace. Failed,
aborted and interrupted runs remain available. There is no force/resume option.

Run the production application-context gate with explicit paths:

```sh
python3 -B defense4/timing/framework/size/endpoint_gate/run.py \
  --output /tmp/new-context-evidence --work /tmp/new-context-build \
  --dependency-cache /tmp/dnp3-case4-endpoint-gate/build/_deps --jobs 2
```

Add `--sockets` to build the real TCP endpoint application and run exactly one
SELECT/OPERATE pair inside private user/network namespaces. Both phases use
one fresh socket. Application response timeouts and endpoint select retention
are each configured to 500 ms. The configured callback points are 1 and 201;
all callback effects are counters in this software process. No devices or host
interfaces participate. This gate uses the software image oracle, not P4.
It deliberately truncates each initial 55-byte wire request to 35 bytes once,
then requires actual Linux packets to replay the remaining stream. It sends no
synthetic ACKs and performs no application resend or autonomous bridge send.

A subsequent fresh acquisition can reuse the pinned socket executable and
production library using `--sockets --built-manifest PATH/manifest.json`.
Their hashes and compiled application/handler identities must still match;
current gate/bridge/profile/model inputs are independently snapshotted and
verified before launch. Reuse does not resume a connection or output directory.
The independent pcap check runs in its own exclusive subdirectory before the
outer completion inventory is sealed.

`context_evidence_03` passed 4 production-context cases / 46 assertions.
`socket_evidence_03` passed the production TCP socket pair and its independent
capture check: native ACK boundaries 34/35 and 69/70, one-byte kernel
retransmissions, 21-byte cached replays, both complete 57-byte success echoes,
and identical SELECT/OPERATE object sets. Observed replay intervals were
206.717 ms and 439.109 ms; selected-to-operated acceptance was 440.139 ms.
These are single software observations, not physical timing bounds or generic
TCP support. Socket 03 reuses the hash-verified production build from socket 02.
Its snapshots predate a later abort-only process-group cleanup hardening; that
hardening has a separate interruption regression.

`socket_evidence_01` remains failed after an asynchronous bridge startup lost
the first SYN. Socket 02 passed application callbacks but omitted sequence
translation on pure ACK/FIN packets; `socket_analysis_02` correctly failed.
`context_evidence_02` remains failed after the pinned single-header Catch cache
was looked up through the wrong FetchContent include directory. The corrected
path verifies Catch's declared SHA-1. No failed captures or manifests were
rewritten.

The socket result exports connection identity (run UUID plus captured tuple),
production binary/source/profile/transport hashes, callback counts and software
steady-clock SELECT/OPERATE acceptance instants. `tcp_info.jsonl` retains raw
`ss -tin` observations from the private master namespace. The raw pcaps and
`independent_analysis/result.json` supply the separate stream proof. Physical
admission, complete Tofino transport state and hardware measurements remain
outside this gate.
