# Gate S4 Packet-Preserving Software Prototype Specification

Status: implementation contract after Gate S3 PASS

Scope: rootless Linux network namespaces, veths, synthetic DNP3/TCP endpoints, and recorded replay only. No physical interface, Vision/Tofino SSH session, P4/BFRT state, or relay is part of this gate.

## Result required

S4 passes only if two independent software shims carry complete Ethernet frames through the unchanged `S3-RNL-256-v1` fixed-cell protocol while native endpoint TCP remains end to end. The observed link must contain only fixed 256-byte EtherType `0x88B5` cells. A socket-level TCP proxy is forbidden.

## Isolated topology

The harness runs inside a fresh user plus network namespace. PID-held child network namespaces avoid `/run/netns` and root privileges on the host.

```text
master endpoint ns
  m_ep 10.44.0.1/24
       |
       | clear inner Ethernet (trusted capture F_IN)
       |
  v_in [Vision shim ns] v_out
       |
       | fixed-cell link, observer capture O
       |
  test-only bounded link emulator
       |
  u_out [UFISpace-role shim ns] u_in
       |
       | clear inner Ethernet (trusted capture F_OUT)
       |
relay endpoint ns
  r_ep 10.44.0.2/24
```

The link emulator is testing apparatus, not a deployment component. In the baseline it forwards exact outer frames. Fault cases use it to drop, duplicate, or reorder cells after transmission so transmitter scheduling remains fixed.

Endpoint namespaces hold the only inner IPv4 addresses. Shim inner and outer veths have no IP addresses. IPv6 is disabled on the isolated interfaces. Interface offloads are disabled where supported so the trusted capture oracle observes completed IPv4/TCP checksums.

Endpoint interface identities are fixed for the run: master MAC `02:44:00:00:00:01`, relay MAC `02:44:00:00:00:02`, master IPv4 `10.44.0.1/24`, and relay IPv4 `10.44.0.2/24`. No static neighbor entry is installed. Native endpoint ARP request/reply frames therefore cross the shims as complete protected inner frames. The shims do not rewrite inner MAC or IP fields.

Before a run, the harness must prove `unshare --user --map-root-user --net`, veth creation, link movement by PID namespace, and `AF_PACKET` raw bind/send are available. This proves the mapped-root namespace has the required `CAP_NET_ADMIN` and `CAP_NET_RAW` operations. Any failure marks S4 `BLOCKED IN ENVIRONMENT`; it does not authorize an in-process substitute or weaker pass threshold.

## Hard packet-preservation invariant

- Each shim receives and injects complete Layer-2 frames through Linux `AF_PACKET` raw sockets.
- The shims never call `listen`, `accept`, or `connect` and never terminate TCP.
- A delivered decoded frame is byte-for-byte identical to the corresponding captured input frame, excluding physical FCS which veth does not expose.
- Directional frame order is preserved. A fixed slot cannot overtake an older frame assigned to a later slot.
- Clear ARP, IPv4, TCP, or DNP3 is never placed on the observed cell link.

## Reused cell policy

S4 imports the committed S3 codec without modifying it:

- complete outer Ethernet frame `C = 256` bytes;
- four request cells and two tail cells in the forward direction;
- two ACK/control cells and fourteen response cells in the reverse direction;
- exactly 22 cells and 5,632 captured outer bytes per epoch;
- nominal offsets `0..750 us`, `1000..1250 us`, `200000..203250 us`, and `203500..203750 us`;
- ChaCha20-Poly1305 with distinct directional keys and nonce spaces;
- no cell-layer NACK, retransmission, escape record, or clear fallback.

Prototype keys are generated at run time in a mode-`0600` temporary file, read by both shims, then deleted. Keys and plaintext are never written to logs. Deterministic public S3 keys remain limited to unit tests.

## Bounded shim state

Each shim has one direction-preserving FIFO bounded to 128 frames and 262,144 serialized bytes. Queue admission, high-water marks, drops, slot overflows, deadline misses, authentication failures, replay failures, incomplete slots, and injected frames are local metrics.

At a slot deadline the shim removes only the oldest consecutive frames assigned to that slot that fit the fixed capacity. A single frame that cannot fit its selected slot is consumed as an overflow event; the slot emits authenticated cover and releases no partial bytes. Newer frames never pass it. All unused capacity is cover.

The receiver groups cells by the public per-direction counter window, accepts bounded within-slot reordering and exact duplicates, and releases a bundle only after every configured cell authenticates. Incomplete, conflicting, stale, replayed, wrong-key-epoch, malformed, and unauthenticated groups release nothing.

## Three capture oracles

1. **Trusted input:** exact frames captured as they leave each native endpoint.
2. **Observed link:** all frames seen on the Vision-side outer veth, including both directions.
3. **Trusted output:** exact frames injected toward each native endpoint after complete authenticated decoding.

For the no-fault run, forward trusted-input and relay trusted-output sequences must match exactly; reverse trusted-input and master trusted-output sequences must match exactly. Every restored IPv4/TCP checksum and every DNP3 link/header/data CRC must validate. Endpoint application streams must match their generated requests and responses exactly.

The observed-link capture must contain no non-cell frame. Every baseline epoch must have the same complete size, direction, count, counter-stride, and nominal slot vector across the declared response-length classes.

## Link and TCP lifecycle treatment

ARP, TCP SYN/SYN-ACK/ACK, pure ACKs, FIN, and RST are protected inner traffic, never preconditioned clear setup. Vision-side ARP, SYN, data, and other forward control enter request slots except pure ACK/FIN-after-response traffic, which enters tail slots. UFISpace-side ARP replies, SYN-ACK, and pure ACK/control enter ACK/control slots; response payload enters response slots. One direction-preserving FIFO prevents cross-slot overtaking.

The primary RN-L statistics use only 100 balanced successful application exchanges on one persistent TCP connection. Startup, teardown, idle cover epochs, and three clean reconnects are evaluated separately for outer-link exclusivity, fixed epoch volume, native TCP correctness, exact frame recovery, and bounded state. They are not mixed into the five-class application-length classifier and do not expand the RN-L claim to transaction-class concealment.

The live loss/retransmission scenario is also separate from the passive RN-L dataset. The test link drops a cell only after the sender emitted it; the sender continues every scheduled cell. Native endpoint TCP later emits a new inner retransmission, which can cross only through a later complete 22-cell epoch.

## Evaluation corpus

The baseline uses one persistent native TCP connection on port 20000 and at least 100 synthetic DNP3 request/response exchanges, balanced across five valid DNP3 response wire lengths. The traffic is generated only in the endpoint namespaces. A direct-veth run of the same endpoint workload supplies the latency baseline.

Leakage analysis reuses the S3 method without weakening it: five balanced response-length classes, transaction-disjoint train/test splits, 1,000 mutual-information permutations, 2,000 classifier bootstraps, and confidence intervals compared with five-class chance.

The fault suite covers:

- within-slot reorder;
- exact duplicate;
- missing cell with no partial inner release;
- replay after accepted epoch;
- wrong key epoch and authentication failure;
- conflicting duplicate;
- bounded-queue pressure and single-frame slot overflow;
- receiver timeout and clean fixed-duration shutdown;
- one live link-loss case in which native inner TCP retransmits later and the retransmission crosses a new complete fixed epoch.

Fault-injected transcripts are labeled separately from the passive no-fault RN-L evaluation.

## Pre-registered pass thresholds

| Gate | Required result |
| --- | --- |
| Application correctness | 100/100 expected DNP3 request/response exchanges, zero stream mismatch |
| DNP3 integrity | 100% validated link-header and data-block CRCs |
| Inner packet integrity | 100% byte equality at both trusted-boundary sequence oracles; 100% valid IPv4/TCP checksums |
| Outer exclusivity | 100% EtherType `0x88B5`; zero clear ARP/IPv4/TCP/DNP3 frames |
| Structural transcript | 256 bytes per cell; 22 cells and 5,632 bytes per complete baseline epoch; fixed 6-forward/16-reverse slot vector |
| Leakage evaluation | structural mutual information 0; transaction-disjoint classifiers' confidence intervals include five-class chance |
| Scheduling | no skipped transmitter cell; p99 absolute send-deadline slip at most 20 ms and maximum at most 50 ms in this host run |
| Buffers | high-water marks stay within 128 frames and 262,144 bytes; zero baseline overflow/drop |
| Resources | each shim maximum RSS at most 128 MiB and process CPU/wall ratio at most 1.0 |
| Latency/rate | normalized p95 RTT and p95 added RTT at most three 210-ms epochs; at least 2 completed exchanges/s over the measured steady-state interval |
| Fault behavior | every declared case is fail closed or recovers through native TCP as specified; no deadlock; no partial frame release |

If host scheduling noise alone exceeds a timing threshold, S4 is `PARTIAL` and the measured gap is retained; the threshold is not silently weakened after the run.

## Evidence package

Generated evidence lives at `evidence/s4_software/` and includes:

- trusted input/output PCAPs for both directions;
- observed outer-link PCAP and observer CSV/statistics;
- application, packet, checksum, transcript, fault, latency/rate, and resource JSON/CSV summaries;
- topology/tool-version log, reproduction script, claim matrix, and SHA-256 manifest.

Evidence logs may contain synthetic case identifiers, hashes, public counters, and aggregate metrics. They do not contain keys, decrypted cell metadata, true per-epoch occupancy, or production traffic.

## Claim and stop condition

A pass supports only:

> PASS - isolated rootless network-namespace software prototype of the RN-L packet-preserving fixed-cell bridge.

It does not demonstrate hardware-observed real size normalization, the Tofino CPU punt/reinject path, RRC/BOR integration, physical-relay behavior, RN-T, multi-device indistinguishability, production key lifecycle, or deployment readiness. Work stops before S5.
