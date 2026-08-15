# Size Topology and Capability Audit

Gate: S1

Status: reviewed read-only audit

Audit time: 2026-08-14 EDT / 2026-08-15 UTC

## Decisive result

The current testbed contains a verified master-side shim host and one plausible—but not yet proven—relay-edge shim path:

```text
Vision host software
  <-> observed 25G Vision/dp9 link
  <-> Tofino P4 CPU steering
  <-> onboard UFISpace CPU via ens1/bf_kpkt
  <-> clear relay-side timing/forwarding path
  <-> existing SEL/ION leg on dp64
```

Vision is capable of hosting the first trusted boundary. The UFISpace onboard x86 CPU has working standard AEAD APIs and a live `bf_kpkt` kernel packet interface, so it is the only plausible second boundary under the no-new-hardware constraint.

However, the second boundary is **not established** by those facts. The current Defense 4 P4/control sources do not implement a fixed-cell CPU punt/reinject path, and this audit did not mutate the live dataplane to prove one. Exact endpoint-transparent packet flow from `dp9 -> CPU -> timing path -> dp64`, and the reverse path, is the central post-approval feasibility gate.

If that CPU path cannot be proven on the installed switch, real total-length hiding is impossible in this testbed. No other relay-edge host, SmartNIC, or gateway is available or permitted.

## Evidence classification

- **Verified live** — read directly from Vision or UFISpace during this audit.
- **Verified repository** — established by the active authority or frozen evidence.
- **Supported by installed source** — the local SDE/driver contains the capability, but Defense 4 has not integrated or exercised it.
- **Unverified** — must not be treated as an available mechanism.

No command in this audit changed interfaces, routes, P4, BFRT tables, ports, TM, PRE, mirrors, pktgen, traffic, capture state, or relay state.

## Current physical topology

| Zone | Component | Current path | Evidence status |
| --- | --- | --- | --- |
| Master trust zone | Vision host | DNP3 master side on `enp59s0f0np0`, `192.168.10.1/24` | Verified live and repository |
| Protected observer link | Vision to Tofino | Vision NIC to switch `dp9`, 25 Gb/s | Verified live/repository |
| Switch data plane | UFISpace Tofino-1 | `dp8` RRC loopback, `dp9` Vision, `dp64` relay, `dp68` internal pktgen/recirc | Verified repository; prior and current live programs differ |
| Candidate relay-edge trust zone | UFISpace onboard CPU | Linux `ens1`, driver `bf_kpkt` | Verified live; end-to-end steering unverified |
| Relay zone | Existing unmanaged relay leg | `dp64` at 1 Gb/s to SEL-751 `.7` and ION 7550 `.8`, TCP/20000 | Verified repository and reachability audit |

The user explicitly excluded Hulk and all added hosts/SmartNICs. Historical Tooling references to Hulk are not candidate resources for this phase.

## Live-state drift that affects design

The frozen final evidence records `defense4_rrc_bor_unified12` as the one-program RRC+BOR authority. At audit time the live `bf_switchd` command was:

```text
/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd
  --conf-file /home/decps/rrc_build/defense4_rrc.conf
```

and that configuration identifies `defense4_rrc_kernel`, an RRC-only baseline. This does not change the frozen result, but it means a future integration plan cannot assume the final unified binary is currently loaded. No reload or bind-changing BFRT query was attempted.

## Vision: master-side boundary audit

### Verified host and link

| Item | Live value |
| --- | --- |
| OS / kernel | Ubuntu 24.04.4 LTS / Linux 6.8.0-136-generic |
| CPU | 2x Intel Xeon Gold 6140, 72 logical CPUs |
| CPU crypto flags | `aes`, `pclmulqdq`, `avx`, `avx2`, `rdrand`, `rdseed` |
| Data interface | `enp59s0f0np0`, driver `i40e` |
| Address | `192.168.10.1/24` |
| Current MTU / supported max | 1500 / 9702 |
| Link | 25,000 Mb/s, full duplex, DAC, link detected |
| Python / cryptography | Python 3.12.3 / `cryptography 41.0.7` |
| AEAD APIs | `AESGCM` and `ChaCha20Poly1305` import successfully |
| OpenSSL | 3.0.13 |

### Hook points

The host already provides `tc`, `bpftool`, `iptables`, `nft`, raw packet tools, and Python. A user-space proxy/TUN or raw-socket prototype is therefore viable without modifying the DNP3 master binary. XDP/eBPF may be useful for steering, but cryptography should remain in reviewed user-space or kernel tunnel code rather than be invented in eBPF.

TSO, GSO, and GRO are currently enabled. They can change host-side capture shape, so later observer evidence must capture at the actual wire boundary or explicitly control/account for offloads. S0-S2 did not change them.

### Crypto and tunnel offload

Vision's NIC reports the following as fixed off:

- ESP hardware offload;
- TLS TX/RX and TLS record offload;
- MACsec hardware offload.

`wg`, `ipsec`, and `swanctl` were not found. The immediately available option is software AEAD via installed libraries, not a preconfigured standard tunnel or NIC crypto offload.

### Assessment

**Verified capable** as the first trusted boundary. Performance remains to be benchmarked with synthetic buffers after design approval, but the small current DNP3 transaction rate is not an S1 capacity blocker.

## UFISpace onboard CPU: candidate second boundary

### Verified host and interface

| Item | Live value |
| --- | --- |
| OS / kernel | Ubuntu 20.04.3 LTS / Linux 5.4.0-216-generic |
| CPU | Intel Xeon D-1527, 4 cores / 8 threads |
| CPU crypto flags | `aes`, `pclmulqdq`, `avx`, `avx2`, `rdrand`, `rdseed` |
| Packet interface | `ens1`, driver `bf_kpkt` 9.13.2-281-cpr |
| MAC / address | `00:02:00:00:03:00`; link-local IPv6 only |
| Current MTU / supported max | 1500 / 9710 |
| Observed counters | RX 23 packets / 1604 bytes; TX 152 packets / 11666 bytes; zero errors/drops |
| Python / cryptography | Python 3.8.10 / `cryptography 2.8` |
| AEAD APIs | `AESGCM` and `ChaCha20Poly1305` import successfully |
| OpenSSL | 1.1.1f |

The `bf_kpkt` module is loaded. Live parameters include `kpkt_mode=1`, MSI interrupt mode, RX count 256, and 32 bytes of headroom.

### Installed-source evidence

The installed SDE 9.13.2 sources provide concrete CPU-port machinery:

- `pkgsrc/switch-p4-16/p4src/shared/parde.p4` defines ingress and egress CPU-port value sets and CPU parsing;
- `pkgsrc/switch-p4-16/p4src/shared/port.p4` defines CPU-port properties and rewrite tables;
- `pkgsrc/bf-drivers/kdrv/bf_kpkt/bf_kpkt_net.c` registers a Linux net device with RX and TX paths;
- the driver transmit function queues Ethernet frames to the packet DMA rings, while RX delivers ASIC packets into the Linux networking stack.

This proves the installed platform has generic host-packet I/O capability. It does **not** prove the Defense 4 P4 parser, metadata, direction classification, or forwarding graph can use it correctly.

### Missing endpoint-transparent proof

The Defense 4 P4/control sources contain no explicit `bf_kpkt`, CPU-port, punt, or reinject path. The following remain unverified:

1. the exact CPU dev-port/value-set mapping for the installed UFISpace target;
2. the metadata/header contract for packets punted to and reinjected from `ens1`;
3. classification of CPU-origin clear DNP3 as trusted master-side or relay-side traffic;
4. placement of CPU steering relative to RRC/BOR internal loops;
5. reverse-path routing that prevents clear variable-length response bytes from reaching `dp9` before cellization;
6. stage/resource fit beside the authoritative unified design;
7. CPU-path latency, throughput, queue bounds, and failure behavior.

### Crypto and offload

The CPU supports software AES acceleration and both reviewed AEAD APIs import. The `bf_kpkt` interface reports ESP, TLS, and MACsec hardware offloads fixed off. `wg`, `ipsec`, and `swanctl` were not found. There is no verified inline hardware crypto accelerator on this path.

### Assessment

**Plausible, not proven** as the second trusted boundary. The distinction is load-bearing: `ens1` being UP is not equivalent to a working fixed-cell decapsulation/reinjection path.

## Tofino data-plane constraints

The Tofino data plane can classify fixed outer cells, steer them to the CPU, distinguish CPU-origin frames, and forward clear relay-side packets if a fitting P4 design is compiled and validated. It cannot provide standard cryptographic confidentiality or authenticated decryption in P4, and this phase will not invent such cryptography.

The selected design must preserve the conceptual mechanisms:

- BOR decides when an inner OPERATE is intended to reach the relay;
- RRC decides master-visible ACK/response timing;
- cellization decides the sizes/counts visible on the protected link.

The current `[28,21]` egress carve must not remain in the public protected transcript. Whether it is bypassed, removed, or retained only inside a trusted clear zone is an S2 integration decision.

## Relay leg and capture locations

### Relay capability

The existing `dp64` leg reaches both current devices through the unmanaged switch:

- SEL-751 at `192.168.10.7:20000`;
- ION 7550 at `192.168.10.8:20000`.

Both were reachable from Vision during the read-only audit. Neither endpoint is modified, and no relay-edge host exists beyond the Tofino CPU candidate.

### Capture matrix

| Location | Current capability | Limitation |
| --- | --- | --- |
| Vision `enp59s0f0np0` | Verified master-facing capture point and selected observer link | Host offloads must be controlled/accounted for in later wire evidence |
| Vision local shim boundary | Feasible future inner cleartext oracle | Does not exist until implementation |
| Tofino `ens1` | Future CPU-side cell/clear boundary capture is plausible | Actual punt/reinject path is unverified |
| Relay-facing `dp64` | Physical forwarding link | No dedicated passive host tap in the current testbed |
| `dp68` | Internal pktgen/recirc/clone | Explicitly not a host-capturable relay tap |

The lack of a `dp64` tap preserves the prior BOR evidence limitation. Later size proof can still use paired trusted-shim byte logs/pcaps plus the public observer capture, but must not call `dp68` a wire oracle.

## Clock synchronization

Both Vision and UFISpace report `NTP=yes` and `NTPSynchronized=yes`. Vision chrony reported stratum 3 and approximately 17 microseconds RMS offset during this audit. UFISpace lacks a verified `chronyc` detail readout, so NTP synchronization is confirmed but its current offset bound is not.

This supports a future scheduled-cell experiment, but timing claims still require common capture calibration or one capture clock at the observer link.

## Existing traffic-size inventory

The committed corpus provides design inputs, not final cell parameters:

| Evidence class | Inner sizes observed | Status |
| --- | --- | --- |
| Physical SEL admitted requests | 20-byte READ; 45-byte SELECT/OPERATE | Physical current-testbed evidence |
| Physical SEL eligible responses | 49 bytes, native `[49]` or defended `[28,21]` | Physical current-testbed evidence |
| Physical state-read outlier | 58-byte response | Physical but outside prior admitted profile |
| Existing ION comparison | 17-byte READ response; 32-byte SELECT echo | Current relay-leg device evidence, incomplete |
| OpenDNP3 loopback | 243-byte response; 1574-byte reassembled fragmented response | Software-only envelope evidence |

These data prove that request direction and larger records matter. They do not justify numerical `C`, `K_req`, `K_ack`, `K_resp`, or `L_max`. S2 may define a sizing method and provisional policy, but S3 must measure a fresh fixed-cell trace before freezing constants.

## Boundary-placement candidates

| Placement | Feasibility | Decision input |
| --- | --- | --- |
| Vision user-space proxy/TUN plus reviewed AEAD | Verified feasible | Preferred master-side boundary |
| Vision XDP/eBPF steering plus user-space AEAD | Feasible but more complex | Optimization only; not needed for initial proof |
| Tofino onboard CPU `ens1`/`bf_kpkt` | Plausible, integration unverified | Only current-testbed relay-edge candidate |
| Tofino P4 data plane alone | Infeasible for required crypto | P4 may steer/schedule, never encrypt/decrypt |
| Existing WireGuard/IPsec tunnel | Unavailable today | Tools are absent; tunnel alone would still leak length |
| NIC/TLS/IPsec/MACsec hardware offload | Not available on audited interfaces | Reported fixed off |
| Added host, SmartNIC, or gateway | Excluded | User constraint |

## S1 verdict and S2 entry conditions

S1 passes as a truthful capability audit, not as proof of deployability:

- **Verified:** first boundary on Vision; software AEAD on both x86 hosts; installed `bf_kpkt` packet I/O substrate; MTU/link/clock/capture facts.
- **Conditionally viable:** second boundary on the Tofino CPU using a new, reviewed P4 CPU-steering path.
- **Unverified blocker:** endpoint-transparent bidirectional punt/reinject integrated with RRC/BOR without cleartext bypass.
- **Unavailable:** extra hardware, preinstalled standard tunnels, or audited inline crypto offload.

S2 may select the Tofino-CPU design only as a **conditional architecture**. Before any hardware deployment claim, a later approved minimal proof must demonstrate:

```text
fixed cell on dp9
  -> P4 punt
  -> ens1 userspace receipt
  -> authenticated decellization
  -> CPU reinjection
  -> clear DNP3 through the intended timing path to dp64

relay response on dp64
  -> RRC timing release
  -> CPU delivery
  -> fixed-volume cellization
  -> fixed cell on dp9
```

Failure of that proof terminates the mechanism under the present topology.

## Evidence anchors and commands

Repository:

- `defense4/README.md`
- `defense4/CLAIMS.md`
- `defense4/size/native_parity/evidence/E_FINAL/E0_testbed_preservation.md`
- `defense4/size/native_parity/evidence/E_FINAL/`
- `/home/philip/Projects/Tooling/tofino_25g_connectivity_map.md`

Read-only command families used:

- `ssh`, `hostname`, `uname`, `lscpu`;
- `ip -br addr`, `ip -d link`, `ip -s link`;
- `ethtool`, `ethtool -i`, `ethtool -k`;
- Python imports of `cryptography`, `AESGCM`, and `ChaCha20Poly1305`;
- `openssl version`, `command -v wg/ipsec/swanctl`;
- `timedatectl`, `chronyc tracking` where available;
- `pgrep -a bf_switchd`, read-only config inspection;
- read-only searches of installed SDE and `bf_kpkt` source.

Detailed excerpts are preserved in:

- `agents/topology_capability.md`
- `agents/trace_inventory.md`
- `agents/crypto_options.md`
