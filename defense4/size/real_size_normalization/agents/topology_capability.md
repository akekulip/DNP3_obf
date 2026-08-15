# Topology Capability Audit

Owner: `testbed_capability` lane

Date: 2026-08-15 UTC

Scope: existing Vision host, existing UFISpace Tofino-1, and existing relay leg only
Mode: read-only SSH/repo audit; no capture, no injection, no BFRT mutation, no interface/route/port changes

## Decisive conclusion

The current testbed has enough hardware to explore a two-boundary fixed-cell design without adding another host: Vision can be the master-side trusted shim, and the UFISpace switch control CPU exposes an onboard kernel packet interface (`ens1`, driver `bf_kpkt`) that could plausibly become the relay-edge trusted shim.

That is not yet a demonstrated relay-edge trusted boundary. What is verified today is the CPU-side packet interface and local AEAD software availability. What remains unproven is the DNP3 punt/reinject path between the live P4 pipeline and `ens1`, plus a policy that keeps the observer-facing Vision<->Tofino link fixed-volume while delivering clear DNP3 only on the relay side.

If the CPU punt/reinject path cannot be made to carry the protected DNP3 stream inside the existing switch, then this topology falls back to one-sided segmentation only, and real total-length hiding is impossible under the mission observer.

## Repository and authority anchors

- `defense4/README.md:31-41` defines the completed topology as Vision on dp9, one Tofino-1, SEL-751 on dp64, internal loopbacks dp8/dp10, and pktgen dp68.
- `defense4/README.md:47-55` says the completed result demonstrated CLRT normalization and fixed `[28,21]` segmentation, but not exactly-once relay-facing BOR, multi-device indistinguishability, or byte identity.
- `defense4/CLAIMS.md:34-37` explicitly says relay-facing T0+J was not directly observed and total DNP3 length is not hidden: 49 bytes remains 49 bytes.
- `defense4/size/native_parity/evidence/E_FINAL/E0_testbed_preservation.md:8-14` records the frozen final port map: Vision dp9, SEL-751 dp64, dp8/dp10 internal loopbacks, dp68 internal pktgen/recirc/clone.
- `/home/philip/Projects/Tooling/tofino_25g_connectivity_map.md:15-52` records the current DNP3 rig map: UFISpace `10.10.54.81`, Vision `192.168.10.1/24` on dp9, relay leg on dp64 through an unmanaged switch to SEL `.7` and ION `.8`.

## Live Vision evidence

Command: `ssh decps@10.10.54.19 ...`

Verified excerpts:

```text
hostname: vision
OS: Ubuntu 24.04.4 LTS
kernel: Linux vision 6.8.0-136-generic
CPU: Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz
CPU(s): 72
Flags include: aes pclmulqdq avx avx2 avx512f rdrand rdseed
```

Network hook point:

```text
enp59s0f0np0 UP 3c:fd:fe:cc:5d:c0
enp59s0f0np0 192.168.10.1/24
mtu 1500 qdisc mq state UP
minmtu 68 maxmtu 9702
Speed: 25000Mb/s
Duplex: Full
Auto-negotiation: on
Port: Direct Attach Copper
Link detected: yes
driver: i40e
firmware-version: 8.15 0x800096ca 20.0.17
```

Offload and Linux hook surface:

```text
rx-checksumming: on
tx-checksumming: on
tcp-segmentation-offload: on
generic-segmentation-offload: on
generic-receive-offload: on
large-receive-offload: off [fixed]
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.ip_forward = 1
available commands include: iptables nft bpftool tc tcpdump tshark iperf3 python3 openssl
WireGuard: wg: command not found
```

Crypto software:

```text
OpenSSL 3.0.13
Python 3.12.3
cryptography 41.0.7
AEAD import: AESGCM and ChaCha20Poly1305 import successfully
```

Relay reachability from Vision:

```text
192.168.10.7 ping: 1 received, 0% packet loss
192.168.10.8 ping: 1 received, 0% packet loss
sel_tcp20000=0
ion_tcp20000=0
```

Assessment:

- Verified: Vision is a strong master-side software shim host with 25G data NIC, MTU headroom to 9702, Linux packet hooks, packet tools, Python AEAD support, and relay reachability.
- Verified risk: TSO/GSO/GRO are enabled today; any later transcript measurement must either disable or account for offloads at the capture/transmit boundary.
- Not verified: no live shim or fixed-cell process exists yet.

## Live UFISpace / Tofino evidence

Command: `ssh decps@10.10.54.81 ...`

Identity and active process:

```text
hostname: ufispace
OS: Ubuntu 20.04.3 LTS
kernel: Linux ufispace 5.4.0-216-generic
bf_switchd:
801137 /home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd
  --install-dir /home/decps/Downloads/bf-sde-9.13.2/install
  --conf-file /home/decps/rrc_build/defense4_rrc.conf
  --init-mode=cold
  --status-port 7777
```

Loaded configuration:

```text
program-name: defense4_rrc_kernel
bfrt-config: /home/decps/rrc_build/out_rrc/bfrt.json
context: /home/decps/rrc_build/out_rrc/pipe/context.json
config: /home/decps/rrc_build/out_rrc/pipe/tofino.bin
```

CPU:

```text
CPU: Intel(R) Xeon(R) CPU D-1527 @ 2.20GHz
CPU(s): 8
Thread(s) per core: 2
Core(s) per socket: 4
Flags include: aes pclmulqdq avx avx2 rdrand rdseed
```

Linux interfaces:

```text
enp8s0 UP 10.10.54.81/24          # management
enp2s0f0 DOWN
enp2s0f1 DOWN
ens1 UP 00:02:00:00:03:00 fe80::202:ff:fe00:300/64
ens1 mtu 1500 qdisc mq state UP
ens1 minmtu 68 maxmtu 9710
driver: bf_kpkt
version: 9.13.2-281-cpr
bus-info: 0000:04:00.0
```

Kernel packet module:

```text
lsmod: bf_kpkt 39772160 2
/sys/module/bf_kpkt/parameters:
intr_mode=msi
kpkt_dr_int_en=1
kpkt_hd_room=32
kpkt_mode=1
kpkt_rx_count=256
```

Packet counters at the time of audit:

```text
ens1 RX: bytes 1604 packets 23 errors 0 dropped 0
ens1 TX: bytes 11666 packets 152 errors 0 dropped 0
```

Crypto software:

```text
OpenSSL 1.1.1f
Python 3.8.10
cryptography 2.8
AEAD import: AESGCM and ChaCha20Poly1305 import successfully
WireGuard: wg: command not found
```

Assessment:

- Verified: the Tofino control CPU is a real onboard Linux trust candidate with AES-capable x86 CPU, Python AEAD support, and a live `bf_kpkt` interface (`ens1`) into the ASIC packet path.
- Verified: current live P4 is `defense4_rrc_kernel`, not the frozen final `defense4_rrc_bor_unified12` binary. The frozen final result remains repository authority for completed claims, but today's live switch state is an RRC-only baseline.
- Verified: `ens1` has no IPv4 address today and only link-local IPv6; there is no existing routed relay-edge gateway on the CPU.
- Not verified: no current P4 table/rule audit proves DNP3 packets are punted to `ens1` or that packets written on `ens1` are reinjected to dp64/dp9 with the intended metadata.

## Tofino P4 and CPU-port boundary finding

Repo search across the current RRC and unified P4/setup files found no explicit `CPU`, `bf_kpkt`, `ens1`, `punt`, `reinject`, or CPU dev-port constants in the Defense 4 P4/control sources. Matches were only generic parser declarations such as `parser IgParser(packet_in pkt, ...)`.

This means the current Defense 4 codebase does not already contain an obvious CPU-shim path. A later implementation would need a deliberate P4/control-plane addition for:

- classifying fixed-cell outer packets from Vision;
- sending those cells to `ens1` or another verified CPU ingress path;
- accepting decapsulated clear DNP3 from the CPU and steering it to dp64;
- accepting relay responses from dp64 and steering them through RRC/timing before CPU-side cellization toward Vision;
- ensuring no clear or variable-length DNP3 transcript remains visible on the protected observer link.

I attempted to run the existing read-only port inventory script, but it binds to `defense4_rrc_bor_unified12` and failed because the live program is `defense4_rrc_kernel`:

```text
StatusCode.NOT_FOUND:
Failed to find BfRtInfo for program defense4_rrc_bor_unified12
```

I did not force a live BFRT bind/query after the sandbox reviewer flagged `bind_pipeline_config` as potentially issuing `SetForwardingPipelineConfig`. The audit therefore does not claim a fresh live `$PORT` table dump. It relies on live Linux/process evidence plus the repository/Tooling port-map anchors above.

## Clock and capture options

Vision:

```text
System clock synchronized: yes
NTP service: active
chrony tracking: stratum 3, RMS offset 0.000015596 seconds
```

UFISpace:

```text
System clock synchronized: yes
NTP service: active
chronyc: command not found
```

Capture points:

- Verified existing master-facing capture: Vision `enp59s0f0np0` per E_FINAL reproduction docs.
- Existing relay-facing direct tap remains unavailable; `dp68` is internal pktgen/recirc/clone and not a host-capturable relay tap.
- Any S3/S4/S5 measurement of size secrecy should first use offline/network-namespace traces, then later capture the protected Vision<->Tofino outer link once shims exist.

## Feasibility boundary

Verified feasible local building blocks:

- Vision can host the master-side fixed-cell shim.
- UFISpace control CPU can host standard software cryptography and exposes `ens1` via `bf_kpkt`.
- Existing physical relay leg remains reachable through dp64 to SEL `.7` and ION `.8`.
- Both Vision and UFISpace CPUs advertise AES-capable x86 instructions; Python AEAD imports work on both.

Unverified blockers before selecting this as the final S2 design:

- CPU-port punt/reinject semantics for `bf_kpkt` with the current SDE and target P4 program.
- Exact metadata/header format and dev-port mapping for cells entering/leaving `ens1`.
- Throughput and latency budget of user-space AEAD plus `bf_kpkt` on the Xeon D-1527.
- How to preserve RRC/BOR ordering when relay responses must pass through CPU cellization.
- Whether the live P4 can fit the required CPU-steering path alongside existing RRC/BOR constraints without breaking the ≤12-stage authority.

## Recommendation to leader

Select the existing-testbed architecture conditionally:

```text
Vision shim
  <-> fixed-size AEAD cell transcript on observed dp9 link
  <-> Tofino P4 CPU-steering boundary
  <-> UFISpace CPU shim on ens1/bf_kpkt
  <-> clear DNP3 only on relay-side path through RRC/BOR and dp64
```

But gate it on an S2 approval condition: before S3/S4 implementation claims, prove in an offline/minimal hardware-safe harness that `bf_kpkt` can receive a P4-punted frame and reinject a CPU-originated frame to the desired data-plane port without adding hardware or exposing clear variable-length DNP3 on the protected link.

If that condition fails, there is no verified second trusted boundary in the current testbed. The project must stop at the impossibility result rather than relabeling resegmentation, Ethernet padding, fragmentation, chaff, or clear DNP3 padding as real size normalization.
