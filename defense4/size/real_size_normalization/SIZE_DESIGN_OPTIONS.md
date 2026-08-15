# Size Design Options

Gate: S2

Status: reviewed; conditional selection awaiting author approval

## Decision frame

Every viable option must:

- use only Vision, the installed UFISpace Tofino-1/onboard CPU, and the existing relay leg;
- create two real trusted boundaries around the observed Vision-to-`dp9` link;
- preserve unmodified master and relay behavior;
- keep standard cryptography out of P4;
- emit fixed outer sizes, counts, directions, and policy slots;
- encrypt inner length, type, occupancy, and padding boundaries;
- preserve RRC/BOR as distinct timing/release mechanisms;
- fail closed with no clear DNP3 fallback on the observed link.

No numerical `C`, `K`, or `L_max` is selected here because the S1 trace inventory does not yet bound the protected corpus and overhead sufficiently.

## Option A — packet-preserving Layer-2 AEAD cells

### Shape

```text
Vision virtual-Ethernet boundary
  <-> fixed-count fixed-wire-size AEAD Ethernet cells
  <-> P4 CPU gate
  <-> UFISpace CPU ens1/bf_kpkt shim
  <-> clear inner Ethernet frames
  <-> RRC/BOR and dp64 relay leg
```

The shims encode complete inner Ethernet frames, excluding physical FCS, into a fixed directional slot schedule over a dedicated outer EtherType. The outer link does not expose inner IP/TCP sequence, ACK, DNP3 length, or function fields. The receiving shim restores the original inner frame before delivery.

### Assessment

| Dimension | Assessment |
| --- | --- |
| Security | Strongest fit. Fixed valid AEAD cells directly implement the S0 transcript invariant. |
| Endpoint transparency | Best option. It preserves the original end-to-end TCP packets rather than terminating TCP in proxies. |
| Implementation effort | High. Requires a Vision TAP/virtual-Ethernet shim and a new P4/CPU steering contract. |
| Timing interaction | Compatible with RRC/BOR if request reinjection and response cell release use fixed deadlines. |
| Hardware needs | No added hardware; conditional on the installed CPU packet path. |
| Throughput | Software AEAD on both x86 CPUs; current DNP3 rates are plausible, but CPU/queue performance is unmeasured. |
| Loss handling | No public cell-layer retransmission; fixed deadline, bounded buffering, fail-closed epoch drop, inner TCP recovery in a new fixed epoch. |
| Testbed change | Later software/interface configuration and P4 integration; none during S0-S2. |

### Verdict

**Selected conditionally.** It is the only option that preserves the current timing architecture and removes inner TCP metadata from the observed link.

## Option B — dual TCP proxies with fixed AEAD records

### Shape

Vision terminates the master's TCP connection, sends fixed encrypted application records, and the UFISpace CPU originates a second TCP connection to the relay.

### Assessment

| Dimension | Assessment |
| --- | --- |
| Security | Can hide length if record count/schedule is fixed. |
| Endpoint transparency | Endpoints are unmodified, but original end-to-end TCP semantics are replaced by two sessions. |
| Implementation effort | Moderate for application framing; high for connection lifecycle and exact DNP3 behavior. |
| Timing interaction | Poor fit. Master-visible TCP ACK behavior becomes local to Vision and no longer reflects the existing RRC path. |
| Hardware needs | Same unproven Tofino CPU boundary. |
| Throughput | Two software TCP stacks plus AEAD are likely adequate for DNP3 rates, but remain unmeasured. |
| Loss handling | Mature TCP reliability, but two independent congestion/retransmission systems complicate the observer schedule. |
| Testbed change | New privileged proxies, address/route redirection, and timing-policy redesign. |

### Verdict

**Rejected as primary.** It solves a different endpoint model and risks invalidating the strongest existing RRC claim.

## Option C — fixed records inside WireGuard or IPsec

### Shape

A shim first emits fixed-size, fixed-count plaintext records; a standard secure tunnel then encrypts and transports them between Vision and the UFISpace CPU.

### Assessment

| Dimension | Assessment |
| --- | --- |
| Security | Strong tunnel security, but only the inner fixed-record shim supplies size hiding. |
| Endpoint transparency | Compatible with a trusted virtual link if routing and MTU are correct. |
| Implementation effort | Moderate when already installed; higher here because no tunnel tool is present. |
| Timing interaction | Handshakes, keepalives, rekeys, PMTU, and error traffic create visible events that must be excluded or scheduled. |
| Hardware needs | No new hardware; software installation/configuration is required later. |
| Throughput | A kernel tunnel could outperform a Python transport, but neither endpoint is benchmarked for this design. |
| Loss handling | Tunnel fragmentation, retransmission interaction, PMTU, and rekey behavior require direct validation under the complete observer. |
| Testbed change | New packages, keys, interfaces, routes, and P4 steering. |

### Verdict

**Fallback only.** `wg`, `ipsec`, and `swanctl` are absent on both audited hosts. An ordinary tunnel carrying variable packets remains insufficient.

## Option D — existing hardware crypto/offload

The audit checked the actual Vision and `bf_kpkt` interfaces rather than inferring from product families. ESP, TLS, and MACsec offloads report fixed off, and no other installed inline accelerator was verified.

### Assessment

| Dimension | Assessment |
| --- | --- |
| Security | Unknown because no installed standard inline-crypto path is exposed; P4-only cryptography is excluded. |
| Endpoint transparency | Potentially strong for a real inline device, but no such device/path is present. |
| Implementation effort | Indeterminate and not actionable on the installed hardware. |
| Timing interaction | Unknown; no path exists to measure alongside RRC/BOR. |
| Hardware needs | Would require hardware or firmware capability not verified in the allowed testbed. |
| Throughput | No applicable measurement can be made without a real offload path. |
| Loss handling | No applicable record/replay/overflow contract exists; offload alone would still require the fixed-cell scheduler. |
| Testbed change | Enabling a nonexistent/unverified feature is not an authorized design; adding hardware is prohibited. |

### Verdict

**Unavailable.** Hardware crypto cannot be selected on current evidence. P4 CPU steering is useful packet plumbing, not cryptographic offload.

## Explicitly rejected observer tricks

| Mechanism | Reason for rejection |
| --- | --- |
| `[49] -> [28,21]` or other resegmentation | TCP novel-byte total remains the true length. |
| IP fragmentation | Reassembly reveals the same total. |
| Ethernet padding | IP length distinguishes padding from inner bytes. |
| TCP options | Inner byte count and ACK progression remain visible. |
| Invalid, out-of-window, or duplicate packets | A protocol-aware observer filters or de-duplicates them. |
| Filterable chaff or cover on another flow | A protocol-aware observer separates it from the protected flow. |
| Clear DNP3 padding | Framing and length/type remain parseable; endpoints cannot remove it. |
| P4 cryptography | No reviewed standard crypto implementation is available in TNA P4. |
| Ordinary TLS/WireGuard/IPsec | Ciphertext length remains correlated without fixed records and schedule. |

## Comparative decision

| Option | S0 property | Preserves end-to-end TCP/RRC | Available now | Existing-testbed fit | Decision |
| --- | --- | --- | --- | --- | --- |
| A. L2 AEAD cell bridge | Yes by construction | Yes, if CPU path works | Building blocks only | Best | **Select conditionally** |
| B. Dual TCP proxies | Yes by construction | No | Building blocks only | Weak timing fit | Reject primary |
| C. Fixed records in standard tunnel | Yes only with shims | Potentially | Tunnel tools absent | Fallback | Defer |
| D. Hardware crypto/offload | Unknown | Potentially | No verified offload | Unavailable | Reject |

## Selection rationale

Option A is selected because it changes the public wire representation while keeping the original Ethernet/IP/TCP/DNP3 packet intact inside the trusted boundary. It is creative where the testbed permits creativity—the packet plumbing and schedule—not in cryptography.

The selection is conditional on a later approved proof that `bf_kpkt`/`ens1` and a fitting P4 program can form the relay-edge packet boundary. If that proof fails, S0's impossibility result controls.

## Evidence anchors

- `SIZE_SECURITY_DEFINITION.md`
- `OBSERVER_MODEL.md`
- `ONE_SIDED_IMPOSSIBILITY.md`
- `SIZE_TOPOLOGY_CAPABILITY_AUDIT.md`
- `agents/architecture.md`
- `agents/crypto_options.md`
- `agents/trace_inventory.md`
