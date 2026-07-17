# Phase 04B — Gate B (dual-case smoke): local end-to-end DCRN result

**PASS (local veth, DCRN_FIXED).** The DCRN tc/eBPF executor was loaded and run end-to-end on an
isolated veth pair (replay server in a netns on `vdcrn1` with DCRN ingress+egress attached; client in
the root netns; authoritative capture on the client-side `vdcrn0`). Real measured result:

| metric | native (pre-fix / no enforcement) | DCRN_FIXED (target 32.39 ms) |
|---|---:|---:|
| req→response median (non-first) | ~16.4 ms | **32.42 ms** |
| req→response spread (min–max, non-first) | ~15–32 ms | **32.41–32.63 ms** |
| separate (SEL) req→pure-ACK median | ~0.04 ms (native) | **32.42 ms** (held to target) |
| byte-identical | 150/150 | **150/150** |
| retransmissions / resets (non-first, established) | 0 / 0 | **0 / 0** |

**What this proves:** DCRN normalizes the visible request→response timing of BOTH native structures to
the common calibrated target, byte-preservingly, with clean established-session transport. The
separate-case pure ACK and response are both held to the target (dual-case); the combined-case response
is held to the target. Packet structure is preserved (SEL stays separate, AB/ION stay combined).

**Root causes fixed to get here (real debugging, wire-verified):**
1. Ingress `is_read_request` used direct packet access, but the DNP3 payload is **not linear on the
   tc-ingress path** → the func-byte read failed and nothing armed. Fixed with `bpf_skb_load_bytes`.
2. Ingress and egress are two separate `tc filter` attaches of one object → the legacy loader gave each
   its **own private map instance** (arming in one, lookup in the other → always noflow). Fixed by
   **pinning the maps** (`.pinning = 2` → `/sys/fs/bpf/tc/globals/`) so both attaches share them. (On
   the real rig root netns a plain attach shares the pinned maps; the local run additionally does both
   attaches in one `ip netns exec` shell because per-exec mount namespaces otherwise split bpffs.)
3. Removed an over-eager `response_seen` egress guard that bypassed post-first transactions.

The proven minimal EDT program held a ping to ~30 ms on the same veth, confirming fq EDT enforcement is
not the issue — the failures were DCRN logic, now fixed.

**Scope / not yet done:** this is a single local veth run (DCRN_FIXED). The full paired campaign
(NATIVE / OLD_APPLICATION_SCHEDULER / DCRN_FIXED / DCRN_COMMON_BOUNDED), the two-host Vision↔Hulk rig,
the equal-deadline FIFO/guard microbenchmark, the RTO re-measurement, and the timing attacker eval
remain. Evidence: `manifests/gate_b_local_dcrn_fixed.pcap` (sha256 3178b7a4…).
