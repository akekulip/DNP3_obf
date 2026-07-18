# Phase 04B — Two-host rig results (Vision master ↔ Hulk outstation)

**Executed 2026-07-18.** DCRN loaded on **Hulk `eno1`** (outstation egress), authoritative capture on
**Vision `eno1`** (external-observer vantage, §6), DNP3 over TCP/20000 on the 1G management path.
Same source transactions / order / seed as the local Gate-C campaign. RUNS=5 per condition, 5/5 runs
ok each. Rig environment: **kernel 6.8.0-134, iproute2-6.1.0, libbpf 1.3.0** (Hulk + Vision).

## Toolchain port required (and its evidence)

The gambit-built DCRN object uses the **legacy iproute2 internal-loader** map format
(`bpf_elf_map`), which the rig's **libbpf-linked `tc`** rejects. This was caught by the Gate-A probe
on the rig (not assumed). A libbpf/BTF variant (`phase04b_dcrn.libbpf.o`, pin-by-name maps, built
with `-g`) was produced and **verifier-accepted on both hooks on kernel 6.8** (Gate-A rig evidence:
`manifests/gate_a_rig_hulk_capability_probe.txt`). This is the same DCRN decision core — only the map
ABI differs (`bpf/phase04b_dcrn.c`, `#ifdef DCRN_LIBBPF_MAPS`).

## Per-profile results (NOT pooled)

**NATIVE** (n=114) — native fingerprint on the real path:

| Profile | Structure | req→resp (med ms) | req→ACK-event (med ms) | ACK→resp gap (med ms) | Deadline misses | Order viol. |
|---|---|---:|---:|---:|---:|---:|
| SEL751 | Separate | 18.64 | **0.36** | 18.27 | 0/40 | 0 |
| AB1400 | Combined | 16.68 | 16.68 | N/A | 0/40 | 0 |
| ION7550 | Combined | 16.58 | 16.58 | N/A | 0/34 | 0 |

**DCRN_FIXED** (n=90, target 32.39 ms):

| Profile | Structure | req→resp | req→ACK-event | ACK→resp gap | Deadline misses | Order viol. |
|---|---|---:|---:|---:|---:|---:|
| SEL751 | Separate | 32.78 | 32.72 | **0.060** | 0/30 | 0 |
| AB1400 | Combined | 32.73 | 32.73 | N/A | 0/30 | 0 |
| ION7550 | Combined | 32.73 | 32.73 | N/A | 0/30 | 0 |

**DCRN_COMMON_BOUNDED** (n=88, window [32.39, 42.39] ms):

| Profile | Structure | req→resp | req→ACK-event | ACK→resp gap | Deadline misses | Order viol. |
|---|---|---:|---:|---:|---:|---:|
| SEL751 | Separate | 37.52 | 37.46 | 0.059 | 0/30 | 0 |
| AB1400 | Combined | 38.10 | 38.10 | N/A | 0/30 | 0 |
| ION7550 | Combined | 37.98 | 37.98 | N/A | 0/28 | 0 |

Range [32.86, 42.71] ms, 100% within window, **target profile-independent (permutation p=0.869)**.

## Transport safety & byte preservation

**0 retransmissions, 0 resets, 0 duplicate-ACKs, 0 ACK-after-response violations, 0 ordering
violations, 0 deadline misses** across all three conditions (292 non-first transactions total). DCRN
writes only `skb->tstamp`, never payload — byte preservation holds by construction, and the clean
transport (0 retrans over 15 runs) empirically confirms every target is inside the RTO-safe window on
the real master (RTO precondition satisfied by measurement; `TCP_RTO_MIN` is a 200 ms kernel constant
unchanged on 6.8).

## Scheduler error by profile (FIXED)

`e_i = t_release − (t_request + 32.39 ms)`. Per-profile median error: SEL751 +0.39 ms, AB1400/ION7550
+0.34 ms. **Device-correlated = TRUE** (max median difference **0.056 ms**, p=0.0002). The dual-case
guard residual is *smaller* than on loopback (0.056 vs 0.19 ms) but still deterministic — and, as the
CV below shows, still a classifier handle.

## Attacker evaluation — rig confirms the loopback conclusion

Pure response-timing balanced accuracy (100-split grouped CV, chance 0.333), rig vs loopback:

| Condition | rig | loopback |
|---|---|---|
| NATIVE | 0.731 [0.571, 0.818] | 0.528 [0.378, 0.611] |
| **DCRN_FIXED** | **0.740 [0.642, 0.839]** | 0.616 [0.554, 0.661] |
| **DCRN_COMMON_BOUNDED** | **0.289 [0.177, 0.401]** | 0.302 [0.218, 0.363] |

Mode + size unchanged (mode_only 0.667, size 0.667, all 1.0) on the rig too.

**The rig answers the open question from the loopback audit:** the FIXED guard-delta residual
**survives real switched-path jitter** — DCRN_FIXED pure-timing accuracy (0.740) is above chance and
statistically indistinguishable from native (0.731); the deterministic guard is a classifier handle
regardless of magnitude. **DCRN_COMMON_BOUNDED closes the timing channel** on the physical rig (0.289,
CI spans chance), exactly as on loopback. **Design conclusion, now confirmed on hardware: operate DCRN
in BOUNDED mode; FIXED alone does not reduce timing leakage.** ACK mode and size remain the
out-of-scope residual channels (all = 1.0) — DCRN is a timing normalizer, as designed.

## Scope / caveats

- Smaller sample than loopback (n=88–114 vs 504–522; ~30–40 txns/profile, RUNS=5 over 6 sessions) →
  **wider CIs**. The within-rig ordering (BOUNDED ≪ FIXED ≈ NATIVE for pure timing) is robust; the
  absolute native pure-timing estimate (0.731) carries wide uncertainty. A higher RUNS count would
  tighten the CIs — offered as a cheap follow-up, not a blocker.
- 1G management path (not the 25G Tofino data plane); READ-only, single-outstanding, loss-free
  workload (see `bypass_realism.md`). Physical three-device hardware (real SEL-751/AB1400/ION7550,
  not replay) remains a separate external-validation line.

**Evidence.** `campaign_rig/{NATIVE,DCRN_FIXED,DCRN_COMMON_BOUNDED}.pcap` +
`phase04b_{timing_summary,classifier_metrics,audit}.json` + `spec.json`; sha256 in
`manifests/campaign_rig_sha256.txt`. Gate-A rig probe: `manifests/gate_a_rig_hulk_capability_probe.txt`.
