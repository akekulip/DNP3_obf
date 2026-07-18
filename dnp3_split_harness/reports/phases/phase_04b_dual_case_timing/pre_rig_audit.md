# Phase 04B — Pre-rig audit (corrective.md §14–16)

Required audit **before** the two-host rig run is meaningful. Run unprivileged on the local
Gate-C campaign (`phase04b_dcrn_audit.py --run-dir …`); the identical audit will run on the rig
captures. Source: `campaign_local/{NATIVE,DCRN_FIXED,DCRN_COMMON_BOUNDED}.pcap`, machine output
`campaign_local/phase04b_audit.json`. Device mapping verified: SEL751 → 174 separate, AB1400 → 174
combined, ION7550 → 174 combined per condition (no pooling).

## 1. Per-profile results (NOT pooled)

**NATIVE** — the native fingerprint the defense must remove:

| Profile | Native ACK structure | req→response (med ms) | req→ACK-event (med ms) | ACK→resp gap (med ms) | Deadline misses |
|---|---|---:|---:|---:|---:|
| SEL751 | **Separate** | 18.23 | **0.064** | 18.14 | 0/174 |
| AB1400 | Combined | 16.84 | 16.84 | N/A | 0/174 |
| ION7550 | Combined | 16.28 | 16.28 | N/A | 0/174 |

**DCRN_FIXED** (target 32.39 ms):

| Profile | Structure | req→response | req→ACK-event | ACK→resp gap | Deadline misses | Ordering viol. |
|---|---|---:|---:|---:|---:|---:|
| SEL751 | Separate | 32.63 | 32.47 | **0.182** | 0/168 | 0 |
| AB1400 | Combined | 32.44 | 32.44 | N/A | 0/168 | 0 |
| ION7550 | Combined | 32.44 | 32.44 | N/A | 0/168 | 0 |

**DCRN_COMMON_BOUNDED** (window [32.39, 42.39] ms):

| Profile | Structure | req→response | req→ACK-event | ACK→resp gap | Deadline misses | Ordering viol. |
|---|---|---:|---:|---:|---:|---:|
| SEL751 | Separate | 37.99 | 37.79 | 0.198 | 0/168 | 0 |
| AB1400 | Combined | 37.55 | 37.55 | N/A | 0/168 | 0 |
| ION7550 | Combined | 36.91 | 36.91 | N/A | 0/168 | 0 |

The native tell is stark: SEL's req→ACK-event is **0.064 ms** (a prompt pure ACK) against ~16 ms for
the combined devices. DCRN pins every profile's response to the target; the separate case's native
18.1 ms ACK→response gap collapses to a ~0.18–0.20 ms scheduler guard delta.

## 2. Scheduler error by profile — a residual fingerprint (the key finding)

`e_i = t_release − (t_request + D_i)`, computed on **DCRN_FIXED** (D_i = 32.39 ms is the clean case;
BOUNDED target independence is point 5). Per-profile median error: SEL751 **+0.24 ms**, AB1400/ION7550
**+0.05 ms**. Permutation test on the largest pairwise median difference:
**max median difference = 0.19 ms, p = 0.0002 → device-correlated scheduler error = TRUE.**

**Interpretation.** The dual-case guard (the separate case releases the response a scheduler-guard
after its pure ACK) makes the *separate* profile's response land ~0.19 ms later than the combined
profiles', deterministically. That 0.19 ms is a **new, device-correlated timing signal the defense
itself creates** — exactly the risk this audit exists to catch. It is small, but under FIXED it is
*deterministic*, so a classifier locks onto it (see point 6: FIXED pure-response leakage 0.62 > native
0.53). **Mitigation, already measured:** the BOUNDED target's per-transaction jitter masks the guard
delta (point 6: bounded pure-response 0.30, CI spans chance). **Design consequence: operate DCRN in
BOUNDED mode; FIXED alone re-encodes the ACK mode into response timing via the guard.** A second,
orthogonal fix is to shrink the guard toward zero (co-schedule the separate pure ACK and its response)
or to remove the separate ACK entirely via the Phase-05 coalescing primitive — the guard residual is
ultimately the ACK-mode channel bleeding into timing.

## 3. Ordering

**Zero** response-before-pure-ACK violations for every separate transaction, in every condition
(`ordering_response_before_pure_ack.violations = 0` for SEL751 in NATIVE/FIXED/BOUNDED; 168–174 separate
txns each). The invariant *pure ACK precedes response* holds by construction and is confirmed on the wire.

## 4. Timing feature-family purity

The pure-timing family is **`req_to_resp_ms` only** — clean, no `is_separate`, packet count, missingness
sentinel, or `resp_size` in it (`pure_timing_is_clean = True`). `req_to_ack_event_ms` is **mode-coupled
by construction** (it is the pure-ACK time for separate transactions and the response time for combined
ones), so its discriminating power is ACK mode, not timing — in NATIVE it alone scores 0.770, matching
`timing_all`. It is therefore reported as its own family and **excluded from the pure-timing claim**;
`timing_all` (both columns) is reported but flagged as inheriting the mode-coupling. All pure-timing
conclusions rest on `response_timing`.

## 5. Bounded-target independence

Observed range **[32.44, 42.61] ms**, **100 %** within the intended [32.39, 42.39] window (±1 ms band).
Per-profile response medians (SEL 37.99 / AB1400 37.55 / ION7550 36.91) — permutation test for a
profile-correlated target: **p = 0.124 → target independent of profile = TRUE**. The bounded target is
drawn from a per-transaction counter via `splitmix64(seed, counter)` (policy `select_target_ns`), a
function of neither profile, source IP, response size, native readiness, nor session — confirmed both in
code and by this distributional test.

## 6. Repeated grouped-CV uncertainty (100 disjoint session splits, chance = 0.333)

Balanced accuracy, mean ± std [95 % CI]:

| Family | NATIVE | DCRN_FIXED | DCRN_COMMON_BOUNDED |
|---|---|---|---|
| mode_only | 0.663 ± 0.024 | 0.665 ± 0.017 | 0.657 ± 0.070 |
| size | 0.657 ± 0.052 | 0.658 ± 0.050 | 0.653 ± 0.077 |
| **response_timing (PURE)** | 0.528 [0.378, 0.611] | **0.616 [0.554, 0.661]** | **0.302 [0.218, 0.363]** |
| ack_event_timing (mode-coupled) | 0.770 [0.682, 0.839] | 0.352 [0.291, 0.406] | 0.319 [0.218, 0.366] |
| timing_all | 0.770 [0.682, 0.839] | 0.641 [0.586, 0.684] | 0.407 [0.264, 0.480] |
| all | 0.993 | 0.990 | 0.987 |

Readings (with uncertainty, not a single split):
- **DCRN removes the dominant native timing leak** — the mode-coupled reverse-event timing falls
  0.770 → ~0.33 (chance) in both modes.
- **DCRN_BOUNDED closes the pure-timing channel:** response-timing 0.302, CI **[0.218, 0.363]** spans
  chance. **DCRN_FIXED does not** — 0.616, CI **[0.554, 0.661]**, strictly above chance and *above native*
  (0.528), because the deterministic 0.19 ms guard delta is a cleaner separator than the noisy native
  timing. This is the point-2 residual, seen through the classifier.
- **ACK mode and size are untouched** (mode_only ~0.66, size ~0.66, all ~0.99) — DCRN preserves them by
  design; they remain the out-of-scope residual channels.

## 7. Old application-scheduler condition — deliberate removal

`OLD_APPLICATION_SCHEDULER` (the Phase-02 application-write delay in `split_server`/`timing_policy`) is
**deliberately not re-run** in this campaign. It is a *different mechanism* — an application-layer delay
applied *before* the kernel chooses separate/combined — fully characterized in Phase 02
(`reports/phases/phase_02/`). DCRN's reason to exist is that it schedules *below* TCP, after the ACK
mode is already fixed, so it cannot perturb the ACK mode the way an application delay can. Re-running the
app scheduler here would add no information about DCRN and would risk the Phase-02 ACK-mode side effect.
Its removal is a scoping decision, documented; adding it to the rig as a comparison baseline is optional
future work, not a gate.

## Synthesis — audit verdict and what the rig must confirm

- **PASS with a named residual.** DCRN is byte-preserving, order-safe (0 violations), deadline-clean
  (0 misses), transport-clean, and removes the dominant native timing leak. The **BOUNDED** target closes
  the pure-timing channel to chance; the **FIXED** target leaves a **0.19 ms device-correlated guard-delta
  residual** — quantified, explained, and mitigated by BOUNDED. This is the honest basis for the status
  label `local_timing_attacker_eval = PASS_WITH_RESIDUAL_LEAKAGE`.
- **What the rig adds.** The 0.19 ms guard residual is a *loopback* measurement. The two-host rig must
  test whether it survives real switched-path jitter (it may fall below the noise floor, or persist),
  re-measure RTO on the real master, and confirm the per-profile picture on physical NICs / kernel 6.8 /
  observer-side Vision capture. **Report per-profile, never pooled**, and re-run this exact audit on the
  rig PCAPs.
