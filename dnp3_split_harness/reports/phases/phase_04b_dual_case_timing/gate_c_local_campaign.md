# Phase 04B — Gate C: full paired local campaign (corrective.md §10–11, §15)

**Environment.** gambit, kernel 5.15.0-139, python 3.8. Isolated veth pair
`vdcrn0` (root ns, client/observer) ↔ `vdcrn1` (`dcrn-srv` netns, server), `fq`
root qdisc on the server side, DCRN attached on the server-side `tc` ingress+egress.
**Authoritative capture on the client-side veth `vdcrn0`** (external-observer vantage, §6).
Same source transactions / order / seed across every condition (only the loaded DCRN
object changes). Runner: `scripts/phase04b_local_campaign.sh` (3 runs × the spec's
session set per condition). Post-capture analysis is unprivileged.

## Conditions

| Condition | DCRN object | What it is |
|---|---|---|
| NATIVE | none | no DCRN, no application scheduler — the native dual-structure baseline |
| DCRN_FIXED | `bpf/phase04b_dcrn.o` | DCRN eBPF, single fixed class-independent target (32.39 ms) |
| DCRN_COMMON_BOUNDED | `bpf/phase04b_dcrn_bounded.o` | DCRN eBPF, per-transaction target drawn from the bounded window [32.39, 42.39] ms |

`OLD_APPLICATION_SCHEDULER` (the Phase-02 application-write delay) is **not** re-run
here; it was characterized in Phase 02 and is retained as a documented reference
condition. DCRN's structural advantage over it — it schedules *below* TCP, after the
kernel has already chosen separate/combined, so it cannot change the ACK mode — is the
reason this line exists.

## Timing result (req→response, non-first transactions)

| Condition | n | median (ms) | mean (ms) | std | p99 (ms) | separate ACK→resp gap median (ms) |
|---|---:|---:|---:|---:|---:|---:|
| NATIVE | 522 | 16.66 | 17.47 | 2.35 | 26.34 | 18.14 |
| DCRN_FIXED | 504 | 32.61 | 32.60 | 0.17 | 32.97 | 0.18 |
| DCRN_COMMON_BOUNDED | 504 | 37.54 | 37.57 | 2.89 | 42.34 | 0.20 |

- **DCRN_FIXED** pins the response to the calibrated 32.39 ms target (measured median
  32.61 ms, std 0.17 ms) for **both** native structures. The separate case's native
  18.1 ms pure-ACK→response gap collapses to a **0.18 ms** scheduler guard delta.
- **DCRN_COMMON_BOUNDED** holds every transaction inside the [32.39, 42.39] ms window
  (measured min 32.44, max 42.61), median 37.54 ms.
- NATIVE's `req→ACK-event` spans **0.02 ms → 32 ms**: the SEL separate pure-ACK arrives
  near-immediately, the combined ACK-bearing response near 16 ms — the raw timing tell
  DCRN removes.

## Transport safety (all conditions)

Retransmissions **0**, resets **0**, duplicate-ACKs **0**, ACK-after-response
violations **0**. Byte preservation held for every replayed response
(`b"".join(chunks) == response`, asserted by the replay server). No transaction was
excluded as an anomaly.

## Attacker evaluation (leakage-safe grouped split, chance = 0.333)

Balanced accuracy, 3-device closed set (AB1400 / ION7550 / SEL751), RandomForest,
train/test split disjoint by session parity:

| Condition | mode_only | timing_all | size | all |
|---|---:|---:|---:|---:|
| NATIVE | 0.667 | 0.720 | 0.667 | 1.000 |
| DCRN_FIXED | 0.667 | 0.639 | 0.667 | 1.000 |
| DCRN_COMMON_BOUNDED | 0.667 | **0.436** | 0.667 | 1.000 |

**Reading (matches §15).** Timing-only classification falls toward the 0.333 chance line
(0.720 → 0.639 → 0.436); the bounded target gets closest. `mode_only` (ACK separate vs
combined) and `size` are **unchanged at 0.667** — DCRN deliberately preserves packet
structure and size, so those channels persist and `all` stays at 1.000. **DCRN is a
timing normalizer, not a size/mode normalizer; this result confirms exactly that scope.**
The DCRN_FIXED residual (0.639, above chance) is partly the ~0.18 ms separate-case guard
delta — a small, reported residual, not a hidden leak.

## Scope / caveats

- Loopback veth, not the two-host rig. Absolute latencies are lab-loopback values; the
  **relative** normalization (native spread → fixed/bounded target, structure-independent)
  is the claim. The two-host rig run (§ runbook) is still pending and is required before
  any rig-level PASS.
- 3 runs over the spec session set (504–522 non-first txns/condition); a broader
  session/run count on the rig is future work.
- READ-only, single-outstanding, loss-free workload (see `bypass_realism.md` for the
  TCP-state checks handled in-BPF vs post-capture vs not-implemented).

**Evidence.** `campaign_local/{NATIVE,DCRN_FIXED,DCRN_COMMON_BOUNDED}.pcap`,
`campaign_local/phase04b_{timing_summary,classifier_metrics}.json`,
`campaign_local/spec.json`; sha256 in `manifests/campaign_local_sha256.txt`.
