# DNP3 Size-Pattern Builder — Report (v1.1)

Off-switch, trace-grounded tooling for the locked joint size-and-time path. **v1.1 repairs v1's
blocking analysis defects (autunomous.md §6) AND the Gate-A audit findings.** No switch touched; no
`pat_state` programmed; no P4/Defense change. Numbers are from `$RESEARCH_PYTHON` runs, independently
re-verified, on a **decontaminated** corpus.

## ⚠ Gate-A correction — corpus decontamination + a RETRACTION (read first)
The independent DNP3/ICS audit found that v1's/earlier-v1.1's extractor filtered flows only by TCP
port 20000 and stamped every port-20000 flow with the pcap's device name. **Each base pcap also
contains a second, shared outstation `10.0.0.2` (a combined-ACK device), 904 packets in SEL751.pcap.**
It was silently mislabeled SEL751/AB1400/ION7550.

**RETRACTED:** the earlier v1.1 claim "SEL-751 is ~50/50 separate/combined." That was an artifact of
`10.0.0.2` contamination. On the corrected corpus (each scope filtered to its **declared outstation
IP**), the real **SEL-751 (10.0.0.1) = 299/299 = 100% separate-ACK**, consistent with the locked ground
truth (`ACK_DELAY_POLICY.md` §5.A: native CLRT median 12.9 ms; `CASE_A_TERMINOLOGY.md`: Case A =
separate-ACK = SEL-751). AB1400/ION7550 are combined. The extractor now filters by outstation IP
(and a master application CONFIRM no longer opens a spurious transaction). Every per-device number
below is regenerated on the clean corpus.

## What v1.1 corrected (vs v1)
1. **Transaction identity `(device, capture_id, flow, transaction_id)`** + capture index — flows reusing
   a transaction number no longer merge.
2. **Chronological order** by `(ts, capture_index)`; no reordering.
3. **Full TCP/IP metadata**; a pure ACK only when payload=0 AND ACK=1 AND SYN=FIN=RST=0, with ACK role
   separated.
4. **`ack_mode_observed` per transaction** (`separate|combined|ambiguous|incomplete`), device label as
   provenance only. **SEL-751 = 100% separate; AB1400/ION7550 = combined** (corrected — see above).
5. **Explicit size metrics** (canonical `ethernet_frame_bytes_no_fcs_min_applied`); pcaps are Ethernet,
   no captured FCS, no preamble/IFG, 60 B min-frame applied.
6. **Retransmission (data-only) + duplicate detection**; distinct pure ACKs kept. RAW + ANALYSIS
   inventories, documented dedup.
7. **Corpus scopes** explicit and never conflated: `base` (3-device, filtered per outstation IP),
   `long`, `multicrob` (real SBO/CROB). **Max reported per corpus AND per class.**
8. **Measured leakage** (empirical MI in bits with a permutation null + flow-grouped bootstrap, and
   grouped-CV balanced accuracy with folds grouped by flow) replaces `log2(#states)` (kept only as a
   labelled upper bound).

## Corpus maxima (clean; canonical = Ethernet frame bytes, no FCS, min-applied)
| corpus | named-device max | SEL-751 | AB1400 | ION7550 | distinct sizes |
|---|---|---|---|---|---|
| base | **120 B** (SEL-751 RESPONSE) | 120 | 108 | 115 | 13 (60–120 B) |
| long | 120 B | 120 | — | — | — |
| multicrob | 118 B (RESPONSE); SELECT/OPERATE 116; WRITE 87 | — | — | — | 9 |

**127 B is NOT a corpus/device maximum** — it originated entirely from the removed `10.0.0.2`. The real
named-device base max is **120 B**. `single128` still covers it (120→128).

## Candidates (base; filename == `candidate_id`; targets rounded to an 8 / 64-128-256 convention)
| candidate | states (B) | covers max | unfit | fits existing P4 | note |
|---|---|---|---|---|---|
| **single128_corpus_baseline** | [128] | ✅ | 0 | **✅** (1 state, 1 real queue, 128∈pad set) | zero measured SIZE-channel leak; labelled corpus baseline, not deployment pattern |
| cover_larger_corpus | [128,256] | ✅ | 0 | ✅ (2 pad headers) | dominated by single128 in base; 256 B = Class-0/larger-corpus headroom |
| two_state_round8 | [80,128] | ✅ | 0 | ❌ (80 ∉ pad set) | lowest padding but **leaks operation** (READ ~ small state, DIRECT_OPERATE ~ larger) |
| ack_data_split | [72,128] | ✅ | 0 | ❌ (72 ∉ pad set) | ACK/data split |

**Single-state sanity invariant holds** (single128 → MI(device/op/ackmode/direction)=0, grouped
balanced accuracy = chance). Precise MI values, permutation-null p-values, flow-grouped CIs, and
grouped-BA (leave-one-group-out) CIs are in `evaluation.json` (base). The decision-relevant findings, honestly scoped to the decontaminated corpus (base/long = **3 flows =
1 per device / 1 ack-mode per flow**):
- **`single128` = zero measured size-channel leakage** — a constant-feature property (MI=0, perm p=1.0,
  invariant verified), label-invariant, holds on all three scopes.
- **The two-state candidates trade padding for a size→OPERATION signal** (READ vs DIRECT_OPERATE):
  record-level significant (permutation p = 0.001 base/long, 0.018 multicrob), but **flow-robust only
  where ≥5 flow-groups exist (multicrob: flow-grouped MI CI [0.068,0.114], LOGO bal-acc CI
  [0.620,0.713] both exclude the null)**; on the 3-flow base/long corpora the flow-grouped CI spans the
  null, so it is a directional/record-level signal, not a flow-generalizable one there.
- **Device and ACK-mode leakage are NOT cross-validatable** on the decontaminated base/long (each device
  is now a single flow) — reported "insufficient". Any device/ACK-mode number must be read from the
  flow-grouped MI CI, not the record-level permutation p; generalization needs more independent flows
  per device.

## Per-direction overhead (base, measured cadence 1.00 txn/s; from actual packets — NOT mean-pad × window)
`single128`, cover=OFF (padding only): **master→outstation ~102 B/txn (~0.8 kbps)**, **outstation→master
~26 B/txn (~0.2 kbps)** (final decontaminated numbers in `evaluation.json`); ~11 MB/day total. Feasible
on 64 kbps / 1 Mbps / 100 Mbps / 1 Gbps, far under the 211 ms RTO ceiling. Transaction-window mode adds
an explicit outstation-ACK cover slot to combined transactions (AB1400/ION7550); **SEL-751 is 100%
separate, so it needs no ACK-mode filler** — the ACK-mode-hiding motivation applies to the combined
devices, not to the current SEL-751 scope.

## Ranking sensitivity + Pareto (not one arbitrary weight)
Score = mean_pad + w·(aggregate leakage) over w ∈ {0,1,5,20,100}; leakage axis = **max MI over
{device, operation, ack_mode}** (broadened from device-only per the stats audit) so single128's
zero-leak advantage is visible in the numbers, not only the prose. Pareto frontier over (padding,
leakage, #states, queue count, max latency, cover overhead) — see `evaluation.json`.

## Corrected P4 blocker
A single fixed padding-header width **cannot** normalize variable 60–120 B inputs to one size. The
implementable Level-1 options: **(a) exact-match on the finite observed input-length set selecting a
finite set of compile-time pad headers**; (b) a synthetic wrapper format whose total = the target;
(c) an off-ASIC gateway/DPU. The loaded microbench pads to compile-time 128/256 B and classifies by
synthetic UDP dport (not DNP3/TCP) — realizing a pattern on real traffic needs new dataplane work
(Phase 3).

## Known extractor limitations (documented, non-fatal on this corpus)
- **TCP-coalesced segments** carrying two DNP3 frames: only the first frame's FC is parsed (~0.25% of
  payload packets; the 2nd collapses into the record). No reassembly. Would grow on higher-rate SEL-751.
- **Frame split across TCP segments**: the continuation has no `0x0564` → labelled `unknown` (correct,
  not misparsed), no reassembly.
- **Multi-fragment responses (FIR/FIN)**: all base responses are single-fragment (FIR=FIN=1), so
  multi-fragment reconstruction is **untested** — do not claim it. CONFIRM-opens-transaction is now
  closed. Reassembly + multi-fragment handling are required before higher-rate/physical-SEL-751 use.

## Tests
`test_pattern_builder.py`: **16/16 pass** on the clean corpus (all §6.12 regressions).

## Finite-sample caveat (required)
All leakage statistics rest on a small number of flows / 3 devices at 1 Hz; the packet count does not
confer that many independent samples. Device- and flow-level results are **corpus-descriptive, not
generalizable**; the only leak robust to resampling the flows is the two-state **operation** leak.
`single128`'s zero size-channel leak is a constant-feature property (label-invariant).

## Scope statement
Off-switch size-pattern builder v1.1 only. No queue scheduling, cover, encapsulation, sanitizer,
ACK-ordering enforcement, flow-aware P4 state, or switch load; **no** claim of a completed joint
defense, live DNP3/TCP validity, or device/operation/ACK-mode/direction/SBO/deployment hiding. It
produces trace-grounded candidate patterns + measured size-channel leakage/overhead for the Level-1
hardware experiment. `single128_corpus_baseline` is the defensible Level-1 baseline for the base corpus.
