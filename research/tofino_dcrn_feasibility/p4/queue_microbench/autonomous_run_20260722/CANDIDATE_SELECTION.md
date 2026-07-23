# CANDIDATE_SELECTION.md — Phase 2 (autonomous run 2026-07-23)

**Selected Level-1 hardware baseline: `single128_corpus_baseline` — one size state = 128 B, base
3-device corpus.** Decided from the Gate-A-verified evaluation on the decontaminated corpus.

## Alternatives considered (base scope, verified numbers)
| candidate | states (B) | fits P4 | mean pad | measured size-channel leak | verdict |
|---|---|---|---|---|---|
| **single128_corpus_baseline** | [128] | **✅ (1 real queue, 128∈pad set)** | 45.9 B | **0** (MI=0, invariant True) | **SELECTED** |
| cover_larger_corpus | [128,256] | ✅ (2 pad headers) | 45.9 B | 0 (256 unused in base) | dominated by single128 in base; 256 = future Class-0 headroom |
| two_state_round8 | [80,128] | ❌ (80 ∉ pad set → recompile) | ~21 B | operation signal (perm p=0.001; flow-robust only ≥5 groups) | rejected: needs recompile + leaks operation |
| ack_data_split | [72,128] | ❌ (72 ∉ pad set) | ~22 B | device/ack (record-level only, not flow-robust) | rejected: needs recompile |

## Why single128 wins
It is the **only** candidate that simultaneously: fits the existing P4 (1 real queue; 128 is already a
compile-time pad target), has **zero measured size-channel leakage** (a constant-feature property, not a
finite-sample fluke), covers the true base-corpus maximum (120 B → 128), and has **0 unfit packets**.
The lower-padding two-state candidates both need a recompile (their small state is not a compile-time
pad width) **and** re-introduce a size→operation signal. Padding is higher for single128, but the
overhead is tiny (below) and the design goal here is to demonstrate size-signal removal, for which the
single state is the cleanest, strongest instrument.

## The selected pattern (exact, implementable)
- **Corpus scope:** base 3-device fingerprint corpus (SEL-751 100% separate; AB1400/ION7550 combined).
- **One target-size convention:** every frame → **128 B** Ethernet (no-FCS, min-applied).
- **Finite observed input-length set (13):** {60, 62, 66, 74, 76, 88, 89, 91, 101, 103, 108, 115, 120} B.
- **Pad deltas to 128 (13):** {8, 13, 20, 25, 27, 37, 39, 40, 52, 54, 62, 66, 68} B → realizable by a
  finite pad-header set (power-of-2 headers {1,2,4,8,16,32,64} selected by the delta's bits, or 13
  exact pad headers). **max pad 68 B; mean 45.9 B/packet.** 0 unfit; no splitting.
- **Queues:** 1 real high-priority queue; cover queue optional for compatibility; external cover OFF.

## What it hides / does not hide (measured, scoped)
- **HIDES:** the packet-SIZE channel on the base corpus — after mapping, output size is constant, so
  MI(size; device/operation/ack-mode/direction)=0 and any size classifier collapses to prior. Verified
  offline (`single_state_invariant_holds=True`).
- **DOES NOT HIDE:** direction (trivially readable), packet count / transaction structure, timing/CLRT,
  ACK mode, or SBO structure. Those are out of the size component's scope and require the timing defenses
  (Defense 1/2) and/or the future two-edge cover architecture. **No READ-vs-SBO indistinguishability is
  claimed.**

## Padding overhead (measured, per direction, cover=OFF, 1 txn/s)
- master→outstation: **109.6 B/txn → 0.88 kbps → ~9.5 MB/day**.
- outstation→master: **37.4 B/txn → 0.30 kbps → ~3.2 MB/day**.
- Feasible on 64 kbps / 1 Mbps / 100 Mbps / 1 Gbps; far under the 211 ms RTO ceiling.

## Corpus limitations
Base = 3 flows = 1 per device; device/ACK-mode leakage is not flow-cross-validatable (Gate A). The
zero-size-leak claim is scoped to this corpus and is a constant-feature property; generalization needs
more independent flows per device. 127 B (contamination) is not a maximum; 120 B is the true max.

## P4 requirements (Phase 3)
A NEW `queue_microbench_trace_v1.p4` (the loaded microbench is NOT modified): a trace-replay classifier
(declared input-size class), a finite pad-header set mapping each of the 13 input sizes → 128 B,
placement into 1 real queue, cover OFF, no metronome, measurement-only digest. Level-1 only — no valid
live TCP/DNP3 required. Expected resources: comparable to the current microbench (≤12 ingress stages);
confirm by local `bf-p4c 9.13.1`.

## Experiment hypothesis
Padding every base-corpus frame to a single 128 B state on Tofino-1 silicon removes the packet-size
signal (output-size histogram → a single value; MI(size; device/op/ack-mode) → 0; grouped classifier
balanced accuracy → chance) with **zero loss, zero reordering, zero queue growth, zero external cover**,
at the measured bounded per-direction overhead — validating the SIZE component of the joint
size-and-time architecture, explicitly separate from the event/deadline timing defenses.
