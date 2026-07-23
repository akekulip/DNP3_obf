# DNP3 Size-Pattern Builder — Report (v1.1)

Off-switch, trace-grounded tooling for the locked joint size-and-time path. **v1.1 repairs the
blocking analysis defects of v1** (autunomous.md §6). No switch touched; no `pat_state` programmed;
no P4/Defense change. All numbers below are from `$RESEARCH_PYTHON` runs of the committed scripts and
were independently re-run to verify.

## What v1.1 corrected (vs v1)
1. **Transaction identity now `(device, capture_id, flow, transaction_id)`** + a stable capture index —
   two flows reusing a transaction number no longer merge.
2. **Chronological order preserved** by `(ts, capture_index)`; responses/ACKs are no longer reordered.
3. **Full TCP/IP metadata** recorded (flags, seq, ack_no, IP/TCP header lengths, connection phase);
   a **pure ACK is classified only when payload=0 AND ACK=1 AND SYN=FIN=RST=0**, with ACK *role*
   separated (outstation-ack-of-request / master-ack-of-response / handshake / close / keepalive-or-dup /
   ambiguous).
4. **`ack_mode_observed` is per-transaction** (`separate|combined|ambiguous|incomplete`), not
   hard-coded from the device name. **Load-bearing correction:** SEL-751 is **~50/50 separate/combined
   (300/298 transactions), NOT purely separate**; AB1400/ION7550 are ~99.9% combined. The device label
   is kept only as provenance.
5. **Explicit size metrics** replace v1's ambiguous `wire_size`: `captured_l2_bytes_no_fcs`,
   `ethernet_frame_bytes_no_fcs_min_applied` (canonical), `…_with_fcs`, `wire_occupancy_…preamble_ifg`,
   `ip_total_length`, `tcp_payload_bytes`, `dnp3_payload_bytes`. pcaps are Ethernet, **no captured FCS,
   no preamble/IFG** (documented); 60 B min-frame handling applied.
6. **Retransmission (data-only) + duplicate-capture detection**; distinct pure ACKs (which legitimately
   repeat a sequence number) are kept. RAW + ANALYSIS inventories per scope, documented dedup policy.
7. **Corpus scopes** are explicit and never conflated (§6.7): `base` (3-device), `long` (`*L.pcap`),
   `multicrob` (real SBO/CROB). **Max is reported per corpus and per class — 127 B is the base-corpus
   RESPONSE max, NOT a global/deployment maximum.**
8. **Measured leakage** replaces `log2(#states)`: empirical mutual information (bits, 95% bootstrap CI)
   and grouped-CV balanced accuracy (folds grouped by flow), for device/operation/ack-mode/direction.
   `log2(k)` kept only as a labelled theoretical upper bound.

## Corpus maxima (canonical size = Ethernet frame bytes, no FCS, min-applied)
| corpus | max frame | ACK | READ_REQ | DIRECT_OP_REQ | RESPONSE | distinct sizes |
|---|---|---|---|---|---|---|
| base | 127 B (RESPONSE) | 66 | 88 | 101 | 127 | 15 |
| long | 127 B | — | — | — | 127 | 16 |
| multicrob | 118 B (RESPONSE) | 66 | — | — | 118; SELECT/OPERATE 116; WRITE 87 | 9 |

## Candidates (base scope; filename == `candidate_id`; targets rounded UP to an 8/64-128-256 convention)
| candidate | states (B) | covers max | unfit | fits existing P4 | mean pad | MI_device | MI_operation | op bal-acc (chance) |
|---|---|---|---|---|---|---|---|---|
| **single128_corpus_baseline** | [128] | ✅ | 0 | **✅** (1 state, 1 real queue, 128∈pad set) | 41.5 B | **0.000** | **0.000** | 0.500 (0.500) |
| cover_larger_corpus | [128,256] | ✅ | 0 | ✅ (2 pad headers) | 41.5 B | 0.000 | 0.000 | 0.500 (0.500) |
| two_state_round8 | [88,128] | ✅ | 0 | ❌ (88 ∉ compile-time pad set) | 21.2 B | 0.000 | **0.071** | **0.657** (0.500) |
| ack_data_split | [72,128] | ✅ | 0 | ❌ (72 ∉ pad set) | 21.6 B | 0.005 | 0.000 | 0.500 (0.500) |

**Single-state sanity invariant verified:** `single128` leaks **zero** — MI(device/op/ackmode/direction)=0
(CI [0,0]) and grouped balanced accuracy = chance (device 0.333, op/ackmode 0.500). A single size makes
the size classifier collapse to prior. The **two-state candidates trade padding for measurable operation
leakage** (`two_state_round8` op balanced-accuracy 0.657 > chance): READ requests (~88 B) and
DIRECT_OPERATE requests (~101 B) fall in different states, so the state reveals the operation.

## Per-direction overhead (base, measured cadence 1.00 txn/s; from actual packets — NOT mean-pad × window)
`single128`, cover=OFF (padding only): **master→outstation 102.5 B/txn (0.82 kbps)**, **outstation→master
26.4 B/txn (0.21 kbps)**, ~11 MB/day total. Transaction-window mode (padding + the **explicitly added
128 B outstation-ACK cover slot** on the ~90% combined transactions): outstation→master rises to 141.5
B/txn (1.13 kbps). Continuous is an upper bound only. **Feasible on 64 kbps / 1 Mbps / 100 Mbps / 1 Gbps**,
far under the 211 ms RTO ceiling.

## Ranking sensitivity + Pareto (not one arbitrary weight)
Score = mean_pad + w·MI_device over w ∈ {0,1,5,20,100}: `two_state_round8` ranks first on padding at
every weight (~21.2), `single128`/`cover_larger_corpus` last (~41.5, max padding but zero leak) — the
tradeoff is exposed, not hidden. **Pareto-optimal** over (padding, MI-device, #states, queue count,
max latency, cover overhead) = **{single128_corpus_baseline, two_state_round8, ack_data_split}**;
`cover_larger_corpus` is dominated by `single128` **within the base corpus** (its value is the 256-B
Class-0/larger-corpus headroom).

## Transaction-window schedules (per ack-mode × operation)
Built separately for separate/combined READ, separate/combined DIRECT_OPERATE, and a clearly-labelled
**synthetic** SBO. A combined-ACK READ is 3 slots vs a separate-ACK READ's 4; the ACK-mode-hiding common
schedule **adds the missing outstation-ACK cover slot** to combined transactions so both present an
identical 4-slot sequence. **Filler is explicitly required** for ACK-mode hiding — no claim that none is
needed. Strong transaction/SBO hiding is **not** claimed from synthetic SBO.

## Corrected P4 blocker (v1's error fixed)
A single fixed padding-header width **cannot** normalize variable 54–127 B inputs to one size (v1
implied it could). The implementable Level-1 options are: **(a) exact-match on the finite observed
input-length set selecting a finite set of compile-time pad headers** (the base corpus has 15 sizes);
(b) a synthetic wrapper format whose total output is exactly the target; (c) an off-ASIC gateway/DPU.
The loaded microbench pads to compile-time 128/256 B headers only and classifies by synthetic UDP dport
(not DNP3/TCP) — so realizing any pattern on real traffic needs new dataplane work (Phase 3).

## Tests
`test_pattern_builder.py`: **16/16 pass** (all §6.12 regressions: two-flows-same-txn-id no-merge;
timestamp-preserving post-response ACK order; SYN/FIN/RST exclusion; separate vs combined detection;
data-only retransmission; duplicate handling; 127→128 mapping; larger Class-0 input → needs
split/fail-open/larger state; per-direction overhead; combined-vs-separate canonical filler; corpus-max
handling; filename==candidate_id; dry-run schema validation).

## Scope statement
Off-switch size-pattern builder v1.1 only. It does **not** implement queue scheduling, transaction-window
cover, continuous cover, encrypted encapsulation, a sanitizer, ACK-ordering enforcement, flow-aware P4
state, or any switch load, and makes **no** claim of a completed joint defense, live DNP3/TCP validity,
transaction/direction/ACK-mode/SBO hiding, or deployment readiness. It produces trace-grounded candidate
patterns + measured leakage/overhead for the Level-1 hardware experiment.
