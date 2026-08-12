# Native-parity size defense — result

## Conclusion (plain)

A READ and a Select-Before-Operate (SBO) transaction to the SEL-751 **can be made equal under an
`O_count+segmentation` observer without any switch byte insertion**, by configuring even-real /
odd-decoy points so both produce the same NATIVE response size, then splitting both identically at
DNP3 CRC-block boundaries. This **sidesteps the multi-boundary transport ledger** that makes
switch-side insertion infeasible on one Tofino-1 — the split is byte-preserving (0 registers, no
seq/ack translation). **A parser-aware observer still distinguishes READ (G10/G30) from SBO (G12
CROB); the claim is size+segmentation parity, not DPI parity.** Software- and compile-proven only; no
hardware, no relay writes, no P4 load this run.

## 1. Selected native READ/SBO construction
- **C04 (primary): 49 B.** SBO = 2 CROBs (1 real + 1 decoy), one shared G12V1 header, qualifier `0x17`.
  READ = 23-point G10V2 binary-output-status.
- **C05 (analog): 61 B.** SBO = 3 CROBs (1 real + 2 decoy). READ = 7-point G30V1 analog.
- 12 Tier-1 intersections total (`candidates.json`); C01/C02 (35 B, 1-CROB / 11-pt) carry zero decoy cover.
- **Grounding (evidence-red-team):** only the **35 B and 49 B SBO echoes** were physically measured on the
  SEL-751. The 61 B SBO and **every READ cover** (incl. the 23-pt G10V2) are opendnp3-serialization-derived
  (software) and assume the relay is configurable with the required points — TBD at the hardware gate.

## 2. Point indices, real vs decoy
Even indices = REAL, odd = DECOY (safety invariant). C04: real CROB at an even output index (e.g. 0),
decoy CROB at the paired odd index (e.g. 1). READ status points are configured measurement objects.
**Mandatory future hardware prerequisite (NOT performed): odd decoy output points must be proven
physically disconnected / unmapped from breaker control, and the real point configured SBO-only.**

## 3. Actual serialized sizes + CRC boundaries
49 B: block boundaries `10 / 28 / 46 / 49`. 61 B: `10 / 28 / 46 / 61`. Because `link_size(u)` is strictly
increasing, equal native size ⇒ equal `u` ⇒ equal CRC-block geometry (single-frame responses).

## 4. Emitted TCP payload-length vectors
Both classes emit the SAME vector: **49 B → `[28, 21]`**; 61 B → `[28, 33]` (or `[46, 15]`).
Byte-preserving: `concat(segments) == original`, seg0.seq = orig, seg1.seq = orig + 28.

## 5. Endpoint semantic results (Gate E — PASS)
Real opendnp3 3.1.2 master+outstation, 1072+ assertions, 0 failures. One shared G12V1 header; OPERATE
repeats SELECT byte-for-byte; real callback once; odd decoys inert; every per-object status parsed; **a
failed decoy fails the whole parity op** (opendnp3 caches the selection only if all objects SUCCESS →
no OPERATE, real command safely lost). Unconfigured/missing/added/reordered/value-mismatch/
control-mismatch and direct-OPERATE-without-SELECT all → NO_SELECT, nothing actuated.

## 6. Observer-by-observer equality matrix (from real bytes)
| Observer | READ vs SBO |
|---|---|
| O_count+segmentation | **EQUAL** |
| O_parse_link | distinct (func/IIN/layout; request 0x01 vs 0x03+0x04) |
| O_parse_app | **distinct** (G12 CROB vs G10/G30) |
| O_profile/config-known | distinct |

## 7. Adversarial transport results (Gate S)
Splitter conformance vs a reference model + TCP reassembler: byte-exact reassembly, correct seq offsets,
ACK/window preserved, PSH/FIN only-last, valid IPv4+TCP checksums, MTU; exact/loss/partial/overlapping
retransmit + seg-loss recovery with seq-dedup; out-of-order; coalesced; 13 fail-open vectors native.
**6/6 mutants killed.**

## 8. P4 compile (Gate C)
`bf-p4c 9.13.1` (SHA e558d01), `defense4_crc_split_kernel.p4`: **0 errors**, 3 inherited warnings,
`tofino.bin`. **Egress = 3 stages, 0 stateful registers** (transport-stateless — the wall is gone; the
insertion kernel needed 11). Frozen ingress byte-identical to the sibling/cover kernel; clean rebuild
deterministic. Re-compiled and re-verified by the PI.

## 9. Mutations killed
Length synth: 87 checks incl. ±1 mutation of every fixed overhead. Splitter: 6/6. Observer: power tests
(different split → differs; 40 B vs 49 B → differs).

## 10. Residual distinguishers (honest)
O_parse_app (G12 vs G10/G30); request direction (1×`0x01` vs `0x03`+`0x04`); the SBO qualifier width
(`0x17` vs default `0x28`); CROB control-code/timing fields; response-direction-only (request sizes differ).

## 11. Assumptions about SEL-751 point configuration
The relay must expose ≥23 readable G10V2 binary-output-status points (C04) or ≥7 G30V1 analog points
(C05), plus configured odd decoy output points, and the master configured `controlQualifierMode =
allow_one_byte` with decoy indices ≤255. **SEL-751 point-map compatibility is TBD** (not tested this run).

## 12. Hardware steps still prohibited / awaiting authorization
Gate P blocked. Awaiting a future authorized hardware gate: (a) prove odd decoy points physically
disconnected; (b) load `defense4_crc_split_kernel.p4` and **wire-capture both mirror replicas** to prove
runtime replication (compile ≠ silicon; a silent replication failure drops the eligible response —
availability risk, so the safe pre-silicon config is transparent/native); (c) configure the relay READ +
decoy CROBs; (d) capture READ and SBO and confirm the emitted length vectors are equal on the wire.

## 13–16. Commits / branch / tree / next
- Commits: `a630c23` (length synth), `ffa11d8` (observer), `2aeba84` (spec), `359fc47` (CRC splitter),
  `be6e590` (endpoint harness), `062a74a` (qualifier finding), + this result doc.
- Branch: `defense4-size-native-parity-crc-split` (pushed; final SHA recorded at push).
- Strongest next experiment: the authorized hardware gate above — the one thing software/compile cannot
  settle is the mirror→multicast runtime replication and the on-wire length-vector equality.
