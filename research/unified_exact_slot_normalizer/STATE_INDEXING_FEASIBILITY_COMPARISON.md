# State-indexing feasibility comparison (Part 1)

Four strategies for indexing per-transaction state in the unified Tofino-1 timing normalizer, evaluated
before implementation. Grounded in the frozen `dcrn_defense1.p4` resource profile (12/12 ingress; registers
`reg_armed`8b / `reg_expected_ack`32b / `flow_has_held_ack`8b / `reg_resp_seen`8b / `reg_ack_gone`8b, each
**65536 entries**, indexed by a **16-bit CRC16 flow_hash**, with **NO stored fingerprint**) and the Phase-2
finding (generation *carried* fits 12/12, generation *enforced* did NOT — table-placement exhaustion).

## The strategies

- **A. Exact admitted-flow table → direct slot_id.** A static SRAM exact-match table `flow_admission` maps
  each configured canonical flow key to a compact `slot_id`; state registers are indexed by `slot_id`.
- **B. Single over-provisioned hashed register array.** Hash the flow key → index; MUST store + verify a
  flow fingerprint (else false release on collision); collision → fail-open.
- **C. Two-bank / two-choice / d-left hashing.** 2 hashes, 2 bank reads, occupancy check, dependent
  fallback selection, allocation/cleanup.
- **D. Bloom pre-check → exact state lookup.** Bloom membership test, then an exact lookup for the slot.

## Metric comparison

| Metric | A. Exact table | B. Single hash array | C. d-left / 2-choice | D. Bloom + exact |
|---|---|---|---|---|
| **Exactness** | **perfect** (table is authoritative) | approx (needs fingerprint verify) | approx (needs fingerprint per bank) | approx (Bloom has FPs; still needs exact) |
| **Collision probability** | **0** (distinct keys → distinct entries) | birthday: ~N²/2·2^m; must verify fingerprint | lower than single-bank but nonzero | Bloom FP rate on top of the exact lookup |
| **False-positive behavior** | none | a colliding fingerprint mismatch → BYPASS | same, per bank | Bloom FP → wasted exact lookup; **must not** admit on membership alone |
| **SRAM** | exact-match: N×(80b key+action) — **tiny** (N≤~1000 → ~1 block); state regs: 2^ceil(log2 N) entries (e.g. 1024) — **64× smaller than 65536** | large: array_size×(fingerprint+state); 65536 = big | ~2× array + fingerprints | Bloom bits + exact array (largest) |
| **Exact-match table resources** | 1 SRAM exact-match table (no TCAM; 80b key fits) | 0 | 0 | 0 (+ Bloom SRAM) |
| **Stateful ALUs** | state RegisterActions only (no fingerprint compare) | +1 SALU for fingerprint read+compare | +2 (per-bank fingerprint compares) | +Bloom SALU/bit ops + exact |
| **Hashes** | **0** (exact match, no CRC) | 1 | **2+** | 1+ (Bloom) then exact |
| **Dependent register ops** | slot_id from table → direct index (1 dependency) | hash → array read → fingerprint compare → act (chain) | 2 dependent bank reads + fallback (longer chain) | Bloom → exact → act (longest) |
| **PHV fields** | slot_id (small) + canon key temporaries | hash idx + fingerprint + state | 2 idx + 2 fingerprints | Bloom idx + exact idx + fingerprint |
| **Ingress stages** | admission table (1) + state (≈ frozen); **removes the hash + fingerprint-compare stages** | hash + fingerprint-compare + state (≥ frozen +1) | +1–2 for the second bank + fallback | +2 (Bloom then exact) — **most** |
| **Recirc-pass cost** | index by carried `slot_id` (no re-hash) | re-hash OR carry idx+re-verify fingerprint | re-hash both banks OR carry bank+idx | re-check membership OR carry idx |
| **Allocation complexity** | **control-plane init only** (populate table once); no fast-path alloc | fast-path insert-on-miss + occupancy | fast-path 2-bank insert + eviction | insert into Bloom + exact |
| **Stale-generation behavior** | generation in packed state + carried in recirc; slot is stable (no reuse ambiguity from collision) | generation + fingerprint both needed | generation + fingerprint per bank | generation + fingerprint |
| **Fail-open behavior** | table **miss → default action = BYPASS** (clean, per-packet) | collision/fingerprint-mismatch → BYPASS | bank-full/mismatch → BYPASS | Bloom-miss → BYPASS; FP → exact-miss → BYPASS |
| **1 / 10 / 100 / 1000 flows** | all trivial (exact-match SRAM holds thousands of 80b keys; slot space sized to need) | array must be ≫ flows to keep collisions rare (over-provision) | same, ×2 | same + Bloom sizing |
| **One-outstanding-per-flow** | native (1 flow → 1 slot → 1 state entry) | native | native | native |
| **12-stage ingress fit** | **best** (no hash, no fingerprint-verify stage → likely frees a stage vs frozen — may let generation ENFORCEMENT fit where the hash design did not) | ~frozen +1 (fingerprint) — tight | frozen +1–2 — likely does NOT fit | worst — likely does NOT fit |

## Why not the hash designs (per the task's explicit cautions)

- **A large register array does NOT eliminate collisions** — 65536 entries with a 16-bit hash still collide
  by the birthday bound, and the frozen defense stores **no fingerprint**, so a collision would let one
  flow's response act on another flow's state. A *safe* hash design must add a stored fingerprint + an
  exact compare (extra SALU + stage) — which erodes the only advantage over the exact table while remaining
  approximate.
- **d-left is not cheap** — it costs 2 hash calculations, 2 register-bank reads, an occupancy check, a
  dependent fallback selection, and allocation/cleanup logic, and the recirculated packet must
  deterministically relocate its bank. On a 12-stage budget that is a large, dependency-heavy addition.
- **Bloom is unsuitable here** — it has false positives, it does **not return the state slot**, exact
  verification is still required afterward, and it adds hash+memory ops. It only helps when the exact
  lookup is expensive — but the exact admission table already resolves in one stage, so Bloom adds cost with
  no benefit. Critically, **an unrelated response must never be admitted on probabilistic membership**; Bloom
  cannot provide that guarantee alone.

## Decision

**Select A — the exact admitted-flow table → direct slot_id.** It is the only *collision-free* design; it
uses the least SRAM (tiny table + small slot-indexed registers vs a 65536-entry array), the fewest hashes
(zero) and the shortest dependency chain (table → direct index), it fails open cleanly on a table miss, and
for a **static OT deployment exact admission is a security feature** — only configured device sessions can
allocate timing state, so an unknown/hostile flow cannot exhaust state or trigger a false release. It is
also the most likely to fit the 12-stage budget *with* generation enforcement, precisely because it removes
the hash and the fingerprint-verify that a safe hash design would need — a hypothesis tested directly in the
Part-6 prototypes. No other strategy demonstrates a clear, measured advantage without violating the stage
or correctness constraints, so none is selected. (A single-bank hashed **fallback** is kept in reserve for a
deployment that genuinely cannot enumerate its flows — Part 7, gated.)
