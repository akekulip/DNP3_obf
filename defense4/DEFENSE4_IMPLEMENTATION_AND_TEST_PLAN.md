# Defense 4 — implementation and test plan

> **REGENERATED 2026-08-04 to the evidence labels of [`DEFENSE4_DIRECTIVE.md`](DEFENSE4_DIRECTIVE.md).
> Three-verdict framing (Unified ingress core: GO / Complete bounded Defense 4: GO WITH CONSTRAINTS /
> End-to-end: NOT YET DEMONSTRATED). MB-1 v3 (defect-free complete core) FITS at 12/12 ingress CP 11 — at
> the ceiling, 0 headroom; stripped-D2 baseline 9 ingress.
> MB-8 (offline size-data-path gate) added before any switch size work; MB-3 (4-level priority) is the
> first switch experiment. Defense 4 stays integrated size-AND-timing; size via outer encapsulation only
> — no decoy CROBs / no DNP3-object edits. Slot pattern is PROVISIONAL until MB-8 passes.**


**2026-08-04. Dependency-ordered milestones with entry/exit criteria, the microbenchmark
specifications, the functional + leakage test matrix, and the safety constraints. High-information,
low-cost, no-hardware experiments come first. Analysis/planning artifact — no hardware step runs
without explicit Philip authorization.**

---

## 1. Dependency graph (what kills or simplifies later work)

```
E1 decisive compile ──► gates ALL P4 work (P3-P8)
E2 SBO size corpus  ──► unblocks size half (P5-P8, tasks T1/T3)
E3 E0-replication + synthetic falsifier ──► validates the grid claim
        │
        ▼
P0 freeze contract ─► P1 corpus ─► P2 offline oracle ─► P3 stripped-D2 baseline
                                                          │
                                                          ▼
                          P4 unified release engine ─► P5 size encoding ─► P6 one-switch topology
                                                          │
                                                          ▼
                          P7 READ/SBO template ─► P8 joint size+timing ─► P9 robustness/concurrency
                                                          │
                                                          ▼
                                              P10 full evaluation
```

E1/E2/E3 were the three offline gate experiments; **E1 (MB-1) and E2 (SBO corpus) are now DONE** — E1
converted the ingress budget from a coin-flip into the measured 10/12-ingress GO, and E2 delivered the
14.6 B/CROB envelope with the pass-gate repaired. E3 (E0-replication + synthetic falsifier) is reproduced
(`analysis/e0.py`). The **next** offline gate is **MB-8** (the size-data-path proof); the first switch
step is **MB-3** (4-level priority), gated.

## 2. Milestones

| # | milestone | entry | exit | artifacts | rollback |
|---|---|---|---|---|---|
| **P0** | Freeze the contract | this study | `DEFENSE4_ARCHITECTURE_SPEC.md` accepted; threat model + envelope + claim boundary fixed | the spec | n/a |
| **P1** | Real SBO corpus (emulator) | P0 | **DONE:** per-N pcaps N=1..16 (all-SUCCESS, wire-verified) + N≥17 rejected corpus (TOO_MANY_OPS, `maxControlsPerRequest=16`); pass-gate repaired; 14.6 B/CROB envelope extracted | `evidence/sbo_corpus/` + `FINDINGS.md` + `corpus_split.json` | none (emulator only) |
| **P2** | Offline transaction oracle | P1 | **DONE + CORRECTED (v2):** transaction closure fixed (60 READ now all 4-unit); emits all six promised fields (txn_id, phase, ack_assoc, fragment, outer_len, expected_slot); full N=1..16; corrected **Candidate A2** (READ→slots 0/1/4/5+filler; slot-1 size unified; format (b); provisional τ) | `defense4/analysis/txn_oracle.py`, `evidence/oracle/annotated_corpus.json`, `PROVISIONAL_SLOT_CANDIDATES.md` | n/a |
| **P3** | Stripped-D2 resource baseline | P0 | **DONE:** offline compile of the stripped core = **9 ingress / CP 7 / 50 tables** (the controlling budget number; the "≈7–8" estimate is RETIRED) | `p4/build_d2core/pipe/logs/table_summary.log` | keep frozen D2 untouched |
| **P4** | Unified D1/D2/D3 release engine | P3, **E1 GO** | one binary reproduces D1, D2, D3 individually via config; the switch-clock grid added | `case_a_defense4.p4` skeleton | revert to D3 |
| **P5** | Bounded egress size states | P4 | encap/decap round-trip byte-identical; exact observer-visible sizes across ≥3 states; overflow fallback | size microbench | disable size plane (timing still works) |
| **P6** | One-switch external-loop topology | P5 | encode/decode passes discriminated; protected link observer-visible; filler stripped before endpoints | port config + capture | revert to inline single-pass |
| **P7** | READ/SBO template + bounded filler | P6, P2 | slot tracking, phase progression, SELECT↔OPERATE linkage, missing-phase + slot-miss handling; READ shaped to SBO count/direction | template config | Profile A (no filler) |
| **P8** | Joint size+timing integration | P7 | classify→map→encode→hold→release→decode for one READ + one SBO; endpoint behaviour preserved | first real Defense 4 | disable one plane |
| **P9** | Robustness + limited concurrency | P8 | retransmission/collision/overflow handling; ≥1 concurrent bank or admission control | — | one-transaction mode |
| **P10** | Full evaluation | P8/P9 | the leakage/ablation matrix (§4) at acceptance criteria; paper-ready package | evaluation report | — |

## 3. Microbenchmark specifications (dependency-ordered)

Each: setup, independent variable, raw output, success criterion, failure interpretation, resource
measurement, cleanup. All offline unless marked. Preserve negative evidence.

1. **MB-1 (E1) — DONE, VERIFIED (skeleton → v2 → v3).** Skeleton 10/12 CP 9 (placeholder); MB-1 v2 10/12
   CP 8 was found to carry ten fatal logic defects (superseded). **MB-1 v3** (`mb1_v3_unified_core.p4`)
   fixes all ten (canonical bidirectional flow key + collision-guard fail-open, pktgen ordering, explicit
   gen validity, both blocker reservoirs, full state retirement, full-mask slot-occupancy + expected-slot,
   8-byte header w/ inner_len, MODE_FAIL_OPEN release, safe parser init) and **compiles at 12/12 ingress,
   CP 11 — FITS but EXACTLY at the ceiling, 0 headroom.** Verdict = **Unified ingress core: GO, QUALIFIED**
   (resource/compile, not silicon; further ingress needs an egress move or 2-pass). Raw evidence:
   `p4/evidence_mb1v3/`; freeze: `p4/MB1_EVIDENCE_FREEZE.md`.
2. **MB-2 — stripped-D2 baseline (P3). DONE, VERIFIED.** Stripped core = **9 ingress / CP 7 / 50 tables**
   — the controlling budget number; the "≈7–8" estimate is RETIRED. Frozen file untouched.
3. **MB-8 — size-data-path offline gate (NEW, directive §9; MUST precede any switch size work).** The
   consolidated OFFLINE proof of the size *mechanism* (MB-1 proved only that the outer-field *assignment*
   is cheap). Exact outer format, real padding bytes, exact observer-visible frame lengths per state,
   encoder/decoder port paths, padding removal, byte-identical inner restoration, hidden real/filler
   discrimination, and MTU/unsupported-size handling — proven offline on the corpus before the switch is
   touched. Consumes the PROVISIONAL slot candidates (`PROVISIONAL_SLOT_CANDIDATES.md`) once one is
   chosen. Success: every corpus transaction encodes to the declared public sizes and decodes
   byte-identically; no real/filler leak. *Offline, no switch.*
4. **MB-3 — 4-level strict priority — THE FIRST SWITCH EXPERIMENT (directive §11, switch, GATED).** Verify
   `Q_ACK_BLOCK > Q_ACK_HOLD > Q_RESP_BLOCK > Q_RESP_HOLD`: `Q_HOLD_ACK` drains at tick k while
   `Q_HOLD_RESP` stays starved until k+N. **Synthetic packets only — no DNP3, no SEL-751, no SELECT/
   OPERATE.** Success: correct causal drain order 100/100 in BOTH injection orders, BF-RT readback, no
   premature release, no blocker escape, bounded fail-open.
4. **MB-4 — encap/decap byte-identity (P5, offline+emulator).** Prepend outer, physical-loop, decap;
   assert inner packet byte-identical. Success: `join(inner)==original` over the corpus.
5. **MB-5 — exact observer-visible size (P5).** Across ≥3 size states, confirm the wire frame length on
   the loop equals the target for each state. Success: measured == declared for all states.
6. **MB-6 — safe filler round-trip (P6/P7).** pktgen filler cell → loop → decoder drop; assert no filler
   egresses to an endpoint. Success: 0 filler frames on dp9/dp64.
7. **MB-7 — the grid device-independence falsifier (E3, offline).** Drive the grid model with programmed
   (a,c) profiles; between-profile classifier AUROC must sit in [0.50, 0.60] on every feature. Failure
   localizes the surviving native quantity (predicted: READ→ACK if ε < spread(a)).

## 4. Functional + leakage test matrix

### 4.1 Functional correctness (P8/P10 exit)

READ measurements identical; SELECT/OPERATE semantics preserved (emulator); decoded bytes
byte-identical; no filler reaches an endpoint; ACK precedes its matching RESPONSE; SELECT-RESP precedes
OPERATE; no generation crossing; fail-open releases without corruption. Plus the **22-row corner-case
table** (`agent_notes/dnp3_sbo_safety.md`) as an explicit checklist — each row's required behaviour + no
unsafe side effect.

### 4.2 Leakage (the ablation ladder, `agent_notes/evaluation_e0.md`)

Rungs: unprotected / size-only / D1-only / D2-only / D3-only(=E0 measured) / unified-timing-only(grid) /
D4-without-filler / full-bounded-D4. Attacker: XGBoost + L2-logistic on all observable features (per-slot
sizes, direction sequence, counts, timing, TCP flags); inter-arrival as a covariate only (harness
confound). Split **by connection, never transaction**. Statistics: bal-acc, ROC-AUC, PR-AUC, MI (Miller-
Madow + shuffle null), block-bootstrap 95% CIs. **Load-bearing prediction:** rung 5→6, READ→ACK AUROC
must fall from 1.000 (0.65-bit residual) to ≤0.60, else the grid's anchor-fix claim is refuted.

### 4.3 Acceptance

- **Strong ("Obs(READ)≈Obs(SBO)"):** every feature's AUROC 95%-CI upper ≤ 0.60, cross-run AND vs the
  synthetic population — only rung 8, shape axes, and only with the external MACsec assumption.
- **Honest ("reduces differences"):** CI-separated AUROC drop, ≥1 feature stays >0.60 — the plaintext
  claim the current evidence supports.
- **Slip-rate:** `P(|obs − grid_slot| > ε) ≤ 1%` (pre-registered), the tail-leakage complement to mean
  AUROC.

## 5. Performance + safety metrics (P10)

Added latency/jitter, deadline-miss rate, residual drain offset, packet loss/reorder, retransmissions/
resets, DNP3 timeout + SBO-selection-failure rate, throughput, queue occupancy, recirculation load,
filler/bandwidth overhead, Tofino compiler + TM resources.

## 6. Safety constraints (hard)

1. **No OPERATE to the physical SEL-751**, ever, for Defense 4 development. SBO app-layer traffic comes
   from the emulator only. Physical relay is READ-ONLY.
2. **No live SELECT to the relay** until its device `selectTimeout` and control-point→output/SELOGIC
   wiring are read (BLOCKED — device profile). A SELECT arms the select state.
3. **No fabricated DNP3** (CONFIRM, g50 time-sync, clear-restart) may reach an endpoint — the primitive
   is strictly byte-preserving on inner DNP3. Fabricated CONFIRM → permanent SOE deletion.
4. **No decoy CROBs and no DNP3-object edits — RETIRED entirely for Defense 4** (directive 2026-08-04).
   Size concealment is outer-encapsulation only; the switch never injects any control, so the
   decoy-inertness (V1) question does not gate Defense 4. Any future variant that reintroduces decoy
   CROBs re-opens under V1.
5. **Filler is outer-encapsulated only**, never an inner DNP3 object (a g110 filler crashes the rig
   master); the decoder must provably strip all filler before an endpoint.
6. **No hardware step** — compile-on-switch, TM config, port readback, or a microbench load — without
   explicit Philip authorization. The switch stays on Defense 3 until then.

## 7. Estimated effort (ranges, with assumptions)

- E1/E2/E3 (offline): each ~0.5–1 day, no hardware. **Do these first.**
- P0–P3: ~1 week (contract + corpus + oracle + baseline compile).
- P4–P6: ~2–4 weeks, dominated by the unified engine and the encap/decap round-trip; assumes E1=GO.
- P7–P8: ~2–3 weeks (template + integration).
- P9–P10: ~2–4 weeks (robustness + full evaluation).
Assumes single-transaction Profile A; the strong-claim / MACsec / concurrency extensions are separate.
