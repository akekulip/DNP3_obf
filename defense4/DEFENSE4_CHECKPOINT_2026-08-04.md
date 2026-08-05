# Defense 4 — architecture correction checkpoint (2026-08-04)

**Governing checkpoint. This supersedes the outer-encapsulation / two-edge / filler-cell / decoder /
MB-8 direction. Documentation + specification only — no P4 implementation, no MB-8, no switch, no
physical relay this checkpoint (per the 2026-08-04 directive). The superseded work is PRESERVED as
historical feasibility evidence, not deleted.**

Return artifacts for review are all in this file: the new architecture (§1), the superseded list (§2),
the source-grounded D1/D2/D3 semantics matrix (§3), the proposed unified release truth table (§4), the
size-plane specification (§5), the fixed-K emulator experiment matrix (§6), the safety boundary (§7),
the corrected claims (§8), and the remaining unresolved decisions (§9).

---

## 1. The controlling Defense 4 architecture (new)

```
DNP3 master  →  observed WAN  →  [ one Tofino-1 switch at the outstation ]  →  relay / outstation
```

A **single Tofino-1 at the outstation edge**. No second switch, no outer wrapper, no loopback tunnel, no
decoder pass. Defense 4 combines two planes on that one switch + the authorized master:

1. **Unified Tofino timing engine** — one transaction-aware engine containing the proven mechanisms of
   Defenses 1, 2, and 3, with the individual defenses selectable as separate modes (for ablation) and a
   combined Defense 4 policy (§4). **Timing goal: CLRT normalization and device-fingerprint mitigation.**
2. **Fixed-count real-plus-decoy CROBs** — the authorized master pads every control transaction to a
   fixed public object count **K = R + D** (R real CROBs + D inert decoy CROBs), so SELECT/OPERATE
   request size and the echoed response size are constant for a given K regardless of R. **Size goal:
   reduce leakage from CROB count and transaction size.** The Tofino does not fabricate, insert, or
   modify CROBs (§5).

**Explicit non-goal:** Defense 4 does **not** attempt to make READ and SBO semantically indistinguishable.
The READ-vs-SBO six-slot-equivalence framing is retired (§2).

---

## 2. Superseded artifacts — PRESERVED, not deleted

The following are marked **SUPERSEDED** as of this checkpoint. Their files and commits remain in the
tree/history as historical feasibility evidence (they establish what was tried and what was learned).

| superseded artifact | where it lives (kept) | why retired |
|---|---|---|
| **Candidate A / A2 / A3** slot patterns | `PROVISIONAL_SLOT_CANDIDATES.md` | replaced by the K=R+D size plane; no public slot grid |
| **Outer Ethernet encapsulation** (format (b), 8-byte D4 header, inner_len) | `PROVISIONAL_SLOT_CANDIDATES.md` §2, `DEFENSE4_ARCHITECTURE_SPEC.md` §5, MB-1 v3 header | size is normalized at the DNP3 object layer (decoys), not by a wire wrapper |
| **Second decoder / decode pass** | arch spec §2 topology, MB-1 v* decode-pass logic | one-switch-at-outstation has no loopback/decoder |
| **Filler slots / filler-cell grid** | Candidate A3 §3, arch spec §5 | no slot grid; padding is real+decoy CROBs from the master |
| **READ-vs-SBO six-slot equivalence** | Candidate A3 | explicit non-goal now |
| **Two-edge / external-loop tunnel topology** | arch spec §2, `DEFENSE4_DIRECTIVE.md` | single switch at the outstation |
| **MB-8 size-data-path gate** | impl plan MB-8, feasibility report | no wire wrapper to prove; size verified at the emulator (§6) |

**Retained and still load-bearing:** the D1/D2/D3 timing mechanisms (§3), the unified timing engine
concept (§4), the SBO/CROB emulator corpus and the persistent-connection finding, the E0 timing
analysis, and the Defense-3 silicon result. The MB-1 v1/v2/v3 compiles are retained as **timing-core
feasibility evidence** (they show a transaction-aware timing engine fits a Tofino-1 pipeline); the
outer-header/decode portions of those programs are superseded, but the compiles are not deleted.

---

## 3. D1 / D2 / D3 source-grounded semantics matrix

> **Provenance correction (verified this session).** The three git tags do **NOT** contain the canonical
> source files — each tag predates its file. `ack-delay-caseA-c3-pass` (2026-07-20) predates
> `case_a_defense3.p4` (2026-07-30); the `d1-/d2-telem-v1-verified` tags (both 2026-07-22) hold the
> earlier `*_telem.p4` variants, not the hardened builds. **Cite the file's last-touch commit SHA, not the
> tag.** (Repo has only 5 tags total; the other two are `timing-final-meeting-v1`, `queue-trace-level1-hw-pass`.)

| dimension | **D1 — event-governed ACK release** | **D2 — immediate ACK + ACK-relative RESPONSE deadline** | **D3 — predetermined delayed ACK deadline** |
|---|---|---|---|
| **Held packet(s)** | pure TCP **ACK only** (the RESPONSE is also looped, but only to enforce ordering) | **RESPONSE only** — the ACK is forwarded immediately (`to_fwd`, "ACK is NEVER held") | the **ACK and every in-transaction RESPONSE**, both into one `Q_HOLD` |
| **Timing reference** | a **response event** (`reg_resp_seen`), **no wall-clock**; the bridge tick exists but "Case A does NOT read it" | **t_ack + G** (`reg_deadline`; `now = t_ack`, `dl = now + G`; G default ≈ 25 ms, 256-ns ticks) | **t_ACK + D** (`reg_deadline`; D default ≈ 2 ms, runtime-writable, control-plane clamps ≤ 40 ms) |
| **Release predicate** | **ACK:** `respseen_getclr == 1` (RESPONSE has entered). **RESP:** `ackgone==1` after `GUARD_PASSES=4` | **RESPONSE:** the K-token reservoir drains when each token is `expired` (`now ≥ t_ack+G`, sign-bit test); emptied `Q_BLOCK` stops starving `Q_RESP` | **ACK then RESP:** reservoir drains at `now ≥ t_ACK+D`; then `Q_HOLD` is served. The held ACK itself has **no `expired` test by design** (would race the release tail) |
| **ACK-before-RESP ordering** | **zero-inversion invariant** (register-write visible only to strictly-later passes) + one shared FIFO (qid 0); **no strict priority** | **structural** — the ACK is never queued; **2-level** strict priority `Q_BLOCK qid7 > Q_RESP qid1` | **4-part invariant** (same ingress port, same `Q_HOLD` qid, exactly 1 loop pass each, same egress qid) + FIFO; **2-level** SP `Q_BLOCK qid7 > Q_HOLD qid1`; **ordering held 480/480** |
| **Expiry + fail-open** | pass caps `ACK_MAX=2^16`, `RESP_MAX=2^17`; **never drops**; even fail-open sets `ack_gone` so the RESPONSE is never stuck | per-token budget `100000` + deadline; termination priority **stale > deadline > budget**; RESPONSE releases on drain (`ctr_release_deadline` vs `ctr_release_fail_open`) | per-token budget `B=18000`, horizon `H=B·K/rate`; **stale > deadline > budget**; **R2 repair** = non-destructive fail-open (records gen in `reg_failopen`, leaves `reg_tag` intact) |
| **Txn matching + cleanup** | `flow_id` = **canonical bidirectional CRC16** over `{cli_ip,srv_ip,cli_port}`; `armed` + `expected_ack` + pure-ACK flags; one-shot test-and-set; `getclr` self-cleans; FIN/RST aborts clear `armed` | `reg_tag` packs generation+active (DNP3 `app_control` `0xCn`); `deadline_arm_once` (first-ACK idempotent); ARM disarms; `budget_zero → TAG_INACTIVE` retires | `reg_tag` generation; **CONSENSUS conjuncts** `exp_relay_seq` ∧ `exp_ack` ∧ `session_port` (rejects keepalives); `tag_retire_if_unmarked`; `reg_ack_rel` generation-bound, self-clearing |
| **Source + commit + evidence** | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1_hardened_dp9_dp11.p4` **@ `814c42b`** (2026-07-24). Evidence: `.../evidence/c3_matrix/*.tel.json`, `native_clrt_baseline.txt`. Ordering proof: `research/ibspg_paired/…/ibspg_paired.p4` (Part 11), **100/100 both orders**, 3 SP levels | `research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4` **@ `d95f731`** (2026-07-28) — **COMPILE-FIT ONLY, never run**. Silicon proof: `research/ibspg_hold_response/…/ibspg_hold_response.p4` (Part 12), ACK→RESP hits G within **~1.7 µs**, 23 ns spread | `defense3/p4/case_a_defense3.p4` **@ `0e52f9d`** (2026-07-30) — **LOADED + validated on Tofino-1 vs the physical SEL-751**. Evidence: `defense3/evidence/physical_repaired/RESULTS_R1R2R3.md`, `.../ksweep/RESULTS.md`. **CLRT σ 2.854 ms → 0.012 ms at D=16 ms (~238×)** |

**Merge-critical facts (from the sources):**
- **D2 and D3 are already two modes of the same deadline-reservoir substrate** — identical `reg_tag` /
  `reg_deadline` / `tbl_deadline_expiry` / K=64 `Q_BLOCK` / 256-ns armed-word encoding. They differ only in
  (i) **what enters the low-priority hold queue** (D2: RESPONSE only, ACK forwarded now; D3: ACK + RESPONSE)
  and (ii) **the deadline anchor** (`t_ack+G` vs `t_ACK+D`). Each arms **exactly one** deadline per
  transaction — a merged engine **selects the anchor, it does not add G+D**.
- **D1 is the outlier** — event-governed, no reservoir, no deadline; it holds the ACK on a recirc loop
  until the RESPONSE event and orders via register-visibility on a shared FIFO. Folding it in needs an
  explicit **event-release mode**; **IBSPG Part 11 is the bridge** (it demonstrates D1-style
  ACK-before-RESPONSE on the same strict-priority reservoir via a third queue level `Q_ACK qid5`).
- **Loopback-port mismatch to reconcile:** D1's hold loop is `dp68`; D2/D3 run the reservoir on `dp8` and
  use `dp68` for the pktgen source. A unified engine must pick one port/queue map.

---

## 4. Proposed unified release truth table (for review, NOT implemented)

One engine, one deadline-reservoir substrate (`reg_tag` + `reg_deadline` + `tbl_deadline_expiry` + K
`Q_BLOCK` reservoir, from D2/D3) plus an **event-release mode** (from D1, via the Part-11 strict-priority
bridge). A per-transaction **MODE** (from `tbl_params`) selects (a) which packets are held, (b) the
release trigger, and (c) the deadline anchor. **Delays are never summed** — each packet carries at most
one deadline; D4 uses two *independent* anchors on two *different* packets, not two on one.

### 4a. Mode → routing + release trigger

| MODE | ACK routing | ACK release trigger | RESPONSE routing | RESPONSE release trigger |
|---|---|---|---|---|
| **D1 · EVENT** | hold (Q_ACK, strict-priority level, per Part 11) | **event:** matching RESPONSE seen (`resp_seen==1`) | hold (Q_RESP) | `ack_gone==1` after `GUARD_PASSES` |
| **D2 · RESP_DL** | **forward now** | — (never held) | hold (Q_RESP) | **deadline:** `now ≥ t_ack + G` |
| **D3 · ACK_DL** | hold (Q_HOLD) | **deadline:** `now ≥ t_ACK + D` | hold (Q_HOLD, same FIFO) | **after ACK** (FIFO, 1 pass) |
| **D4 · COMBINED** | hold (Q_ACK) | **deadline:** `now ≥ t_nativeACK + D` | hold (Q_RESP) | **deadline:** `now ≥ ack_release + G` |

### 4b. Explicit release truth table (per held packet; all decisions in the data plane)

| MODE | packet | HOLD while … | RELEASE when … |
|---|---|---|---|
| D1 EVENT | ACK | `resp_seen == 0` | `resp_seen == 1` |
| D1 EVENT | RESP | `ack_gone == 0` OR `guard_passes < G_P` | `ack_gone == 1` AND `guard_passes ≥ G_P` |
| D2 RESP_DL | ACK | — | *forwarded immediately (never queued)* |
| D2 RESP_DL | RESP | `now < t_ack + G` (reservoir non-empty) | `now ≥ t_ack + G` (reservoir drained) |
| D3 ACK_DL | ACK | `now < t_ACK + D` (reservoir non-empty) | `now ≥ t_ACK + D` (reservoir drained) |
| D3 ACK_DL | RESP | ACK not yet released | ACK released (same `Q_HOLD` FIFO, equal pass count) |
| D4 COMBINED | ACK | `now < t_nativeACK + D` | `now ≥ t_nativeACK + D` |
| D4 COMBINED | RESP | ACK not released OR `now < ack_release + G` | ACK released AND `now ≥ ack_release + G` |
| **ANY** | any held pkt | budget/pass-count not exhausted | **`budget_zero` → RELEASE (bounded fail-open backstop, universal)** |

**Global invariant (all modes):** the ACK egresses **before** the RESPONSE — by strict priority (D2/D4,
`Q_BLOCK/Q_ACK > Q_RESP`), by shared FIFO + equal pass count (D3), or by register-write visibility
(D1). Verified 480/480 (D3) and 100/100 both injection orders (Part 11).

### 4c. The combined Defense 4 policy (proposed — the item for review)

D4 composes **D3's predetermined ACK deadline D** (hide the native ACK arrival → device-fingerprint
mitigation) with **D2's ACK-relative RESPONSE deadline G** (normalize the ACK→RESPONSE interval = CLRT to
a chosen constant → CLRT mitigation). The observer sees the ACK at `native_ACK + D` and the RESPONSE at
`ACK_release + G` — both public policy constants, neither the device's native timing. **This reproduces
each frozen defense at a degenerate setting, which is why the separate modes stay available for ablation:**

| set | recovers |
|---|---|
| `G → 0` (RESPONSE released right after the ACK) | **D3** (CLRT ≈ 0) |
| `D → 0` (ACK forwarded immediately) | **D2** (RESPONSE at `t_ack + G`) |
| deadlines disabled, event-release selected | **D1** (ACK on the RESPONSE event) |

**Design nuance flagged for review (unresolved):** D4's RESPONSE deadline is anchored to *ACK-release*,
so the RESPONSE deadline must be **armed when the ACK releases** — a second arming event that neither D2
nor D3 needs alone. Whether this second arm fits the ingress budget is open: **MB-1 v3 already sits at
12/12 ingress with zero headroom**, so the combined mode may need the second deadline placed in egress or
a 2-pass split (unresolved decision §9.5). This is exactly why the truth table is presented **for review
before any P4 implementation** — the combined policy is not yet compiled or costed.

**Retained invariants (all three defenses satisfy them; the unified core must too):** Tofino-1-only; no
controller packet-release fast path; exact transaction matching; queue-resident holding; blocker/token
isolation by strict priority; bounded expiry; universal fail-open; state cleanup on release/FIN/RST/
expiry; lightweight correctness counters only.

**Invariants the unified core must keep (all three defenses already satisfy them individually):**
Tofino-1-only; **no controller packet-release fast path** (all release decisions in the data plane);
exact transaction matching; queue-resident holding (held packets sit in a TM queue, not a controller);
blocker/token isolation (the reservoir that pins a held packet is isolated per role by strict priority);
bounded expiry; fail-open backstop; state cleanup on release/FIN/RST/expiry; lightweight correctness
counters only.

---

## 5. Size plane specification — fixed-count real-plus-decoy CROBs

**Public profile K = R + D**, where **R** = the number of real CROBs the operator intends and **D** = the
number of inert decoy CROBs. The transaction is padded to a fixed K so its observable size is constant
for that K regardless of R.

- **The authorized master inserts the decoy CROBs.** The Tofino does **not** fabricate, insert, or modify
  any CROB — it only times packets (§4). This keeps the switch's DNP3 payload byte-preserving.
- **SELECT and OPERATE carry the same ordered K-object list** (identical index+control-code ordering), so
  the outstation echoes K objects in both responses and the request/response sizes are constant per K.
- **The relay contains explicitly configured inert decoy points** — DNP3 control indexes that exist and
  accept SELECT/OPERATE (returning valid status) but are **provably unmapped** to any physical output,
  alarm, automation, or SELOGIC element. R real controls act; the D decoys are inert.
- **No second switch, decoder, outer wrapper, or filler-cell grid.** Size normalization is entirely at
  the DNP3 application-object layer (the K-object list), produced by the master, echoed by the relay.
- **Leakage reduced, not eliminated:** K is public (an observer sees "K controls"), but the *real* count
  R (1 ≤ R ≤ K) is hidden within K. Choosing K (e.g. 4/8/16) is a policy trade-off between overhead and
  the size of the anonymity set for R.

**Boundary with the timing plane:** the size plane is master + relay configuration (object counts +
inert points); the timing plane is the Tofino engine (§4). They compose but are specified and tested
independently.

---

## 6. Fixed-K emulator experiment matrix (next experiment — emulator only, no switch, no relay)

For **K ∈ {4, 8, 16}** and every supported real count **R ∈ {1 … K}**, the master pads to K = R real +
(K−R) decoy CROBs against the **emulator** outstation (Vision master ↔ Hulk emulator; no Tofino, no
SEL-751). One persistent TCP connection (per the connection-lifecycle finding). Verify:

| # | criterion | measurement | pass condition |
|---|---|---|---|
| 6.1 | **Constant SELECT request size** per K | `tcp.len` of the SELECT frame across all R | identical for all R at a given K |
| 6.2 | **Constant OPERATE request size** per K | `tcp.len` of the OPERATE frame across all R | identical for all R at a given K |
| 6.3 | **Constant response size** per K | `tcp.len` of SELECT-response and OPERATE-response across all R | identical for all R at a given K |
| 6.4 | **Correct statuses + completion** | per-object status in both responses; master task-completion | R real → success status; task completes; K objects echoed |
| 6.5 | **Only intended real controls act** | outstation point-state JSON after the txn | exactly the R real points change; the (K−R) decoys do not |
| 6.6 | **Decoy points remain inert** | outstation decoy-point state + side effects (alarms/automation surrogate) | no state change, no side effect on any decoy index |
| 6.7 | **Clean TCP** | pcap: 0 retransmits/resets; persistent connection; teardown only at end | clean, persistent, no per-txn teardown |
| 6.8 | **No obvious real-vs-decoy timing side channel** | per-object or per-transaction inter-arrival vs R | no monotonic/separable timing signal that recovers R from K |

Artifacts: per-(K,R) pcaps + analyzer JSON + a summary matrix. This experiment establishes the **size**
half on the emulator; it is the immediate next step after this checkpoint is reviewed.

---

## 7. Safety boundary (hard)

- **No SELECT or OPERATE to the physical SEL-751.** All control-plane (SBO/CROB) traffic is
  **emulator-only** until the boundary below is cleared.
- **Physical testing remains READ-only** until **every** configured decoy point is **proven unmapped**
  from outputs, alarms, automation, and SELOGIC on the real relay, AND explicit authorization is
  obtained. Proving decoy inertness is a prerequisite, not an assumption.
- The Tofino stays on Defense 3; no switch change and no unified-core load this checkpoint.
- The master inserts decoys; the switch never fabricates/inserts/modifies a control. No fabricated DNP3
  (CONFIRM/time-sync/clear-restart) ever reaches an endpoint.

---

## 8. Corrected claims (what the evidence supports today)

**Supported now:**
- **Defense 1, 2, 3 timing mechanisms are individually complete and silicon-validated** against the
  physical SEL-751 (see §3 for the per-defense source + tag + evidence).
- An **emulator CROB/SBO corpus** exists (N=1..16 successful, N≥17 rejected; persistent-connection rerun
  establishing a real slot-5 / clean transaction template) with a correctly-modeling offline oracle.
- The unified timing engine is **compile-feasible** on one Tofino-1 (MB-1 v3 fits at 12/12 ingress, at
  the ceiling) — a resource result for the timing core (the outer-header parts of that compile are
  superseded).

**NOT supported / explicitly not claimed:**
- **Complete Defense 4 has NOT been demonstrated.** The unified core is not implemented or run; the
  real+decoy size plane is not yet verified even on the emulator (§6 is the next step); nothing is on
  silicon for the combined system.
- No READ/SBO semantic indistinguishability (explicit non-goal).
- No outer-encapsulation / two-edge / filler-grid result (superseded).
- No physical control-plane (SBO) result; the physical relay is READ-only.

---

## 9. Remaining unresolved decisions (for review)

1. **K values + policy.** Which fixed K (4/8/16, or a per-deployment K) and the R-anonymity-set trade-off.
2. **Decoy-point provisioning + inertness proof.** How the inert decoy points are configured on the
   SEL-751 and the exact procedure/evidence that proves them unmapped from outputs/alarms/automation/
   SELOGIC (gates any physical control test).
3. **Combined Defense 4 timing policy.** Which release mode (or composition) the combined policy uses per
   phase (READ vs SELECT vs OPERATE), from the §4 truth table — pending review.
4. **Timing side-channel on decoys.** Whether padding to K introduces any real-vs-decoy timing signal
   (§6.8) and, if so, how the timing engine neutralizes it.
5. **Ingress headroom.** MB-1 v3 fits at 12/12 with zero margin; whether the combined timing policy needs
   any ingress logic beyond the v3 feature set (which would force an egress move or 2-pass).
6. **Select-timeout budget on the physical relay.** Still BLOCKED (device setting unread); bounds any
   future live SBO timing.
