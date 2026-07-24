# END-TO-END IMPLEMENTATION PLAN — DNP3 Obfuscation (physical SEL-751 + Tofino)

Phase-0 deliverable of `research/END_TO_END_MISSION_CHARTER.md`. **Read-only audit; nothing was
built, compiled, loaded, or sent to the relay to produce this plan.** Every claim below is grounded
in a file that was actually read (citations inline). This plan is shown for review **before any
implementation**; per the charter it is not committed until you confirm the terminology decision
(§3) and acknowledge the plan.

Audit date 2026-07-23. Branch `research/caseA-ditto-queue`, HEAD `cd8813c`. Remote
`github.com/akekulip/DNP3_obf`. Read-only Tofino check: currently loaded program is
`/home/decps/queue_microbench/out/queue_microbench_abs.conf` (the queue microbench, from this
session's earlier authorized restore — **not** a defense, **not** decoy_paper3).

---

## 1. Provenance & re-verification caveat (read first — it qualifies "PASS_MEASURED")

The silicon results in the reports were produced by builds that are **not byte-identical to the P4
files now on disk**:

- On-disk `dcrn_defense1.p4` / `dcrn_defense2.p4` hash to `fa6a2f10…` / `fef72a5a…` (match the
  "frozen @HEAD" hashes in `DEFENSE1/2_TELEMETRY_REVIEW.md`).
- The hardware evidence cites **different shas**: Defense-1 C3 matrix on `c9f4c109`
  (`ACK_DELAY_CURRENT_STATUS.md:15`); continuous / SEL751-replay / Formby on `6e1b659b`; Defense-2
  hardware on `6387accb` (`evidence/defense2_hardware/RESULT.md:3`). The compiled evidence names the
  program `dcrn_ackA.p4` (pre-rename).
- The current on-disk `dcrn_defense1.p4` is the **hardened FIX1/2/4 build (12/12 stages)**, re-verified
  **only by off-switch compile**; the `c9f4c109` build the C3 matrix measured is a different
  (broad-match) generation.

**Consequence:** "PASS_MEASURED_ON_TOFINO" is true for *earlier* builds on a single-host Hulk loopback
rig (Vision off) with *replayed* traffic. It is **not** a live-physical-relay result, and it is **not**
a re-verification of the exact current files. This must be stated in every downstream report.

---

## 2. Current-state / gap matrix

Status = COMPLETE · PARTIAL · NOT IMPLEMENTED · BLOCKED (gated) · DEFERRED.

| # | Component | Status | What actually exists (grounded) | Gap to charter goal |
|---|---|---|---|---|
| 1 | Physical native characterization | **COMPLETE** | 300/300 Class-0 reads, ACK-mode-A confirmed, CLRT median 1.899 ms, validated (temporal dependence + moving-block CIs). Commits `ac29155`/`d36ddb6`/`d7c9483`. | none — preserve as-is |
| 2 | Live DNP3 shadow classifier (parse-only, no timing/size/order change) | **NOT IMPLEMENTED** | The Defense-1 parser already parses Eth→IPv4(ihl=5)→TCP→DNP3 0x0564, gates zero-payload ACKs out of DNP3 (`total_len ≥ 30+4·data_offset`, `dcrn_defense1.p4:273-303`), computes the canonical flow hash, and classifies READ/ACK/RESPONSE — **but inside an active hold defense**. No passive variant exists. | Phase 1: extract a passive shadow variant that emits digests and changes nothing |
| 3 | Shared generation-safe transaction core | **PARTIAL** | Canonical bidirectional CRC16 flow hash `{client_ip,server_ip,client_port}` EXISTS (`dcrn_defense1.p4:468-476`); one-outstanding-per-flow; ACK-before-response enforced (`reg_ack_gone` zero-inversion). **Generation/epoch does NOT exist** — `reg_gen` dropped, `bridge.gen` hardcoded 0 and never read (`:365,505-507`). | Phase 2: add generation freshness + harden lifecycle (no cold-reload) |
| 4 | Defense 1 (hold ACK) — replay | **PARTIAL** | C3 matrix PASS (sha `c9f4c109`): CLRT 2.48–20.52 ms → ~0.028 ms, byte-ok, but needed **cold reload between groups**. Continuous 120-txn PASS on `6e1b659b`, one connection, no reload. Current 12/12 build compiles off-switch only. | Phase 3: re-verify the *current* file continuously without reload; multi-flow unproven |
| 5 | Defense 1 — physical relay | **BLOCKED** (gated) | Only *faithful replay* done (`evidence/sel751_replay/`, "not the live relay"). | Phases 3→GATE 1/2/3 |
| 6 | Defense 2 (hold response, ACK-relative deadline) — replay | **PARTIAL / mis-calibrated** | Compiles 10/12. Hardware (sha `6387accb`) gave a device-independent **constant ~107 ms**, but the intended bounded distribution "does NOT manifest — recirc-drain offset (~47 ms under load) DOMINATES" (`evidence/defense2_hardware/RESULT.md:39-45`). The M2 parent-program hold also capped (~2.9 ms) because `qid` was not set on recirc. | Phase 4: fix the recirc-drain/qid calibration so external release tracks G; run 8/12/16/20 ms campaign |
| 7 | Defense 2 — physical relay | **BLOCKED** (gated) | none | Phase 4→gates |
| 8 | Size-state regeneration from physical evidence | **NOT IMPLEMENTED** | Level-1 normalizer uses a **declared** `input_size_class` in a `0x88B7` replay wrapper (not live DNP3), single **128 B** state, one queue, corpus max **120 B**. Physical SEL response is **134 B wire / 115 B DNP3** → does not fit (max declared class 120 → fail-open forward-unchanged). | Phase 5: rebuild the size inventory from physical + trace evidence; new target state(s) |
| 9 | Two-edge outer size-normalization prototype | **NOT IMPLEMENTED** | Does not exist in this repo (TODO only). The one size-encap stack is in a *separate* GridCloak project and the DNP3 audit explicitly rejects copying it. The DNP3 encap/decap that exists is a byte-preserving **timing** bridge, not size. | Phase 6: software two-edge prototype first |
| 10 | Joint size + timing | **NOT IMPLEMENTED** (single-program **infeasible**) | Defense 1 is **12/12 ingress stages — full** (`COMPILE_FACTS.md:6`, `DEFENSE1_TELEMETRY_REVIEW.md:218`). "No stages left for size+split → SmartNIC is the fix." | Phase 7: platform split (Tofino timing + software/NFP edge for size) |
| 11 | Combined-ACK (ACK mode B) handling | **NOT STARTED / DEFERRED** | `case_b_defense_design.md` is a design study only. | out of scope until Defense 1/2 done + explicit authorization |
| 12 | Bounded transaction-window cover | **DEFERRED** | design-only. | separate authorization + safety review |

**Existing assets to reuse (do not rebuild):** the shared parser + canonical flow hash + fc_allowlist
(`dcrn_defense1/2.p4`); the recirc-hold bridge geometry (byte-preserving); the reference state machines
`refmodel/defense1_state_machine.py`, `defense2_state_machine.py`; the unit tests
`tests/test_defense1.py`, `test_defense2.py`, `test_hardening_fix124.py`; the control-plane
`defense1_setup.py`/`defense2_setup.py`/`defense1_read.py`; the C3/continuous/formby evidence harness;
`SWITCH_ROLLBACK_RUNBOOK.md`; the size-pattern builder (`size_pattern_builder/`) and the Level-1
normalizer as a size *mechanism* reference.

---

## 3. Terminology — a real conflict that needs your decision

The repo is **internally inconsistent**, three ways:
- `CASE_A_TERMINOLOGY.md` (locked by `meeting_direction.md` §1 "NON-NEGOTIABLE"): **Case A/B = the two
  device cases** (separate vs combined ACK); Defense 1/2 = the defenses; "never call Defense 2 'Case B'."
- `COMPILE_FACTS.md:3` and `ACK_DELAY_STATE_MACHINE.md`: **"Case A/Case B" = the two defenses**
  (`ackA`=Defense 1, `ackB`=Defense 2) — the old mislabel.
- The charter §B: **ACK mode A/B = the device cases**; Defense 1/2 = the defenses; never "Case B" for
  Defense 2.

**RESOLVED — option (b) (user decision, 2026-07-23).** Preserve **Case A / Case B** as the
meeting-locked *device-pattern* terminology (Case A = separate-ACK / SEL-751; Case B = combined-ACK /
AB1400, ION7550). **"ACK mode A" and "ACK mode B" are used only as aliases** for Case A and Case B
respectively. **Defense 1 and Defense 2 remain mechanisms within Case A.** **Case B must never be used
as a synonym for Defense 2.**

Concrete edits under this decision (additive; the meeting-locked `CASE_A_TERMINOLOGY.md` keeps its
meanings, only gains the alias note):
- `CASE_A_TERMINOLOGY.md`: add "ACK mode A ≡ Case A; ACK mode B ≡ Case B (aliases)".
- `COMPILE_FACTS.md` and `ACK_DELAY_STATE_MACHINE.md`: add a correction banner — these predate the rename
  and misuse "Case A/Case B" to mean the two *defenses*; the banner maps their "Case A/B" to **Defense
  1 / Defense 2** and reaffirms Case B ≠ Defense 2. Their body text is left intact (they are historical).

---

## 4. Intended architecture (grounded in the resource reality)

```
        Vision (master)  --Class-0 READ-->  [ Tofino-1 : TIMING ]  <--response--  SEL-751
                                              |  shadow classifier (Phase 1)
                                              |  gen-safe txn core (Phase 2)
                                              |  Defense 1 OR Defense 2 (separate variants)
                                              |  recirc hold; TM = priority/occupancy only; cover OFF
        [ trusted software/NFP edge : SIZE (Phases 5-6) ] -- outer encap/pad --> observer -- decap -->
```

- **Timing on the Tofino, size on a second trusted edge** — forced by the 12/12 stage wall on Defense 1.
  Separate compile-time P4 variants (shadow / Defense 1 / Defense 2), never one combined program.
- Controller installs policy **before** traffic; not in the packet fast path.
- Endpoints unmodified; existing TCP/DNP3 bytes preserved; no seq translation; no DNP3 CRC recompute
  for timing; recirculation is the sparse-hold primitive; pktgen OFF; fail-open forwards the original.

> **Silicon implementation fact (confirmed on Tofino-1, 2026-07-23 GATE-1 — keep explicit in all
> architecture docs):** classification is **physically direction-dependent, not merely TCP-port-dependent.**
> `dnp3_shadow.p4` (and the defenses' shared classifier) sets `meta.dir` from the **physical ingress
> port** (`dir=0` iff ingress == `PORT_VISION`/dp8, else `dir=1`) and gates `DNP3_READ` on
> `func==1 && dir==0 && dst==20000` and `DNP3_RESP` on `func==129 && dir==1 && src==20000`; a correct
> function code on the wrong physical port falls to `LINK_OTHER/NOTE_WRONG_DIR`. Consequences: (a) any
> silicon validation must inject each direction on its correct port (**B1 bidirectional**, not a single-
> port replay); (b) the direction-agnostic Python reference model is the *looser* oracle and agrees only
> when physical direction matches TCP-port direction (i.e. real inline, or B1); (c) the port↔role wiring
> (dp8=Vision/master, dp9=Hulk/outstation) is part of the classifier's correctness contract, not just
> cabling. Evidence: `.../shadow/SHADOW_PARSER_VALIDATION_REPORT.md` §2, `GATE1_REPLAY_TOPOLOGY_RECONCILIATION.md` §0'.

---

## 5. Compile / resource risks (grounded)

- Defense 1 = **12/12 ingress** (full), parser 171/256, SRAM 55/960, stateful ALU 9/48 (bf-p4c 9.13.1).
  **Cannot** absorb the shadow classifier, generation logic, or size logic in the same program.
- Defense 2 = **10/12 ingress**, 2 stages headroom.
- Shadow classifier (parse + digest, no hold) should be *smaller* than a defense (no recirc/release
  logic) — expected to fit, but must be measured.
- Generation freshness (Phase 2) adds a register read on ≥2 paths — risk of pushing Defense 1 past 12
  stages → will require a compact redesign or a Defense-1 variant that trades a feature for the register.
- Joint (Phase 7) single-program: **infeasible** — mandated platform split.
- Every P4 build: compile with the actual SDE (local 9.13.1 for iteration; on-switch 9.13.2 is
  authoritative), save full compiler output, parse stages/SRAM/TCAM/PHV/ALU into `RESOURCE_BUDGET.md`,
  and treat any "unsupported behavior" warning as a failure.

---

## 6. Phase order, definition of done, and hardware gates

Autonomous (no gate): inspection, coding, **offline** compile (local 9.13.1), unit tests, PCAP replay,
analysis, doc drafts, git prep. Everything touching the shared Tofino or the relay is gated.

| Phase | Work | Definition of done (offline) | Gate before hardware |
|---|---|---|---|
| **0** | this plan + terminology decision | plan reviewed; terminology chosen | — |
| **1** | shadow classifier variant | parses/classifies the 300-poll pcap correctly (300 READ/ACK/RESPONSE, 0 link-frame misclass, 0 zero-ACK-as-DNP3); byte/size/order identity; negative tests; compiles + resource report | GATE 1 (load) |
| **2** | generation-safe txn core | reference-model + replay tests pass (retransmit, stale ACK, resp-before-ACK, FIN/RST, timeout, 2nd request, seq wrap, gen rollover, hash-collision sim); no stale state; fits a variant | — (used by 3/4) |
| **3** | Defense 1 harden (current file) | continuous sequential replay **without cold reload**, byte-identical, ACK-before-response always, no anomalies, fits Tofino-1; resource report | GATE 1→2→3 |
| **4** | Defense 2 calibrate | fix the recirc-drain/qid offset so external release tracks G within small bounded error at 8/12/16/20 ms; reproducible replay per target; no unexplained constant offset | GATE 1→2→3 |
| **5** | size regeneration | inventory from physical + trace pcaps; candidate states derived from evidence (must cover 134 B); MI/classifier before/after; manifest | — |
| **6** | two-edge size prototype (software) | namespaces/replay: inner byte-identity, cover never reaches endpoint, decap reproduces original; label it *unauthenticated* unless a real reviewed auth mechanism is used | new gate before relay path |
| **7** | joint eval | native vs D1 vs D2 vs size vs joint, on the attacker-visible trace; MI/classifier/CIs; no mode-hiding claim unless actually hidden | gates as needed |

**Gate content (presented and stopped-on each time):** exact action; exact commands; active program to
replace; restoration command + known-good program (`SWITCH_ROLLBACK_RUNBOOK.md`); affected ports;
downtime; packet bounds; relay poll count; runtime; safety checks; stop conditions; evidence outputs.

---

## 7. Safety plan (unchanged from the charter; enforced)

Relay read-only forever: the native/shadow probes keep the pins (empty startupIntegrityClassMask, empty
unsolClassMask, disableUnsolOnStartup=False, ignoreRestartIIN=True, TimeSyncMode.None, no-retry). One
persistent session, one outstanding, hard-stop on FIN/RST/timeout/retry/reconnect/unexpected-FC/
IIN-error/unmatched-response/loss/reorder/retransmit/fail-open/non-restorable-switch. A dropped session
ends the experiment — no reconnect-and-continue. Tofino: no load without GATE 1; restoration proven
first; raw evidence never overwritten; manifests never edited to conceal.

---

## 8. Expected new files/evidence (timestamped dirs; nothing overwritten)

- Phase 1: `p4/ack_delay/shadow/dnp3_shadow.p4` + setup + replay harness + `evidence/shadow_<ts>/`.
- Phase 2: `p4/ack_delay/txncore/` (or folded into variants) + expanded `tests/`.
- Phase 3/4: new `evidence/defense1_seq_<ts>/`, `evidence/defense2_cal_<ts>/`; updated resource reports.
- Phase 5: `research/physical_sel751/size_regen_<ts>/` (`SIZE_PATTERN_REGENERATION.md`,
  `packet_size_inventory.csv`, `candidate_patterns.json`, `overhead_analysis.csv`, plots, manifest).
- Phase 6: `research/two_edge_size_<ts>/` (software prototype + tests + manifest).
- Final: `END_TO_END_IMPLEMENTATION_REPORT.md`, `FINAL_STATUS_MATRIX.csv`, `FINAL_ARCHITECTURE.md`,
  `REPRODUCIBILITY.md`, `SAFETY_CASE.md`, `RESOURCE_BUDGET.md`, `EVIDENCE_INDEX.md`; updated holistic +
  walkthrough reports; separate SHA-256 manifests (raw / derived / validation / reports).

---

## 9. Claims that will remain explicitly UNSUPPORTED until their evidence exists

- No "the Formby fingerprint is erased" — at most "Defense 1 collapses the separate-ACK CLRT feature at
  low added latency," with residual leakage (request→response timing, size, packet count, ACK mode)
  reported.
- No "end-to-end defense applied to the physical SEL" until an authorized live inline run exists (the
  holistic report title/contribution will be corrected to a *characterization + primitives* framing,
  charter §P).
- No "transparent DNP3 padding" — the Level-1 result is an endpoint-visible wrapper; the two-edge
  prototype is a wrapper by design.
- No "secure/authenticated" size prototype unless a real reviewed mechanism is used.
- No claim that any current on-disk defense file's silicon behavior is re-verified until it is actually
  re-compiled+run under a gate (see §1).
- No strong p99 from ~300 samples; no multi-flow/high-rate/combined-ACK claim.
- 16 ms is not "universally safe" merely because it exceeds the 300-poll max of 15.649 ms.

---

## 10. Immediate next actions

1. **Terminology decided: option (b)** (see §3) — Case A/B locked as device patterns; ACK mode A/B are
   aliases; Defense 1/2 within Case A; Case B never = Defense 2.
2. Commit this plan + the charter + the terminology correction notes as
   `project: align terminology and end-to-end plan` (charter Q.1). Preserve commits/tags untouched.
3. Proceed autonomously into **Phase 1 (shadow classifier)** — offline coding + local `bf-p4c 9.13.1`
   compile + reference-model replay against the committed 300-poll pcap + negative tests — and stop at
   **GATE 1** before any switch load, presenting the full gate package. The Tofino and relay are not
   touched before that gate.

## Applied plan corrections (this revision)
The five substantive reconciliations the audit surfaced, now recorded here as the authoritative plan:
(1) **terminology** — resolved to option (b), §3; (2) **provenance caveat** — §1 (PASS_MEASURED is on
earlier shas / replay / single-host, not the current files, not physical); (3) **Defense 2
mis-calibration** — gap row 6 (recirc-drain offset dominates the deadline; Phase 4 fixes the mechanism);
(4) **joint size+timing is single-program infeasible → platform split** — §4, §5, gap row 10; (5)
**size 128 B vs physical 134 B mismatch** — gap row 8 (Phase 5 regenerates the pattern from physical
evidence). Corrections (2)–(5) are documentation reconciliations carried by this committed plan;
correction (1) additionally edits the three terminology files noted in §3.

**Nothing in the mission prompt is treated as approval for GATE 1/2/3.**
