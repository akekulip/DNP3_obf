# Defense 4 — evidence ledger

**Grounding audit, 2026-08-04. Purpose: establish a verified factual base before designing,
per the feasibility prompt's "build an evidence ledger before designing anything." Labels:
`VERIFIED` (reproduced from source/trace/compiler/hardware this session), `REPORTED` (stated
in an artifact, not reproduced), `INFERRED`, `PROPOSED`, `BLOCKED`. No hardware was touched;
the switch is on Defense 3 from earlier work and is not to be disturbed for this planning
task.**

---

## 1. Git / repository state

| fact | label | source |
|---|---|---|
| branch `main`, HEAD `17df254`, tree clean except untracked `defense4/`, `research/ditto_comparison/`, `defense3/evidence/pure_defense3/`, `defense3/run/pure_defense3_capture.sh` | VERIFIED | `git status`, `git rev-parse` |
| commit `a769dee` = "Defense 1 telem v2 — stable txn key" (2026-07-22) | VERIFIED | `git cat-file`, `git log` |
| commit `49c1b0b` = "dcrn_defense2_telem.p4 (deadline-defense instrumentation)" (2026-07-22) | VERIFIED | `git log` |
| commit `f00a5fd` = "Part 12 COMPLETE: cleanup verified, switch restored" (2026-07-24) | VERIFIED | `git log` |
| commit `e7e7223` = "DNP3 size-pattern builder v1 (off-switch)" (2026-07-22) | VERIFIED | `git log` |
| tags `d1-telem-v1-verified`, `d2-telem-v1-verified`, `queue-trace-level1-hw-pass`, `ack-delay-caseA-c3-pass`, `timing-final-meeting-v1` present | VERIFIED | `git tag` |

The prompt's reported commits/tags all resolve. The prompt is describing THIS repository.

---

## 2. Reported anchors — verification

| # | reported anchor (from the feasibility prompt) | ruling | controlling evidence |
|---|---|---|---|
| A | SEL-751 "outstation address 10" | **REFUTED for the physical relay** | The physical SEL-751 is outstation link addr **0**, master 1, verified on the wire 2026-07-25 (`defense3/CLAUDE.md:147-149`). "outstation=10" is the stale 10.0.0.x *corpus* value and is explicitly recorded as WRONG for the physical relay. Any Defense 4 work on the physical relay must use addr 0. |
| B | "Full SELECT-to-OPERATE SBO was absent from the earlier DIRECT_OPERATE corpus" | **SUPERSEDED** | `dnp3_multicrob_harness/captures/multi_crob_sbo.pcap` decodes (tshark, this session) to func **3 SELECT** (tcp.len 50) → func **129 SELECT-RESPONSE** (52) → func **4 OPERATE** (50) → func **129 OPERATE-RESPONSE** (52), on the **simulated** outstation (Hulk `10.10.54.158`), preceded by enable-unsolicited (func 20) and a WRITE (func 2). Real SBO exists — but (i) emulator not physical relay, (ii) a single fixed CROB count, not the 1/2/4/8 sweep the size envelope needs. Tooling: `run_multicrob_sweep.py`, `dnp3_multicrob_harness/`. **Consequence: roadmap Phase 1 shrinks from "build SBO generation" to "run the existing SBO sweep and characterize sizes."** |
| C | Defense 1 = matching-RESPONSE event releases held ACK, bounded fail-open | REPORTED, P4 present | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1.p4` (+ `_hardened_dp9_dp11`, `_telem`). Behavior consistent with memory `dnp3-clrt-case-taxonomy` (Defense 1 = hold ACK). Stage count (reported 12/12) not re-compiled this session. |
| D | Defense 2 = ACK-relative absolute deadline holds a queue-resident RESPONSE | REPORTED, P4 present | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense2*.p4`; frozen silicon-proven core `research/defense2_pktgen/p4/dnp3_timing_normalizer_pktgen.p4` (the current switch restore baseline). |
| E | Part 12 HOLD_RESPONSE 200/200, ~1.72 ms offset | REPORTED (commit `f00a5fd` verified) | Consistent with memory `ibspg-hold-response-part12` (ACK→response hits deadline within ~1.7 µs, 23 ns spread; note memory says **µs** offset for the queue-resident release tail, the prompt says "1.72 ms" — likely a units slip in the prompt; the release TAIL is ~1.72 µs, the HOLD is ms-scale). Flag for the ledger: **do not quote "1.72 ms offset" without checking; the measured release tail is ~1.72 µs.** |
| F | 3-level nested strict priority proven (ACK-before-response) | VERIFIED (prior silicon) | memory `ibspg-paired-part11`: Q_BLOCK(7)>Q_ACK(3)>Q_RESP(0), 100/100 both injection orders. The arch doc's 4-queue order is a 4-LEVEL extension of this. |
| G | Level-1 size microbench normalized synthetic frames to 128 B, reduced size leakage, NOT live DNP3 / no splitting | VERIFIED | memory `queue-trace-level1-hw-pass`: size MI 0.91→0.00 on **declared-size** synthetic frames, 3 flows, measurement-only telemetry. `research/tofino_dcrn_feasibility/p4/queue_microbench/queue_microbench_trace_v1.p4`. The physical SEL Class-0 response is **200 B wire / 134 B TCP payload > the 128 B state** — the 128 B state is NOT universal (arch doc §6 says the same). |
| H | Invalid in-protocol DNP3 padding is negative evidence | VERIFIED | `dnp3_multicrob_harness/reports/padding_candidates/`: invalid-index CROB → OUT_OF_RANGE, **partial SELECT failure suppresses OPERATE**. A *valid-but-unwired* index dodges this (SELECT success, OPERATE proceeds) but "unwired = inert" is UNVERIFIED on the physical relay (a point may drive a remote bit / SELOGIC input). |

---

## 3. Defense 3 measured facts (this session, from the shipped build)

| fact | label | source |
|---|---|---|
| shipped `case_a_defense3.p4`: 10/12 ingress stages, 0 egress, crit path 10, 76 tables | VERIFIED | `defense3/evidence/pure_defense3/20260804T155605Z/resources/table_summary.log` |
| stages 7-8 saturated 16/16 logical tables; SALUs 11/40 (st 1,2,4,6,9); PHV normal 45 containers/793 bits; groups B0-15 and W0-15 fully exhausted; 246 ingress cycles, dependency-bound | VERIFIED | `resources.json`, `phv_allocation_summary_0.log`, `power.json` |
| pure Defense 3 at D=16 ms: 60/60 held, CLRT median 32 µs, sd 13.6 µs, 59/60 < 0.1 ms | VERIFIED | `defense3/evidence/pure_defense3/20260804T155605Z/` (pcap + counters) |
| native `a` (READ→ACK) med 0.453 / p95 2.914 / max 3.731 ms; `c` (CLRT) med 2.828 / p95 12.222 / max 13.175 ms; `a+c` max 17.662 ms over 400 txns | VERIFIED | `defense3/evidence/physical*/dsweep_blocks.jsonl` (computed this session) |
| grid slip rate P(a+c > N·T) = 0 at N·T ≥ 32 ms (T=16,N=2); H=30.8 ms < 32 ms so fail-open budget B must rise to ~30 000 | VERIFIED / INFERRED | computed this session; `research/ditto_comparison/DEFENSE4_GRID_DESIGN.md` §3 |

---

## 4. DNP3 / TCP facts (source-verified in opendnp3-community)

| fact | label | source |
|---|---|---|
| outstation `selectTimeout` default 10 s; OPERATE validated against SELECT within it | VERIFIED | `opendnp3-community/.../OutstationParams.h:41`, `OutstationContext.cpp:770` |
| any injected application frame runs `ProcessIIN` unconditionally → NEED_TIME = g50 time-sync WRITE, DEVICE_RESTART = clear-restart WRITE; fabricated CONFIRM deletes SOE records | VERIFIED | `MasterContext.cpp:217-266` (prior power-systems agent) |
| physical SEL-751 Class-0 response = 200 B wire / 134 B TCP / 115 B DNP3 len, ONE distinct size n=300; decodes to g1v2 idx0-15 / g10v2 idx0-31 / g30v4 idx0-20 | VERIFIED | `research/physical_sel751/size_inventory_20260724/` + byte decode |
| SBO CROB request grows 14.6 B/CROB, R²=0.9999 (n=1/N caveat) | REPORTED | `research/split_pad_timing_policy/` |
| TCP: MSS 1460, RFC 7323 timestamps on, SACK-permitted both directions | VERIFIED | prior capture decode |
| mis-translated ACK → RFC 9293 challenge-ACK + drop (NOT RST); practical failure = stall/timeout | VERIFIED | RFC 9293 §3.10.7.4 (corrects a prior "challenge-ACK/RST" note) |

---

## 5. Named-file locations (for the agents / next session)

| file (prompt name) | actual path | note |
|---|---|---|
| `GROUNDING.md` | `research/ack_timing_normalization/GROUNDING.md` | ACK-timing line, not Defense-4-specific |
| `CASE_A_QUEUE_DESIGN.md` | `CASE_A_QUEUE_DESIGN.md` (repo root) | queue design |
| `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md` | `research/tofino_dcrn_feasibility/p4/queue_microbench/` | Level-1 size + queue microbench |
| `DEFENSE1_TELEMETRY_REVIEW.md` | `research/tofino_dcrn_feasibility/p4/ack_delay/` | |
| Defense 1/2 P4 | `research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense{1,2}*.p4` | + frozen D2 core `research/defense2_pktgen/` |
| size-pattern builder | `research/tofino_dcrn_feasibility/p4/queue_microbench/size_pattern_builder` | commit e7e7223 |
| emulator SBO capture | `dnp3_multicrob_harness/captures/multi_crob_sbo.pcap` | **real SELECT→OPERATE** |

---

## 6. Conflicts resolved (do not silently average)

1. **SEL outstation address:** prompt says 10, wire says 0. **Controlling: the wire (addr 0).**
2. **SBO corpus presence:** arch doc says absent, capture says present (emulator). **Controlling:
   the decoded capture — emulator SBO exists; physical-relay SBO and the CROB-count sweep do
   not.** Roadmap Phase 1 adjusts accordingly.
3. **"1.72 ms offset" (prompt E):** the measured queue-resident release TAIL is ~1.72 **µs**
   (memory `ibspg-hold-response-part12`), not ms. **Controlling: the µs measurement.** The
   ms-scale quantity is the HOLD (D or G), not the tail.
4. **128 B size state universality:** Level-1 used 128 B; the physical response is 134 B TCP
   payload (larger). **Controlling: the measured 134 B — the 128 B state is not universal**
   (arch doc §6 agrees).

---

## 6b. Offline-wave verified facts (2026-08-04, added after the compiles + SBO sweep)

| fact | label | source |
|---|---|---|
| **Unified ingress control core compiles in one Tofino-1 pipeline image at 10/12 ingress stages, with critical path 9** (0 egress / 75 tables; full size-control surface) → **Unified ingress core: GO** | VERIFIED | `defense4/p4/MB1_EVIDENCE_FREEZE.md`, `build_mb1/pipe/logs/table_summary.log` |
| **Controlling budget number = 9 ingress** (stripped-D2 hold core: 9 ingress / CP 7 / 50 tables) — the "7–8 stage" estimate is RETIRED | VERIFIED | `defense4/p4/build_d2core/pipe/logs/table_summary.log` |
| MB-1 leaves 2 empty ingress stages (st10/11); egress 0/12 free for the ~2–4 egress padding action | VERIFIED / INFERRED | MB-1 logs; egress cost from prior egress-normalization work (not re-measured) |
| **SBO CROB-count size channel = 14.6 B/CROB in BOTH directions.** Layer named explicitly: this is **TCP payload** (`tcp.len`) 35→254 B (request) / 37→256 B (response), N=1..16; observer **Ethernet frame_len** (excl FCS) = tcp.len + 66 = 101→320 B / 103→322 B | VERIFIED (16-point sweep + oracle) | `defense4/evidence/sbo_corpus/`, `defense4/evidence/oracle/annotated_corpus.json` |
| **SBO pass-gate REPAIRED** — the `task=None`/`out_match=False` failure was a harness rsync/`--mkpath` plumbing bug (`run_multicrob_sweep.py` `pull()`), NOT a DNP3 fault; fixed with `os.makedirs` (line 61). N=1..16 wire-verified all-SUCCESS; N≥17 rejects on `maxControlsPerRequest=16` (TOO_MANY_OPS) | VERIFIED | `defense4/evidence/sbo_corpus/FINDINGS.md`, `corpus_split.json` |
| **Offline transaction oracle** parsed the full corpus into complete bidirectional wire sequences: Case-A READ (4 units, separate ACK, D=16 ms hold + 32 µs residual CLRT, constant sizes) + Case-B SBO (6 units, piggyback ACK) + N≥17 rejection shape | VERIFIED | `defense4/analysis/txn_oracle.py`, `evidence/oracle/annotated_corpus.json`, `PROVISIONAL_SLOT_CANDIDATES.md` |
| **Part-12 release tail = ~1.72 µs** (deadline_error median 1735 ns, block_term→release median 1720 ns; hold = G + tail) — settles the µs-vs-ms conflict from raw timestamps | VERIFIED | `research/ibspg_hold_response/evidence/part12/rep_campaign_100/campaignA_summary.json` |
| E0 reproduced from the repo copy: CLRT 4.33→0.00 bits, READ→ACK 0.65-bit residual, response size 0 bits | VERIFIED | `defense4/analysis/e0.py` |

**Three-verdict labels (directive §2):** Unified ingress core = **GO**; Complete bounded Defense 4 =
**GO WITH CONSTRAINTS**; End-to-end Defense 4 = **NOT YET DEMONSTRATED**. Do not collapse them into one.
**Correction to conflict #3 (Part-12 unit):** now VERIFIED from raw timestamps — 1.72 µs, not 1.72 ms.
**Correction to the E0 "size has no target" reading:** true for the constant Class-0 READ *response*
(0 bits), but the **SBO CROB count is a strong 14.6-B/CROB size channel** — size has a real target and
stays a first-class Defense 4 work package (directive §1).
**Terminology (directive §5):** the 35–254 B figures are **TCP payload**, not Ethernet frame size; the
observer-visible Ethernet frame_len = tcp.len + 66 (constant overhead), on-wire Ethernet = frame_len + 4
(FCS). Public **outer** wire sizes are derived per `PROVISIONAL_SLOT_CANDIDATES.md` §2 (inner + 8-byte
outer shim + FCS, clamped to [64, 1500]).

## 7. Open verification items (BLOCKED without hardware or a document)

- SEL-751 `selectTimeout` device setting (needs the relay config / instruction manual App. D). BLOCKED.
- Whether any valid DNP3 control index on the SEL-751 is provably inert (no breaker, no remote
  bit read by any SELOGIC equation). BLOCKED — but **no longer gates Defense 4**: decoy CROBs are
  retired, so this only matters if a future variant reintroduces them.
- Defense 1/2/3 stage counts on 9.13.2 (needs offline compile). Deferred to WP-E.
- Whether the emulator SBO CROB-count can be swept without a physical OPERATE — **RESOLVED: yes.** The
  N=1..16 sweep ran against a software-only outstation (`--control-point-count N`, simulated points); no
  physical relay, no breaker. See `evidence/sbo_corpus/FINDINGS.md`.
- **Same-device `Obs(READ)≈Obs(SBO)` co-measurement** — READ is Case-A physical-relay, SBO is Case-B
  emulator; both operations on one device/path (or a device-independence argument) needed before the
  strong equalization claim. Open.
- **MB-8 size-data-path offline gate** — exact outer format, real padding bytes, observer-visible frame
  lengths, encode/decode ports, padding removal, byte-identical restore, real/filler discrimination,
  MTU/oversize. Not yet run (directive §9).
