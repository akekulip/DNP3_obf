# Defense 4 §3 — reservoir-bootstrap feasibility: evidence + verdict

**Verdict (CORRECTED 2026-08-05): §3 = PARTIAL / FAIL — R11 REMAINS OPEN (not feasibility-blocked).**

An earlier version of this file claimed "OFFLINE BOOTSTRAP FEASIBLE." That verdict was **over-reached
and is withdrawn.** The probe `../bootstrap_probe.p4` (commit `d991944`) **places** eight bootstrap
mechanisms in *isolation* on Tofino-1 (the compile facts below are accurate), but a subsequent audit
established that it **does NOT implement the eight R11 requirements as a faithful contract** — see the
gap table. Placeability of isolated mechanisms is **not** feasibility of the bootstrap. Therefore:

- **`d991944` is retained as a PARTIAL NEGATIVE probe** (valuable evidence of what the periodic +
  deduplicated-identity concept can and cannot do), not as a feasibility result.
- **R11 remains OPEN.** The concept is promising (this is not an impossibility result), but the full
  contract must be implemented and evidenced before feasibility can be claimed. Successor probes:
  **v2** (`../bootstrap_probe_v2.p4`, commit `d67184f`) built the four-queue contract but is ALSO a
  partial negative probe (six audit defects; see `evidence_v2/BOOTSTRAP_FEASIBILITY_V2.md`); **v3**
  (`../bootstrap_probe_v3.p4`) implements Philip's staged RESPONSE-first establishment under the
  static 7>6>5>4 ladder (`evidence_v3/BOOTSTRAP_FEASIBILITY_V3.md`).
- **No §4, Gate 3, size, TM, switch-load, or hardware work is authorized.** This stays at §3.

## Why `d991944` does NOT satisfy R11 (the eight gaps)

| R11 requirement | `d991944` actual behaviour — GAP |
|---|---|
| Two **isolated** reservoirs | Both token roles use one `QID_BLOCK`, both originals one `QID_HOLD`. Does **not** implement Q_ACK_BLOCK(7)/Q_ACK_HOLD(6)/Q_RESP_BLOCK(5)/Q_RESP_HOLD(4). |
| Both reservoirs ready **before ACK admission** | The ACK path reads only `pop[ACK]`; it can hold the ACK while the RESPONSE reservoir is unready. |
| **Transaction-level** fail-open | An ACK-before-ready is forwarded but `active` stays set, so a later RESPONSE can still be held after the transaction has already failed open. |
| **Authenticated** token identity | The marker is written but never validated; no separate scheduler-domain + role identity; unchecked domain/token-id bits alias into valid register cells. |
| Stale-token termination | A generation mismatch calls `adopt_epoch()` and **persists**. Termination needs a later CP `reg_retire` write, is not generation-qualified, and can also kill current tokens. |
| **Truthful** establishment | `pop` increments **before** `to_block()` and before the first authenticated loopback return — it proves ingress admission, not reservoir establishment (an early-ready window even without loss). |
| Normal cleanup | Only TCP FIN/RST clears `active`; a normal DNP3 transaction over a persistent TCP connection never returns the domain to inactive. |
| Reproducible one-time setup | No committed setup records the two timer apps, templates, packet count, period, parser value-set entries, or enable sequence. |

The compile facts, construction description, and review provenance below remain accurate **for what
the probe is** — a partial probe — and are kept as the record. They do **not** upgrade the verdict.

## Verified compile facts (from the committed logs in this directory)

| item | value |
|---|---|
| source | `defense4/timing/bootstrap/bootstrap_probe.p4` |
| source sha256 | `73447b6318b0c7d3b8ad5e69d6798e937f44619ea6ca208c333482135f1a5a95` |
| git commit (probe) | `d991944` (pushed to `origin/main`) |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline; switch not loaded) |
| exact command | `bf-p4c --target tofino --arch tna -g -o build_final bootstrap_probe.p4` |
| **ingress stages** | **6 / 12** |
| egress stages | 0 |
| **critical path** | **3** |
| tables allocated | 50 (mostly compiler-decomposed logical tables from the flat `apply`) |
| SRAM | 38 |
| Map RAM | 38 |
| **TCAM** | **0** (no ternary match tables) |
| **stateful (meter) ALUs** | **5** (= `reg_present`, `reg_pop`, `reg_gen`, `reg_retire`, `reg_active`) |
| **statistics ALUs** | **14** (= the 14 correctness counters) |
| PHV containers | 52 (8×8-bit, 29×16-bit, 15×32-bit) |
| PHV bits used / allocated | 1008 / 1008 (49.2 %) |
| compile result | **0 errors, 3 warnings** |

The committed `table_summary.log`, `mau.resources.log`, `phv_allocation_summary.log`, and
`gate_bootstrap_compile_transcript.log` support every value. The three warnings are benign: one
`uninitialized_out_param` on `meta` (the classification fields it flags — `port_ok`/`is_first`/
`is_loop`/`from_out` — are in the build's parser `init_zero` set, so they default to 0 as the origin
checks require), and two parser min-depth unroll notices. **`context.json` and `.bfa` bytes are NOT
committed and are run-specific** (bf-p4c embeds non-reproducible build data — two compiles of the
identical source produced different artifact hashes), so they are not cited as authoritative; the
reproducible evidence is the source sha256 + compiler + command + the deterministic logs.

## The construction under test

A **residency-tracked, self-healing reservoir** seeded by a **one-time** pktgen **timer** app:

- **Source (one-time).** A pktgen timer app configured **once** fires each domain's K `packet_id`s
  (0..K-1; `app_id`→domain) **periodically**. No data-plane action triggers it. A period fire that
  hits a still-live token is de-duplicated in the data plane; a fire that hits a freed slot re-admits
  it — so one one-time app both **seeds and re-seeds**. (Directive R11 explicitly permits a
  continuously-configured pktgen source *iff* configured once and the data plane controls
  admission/stamping/readiness — this is that.)
- **Residency.** `reg_present` is a per-`(domain, packet_id)` occupancy cell (admit sets, retire
  clears); `reg_pop` is the per-domain **live** count (`++` on a distinct admit, `--` on a
  termination). `ready ⟺ pop == K`. Because `pop` tracks residency it **falls** when tokens
  terminate, so an emptied ring can never read "ready", and freed slots are re-seedable.
- **Persistence.** A recirculating token is simply re-enqueued each pass — **no self-draining
  budget** (that was the refuted design). On an epoch change it re-stamps (`adopt_epoch`).
- **Termination.** A token terminates **only** when its domain is retired via a control-plane-set
  `reg_retire` (an **admin** drain/reprovision, not per-transaction), clearing its own cell and
  decrementing its own domain's count and nothing else; the periodic source then re-seeds.

Why not the frozen `defense2_pktgen` pktgen: that variant is **request-triggered** (a READ mirrors a
clone that fires a per-READ K-token batch) — a per-transaction data-plane action, which §3 forbids.

## Property → site demonstration (directive §3)

Each is realized in code (grep the `[Pn]` tags) and was confirmed by the adversarial re-review:

| # | property | site | verdict |
|---|---|---|---|
| P1 | authenticated internal origin | parser `from_pgen`/`from_loop` + `value_set pgen_timer`; a `0x88C1` frame from a host port (`is_first==0 && is_loop==0`) → `drop_pkt` (`ctr_seed_badorigin`) | PASS |
| P2 | distinct id, no double-count of recirc passes | `reg_present` occupancy; `pop_incr` only on `present_old==0`; recirc passes are `is_loop` and never touch present/pop; a re-fire of a live id dedups | PASS |
| P3 | ACK + RESPONSE reservoir readiness | `reg_pop` indexed by domain (2 reservoirs); `ready ⟺ pop==K`; `pop` tracks **live** residency so it is truthful | PASS |
| P4 | data-plane generation/role/domain stamping | `admit_token()` stamps marker/domain/gen/tokid in the MAU from `reg_gen` + pktgen header (not the CP template); `adopt_epoch()` re-stamps and the adopt compare **reads** `hdr.token.gen` | PASS |
| P5 | ACK-before-ready fail-open, un-stranded | host ACK/RESP: `ready && active && from_out` → `to_hold`, else `to_fwd` (forwarded, never enqueued behind an unready reservoir) | PASS |
| P6 | stale-token termination touching no newer generation | retire branch: `drop_pkt` + `present_clear(own cell)` + `pop_decr(own domain)` only; writes no other token and not `reg_gen` | PASS |
| P7 | inactive nonblocking | `reg_active==0` → host ACK/RESP forwarded, never held; the token loop never reads `reg_active`, so tokens keep looping harmlessly | PASS |
| P8 | bounded cleanup + restoration | FIN/RST → `active_clear` (one write); the pool is **not** drained, so restoration on the next ARM is O(1) (`active_set`); the heavier retire+re-seed drain is admin-only | PASS |

## Review provenance (the honest record)

The **first** draft (one-shot timer + a finite per-token `budget`) compiled clean but was
**refuted in code** by the adversarial P4/TNA review — a compile alone could never have caught it:

1. `budget` decremented every recirc pass with no refresh → both pools drained in ~0.17 s **with zero
   host traffic**, and sticky `reg_present` made re-seed impossible.
2. `gen_bump` was `v+1` unguarded and `GEN_TERMINATE = 0xFF`, so the **255th READ** set `reg_gen=0xFF`
   and the next pass drained **both** domains.
3. `reg_pop` never decremented → `pop==K` stayed **stale-true** over an empty ring (silent protection
   loss — the worst failure mode for a security control).

The probe was **rewritten** to the construction above (periodic source; residency-tracked `pop` with
`present_clear`/`pop_decr`; termination via a read-only `reg_retire`, not a gen sentinel; live epoch
adoption). The **re-review confirmed all three killers closed, not relocated**: no zero-traffic drain
(no draining counter exists), no host-drivable drain (`reg_retire` has only a read-only data-plane
action — no host packet can set it), and `pop == #live cells ∈ [0,64]` as a preserved invariant so
`ready ⟺ pop==K` is truthful. No new TNA-legality violation was introduced (each of the five
registers is accessed ≤1×/packet across mutually-exclusive role branches; the compile confirms
placement in 6/12 stages).

## Disclosed residuals (scoped, NOT claimed closed)

- **`pop` is an admit/retire ledger, not a physical census.** A *silicon* token loss (TM overflow,
  link flap) that bypassed the retire branch would let `pop` over-read `ready`. This is exactly the
  dual-reservoir **continuity** obligation (R2 / R11) and is carved to Gate 3 / hardware — not an
  offline claim.
- **Periodic top-up rate / retire-refill gap.** During an admin retire, freed slots refill only as
  fast as the periodic source fires, and the `is_first` admit path does not consult `reg_retire`, so
  `pop` can transiently lift during a retire. Whether the rate keeps `pop==K` continuously across a
  transaction boundary is a **timing** question for silicon — the header and this doc scope it out.
- **`K ≤ 64` is hard-coded** by the `packet_id[5:0]` occupancy index (two consistent sites). Correct
  for K=64; **guard/widen the index before any resize** (§4). Low-severity, latent.
- **`to_hold` has no release** — the deadline/release machinery is deliberately §4-out-of-scope; the
  probe demonstrates only the admission *gate* decision, not a working hold.
- **Host classification is a compact subset** (TCP `data_offset` 5/8; DNP3 READ/RESPONSE; FIN/RST),
  sufficient to exercise the gates; the full classifier is the §4 core's job.

## What this probe does and does NOT establish (CORRECTED)

**Establishes:** each of the eight mechanisms, taken in **isolation**, is expressible and **places**
on Tofino-1 (6/12 ingress stages, 0 errors), and the periodic + deduplicated-identity concept does
not self-drain. That is a useful **partial** result.

**Does NOT establish:** that the eight R11 requirements are met as a **faithful contract** — the gap
table above shows they are not (single queue pair, non-atomic dual-readiness, non-transaction-level
fail-open, unvalidated identity, non-generation-qualified termination, ingress-time rather than
loopback-confirmed establishment, FIN/RST-only cleanup, no committed setup). It also establishes
**no** silicon behaviour.

## Consequence for the plan (CORRECTED)

**R11 is NOT resolved — it remains OPEN.** `d991944` is a partial negative probe, not a feasibility
result, and does **not** license the §4 core rebuild. The required next step is the **v2 probe**
(`../bootstrap_probe_v2.p4` + committed one-time setup config), built to the four-queue contract with
every R11 requirement implemented and validated, then re-evidenced — still at **§3**. No §4, Gate 3,
size, switch-load, TM, or hardware work is authorized. **Complete Defense 4 remains NOT DEMONSTRATED.**
