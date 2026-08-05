# Defense 4 §3 — reservoir-bootstrap feasibility: evidence + verdict

**Verdict: OFFLINE BOOTSTRAP FEASIBLE, SILICON UNVERIFIED.**

The R11 kill-question — *can both blocker reservoirs (ACK + RESPONSE, K=64) be **established and
maintained** with **one-time** control-plane configuration only, with no per-transaction host,
controller, ARM, blocker-injection, or TM action?* — is answered **NOT BLOCKED**. An isolated probe
(`../bootstrap_probe.p4`) demonstrates, in compiling P4 that places on Tofino-1, all eight required
bootstrap mechanisms, and an adversarial P4/TNA review confirms the construction has no self-drain,
no host-drivable drain, and truthful readiness. The remaining obligations (dual-reservoir
**continuity**, the periodic top-up **rate**, deadline/ordering correctness) are **silicon**
questions and stay UNVERIFIED for Gate 3 / the hardware phase — they are not resolvable offline and
are not claimed here.

This is a **feasibility probe only**. It is NOT the Defense 4 timing core, does NOT patch
`defense4_timing.p4`, was **not loaded and not run**, and omits the deadline/release machinery
(directive §4, gated). It answers a compile-fit + logical-demonstration question, nothing more.

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

## What this does and does NOT establish

**Establishes (offline):** each of the eight bootstrap mechanisms is expressible and **places** on
Tofino-1 with one-time config; the establish→admit→terminate→re-seed logic is internally consistent
(no drain, truthful readiness); the R11 kill-criterion is **not** met (bootstrap is not blocked).

**Does NOT establish:** any silicon behaviour — dual-reservoir continuity, the top-up rate, deadline
correctness, ACK-before-RESPONSE ordering, or that a held ACK/RESPONSE is actually released. Those
remain the Gate 3 (synthetic) and hardware obligations. **Complete Defense 4 remains NOT
DEMONSTRATED.**

## Consequence for the plan

R11 resolves to **feasible-offline**: the reservoir bootstrap can proceed to the §4 core rebuild
**when that step is authorized**. This probe is the isolated evidence that the core may assume an
autonomous, one-time-established dual reservoir; it does not itself begin §4, Gate 3, size work,
switch loading, TM configuration, or any hardware action.
