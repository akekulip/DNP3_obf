# Defense 4 §3 — reservoir bootstrap v4 (shadow staging): evidence + verdict

**Verdict: the R11 contract PLACES in a SINGLE Tofino-1 ingress pass (12/12 stages, 0 errors, no
semantic tradeoff). Silicon continuity remains UNVERIFIED, so R11 stays OPEN.** This is the positive
offline result Philip's construction was aimed at: a single-pass shadow-staged bootstrap that keeps
the authoritative packed dual-readiness word atomic AND satisfies the staged-admission,
generation-qualification, and fail-open requirements. It does NOT establish that the staged
establishment reaches and holds K/K within the CLRT on hardware — that is the continuity obligation
(R2/R11) and is the narrowly-scoped silicon test this offline pass would justify authorizing.

Supersedes v1 (`d991944`), v2 (`d67184f`), v3 (`ead57b2`) — all retained as PARTIAL/NEGATIVE probes.
Still a §3 feasibility probe: NOT the timing core, does NOT patch `defense4_timing.p4`, NOT loaded,
NOT run.

## Verified compile facts (independently recompiled)

| item | value |
|---|---|
| source | `defense4/timing/bootstrap/bootstrap_probe_v4.p4` |
| source sha256 | `dce08aa613aaaa38ca80ee106e7b5b9d3fd6ab18f64f678ce99aa585641b74dc` (reviewed `dcd704a6` + review-requested comment/setup fixes, semantically identical, recompiled clean) |
| one-time setup | `defense4/timing/bootstrap/bootstrap_setup.py` (2 `trigger_timer_periodic` apps, templates, K, period, value-set, **fixed 7>6>5>4 ladder, shaping disabled**, enable; refuses to run without `DEFENSE4_HW_AUTHORIZED=1`) |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline) |
| exact command | `bf-p4c --target tofino --arch tna -g -o build_v4 bootstrap_probe_v4.p4` |
| **ingress stages** | **12 / 12** |
| egress stages | 0 |
| critical path | 5 |
| tables allocated | 57 |
| **stateful (meter) ALUs** | **8** — the 8-register acyclic chain, 1 SALU each |
| statistics ALUs | 8 |
| binary | `tofino.bin` produced |
| compile result | **0 errors, 2 warnings** (parser loop-unroll only; **no** `uninitialized_out_param`) |

Register chain places strictly increasing:
`reg_gen@0 < reg_ident_resp@2 < reg_resp_stage@3 < reg_ident_ack@4 < reg_pop_packed@6 <
reg_resp_gen@7 < reg_active@8 < reg_failopen@10`.

## The construction (Philip's shadow staging)

The v3 finding was that DIRECTLY REUSING the authoritative packed population register as the staged
ACK-seed predicate creates an unsatisfiable single-pass register-ordering cycle — NOT that staged
admission and atomic readiness are inherently incompatible. v4 decouples them:

- **`reg_resp_stage`** — a RESP-only **shadow** count, placed BEFORE `reg_ident_ack`. Its sole job is
  to open ACK seeding: a pktgen ACK token is dropped while `stage_read != K`. It **never** authorizes
  a native packet.
- **`reg_pop_packed`** — the AUTHORITATIVE `{ack(hi16), resp(lo16)}`, placed LAST, read ONCE by
  native admission (single-word atomic `== 0x00400040`). Preserved.
- Because the shadow (read by ACK seeding, before `ident_ack`) and the authoritative word (written by
  ACK confirm, after `ident_ack`) are DIFFERENT registers, the order
  `gen < ident_resp < resp_stage < ident_ack < pop_packed` is acyclic.
- **Atomic safety (confirmed by review):** the shadow is NOT in the native decision at all
  (`tbl_native_decide` never reads `reg_resp_stage`), so it cannot authorize a native packet by
  construction. Stronger: `reg_resp_stage` and `pop.RESP` are incremented in **lockstep** on the same
  first-RESP-confirm and reset together on a READ, so `shadow == pop.RESP` is an absolute invariant —
  they cannot diverge, and `pop_packed` first reads `0x00400040` only when both halves are genuinely
  64 (RESP first). No false K/K.

Staged flow: a READ resets `pop_packed` 0/0 and the shadow 0; RESP seeds are ungated and confirm to
`0/K` (while `Q_ACK_BLOCK` is empty, so `Q_RESP_BLOCK` dequeues freely under the strict ladder); only
then do ACK seeds enter, confirming to `K/K`; only `K/K` admits the native ACK. At the deadline (§4)
the static ladder drains ACK-blocker → ACK → RESP-blocker → RESP.

## Two v3 semantic bugs fixed

- **FIX-ACK:** the native ACK now checks the generation-qualified fail-open latch — a duplicate ACK
  is NOT held after an earlier ACK failed open (`hold ⇔ ready ∧ fo_eq==0`, via `tbl_native_decide`).
- **FIX-RESP:** an unready native RESPONSE now LATCHES fail-open (`failopen_rmw` sets `cur_gen` when
  `ready==0`), so all subsequent packets of the generation bypass.
- `reg_resp_gen` is written gated-on-ready BEFORE the active read (`resp_gen < active`), breaking the
  `resp_gen/active/failopen` cycle. Cleanup (active clear) happens only at the held-RESPONSE loopback
  completion when `reg_resp_gen == cur_gen`, or on FIN/RST.

## The 12-stage fit (independently verified bit-exact)

The acyclic 8-register chain + validation tables + counters initially needed 16 stages. The fit to 12
used only behaviour-preserving reductions (each verified here):
- **Counter reduction** 23 → 6 `Counter` + 1 `DirectCounter` on `tbl_native_decide`. The dropped
  counters were purely diagnostic (each beside an unconditional `drop`/`fwd`, gating no control flow);
  required observability (seed/confirm/hold/fail-open/stale/overlap) is retained.
- **Seed dedup reformulation** to a two-comparator form `v==cur_gen ∨ v==cur_gen_conf` — **bit-exact**
  to `(v & GEN_MAX)==cur_gen` for the reachable cell states `{0, G, G|CONF_BIT}` with
  `cur_gen∈[1,0x7FFFFFFF]`. Forced by a bf-asm defect (below).
- **Native decision** cascade → one exact-match table `tbl_native_decide` keyed on `{role, ready,
  fo_eq}`; all 8 entries verified to reproduce FIX-ACK and FIX-RESP exactly.
- **`fo_eq` fold** into `failopen_rmw` (returns the pre-write `old==cur_gen`); `ready` already includes
  the active check (`pop==K/K && active==1`).
- Index micro-tables removed (slice passed directly); `@stage` pins on `reg_ident_ack`/`reg_active`
  (pure placement).

### Toolchain findings (SDE 9.13.1), recorded
1. **bf-asm cannot assemble a masked stateful compare** `(v & 0x7FFFFFFF) == phv` (it demands a
   register-slice operand; a sliced compare `v[30:0]==…` is rejected by the frontend). The masked form
   *places* but never *assembles* — hence the two-comparator reformulation.
2. **The table placer is non-monotonic:** adding the extra `cur_gen_conf` field (needed for #1) tipped
   the greedy placer into non-convergence on two multi-branch registers despite valid stages; `@stage`
   pins on register-wrapping tables are the reliable lever.

## Review provenance

v4 was adversarially reviewed by the P4/TNA specialist against the full shadow-staging contract and
both fixes, with concrete failure-construction attempts. Verdict: **clean on substance** — staged
safety (no false K/K; the `shadow == pop.RESP` lockstep invariant makes divergence unreachable),
generation qualification, FIX-ACK/FIX-RESP (all 8 `tbl_native_decide` entries checked exact), the fit
changes (dedup bit-exactness, `fo_eq` fold, counter removal, `@stage` pins), identity gating,
metadata init, and TNA legality all PASS. The only substantive residual is the overlapping-transaction
wrong-clear (above) — fail-open, requires a single-outstanding violation, disclosed. Five low/info
comment-and-wording defects it flagged (stale seed-dedup comment; `ctr_overlap` called a "guard";
"gated-on-ready" imprecision; missing `increment_source_port=False`; stale `meta.failopen_old` note)
were fixed in the committed source/setup (semantically identical; recompiled clean at 12 stages).

## Disclosed residuals (scoped, NOT claimed closed)

- **Silicon continuity (R2/R11):** whether the staged establishment reaches and HOLDS `K/K` within the
  CLRT is unverified — the primary reason R11 stays OPEN. The probe models the held packet's release at
  its FIRST loopback return (to place cleanup correctly); the real hold DURATION (deadline) is §4.
- **`reg_resp_gen` single-outstanding assumption:** the gated-on-ready write is behaviour-equivalent
  only if an older held RESPONSE cannot coexist with the current generation. The review constructed the
  overlapping-transaction wrong-clear and confirmed it (a) requires a single-outstanding violation
  (which DNP3 polling forbids) and (b) is strictly **fail-open** (an early `active` clear only makes
  later native ACKs forward — nothing is stranded/lost/misrouted). `ctr_overlap` is a **detector
  (canary), NOT a guard** — it neither rejects the overlapping READ nor prevents the clear; prevention
  rests on the environmental single-outstanding assumption plus the fail-open outcome. Robust
  overlapping-transaction handling would carry the generation in the loopback shim (a §4 mechanism) —
  noted, not built.
- **K ≤ 64** hard-coded by the `token_id[5:0]` cell index; guard/widen before any resize.
- Host classification is the compact subset (TCP offset 5/8; DNP3 READ/RESPONSE; FIN/RST).

## What v4 establishes / does NOT

**Establishes (offline):** the full R11 shadow-staging contract — staged RESPONSE-first admission
under the static 7>6>5>4 ladder, an authoritative single-word atomic dual-readiness, generation-
qualified per-role cells and population, both fail-open fixes, and data-plane cleanup at the
generation-qualified RESPONSE completion — is expressible and **places in a single 12-stage Tofino-1
ingress pass with no semantic tradeoff**, with a committed one-time setup.

**Does NOT establish:** any silicon behaviour (continuity, establishment latency, ordering, release).
**R11 remains OPEN.** Per Philip: only after this offline construction passes should a narrowly-scoped
silicon continuity test be authorized — which is a hardware step, gated. **Complete Defense 4 remains
NOT DEMONSTRATED.**
