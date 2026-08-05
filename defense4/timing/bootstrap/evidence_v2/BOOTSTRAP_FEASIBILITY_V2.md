# Defense 4 §3 — reservoir bootstrap v2 (four-queue R11 contract): evidence + verdict

**Verdict: §3 = PARTIAL — R11 REMAINS OPEN.** The R11 contract is now genuinely **implemented** and
**places** on Tofino-1, and six of the eight requirements close in code with a seventh (G3) fixed
here. But feasibility is **not** established: a load-bearing **silicon/TM** question — whether two
continuously-recirculating strict-priority block reservoirs can coexist on one loopback port without
starving one — may make readiness **structurally unreachable**, and it was never concluded on
hardware. R11 stays OPEN; no §4/Gate 3/size/TM/switch/hardware work is authorized.

This supersedes the v1 probe (`../bootstrap_probe.p4`, commit `d991944`), which is retained as a
**partial negative** probe (its own evidence in `../evidence/BOOTSTRAP_FEASIBILITY.md`). v2 corrects
all eight gaps v1 left open. It is still a §3 feasibility probe: NOT the timing core, does NOT patch
`defense4_timing.p4`, **not loaded, not run**; the deadline/release machinery is §4 (out of scope).

## Verified compile facts

| item | value |
|---|---|
| source | `defense4/timing/bootstrap/bootstrap_probe_v2.p4` |
| source sha256 | `0c8770c1b45444d8010b9ecc3b0ff1cef33f3af58f1557ad66ee0d47a433691e` |
| git commit | `d67184f` (pushed to `origin/main`) |
| one-time setup record | `defense4/timing/bootstrap/bootstrap_setup.py` (committed; refuses to run without `DEFENSE4_HW_AUTHORIZED=1`) |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline; switch not loaded) |
| exact command | `bf-p4c --target tofino --arch tna -g -o build_v2_final bootstrap_probe_v2.p4` |
| **ingress stages** | **7 / 12** |
| egress stages | 0 |
| critical path | 5 |
| tables allocated | 67 (mostly compiler-decomposed logical tables) |
| SRAM | 44 |
| Map RAM | 42 |
| TCAM | 1 (the `token_id < 64` / identity ternary) |
| **stateful (meter) ALUs** | **5** (`reg_ident`, `reg_pop`, `reg_gen`, `reg_active`, `reg_failopen`) |
| statistics ALUs | 16 |
| PHV containers / bits | 52 / 1008 (49.2 %) |
| compile result | **0 errors, 3 warnings** (benign) |

Logs: `table_summary.log`, `mau.resources.log`, `phv_allocation_summary.log`,
`gate_v2_compile_transcript.log`. As before, `context.json`/`.bfa` are run-specific and not cited.

## Per-gap outcome (adversarially reviewed)

| gap | requirement | v2 outcome |
|---|---|---|
| G1 | four **isolated** queues 7/6/5/4 | **routing PASS in code** (ACK token→qid7, RESP token→qid5, held ACK→qid6, held RESP→qid4) — **but the block-queue SCHEDULING is the open blocker below** |
| G2 | both reservoirs ready before ACK, atomically | **PASS** — one packed `reg_pop` read tests `== 0x00400040`; borrow/carry proven safe (decrements fire only when the cell was CONFIRMED, so no half underflows) |
| G3 | transaction-level latched fail-open | **PASS (after fix)** — unready ACK latches `reg_failopen=cur_gen`; same-gen RESPONSE bypasses; reset per READ. **Fixed here:** `gen_bump` now skips 0 so a wrapped generation can never alias the fail-open "not-latched" sentinel (0) |
| G4 | authenticated token identity | **PASS** — `tbl_token_valid` checks marker/sdomain/role exact + `token_id<64` (ternary `&&& 0xFFC0`) **before** any cell access; malformed tokens dropped; host-port `0x88C1` dropped; tokens are data-plane stamped |
| G5 | generation-qualified stale termination | **PASS in code** — a gen-mismatch loop token terminates in-band (`ident_clear` own cell + `pop_decr` own domain + drop), never touching `reg_gen` or another cell; current-gen tokens never die; `reg_retire` removed |
| G6 | truthful establishment | **PASS** — `pop` increments **only** on `SEEDED→CONFIRMED` (first authenticated loopback return), never at ingress admit; no double-count; recirc passes never miscounted |
| G7 | data-plane normal cleanup | **PASS** — the RESPONSE (`active_read_clear`) returns the domain to inactive every transaction over a persistent TCP connection; next READ re-arms; `reg_retire` gone |
| G8 | reproducible one-time setup | **PASS** — `bootstrap_setup.py` records two `trigger_timer_periodic` apps, templates, K, period, value-set, port enable, all issued once, constants matching the P4; refuses to run un-authorized |

**TNA-legality:** PASS — no register is accessed more than once per packet (every multi-action
register's `execute()` sites are in mutually-exclusive role branches); `reg_active` carries 4
RegisterActions, at the SALU limit but accepted; the compile corroborates.

## The load-bearing OPEN item — dual-reservoir coexistence (why R11 stays OPEN)

The four queue IDs route correctly, but the **scheduling policy between the two BLOCK reservoirs is
unresolved and may be structurally infeasible as usually configured**:

- Under a naive **strict priority 7 > 6 > 5 > 4** on one loopback port, `Q_ACK_BLOCK` (qid7)
  recirculates continuously and is essentially **never empty**, so `Q_RESP_BLOCK` (qid5) is
  **starved**: RESP tokens never dequeue → never loop back → never CONFIRM → `pop[RESP]` never
  reaches K → **`BOTH_READY` (0x00400040) is never satisfied → every transaction fails open.**
  Predicted signature: `reg_pop` stalls at `0x00400000` (ACK half only).
- This is **more fundamental** than "re-seed within the CLRT": it is *whether two continuously
  recirculating strict-priority reservoirs can coexist on one port at all.* Per the project record
  (`case-a-four-queue-oracle-resume`), that was **never concluded on silicon** — both pilots failed
  for harness reasons.
- **The P4 cannot express or fix this.** It requires the two block queues to be **co-equal** (same
  priority, WRR) or **each rate-shaped**, with the hold queues below — a **Traffic-Manager** decision
  that must be **proven on hardware**. `bootstrap_setup.py` therefore leaves
  `configure_queue_scheduling` an explicit `NotImplementedError` stub rather than asserting a policy.

Until that TM policy is chosen and validated on silicon, **the bootstrap is not demonstrated to
work** — `BOTH_READY` may be unreachable. This is the primary reason R11 is OPEN.

Also silicon-gated (secondary): after a READ turns the pool over, whether the periodic source
re-seeds and CONFIRMS the current generation's K tokens fast enough to keep `pop==K` across the CLRT
(establishment-latency / continuity, R2). And a §4 detail: a **multi-fragment** DNP3 response would
have only its first fragment see `active==1` (hold-granularity), to revisit in the core.

## Review provenance

v2 was adversarially reviewed by the P4/TNA specialist against all eight gaps. It confirmed
G2/G4/G5/G6/G7/G8 close in code and the program is TNA-legal, flagged the G3 `gen==0` wrap (**fixed
here** — the committed source is the reviewed source plus that one fix), and identified the
strict-priority starvation as the sharper, load-bearing silicon risk recorded above.

## What v2 does and does NOT establish

**Establishes:** the R11 contract is expressible and **places** on Tofino-1 (7/12 ingress stages, 5
SALUs, TNA-legal); identity validation, atomic dual-readiness accounting, generation-qualified
termination, confirmed-on-loopback establishment, transaction-level fail-open, and data-plane normal
cleanup are all realized in code; the one-time setup is recorded and constant-consistent.

**Does NOT establish:** that the bootstrap **works** — the two block reservoirs' coexistence
(scheduling policy) is unresolved and may make readiness structurally unreachable; nor any silicon
behaviour (continuity, establishment latency, ordering, release). **R11 remains OPEN. Complete
Defense 4 remains NOT DEMONSTRATED.**

## Consequence for the plan

The required pre-feasibility step is now **a silicon/TM question**, not more offline P4: choose and
**prove on hardware** a block-queue scheduling policy (co-equal/WRR or per-reservoir shapers) under
which both reservoirs establish and hold `pop==K`. That is a **hardware-gated** action and is **not**
authorized. §3 stops here with R11 OPEN; no §4, Gate 3, size, TM, switch-load, or hardware work.
