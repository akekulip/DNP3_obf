# Defense 4 §3 — reservoir bootstrap v3 (staged): evidence + finding

**Verdict: §3 = PARTIAL, R11 OPEN. v3 is a NEGATIVE result — it does NOT place on Tofino-1.** The
staged RESPONSE-first design and all six v2 fixes are implemented at the parser/semantic level (the
`uninitialized_out_param` warning is GONE — full metadata init works), but the fully-coupled
single-pass contract hits a **register-stage ordering CYCLE** that bf-p4c cannot satisfy. This is a
real, evidenced Tofino-1 limitation, and it forces a design decision (below) — one option of which
conflicts with the "atomic single word" instruction, so it is surfaced for Philip, not taken
unilaterally.

## Compile status (the wall)

| item | value |
|---|---|
| source | `defense4/timing/bootstrap/bootstrap_probe_v3.p4` |
| source sha256 | `31b51fce6a7910ad4e83535ffc9fc221e85bf6fa277e0d810bedbe00f4290f60` |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline) |
| parser / semantic | **compiles**; `uninitialized_out_param` warning GONE (F-init/G4 fixed) |
| table placement | **FAILS — 2 errors** (register-ordering cycles) |

```
error: Table placement was not able to allocate tbl_...v3l555, tbl_...v3l589 in the same stage
       along with Register Ingress.reg_resp_gen
error: Table placement was not able to allocate tbl_...v3l495, tbl_...v3l517 in the same stage
       along with Register Ingress.reg_ident
```

## The finding — a register-stage ordering cycle (rigorously diagnosed)

A Tofino Register occupies ONE MAU stage, so every branch's access order must agree on a single
global stage order for each register. Two independent cycles make that unsatisfiable:

**Conflict 1 — `reg_ident` ↔ `reg_pop` (the atomic-pop / staged-gate conflict).**
- The staged ACK-seed gate **reads `reg_pop`** (is pop.RESP == K?) **before** the ACK seed **writes
  `reg_ident`** (`ident_seed`) → `pop < ident`.
- A loopback confirm **writes `reg_ident`** (`ident_confirm`) **before** it increments **`reg_pop`**
  (count on first CONFIRM) → `ident < pop`.
- `pop < ident ∧ ident < pop` is impossible for two single-stage registers. **Splitting `reg_ident`
  alone does not help** — the ACK reservoir's own seed-reads-pop and confirm-writes-pop still cycle
  through the one `reg_pop`. The cycle breaks ONLY if **both `reg_ident` and `reg_pop` are split by
  role** (`ident_ack/ident_resp`, `pop_ack/pop_resp`), giving the acyclic order
  `ident_resp < pop_resp < ident_ack < pop_ack` (the ACK gate reads `pop_resp`; ACK confirm writes
  `pop_ack`).
- **But splitting `reg_pop` DROPS the single-word atomic dual-readiness** that the v2 audit
  required ("pack both counts into one stateful word so an ACK can test both atomically"): the
  native ACK would read `pop_ack` and `pop_resp` in two ops. **So the atomic-packed-pop requirement
  and the staged ACK-seed gate are mutually incompatible in a single Tofino-1 ingress pass.**

**Conflict 2 — the `{reg_resp_gen, reg_active, reg_failopen}` SCC (RESOLVABLE, semantics-preserving).**
As specified ("set `reg_resp_gen` when admitted to hold"), the native RESP path reads `active`/
`failopen` before writing `resp_gen`, while loopback completion reads `resp_gen` before clearing
`active`, and native ACK reads `active` before setting `failopen` — a strongly-connected cycle.
**Fix:** write `reg_resp_gen = cur_gen` **unconditionally and early** on every native RESP (before
reading `active`/`failopen`). This removes the `active < resp_gen` and `failopen < resp_gen` edges,
leaving the acyclic `resp_gen < active < failopen`. It is behaviour-equivalent: only a **held**
RESPONSE loops back to read `resp_gen`, and the generation qualification (`resp_gen == cur_gen`)
still gates cleanup, so setting `resp_gen` on a bypassed/failed-open RESP is inert.

## The decision this forces (SURFACED, not taken)

Conflict 2 is fixable cleanly. Conflict 1 forces a choice, and one option contradicts the explicit
"atomic single word" instruction — so it is Philip's call:

- **Option A — single ingress pass, split `reg_pop` by role (drop single-read atomicity).** The
  native ACK reads `pop_ack` and `pop_resp` in two ops. **Correctness is preserved** by the OTHER
  v3 fixes: `reg_pop` is reset to 0/0 on a READ and only current-generation CONFIRMs increment it
  (generation-qualified), and the staged establishment means readiness is a stable latched state at
  admission, not a racing counter — so a two-op read cannot yield a false K/K (any intervening READ
  makes at least one half read 0 → fail-open). Under generation-qualification the single-read
  atomicity is redundant; it was v2's fix for the *non-generation-qualified* stale-K/K bug, which v3
  already closes differently. Places in one pass.
- **Option B — multi-pass / recirculation restructuring (preserve atomicity).** Move the
  generation-qualified cleanup (and/or the staged gate) onto a separate recirculation pass so the
  conflicting read/write orders no longer share a single straddled stage order. Keeps the atomic
  packed pop, but adds a recirculation hop with its own timing/behaviour implications (closer to §4
  territory) and must be re-validated.

## What v3 establishes / does NOT

**Establishes:** the staged RESPONSE-first design + all six v2 fixes are expressible (full metadata
init verified — warning gone), and — importantly — that the **fully-coupled single-pass R11 contract
does not place on Tofino-1**: the atomic-packed-pop and staged-admission requirements are provably
incompatible in one ingress pass (a register-ordering cycle), with Conflict 2 resolvable and
Conflict 1 forcing the Option A/B fork above.

**Does NOT establish:** a placing artifact (v3 fails placement as-is), nor any silicon behaviour.
**R11 remains OPEN. Complete Defense 4 remains NOT DEMONSTRATED.** Next step is Philip's Option A/B
decision, then implement + evidence the chosen resolution, still at §3. No §4/Gate 3/size/TM/
switch/hardware is authorized.
