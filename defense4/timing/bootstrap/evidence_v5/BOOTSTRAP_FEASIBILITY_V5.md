# Defense 4 §3 — reservoir bootstrap v5 (shim + atomic overlap guard): evidence + verdict

**Verdict: v5 PLACES in a single 11/12-stage Tofino-1 ingress pass, closes the held-RESP
generation-association residual, and its atomic packed `{active, generation}` guard ASSEMBLES on
bf-p4c 9.13.1 — the "strongest construction" is real. R11 STAYS OPEN, and v5 additionally EXPOSED a
load-bearing §4 dependency: a genuinely-HELD RESP can retire only at the §4 deadline release, so
§3-in-isolation wedges FAIL-CLOSED after the first hold.** v5 supersedes v4 (`9effc43`); v1–v4 are
retained as the prior probes. Still a §3 feasibility probe: NOT the timing core, does NOT patch
`defense4_timing.p4`, NOT loaded, NOT run.

## Verified compile facts (independently recompiled)

| item | value |
|---|---|
| source | `defense4/timing/bootstrap/bootstrap_probe_v5.p4` |
| source sha256 | `7724ca70771debd1ba8514aa85e36a5c1bd4cd934d36842bff0cb01114b7d5c1` (reviewed `5d51deba` + a port-qualifier fix + the honest disclosure below; recompiled clean) |
| one-time setup | `bootstrap_setup.py` — now also READS BACK and ASSERTS the ladder 7>6>5>4 + shaping disabled; refuses to run without `DEFENSE4_HW_AUTHORIZED=1` |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline) |
| **ingress stages** | **11 / 12** (−1 vs v4) |
| egress stages | 0 |
| critical path | 5 |
| **stateful (meter) ALUs** | **6** (`reg_txn`, `reg_ident_resp`, `reg_resp_stage`, `reg_ident_ack`, `reg_pop_packed`, `reg_failopen`) — down from v4's 8; `reg_gen`+`reg_active` merged into `reg_txn`, `reg_resp_gen` deleted |
| binary | `tofino.bin` produced |
| compile result | **0 errors, 2 warnings** (benign parser-unroll; no `uninitialized_out_param`) |

Register chain: `reg_txn@0 · reg_ident_resp@3 · reg_resp_stage@4 · reg_ident_ack@5 · reg_pop_packed@7
· reg_failopen@9 · tbl_native_decide@10`. `reg_txn` at stage 0 (single depth) is the structural win.
Note: 11, not the 10 *target* — the atomic guard requires `{active,generation}` in the EARLY word,
which is mutually exclusive on Tofino with the late `active`+`pop` co-location that would reach 10
(a Register is one physical stage). B (the explicit strongest construction) was implemented.

## What v5 adds / fixes

**Loopback-generation shim (removes `reg_resp_gen`) — CLOSES the v4 residual.** A held/forwarded
RESPONSE is stamped with a shim header (`shim_h`, etype `0x88C3`, `gen = cur_gen|CONF`) before
looping on `PORT_L`; `from_loop` distinguishes shim (`0x88C3`) / token (`0x88C1`) / held-ACK
(`0x0800`) by the first ethertype; completion is generation-qualified atomically inside `reg_txn`
(`v == shim.gen`); the shim is stripped before the master hop, so the RESP is **byte-identical**.
Each held RESP now carries its OWN generation — robust for overlapping transactions, which the
single `reg_resp_gen` register could not do.

**Atomic packed `{active, generation}` READ-admission guard (`reg_txn`) — ASSEMBLES, no fallback.**
`reg_gen`+`reg_active` merge into one early word (bit31=active, [30:0]=generation). The in-SALU
active test — which the bf-asm masked/slice-compare defect blocks in the obvious form — was PROBED
and works as an **unsigned magnitude compare** `if (v < 0x80000000)`, with the open a single
`v + 0x80000001` (generation++ AND set-active in one add; wrap `GEN_MAX → 0x80000001`), and the
generation-qualified retire a full-word compare. An OVERLAPPING READ (arriving while active) is a
genuine NO-OP: `txn_open` returns the pre-open word and the READ-path resets are gated on that
pre-open active bit, so generation, counts, identities, shadow, and fail-open are all left
unchanged. Verified correct for every input class (adversarial review).

**Retirement lifecycle + inactive behavior.** Retire = clearing `reg_txn`'s active bit
(generation preserved), generation-qualified, on a RESP's authenticated loopback completion (or
FIN/RST). A FORWARDED (fail-open/bypass) RESP is routed onto the shim'd loopback on **qid7**
(highest, so it loops promptly and cannot starve), retires there, and reaches the master
byte-identical. While `active==0`, loopback tokens and pktgen seeds are DROPPED (no re-enqueue, no
re-seed), so the **≤2K resident blockers drain within one loop period** (bounded). Stale-generation
tokens are dropped before any cell/pop access. **Fix:** `ROLE_ARM` is now port-qualified
(`from_out==0`) so a relay-side READ cannot spuriously open a transaction.

## ►► The load-bearing finding — retire is §4-deadline-dependent (adversarially reviewed)

A genuinely-HELD RESP is enqueued to **qid4 (LOWEST strict priority)**. The reservoir is sized
(`K=64`, Little's law) precisely to keep `qid7`/`qid5` **continuously queue-resident** — the whole
mechanism of a blocker reservoir. By strict priority, `qid4` therefore **starves**: the held RESP
dequeues (and thus loops → completes → retires) ONLY when the **§4 deadline** drains the reservoir.
The retire is correctly WIRED to that release (the held packet is already queued with its shim +
`PORT_L` egress). Consequences, disclosed:

- **§3-in-isolation (no deadline modeled) wedges FAIL-CLOSED after the first hold:** active stays
  set → the overlap guard no-ops every subsequent READ → later transactions re-hold on the starved
  qid4 → the master receives nothing. §3-in-isolation is correct only for a SINGLE transaction and
  for the fail-open paths. (This is worse than the missing-RESP case, which is fail-OPEN.)
- **HARD §4 REQUIREMENT:** the deadline release must fire, and **deadline < poll interval** (the
  held RESP must retire before the next READ). If violated (or on a READ retransmit mid-transaction),
  the overlap guard degrades to a fail-closed held pileup. A §4 **bounded-transaction watchdog** is
  also needed to clear a stranded active on a never-answered poll (missing-RESP: fail-open; a ready
  next txn re-enters the qid4 wedge).
- **v4 masked this** with its unconditional re-open (reset every transaction on every READ, at the
  cost of clobbering an in-flight transaction — exactly what v5's guard correctly fixes). So v5's
  guard is a genuine correctness improvement that EXPOSED a latent §4 dependency v4 hid.

## Toolchain findings (SDE 9.13.1), recorded
- The obvious in-SALU active test (`(v & 0x80000000)==0` / `v[31:31]==0`) does not assemble
  (masked/slice stateful compare defect); the magnitude form `v < 0x80000000` does.
- A parser-side `hdr.shim.gen | CONF_BIT` ICEs bf-p4c 9.13.1 (worked around by stamping the shim with
  the CONFIRMED form at admission); deriving `cur_gen = txn_old & GEN_MASK` in the MAU ICEs (the
  slice `txn_old[30:0]` is fine).

## Disclosed residuals (scoped, NOT claimed closed)
1. **Held-RESP retire is §4-deadline-dependent** (above) — the primary reason R11 stays OPEN, and a
   hard §4 requirement (deadline < poll interval) + a bounded-transaction watchdog.
2. **Missing RESPONSE** strands active (fail-open; self-heals only if the next RESP takes the qid7
   retire path).
3. **Forwarded-RESP qid7 detour** adds one loop-RTT of latency before the master hop.
4. **K ≤ 64** hard-coded by `token_id[5:0]`; host classification is the compact subset.
5. All silicon behaviour (continuity, establishment latency, ordering, actual release) UNVERIFIED.

## What v5 establishes / does NOT
**Establishes (offline):** the shim closes the held-RESP generation-association residual; the atomic
packed `{active, generation}` guard (the strongest construction) ASSEMBLES and yields a genuine
side-effect-free overlap no-op; the contract still places, now in 11/12 stages with 6 registers; the
setup reads back and asserts the ladder. It also produced a real design finding: the retire lifecycle
is correctly coupled to — and REQUIRES — the §4 deadline release (deadline < poll interval).

**Does NOT establish:** any silicon behaviour, nor that the bootstrap runs end-to-end without §4 (a
held RESP cannot retire in §3-isolation → fail-closed wedge). **R11 remains OPEN. Complete Defense 4
remains NOT DEMONSTRATED.** §3 STOPS here. No §4/Gate 3/size/TM/switch/hardware.
