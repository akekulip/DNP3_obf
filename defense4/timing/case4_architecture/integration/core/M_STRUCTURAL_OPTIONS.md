# M structural options: closing the four-register wall

Status: design note, read-only research. No code, test, compile or hardware action taken for this
note. Author role: read-only analysis per the binding task (defensive research P4 work; no
hardware load, no traffic). Authorization context: `defense4/CLAUDE.md` "Current Case 4 scope
(2026-10-06)" (offline code, tests, isolated model work and compiler evidence are authorized).

Markers: **[V]** read directly from a file or evidence log this session, cited by path and line.
**[I]** inferred by this note's author from [V] facts, not itself re-run or compiled. Nothing in
this note was compiled, tested or run; all stage counts and byte counts are quoted from retained
evidence, not fresh measurements.

## 0. What was read

`LEDGER.md` lines 470-678 (the four 2026-10-07 M stage-fit entries: diagnosis 13->9, hoist 9->8,
reservation merge 8->10, fourth-register-wall verdict) [V]. `HANDOVER.md` lines 72-155 (installed-SDK
transport checkpoint and both continuation entries) [V]. `integration/core/STEP3_DESIGN.md` in full
[V]. `integration/evidence/model_28/RESULT.md` and `PORTS_PROPOSAL.md` in full [V]. The current real
M source `integration/core/ordinary/transport.py` (52,026 bytes, working tree, **uncommitted** diff
of +37 lines against HEAD `bfc1877c6` — confirmed by `git diff --stat`/`git show HEAD:...`), its
base skeleton `m.p4`, and `work_record.p4`. `integration/read/read_timing.p4` lines 1-40 and the
`expected_work_record.p4` family (`ownership/p4/expected_work_record.p4`, sha256
`26b2019e…71ef2`, identical across every T evidence copy checked). `integration/core/ordinary/tests/
test_transport_reverse.py` and `test_m_activate.py`. `integration/evidence/model_23/RESULT.md`.
`integration/core/ordinary/README.md`.

**Provenance of the M source cited below.** `transport.py`'s working tree already contains (uncommitted,
+37 lines, `m.p4` untouched) the LEDGER round-4 entry's "genuine small win... not yet ported to the
real generator" (line-440.654-665 area): the `output_newhead`/`output_newbody`/`output_newtail`/
`crc_render` decoupling from `construct_t`'s just-written fields to the original parsed copies. This
was present in the working tree before this task started; this note did not make it. Regenerating
`transport.py`'s `generate_roles()['m3.p4']` in this session (`python3 -c "import transport;
transport.generate_roles()"`, saved to the session scratchpad, not the repo) reproduces this and
**differs from the committed `transport_candidate_next18/m3.p4` (sha `fccac901…905a4`) only in those
four action bodies — identical line count (263 lines), identical table/register declarations and
identical `apply{}` control flow.** All line numbers below are therefore valid against both the
on-disk `transport_candidate_next18/m3.p4` and the current uncommitted generator output; LEDGER's own
m19 entry independently measured that this decoupling leaves critical path at 10 (`evidence/
stage_fit_m19_01`, LEDGER.md:656-665) — i.e. it does not change the fit verdict below.

## 1. The four registers, their real reader/writer tables, and current stage windows

All tables and actions named below are quoted from `transport.py`'s generated `m3.p4` (`m.p4` for
the register declarations, which `transport.py` does not rename) at the line numbers above, read
this session. "Early" / "late" describe position in the single `apply{}` block of `control
Ingress` (`m3.p4:213-255`, reproduced at the end of this section), not a physical stage number —
the physical stage is what the compiler could not resolve.

| Register | Declaration | Early reader (role) | Late writer (role, gate) | Current apply-order position |
|---|---|---|---|---|
| `Ingress.reservation` | `Register<producer_cell_t,bit<1>>(1,{0,4}) reservation;` `m3.p4:74` | `mapping_reservation_t` (role 3‖4, action `mapping_reservation`→`read_map_reservation`, `m3.p4:175`), applied unconditionally right after `connection.apply()` (`m3.p4:217`) | (a) `activation_reservation_t` (role 1‖2, merged by the m18 fix into one table keyed `(m.role:exact, m.enabled:ternary, m.profile:ternary)`, `m3.p4:96`), applied at `m3.p4:222`, directly after role dispatch — **this touch point is RESOLVED**; (b) `reserve_t` (role 0, action `reserve_producer`→`reserve`, `m3.p4:84`), applied at `m3.p4:246`, gated behind `profile.apply()` + three CRC-hash tables (`input_head_t`/`input_body_t`/`input_tail_t`, `m3.p4:239-245`) — **this touch point is the unreached fourth wall** |
| `Ingress.producer_context` | `Register<context_t,bit<1>>(1,{0,0}) producer_context;` `m3.p4:86` | `qualify_context_t` (role 1‖2, action `qualify_context`→`context_check`, `m3.p4:90`), applied at `m3.p4:223`, immediately after (a) above | `construct_t` (role 0, action `construct`, which calls `context_write.execute(1w0)` as its first statement — `m.p4:128`), applied at `m3.p4:248`, inside the same role-0 branch as `reserve_t`, one `if(m.reservation_grant==32w1)` deeper | same unreached fourth wall, paired with `reservation`'s (b) |
| `Ingress.ledger_position` | `Register<bit<32>,bit<1>>(1,0) ledger_position;` `m3.p4:105` | `mapping_position_t` (role 3 action `mapping_position`, role 4 action `qualify_map_position`, keyed table `m3.p4:187`), applied at `m3.p4:219` inside the same role-3‖4 block as the `reservation` early read | `activate_position_t` (role 1 only, action `activate_position`→`write_position`, `m3.p4:108`), applied at `m3.p4:235`, gated behind `m.enabled&&m.profile` (`:230`) → `m.reservation_grant==1` (`:232`) → `m.context_grant==0`→`claim_once_t` (`:233-234`) → `m.activation_grant==1` (`:235`) | confirmed conflicting in m17 (LEDGER.md:540-541), not re-triggered as the *active* blocker in m18's placement log (LEDGER.md:601-604, "not established either way") |
| `Ingress.ledger_tag` | `Register<ledger_tag_t,bit<1>>(1,{0,0}) ledger_tag;` `m3.p4:113` | `mapping_tag_t` (role 4 only, action `mapping_tag`, `m3.p4:177`), applied at `m3.p4:218` only on the `else` side of `if(m.role==8w3)` inside the same early block | `activate_ledger_t` (role 1 only, action `activate_ledger`→`write_ledger`, keyed `(m.geometry_done, m.position_done)`, `m3.p4:116`), applied at `m3.p4:235`, same four-gate depth as `activate_position_t` above | **confirmed, active, reproducible wall** — the sole repeated "requiring more than one stage" conflict in every m18 retry log (LEDGER.md:596-600) |

`m3.p4:213-255` (current `apply{}`, read this session, reproduced in full because every cited line
above is inside it):

```
213  apply{
214  stamp_t.apply();context_owner_t.apply();ledger_generation_t.apply();if(m.role!=8w3&&m.role!=8w4){forwarding.apply();}
215  if(md.drop_ctl==3w0&&m.parsed==1w1&&!m.ip_error&&m.tcp_sum==16w0xFFEB&&hdr.ip.ttl!=8w0){
216   connection.apply();
217  if(m.role==8w3||m.role==8w4){mapping_reservation_t.apply();
218   if(m.role==8w3){mapping_raw_owner_t.apply();}else{mapping_context_t.apply();mapping_tag_t.apply();}
219   mapping_boundary_t.apply();mapping_position_t.apply();
220  }
221  if(m.role==8w1||m.role==8w2){reference_differences_t.apply();activation_identity_t.apply();}
222  if(m.role==8w1||m.role==8w2){activation_reservation_t.apply();}
223  if(m.role==8w1||m.role==8w2){qualify_context_t.apply();}
224  if(m.role==8w3){
225   capture_mapping_owner_t.apply();emit_mapping_snapshot_t.apply();
226  }else if(m.role==8w4){
227   prepare_packet_edges_t.apply();prepare_edges_t.apply();prepare_right_offset_t.apply();inverse_left.apply();inverse_right.apply();finish_window_t.apply();check_geometry_t.apply();
228   check_mapping_snapshot_t.apply();map_return_t.apply();
229   if(m.reverse_changed==1w1){map_ack_low_t.apply();emit_normalized_t.apply();}
230  }else  if(m.role==8w1||m.role==8w2){
231    if(m.enabled==1w1&&m.profile==1w1){
232     if(m.role==8w2){terminal_result_t.apply();}else if(m.reservation_grant==32w1){
233      if(m.context_grant==32w0){
234       claim_once_t.apply();
235       if(m.activation_grant==32w1){activate_geometry_t.apply();activate_position_t.apply();activate_ledger_t.apply();dirty_return_t.apply();}else{deny();}
236      }else{deny();}
237     }else{deny();}
238    }else{deny();}
239   }else{profile.apply();
240   if(m.enabled==1w1&&m.profile==1w1){
241    input_head_t.apply();input_body_t.apply();input_tail_t.apply();
242    if(hdr.dl.crc!=(m.hcrc[7:0]++m.hcrc[15:8])){m.badh=1w1;}
243    if(hdr.native.crc!=(m.bcrc[7:0]++m.bcrc[15:8])){m.badb=1w1;}
244    if(hdr.tail.crc!=(m.tcrc[7:0]++m.tcrc[15:8])){m.badt=1w1;}
245    if(m.badh==1w0&&m.badb==1w0&&m.badt==1w0&&hdr.native.index!=hdr.captured.index){
246     reserve_t.apply();
247     if(m.reservation_grant==32w1){
248      construct_t.apply();output_newhead_t.apply();output_newbody_t.apply();output_newtail_t.apply();crc_render_t.apply();
249     }else{deny();}
250    }else{deny();}
251   }else{deny();}
252   }
253   }else{deny();}
254   }
255  }
```

**The real shape of the wall, stated precisely.** It is not a stage-budget shortage (M is 8-10 of
12 stages used, LEDGER.md:589-590,605-608 [V]). It is an ordering contradiction: for each register,
the early reader's surrounding chain (role 3‖4's own subsequent translation tables, `m3.p4:224-229`,
about 7-9 tables) forces the merged register table toward a *low* stage number, while the late
writer's surrounding chain (role 1's own preceding admission tables, `m3.p4:221-234`, about 5-6
RegisterAction-gated tables) forces it toward a *high* stage number — and because one register's
SALU is one physical unit, every table that invokes a `RegisterAction` on it must share **one**
stage number for **every** caller, in every branch, regardless of which branch a given packet
takes. m16-m18's repeated merge/regress cycle (13→9→8→10, LEDGER.md:470-678) is the direct evidence
that *shrinking stage count* does not touch this: the broader m18 variant that hoisted the mutating
steps earlier *increased* critical path to 14 and introduced a *new* conflict (`construct_t`,
LEDGER.md:609-624) instead of resolving one, because moving a mutation ahead of its own validation
is exactly what the task's gating-preservation constraint forbids.

## 2. Three options against the five criteria

### (a) A second M ingress pass via recirculation

**Mechanism.** Split each of the two problem chains at its natural validation/commit seam, and
carry the *result* of validation — not the inputs — across a recirculation hop so the commit step
starts "early" in its own pass, the same way the early readers already are in theirs:
- Role 0 (`m3.p4:239-249`): pass 0 does `profile.apply()`→CRC checks→`reserve_t.apply()` only, then
  recirculates to one of M's own local ports (pipe 1 local 68-71 all recirculate to the same pipe's
  ingress — model-verified for every pipe, `model_28/PORTS_PROPOSAL.md:10-11` [V]; local 68 and 69 of
  pipe 1 are already spoken for by the N→M (E1) and T→M (E4) hops in `PORTS_PROPOSAL.md:30-31`, so
  this needs local 70 or 71, both confirmed to recirculate). Pass 1 starts with `reservation_grant`
  already resolved (re-derivable at stage 0-1 by rereading `reservation`'s own generation/phase, not
  by trusting a carried bit — see the forgery risk in criterion 4) and runs `construct_t` immediately.
- Role 1 (`m3.p4:221-235`): pass 0 does `reference_differences_t`→`activation_identity_t`→
  `activation_reservation_t`→`qualify_context_t`→`claim_once_t` only, recirculates. Pass 1 starts
  with `activation_grant` resolvable early and runs `activate_geometry_t`/`activate_position_t`/
  `activate_ledger_t`/`dirty_return_t` immediately — now at the same early stage depth as
  `mapping_tag_t`/`mapping_position_t`/`mapping_reservation_t`'s role-3‖4 placement, because both
  sides of each register now have a *short* preceding chain *in their own pass*.
- M already has the scaffolding this needs: `forwarding` (`m3.p4:70`, keyed on `ig.ingress_port`) is
  an existing ingress-port-routing table; adding one more route (recirculate to the new local port on
  the pass-0 exit) is an extension of an existing pattern, not a new one.

1. **Closes all four walls, not just moves them: yes, by construction**, for both pairs
   (`reservation`×`reserve_t`, `producer_context`×`construct_t`, `ledger_position`×`activate_position_t`,
   `ledger_tag`×`activate_ledger_t`) — each pair's late side becomes early-in-its-own-pass. [I] This
   is not re-derived here by compiling; it follows from the stage-placement logic the compiler itself
   reported (LEDGER.md's repeated "requiring more than one stage" lines name exactly a reader/writer
   depth mismatch, never a register-count or table-count ceiling).
2. **Cost.** One additional M-internal pass, but only for SELECT/OPERATE-class (role 0) and
   activation-class (role 1) events — the high-frequency per-packet case (role 3‖4 mapping, every
   ordinary ACK/window translation) is untouched, single-pass. Using `model_23/RESULT.md:49` [V]
   ("Recirculated bytes per 4-pass exchange = 3 x (frame + 16-byte private prefix + 4 FCS): SELECT 3
   x 109 = 327 bytes") as the basis: one extra M-internal lap costs on the order of one more
   frame-sized trip through M's own recirculation port per SELECT/OPERATE event — call it ~100 bytes,
   by analogy to the measured N frame sizes, not a fresh M measurement [I]. STEP3_DESIGN.md:214-220
   already concludes internal amplification is "at most about 6 times" and "not binding at the
   declared workload" for N's four passes; one more M pass at the same per-event rate (once per
   SELECT, once per OPERATE, not per packet) is a small addition to that, not a new order of
   magnitude. **Latency is unmeasured and this note does not estimate it** — no pass or
   cross-recirculation timing exists anywhere in this repository (`model_23` explicitly: "the
   model's clock is not wall time", STEP3_DESIGN.md:219 "Latency per pass... is unmeasured anywhere
   in the repository; no rate or latency claim follows from these counts").
3. **What changes vs. survives.** Role 3‖4 (`mapping_*`, `capture_mapping_owner_t`,
   `emit_mapping_snapshot_t`, `prepare_packet_edges_t`…`emit_normalized_t`) is untouched — so is
   `ReverseTransport` in `tests/test_transport_reverse.py` (the paired-coordinate reread tests).
   Role 0 and role 1's control flow changes (new pass-boundary branch, one new M-local recirculation
   route); their RegisterAction bodies do not need to change. `tests/test_m_activate.py`'s
   `MActivation` class (3 tests) needs rewriting to model two passes. A new test module is needed for
   the pass-boundary forgery case (criterion 4). `work_record.p4`'s pin discipline
   (STEP3_DESIGN.md section 7, "held pin") needs to be understood to extend across M's own internal
   boundary, not just N's claim-to-confirm span — this is additional but not new invention (see
   criterion 5).
4. **Invariant risk.** Role-3‖4-never-mutates: **unaffected** — role 3‖4 is not touched by this
   change. Paired-coordinate forgery/reread: **a new, real risk that must be designed against, not
   automatic.** Splitting role 0/1 into two passes creates exactly the shape of attack the existing
   `ReverseTransport` tests already defend against on the *other* side (role 3‖4): a forged or
   replayed pass-1 packet that skips pass 0 and asserts `activation_grant=1`/`reservation_grant=1`
   directly. The mitigation is not new invention — it is the same discipline T already uses
   (`read_timing.p4:8-14` [V]: "a writer with a higher cookie lazily re-arms the cell, an equal
   cookie accumulates, a lower (stale) cookie is ignored. No cell is ever cleared") and the same
   discipline M's own role-3‖4 path already implements (`test_transport_reverse.py:109-125`,
   `test_snapshot_foreign_full_refs_or_concurrent_publication_refuse_readonly`: reject unless a full
   reread of generation/owner/phase matches). Concretely: pass 1 must **reread** `reservation` /
   `producer_context`'s generation+phase (or epoch+owner) fields itself and compare against the
   recirculated copy, never trust the carried grant bit alone. This is a design obligation this note
   is flagging, not a solved problem.
5. **Size.** Not a day's work, not a rewrite. Most of the ~25 existing tables are untouched; the
   change is confined to role 0's and role 1's control flow, one new M-local recirculation route
   reusing the existing `forwarding` table pattern, and the reread discipline above. Estimate:
   several days including the new pass-boundary forgery tests, closer to the size of the m16-m18
   sequence already completed this session than to a new subsystem. [I]

### (b) Move the four registers to M's egress (M has 0 of 12 egress stages used today)

A register declared in `control Ingress` and one declared in `control Egress` are **physically
separate** TNA program objects — a register cannot be read on one side and written on the other.
So this option is not "move the registers" in isolation; it requires moving **both** the early
reader and the late writer of **each** register into egress, which in turn means moving role 3‖4's
entire mapping chain and role 0/1's entire admission chain into egress together (they cannot be
split across the ingress/egress boundary without duplicating the register).

1. **Does it close the walls?** [I] **No, not by itself.** The conflict identified in section 1 is
   an ordering contradiction (short-preceding-chain caller needs an early stage, long-preceding-chain
   caller needs a late stage, one shared SALU must serve both), not a capacity shortage — M already
   fits in 8-10 of 12 ingress stages (LEDGER.md:589-590). Relocating the identical table graph
   wholesale into a fresh, otherwise-empty 12-stage egress budget does not change role 1's intrinsic
   preceding-chain depth (`reference_differences_t`→`activation_identity_t`→
   `activation_reservation_t`→`qualify_context_t`→`claim_once_t`, five sequential RegisterAction-gated
   steps before `activate_ledger_t`, `m3.p4:221-235`) relative to role 3‖4's intrinsic
   preceding-chain depth (`connection.apply()` only, `m3.p4:216-217`) — the same two numbers that
   don't overlap in a 12-stage ingress budget don't overlap in a 12-stage egress budget either.
   HANDOVER's own flagged egress fallback (moving only the *stateless* `construct_t`/`output_new*`/
   `crc_render_t` remainder to egress) was separately evaluated in LEDGER.md:662-665 and found "NOT
   sufficient alone: it frees ingress stages but does not touch any of the four register-mutation
   sites" — the same conclusion generalizes to moving the stateful tables too, because egress has the
   identical one-SALU-one-stage constraint as ingress (evidenced by E's own per-pipe-egress 7-10 stage
   figures in `HANDOVER.md:24-34`, which is a budget of the same kind, not a different kind).
2. **Cost if attempted anyway.** Would require duplicating or bridging every ingress field role 0/1/3/4
   currently read directly from the packet header (`hdr.tcp.seq`, `hdr.reference.*`, `hdr.cache.*`) as
   bridged metadata, since egress only sees what ingress explicitly bridges forward — a nontrivial
   rewrite of the parser/metadata boundary for no structural gain per point 1. [I]
3. **What changes vs. survives.** Nearly everything: all of role 0, 1, 3, 4's logic moves to a
   different control (`Egress` instead of `Ingress`), which is a different program object with a
   different test harness surface — the Python model interpreters used by `test_transport_reverse.py`
   and `test_m_activate.py` model ingress-only behavior today and would need to be rebuilt for egress
   semantics. High disruption for, per point 1, no resolved conflict.
4. **Invariant risk.** High and undifferentiated — moving the whole mapper changes the physical
   location of every invariant-bearing table, so every existing test needs re-deriving against the new
   location before it can be trusted again, regardless of whether the underlying logic changed.
5. **Size.** Larger than (a) for a worse expected outcome — not recommended.

### (c) A ground-up M redesign built around the four-register constraint from the start

1. **Does it close the walls?** [I] Only if it adopts the same mechanism as (a) — multi-pass
   recirculation with an early-committed grant carried across the boundary — because, per section 1's
   analysis, *any* single-pass design that (i) validates role 1's grant through a sequential
   RegisterAction chain and (ii) shares registers with role 3‖4's single-step early reads will
   reproduce the identical ordering contradiction. A from-scratch design that does not use recirculation
   has no mechanism available to it that (a) does not already have. So (c) either converges to (a)'s
   mechanism under a new source tree, or it does not close the walls either.
2. **Cost.** Unknown without a new design pass, but necessarily larger than (a): a full redesign
   discards the 20+ already-compiled, already-tested tables for role 2, role 3, role 4 and most of role
   0/1's individual actions, none of which are implicated in the four-register conflict.
3. **What changes vs. survives.** By definition, little survives unmodified; the entire 71/71
   `ordinary`, 33/33 `core/m`, and 84/84 `connection/binding` (`LEDGER.md:520-524`) regression
   baselines would need re-deriving against new source, not just re-running.
4. **Invariant risk.** Equivalent to (b) — nothing is preserved to anchor the paired-coordinate
   reread and role-3‖4-never-mutates invariants until the whole suite is rebuilt from zero.
5. **Size.** A rewrite, not a day's work — strictly larger than (a) for, per point 1, no better
   expected outcome (it converges to the same mechanism or fails the same way).

### Reuse check: N's and T's existing patterns

**N's `ExpectedWorkRecord`** (`integration/core/ordinary/work_record.p4`, and its evolved twin
`ownership/p4/expected_work_record.p4` used by T, sha256 `26b2019e…71ef2`, identical across every T
evidence copy checked this session) is **already the general mechanism option (a) needs**: one
register, one `dispatch` table, keyed on `(operation:exact, generation:ternary, expected_phase:ternary)`,
where different operations (claim / return / read / **downstream**, a hand-off that advances phase by
+2 instead of +1) are selected by match key rather than by control-flow depth. Crucially, T's variant
already generalizes this to a cross-role hand-off: "operation3 uniquely hands SELECT to downstream
processing: 3->5 pending, 5->7 ready-received/pinned, 7->9 terminal/free" (diff of
`expected_work_record.p4` against `work_record.p4`, read this session). This directly demonstrates
the pattern (a) proposes — a register whose own table design spans multiple passes/hand-offs by
keying on a cheap, already-known field, not by threading a long validation chain through one pass —
already works in this codebase for a different register. **T's cookie-tagged cells**
(`read_timing.p4:8-14`: "a writer with a higher cookie lazily re-arms the cell, an equal cookie
accumulates, a lower cookie is ignored") is the exact reread/re-arm discipline this note's criterion-4
risk calls for: M's pass-1 side should re-arm/compare by generation, not trust a bare carried grant
bit. **Recommendation: adapt `ExpectedWorkRecord`'s dispatch-table pattern for `reservation` and
`producer_context`'s pass-0/pass-1 split, and T's cookie-compare discipline for the reread at pass 1's
entry, rather than inventing new RegisterAction logic for M.**

## 3. Recommendation

**Option (a), a second M ingress pass via recirculation, applied separately to role 0's
validate-then-claim chain and role 1's qualify-then-activate chain, reusing N's `ExpectedWorkRecord`
dispatch-table pattern and T's cookie-tag reread discipline rather than new mechanism.**

Reasoning, in order of weight: (1) section 1 established the wall is an ordering contradiction, not
a stage-count shortage; only a mechanism that lets the "long chain" complete *before* the register
table is reached in the pass that needs it "early" can resolve that, and recirculation is the only
such mechanism available in TNA (egress does not have a second ingress-style traversal to split
across, and a redesign without recirculation faces the identical contradiction). (2) The codebase
already has every piece this needs, proven working on *other* registers: N's claim/return pattern
already splits a register's lifecycle across passes (`work_record.p4`); T's own request handling
already does multi-pass pin/commit ("A request runs four pinned passes: P0 claim, P1 debt peek, P2
mint cookie..., P3 install the response receipt, commit the association", `read_timing.p4:16-19`
[V]); M's own role 3‖4 already implements the reread-before-trust discipline the pass-1 boundary
needs (`test_transport_reverse.py`). (3) It is the only option of the three that does not discard
already-compiled, already-tested work: role 2/3/4 and most of role 0/1's individual actions are
untouched. (b) and (c) either fail to resolve the wall (b, argued in section 2) or converge to (a)'s
own mechanism while discarding more (c).

## 4. Ordered TDD tickets (red first; granularity matches `STEP3_DESIGN.md` section 9)

| # | Ticket | Files | Red test first | Acceptance |
|---|---|---|---|---|
| M-R1 | M-local recirculation route (extend `forwarding`) | `integration/core/ordinary/m.p4` (`forwarding` table, `m3.p4:70`), `integration/core/ordinary/transport.py` | a packet arriving on the new local recirc port (70 or 71, per `model_28/PORTS_PROPOSAL.md`) is dropped by `forwarding`'s current `deny()` default | `forwarding` routes M's own recirc-port traffic back into the M ingress dispatch; existing routes for 68/69 (E1/E4) unaffected; 71/71 `ordinary` suite still green |
| M-R2 | Role-0 pass split: `reserve_t` moves to pass 0 exit, `construct_t`+output chain moves to pass 1 entry | `transport.py` (new pass-marker field reuse of `hdr.reference.format`'s spare bits or a new 1-byte field), `tests/test_m_prepare.py` (new) | a single-pass role-0 packet with `m.reservation_grant==1` currently reaches `construct_t` in the same pass (no test exists asserting it must NOT); add one asserting the NEW two-pass behavior, which fails against the current one-pass source | pass 0 ends after `reserve_t`, recirculates with `reservation_grant` carried; pass 1 starts, **rereads** `reservation`'s generation/phase (not just the carried bit) before calling `construct_t`; stale/forged pass-1 entry (wrong generation) is refused and counted |
| M-R3 | Role-0 pass-skip forgery test (criterion 4) | `tests/test_m_prepare_forgery.py` (new) | inject a pass-1-shaped packet (recirc-port ingress, `activation`/`reservation` grant bits set) with NO prior pass-0 visit | refused; `reservation`/`producer_context` unchanged; counted, not silently dropped |
| M-R4 | Role-1 pass split: `claim_once_t` output ends pass 0, `activate_geometry_t`/`activate_position_t`/`activate_ledger_t`/`dirty_return_t` move to pass 1 entry | `transport.py`, `tests/test_m_activate.py` (rewrite the 3 existing `MActivation` tests for two passes) | the 3 existing `MActivation` tests currently assert single-pass behavior; update to assert the pass boundary and rerun — must fail against the unmodified source first | pass 0 ends after `claim_once_t` with `activation_grant` resolved; pass 1 rereads `ledger_position`/`ledger_tag`'s own generation/epoch before writing; `activate_geometry_t`/`activate_position_t`/`activate_ledger_t`/`dirty_return_t` unchanged internally |
| M-R5 | Role-1 pass-skip forgery test, mirroring M-R3 | `tests/test_m_activate_forgery.py` (new) | inject a pass-1-shaped activation packet with no prior pass-0 visit | refused; `ledger_position`/`ledger_tag`/`activation_receipt` unchanged; counted |
| M-R6 | `ExpectedWorkRecord`-pattern adoption for the pass boundary (replace ad hoc carried bits with a keyed dispatch table, per section 2's reuse check) | `integration/core/ordinary/work_record.p4` or a new `m_pin.p4` adapting `ownership/p4/expected_work_record.p4`'s `downstream` operation | the carried-bit approach of M-R2/M-R4 has no single owning table; a test asserting "exactly one table governs the pass-0-to-pass-1 hand-off for `reservation`" fails against the ad hoc version | the hand-off for `reservation` and `producer_context` is one dispatch table keyed on `(operation, generation, phase)`, mirroring `work_record.p4`'s `dispatch` table; existing M-R2/M-R3/M-R4/M-R5 tests still pass |
| M-R7 | Stage-fit canary compile of the split M (resource canary only, no new logic) | new evidence dir `evidence/stage_fit_m21_01` | none (canary) | critical path and PHV recorded for the two-pass structure; per this note's section 2 criterion 1, expect no "requiring more than one stage" conflict on any of the four registers — if one still appears, the devil's-advocate test in section 5 has caught a wrong assumption and the design must be revisited before further coding |
| M-R8 | Full regression rerun across the same 7 suites LEDGER.md's m17/m18 entries ran | existing suites, no new files | none | `ordinary` 71/71, root `tests` 33/33, `connection/binding` 84/84, `controller` 17/17, `core/harness` 42/42, `core/m` 33/33, `read` 103/103 — all still pass with the new pass-boundary logic in place |

Dependency order: M-R1 first (shared scaffolding), then M-R2/M-R3 and M-R4/M-R5 in parallel
(independent chains), then M-R6, then M-R7 (canary compile — gate before any further work, per
STEP3_DESIGN.md's own devil's-advocate discipline for its S3-3 canary), then M-R8.

## 5. Devil's advocate: two ways this recommendation could be wrong

1. **The compiler may not actually place the merged dispatch table (M-R6) at a stage both pass-0
   and pass-1 callers can share, even though each individual pass's preceding chain is now short.**
   This note's argument in section 1 is a plausibility argument from the observed compiler behavior
   (LEDGER's repeated "requiring more than one stage" lines describe a depth mismatch), not a
   re-derivation from the Tofino compiler's actual placement algorithm, which this note did not run.
   It is possible the compiler's dependency graph treats a recirculated field's availability
   differently from a freshly-parsed one (e.g., if the pass-marker and carried grant live in a header
   that is reparsed late rather than available at parser-exit), which would reproduce the same "late"
   depth this option is meant to avoid. **Catching test: M-R7's canary compile, before M-R2-M-R6 are
   fully built out** — exactly as STEP3_DESIGN.md requires for its own S3-3 M canary (LEDGER's own
   devil's-advocate #2, STEP3_DESIGN.md:469-473). A fail there means the carried-field placement
   needs to move earlier in the parser, not that the whole approach is wrong.
2. **The pass-skip forgery mitigation (M-R3, M-R5: reread generation/phase at pass-1 entry) may not
   be sufficient if an attacker can replay a stale pass-0 output whose generation still matches**
   (e.g., a captured-and-replayed pass-0-exit packet before the real pass-1 recirculation arrives,
   or two recirculating copies racing). T's cookie re-arm discipline handles a *stale* cookie by
   ignoring it, but does not by itself handle a *duplicate, same-generation* pass-0 output arriving
   twice (T's "no cell is ever cleared" is a different property: idempotent re-arming, not exactly-once
   consumption). If `reservation`'s phase transition (1→4, "claimed"→"free", per `work_record.p4`) is
   not also checked for single-use at the pass boundary, a duplicated recirculation could cause
   `construct_t`/`activate_ledger_t` to run twice for one claim. **Catching test:** extend M-R3/M-R5
   with a duplicate-recirculation case (inject the SAME pass-0-exit packet twice before any pass-1
   confirm) and assert the second copy is refused or no-ops, not that it silently re-executes
   `construct_t`/`activate_geometry_t`/`activate_position_t`/`activate_ledger_t`. This mirrors the
   existing residual-hazard language STEP3_DESIGN.md already states plainly for N's own held pin
   (section 7, "Residual hazards": "A lost mirror clone or lost M or E packet leaves the pin at phase
   3 forever... The recovery is a controller-side reset... which does not exist yet") — this note is
   not claiming a stronger guarantee for M's internal pin than STEP3_DESIGN.md claims for N's.
