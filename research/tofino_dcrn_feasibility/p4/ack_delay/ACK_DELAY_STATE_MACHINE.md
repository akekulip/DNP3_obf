# ACK-Delay P4 State Machine — Case A / Case B on Tofino-1

Section-27 items 4 (P4 state machine), 5 (minimum Case-A changes), 6 (hardware unknowns) +
Section-25 `ACK_DELAY_STATE_MACHINE.md`. Design only — **no switch, no compile run in this stage.**
Grounded in `research/tofino_dcrn_feasibility/p4/dcrn.p4` and the p4-dataplane-engineer review.

## 0. The load-bearing asymmetry (resolves the build order)
- **Case A ACK release is EVENT-governed** — a per-pass poll of a `resp_seen` register. It needs **no
  refreshing wall-clock**, so it is **immune** to the unresolved "does `global_tstamp` refresh on
  recirc" bug that stalls every deadline hold. → Case A can be built and hardware-proven **before** the
  clock fix.
- **Case B response release is DEADLINE-governed** — needs a per-pass-refreshing time source. → Case B
  waits on the clock fix (§4 below).

Consequence: **build Case A first** (also Dr. Lin's mandate); fix the clock in parallel for Case B and
Case A's bounded-guard variant.

## 1. Per-flow register state (§9) — minimal, generation-protected
Keep separate `bit<8>` flag registers (Class 8: no single enumerated-state register; no in-SALU
`v==0` sentinel — controller cold-seeds). Per-flow index = canonical bidirectional hash (already in
`dcrn.p4`). One outstanding transaction per flow.

| Register | Width | Purpose |
|---|---|---|
| `reg_gen` | bit<8> | transaction generation — stale state from an old txn cannot match a later one |
| `reg_policy` | (compile-time constant, not a register — see §5) | A vs B is a build-time variant |
| `reg_armed` | bit<8> | flow armed on an eligible READ |
| `reg_req_tick` | bit<32> | request arrival tick (`ig_prsr_md.global_tstamp[47:16]`, a real port arrival — trustworthy) |
| `reg_ack_seen` | bit<8> | a pure ACK for this armed txn has been observed (mode = separate) |
| `reg_resp_seen` | bit<8> | the DNP3 response for this txn has entered the pipeline (Case A trigger) |
| `reg_ack_gone` | bit<8> | the held ACK has been directed to the master egress port (Case A ordering) |
| `reg_deadline` | bit<32> | Case B absolute deadline tick = `t_ack + G_i` (unused in Case A) |
| `reg_target_idx` | bit<32> | Case B: global-counter index into the preloaded target sequence |

Global (index 0): `reg_txn_counter` (global transaction counter → common target index, device-independent),
`reg_held_count` (recirc-occupancy watermark — gates ARMING new holds only, see §3 corner-fix).

## 2. States (§9) and transitions

```
IDLE
 └─ eligible Class-0 READ (dst:20000, established, 1-outstanding, FC=READ)
      → arm: reg_gen++, reg_req_tick=now, reg_armed=1 ; forward request unchanged → ARMED

ARMED_WAIT_ACK_OR_RESPONSE
 ├─ pure ACK (src:20000, payload==0, acks the armed req)
 │    CASE A → reg_ack_seen=1 ; recirculate the ACK on QID_HOLD → ACK_HELD_WAIT_RESPONSE
 │    CASE B → reg_ack_seen=1 ; forward ACK immediately ; reg_deadline = now + G_i ; → ACK_FWD_WAIT_RESP
 ├─ ACK-bearing response first (no pure ACK yet) → classify COMBINED → BYPASS (fail-open forward)
 └─ safety timeout / watermark / non-eligible → BYPASS

ACK_HELD_WAIT_RESPONSE   (Case A)
 ├─ each recirc pass: read reg_resp_seen
 │    resp_seen==0 → keep looping (QID_HOLD) [paced; guard is a few passes, NOT a matured deadline]
 │    resp_seen==1 → direct ACK to PORT_VISION ; reg_ack_gone=1 → COMPLETE(ack)
 └─ MAX_PASS reached → fail-open forward ACK ; count max_pass_fail_open (alarm) → BYPASS

RESPONSE handling (Case A), when the DNP3 response arrives for an armed+ack_seen flow:
 → reg_resp_seen=1 ; admit response to the hold loop (do NOT forward immediately)
 → each pass: read reg_ack_gone
       ack_gone==0 → keep looping
       ack_gone==1 → hold δ more paced passes → direct response to PORT_VISION (same FIFO queue) → COMPLETE

ACK_FWD_WAIT_RESP   (Case B)
 └─ DNP3 response arrives:
       now >= reg_deadline → release to PORT_VISION (deadline already matured / miss) → COMPLETE
       now <  reg_deadline → recirculate on QID_HOLD; release when bridge-timestamp tick >= reg_deadline
       MAX_PASS → fail-open (alarm) → BYPASS

COMPLETE → clear flow state (reg_armed=0, reg_resp_seen=0, reg_ack_gone=0, reg_gen bump on next arm)
BYPASS   → forward unchanged, increment bypass counter with reason
```

## 3. The Case-A ordering race — the zero-inversion invariant (the crux, §10/§21)
**Invariant:** a response frame is directed to the master port **only** on a pass where it reads
`reg_ack_gone == 1`; the ACK sets `reg_ack_gone := 1` on the same pass it is directed to that port.
Because **register writes are visible only to strictly-later passes**, the response's release pass is
strictly later than the ACK's release pass; on a **shared FIFO egress queue** (both pinned to
`PORT_VISION`) the ACK therefore dequeues first. Non-same-cycle visibility can only *delay* the
response's read of `ack_gone` (adds guard), never advance it → **cannot invert.**

Rests on two things we control and must assert on hardware:
1. **monotone register visibility** (write on pass N seen only on pass ≥ N+1), and
2. **ACK and response on the same `PORT_VISION` queue** (make this a HW-probe assertion, not an
   assumption — different queues break FIFO ordering and the guarantee collapses).

**Corner fix (p4-engineer):** the recirc-occupancy watermark gates **arming NEW holds**, not
**completing existing ones** — when a response arrives for an already-armed flow, admit it to the loop
even past the watermark; the response gets **no independent time-based fail-open** (its only non-gated
exit is first-arrival bypass, which preserves native ACK-first order). Otherwise a watermark-bypassed
response could overtake a still-held ACK.

**Multi-segment responses are the real failure risk (sdn + p4 agree):** only the first segment triggers
`resp_seen`; every later segment arriving while the ACK is still looping must also be parked and kept
in order behind the first segment and behind the ACK. A single-flag machine is insufficient for N
segments and unequal pass counts can invert them. For single-segment Class-0 reads (the initial scope,
and all three real devices today) this is fine; larger real responses are where "zero segment
inversion" (§21) will bite → gated to a later step with a controlled multi-segment size sweep.

## 4. The clock fix for Case B (deadline holds) — bridge back the EGRESS timestamp
Diagnosis of the current 38–100 ms (p4-engineer, arithmetic attribution): **two independent defects.**
(1) The loop is **unpaced** — at `HOLD_LOOP_PPS=10000` (100 µs/pass) `MAX_PASS=65536` would be **6.5 s**,
not 47 ms; the observed ~47 ms ⇒ bare ~0.7 µs/pass ⇒ the dp68 qid5 shaper is **not applied at all**
(prime suspect: wrong `pg_id`/`pg_queue` mapping, NOT "shaper can't pace a lone frame"). (2) A bare
loop would mature a real 33 ms deadline at ~46k passes < 65536 and release ~33 ms tight; we see *more
and variable* ⇒ **`ig_prsr_md.global_tstamp` is not advancing on recirc.**

**Fix:** the egress `global_tstamp` refreshes every pass. Add `tstamp_tick` to the recirc bridge
header, write `eg_prsr_md.global_tstamp[47:16]` in egress on DCRN frames only, and have the ingress
release compare read `hdr.bridge.tstamp_tick`. The **arm** stays anchored on the request's real
`ig_prsr_md` (a genuine port arrival). Q1-immune; costs ~1 pass of lag. **Fallback:** pass-count
self-clock (`pass_count >= Di / L_pass`) once the loop is *paced* (re-couples to the pacing fix).
`MAX_PASS` stays strictly between max-deadline (~42 ms) and the RTO cap (~150 ms) as **pure fail-open,
counted as an alarm.**

## 5. Stage budget & minimum Case-A changes (§27 item 5)
Un-compiled estimate (p4-engineer): **Case B 8–10 stages** (SMALLER than today — deletes the dual-case
FIFO); **Case A 10–12** (the fit-risk case: 3–4 new `bit<8>` flag SALUs + a 4-way recirc/first-arrival ×
ACK/response dispatch). Constraints to respect: keep `pass_count` compares out of combined gateways
(Class 1); separate flag registers, not one enumerated state register (Class 8). **Build Case A and
Case B as COMPILE-TIME variants** sharing parser/deparser/prologue — NOT one runtime `policy_mode`
program (stacked they blow the 12-stage limit).

**Minimum changes to `dcrn.p4` for Case A first** (file-level):
1. Headers: add `tstamp_tick` to the bridge (for the later Case-B clock fix; harmless for A).
2. Registers: add `reg_resp_seen`, `reg_ack_gone`, `reg_gen`; keep `reg_ack_seen`; drop the
   request-relative `set_deadline`/`bounded_target` arming from the Case-A variant.
3. Parser: unchanged (already classifies pure-ACK vs payload-bearing response).
4. Ingress apply — replace the request-relative both-hold branch with the Case-A state machine (§2/§3):
   arm on READ; on pure ACK → recirc-hold (QID_HOLD); on response → set `resp_seen`, admit to loop; ACK
   releases on `resp_seen`, sets `ack_gone`; response releases on `ack_gone` + δ passes; both to
   `PORT_VISION`.
5. Deparser: unchanged (byte-preserving; bridge popped before egress).
6. `dcrn_setup.py`: add a Case-A control-plane bring-up (ports, recirc, QID_HOLD queue, `reg_gen` seed,
   FC allowlist = READ only). Confirm the dp68 qid5 `pg_id`/`pg_queue` mapping (the pacing fix).

## 6. Hardware unknowns (§27 item 6) — ranked; only a switch run resolves
1. **`global_tstamp` refresh on recirc** — does `ig_prsr_md.global_tstamp` re-take each pass? (Case B
   only; Case A immune.) Resolved by the C1–C4 probe (see EXPERIMENT_PLAN GATE 2). Fallback: egress-
   bridge timestamp / pass-count self-clock.
2. **dp68 qid5 pacing** — is the shaper actually applied to the recirc queue (correct `pg_id`/`pg_queue`)?
   Does a paced pass give a deterministic period? (Needed for a bounded Case-A guard and any pacing.)
3. **Monotone register visibility + same-queue FIFO** — the two invariants the zero-inversion guarantee
   rests on. Assert directly on hardware (Case A).
4. **Minimum reliable ordering guard δ** — the register write-to-read latency in passes (Case A E1).
5. **Multi-segment ordering** — later segments parked behind the ACK without inversion (needs a
   controlled larger-response sweep).
6. **RTO-safety** — re-measure the master's effective RTO on the rig; bound Case-A ACK-hold and Case-B
   `G_i` well below it.

Nothing in this document has been compiled or run. The first step that needs **no switch** is the local
`bf-p4c 9.13.1` Case-A build (EXPERIMENT_PLAN GATE 3).
