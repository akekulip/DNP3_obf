# DEFENSE2_TELEMETRY_REVIEW.md

**Track 1: instrumentation of the cover-OFF deadline-governed timing defense.**

Review of the new `dcrn_defense2_telem.p4` — a non-invasive per-release learning-digest graft on the
frozen `dcrn_defense2.p4` (Case A, "delay the response": forward the ACK, hold the response to an
ACK-relative absolute deadline `t_ack + G_i`). Static + off-switch only.

> **Scope (explicit):** this instruments the *existing, silicon-proven* cover-OFF Defense 2 mechanism
> so it can be characterized. It does **not** implement or complete size normalization, TM queue
> scheduling, packet padding, splitting, transaction-window cover, continuous cover, or READ-vs-SBO
> hiding, and makes **no claim** about the locked joint size-and-time architecture. The queue
> microbench, size pattern, padding path, cover modes, transaction-window controller, and switch
> configuration were not touched. Nothing was loaded onto the switch.

- Date: 2026-07-22
- Compiler: local `bf-p4c 9.13.1` (`/home/philip/bf-sde-9.13.1`), `--target tofino --arch tna -g`.

## 1. Git identity

| Object | Hash |
|---|---|
| Frozen `dcrn_defense2.p4` blob @HEAD | `fef72a5a5bdeb42c24ef35e79f8e69be59d016c7` |
| `dcrn_defense2_telem.p4` blob | `097dec0eff177015a9917e84cdd66c933de5b411` |
| Frozen-base last-touch commit | `a5843c7` |

`git diff --quiet HEAD` is clean for `dcrn_defense2.p4` and `defense2_setup.py` (frozen preserved).
Frozen→telem diff is **additions-only: 154 added, 0 code lines removed or altered.**

## 2. Compile result (off-switch)

| | Frozen baseline | Telem |
|---|---|---|
| Exit / errors | 0 / **0** | 0 / **0** (2 benign parser-unroll warnings, identical) |
| `tofino.bin` + `context.json` | yes | **yes** |
| Ingress stages | 10 / 12 | **10 / 12** (0 growth) |
| Critical path (table dep graph) | 8 | 8 |
| Ingress latency (cycles) | 242 | 246 (+4) |

## 3. What it measures (the characterization purpose)

Two register-free learn-digests, joined by a stable transaction key `(run_id, flow_id, txn_ack)`
where **`txn_ack = hdr.tcp.ack_no`** (the acknowledged request end-sequence, identical on the pure
ACK and its response; captured on the live re-parsed TCP header):

```p4
struct d2_ack_dg_t  { // at qualified ACK (digest_type==DIGEST_ACK), 16 B
  bit<16> run_id; bit<16> flow_id; bit<32> txn_ack;
  bit<32> deadline_tick;  // meta.deadline = ack_tick + G_i  (the ACK-relative absolute deadline)
  bit<32> ack_tick;       // pure-ACK arrival tick
}
struct d2_resp_dg_t { // at response release (digest_type==DIGEST_RESP), 21 B
  bit<16> run_id; bit<16> flow_id; bit<32> txn_ack;
  bit<32> t_in;           // response arrival tick
  bit<32> release_tick;   // response release tick
  bit<32> pass_count;     // recirc laps (0 if released without holding)
  bit<8>  release_reason; // 1|2|3|4
}
```

- **Primary metric `E_D2 = resp.release_tick − ack.deadline_tick`** = overshoot past the ACK-relative
  deadline. On-chip hold = `release_tick − t_in`; **internal recirculation cost = `pass_count`**.
- **All four release reasons are separated** by `release_reason`:
  `1 REL_TIMESTAMP_DEADLINE` (clean `now_eff >= deadline`), `2 REL_FAIL_OPEN_MAXPASS`
  (`pass_count >= MAX_PASS`), `3 REL_AMBIGUITY_FAIL_OPEN` (first-arrival, deadline already
  matured/stale), `4 REL_BYPASS` (combined/ineligible frame forwarded unchanged).
- **Diagnostic for the nominal 60 ms vs measured ~107 ms result:** a **negative `E_D2` with
  `release_reason == 2`** is the signature of a *stuck recirc clock* — the response looping to
  `MAX_PASS` instead of releasing on the timestamp deadline. Clean `reason == 1` with small `|E_D2|`
  is a true deadline release. This is exactly the distinction the 107 ms number could not previously
  be resolved into.

All ticks are `global_tstamp[47:16]` (65.536 µs units). `release_tick` uses the **egress-refreshed
`bridge.tstamp_tick`** — the *same clock the frozen `check_deadline` compares against* — not raw
`ig_prsr_md.global_tstamp` (which the frozen design establishes does **not** refresh on the recirc
loop), so `release_tick`, `deadline_tick`, and `t_in` share one timebase and `E_D2` subtracts directly.

## 4. Frozen semantics preserved — byte-identical predicates

Every release / fail-open / ambiguity / bypass / occupancy / cleanup predicate is byte-identical to
the frozen original (only line numbers shift; frozen → telem):

| Semantics | Frozen | Telem | Predicate |
|---|---|---|---|
| Deadline compare (SALU) | 398 | 490 | `if (meta.now_eff >= dl) { released = 1; }` |
| Deadline release | 548 | 664 | `meta.released = check_deadline.execute(meta.flow_id);` |
| Release decision | 555 | 671 | `bit<8> do_release = meta.released;` |
| `FAIL_OPEN_MAXPASS` | 557 | 673 | `if (hdr.bridge.pass_count >= MAX_PASS) { do_release = 1; alarm = 1; }` |
| Ambiguity (first-arrival) | 577 | 710 | `} else if (meta.released == 1) {` |
| Bypass | 572–573 | 698–699 | `if (seen==1 && meta.not_abort==1) { sep = 1; }` … `if (sep == 0)` |
| Occupancy watermark | 416/583 | 508/724 | `if (v >= HELD_MAX) { over = 1; }` / `held_check_inc.execute(0)` |
| Cleanup | 560 | 686 | `hdr.bridge.setInvalid();` (byte-preserved) |

The four per-`if` telemetry blocks are appended **after** these decisions and read them read-only; no
frozen predicate is edited (guaranteed by the additions-only diff). The frozen 4 per-flow
65536-entry registers (`reg_armed`, `reg_expected_ack`, `reg_deadline`, `reg_ack_seen`) are unchanged
and **no new 64K register is added** (hash bits unchanged at 130).

## 5. Measurement-only proof

The only telemetry symbols in any `if(...)` are the four `if (meta.telem_on == 1)` A/B gates
(lines 639, 684, 709, 721) — each only sets `ig_dprsr_md.digest_type` and counts `ctr_digest_emit`;
none sets an egress port, drop, recirc, or release. A grep of every frozen release predicate
(`do_release`/`alarm`/`meta.released`/`MAX_PASS`/`sep`/`over`/`held_check_inc`/`check_deadline`) for
any telemetry value (`t_in`/`d_*`/`deadline_tick`/`txn_ack`/`global_tstamp`) is empty. `telemetry_enable`
defaults 0 ⇒ with telemetry off, the program is byte- and timing-identical to the frozen original.
(One line — `if (alarm == 1) { meta.d_reason = REL_FAIL_OPEN_MAXPASS; }` — reads the *frozen* `alarm`
to *label* the digest reason; it gates nothing.)

## 6. Resource comparison (baseline → telem)

| Resource | Baseline | Telem | Δ |
|---|---|---|---|
| Ingress stages | 10 | 10 | **0** |
| Ingress latency (cycles) | 242 | 246 | +4 |
| PHV containers | 99 | 108 | +9 |
| SRAM | 63 | 73 | +10 |
| Map RAM | 60 | 70 | +10 |
| **TCAM** | 0 | 0 | **0** |
| Meter (stateful) ALU | 6 | 8 | +2 |
| Stats ALU | 6 | 9 | +3 |
| Gateway | 34 | 39 | +5 |
| Hash bits | 130 | 130 | 0 |
| VLIW instr | 29 | 32 | +3 |
| Logical tables | 48 | 56 | +8 |

The +10 SRAM / +10 Map RAM come from the small per-`if` telemetry action tables — **not** a 64K
register (a redundant per-flow deadline mirror would have cost ~256 KB SRAM ≈ 25 blocks; it was
avoided). TCAM and stages unchanged; comfortable 2-stage headroom.

## 7. Two design deviations from the literal spec (necessary; compiled evidence)

1. **Deadline exported at the ACK via a second digest — not read from `reg_deadline` at admit.** The
   frozen `check_deadline` SALU consumes `reg_deadline`'s single per-packet stateful access on every
   pass and returns only the 1-bit `released`, not the stored value; a second read at admit would
   collide, and a redundant per-flow mirror register was explicitly forbidden. So `deadline_tick` is
   emitted register-free at the qualified-ACK site (where `meta.deadline = t_ack + G_i` already
   exists), in `d2_ack_dg_t`, joined to the response record by `txn_ack`. (Same two-digest idiom as
   Defense 1.)
2. **`release_tick` = egress-refreshed `bridge.tstamp_tick`, not raw `global_tstamp`.** Raw
   `global_tstamp` is stale on the recirc loop (frozen-design fact), which would make `E_D2`
   meaningless; using the same refreshed clock as `check_deadline` keeps all ticks in one timebase.

## 8. Collector correlation, completeness, boundaries

- **Correlation:** join the ACK record and the response record on `(run_id, flow_id, txn_ack)`;
  `E_D2 = resp.release_tick − ack.deadline_tick`. `run_id` (per-run epoch) prevents cross-run mixing;
  `txn_ack` is robust to digest reordering (key-based, not order-based).
- **Completeness:** VALID iff `ctr_digest_emit_delta == records(ACK)+records(RESP)` and every released
  transaction has both records with matching key; a missing record is detected (records < events).
- **Boundaries** (same as Defense 1): TCP restart → fresh ISN → distinct `txn_ack`; 16-bit flow-hash
  collision is a frozen-base property that `txn_ack` de-ambiguates for correlation; 32-bit `ack_no`
  wrap is negligible for low-rate DNP3 (bounded window + order tiebreak); digest loss is isolated per
  transaction; digest reordering is harmless (key-based join).

## Rollback / status
The frozen `dcrn_defense2.p4` is unchanged in git; rollback is simply not using the telem copy.
Off-switch throughout; not loaded. **Loading onto the switch requires separate authorization.**
This is Track 1 (cover-OFF deadline-defense instrumentation) — it does not complete the joint
size-and-time architecture.
