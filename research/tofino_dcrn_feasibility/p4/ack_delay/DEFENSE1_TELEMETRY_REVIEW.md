# DEFENSE1_TELEMETRY_REVIEW.md

Focused review of the committed Defense 1 telemetry copy `dcrn_defense1_telem.p4` against the frozen
`dcrn_defense1.p4`. Static + off-switch compile only. **No switch touched; Defense 2 not started.**

- Date: 2026-07-22
- Reviewer artifact for: commit `8077c40` (`feat(phase4): Track 1 — dcrn_defense1_telem.p4`).
- Compiler: local `bf-p4c 9.13.1` (`/home/philip/bf-sde-9.13.1`), `--target tofino --arch tna -g`.
- Baseline: the frozen original compiled off-switch into a scratch dir for the resource comparison.

---

## 1. Git hashes

| Object | Hash |
|---|---|
| Frozen `dcrn_defense1.p4` blob @HEAD | `fa6a2f10c52e6c77d526b7678bff699431b95d5d` |
| `dcrn_defense1_telem.p4` blob @HEAD | `2a4c202fcc8de64b810f241a3d27820d026194cb` |
| Telemetry-copy commit | `8077c40` |
| Frozen-base last-touch commit | `a5843c7` |

`git diff --quiet HEAD -- dcrn_defense1.p4` → **clean** (frozen original byte-unchanged);
`defense1_setup.py`, `refmodel/`, `tests/`, `evidence/` all unchanged.

---

## 2. Focused diff (dcrn_defense1.p4 → dcrn_defense1_telem.p4)

**Additions-only.** `diff -u` = 140 added lines, **0 code lines removed or altered** (the single `-`
line in the raw diff is the `--- ` file header). Every telemetry construct is new code inserted into
gated / measurement-only positions; no original statement is edited, reordered, or deleted. The
release-decision code is textually identical (proof in §7).

Hunk map (new-file line numbers):

| Region | New-file lines | What |
|---|---|---|
| Banner | 46–72 | graft description (comment only) |
| Constants | 128–137 | `release_reason` enum + `DIGEST_ACK`/`DIGEST_RESP` |
| Bridge header | 161 | `bit<32> t_in` (measurement-only) |
| Metadata | 239–246 | 8 telemetry carrier fields |
| Digest structs | 274–291 | `d1_ack_dg_t`, `d1_resp_dg_t` |
| Parser init | 311–318 | zero-init the 8 new meta fields |
| Counter | 433 | `ctr_digest_emit` |
| Registers | 500–517 | `telemetry_enable`, `run_id_reg`, `reg_resp_tick` |
| Prologue | 554–555 | read `telemetry_enable`, `run_id` once |
| ACK-release telemetry | 630–641 | gated on `ack_release==1` |
| Response-release telemetry | 667–678 | gated on `resp_release==1` |
| ACK hold-enter | 705 | `bridge.t_in = global_tstamp` (ACK arrival) |
| Response-admit | 730, 732, 742 | `now_lo`, `resptick_write`, `bridge.t_in` |
| Deparser | 772–786 | 2 `Digest<>` + gated `pack` |

---

## 3. Every changed construct (by category)

**Parser** (`IngressParser.start`, new lines 311–318): adds `meta.telem_on/run_id/now_lo/d_ack_rel/
d_ack_reason/d_resp_rel/d_resp_reason/d_order = 0`. No parse-state graph change; the recirc path
(`ETHERTYPE_DCRN → parse_bridge → parse_ipv4 → parse_tcp → … → parse_dnp3_app`) is unchanged.

**Metadata** (`metadata_t`, 239–246): `telem_on` (bit8), `run_id` (bit16), `now_lo` (bit32),
`d_ack_rel` (bit32), `d_ack_reason` (bit8), `d_resp_rel` (bit32), `d_resp_reason` (bit8),
`d_order` (bit8). All measurement carriers; none read by a release predicate.

**Bridge header** (`dcrn_bridge_h`, line 161): `bit<32> t_in` — the hold-enter timestamp, carried on
the recirc loop, stripped in egress before Vision (bridge is popped on release, unchanged mechanism).

**Control** (`DcrnIngress.apply`):
- Prologue (554–555): `meta.telem_on = telemetry_enable_read.execute(0)`,
  `meta.run_id = run_id_read.execute(0)` — single call site each; side-effect-free reads.
- ACK-release block (630–641) and response-release block (667–678): see §5.
- ACK hold-enter (705): `hdr.bridge.t_in = (bit<32>)global_tstamp`.
- Response-admit (730/732/742): `meta.now_lo = (bit<32>)global_tstamp`;
  `resptick_write.execute(meta.flow_id)`; `hdr.bridge.t_in = meta.now_lo`.

**Deparser** (`IngressDeparser`, 772–786): `Digest<d1_ack_dg_t>() ack_digest;`,
`Digest<d1_resp_dg_t>() resp_digest;`, packed under `if (ig_dprsr_md.digest_type == DIGEST_ACK/RESP)`.

**Registers** (500–517): `telemetry_enable` (Register<bit8,bit1>(1,0)), `run_id_reg`
(Register<bit16,bit1>(1,0)), `reg_resp_tick` (Register<bit32,bit16>(65536,0), write-only in the
dataplane). Each with one RegisterAction.

**Counter** (433): `ctr_digest_emit` (Counter<bit64,bit1>(1, PACKETS)).

**Setup / control plane**: `defense1_setup.py` is **UNCHANGED** — the graft is dataplane-only. To
DRIVE it, the control plane must additionally (not yet written): seed `telemetry_enable[0]=1`,
seed `run_id_reg[0]=<epoch>` per run, and register two learn-digest callbacks (`d1_ack_dg_t`,
`d1_resp_dg_t`). With `telemetry_enable=0` (default) the program is byte- and timing-identical to the
frozen original.

---

## 4. Digest schema, field widths, release-reason enum

```p4
// release_reason (bit<8>):
REL_RESPONSE_EVENT = 1;   // ACK normal release (reg_resp_seen observed)   [event-governed]
REL_ACK_MAX_PASS   = 2;   // ACK fail-open (ACK_MAX_PASS = 65536 cap)
REL_RESP_MAX_PASS  = 3;   // response fail-open (RESP_MAX_PASS = 131072 net)
REL_RESP_ORDERED   = 4;   // response normal release (ack_gone observed → ACK-first)

struct d1_ack_dg_t {          // emitted at ACK release, digest_type == DIGEST_ACK ; 136 bits / 17 B
    bit<16> run_id;
    bit<16> flow_id;
    bit<32> ack_arr_tick;     // pure-ACK arrival (bridge.t_in @ hold-enter)
    bit<32> ack_rel_tick;     // ACK release tstamp
    bit<32> ack_pass;         // ACK recirc pass count
    bit<8>  ack_reason;       // 1=RESPONSE_EVENT | 2=ACK_MAX_PASS
}
struct d1_resp_dg_t {         // emitted at response release, digest_type == DIGEST_RESP ; 144 bits / 18 B
    bit<16> run_id;
    bit<16> flow_id;
    bit<32> resp_evt_tick;    // response-event tstamp (bridge.t_in @ admit)
    bit<32> resp_rel_tick;    // response release tstamp
    bit<32> resp_pass;        // response recirc pass count
    bit<8>  resp_reason;      // 4=RESP_ORDERED | 3=RESP_MAX_PASS
    bit<8>  order_result;     // 1=ACK-first confirmed | 0=fail-open
}
```
Both are well within the TNA learn-quantum. **Primary metric E_D1 = `ack_rel_tick` (ACK digest) −
`resp_evt_tick` (RESP digest)** = the ACK's release latency after the response event.

---

## 5. Digest emission sites and their control-flow predicates

**ACK-release digest** (new lines 630–641), inside the `hdr.bridge.role == ROLE_ACK` branch,
**after** the unchanged release predicate:
```p4
if (ack_release == 1) {                                   // release pass ONLY → never per-pass
    meta.d_ack_rel = (bit<32>)ig_prsr_md.global_tstamp;   // MEASUREMENT only
    if (ack_alarm == 1) { meta.d_ack_reason = REL_ACK_MAX_PASS; }
    else                { meta.d_ack_reason = REL_RESPONSE_EVENT; }
    if (meta.telem_on == 1) {                             // A/B gate (prologue read)
        ig_dprsr_md.digest_type = DIGEST_ACK;
        ctr_digest_emit.count(0);
    }
}
```

**Response-release digest** (new lines 667–678), inside the response branch, after `resp_release`:
```p4
if (resp_release == 1) {
    meta.d_resp_rel = (bit<32>)ig_prsr_md.global_tstamp;
    if (resp_alarm == 1) { meta.d_resp_reason = REL_RESP_MAX_PASS; meta.d_order = 0; }
    else                 { meta.d_resp_reason = REL_RESP_ORDERED;  meta.d_order = 1; }
    if (meta.telem_on == 1) { ig_dprsr_md.digest_type = DIGEST_RESP; ctr_digest_emit.count(0); }
}
```

**Deparser** (772–786): each `pack` is gated on the CONSTANT `digest_type` (TNA requirement), so the
emit is compile-time-selected and A/B-gated via `digest_type` being set only when `telem_on==1`.
`digest_type` defaults 0 ⇒ no digest when telemetry is off.

---

## 6. Where the two key timestamps are captured

- **response_event_timestamp** — at the response-admit site: `meta.now_lo = (bit<32>)global_tstamp`
  (line 730), written to the recirc bridge `hdr.bridge.t_in = meta.now_lo` (line 742) so it rides the
  loop and is emitted as `d1_resp_dg_t.resp_evt_tick`; also mirrored into `reg_resp_tick[flow_id]`
  (line 732) for an optional control-plane cross-check.
- **ack_release_timestamp** — at the ACK-release edge: `meta.d_ack_rel = (bit<32>)global_tstamp`
  (line 631), gated on `ack_release==1`, emitted as `d1_ack_dg_t.ack_rel_tick`.

Both reads of `global_tstamp` are MEASUREMENT-only and appear in no release predicate.

---

## 7. Proof the release path is unchanged

**(a) Diff is additions-only** (§2): no original line edited or removed.

**(b) ACK release predicate — byte-identical** (original 513–516 vs telem 610–613):
```p4
bit<8> rs = respseen_getclr.execute(meta.flow_id);   // atomic poll+self-clear
bit<8> ack_release = rs;                   // event-governed
bit<8> ack_alarm   = 0;
if (hdr.bridge.pass_count >= ACK_MAX_PASS) { ack_release = 1; ack_alarm = 1; }
```

**(c) Response release predicate — byte-identical** (original 540–548 vs telem 649–657):
```p4
if (hdr.bridge.pass_count >= GUARD_PASSES)  { guard_ok = 1; }
bit<8> resp_alarm = 0;
if (hdr.bridge.pass_count >= RESP_MAX_PASS) { resp_alarm = 1; }
bit<8> ag = 0;
if (guard_ok == 1) { ag = ackgone_getclr.execute(meta.flow_id); }
bit<8> resp_release = resp_alarm;
if (ag == 1) { resp_release = 1; }
```

**(d) ACK-before-response invariant unchanged** — `ackgone_set.execute(meta.flow_id)` on the ACK's
release pass (617), `ackgone_getclr` guard-gated on the response (652), release at **qid 0** (shared
FIFO on PORT_VISION; `QID_HOLD=5` only for held frames), `GUARD_PASSES=4` — all original, none inside
the additions.

**(e) Fail-open ceilings unchanged** — `ACK_MAX_PASS=65536`, `RESP_MAX_PASS=131072`; `drop()` is
L2-malformed only. The new `release_reason` enum only *labels* these in the digest; it does not gate
release.

**(f) Flow qualification unchanged** — `flags_ok` / `not_abort` (prologue), `expack_match`
(expected-ACK), `fc_allowlist` (DNP3 func-code), the CRC16 flow hash (565–573) are original. Note the
recirc frame re-parses ipv4/tcp, so `flow_id` is **valid on the release pass** (the digest's
correlation key is sound).

**(g) Transaction cleanup unchanged** — `armed_set`/armed read-and-clear, `respseen_getclr`
self-clear, single-phase `reg_ack_gone` — original. The one new stateful write `reg_resp_tick`
(write-only, never read in the dataplane) cannot affect any release decision.

---

## 8. Resource comparison (off-switch, bf-p4c 9.13.1)

| Metric | ORIGINAL | TELEM (committed) | Δ | TXNKEY variant (§10) |
|---|---|---|---|---|
| Ingress stages | **12** | **12** | **0** | **12** |
| Egress stages | 1 | 1 | 0 | 1 |
| Ingress latency (cycles) | 244 | 248 | **+4** | ~248 |
| PHV occupied containers | 96 (8b×23,16b×38,32b×35) | 102 (8b×26,16b×39,32b×37) | **+6** | 103 (+1 32b) |
| SRAM | 55 | 80 | **+25** | ≈80 |
| Map RAM | 53 | 78 | **+25** | ≈78 |
| **TCAM** | 0 | 0 | **0** | 0 |
| Meter (stateful) ALU | 7 | 10 | +3 | ≈10 |
| Stats ALU | 6 | 8 | +2 | ≈8 |
| Gateway | 41 | 48 | +7 | — |
| Hash bits | 121 | 137 | +16 | — |
| VLIW instr | 32 | 38 | +6 | — |
| Logical tables | 57 | 68 | +11 | — |
| Exact-match xbar | 72 | 79 | +7 | — |

Reading it: **stages and TCAM are unchanged**; the graft costs +4 cycles latency, +6 PHV containers,
and roughly +25 SRAM / +25 Map RAM / +3 stateful ALU — all absorbed inside the existing 12 stages
(compile fit, `tofino.bin` produced, 0 errors, 2 pre-existing parser warnings identical to the
original). **The dominant SRAM/Map-RAM cost is `reg_resp_tick` (65536 × 32 b ≈ 256 KB).** See §10 —
that register is *redundant* with the RESP digest and can be dropped to roughly halve the SRAM cost.

---

## 9. Collector correlation and completeness rules

**Correlation (as committed):** two records per transaction — a `d1_ack_dg_t` (at ACK release) and a
`d1_resp_dg_t` (at response release). Both carry `run_id` (seeded per run, so cross-run batches never
mix) and `flow_id`. Under Defense 1's **single-outstanding-per-flow** operating scope, `(run_id,
flow_id)` + release order pairs them, then **E_D1 = ACK.ack_rel_tick − RESP.resp_evt_tick**.

**Completeness (mirror the microbench collector):** a run is VALID iff
`collector_records(ACK) == events[EV_ACK_RELEASED]+events[EV_ACK_MAXPASS]`,
`collector_records(RESP) == events[EV_RESP_RELEASED]+events[EV_RESP_MAXPASS]`,
`ctr_digest_emit_delta == records(ACK)+records(RESP)`, and (per flow) exactly one ACK and one RESP
record with matching `run_id`. A record with `ack_reason==2` (ACK_MAX_PASS) means **no response
event occurred** — the collector excludes it from E_D1 and counts it as a fail-open. `order_result`
must be 1 on every normal `RESP_ORDERED` release.

**Weakness of order-based pairing:** it relies on the single-outstanding assumption and on record
delivery order; it has no intrinsic transaction key. §10 removes this weakness.

---

## 10. The missing "generation" field — and a better fix (a stable transaction key)

**The gap.** The committed telem copy does not carry a per-transaction *generation* or the *request*
timestamp on-chip; correlation therefore leans on `(run_id, flow_id)` + release order + the
single-outstanding scope. A per-transaction generation counter would need a 2-site stateful register
(bump @ ACK-enter, read @ response-admit) at the already-saturated edges — which is exactly what
over-constrained placement when the agent tried it.

**The inspection you asked for — and its result.** Rather than a generation counter, I checked
whether a value **already present at the release edges** can serve as a stable transaction key
without a state-machine change or a stage increase. Key observation (§7f): **the recirc frame
re-parses ipv4/tcp on every pass**, so `hdr.tcp.ack_no` is a **live PHV field at both release
edges** — it need not be captured into the bridge at enter. `hdr.tcp.ack_no` is the **acknowledged
request end-sequence**; for a single-outstanding DNP3 transaction the pure ACK and its response both
acknowledge the same master request, so **both carry the same `ack_no`** = a natural transaction key.

**Compiled proof (not speculation).** I built a variant (`dcrn_defense1_telem_txnkey.p4`, in scratch)
that captures `meta.d_txn_ack = hdr.tcp.ack_no` at each release edge (gated on the existing
`ack_release`/`resp_release`) and widens each digest by one `bit<32> txn_ack`. Off-switch compile:

- **0 errors, `tofino.bin` produced, 12/12 ingress stages — NO stage growth.**
- PHV: **+1 container** over the committed telem (103 vs 102). No new register, no new table, no
  state-machine change.

**Recommendation.** Adopt the `ack_no` transaction key: correlation becomes **join on
`(run_id, flow_id, txn_ack)`** — a real per-transaction identifier that survives record reordering
and no longer depends on the single-outstanding assumption for *pairing* (it still holds under it;
the key just makes it explicit and robust). This satisfies your bar — exported without semantic
change and without increasing stage usage (only +1 PHV container). Caveat to document: `ack_no`
equality across the ACK and the response assumes the master does not advance its send sequence
between them, which is guaranteed under Defense 1's single-outstanding-per-flow scope (the same scope
release-order correlation already assumes); if the master ever pipelines, the collector falls back to
order.

**Bonus resource finding.** `reg_resp_tick` (65536 × 32 b) is the graft's dominant SRAM/Map-RAM cost
(§8) and is **redundant**: the response-event timestamp already rides `bridge.t_in` into the RESP
digest (`resp_evt_tick`). Dropping `reg_resp_tick` (keep only the bridge-carried tstamp) removes the
per-flow register and roughly halves the added SRAM/Map-RAM, with no loss to E_D1. Recommend removing
it in the same refinement.

---

## Decision points for you (nothing applied without approval)

1. **Adopt the `ack_no` transaction key?** (compiled, fits at 12/12, +1 PHV container) — replaces
   release-order correlation with `(run_id, flow_id, txn_ack)`.
2. **Drop the redundant `reg_resp_tick`?** — halves the SRAM cost; E_D1 unaffected.
3. If both: I fold them into `dcrn_defense1_telem.p4`, recompile off-switch, and re-verify before any
   Defense 2 work or any switch load.

Everything above is static + off-switch. No switch was touched; Defense 2 has not been started.
