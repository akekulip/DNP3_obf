# EGRESS_OFFLOAD_DESIGN — moving release-side evidence to egress (variant P2 / WS3)

Compile-only, local bf-p4c 9.13.1. Subject: Part 12 `ibspg_hold_response.p4` (P0, 12/12 ingress
stages, **0 egress stages** — egress is entirely free real estate).

**Headline, stated before the design so it is not buried: P2 saves ZERO ingress stages, as
predicted, and it is still worth doing.** It is not a stage-reclamation lever and must not be
reported as one. What it buys is ingress SRAM, map RAM, SALU and Stats-ALU headroom, and a cleaner
separation between the state machine and the evidence it produces.

---

## 1. Why the bound is zero, and why that was known before compiling

WS1 measured that **deleting** the entire timestamp bank — all four registers and all four call
sites — leaves P0 at 12 ingress stages. Deletion is strictly more aggressive than relocation, so it
upper-bounds any offload. The bound is zero and no amount of cleverness in this variant can beat it.

The reason is structural: the ingress depth is set by the serial state chain at the *head* of the
pipeline (P0 stages 0–9, each pinned `[n,n]`). The telemetry sits in the *tail*, in stages that were
placement outcomes rather than dependency requirements. Removing tail work lets the allocator spread
out; it does not shorten the chain.

**Measured confirmation: P2 = 12 ingress stages, 12 critical path.** Identical to P0.

## 2. What moves, and what physically cannot

The constraint is brutally simple: **only packets that traverse egress can carry evidence to
egress**, and in this program that is exactly the `to_host()` set — the immediately-forwarded ACK and
the released response. Everything else is enqueued with `bypass_egress = 1` or dropped in ingress.

**Moved (the complete release-side evidence group):**

| item | evidence it provides |
|---|---|
| `reg_ts_ack_arm` | `t_ack` — the left edge of the measured interval |
| `reg_ts_first_resp_release` | the release timestamp — the right edge |
| `ctr_ack_arm`, `ctr_ack_bypass` | release-role counters for the ACK |
| `ctr_resp_release` | released-packet count |

`G_observed = ts_first_resp_release − ts_ack_arm` is therefore computed entirely from egress-resident
registers after the move.

**Not moved, with the physical reason:**

| item | why it cannot move |
|---|---|
| `reg_ts_first_block`, `ctr_block_enq`, `ctr_resp_enq` | the fresh BLOCK and the enqueued RESP are sent with `bypass_egress = 1`; they never enter egress |
| `reg_ts_block_term`, `ctr_block_term_{stale,deadline,timeout}` | a terminating blocker is **dropped in ingress**; it has no egress at all |
| `ctr_arm`, `ctr_nonibspg`, `ctr_block_loop` | likewise dropped or recirculated, never egress-bound |

Routing any of those through egress would add an egress traversal to **every recirculation pass**,
changing the loop period — that is, changing the very timing the experiment measures. The brief
forbids moving anything that determines whether a packet is held or released, and the blocker's pass
timing is exactly that. This is a hard boundary, not a conservative choice.

Consequence: two of the four timestamp registers and three of the eleven counters stay in ingress.
Even under a hypothetical "move everything movable", the ingress timestamp bank does not empty.

## 3. Carrying the one bit that cannot be recomputed

A released response is **self-identifying in egress**: an enqueued response bypasses egress, so a
`ROLE_RESP` packet seen in egress can only be a released one. No metadata is needed for it.

"Did this ACK qualify?" cannot be recomputed in egress, because qualification is a function of
ingress state. One bit must cross. A 5-byte bridge header carries it:

```p4
header bridge_h { bit<8> ack_ok; bit<32> ts32; }
```

**Why the ingress timestamp is carried rather than re-stamped in egress.** Stamping in egress would
be free, but it would change what the evidence *means*:

- both edges of `G_observed` would shift by one pipeline traversal — self-cancelling, since both the
  ACK and the released response take the same path, so `G_observed` itself would survive;
- but `release_tail = ts_first_resp_release − ts_block_term` would then subtract an **ingress**
  timestamp from an **egress** one, putting a derived measurement on two different clocks and
  silently adding a pipeline traversal to a ~1.72 µs quantity.

Carrying `ts32` keeps every recorded value bit-identical to what P0 recorded. The offload then
changes *where the register lives*, not *what it holds* — which is the only form of the change that
can be validated against P0's existing silicon results.

## 4. Byte preservation

The bridge header is made valid **inside `to_host()` and nowhere else**, so it can only ride packets
with `bypass_egress = 0`. Three cases, all safe:

- **blocker tokens** (`to_block`, `bypass_egress = 1`): no bridge header is ever attached, so the
  recirculated frame is unchanged. This matters — a stray header here would corrupt the loopback.
- **the held response** (`to_resp`, `bypass_egress = 1`): enqueued with no bridge header, so the
  bytes sitting in Q_RESP are the same bytes P0 queues.
- **released response and forwarded ACK** (`to_host`, `bypass_egress = 0`): the ingress deparser
  emits `br + eth + ib`, the egress parser extracts and discards `br`, and the egress deparser emits
  only `eth + ib`. What leaves the switch is byte-identical to what arrived.

## 5. Measured cost and benefit

| metric | P0 | P2 | change |
|---|---|---|---|
| ingress stages | 12 | 12 | **0 — the predicted bound** |
| egress stages | 0 | 1 | +1, from a budget of 12 that was entirely unused |
| ingress SALU | 7 | 5 | **−2 freed** |
| ingress Stats ALU | 11 | 8 | **−3 freed** |
| logical tables | 44 | 48 | +4 (the egress tables) |
| ingress/egress parser states | 2 / 6 | 2 / 6 | unchanged |
| ingress latency (cycles) | 284 | 288 | +4 |

The SALU and Stats-ALU rows are **ingress-resident counts**, obtained by counting `Ingress.reg_*`
and `Ingress.ctr_*` entries in `out/pipe/logs/mau.resources.log`:

```
p0_baseline       ingress: 7 registers, 11 counters | egress: 0 registers, 0 counters
p2_egress_telem   ingress: 5 registers,  8 counters | egress: 2 registers, 3 counters
p3_combined       ingress: 4 registers,  8 counters | egress: 2 registers, 3 counters
```

The whole-program totals reported by the compiler are unchanged (7 stateful ALUs, 11 Stats ALUs) —
the resources **move**, they do not vanish. The point of the move is which gress pays for them, and
P3 leaves ingress holding 4 registers and 8 counters against P0's 7 and 11.

The +4 cycles of ingress latency come from the deparser work for the bridge header. Egress adds one
stage to a gress that had twelve free.

## 6. How this should be framed for the size-normalization work

The DNP3 size axis has to fit *alongside* the timing state machine. P2's contribution is that the
release-side evidence no longer competes for ingress SRAM, Stats ALUs or SALUs, and that egress —
which the WS1 forensics already identified as outside the binding constraint — is where evidence
belongs. Combined with the packed state (variant P3), ingress holds 8 stages of state machine and
nothing else, with 4 stages and the entire egress pipeline free.

## 7. Invariants

| invariant | status under P2 |
|---|---|
| generation safety | untouched — no state logic moved |
| stale / unrelated event rejection | untouched — the qualification decision stays in ingress; egress only *records* its outcome |
| correct deadline release | untouched — the deadline register, the expiry test and the queue assignment all stay in ingress |
| timeout / fail-open watchdog | untouched — entirely ingress-resident |
| internal blocker-token isolation | preserved, and slightly reinforced: tokens never receive a bridge header because they never call `to_host()` |
| byte preservation of the held packet | preserved — §4; the held frame is queued with no added header and the egress deparser never emits the bridge |
