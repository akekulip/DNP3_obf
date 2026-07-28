# Request-Triggered Internal Pktgen — Design

Replace Vision-seeded Defense 2 blocker tokens with **request-triggered, in-switch** generation.
A fresh eligible DNP3 Class-0 READ causes exactly one internal Tofino-1 packet-generator burst of
**K=64** blocker tokens. No host, controller, or periodic timer is in the per-transaction
token-generation path.

This document is grounded entirely in facts verified against the switch's SDE 9.13.2 this session
(see `../evidence/REQUEST_TRIGGERED_PKTGEN_IMPLEMENTATION_REPORT.md` §A). Names in `code font`
are the exact bf-rt / P4 identifiers.

---

## 1. What changes vs the frozen baseline

The frozen `dnp3_timing_normalizer_inline` holds the DNP3 RESPONSE on a low-priority queue
(`Q_RESP`, qid1) behind a high-priority blocker reservoir (`Q_BLOCK`, qid7) on the dp8 internal
loopback; the reservoir's blockers self-terminate at the ACK-relative deadline `t_ack + G`, at
which point `Q_BLOCK` drains and the RESPONSE releases. **All of that is preserved unchanged.**

The **only** thing that changes is *where the 64 blocker tokens come from*:

| | frozen baseline | this design |
|---|---|---|
| blocker source | Vision raw-socket AF_PACKET, 64 per poll | **in-switch pktgen**, 64 per READ |
| trigger | host software, needs `sudo` | **`trigger_recirc_pattern`** on a recirculated clone of the READ |
| generation stamping | host sets `gen` byte in each token | 24-bit pktgen `key` carries gen from the READ; ingress re-stamps on admission |
| host role | injects tokens | sends only the legitimate DNP3 poll |

Everything downstream of "a 0x88C1 token enters ingress" is the baseline's existing, proven path.

---

## 2. Trigger mechanism (tasks A, B)

Tofino-1's only packet-driven pktgen trigger is `trigger_recirc_pattern`: a packet recirculated
onto the generator port (pipe-local **port 68 = dp68**) whose leading 32 bits match
`pattern_value` under `pattern_mask` fires the app. So the READ must cause a **tagged recirculating
clone** to appear on dp68, while the **original READ is forwarded byte-identically to the relay
(dev_port 64)**.

### 2.1 Fresh-READ detection and one-shot generation advance
Reuse the baseline's existing classification: a master-side (dp9) DNP3 Class-0 READ is
`ROLE_ARM`. The baseline already advances/loads transaction state idempotently in `reg_tag` /
`reg_deadline` so a **retransmitted READ does not re-arm** — the same idempotency is what prevents
a duplicate 64-token burst (task B.3). The clone/trigger is emitted **only** on the ARM path that
actually advances the generation, so a duplicate READ produces no second trigger.

### 2.2 The clone (task B.7)
The original READ path is untouched: `fwd_port = PORT_RELAY (dp64)`, emitted in extraction order,
byte-identical. In addition, on the fresh-ARM path only, ingress requests **one mirror/clone**
directed to **dp68** carrying a 4-byte recirc tag:

```
recirc_tag[31:8] = generation-derived key (24b, lands in pktgen_recirc_header_t.key)
recirc_tag[7:0]  = a fixed marker byte that pattern_mask pins, distinct from
                   the pktgen header's own first byte (app_id encoding) so generated
                   packets never re-trigger the app.
```

`pattern_value`/`pattern_mask` are set so **only** this tag matches — the READ itself, the relay
traffic, and the generated tokens do not. The clone never leaves the switch (task B.6): its egress
port is dp68, an internal recirc port.

### 2.3 Egress budget (tasks 10, B.8)
The clone must carry the 4-byte tag. Prepending it is done at the **ingress deparser** on the
mirrored copy (mirror + emit of a 4-byte header), keeping the **deadline comparison and all
transaction logic in ingress** (task 12, B.9). Target: **zero egress stages**; the ceiling is one
simple egress action/table used *only* if the clone tag cannot be formatted at the ingress
deparser. The compile gate must print egress stage usage and redesign if it exceeds 1.

---

## 3. Pktgen burst (task C)

One pktgen app configured at init on dp68:

- `port_cfg`: `pktgen_enable = true` on dp68.
- `pkt_buffer`: the **blocker-token template** — `ethernet{dst=02:00:00:00:00:01,
  src=02:00:00:00:0b:0c, etype=0x88C1}` + `ibspg{role=BLOCK, slot, gen, budget}` padded to 60 B,
  16 B-aligned in the buffer. Same on-wire token the baseline already admits.
- `app_cfg`: `packets_per_batch_cfg = 63` (→64 packets), `batch_count_cfg = 0` (→1 batch),
  `ipg = 0`, `ibg = 0`, `pkt_len`, `pkt_buffer_offset`,
  `make_data(..., 'trigger_recirc_pattern')` with `pattern_value`/`pattern_mask` from §2.2,
  then `app_enable = true`.

One qualifying trigger → one batch → 64 tokens. **No periodic generation, no per-transaction
controller rearm** (the app stays enabled; each fresh READ recirculates a new matching clone).

---

## 4. Token admission (task D)

A generated token enters ingress from the pktgen source (dp68), parsed via the
`pktgen_recirc_header_t` (parser value-set on the leading `app_id` byte, per the SDE example).
On admission ingress:

1. Confirms it is a pktgen-sourced token (parser path + role forced to `ROLE_BLOCK`).
2. Confirms a transaction is active (`reg_tag` generation valid — the baseline's existing check).
3. Reads the current generation and **stamps** the token: `gen = current generation`,
   `budget = initial fail-open pass budget`, `role = BLOCK`.
4. Enqueues to **dp8 / `Q_BLOCK` (qid7)** — the baseline's `to_block()` action, unchanged.
5. **Drops** any pktgen packet with no active transaction (stale trigger / race).
6. Never forwards a token to dp9, dp11, or dp64 (task D.7 / 14).

Stamping on admission (not trusting the template's gen) means a token generated a hair after a new
READ still gets the live generation, and stale-generation tokens self-terminate on their first
loopback pass exactly as in the baseline.

---

## 5. Preserved Defense 2 hold (task E) — unchanged

ACK records `t_ack`; `deadline = t_ack + G`; ACK forwarded immediately; matching RESPONSE enqueued
to `Q_RESP`. Blockers dequeue from `Q_BLOCK`, return through dp8, and on re-entry ingress tests
`now >= deadline`: if false, decrement budget and return to `Q_BLOCK`; if true, terminate (do not
re-enqueue). When `Q_BLOCK` empties, TM dequeues the RESPONSE from `Q_RESP`, which returns once
through dp8 and forwards to Vision. Exact transaction matching, stale-generation rejection,
cleanup, isolation, and fail-open are the baseline's.

---

## 6. Host runner (task F)

`run/poll_pktgen.py`: protected mode sends **only** the legitimate DNP3 Class-0 poll — the
raw-socket 0x88C1 injection is removed, and protected mode **no longer needs `sudo`**. The
original host-seeded `poll.py`/`run.sh` are preserved (in `research/timing_final/live/`) for
rollback and A/B comparison.

---

## 7. Open compile-risk items (resolved at the compile gate, not assumed)

1. **Mirror/clone to dp68 with a 4-byte tag** — exact TNA mechanism (ingress mirror session +
   `ig_dprsr_md.mirror_*` + a 4-byte emit) and whether tag formatting stays at the ingress
   deparser (0 egress stages) or needs 1 egress action.
2. **Parser** additions for `pktgen_recirc_header_t` (value-set on `app_id`) must not disturb the
   existing `from_master`/`from_outstation`/`from_loopback` selects.
3. **Stage budget** — the baseline is at 10/12 ingress stages; the added clone-emit + pktgen-token
   admission path must stay ≤12. Apply the constraint-class workarounds preemptively (wide flags,
   no 32-bit gateway compares, one Hash per tuple shape).
4. **Self-retrigger avoidance** — `pattern_value`/`pattern_mask` must exclude the generated
   packets' own leading bytes.

## 8. Non-negotiables carried from the task
Tofino-1 only; no SmartNIC/DPU/eBPF/host pacing/controller fast-path; frozen files
(`dnp3_shadow.p4`, `dcrn_defense1.p4`, `dcrn_defense2.p4`) untouched; original proven live P4/
setup/runner/evidence untouched; commit each gate separately; preserve negative evidence.
