# Gate 13.2 — real DNP3 classification, compile + resource fit [COMPILED] PASS

`ibspg_dnp3.p4` replaces the synthetic `hdr.ib.role` marker of Part 12 with a real DNP3 classifier,
built entirely in the ingress parser, on top of the unchanged Part 12 HOLD_RESPONSE state machine.

**It fits, with room to spare: 11 of 12 ingress MAU stages — one stage FEWER than the Part 12
baseline it was built on.** Off-switch, compile-only: nothing was loaded, no hardware was touched.

## Provenance
- source SHA-256: `ed72a4743aa08dcda0589725550e04728ce00cd5c6cf974b69c1fd263cc2982f`
- command: `PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g -o compile_local/out ibspg_dnp3.p4`
- compiler: local bf-p4c **9.13.1** (`/home/philip/bf-sde-9.13.1`) only. The authoritative on-switch
  9.13.2 parity compile is a separate gated step and was NOT attempted.
- exit status **0**, **0 errors**, **3 warnings** (all benign — see below)
- log: `compile_local/compile.log`

The Part 12 baseline column below is **not quoted from its note** — `ibspg_hold_response.p4`
(SHA-256 `fa073cf6…`, unmodified) was recompiled with the same compiler and the numbers were read
from the same files, so the comparison is like-for-like.

## Result — side by side against the Part 12 baseline

| | Part 12 `ibspg_hold_response` | Part 13 `ibspg_dnp3` | delta |
|---|---|---|---|
| exit / errors | 0 / 0 | 0 / 0 | — |
| warnings | 2 | 3 | +1 (benign, explained below) |
| **ingress MAU stages** | **12 / 12** | **11 / 12** | **−1** |
| egress MAU stages | 0 | 0 | — |
| critical path (table dep. graph) | 12 | 11 | −1 |
| logical tables | 44 | 45 | +1 (`tbl_guard`) |
| SRAM | 36 | 38 | +2 |
| **TCAM (MAU)** | **0** | **0** | — |
| map RAM | 36 | 38 | +2 |
| Stats ALU | 11 | 12 | +1 |
| Meter ALU (registers) | 7 | 7 | — |
| **ingress parser states** | **2** | **9** | **+7** |
| ingress parser TCAM rows | 4 | 86 / 256 | +82 |
| egress parser states | 6 | 5 | −1 |
| egress parser TCAM rows | 11 | 8 | −3 |

Sources: `compile_local/out/pipe/logs/table_summary.log`, `mau.resources.log` (Totals row),
`parser.characterize.log`, `metrics.json`.

**Why it got shorter, precisely.** In Part 12 the ARM write-driver table could not share a stage with
the classify block, because its gateway read `meta.dequeued`, which the classify block itself
produced: `table_summary.log` shows `…response307` (the `ingress_port == PORT_L` compare) pinned at
`[0,0]` and `…response313` (the ARM drivers) pinned at `[1,1]` — a hard serial link. In Part 13
`meta.dequeued` is written by the parser, so the ARM driver table relaxes to `[0,3]` and lands in
stage 0 alongside the classify work. Every downstream link then shifts up by one. That is the whole
delta; nothing else in the chain moved.

## The chain, stage by stage — same shape as Part 12, one stage shorter

| stage | Part 13 source | what it does | Part 12 stage |
|---:|---|---|---:|
| 0 | `tbl_guard`, 540, 548, 554 | G lookup; `ts32`; `budget_zero`; ARM sets gen/active/deadline drivers | 0 **and** 1 |
| 1 | 560 | `reg_gen` RMW | 2 |
| 2 | 561 | `gen_mismatch` | 3 |
| 3 | 568 | `active` clear driver (stale / budget termination) | 4 |
| 4 | 573 | `reg_active` RMW | 5 |
| 5 | 583 | ACK qualification → deadline write driver | 6 |
| 6 | 589 | `reg_deadline` RMW | 7 |
| 7 | 592, 593 | `dl_armed`, `age = now − deadline` | 8 |
| 8 | `tbl_deadline_expiry` + ACT | ternary sign-bit expiry; queue assignment / forward / drop | 9 |
| 9 | ACT (cont.) | blocker termination and loop branches | 10 |
| 10 | 657–660 | the four timestamp registers | 11 |

The three state registers still execute in the order `reg_gen → reg_active → reg_deadline`, one
RegisterAction with one unconditional call site each, driven by upstream metadata write-enables. The
ternary sign-bit expiry table is unchanged and still costs 0 MAU TCAMs (the compiler folds the
single const entry into gateway logic). No bit-slice of a 32-bit arithmetic field was reintroduced.

## What moved into the parser

Everything the MAU used to be handed on a plate by the synthetic header. The parser now writes six
metadata fields and the MAU consumes them exactly as it consumed `hdr.ib.role` before:

| field | set where | value |
|---|---|---|
| `meta.role` | leaf parser states | `ROLE_ARM` (DNP3 FC 1), `ROLE_RESP` (FC 129), `ROLE_ACK` (pure TCP ACK), `ROLE_BLOCK` (ethertype 0x88C1), else `ROLE_BYPASS` |
| `meta.dir` | port-decode states | `DIR_MASTER` (dp9) / `DIR_OUT` (dp11 and the dp8 loopback) |
| `meta.dequeued` | port-decode state | 1 on dp8 — was an MAU compare in Part 12; this is the stage that was saved |
| `meta.fwd_port` | port-decode states | the transparent-forward peer port for this ingress port |
| `meta.port_ok` | port-decode states | 1 for dp8 / dp9 / dp11, else 0 → dropped |
| `meta.gen_in` | `parse_token`, `parse_dnp3_app` | token `gen` byte, or the DNP3 application control byte |

Verified in the generated `pipe/ibspg_dnp3.bfa`, not merely intended:
- port decode: `0b*******000001000` (dp8) → `dequeued=1, dir=1, fwd_port=9, port_ok=1`;
  `…1011` (dp11) → `dir=1, fwd_port=9, port_ok=1`; `…1001` (dp9) → `fwd_port=11, port_ok=1`;
  any other port → `next: end` with `port_ok` left 0.
- function-code decision: `parse_dnp3_tp` matches `0x81 → B3: 2` (RESP) and `0x01 → B3: 6` (ARM),
  default leaves the role at 0 (BYPASS); `meta.gen_in ← app_control` on all three arms.
- pure ACK: eleven entries of the form `0b0101*******1*0000000000000101000` — data_offset, ACK=1,
  PSH don't-care, RST=SYN=FIN=0, and total_len exactly `20 + 4·data_offset`.
- DNP3 link gate: `0x0564` magic plus the LEN range 8..255 expanded into 5 TCAM patterns.

Both parser-hardening gates from `dcrn_defense1.p4` are in place, and the second one is stricter than
the original: this parser extracts 13 payload bytes (link 10 + transport 1 + application 2), so the
`total_len` range thresholds are `20 + 4·data_offset + 13`, and the DNP3 LEN field must additionally
be ≥ 8 before transport/application extraction is entered. A `LEN == 5` link-only frame therefore
takes the `accept` branch: **valid, ROLE_BYPASS, forwarded transparently, never dropped.** So does
any frame whose payload is too short, whose magic is wrong, or which carries SYN/FIN/RST.

## Warnings (3) — all benign, but one is load-bearing and was verified

1. `out parameter 'meta' may be uninitialized when 'IgParser' terminates`. **Deliberate, and
   verified safe.** Tofino's parser has no clear-on-write: initializing a field in `start` and
   assigning it again in a later state on the same path is a hard error
   (`this re-assignment is not supported by Tofino` — the first compile of this program failed on
   exactly that, for `meta.fwd_port`). The six classification fields are therefore assigned exactly
   once per path and rely on the compiler's own zero-initialization. That this actually happens is
   confirmed in `pipe/ibspg_dnp3.bfa`: `init_zero: [ B3, B4, H1, B5, W2, B6, … ]`, where B3 = `role`,
   B4 = `dir`, H1 = `fwd_port`, B5 = `port_ok`, W2[23:16] = `gen_in`, B6 = `dequeued`. Every default
   is the all-zero encoding: `ROLE_BYPASS=0`, `DIR_MASTER=0`, `port_ok=0`, `gen_in=0`, `dequeued=0`.
2–3. The two `min_parse_depth_accept_loop will be unrolled` notes — identical to Parts 11 and 12.

## Preserved, and what could not be

Preserved unchanged: the pass-budget fail-open (`budget_zero` → blocker self-terminates), generation
safety (stale blocker tokens self-terminate on `gen_mismatch`), the deadline register and its ternary
sign-bit expiry, byte preservation (no field of any host frame is written; emission order equals
extraction order; all carried headers ride TAGALONG containers), and the queue assignment
Q_BLOCK qid7 (HIGH) > Q_RESP qid1 (LOW).

Internal-token isolation is **stronger** than Part 12: ethertype 0x88C1 is forced to `ROLE_BLOCK` in
the parser regardless of the role byte in the token header, and structurally the `ROLE_BLOCK` branch
is the first arm of both ACT dispatches, so an 0x88C1 frame can only ever reach `to_block()` or
`drop_pkt()` — never a host port.

Four places where Part 12 behaviour could **not** be preserved identically, each forced by real
traffic rather than chosen:

1. **ROLE_ARM is forwarded, not consumed.** Part 12 dropped its synthetic ARM packet. ARM is now a
   real DNP3 READ; dropping it would break the live transaction, so it is forwarded to the outstation
   after arming.
2. **ROLE_BYPASS is forwarded, not dropped.** Part 12 dropped all non-IBSPG traffic to isolate the
   microbench. A real DNP3 session needs ARP, the TCP handshake, DIRECT_OPERATE and the master's own
   ACKs to pass. Traffic from any port other than dp8/dp9/dp11 is still dropped. Consequence to keep
   in mind for the silicon gate: background traffic now traverses the register chain (read-only, no
   write-enable is ever set for it) and the host queues.
3. **The ACK-qualification gateway lost `slot` and `gen`, and gained `dir`.** A pure TCP ACK carries
   neither a slot field nor a DNP3 application sequence, so there is nothing to check; qualification
   is now *fresh + pure ACK + from the outstation + transaction armed*. Generation safety itself —
   the token staleness check — is untouched. A master-side pure ACK is still forwarded correctly,
   because the egress port is the parser's `meta.fwd_port` rather than a hard-coded constant.
4. **The generation source changed.** A real frame has no `hdr.ib.gen` byte, so `meta.gen_in` is the
   DNP3 **application control byte** (FIR/FIN/CON/UNS plus the 4-bit application sequence, which
   increments per poll — DNP3's own per-transaction generation) for DNP3 frames, and `hdr.ib.gen` for
   tokens. The ARM writes it to `reg_gen` and tokens are checked against it exactly as before.
   **Injector requirement for the next gate: a blocker token must carry `gen` = the application
   control byte of the READ whose transaction it guards.** With one fixed slot and a 4-bit sequence
   the generation is unique across 16 consecutive polls, which is the same guarantee Part 12's 8-bit
   injected counter gave in practice.

G is also no longer carried in `hdr.ib.seq` of the ACK (a real ACK has no such field). It comes from
`tbl_guard`, a keyless table whose default-action parameter the control plane can rewrite between
trials, so a G sweep still needs no recompile. Compile-time default `G_DEFAULT_NS = 25 ms`, chosen to
sit above the SEL-751 corpus CLRT p95 of 16.5 ms (median 12.9 ms). This is the +1 logical table,
+2 SRAM and +2 map RAM in the table above; it was placed in stage 0 and cost no stage.

## Scope kept deliberately narrow

ONE FIXED SLOT (slot 0), exactly as Parts 9/11/12. No `flow_id` CRC16 hash and no admitted-flow →
slot lookup table — the stage-budget audit identified those as the two most expensive additions, and
they belong to a later gate. Generation handling is otherwise as Part 12 left it.

## Known limits to carry into the silicon gate

- **data_offset coverage.** DNP3 descent is implemented for TCP data_offset 5..8 — 5 (no options) and
  8 (Linux timestamps) are the only values that occur; every frame in all six corpus captures is
  data_offset 8 (measured directly from `Traffic Trace/SEL751.pcap`: data_offset 8 for 400/400
  packets, payload lengths 0 / 22 / 54, flags 0x18 on data and 0x10 on pure ACKs). A data frame with
  options longer than 12 bytes is BYPASS — forwarded, never held: fail-open, not fail-closed. Pure
  ACK detection covers data_offset 5..15 because it needs no option-skipping headers.
- **Multi-segment responses.** Only the TCP segment carrying the DNP3 application header classifies as
  ROLE_RESP; a continuation segment would be BYPASS and would overtake the held first segment. The
  Gate 13.1 audit measured zero frames spanning TCP segments in the corpus and one segment per
  response in the recommended replay stream, so this does not arise there — but it is a real
  constraint on any stream that segments.
- **Parser throughput.** `parser.characterize.log` reports min packet size 82 B at 100 Gbps and
  89.06 Gbps / 152.5 MPps for minimum-size packets. Far above the 25G host ports, but the dp8 loopback
  now carries full-size DNP3 frames as well as the blocker reservoir, which Parts 9/11/12 never did;
  worth watching when the blocker loop rate is measured on silicon.
- Ingress parser TCAM is 86 of 256 rows; extending data_offset coverage costs roughly 13 more rows per
  added value.

## Not done

Nothing has been loaded or run. No on-switch 9.13.2 parity compile, no control plane, no traffic, no
hardware of any kind was touched by this gate.
