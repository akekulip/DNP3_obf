# DEEP_CODE_AND_RESULTS_AUDIT.md

Static, line-numbered architecture audit of the Phase-4 TM queue microbenchmark
(`queue_microbench.p4` / `queue_microbench_setup.py`) against the frozen Case-A defenses
(`dcrn_defense1.p4` = "delay the ACK", `dcrn_defense2.p4` = "delay the response").

- **Date:** 2026-07-22
- **Author:** Philip
- **Trigger:** PAUSE-and-audit directive — finish the running (burst,target) point, preserve its
  evidence, pause the sweep driver, then perform a *static* line-numbered audit BEFORE any further
  hardware action. No P4 reload, no HOLD-queue change, no additional burst points, no
  concurrency/load test, and no physical SEL-751 access were performed for this audit.
- **Method:** read-only. Every factual claim carries a `file:line` reference; code predicates are
  quoted. The two frozen defenses were read in full for the release-mechanism comparison the
  directive requires. Defense-file line numbers are from the frozen `dcrn_defense1.p4` (762 lines) /
  `dcrn_defense2.p4` (718 lines); microbench line numbers are the currently-loaded build
  (p4 sha `0239af8f58d8a014`).

---

## A. Locked terminology (from `CASE_A_TERMINOLOGY.md`)

- **Case A = SEPARATE-ACK device (SEL-751)**, native CLRT (ACK→response) median **~12.9 ms**
  (`CASE_A_TERMINOLOGY.md:12`). CURRENT scope.
- **Defense 1 = delay the ACK** → `dcrn_defense1.p4`, **event-governed** (`CASE_A_TERMINOLOGY.md:20-27`).
- **Defense 2 = delay the response** → `dcrn_defense2.p4`, **ACK-relative deadline** `t_ack + G`
  (`CASE_A_TERMINOLOGY.md:20-27`). **Never called "Case B."**
- **Case B = COMBINED-ACK devices (AB1400/ION7550)**, no CLRT — OUT OF SCOPE; deferred study
  `case_b_defense_design.md`.
- The **queue microbench is a SEPARATE program** from both frozen defenses
  (`queue_microbench.p4:9`, `:4` "review artifact only — NOT the DNP3 defense program").

---

## B. Loaded-program identity and switch state as left (read-back, not from memory)

| Item | Value (read back) |
|---|---|
| On-switch P4 source sha | `0239af8f58d8a014` (= commit 12427e3, the A/B digest build) |
| Loaded binary sha | `fbddefa750827ebf` |
| Ingress stages | 7 / 12 |
| `telemetry_enable` | **0** (digest emission OFF) |
| `cover_mode` | **0 = COVER_OFF** |
| `mech_reg` | **0 = MECH_PKTGEN** (metronome nonetheless disabled — see Q2) |
| `window_active` | **0** |
| pktgen app1 (metronome) | **enable = False** (metronome OFF) |
| HOLD queue dp68/q6 `sched_shaping` | `{unit:PPS, provisioning:UPPER, max_rate:100059, max_burst_size:16384, min_burst_size:16384, min_rate:0}` |

Switch left in the directive-required state: **cover=OFF, metronome=OFF, telemetry_enable=0.** The
35-point burst sweep completed (`runs/burst_sweep/progress.log` "burst sweep DONE") and its evidence
(`results.jsonl`, per-run `manifest_run*.json`, `sw_*.jsonl`, `rx_*.pcap`) is preserved.

---

## Q1 — Release condition for EVERY queue_microbench packet path

`queue_microbench.p4` has one ingress `apply{}` (`:550`), a flat if/else tree over frame type:

| Path | Guard (line) | Release / exit condition | Byte-mod? |
|---|---|---|---|
| Invalid eth | `:551` | `drop()` | — |
| **MB_CHAFF** (injected cover) | `:559` `is_tick==MB_CHAFF` | straight to CHAFF queue on dp9 (`:565-568`); not a held-real release | pad added |
| **MB_METRO** tick, real pending | `:584-590` `pendSx_take==1` | **arms** `relSx_set`, `drop()`s the tick; the real releases later on its SEQ_HELD pass | — |
| **MB_METRO** tick, empty slot | `:591-616` | cover decision: OFF→`ctr_tick`+`drop()` (`:612-614`); WINDOW/CONT→emit 1 cover (`:598-610`) | pad (cover only) |
| **SEQ_ENTER** (first pass) | `:618` | `pendSx_add`, set `SEQ_HELD`, `recirc_hold()` — never releases here | — |
| **SEQ_HELD** (metronome hold) | `:627` | **RELEASE iff `relSx_take==1`** (`:633-635`) — slot armed by a tick; else `recirc_hold()` (`:645`) | strip encap (`:638-639`) |
| **SEQ_HELD_DL** (deadline hold, cover=OFF) | `:648` | **RELEASE iff `hdr.mb.hold_passes==0`** (`:656`); else decrement + `pass_count++` + `recirc_hold()` (`:683-688`) | strip encap (`:677-678`) |
| Host, unclassified | `:698` `is_mb==0` | fail open: forward to peer, `qid=QID_HOLD`, `ctr_failopen` (`:700-703`) | — |
| Host, oversize | `:708` `oversize==1` | fail open: forward to peer, `qid=QID_HOLD`, `ctr_oversize` (`:709-712`) | — |
| Host, classified, PKTGEN, cover=OFF | `:719,:732` | encap, `SEQ_HELD_DL`, `hold_passes=budget`, `t_in`, digest fields; `recirc_hold()` (`:733-746`) | pad + encap |
| Host, classified, PKTGEN, cover armed | `:742-744` | encap, `SEQ_ENTER`; `recirc_hold()` | pad + encap |
| Host, classified, SHAPER | `:748-755` | straight to per-state REAL queue on dp9; TM rate paces (`:752-754`) | pad |

**Two structurally distinct release mechanisms:**
- **Metronome release** (`SEQ_HELD`, `:633-635`): governed by a **token** (`relSx_take`) a pktgen
  tick sets — an internal-clock event. Only when cover is armed.
- **Deadline release** (`SEQ_HELD_DL`, `:656`): governed **purely by a pass-count budget carried in
  the packet** reaching zero — no timestamp, no external event, no token. **The only path the burst
  sweep exercised** (cover=OFF).

**Crux:** in cover=OFF (default ICS mode, and the sweep's mode) a real is released *solely* because
it has looped `hold_passes` times — a self-clocked retention counter, not an event (Defense 1) and
not a wall-clock deadline (Defense 2). See Q10.

---

## Q2 — Is `pat_state` (the ordered size-state list P) used in cover=OFF?

**No. `pat_state` is dead in cover=OFF.**

- `pat_state.apply()` is called at exactly one site: `:582`, inside the `MB_METRO` tick branch.
- In cover=OFF the metronome is **disabled** by the controller
  (`queue_microbench_setup.py:259` `arm_metronome = (mech=="pktgen" and cover_val != COVER_OFF)`;
  `:264-266` "metronome DISABLED"). No pktgen app fires → no `MB_METRO` frame → `:582` never runs.
- The cover=OFF host-encap path (`:732-741`) sets `SEQ_HELD_DL` and does not read `pat_state`; the
  `SEQ_HELD_DL` release path (`:648-689`) does not read it either.

**Consequence:** the "size ORDER" half of the locked mechanism `(P = [S0..S(L-1)], τ|R)` is **not
exercised by the burst sweep** — the sweep measured the **timing (deadline hold) axis only**. The
size-pattern / round-robin ordering is reachable only in cover-armed metronome mode, which the sweep
did not run. `pat_state` is installed by setup (`:447-456`) but sits unused at cover=OFF.

---

## Q3 — Synthetic fixed 64→128/256 B padding vs. general size-normalization

The microbench "size" axis is a **synthetic fixed-size pad**, not a general normalizer:

- Fillers are **compile-time-constant headers**: `pad_s1_h { bit<512> f }` (64 B) and
  `pad_s2_h { bit<1536> f }` (192 B) — `:215-216`. Only two target sizes.
- Generator sends a fixed **64 B base**; pad → **128 B (S1)** or **256 B (S2)** — `:147-150`.
- Selected by **UDP dport** (`mb_classify`, `:483-496`), applied as **zero filler**
  (`hdr.pad_sX.f = 0`, `:716-717`), **appended** after UDP before the residual body (`:799-800`).
- **No ipv4/udp length or checksum edit** (`:151-156` "measures wire size + timing, not payload
  semantics").

**It is NOT the real DNP3 size-normalizer.** The real one needs prepend-not-append, on-chip checksum,
and a per-flow TCP seq/ack translator — flagged out of scope in the code itself (`:155-156`). The
microbench pad is a **wire-size stand-in** adequate only for "does the queue preserve a size label +
timing," not "does it correctly normalize a real DNP3 response."

---

## Q4 — Parser fail-open behavior for short / non-conforming UDP

The parser has **no `verify()` and no error-recovery state** (`:275-342`):

- **Non-IPv4 ethertype** → `default: accept` (`:311`) → `ipv4` invalid → host branch `is_mb==0`
  fail-open. Graceful.
- **IPv4 `ihl != 5`** → `default: accept` (`:323-326`) → L4 unparsed → `udp` invalid → fail-open.
  Graceful (IPv4 options silently passed).
- **Non-UDP L4** → `default: accept` (`:331`) → `udp` invalid → fail-open. Graceful. (Real DNP3 is
  TCP/20000 → protocol 6 → this path → fail-open; `mb_classify` keys on `hdr.udp.dst_port`, invalid
  for a TCP frame.)
- **UDP payload < 8 B** → **NOT graceful.** `parse_udp` unconditionally transitions to `parse_mbq`
  (`:336`), which does `pkt.extract(hdr.mbq)` for the 8-byte `mbq_h` (`:209-212,338-341`). A UDP
  datagram with < 8 B payload runs the extract **past end-of-packet** → TNA parser exception → the
  frame is **dropped by the parser**, not failed open. `parse_udp` never checks `udp.length`.

**Finding:** "fail-open" is asymmetric — everything diverging *before* UDP fails open cleanly, but a
UDP frame is assumed to carry the 8-byte MBQ1 prefix; a shorter UDP frame is dropped. Fine for the
synthetic generator; a latent drop for arbitrary UDP on a shared link.

---

## Q5 — Why fail-open and oversize frames go to `qid 6` on dp9

Both fail-open (`:700-703`) and oversize (`:709-712`) set `ig_tm_md.qid = QID_HOLD` (= `5w6`, `:144`)
and egress to the peer host port (dp9; `PORT_OBSERVE = PORT_HULK = 9`, `:80-82`).

`QID_HOLD` is **overloaded**: on **dp68** it names the recirc hold-loop queue (pg_id 17, pg_queue 6).
But here egress is **dp9**, where (pg_id 2, pg_port_nr 1) maps `qid 6` to `pg_queue = 8+6 = 14`
(`queue_microbench_setup.py:110-111`) — an **ordinary, unshaped queue on dp9**, physically distinct
from the dp68 hold loop.

**Finding:** fail-open/oversize traffic is **forwarded promptly out dp9 on a spare unshaped queue** —
it is *not* recirculated or held. No correctness bug (dp9 qid6 is unshaped → no delay), but reusing
`QID_HOLD` for "the default egress queue for pass-through frames" is **misleading**; a distinct
`QID_PASSTHRU` would be clearer if carried forward.

---

## Q6 — Stale TM state across arms (the entry_mod hazard)

TM config is written with `entry_mod`, which **only sets the fields passed** — all others keep their
prior value. This is a real, silicon-observed hazard:

- **Documented incident** (`runs/RESULTS_minrate_dwrr.txt:36-41`): the first DWRR backlog run read
  `S1 DEQ=661` because the prior **min-rate R=600 cap persisted** (`max/min_rate_enable=True`); the
  DWRR arm was silently capped. Confirmed by live `sched_cfg` readback.
- **Fix only on the DWRR path** (`queue_microbench_setup.py:313-317` explicitly writes
  `min/max_rate_enable=False`). The **shaper→pktgen / minrate→pktgen** transitions have no such
  clearing — switching `--mech` without a reload leaves `*_rate_enable` set on the dp9 REAL queues.
- **HOLD queue (dp68/q6):** `hold_probe.py` left `max_burst_size` at the last swept value (16384, §B);
  any future single run inherits it.

**Finding:** the only guaranteed clean TM slate is a **bf_switchd reload**. The sweep mitigated this
by writing `burst`+`rate` on every point; cross-**mechanism** contamination is unguarded and has
already produced one wrong number on silicon.

---

## Q7 — The 8-bit GLOBAL pend/rel counters: overflow, wrong-flow, reorder

`pendS1/pendS2/relS1/relS2` are **single-entry `bit<8>` registers** (`:450-453`), balanced add/take
(`:454-469`), **global per size-state**, not per-flow:

- **Not used in cover=OFF.** Touched only on metronome paths: `pendSx_add` on `SEQ_ENTER`
  (`:622-623`), `pendSx_take`/`relSx_set` on the tick (`:584-589`), `relSx_take` on `SEQ_HELD`
  (`:633-634`). The `SEQ_HELD_DL` deadline path (the sweep) **never reads them** → for the sweep the
  concerns below are moot; they apply only in metronome/cover mode.
- **Overflow:** `bit<8>` wraps at 256; `pendSx_add` (`:454-457`) has no saturation guard. >255
  simultaneously-pending reals of one state would wrap 255→0 (strand a held frame or arm a spurious
  release). Impossible at the sparse rate, but an unbounded-input latent bug.
- **Wrong-flow (by design):** counters key on **size-state only**, not 5-tuple. A tick arming
  `relS1_set` releases **whichever** held S1 frame next hits `SEQ_HELD`, not a specific flow's. Fine
  for a *stream* (the microbench doesn't care which S1 releases) but it **cannot hold/release a
  specific flow's ACK/response** — the deepest structural gap vs the defenses (Q10).
- **Reorder:** with two S1 held and one token, release order is arbitrary, not FIFO. Unobservable for
  identical S1 frames; ACK↔response ordering is a **measured** property, not enforced (the dcrn
  zero-inversion token is deliberately omitted, `:471-475`).

**Finding:** correct *stream* arm/release for metronome mode, but (a) unguarded 8-bit overflow and
(b) fundamentally **not per-flow**. Neither affects the cover=OFF sweep.

---

## Q8 — Stale / incorrect claims still asserted in `queue_microbench_setup.py`

The **live control-plane script** still carries claims the recirc-clock audit
(`runs/AUDIT_recirc_clock.md`) **disproved** — read by an operator at bring-up, so actively
misleading:

| # | Claim in setup.py | Line(s) | Status |
|---|---|---|---|
| 1 | "**HARD CEILING: the recirc loop caps at ~4096 passes (~3.17 ms)** … the same ceiling dcrn hit at MAX_PASS=4096" | `:433-436` | **DISPROVEN** — `AUDIT_recirc_clock.md:15-28`: passes = hold_passes EXACTLY (40000→236.7 ms); no ceiling. |
| 2 | "Reaching the 17-25 ms CLRT targets needs the dcrn recirc-clock fix (raise the pass ceiling AND make the HOLD shaper throttle)" | `:433-436,:443-445` | **DISPROVEN** — 17/25/40 ms reached without the fix (`AUDIT_recirc_clock.md:104-119`; §D). |
| 3 | `pass_us = ... 0.65` as the sole calibration constant | `:437` | **INCOMPLETE for >~10 ms** — measured **0.617 µs/pass** pre-burst, ramps to **~9.7 µs/pass** post-burst (`AUDIT_recirc_clock.md:90-102`). |
| 4 | printed `WARNING: target … exceeds the measured ~3.17 ms recirc-hold CEILING … hold will saturate near 3 ms` | `:442-445` | **DISPROVEN** — holds scale to 237 ms; nothing saturates at 3 ms. |
| 5 | 0.65 µs/pass (`:437`) **vs** `HOLD_LOOP_PPS=100000` "~10 us/pass" (`:104`) and help text "1e6/HOLD_LOOP_PPS = 10 us/pass" (`:141-143`) | `:104,:141-143,:437` | **INTERNAL CONTRADICTION** (the "0.65 µs vs 100000-pps cap" conflict). Both are real — **0.617 µs pre-burst, ~10 µs post-burst** — stated as if one is *the* latency. |
| 6 | `max_burst_size = 16384` hardcoded | `:280,:373,:395-396` | **HARDCODED** — sweep overrides HOLD burst via `hold_probe.py`, but a direct `setup.py` run bakes 16384 (the breakpoint that makes ≥17 ms holds jittery, §D). |
| 7 | `HOLD_LOOP_PPS = 100000` hardcoded | `:104` | **HARDCODED** — sets the post-burst pass latency; not a flag. |
| 8 | comments say "size-labelled TM queues on **dp8**" | `:15,:47,:287` | **DOC DRIFT vs CODE** — code observes on **dp9** (`PORT_OBSERVE=9` `:85`; `PG_ID_OBSERVE=2/PG_PORT_NR_OBSERVE=1` "Confirmed … dp9" `:108-111`). |

The **authoritative report** (`QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:704-717`) and
`runs/RESULTS_hold_timing.txt:1-5` are already corrected with a WITHDRAWN header. Only the live
`setup.py` still asserts the disproven ceiling. **Recommend** patching `setup.py:431-445` (and the
dp8→dp9 comments) — a comment/print fix, not a datapath change.

---

## Q9 — Actual hold produced by the default `--hold-ms 17`

`--hold-ms` defaults to **17.0** (`queue_microbench_setup.py:135`). With the default `pass_us=0.65`
(`:437`): `hold_passes = 17*1000/0.65 = 26153` (`:438`, clamped ≤65535). But **26153 passes is deep
in the post-burst throttled region** (breakpoint = 16384). From the measured transition table
(`AUDIT_recirc_clock.md:92-94`: 22000→60.17 ms, 30000→137.1 ms, ~9.7 µs/pass post-burst):
```
26153 passes ≈ 60.17 ms + (26153 − 22000) × 9.7 µs ≈ ~100 ms actual hold
```

**Finding:** `setup.py --hold-ms 17` produces a **~100 ms hold, ~6× the requested 17 ms.** The script
even **prints** "DEADLINE hold ~17.00 ms … MEASURED" (`:440-441`) — the printed number is the
*requested* value, not the achieved one, so the operator is told 17 ms while the switch holds ~100 ms.
The default is dangerously wrong above ~10 ms.

**Mitigation in place for the sweep:** `burst_sweep.sh` does **not** use `--hold-ms`; it drives
`hold_probe.py --hold-passes <hp>` with a **per-point Newton calibration** on the switch-side
`last_hold_reg` (`burst_sweep.sh:44-58`), so the sweep is immune. The bug bites only a direct
`setup.py --hold-ms` invocation.

---

## Q10 — Microbench HOLD vs the actual `dcrn_defense1/2` release mechanisms

The three release mechanisms are **fundamentally different**. The microbench cover=OFF path
(`SEQ_HELD_DL`, release on `hold_passes==0`, `queue_microbench.p4:656`) is neither defense — it is a
**pass-count retention proxy** that imitates the *shape* of Defense 2 but not its governance.

**Release governance:**
- **Defense 1 — EVENT.** The held ACK releases when the response arrives: `respseen_getclr` polls
  `reg_resp_seen` (`dcrn_defense1.p4:513-514`), set by the response frame (`:608`). **No wall clock,
  no timestamp read for release** (`:10-12`).
- **Defense 2 — WALL-CLOCK DEADLINE.** The held response releases when `now_eff >= reg_deadline`
  (`dcrn_defense2.p4:396-401`, executed `:548`); `reg_deadline = t_ack + G_i` written once at the ACK
  (`:458,525`), and the *clock* is **refreshed every recirc pass** via `bridge.tstamp_tick`, which
  egress rewrites from `global_tstamp` each pass (`:540,688`).
- **Microbench cover=OFF — PASS-COUNT BUDGET.** Releases purely because the packet has looped
  `hold_passes` times (`queue_microbench.p4:656,684`). It reads `global_tstamp` **only for
  MEASUREMENT** (`mb.t_in` at encap `:736`, `hold_ns = now − t_in` at release `:660`), **never for
  the release decision** — so it **sidesteps the exact hard problem Defense 2 solves** (the
  `global_tstamp`-does-not-refresh-on-recirc issue that forces Defense 2's per-pass `bridge.tstamp_tick`
  rewrite). Its "deadline" is a counter, so it never has to refresh a clock.

The microbench thus does **not** model Defense 1 at all (no response-arrival event), and models
Defense 2's *retention duration* with a pass-count stand-in, not its ACK-anchored refreshing-clock
deadline.

**Per-flow vs stream:**
- Both defenses key a **CRC16 hash of `{client_ip, server_ip, client_port}`**
  (`dcrn_defense1.p4:360,476`; `dcrn_defense2.p4:359,486`) into **65536-entry per-flow register
  arrays** (`d1:366-370`; `d2:363-368`), holding **one outstanding transaction per flow**
  (`ACK_DELAY_STATE_MACHINE.md:21`), armed on an exact expected-ACK match (`d1:569`; `d2:520`) and a
  DNP3 func-code allowlist (`d1:449-454`; `d2:448-453`).
- The microbench has **no flow key, no 5-tuple, no per-flow register** — cover=OFF holds a **stream**
  via the packet's own `hold_passes` (`queue_microbench.p4:695-697`). It cannot model per-flow arming,
  the expected-ACK match, or one-txn-per-flow occupancy.

**Transport & classification:**
- Defenses: **TCP/IPv4 port 20000**, pure-ACK = `payload_len==0` + TCP-flag qualify
  (`d1:480-481,562`; `d2:489-490,510-511`), DNP3 func-code arming.
- Microbench: **synthetic UDP**, class by dport 20001–20006 (`queue_microbench.p4:483-496`); never
  distinguishes ACK from response. Real DNP3 (TCP) fails open through it (Q4).

**HOLD queue / rate / burst — a 10× mismatch:**

| | Microbench (cover=OFF) | Defense 1 | Defense 2 |
|---|---|---|---|
| HOLD qid | **6** (`qmb:144`) | **5** (`d1:65`) | **5** (`d2:78`) |
| HOLD loop rate | **100000 pps** (`setup:104`) | **10000 pps** (`d1_setup:56`) | **10000 pps** (`d2_setup:56`) |
| Pass latency | ~0.617 µs pre-burst → ~10 µs post-burst | ~100 µs/pass | ~100 µs/pass |
| max_burst_size | 16384 | 16384 (`d1_setup:145`) | 16384 (`d2_setup:150`) |

The microbench holds at a **10× faster loop** → ~10× more recirc passes for the same wall-clock hold
→ ~10× the recirc bandwidth per ms held, and the 16384-pass breakpoint lands at a *different*
wall-clock hold (~10 ms in the microbench vs ~1.6 s at 10 000 pps). **Neither the microbench's
`hold_passes → ms` calibration nor its recirc-cost transfers to the real defenses.** A 60 ms
Defense-2 hold ≈ 600 passes at 10 000 pps; the microbench's 60 ms ≈ 6 000–9 000 passes at 100 000 pps.

**Ordering & fail-open:**
- Defense 1 enforces ACK-before-response with an **explicit zero-inversion token** `reg_ack_gone` +
  a shared FIFO at qid 0 + `GUARD_PASSES=4` (`d1:519-520,546-548,65-66`). The microbench
  **deliberately omits** this (`queue_microbench.p4:471-475`).
- Fail-open: defenses cap at `ACK_MAX_PASS/RESP_MAX_PASS=65536/131072` (`d1:80-81`) and
  `MAX_PASS=65536` (`d2:86`), never dropping. The microbench has **no explicit MAX_PASS** — the
  `hold_passes` budget *is* the terminator and the fail-open bound (`queue_microbench.p4:648-653`).

**Byte preservation — read this carefully, the microbench is WEAKER here than the defenses.** Both
strip their internal encap with no byte edit to the carried bytes (defenses pop `bridge` — Defense 1
in **egress** `d1:727-728`, Defense 2 in **ingress** `d2:559-560`, no checksum/seq edit `d1:639`,
`d2:615`; microbench strips `mb`, `queue_microbench.p4:677-678`). BUT the microbench **also PADS** the
frame (`pad_s1/pad_s2`, `queue_microbench.p4:716-717`), so the **released microbench frame is NOT
wire-byte-identical to the input** — it is larger by the filler. The property that transfers is only
"**the recirc HOLD does not corrupt the bytes it carries**"; it is **not** a proof that an arbitrary
live DNP3/TCP frame stays wire-byte-identical after a size transformation. The frozen defenses do
**no** padding, so they release the response **byte-for-byte** (`d2` evidence: 99/99 byte-identical) —
they are the stronger byte-preservation case, and the digest (metadata-only, Q13) grafts onto them
without disturbing that.

**Bottom line for Q10:** the cover=OFF microbench is a **recirculation-retention + timing-precision
calibration instrument** sharing only the *hold-on-recirc + byte-clean-release* substrate with the
real defenses. It uses a **pass-count proxy** for Defense 2's refreshing wall-clock deadline, has
**no per-flow state**, **no ACK/response classification**, **no ordering token**, and a **10×
different hold-loop rate**; it does **not** model Defense 1 at all. Its value is (a) validating the
digest telemetry and (b) characterizing the recirc breakpoint — **not** producing CLRT numbers for
the Case-A defenses.

---

## Q11 — Branch-by-branch feature matrix (microbench vs Defense 1 vs Defense 2)

| Feature | **queue_microbench (cover=OFF)** | **Defense 1 — hold ACK** | **Defense 2 — hold response** |
|---|---|---|---|
| Program | `queue_microbench.p4` (review artifact, `:4`) | `dcrn_defense1.p4` (frozen) | `dcrn_defense2.p4` (frozen) |
| What is held | any classified UDP frame (a stream) | the pure ACK | the response |
| Release governance | **pass-count budget** `hold_passes==0` (`:656`) | **event** `reg_resp_seen` poll (`d1:513-514`) | **wall-clock deadline** `now_eff≥reg_deadline` (`d2:396-401,548`) |
| Deadline clock | none — counter proxy; `t_in` measured only (`:660,736`) | none | ACK-anchored `t_ack+G_i`, refreshed per pass via `bridge.tstamp_tick` (`d2:458,540,688`) |
| Hold primitive | dp68 recirc, qid **6** (`:144,533-536`) | dp68 recirc, qid **5** (`d1:65,530-531`) | dp68 recirc, qid **5** (`d2:78,566-567`) |
| Hold loop rate | **100000 pps** (`setup:104`) | **10000 pps** (`d1_setup:56`) | **10000 pps** (`d2_setup:56`) |
| Burst credit | 16384 (`setup:280`) | 16384 (`d1_setup:145`) | 16384 (`d2_setup:150`) |
| Flow state / key | **none** (stream; per-packet `hold_passes`) | CRC16{cip,sip,cport}→65536 regs (`d1:360,366-370,476`) | CRC16{cip,sip,cport}→65536 regs +2 global (`d2:359,363-368,486`) |
| Arm trigger | UDP dport match (`:483-496`) | DNP3 func-code + exact expected-ACK (`d1:449-454,569`) | DNP3 func-code + exact expected-ACK (`d2:448-453,520`) |
| Transport | synthetic **UDP** 20001–20006 | **TCP/IPv4 :20000** | **TCP/IPv4 :20000** |
| ACK vs response | not distinguished | `payload_len==0`+TCP-flags (`d1:480-481,562`) | `payload_len==0`+TCP-flags (`d2:489-490,510-511`) |
| Ordering guard | **omitted** by design (`:471-475`) | **zero-inversion token** `reg_ack_gone`+FIFO+`GUARD_PASSES=4` (`d1:519-520,546-548,75`) | **not needed** (ACK never held, `d2:530`) |
| Fail-open ceiling | none explicit — budget is the bound (`:648-653`) | `ACK_MAX_PASS=65536`/`RESP_MAX_PASS=131072` (`d1:80-81`) | `MAX_PASS=65536` (`d2:86`) |
| Occupancy control | none (cover=OFF) | per-flow `flow_has_held_ack` TAS (`d1:575`); `HELD_MAX` dead (`d1:83`) | global `reg_held_count` vs `HELD_MAX=256` (`d2:87,414-419`) |
| Byte preservation | yes; `mb` strip in ingress (`:677-678`) | yes; `bridge` strip in **egress** (`d1:727-728`) | yes; `bridge` strip in **ingress** (`d2:559-560`) |
| Checksum/seq edit | none (`:151-156`) | none (`d1:639`) | none (`d2:615`) |
| Size axis | fixed 64→128/256 B pad (`:215-216,716-717`); dead in cover=OFF | none (timing only) | none (timing only) |
| Cover / chaff | OFF (idle tick dropped, `:612-614`); WINDOW/CONT optional | none | none |
| Release reason(s) | one: `PASS_BUDGET` (`:669`) | `RESP_SEEN` / `ACK_MAX_PASS` fail-open | `DEADLINE` / `MAX_PASS` fail-open |
| Telemetry | learning digest, `telemetry_enable`-gated (`:672-676,779-782`) | **none** | **none** |
| Metronome / pat_state | present but disabled in cover=OFF (`:582` unreachable, Q2) | n/a | n/a |
| Target set-point | `hold_passes` (calibrated) | δ = `GUARD_PASSES=4` (compiled) | `G_i` runtime-loadable, default 60 ms (`d2_setup:75,184-208`) |

**Reading the matrix:** the microbench overlaps the defenses on exactly three rows — *hold primitive*
(dp68 recirc), *burst credit*, and *byte preservation*. On every other row that matters for a CLRT
defense (governance, flow state, classification, ordering, rate, release reason, occupancy) it
diverges. The telemetry row is the microbench's genuine new capability and the only one worth porting
back (Q13).

---

## Q12 — Which results stay VALID, which must be WITHDRAWN or FLAGGED

### VALID (keep)
1. **`RESULTS_switchside.txt` (max-rate PPS shaper).** Switch-side MAC/queue counters. Max-rate
   shaper is a **CAP, not a pacer**: sparse input < R passes through unchanged (`:25-29`); low-R
   backlog clumps in ~4.4 s bursts (`:10-19`). Solid negative.
2. **`RESULTS_minrate_dwrr.txt` (min-rate + DWRR).** Both are **backlog disciplines**, not
   sparse-flow pacers (`:15-27,29-44,46-53`). The one wrong number (DWRR silently capped at the
   stale min-rate) was caught and re-run (`:36-41`). Solid negative — supports the "TM scheduling
   cannot pace a sparse flow" thesis.
3. **`RESULTS_ab_digest.txt` (telemetry OFF vs ON A/B).** Digest perturbation on the switch-side
   hold = **0.0000 ms** (`:13-15`); completeness holds (records == ctr_grad == ctr_digest_emit ==
   receiver = 100, 0 dup/missing, all PASS_BUDGET, `:16-18`). Valid **with its stated caveat**: the
   hold is the switch **release-decision** timestamp, not physical wire departure, which was not
   independently measured (`:26-30`).
4. **`AUDIT_recirc_clock.md`.** Supersedes the withdrawn ceiling. Deterministic `ctr_recirc` proves
   passes = hold_passes exactly; transition characterized (0.617 µs pre-burst, breakpoint exactly
   16384, ramps to ~9.7 µs post-burst). Valid.
5. **35-point burst sweep — INSTRUMENTATION validity (§D).** All 35 points: `digest_valid=true`,
   `loss=0`, `ctr_grad == ctr_digest_emit == records == 110`. The digest telemetry itself is
   validated across the whole grid — the sweep's authorized purpose, achieved.

### WITHDRAWN
6. **`RESULTS_hold_timing.txt` — the "~3.17 ms ceiling / ~4096-pass plateau."** Already self-withdrawn
   in its header (`:1-5`): a burst-pcap artifact from overlapping long holds mispairing tx↔rx. Only
   the **sub-burst points remain valid** (1700 passes → 1.14 ms; 3076 → 1.98 ms, `:15-23`). The
   ceiling claim and the "needs the DCRN fix for 17-25 ms" claim (`:25-31`) are withdrawn.

### VALID-BUT-FLAGGED (the sweep's HOLD-TIME achievement)
7. **Two clean calibration regimes:**
   - **Small burst credit (B=256):** fully throttled (~10 µs/pass); calibrates to **< 0.35 ms
     target-error, ~0.31 ms jitter across 5–40 ms** (runs 101–105). Best for the 17/25 ms window.
   - **Pre-burst (hold_passes < burst credit):** deterministic sub-µs, **zero jitter** (run 126/131
     B≥8192,T=5 → 5.042 ms σ=0; run 132 B=16384,T=10 → 10.08 ms σ=0). Precise but only ~5–10 ms.
8. **Straddle regime (intermediate B, hp near the 16384 breakpoint):** usable but **~1.23 ms jitter**,
   calibration-sensitive (runs 106–130; several with 1.7–3.1 ms target-error). Report with the jitter,
   not as precise points.
9. **`run 135` (B=16384, T=40) — CALIBRATION FAILURE, do NOT report as a 40 ms point.** Achieved
   **median 359.9 ms, σ 239.7 ms, target-error 320 ms** for a 40 ms target. Digest internally valid
   (110/110, loss 0), but the hold is ~9× the target — extreme post-breakpoint sensitivity
   (hp 18826→20474 jumps the hold 24 ms→360 ms). **Flag as evidence of breakpoint instability, not a
   40 ms measurement.**

### Cross-cutting caveat on ALL hold-time numbers
`failopen_delta` is **1–3 on every sweep point** (§D) — a few stray/calibration frames on the
fail-open path per window. They are **not** the measured reals (fully accounted: `rx_count = records
= 110`, `non_pass_budget = 0`), so "zero fail-open **among the measured reals**" holds, but the
counter is not literally zero and the report should say so.

---

## Q13 — Minimum instrumentation to add a validated digest to `dcrn_defense1/2` WITHOUT changing release semantics

The microbench's digest is metadata-only (deparser, `queue_microbench.p4:779-782`; A/B-proven to
perturb the switch-side hold by **0.0000 ms**, `RESULTS_ab_digest.txt:13-15`). It grafts onto the
defenses because both already carry an internal `bridge` header and have a single release edge:

**1. Reuse the existing bridge header — add measurement-only fields, no new header.** Defense 1's
bridge has `pass_count` + an unused `tstamp_tick` (`d1:122,731`); Defense 2's carries a per-pass
`tstamp_tick` (`d2:688`). Add `t_in` (bit<32>), `flow_id_echo` (bit<16>, the CRC16 already computed),
`target` (δ passes / `G_i` ticks), `run_id` (bit<16>), riding the recirc loop like the microbench's
`mb.t_in/seq_id/target_passes/run_id` (`queue_microbench.p4:178-182`).

**2. Capture at the ONE hold-enter site, measure at the ONE release site — `global_tstamp` for
MEASUREMENT only (never gate release on it).** Defense 1: capture `t_in = global_tstamp` at ACK
hold-enter (`d1:585-586`); compute `hold_ns` on the ACK release pass (`ack_release==1`, `d1:519`) —
the release predicate `rs` (`d1:513-514`) is untouched. Defense 2: capture `t_in` at response
hold-enter (`d2:598-599`); compute `hold_ns` on release (`do_release==1`→PORT_VISION, `d2:562`) —
the `check_deadline` SALU (`d2:396-401`) is untouched.

**3. Gate the emit on `telemetry_enable` (default 0), count against the EXISTING release counter.**
Copy the microbench's A/B gate verbatim (`queue_microbench.p4:414-416,672-676`): `if
(telemetry_enable==1) { digest_type = DIGEST_TELEM; ctr_digest_emit.count(); }`, add a `run_id_reg`
(`:406-408`), emit `Digest.pack({...})` in the deparser. Everything else on the release path is byte-
and timing-identical for enable=0 vs 1 — the A/B property already proven.

**4. EXTEND `release_reason` — the one schema change the defenses require.** The microbench emits a
single reason `PASS_BUDGET` (`queue_microbench.p4:669`); the collector already anticipates the
extension (`mb_digest_collector.py:28`). The defenses have multiple causes: Defense 1 `RESP_SEEN`
(normal, `d1:514`) vs `ACK_MAX_PASS`/`RESP_MAX_PASS` fail-open (`d1:80-81,516`); Defense 2 `DEADLINE`
(normal, `d2:548`) vs `MAX_PASS` fail-open (`d2:86,557`). Set `release_reason` to the actual cause so
a fail-open is visibly separable from a real release.

**5. Validation invariant (reuse `mb_digest_collector.py` structure):** a run is VALID iff
`collector_records == ctr_digest_emit_delta == <existing release counter> == receiver count`, 0
dup/0 missing flow-correlated records (`mb_digest_collector.py:96-100`). Seed a `run_id` per config
so batched records never mix (`:53-58`).

**Per-defense telemetry schema and primary metric (as specified for the graft):**

*Defense 1 (`dcrn_defense1_telem.p4`) — export:* `run_id`, `flow_id`, transaction generation,
request timestamp, pure-ACK arrival timestamp, response-event timestamp, ACK release timestamp,
response release timestamp, ACK pass count, response pass count, ACK release reason, response release
reason, ordering result. **Primary metric `E_D1 = t_ACK_release − t_response_event`** (the ACK's
release latency after the response is seen). Normal `ACK release reason` MUST remain
**`RESPONSE_EVENT`**; `ACK_MAX_PASS` / `RESP_MAX_PASS` remain **fail-open only**. The ordering result
records whether the ACK egressed before the response (the `reg_ack_gone` invariant, `d1:519-520`).

*Defense 2 (`dcrn_defense2_telem.p4`) — export:* `run_id`, `flow_id`, transaction generation, ACK
timestamp, configured deadline, response-arrival timestamp, response-release timestamp, response pass
count, release reason. **Primary metric `E_D2 = t_response_release − t_ACK-relative_deadline`** (the
overshoot past the intended deadline). Normal `release reason` MUST be **`TIMESTAMP_DEADLINE`**, and
the experiment must **separately identify** these reasons:
- `TIMESTAMP_DEADLINE` — normal (`now_eff >= reg_deadline`, `d2:396-401,548`);
- `FAIL_OPEN_MAXPASS` — hit `MAX_PASS=65536` (`d2:86,557`);
- `AMBIGUITY_FAIL_OPEN` — a released-on-first-arrival / clock-ambiguity release that is not a clean
  deadline (so a "clock frozen vs matured" case cannot be silently counted as a deadline hit);
- `BYPASS` — combined/ineligible frame forwarded unchanged.

Extending `release_reason` to this enumeration is what turns the digest from "it released" into
"**it released for the right reason at the right time**" — the distinction the microbench's single
`PASS_BUDGET` reason cannot make.

**Stage-cost caveat (compile off-switch first):** the microbench added the digest at **7/12 ingress
stages with no increase** (`QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md:699-701`). The defenses are
deeper (Defense 1's 17-deep chain; both near 9/12). Four PHV bridge fields + one subtract + a constant
`digest_type` gate + one counter is light, but must be compiled off-switch (`bf-p4c` 9.13.1 fit-check,
then on-switch 9.13.2) **before any load**, must **not** add per-pass work (only enter + release
edges), and must be done on a **copy** (`dcrn_defense{1,2}_telem.p4`) so the frozen baseline stays
intact — load gated on explicit authorization.

---

## Q14 — Smallest next hardware experiment (Defense 1 / Defense 2 / recirc cost)

### The burst-sweep verdict (grounded in Q10–Q11): CONSIDER IT COMPLETE — do NOT resume it

The sweep is finished (35/35, "burst sweep DONE"). Its **authorized purpose — validate the digest
telemetry — is achieved and passed** (all 35 `digest_valid=true`, `grad==emit==records==110`,
`loss=0`). Q10 shows the sweep's *timing-precision-vs-target* numbers are **microbench-specific**:
taken at qid 6 / 100 000 pps with a **pass-count proxy**, and neither the `hold_passes→ms` calibration
nor the recirc-cost transfers to the real defenses (qid 5 / 10 000 pps, event / refreshing-wall-clock
release). More burst points would only further characterize the microbench's own breakpoint, already
well-characterized (§D). **Marginal value of resuming: low. Of pivoting to instrument the real
defenses: high.** Recommendation: **close the sweep; do not run additional burst/rate/concurrency/
background points on the microbench.**

### What is ALREADY proven (do not re-discover it)

The working notes record that the **basic mechanisms already ran on Tofino**, so the next work is
characterization, not rediscovery:
- **Defense 1 is substantially proven:** defended CLRT collapsed to **~0.026–0.033 ms**, ACK release
  was response-event governed, ACK↔response ordering held, `ACK_MAXPASS=0` / `RESP_MAXPASS=0` (no
  fail-open fired), byte identity preserved, continuous operation passed **120 transactions** on one
  connection, and faithful SEL-751 replay passed. → **The open question is not "does it work"; it is
  how much internal recirculation event-governed ACK retention consumes, and how stable the
  response-event→ACK-release delay is under concurrency and background load.**
- **Defense 2 has supporting evidence but needs cleaner characterization:** the response-delay
  implementation produced a **device-independent CLRT ≈ 107 ms** for two input timing profiles
  (`evidence/defense2_hardware/RESULT.md`), but the configured parameter was **`G_i` = 60 ms** — an
  **~47 ms overshoot** attributed to recirculation/drain behavior. That supports the security concept
  but does **not** yet establish a clean deadline mechanism. → **The open question is whether the
  response release follows the refreshing ACK-relative timestamp deadline with BOUNDED overshoot, or
  is substantially influenced by recirculation/drain/fail-open** — which requires timestamp telemetry
  *inside* Defense 2 (Q13, metric `E_D2`).

### Smallest next hardware experiment (all gated on explicit authorization; frozen files copied, not edited)

**Track 1 applied to Defense 2 first** (its release *shape* is the one the microbench proxied, and its
47 ms overshoot is the sharpest open question):

1. **Defense 2 deadline characterization.** Graft the non-invasive digest (Q13) onto a copy
   `dcrn_defense2_telem.p4`; compile off-switch; on authorization, load and run a **sparse
   single-flow** TCP test at a known `G_i` (start at 60 ms, `defense2_setup.py:75`, then a small
   sweep). Report `E_D2 = t_response_release − deadline` per transaction with the reason split
   (`TIMESTAMP_DEADLINE` vs `FAIL_OPEN_MAXPASS` vs `AMBIGUITY_FAIL_OPEN`), to establish whether the
   **~47 ms overshoot is bounded deadline behavior or recirc/fail-open contamination** — the exact gap
   the 107 ms result left open. Confirm completeness (`records == response-release counter ==
   receiver`, 0 dup/missing).
2. **Defense 1 retention-cost + stability.** Same graft on `dcrn_defense1_telem.p4`; since the CLRT
   reduction is already proven, measure `E_D1 = t_ACK_release − t_response_event` and the **ACK pass
   count / recirc consumption** per transaction (reasons split `RESPONSE_EVENT` vs the fail-open caps),
   i.e. how much internal recirculation event-governed ACK retention costs and how stable the
   event→release delay is.
3. **Recirc-cost at the real rate.** During both, read **dp68 port counters** (passes/frame, recirc
   pps, bytes/frame) at **qid 5 / 10 000 pps** — the microbench's qid 6 / 100 000 pps recirc-cost does
   not transfer, so measure on the defenses directly. Compare event-hold (D1) vs deadline-hold (D2)
   overhead.

Each is a **single sparse isolated transaction on a frozen-logic defense COPY + a metadata-only
digest**, no datapath release change, no physical SEL-751, compiled off-switch first, loaded only on
authorization. **Then** run the concurrency and background-load experiments.

---

## Q15 — The ACK-suppression alternative (ANALYZE, do NOT implement)

A **third** Case-A timing-obfuscation option (beside Defense 1 = hold ACK, Defense 2 = hold response)
is to **suppress the SEL-751 pure ACK entirely**, so the separate-ACK device presents *no standalone
ACK* → no CLRT (ACK→response gap) to fingerprint. This is the **B-MODE** direction in the design study
(`case_b_defense_design.md:107-125`): "suppress its redundant pure ACK (owned socket: coalesce,
proven Phase-05; un-owned: Tofino `mark_to_drop` of the exact-qualified ACK)." Its mirror — *synthesizing*
a fake pure ACK to make a combined device look separate — is analyzed in the doc's §5 (`:128-176`) and
**rejected by all four experts** (byte-generating, needs a `Checksum()` extern, fabricates/source-spoofs
a protected IED with NERC-CIP exposure, manufactures a constant-CLRT tell). **Suppress, never
fabricate** (`:172-176`).

**TCP-correctness conditions for inline pure-ACK suppression (un-owned socket, Tofino `mark_to_drop`):**
1. **Drop only a genuine pure ACK** — `payload_len==0` AND ACK-only flags (SYN/RST/FIN clear). The
   defenses already qualify this exactly (`dcrn_defense1.p4:480-481,562`). Never drop a data-bearing
   segment, a SYN/FIN/RST, or a window update carrying no ack the response also carries.
2. **A later frame must re-acknowledge the dropped bytes within the master's RTO.** The outstation's
   DNP3 response carries an ACK covering the master's request; dropping the pure ACK is safe **iff**
   that response's `ack_no ≥` the dropped ACK's `ack_no` AND the response reaches the master **before
   its request-retransmit RTO fires** (measured Vision RTO ≈ 211 ms, `case_b_defense_design.md:52`).
3. **Incompatible with a large co-located response hold.** If Defense 2 also holds the response past
   the RTO on the same flow, the master gets *no* ack for its request → it retransmits. So
   ACK-suppression must not be combined with a response hold long enough to cross the RTO — the two
   timing defenses **couple through the RTO budget** and cannot be stacked naively.
4. **Idempotent duplicate handling.** If the master does retransmit (ACK suppressed + response late/
   lost), the outstation sees a duplicate request and may re-arm / re-respond → double response. The
   defense's per-flow arm + expected-ACK machinery (`d1:569`; `d2:520`) must treat the retransmit
   idempotently (do not double-hold, do not double-count occupancy).
5. **No window stall.** DNP3 is small and one-outstanding, so removing one pure ACK is unlikely to
   stall the master's send window; but confirm the outstation's receive-window advance does not
   *depend* on that ACK for any burst (e.g. SBO select→operate) before deploying.

**Scope / verdict (analysis only):** ACK-suppression is the **cheapest** Case-A option — a single
`mark_to_drop`, no hold, no recirc loop, no per-flow deadline register — and it is byte-preserving in
the sense of modifying no bytes (it removes a whole frame). But it (a) is safe **only toward
"combined"** (remove, never fabricate), (b) changes the device's observable **ACK mode**
(separate→combined), a *stronger* signal change than CLRT normalization — which **helps** iff the
population is homogenized toward combined (SEL-751 made to match natively-combined AB1400/ION7550) and
**hurts** if the suppressed device then stands out, and (c) couples to the RTO budget so it cannot be
stacked with a long response hold. Per the directive and the design study: **analyze, do not
implement now**; confine any owned-socket ACK coalescing to a DPU/host (proven Phase-05), and never
fabricate an ACK inline on the Tofino.

---

## D. Burst-sweep aggregate (35/35 points) — evidence for Q12

Source: `runs/burst_sweep/results.jsonl` (35 rows). Config (frozen, authorized): rate = 100000 pps,
samples = 110, concurrency = 1, background = 0, cover = OFF, metronome = OFF, telemetry = ON.
Switch-side digest = hold; Hulk dp9 hairpin = count/seq only.

**Every point:** `digest_valid=true`, `loss=0`, `ctr_grad_delta == ctr_digest_emit_delta ==
n_digest == 110`, `pass_count == hold_passes` (single value). `failopen_delta` = 1–3 (stray, not the
reals).

| run | B | T (ms) | hold_passes | median (ms) | p95 | σ | \|err\| | note |
|---|---|---|---|---|---|---|---|---|
| 101 | 256 | 5 | 740 | 4.891 | 5.39 | 0.31 | 0.11 | throttled, clean |
| 102 | 256 | 10 | 1240 | 10.23 | 10.70 | 0.31 | 0.23 | throttled, clean |
| 103 | 256 | 17 | 1940 | 16.77 | 17.24 | 0.31 | 0.23 | throttled, clean |
| 104 | 256 | 25 | 2740 | 25.27 | 25.75 | 0.31 | 0.27 | throttled, clean |
| 105 | 256 | 40 | 4240 | 40.33 | 40.82 | 0.31 | 0.33 | throttled, clean |
| 106–110 | 512 | 5–40 | 1038–4492 | — | — | ~1.24 | up to 1.55 | straddle, jittery |
| 111–115 | 1024 | 5–40 | 1531–4961 | — | — | ~1.23 | up to 1.79 | straddle, jittery |
| 116–120 | 2048 | 5–40 | 2422–5725 | — | — | ~1.2 | up to 3.12 | straddle, jittery |
| 121–125 | 4096 | 5–40 | 4536–8349 | — | — | ~1.23 | up to 1.55 | straddle, jittery |
| 126 | 8192 | 5 | 8104 | 5.042 | 5.042 | **0.00** | 0.04 | pre-burst, exact |
| 127–130 | 8192 | 10–40 | 9164–12417 | — | — | ~1.23 | up to 1.28 | straddle |
| 131 | 16384 | 5 | 8104 | 5.042 | 5.042 | **0.00** | 0.04 | pre-burst, exact |
| 132 | 16384 | 10 | 16207 | 10.08 | 10.08 | **0.00** | 0.08 | pre-burst, exact |
| 133 | 16384 | 17 | 17711 | 15.11 | 16.99 | 1.22 | 1.89 | just past breakpoint |
| 134 | 16384 | 25 | 18826 | 24.09 | 25.97 | 1.24 | 0.91 | just past breakpoint |
| 135 | 16384 | 40 | 20474 | **359.94** | 772.67 | **239.70** | **319.94** | **CALIBRATION BLOWUP** |

Takeaways feeding Q12: (a) the **digest instrument is valid across the whole grid**; (b) precise holds
come from either a **small burst credit** (throttled-linear, B=256 → <0.35 ms error across 5–40 ms) or
**pre-burst** (hp < burst → zero jitter, ≤~10 ms); (c) the region **straddling the 16384 breakpoint**
is jittery (~1.23 ms) and, at run 135, catastrophically unstable.

---

## Bottom Line

1. **The cover=OFF microbench is a recirculation-retention + timing-precision instrument, NOT the
   Case-A defense.** It shares only *hold-on-recirc + byte-clean-release* with `dcrn_defense1/2`. It
   releases on a **pass-count proxy** (`hold_passes==0`), has **no per-flow state, no TCP/DNP3/ACK
   classification, no ordering token**, holds a **stream**, and runs at a **10× faster hold-loop**
   (qid 6 / 100 000 pps vs qid 5 / 10 000 pps). It **does not model Defense 1** (event-governed) at
   all and only proxies Defense 2's *shape* (Q10, Q11).
2. **What the sweep validated is the digest telemetry** — 35/35 `grad==emit==records`, `loss=0`,
   A/B shift 0.0000 ms. That instrument, and byte-preservation, are the only things that transfer to
   the real defenses. **The timing-precision numbers are microbench-specific and do not transfer.**
3. **Close the burst sweep; do not resume it.** Its authorized purpose is met; more points add only
   marginal microbench self-characterization (Q14).
4. **Results:** VALID — the three TM-scheduler negatives (`switchside`, `minrate_dwrr`), the A/B
   digest, `AUDIT_recirc_clock.md`, and the sweep's instrumentation validity. WITHDRAWN — the
   `RESULTS_hold_timing.txt` "3.17 ms / 4096-pass ceiling" (already self-flagged). FLAG run 135 as a
   breakpoint blowup, not a 40 ms point (Q12).
5. **The next high-value step is Track 1:** graft the *validated, non-invasive* digest onto **copies**
   of the frozen defenses (`dcrn_defense{1,2}_telem.p4`), extend `release_reason`, and run one sparse
   single-flow validation each (Defense 2's deadline hold, Defense 1's CLRT reduction) plus dp68
   recirc-cost at the real 10 000-pps rate (Q13, Q14). All off-switch-compiled first, loaded only on
   authorization, frozen baseline untouched.
6. **Housekeeping:** patch the disproven ceiling / `0.65 µs` / dp8-vs-dp9 claims in
   `queue_microbench_setup.py:104,135-145,431-445,287` (comment/print only) so the operator-facing
   script matches the audit; fix the default `--hold-ms 17` (produces ~100 ms, Q9); optionally rename
   the overloaded fail-open `QID_HOLD` on dp9 (Q5). None of these touches the datapath.
7. **ACK-suppression** is a real third Case-A option (cheapest, byte-preserving-by-removal) but
   couples to the master's RTO and changes ACK *mode*; **analyze, do not implement** — suppress
   (never fabricate), owned-socket coalescing on a DPU/host only (Q15).

---

## E. Terminology correction — "Defense 2" is NOT "Case B"

Per the locked taxonomy (`CASE_A_TERMINOLOGY.md`): **Case A** = separate pure ACK then response
(SEL-751); **Defense 1** = hold ACK until the response event; **Defense 2** = forward ACK, delay the
response to an ACK-relative deadline; **Case B** = combined ACK-bearing response (AB1400/ION7550), no
standalone ACK, no CLRT. **Defense 2 lives under Case A. It must never be called "Case B."**

The **107 ms hardware experiment** is therefore correctly described as
**"Case A, Defense 2: ACK-relative response-delay normalization"** — *not* a Case-B (combined-response)
defense.

The living/current docs are already consistent (`CASE_A_TERMINOLOGY.md` locked this 2026-07-21;
`WORKING_NOTES.md` uses "Case B" only for the combined-ACK devices). The mislabel survives only in
**frozen** artifacts, which are **not edited now** (freeze) and are **cataloged here for correction
when the telemetry copies are built**:

| Frozen artifact | Mislabel | Correct at |
|---|---|---|
| `ack_delay/defense2_setup.py:73-74,101,180` | `--mode {forward, case-b}` (the response-delay mode is named `case-b`) | new telem-copy setup |
| `ack_delay/refmodel/defense2_state_machine.py:47` `simulate_case_b` | function name | telem-copy refmodel |
| `ack_delay/refmodel/defense1_state_machine.py:173,198` `simulate_case_b` / `simulate_case_b_hold` | function names | telem-copy refmodel |
| `ack_delay/tests/test_defense1.py`, `test_defense2.py` | call `simulate_case_b*` | telem-copy tests |
| `ack_delay/dcrn_defense2.p4` (comments, e.g. "core Case B" `:530`; banner still `dcrn_ackB.p4`) | comment labels | telem copy `dcrn_defense2_telem.p4` |
| `ack_delay/evidence/defense2_hardware/RESULT.md:28` refers to `caseB_analysis.txt` | evidence filename | leave evidence frozen; note in the paper's data map |

(The frozen `dcrn_defense{1,2}.p4` / `defense{1,2}_setup.py` are **not** modified — the telemetry
work happens on COPIES, which is where the correct naming is applied.)

---

## F. Housekeeping done in this pass (non-datapath, non-frozen; 2026-07-22)

Applied per the "audit and correct stale comments / setup output, without changing preserved result
artifacts" step:
- `queue_microbench_setup.py` — replaced the disproven "~3.17 ms / ~4096-pass ceiling" and
  single-`0.65 µs` claims with the measured nonlinear calibration (0.617 µs pre-burst → ~9.7 µs
  post-burst, no ceiling); `--hold-ms` now labelled a pass-count PROXY (not an absolute deadline) and
  its print/warning corrected to state the ~100 ms overshoot for targets > ~10 ms (Q9); the `--mode
  5` doc-drift "dp8" comments corrected to dp9-hairpin. **Datapath and the compiled `queue_microbench.p4`
  are untouched**, so the loaded-program sha `0239af8f58d8a014` and the run manifests still match.
- `runs/burst_sweep/INVALID_run135.md` — marks run 135 invalid for target-accuracy analysis without
  editing the preserved `results.jsonl`.
- The compiled `queue_microbench.p4` carries one loose comment (`:648-653`, calling the pass-budget
  hold an "absolute-deadline") that is **left as-is** to preserve the loaded-sha↔file linkage; it is
  flagged here and should be corrected only at the microbench's next recompile.
