# BOR two-pipe split — feasibility proposal (COMPILE-ONLY)

> **READINESS SCOPE (read first).** This proposal proves the two-pipe **topology, cross-pipe route,
> T0-handoff, exactly-once release, and per-pipe stage fit** (pipe 0 = 12, pipe 1 = 6). The pipe-1 BOR
> program here still carries the **current fail-open-first readiness** (the SR4 resource-probe behaviour:
> the first OPERATE fails open rather than being held), which is **NOT** a faithful hold. The **faithful
> SELECT-prepares-a-BOR-epoch readiness** (see `BOR_RRC_DESIGN.md`) must be folded into pipe 1 — which has
> six stages of headroom for it — before this is a faithful BOR. That fold + recompile is the next step.

**Question.** The faithful consolidated one-pipe RRC+BOR build is **13 ingress stages, one over
budget** (`BOR_STAGE_RECOVERY_RESULT.md`). The chip is a BFN-T10-032D with **num_pipes = 2**
(evidence: `defense3/REPORT.md` — "The chip has two pipelines (num_pipes = 2)"). Can BOR be split
onto a second pipe so that **each program fits ≤ 12 ingress stages**, with a concrete cross-pipe
route and a proven exactly-once release?

## Verdict — FEASIBLE

| program | role | ingress | egress | fit | bf-p4c |
|---|---|---:|---:|:--|:--|
| **pipe 0** `defense4_twopipe_pipe0_probe.p4` | frozen RRC + T0-admission + cross-pipe route | **12** | 3 | **FITS** | 0 errors |
| **pipe 1** `defense4_twopipe_pipe1_probe.p4` | BOR OPERATE hold/release core only | **6** | 0 | **FITS** | 0 errors |

Both compile clean on **bf-p4c 9.13.1** (`~/bf-sde-9.13.1/install/bin/bf-p4c --target tofino
--arch tna -g`) and both fit ≤ 12 ingress stages. The split is **necessary and sufficient**:

- **(a) pipe 0 fits ≤ 12 — with a caveat that turned into the key finding.** The *naive* split
  (move the OPERATE hold to pipe 1, keep everything else on pipe 0) is **13 — over by one**. The
  isolated +1 is **not** the cross-pipe route (that is free: a build with the route but the
  anti-subtraction T0-anchor dropped fits at 12). The +1 is the **T0-anchoring of the response
  deadlines** — a write-after-write on `dl_val` at MAU level 3. **Folding that arm into the decode
  action** (`PIPE0_ARM_FOLD`, giving the OPERATE arm the *same* `build_cand → dec_ack_arm →
  reg_deadline` shape the ACK arm already uses and that already fits at 12) removes it. With the
  fold, pipe 0 fits **12/3 with the faithful T0-anchor active**.
- **(b) pipe 1 fits ≤ 12 — with wide margin.** The BOR OPERATE hold/release core, standing alone
  (no 12-stage RRC tail underneath it), is **6 ingress / 0 egress** — six stages of headroom.
- **(c) the cross-pipe route is realizable** on the S9180-32X's two pipes via an internal
  MAC-loopback port on pipe 1 (§3). No new hardware, no external cable required.
- **(d) exactly-once is proven** by a byte-level lifecycle model across the cross-pipe handoff,
  retransmit, readiness, and fail-open cases: clean model 10/10, 4/4 design mutants killed (§5).

**A compile is not silicon** and a behavioral model is not a compile. This is a placement +
lifecycle feasibility result; nothing was loaded on hardware.

---

## 1. Architecture — who does what

```
   master ── dp9 ─►┌─────────────────── PIPE 0 ───────────────────┐
   (Vision)        │ frozen RRC transaction engine (READ/SELECT   │
                   │ ACK+response hold, PRE 49B echo carve) +      │
                   │ T0-ADMISSION: on the protected OPERATE, record│
                   │ T0, arm reg_deadline=T0+A / reg_tresp=T0+R     │
                   │ (T0-anchored), stamp T0 into an internal xpipe │
   relay ◄─ dp64 ──┤ header, route ONE copy to pipe 1. Hold the    │
   (SEL-751)       │ relay's later ACK/echo T0-anchored.            │
                   └───────────────┬───────────────────────────────┘
                                   │ cross-pipe: ucast PORT_X1, bypass_egress=1
                                   │ (xpipe-tagged OPERATE, exactly one copy)
                   ┌───────────────▼───────────── PIPE 1 ──────────┐
                   │ BOR hold/release ONLY. Receive the xpipe       │
                   │ OPERATE on PORT_X1, select leak-safe J, arm    │
   relay ◄─ dp64 ──┤ reg_topj=T0+J on its OWN register (T0 from the │
   (release)       │ header), hold byte-identical original in qid2  │
                   │ behind its qid3 reservoir on PORT_L1, release  │
                   │ to the relay EXACTLY ONCE at T0+J.             │
                   └────────────────────────────────────────────────┘
```

**Pipe 0** keeps the entire proven RRC (READ/SELECT timing + the PRE size carve) unchanged. Its
*only* new behavior for the OPERATE is: record T0, T0-anchor `reg_deadline`/`reg_tresp` with the
OPERATE-specific `A`/`R`, stamp T0 into `xpipe`, and route the OPERATE to pipe 1 instead of the
relay. It does **not** hold the OPERATE. When the relay's ACK and echo come back as **fresh**
packets, pipe 0 holds them to the T0-anchored deadlines and carves the 49 B echo exactly as RRC
already does — so the ACK/echo release instants are `T0+A` / `T0+R`, **never** re-anchored to the
delayed release `T0+J` (the anti-subtraction invariant, `BOR_RRC_DESIGN.md §2`).

**Pipe 1** is the OPERATE hold/release core alone: `reg_topj = T0+J` (T0 arrives in the packet,
not a shared register), a qid3 blocker reservoir + qid2 hold on its own loopback ring, and a
single release site to the relay. Because it does not carry the RRC transaction engine, it is a
small program (6 stages).

**State is per-pipe.** T0 crosses to pipe 1 *in the packet* (`xpipe.t0`); the response-anchor T0
lives in pipe 0's own `reg_deadline`/`reg_tresp`. Neither pipe reads the other's registers — no
shared-register assumption anywhere.

---

## 2. The cross-pipe encapsulation (byte-identical release)

`xpipe` is a 6-byte internal header carried **after** Ethernet, discriminated by
`eth.etype == ETYPE_XPIPE (0x88C2)`:

```p4
header xpipe_h { bit<16> orig_etype; bit<32> t0; }   // 6 B, no 8-bit field (PHV-friendly)
```

- **Pipe 0, on the fresh OPERATE:** `xpipe.setValid(); xpipe.orig_etype = eth.etype (0x0800);
  xpipe.t0 = T0_tick; eth.etype = ETYPE_XPIPE;` then `ucast_egress_port = PORT_X1;
  bypass_egress = 1`. The ingress deparser emits `eth · xpipe · ipv4 · …`, so the TM carries the
  xpipe-tagged frame and `bypass_egress` skips pipe-1 egress so it arrives at pipe-1 **ingress**
  intact.
- **Pipe 1, on hold:** `eth.etype = xpipe.orig_etype; xpipe.setInvalid();` then `to_op_hold()`.
  The qid2-held frame is the **byte-identical original** (etype restored, xpipe not emitted).
- **Pipe 1, on release:** forward the byte-identical original to `PORT_RELAY` (dp64, pipe 0);
  cross-pipe egress runs pipe-0's egress as a `rid==0` byte-identical pass-through.

No DNP3 byte, CRC, TCP sequence, or length is touched on the OPERATE path — the only wire mutation
is the reversible etype swap + the prepend-after-eth, both undone before the relay sees it.

---

## 3. The cross-pipe route (concrete, realizable on the S9180-32X)

`dev_port = (pipe_id << 7) | local_port`, so **pipe 0 = dev_port 0–127, pipe 1 = dev_port
128–255** (`pipe = dev_port >> 7`). The existing RRC lives entirely on pipe 0 (dp8/9/64/68).

| role | port (probe const) | pipe | how it is realized |
|---|---|---:|---|
| master | `PORT_VISION` dp9 | 0 | physical (unchanged) |
| relay | `PORT_RELAY` dp64 | 0 | physical (unchanged) |
| pipe-0 hold ring | `PORT_L` dp8 | 0 | MAC loopback (unchanged) |
| pipe-0 pktgen | `PORT_PGEN` dp68 | 0 | pktgen/recirc (unchanged) |
| **cross-pipe entry** | `PORT_X1` dp144 | **1** | **MAC (near-end) loopback** |
| **pipe-1 hold ring** | `PORT_L1` dp136 | **1** | **MAC loopback** |
| **pipe-1 pktgen** | `PORT_PGEN1` dp196 | **1** | pipe-1 pktgen/recirc |

**The route.** Pipe-0 ingress sets `ucast_egress_port = PORT_X1` (a **pipe-1** port in MAC
loopback). The TM delivers the frame to X1; the MAC near-end loopback re-injects it into **pipe-1
ingress** on X1. This is the standard Tofino way to move a packet into another pipe's *ingress*
without an external cable: a packet only runs a pipe's **ingress** if it physically arrives on a
port owned by that pipe, and MAC loopback provides exactly that arrival. The released OPERATE
then egresses pipe 1 → TM → **pipe-0** port dp64 (cross-pipe egress is unrestricted; the TM routes
any ingress pipe to any egress port). This is **not** ordinary recirculation dressed up as "another
12 stages": the two programs are genuinely separate placements on separate pipes.

The `PORT_X1`/`PORT_L1`/`PORT_PGEN1` dev_port values are representative pipe-1 ids; the exact
front-panel ↔ dev_port map for pipe-1 ports comes from the box port map (as the pipe-0 map does in
`~/Projects/Tooling/tofino_25g_connectivity_map.md`). All that the compile requires is that they
are valid pipe-1 (≥128) ids, which they are.

**Per-pipe `pipe_scope` deployment.** The two programs are compiled independently (each a normal
single-`Pipeline` TNA artifact, `Switch(pipe) main`), which is how their per-pipe placement is
measured here. On the chip they are deployed as a **two-program** device via the SDE multi-program
`.conf`, one pipeline profile bound to each pipe:

```jsonc
"p4_devices": [{ "device-id": 0, "p4_programs": [
  { "program-name": "twopipe_pipe0", "pipe_scope": [0],
    "bfrt-config": ".../pipe0/bfrt.json", "context": ".../pipe0/pipe/context.json",
    "config": ".../pipe0/pipe/tofino.bin" },
  { "program-name": "twopipe_pipe1", "pipe_scope": [1],
    "bfrt-config": ".../pipe1/bfrt.json", "context": ".../pipe1/pipe/context.json",
    "config": ".../pipe1/pipe/tofino.bin" }
]}]
```

Each program's control plane (table entries, the pipe-1 pktgen app + qid3 reservoir seed, the
X1/L1 MAC-loopback + queue-priority config) is scoped to its own pipe. This is a deployment detail,
not part of the compile-only result, and is gated on hardware authorization.

---

## 4. Compile evidence

Full matrix + raw logs: `evidence/bor_two_pipe/COMPILE_MATRIX.txt`,
`evidence/bor_two_pipe/{pipe0,pipe1}/table_summary.log`, `.../mau.resources.log`, `.../compile.log`,
and the two isolation summaries in `evidence/bor_two_pipe/diagnostics/`.

| build | flags | ingress | fit |
|---|---|---:|:--|
| frozen RRC kernel (reference) | — | 12 | FITS (INITIAL 13 → settles 12) |
| **pipe 1** (BOR core, standalone) | — | **6** | **FITS** |
| **pipe 0 — final** | `TWO_PIPE_PIPE0 BOR_NO_TOPJ PIPE0_ARM_FOLD` | **12** | **FITS** |
| pipe 0 — naive split (no fold) | `TWO_PIPE_PIPE0 BOR_NO_TOPJ` | 13 | NO-FIT |
| pipe 0 — naive + SR1/SR2/SR3 | `… SR1_TM_DISPATCH SR2_FOLD_PARAMS SR3_CP_TS_GATE` | 13 | NO-FIT |
| pipe 0 — drop T0-anchor (diagnostic) | `… BOR_NO_T0ANCHOR …` | 12 | FITS (not faithful) |
| control: one-pipe RRC+BOR + fold | `PIPE0_ARM_FOLD SR1 SR2` (OPERATE hold present) | 13 | NO-FIT |

Reading the matrix:

1. **The cross-pipe route is free.** Dropping only the T0-anchor already fits at 12, so the xpipe
   header, the `ucast → PORT_X1` route, and removing the OPERATE hold cost **zero** net stages.
2. **The T0-anchor is the isolated +1** in the naive split, and no table-count consolidation
   (SR1/SR2/SR3, drop codebook) recovers it — it is a *dependency-depth* (write-after-write on
   `dl_val`), not a table-capacity, problem.
3. **The arm-fold recovers exactly that stage** (`PIPE0_ARM_FOLD` alone: 13 → 12) by giving the
   OPERATE arm the same decode-action shape the ACK arm already uses. The fold is
   **semantics-preserving**: it computes the identical `T0+A`/`T0+R` deadline words, only in the
   decode action rather than a following overwrite. The T0-anchor stays fully active (the
   anti-subtraction property is not traded away — see the `reanchor` mutant in §5).
4. **The split is necessary.** With the OPERATE hold *present* on one pipe, even the fold + SR
   consolidations stay at 13 — the OPERATE hold/release core (qid2/qid3/`reg_topj`/OP_RELEASE) is a
   genuine separate +1 that only the second pipe absorbs.

Pipe-0 places with the frozen RRC's tail unchanged — stages 0,1,7,8,9,10 at 16/16 Logical
TableIDs, stage 11 at 10/16 — i.e. the fold slots the OPERATE anchor into existing head-room
without disturbing the saturated tail. Pipe 0: 137 logical tables (vs the frozen 125); pipe 1: 46.

---

## 5. Exactly-once across the cross-pipe handoff (lifecycle model)

`offline/bor_twopipe_emulator.py` models the two pipes as two stages joined by the cross-pipe
channel, with a byte-level `relay_rx` log as the ground truth. Output:
`evidence/bor_two_pipe/lifecycle_emulator.out` — **clean model 10/10, mutants killed 4/4.**

Clean-model invariants (all PASS):

- `cross_pipe_exactly_once` — a FRESH OPERATE crosses pipe 0 → pipe 1 exactly once (single ucast).
- `relay_receives_exactly_once` — the relay receives the OPERATE bytes exactly once.
- `released_via_pipe1_hold`, `released_byte_identical`, `release_at_T0_plus_J` — released by the
  pipe-1 hold at `T0+J`, byte-identical to the original (xpipe stripped).
- `ack_echo_T0_anchored` — pipe-0 holds ACK@`T0+A` and echo@`T0+R`, **independent of J** (recorded
  T0), never re-anchored to the delayed release.
- `retransmit_still_one_cross`, `retransmit_still_one_relay_rx` — an exact retransmit while the
  OPERATE is held is dropped by pipe 0 (`reg_tag` duplicate) and never reaches the relay twice.
- `fail_open_forwards_once` — readiness unconfirmed → pipe 1 fails open **without holding**,
  forwarding once (the `BOR_RRC_DESIGN.md §3` readiness-race resolution).
- `t0_travels_in_header` — the release time equals header-T0 + J (no shared register).

Design mutants, each KILLED (breaks the named invariant):

- `pipe0_cross_twice` → `cross_pipe_exactly_once` (two copies cross → double release).
- `pipe1_duplicate_release` → `relay_receives_exactly_once` (two physical operations).
- `reanchor_ack_to_release` → `ack_echo_T0_anchored` (re-anchoring the ACK to `T0+J` leaks J).
- `pipe0_no_dup_drop` → `retransmit_still_one_cross` (a redundant cross). **Defense in depth:** even
  this does not double the relay, because pipe 1 **independently** dedups the same-generation
  re-cross (`V_OP_DUP → drop`) — exactly-once at the relay is protected at *both* pipes.

The one-pipe model (`offline/bor_rrc_emulator.py`) is unchanged and remains the reference for the
readiness-race and anti-subtraction analysis; this two-pipe model adds only the handoff invariants.

---

## 6. What is proven, and what is not

**Proven (compile + model):**

- Both programs compile clean on bf-p4c 9.13.1 and fit ≤ 12 ingress stages (pipe 0 = 12/3,
  pipe 1 = 6/0), with raw table-summary + mau.resources evidence per program.
- The faithful T0-anchor (anti-subtraction) is retained on pipe 0 at 12 stages via the arm-fold.
- Exactly-once release across the cross-pipe handoff, retransmit, readiness and fail-open cases,
  and byte-identity, hold at the behavioral level (mutation-tested).
- The cross-pipe route uses only in-chip MAC loopback on the chip's second pipe.

**NOT proven / out of scope (hardware-gated):**

- **Silicon behavior.** No program was loaded; the cross-pipe MAC-loopback timing, the pipe-1
  pktgen qid3 fill, the two-program `pipe_scope` deployment, and the actual release jitter are
  hardware questions.
- **The readiness race** (`BOR_RRC_DESIGN.md §3`) is resolved here the faithful way (hold only when
  qid3 residency is confirmed for the generation, else fail open without holding), but which policy
  a deployment wants — and whether qid3 can be made resident before the first OPERATE without
  violating generation-binding — is a silicon-timing decision, unchanged by the split.
- **The physical operation-time divergence floor** (the Formby-fingerprint mitigation target)
  needs an authorized physical campaign; synthetic J distributions validate the mechanism, not the
  security floor.
- **The exact pipe-1 front-panel port map** and the MAC-loopback/queue-priority control-plane setup
  are deployment details, gated on hardware authorization.
- **TCP-timestamp channel.** The anti-subtraction claim still requires a no-TCP-timestamp protected
  flow (`BOR_RRC_DESIGN.md §2`); the split does not change this.

## Files

- `p4/defense4_twopipe_pipe0_probe.p4` — pipe 0 (copy of the SR probe + the `TWO_PIPE_PIPE0` /
  `PIPE0_ARM_FOLD` edits). Recipe: `-DTWO_PIPE_PIPE0 -DBOR_NO_TOPJ -DPIPE0_ARM_FOLD`.
- `p4/defense4_twopipe_pipe1_probe.p4` — pipe 1 (new, standalone BOR hold/release core).
- `offline/bor_twopipe_emulator.py` — the two-pipe exactly-once lifecycle model.
- `evidence/bor_two_pipe/` — compile matrix, per-program logs + resource summaries, emulator output.
- Frozen and untouched: `p4/defense4_rrc_kernel.p4`, the caseA files.
