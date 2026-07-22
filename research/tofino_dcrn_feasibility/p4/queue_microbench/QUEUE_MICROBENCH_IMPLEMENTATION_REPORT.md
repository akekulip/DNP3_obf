# Phase-4 TM Queue Microbenchmark — Implementation Report

_Authoritative, self-contained implementation report for the size-labelled Traffic-Manager (TM)
queue microbenchmark on Intel Tofino-1. Branch `research/caseA-ditto-queue`. Written 2026-07-22 after
the min-rate + DWRR run on live silicon. This document explains what the mechanism is, exactly how it
is implemented in P4 and in the control plane, how it was run on the hardware, every queue, every
timing knob, every result, and every open question. It incorporates and extends
`QUEUE_MICROBENCH_REVIEW.md` (the pre-authorization review) with the measured run results._

Directory: `research/tofino_dcrn_feasibility/p4/queue_microbench/`

---

## 0. Status line

- **Compiled + fits** on local `bf-p4c 9.13.1`: 6/12 ingress stages as-run; **7/12 after the
  2026-07-22 cover-mode reimplementation** (§0.5, §4.6 — the two new register reads cost one stage).
  On-switch `bf-p4c 9.13.2` confirmed parity for the as-run build (0 errors, 6/12); the 7-stage
  cover-mode build is **local-compile-verified, not yet re-confirmed on 9.13.2** (gated switch step).
- **RUN on live Tofino-1** (switch `decps@10.10.54.15`, SDE 9.13.2 + Hulk `decps@10.10.54.158`, Vision
  OFF, dp9 hairpin) across all four TM mechanisms: **pktgen metronome, max-rate shaper, min-rate/
  guaranteed-rate, DWRR**.
- **Verdict:** a TM scheduler (max-rate, min-rate, DWRR) is a *backlog* discipline — it cannot pace a
  sparse ~5 Hz DNP3 flow directly. Only the **pktgen/recirc metronome** manufactures a steady cadence
  from a sparse or silent flow. The "round-robin/min-rate could pace cheaply without chaff" idea is
  **refuted on silicon**.
- This is an **instrument**, not the deployed defense: it measures wire *size* + *timing*, using
  synthetic UDP frames classified by destination port. It intentionally leaves L4 length/checksum
  stale (measures size, not payload validity). The deployed defense (real DNP3 over TCP) is Level 2
  in §14.

---

## 0.5 ICS DESIGN CORRECTIONS (review 2026-07-22) — THESE SUPERSEDE ANY CONFLICTING TEXT BELOW

A design review corrected several points that are **non-negotiable for an ICS/SCADA + Ditto-style
deployment.** The implementation code has been changed accordingly (see §7.1, §4.6); this section is
the authority where older text below conflicts.

1. **Internal clock ≠ transmitted filler ≠ secure chaff — three distinct things.** The earlier build
   let an idle `MB_METRO` tick *auto-become* an external chaff packet (~100 pps on the wire with zero
   host input). That conflation is removed. **`MB_METRO` is now an INTERNAL slot clock only, never
   transmitted by default;** `MB_CHAFF` is an *explicit external cover* packet emitted only in an
   approved cover mode; `REAL` is protected traffic. So chaff is **not** "deferred/unbuilt" and **not**
   "already fully present" — a *primitive filler* existed and has been **replaced by three explicit,
   controller-selected cover modes** (below), OFF by default.

2. **The pacer is pktgen, not the TM scheduler.** The measurements show the Traffic Manager does not
   pace sparse traffic; the clock is the pktgen periodic tick. The mechanism is a **pktgen-driven
   size-state slot scheduler**, not a "TM queue scheduler." TM still does queue selection, real-vs-
   cover priority, output contention, and occupancy — but it is *not* the source of the sparse-flow
   cadence. (Full Ditto uses queue rates + continuously-available real/cover + hierarchical scheduling;
   we do not, unless CONTINUOUS cover is armed.)

3. **Three explicit cover modes (implemented as `cover_mode`, default OFF):**
   - **Mode 0 — OFF (default ICS):** an idle tick is consumed internally; **nothing is transmitted**;
     real ACKs/responses still leave in scheduled slots. Sufficient for the immediate Case A *timing*
     experiment. Does NOT give volume anonymity or full SBO hiding.
   - **Mode 1 — TRANSACTION_WINDOW (preferred ICS cover):** a bounded N-slot cover window, opened by an
     eligible DNP3 transaction; missing slots get cover; hard caps (max slots, max bytes/transaction,
     max windows/sec, cooldown, quiet-period termination, real strict-priority, cover dropped first,
     auto-disable on degradation). The window state machine (trigger + caps + DoS controls) is a
     **follow-on build**; `window_active` is a control-plane gate that lets the mode be exercised now.
   - **Mode 2 — CONTINUOUS (optional upper bound):** permanent cover; strongest hiding, highest cost;
     **disabled by default**, only on links with measured spare capacity, presented as a security
     upper bound, not the normal ICS deployment.

   Dataplane (implemented, §4.6): `on tick: advance P; if eligible real → release one real (drop tick);
   else if CONTINUOUS or (WINDOW and window_active) → emit ONE external cover; else → consume tick
   internally (transmit nothing).`

4. **Scope of the current claim.** Claim only **joint size normalization + timing control for the
   packets that are actually transmitted** (incl. Case A CLRT reshaping). Do **not** yet claim **READ
   and SBO are indistinguishable** — that needs a *direction-aware canonical transaction schedule*
   (`slot = (direction, size, timing position)`) with cover for missing messages, generated **and
   removed** at both edges. Chaff is *required* (not optional) for that claim.

5. **Overhead is not just "heavy" — it is computed per pattern and link class (§X-overhead).** For a
   128/256 B alternating pattern: τ=10 ms ⇒ ~154 kbps/direction (~1.66–1.87 GB/day/dir); τ=25 ms ⇒
   ~61 kbps/dir (~0.66 GB/day/dir). Negligible on 100 Mbps/1 Gbps fiber (~0.15%), but **unacceptable**
   on narrowband radio, serial-over-IP, cellular, satellite, or oversubscribed utility WAN. This is
   exactly why continuous cover must be optional and off by default (NIST OT guidance: security
   measures must respect OT performance/availability/safety).

6. **`(P, τ)` cannot be optimized separately — the optimizer output is `(P, τ, cover_mode, window)`.**
   `P` directly drives latency: with `P=[S1,S2]`, an S1 slot recurs every 2τ, so an S1 packet can wait
   ~2τ and its S2 follow-up τ later (≈3τ added). A rare state in a long pattern recurs only every |P|·τ.
   The optimizer must jointly minimize padding + cover + recirc overhead + max slot wait + ACK-to-
   response gap + response latency + transaction completion + occupancy + distinguishability.

7. **Padding: two trusted edges + outer encapsulation, not TCP seq translation (primary plan).**
   Deployable padding/cover needs a *second trusted edge* (Vision software sanitizer / DPU / Linux
   gateway / second switch) and an **encrypted, authenticated outer format**: the sending edge wraps
   the whole inner DNP3/TCP packet, pads the *outer* frame, inserts cover; the receiving edge
   authenticates, drops cover, removes the wrapper, forwards the original unchanged. The inner TCP
   sequence space is **untouched** (no per-flow seq translator; retransmit/SACK stay end-to-end). The
   `0x88B6` marker used in this microbench is **microbench-only** and must NEVER be visible on the WAN.
   (The TCP seq-space translator is retained only as an *alternative feasibility study*.)

8. **Splitting is not on the Tofino-only physical path.** "Pre-split upstream via a software harness"
   means a software proxy modifies traffic → that is the **hybrid software/DPU path**, not "transparent
   switch-only protection of an unmodified physical SEL-751." The Tofino-only physical path preserves
   the inner packet, includes a size state large enough for the largest frame, pads smaller frames, and
   **does not split**. Splitting stays in the broader research, not the Tofino-only physical claim.

9. **Correctness gates that MUST hold before real-TCP / physical-SEL-751 testing:** (a) enforce
   ACK-before-response (restore the hard zero-inversion token — correctness over one or two stages);
   (b) flow-aware per-transaction state (the current single per-state counters cannot distinguish
   multiple flows/masters/outstanding transactions — start explicitly limited to *one flow, one
   outstanding transaction*); (c) fine-grained timing measurement (1-second MAC counters prove ~100 pps
   and no multi-second starvation, but **not** 10 ms slot accuracy or jitter — need HW timestamps / a
   second measurement port / restored Vision receiver); (d) mandatory priority readback (implemented,
   §7.1 — abort, never silently fall back); (e) chaff always loses to real under congestion (drop cover
   first, auto-disable on queue growth/link errors/real loss); (f) DoS controls on transaction-triggered
   cover (only approved flows trigger; rate-limit windows; cap concurrency; authenticate the tunnel).

10. **Switch restored (§20).** The microbench is no longer left loaded — `decoy_paper3` was restored
    after this run (see §17 for the recorded hashes/checks). A shared lab switch is not left in an
    experimental config for a possible future run.

**Verdict-language calibration:** the strong claims that stand are the *negative* TM results
(max-rate/min-rate/DWRR do not pace a sparse flow) and that a pktgen tick *can* create a regular
internal slot cadence. Not yet proven: a valid DNP3/TCP conversation, secure chaff, SBO-vs-READ
indistinguishability, 10 ms slot accuracy, multi-flow correctness, ACK-ordering under all conditions,
safe physical SEL-751 operation, a deployable padding scheme, acceptable ICS-link overhead.

---

## 1. Research context and the locked architecture

The DNP3 obfuscation defense is a **single joint size-and-time pattern** (`CASE_A_QUEUE_DESIGN.md`,
locked by Dr. Lin 2026-07-21). Splitting, padding, and queue scheduling are **components of one
mechanism, not alternative defenses.** The goal: a passive observer on the protected link cannot
fingerprint the outstation device, nor tell a normal READ from a SELECT→OPERATE (SBO) control
transaction, from packet **sizes**, **segmentation**, and **timing** (including the ACK-to-response
gap, the Formby CLRT feature).

**The "pattern" is an ordered SIZE-state list** `P = [S0, S1, …, S(L-1)]`, each `Si` a target
protected-link packet size. **Timing is the scheduler's interval `τ` (or rate `R`)**, supplied by the
Traffic Manager — *not* a per-slot timing pattern. The mechanism is written `(P, τ)`.

Per-packet algorithm (the 8 steps this microbench realizes):
1. **Select** the next size state from `P`.
2. **Preserve** the packet if it already fits the state.
3. **Pad** it up if it is smaller (pure ACKs, requests, and CROB/Select/Operate/confirmation control
   packets all pad to a common state → different operations share a visible size class).
4. **Split** a large response into a *sequence* of smaller states — **not on-switch**; the Tofino
   cannot transparently split a live payload (payload opacity, non-constant-time cut, proxy-grade
   reassembly). The "sequence" is realized by the scheduler pacing **pre-split** components produced
   upstream (the software split harness).
5. **Otherwise wait** for a large-enough state or **fail open**.
6. **Place** the transformed packet into the **real-packet (high-priority)** queue for its state.
7. **Chaff:** use a **lower-priority chaff/filler** queue for a state when an empty pattern slot must
   be preserved (so round-robin never skips a state), and for strong SBO hiding (a control transaction
   must occupy the same fixed slot count as a READ).
8. The **TM scheduler** sets the state's output time (`τ`/`R`).

Claim scope: joint reshaping of size + segmentation + timing. **Not** total volume independence —
without continuous chaff a passive observer can still see whether traffic exists, transaction
duration, and (sometimes) packet count. Chaff and volume-independence are deferred.

---

## 2. The rig / testbed (every host, port, and access path)

| Element | Identity | Role |
|---|---|---|
| **Switch** | `decps@10.10.54.15`, hostname `ufispace`, SDE **9.13.2** | Tofino-1 ASIC; runs the compiled P4 in `bf_switchd`; bfruntime control plane on `localhost:50052` |
| **Hulk** | `decps@10.10.54.158`, NIC `enp59s0f0np0` @ 10.0.2.10/16 | traffic generator + capturer |
| **Vision** | second host | **OFF** for this run; its data NIC was found swapped/down earlier — a true two-host path needs it restored |
| **dp9** | switch device port 9 ↔ Hulk | input **and** hairpin output (Vision down) |
| **dp8** | switch device port 8 ↔ Vision | original observe port; unused while Vision is off |
| **dp68** | internal recirculation port (no cable) | metronome hold-loop + pktgen source |

**Hairpin.** With Vision off, dp9 is both input and output: Hulk sends a 64 B frame in on dp9, the
switch processes it, and sends the result back out dp9; Hulk captures the returned frame
(inbound-only, `-Q in`, on the *physical* NIC — macvlan misses hairpinned frames). The switch dp9 MAC
TX counter is the **ground-truth dequeue** (immune to host capture loss and NIC coalescing).

**Access.** Switch = key-based SSH, passwordless sudo. Hulk = `sshpass -e` with `SSHPASS` from
`~/.lab_env`; sudo needs the password piped to `sudo -S`. All ssh/scp from the dev box (gambit) need
`dangerouslyDisableSandbox`. **Every switch touch is gated on explicit authorization** (master §10);
loading this program displaces the co-resident program (`decoy_paper3`), restored afterward.

---

## 3. The mechanism, explained

The core problem: **the Tofino has no general software timer.** It cannot "send this packet at time
T." So a timing defense cannot simply buffer-and-schedule. There are two families of workaround, and
this microbench compares them:

### 3.1 The metronome (pktgen + recirculation) — the working pacer
A **pktgen periodic timer** app on dp68 emits one small "tick" frame every `τ` nanoseconds. A real
host frame is **encapsulated and recirculated** (held looping on dp68); each tick **releases one held
real** in pattern-slot order. The tick *is* the clock. This manufactures a steady cadence from a
sparse or even silent flow. **An idle tick (no pending real) is consumed internally by default
(cover OFF) and transmits nothing** — see §0.5.3 and §4.6; it becomes an external cover packet only in
an armed cover mode. Reused from GridCloak Mechanism-C: the pktgen periodic timer + recirc-hold +
**balanced arm/release counters**.

### 3.2 The TM scheduler (shaper / min-rate / DWRR) — a backlog discipline, not a pacer
The Traffic Manager can rate-shape or round-robin queues. But a shaper only acts on a **backlog**: a
lone frame at an idle queue leaves immediately (no delay), and at low rates a backlog is released in
coarse clumps, not a smooth cadence. This microbench measured all three TM disciplines and confirmed
none can clock a sparse flow (§12). This is why the metronome, not the TM scheduler, is the pacing
mechanism for the locked pattern.

Which mechanism runs is chosen by a **control-plane register `mech_reg`** (0 = pktgen, 1 = shaper).
The P4 datapath is identical for shaper/min-rate/DWRR — those three differ only in the TM config
written to the queues, not in the datapath — so they run on the same loaded program with no recompile.

---

## 4. The P4 dataplane (`queue_microbench.p4`) — full walk-through

TNA (Tofino Native Architecture), single ingress pipeline, egress is pure pass-through.

### 4.1 Constants (exact values)
```
ETHERTYPE_IPV4 = 0x0800     ETHERTYPE_MB = 0x88B6 (internal recirc encap)   IP_PROTO_UDP = 17
Classification dst ports:
  DPORT_ACK_S1   = 20001  -> state S1, role ACK,      pad up to 128 B
  DPORT_RESP_S2  = 20002  -> state S2, role RESP,     pad up to 256 B
  DPORT_SPLIT_S1 = 20003  -> state S1, role SPLIT     (host pre-split component)
  DPORT_SPLIT_S2 = 20004  -> state S2, role SPLIT     (host pre-split component)
  DPORT_PRE_S1   = 20005  -> state S1, role PRESERVE  (already S1-sized, no pad)
  DPORT_PRE_S2   = 20006  -> state S2, role PRESERVE  (already S2-sized, no pad)
Ports:  PORT_HULK = dp9    PORT_OBSERVE = dp9 (hairpin; was dp8/Vision)    PORT_RECIRC = dp68
Size states:  S_NONE=0  S1=1 (128 B wire)  S2=2 (256 B wire)   base frame = 64 B (S0)
Roles:  NONE=0 ACK=1 RESP=2 SPLIT=3 PRESERVE=4
Pad selectors:  PAD_NONE=0  PAD_S1=1  PAD_S2=2
Mechanism:  MECH_PKTGEN=0  MECH_SHAPER=1
Recirc encap subtype:  MB_REAL=0 (held real)  MB_METRO=1 (metronome tick)  MB_CHAFF=2 (per-state chaff)
Seq machine:  SEQ_ENTER=0 (just encap'd, register pending, hold)  SEQ_HELD=1 (looping, release on slot)
Queue IDs (dev-port-local): QID_REAL_S1=1  QID_CHAFF_S1=2  QID_REAL_S2=3  QID_CHAFF_S2=4  QID_HOLD=6
MIRROR_SID = 2 (optional measurement tap, off unless P4 arms mirror_type)
```

### 4.2 Headers and padding
- `ethernet_h`, `ipv4_h`, `udp_h` — standard.
- `mb_h` (internal encap, between Ethernet and IPv4, present only while recirc-holding):
  `is_tick, state, role, seq, orig_ethertype` (orig ethertype restored on release; encap stripped so
  the delivered frame is clean).
- **Padding headers** `pad_s1_h` = 512 bits (64 B) and `pad_s2_h` = 1536 bits (192 B). Base 64 B →
  S1 128 B or S2 256 B. The filler is emitted **from deparser constants** (not data-path PHV — the
  same mechanism GridCloak's 2048-bit pad uses on silicon), which is why PHV stays at 9.38%. The
  filler goes after the UDP header and before the residual body, so the frame stays a well-formed
  Eth/IPv4/UDP frame at the target wire size. **No IPv4/UDP length or checksum edit** — the microbench
  measures wire size + timing, not L4 semantics (a deliberate microbench-only simplification; the real
  size-normalizer's seq/checksum translation is separate, §14 Level 2).

### 4.3 Parser
`start` → `parse_ethernet`. On `ETHERTYPE_MB` → `parse_mb` (a recirc frame: parse only eth+mb; the
IPv4/UDP/pad ride in the unparsed body). On `ETHERTYPE_IPV4` → `parse_ipv4` → (ihl==5) `parse_l4` →
(proto UDP) `parse_udp`. Anything else → `accept` (fail open).

### 4.4 Classification and guards (tables)
- `mb_classify` — **exact match** on `udp.dst_port`, const entries mapping the 6 dports to
  `(state, role, pad)` as above; default `mb_none()` (`is_mb=0` → fail open). Exact match keeps it
  Class-1 safe (no gateway magnitude compare).
- `oversize_guard` — **range** table on 16-bit `ipv4.total_len`: `0..242` → fits S2; default →
  oversize → fail open (larger than the biggest state can never be padded and there is no on-switch
  split). One TCAM block.
- `pat_state` — **the size pattern `P` itself**, realized as a control-plane table keyed on
  `meta.pat_lo` (= free-running slot counter mod |P|, low 3 bits → |P| ≤ 8), action
  `set_slot_state(st, chaff_pad)`. v1 installs 8×S1/PAD_NONE; final installs S1/PAD_S1, S2/PAD_S2
  alternating. **Switching the pattern is a table-entry change, no recompile.**

### 4.5 Registers (Meter ALUs) — the arm/release state machine
- `mech_reg` (1 entry) — MECH_PKTGEN | MECH_SHAPER; read only on the host path.
- `pat_idx_reg` (1 entry) — `advance_pat`: `v = v+1` each pktgen tick; `meta.pat_lo` indexes
  `pat_state`.
- **Balanced per-state counters** (one 1-entry register per state — RegisterAction needs a constant
  index): `pendS1_reg`, `pendS2_reg`, `relS1_reg`, `relS2_reg`, with add/take RegisterActions.
  `pend++` on a real ENTER; a tick `pend--` (peek a pending real) and `rel++`; the held real `rel--`
  to graduate. **Balanced counters, not saturating flags** (the flag bug that stranded a held frame
  during a 3-in-flight burst — carried over from GridCloak G6).

### 4.6 The two datapath paths (ingress `apply`)
```
mech = mech_read.execute(0)
mb_classify.apply()                      // meta.is_mb / state / role / pad_sel
if is_mb == 0:  fail open -> forward to the peer host, ctr_failopen++
else:
    oversize_guard.apply()               // range on total_len
    if oversize: fail open, ctr_oversize++
    else:
        if pad_sel == PAD_S1: pad_s1.setValid(); f=0     // step (3) pad
        elif pad_sel == PAD_S2: pad_s2.setValid(); f=0
        if mech == MECH_PKTGEN:          // METRONOME
            encap mb_h (is_tick=MB_REAL, state, role, seq=SEQ_ENTER, orig_ethertype)
            ethernet.ether_type = ETHERTYPE_MB
            recirc_hold()                // ucast_egress_port = dp68, qid = QID_HOLD
            ctr_encap++
        else:                            // SHAPER / MINRATE / DWRR (identical datapath)
            ucast_egress_port = dp9(observe)
            qid = (state==S1) ? QID_REAL_S1 : QID_REAL_S2
            ctr_shaper++
```
The **recirc/tick path** (frames arriving with `ETHERTYPE_MB`) handles metronome release: a tick
`advance_pat`s the slot, looks up `pat_state`, and if a real is pending for that slot's state it
releases it to the REAL queue on dp9 (padded to the slot state), arms the release, and **drops the
tick**. If the slot is empty, the cover decision is made by `cover_mode` (§0.5.3, §4.6): **OFF
(default) → the tick is consumed internally, nothing is transmitted;** WINDOW+`window_active` or
CONTINUOUS → emit one external cover packet to the cover (low-priority) queue. Held reals loop on
`QID_HOLD` at dp68 until their slot. **ACK-before-response ordering is currently only MEASURED, not
enforced** (the size pattern places the ACK's slot before the response's; the analyzer verifies order)
— the hard zero-inversion token from `dcrn_defense1` is deliberately omitted so the queue behavior is
isolated. **This MUST be re-enforced before any real-TCP or physical-SEL-751 test (§0.5.9a)** — a
single inversion perturbs TCP ACK/retransmit behavior; re-adding it is a known
extra stage cost.

### 4.7 Counters (Stats ALUs, single-site each — GridCloak B4)
`ctr_encap` (host→recirc hold), `ctr_grad` (**REAL released**), `ctr_tick` (**idle tick consumed
INTERNALLY, no transmit** — this should read the idle-slot count and, in cover=off, external cover
bytes stay zero), `ctr_cover` (**EXTERNAL cover transmitted** — new), `ctr_shaper` (shaper-path real
emitted), `ctr_chaff` (shaper-path external cover), `ctr_failopen`, `ctr_oversize`. `mb_read.py`
reads all eight. Additional telemetry the design calls for but not yet wired as counters
(order_violations, late_slots, missed_slots, recirc_passes, window_starts/completions/aborts) is a
follow-on — spelled out in §0.5 and the design doc.

---

## 5. The queues — complete map

Queues are TM constructs keyed on `(pg_id, pg_queue)`, where `pg_queue = pg_port_nr*8 + qid`. TM
tables require a **pipe-specific target** (`pipe_id=0`), not `0xffff`.

| Queue | qid | Port | pg_id | pg_port_nr | pg_queue | Wire size | Priority | Purpose |
|---|---|---|---|---|---|---|---|---|
| REAL_S1  | 1 | dp9 | 2 | 1 | **9**  | 128 B | strict HIGH | real S1 frames |
| CHAFF_S1 | 2 | dp9 | 2 | 1 | **10** | 128 B | strict LOW  | S1 empty-slot chaff |
| REAL_S2  | 3 | dp9 | 2 | 1 | **11** | 256 B | strict HIGH | real S2 frames |
| CHAFF_S2 | 4 | dp9 | 2 | 1 | **12** | 256 B | strict LOW  | S2 empty-slot chaff |
| HOLD     | 6 | dp68 | 17 | 0 | **6** | — | — | recirc hold-loop (metronome) |

- **dp9 → pg_id=2, pg_port_nr=1** was **read from `tf1.tm.port.cfg` on the switch** (not guessed):
  dp8 → pg2/nr0, dp68 → pg17/nr0. So on dp9, REAL_S1 = pg_queue 9 (the sampler reads this).
- **HOLD (dp68 qid6)** carries a `max_rate = 100000 PPS` cap (`sched_shaping` UPPER/PPS +
  `max_rate_enable`) — churn control so a held real can't crowd out ticks (GridCloak B3).
- Strict priority (real HIGH > chaff LOW) is applied via `sched_cfg` `min_priority`. The write is now
  **verified by mandatory readback (§7.1): if the priority is not confirmed and cover is armed, setup
  ABORTS — no silent fallback** (chaff must never compete with real ICS traffic). With cover OFF a
  mismatch only warns (nothing competes).

---

## 6. The timing

- **Metronome `τ`** = the pktgen periodic timer period (`tf1.pktgen.app_cfg`, `timer_nanosec`,
  default 10 ms = 100 pps). One 64 B `MB_METRO` tick per fire on dp68 (app_id 1). The tick template
  supplies wire byte 6 onward (pktgen prepends a 6 B header into the eth dst-MAC): ethertype `0x88B6`
  at `buf[6:8]`, `is_tick=MB_METRO` at `buf[8]`. This period sets the slot cadence and therefore the
  inter-packet interval of the emitted pattern.
- **Shaper/min-rate `R`** = the per-REAL-queue PPS rate (`--rate-pps`). Default 100 pps (deliberately
  below the ~1200 pps GridCloak starvation floor).
- **Trace-derived timing targets** (candidates, not locked — `QUEUE_PATTERN_FROM_TRACES.md`): native
  SEL-751 ACK→response CLRT median **12.2 ms**, p95 **17.2 ms**, p99 **25.1 ms**, with a thin heavy
  tail to ~166 ms; request→response readiness median **16.1 ms**. TCP `RTO_MIN ≈ 207 ms` ⇒ every slot
  must stay under a **~187 ms ceiling**. Naïve Ditto percentiles are unsuitable (top slot = max =
  166 ms drags the mean); the fix is to **cap at p95–p99 and fail-open the rare tail**.
- **The SIZE pattern `P` is NOT yet computed** — only the timing candidates exist. Computing `P` from
  the DNP3 packet-size distribution is the first task of the end-to-end run (§14, §16).

### 6.1 Cover overhead by pattern and link class (X-overhead; only if a cover mode is ON)
With cover OFF (default), external cover overhead is **zero when idle** — real packets simply leave in
scheduled slots. If a cover mode is armed, overhead for a 128 B/256 B alternating pattern (avg 192 B/
slot) is:

| Slot τ | pps | one-direction rate | per day (1 dir) | + ~24 B/frame PHY (preamble/IFG/FCS) |
|---|---|---|---|---|
| 10 ms | 100 | **~153.6 kbps** | ~1.66 GB | ~172.8 kbps → ~1.87 GB |
| 25 ms | 40 | **~61.4 kbps** | ~0.66 GB | — |

Continuous cover at 153.6 kbps/dir is negligible on 100 Mbps (~0.15%) or 1 Gbps fiber, ~15.4% of a
1 Mbps path, and **exceeds a 64 kbps path** — i.e. **unacceptable on narrowband radio, serial-over-IP
gateways, cellular (volume cost), satellite, shared field networks, or oversubscribed utility WAN.**
This is why continuous cover is optional/off-by-default and each candidate pattern's overhead must be
computed per deployment class (NIST OT guidance: security must respect OT performance/availability/
safety). **`(P, τ)` are not separable** — a longer/heavier `P` also adds latency (§0.5.6); the
optimizer output is `(P, τ, cover_mode, window)`, minimizing padding + cover + recirc overhead + max
slot wait + ACK-to-response gap + latency + occupancy + distinguishability jointly.

---

## 7. The control plane (`queue_microbench_setup.py`)

Runs on the switch per load; connects to bfruntime (`localhost:50052`, `bind_pipeline_config
("queue_microbench")`); no P4 recompile. Stages: (1) dp9 up 25G RS-FEC; (2) recirc + pktgen on dp68;
(3) write the metronome tick template + arm the periodic app (armed only in pktgen mode; **disabled**
in shaper/min-rate/DWRR so dp9 carries only the mechanism under test); (4) dp68 HOLD cap 100000 PPS;
(5) size-labelled dp9 queues (discipline depends on mechanism, below); (6a) seed `mech_reg`; (6b)
install `P` into `pat_state`; (7) mirror session (off unless armed).

Mechanisms (`--mech`, all control-plane only):

| `--mech` | mech_reg | Queue config written to REAL_S1/REAL_S2 | Verified bfrt idiom |
|---|---|---|---|
| `pktgen` | 0 | — (metronome; dp9 queues optional) | GridCloak `gc_switch_setup_c.py:113-143` |
| `shaper` | 1 | `sched_shaping` UPPER/PPS `max_rate=R` + `sched_cfg` `max_rate_enable` | `gc_switch_setup_c.py:163-177` |
| `minrate` | 1 | `sched_shaping` UPPER/PPS `min_rate=max_rate=R` (pinned) + `sched_cfg` `min_rate_enable`+`max_rate_enable` | GridCloak `exp_tm_floor.py:77-93` |
| `dwrr` | 1 | `sched_cfg` `dwrr_weight` + `scheduling_enable`, **min_rate_enable=False + max_rate_enable=False** | GridCloak `legacy/gc_dwrr_setup.py`, `bfrt_gridcloak_setup.py:253-292` |

`--dwrr-weight` (default 1, equal on all 4 queues = byte-fair round-robin). `--rate-pps` is R for
shaper/minrate. The `bfrt_grpc` import is deferred past the `--dry-run` guard so `--dry-run`
(arg/pattern/print validation) runs off-switch on any host.

### 7.1 Cover modes + mandatory priority readback (added 2026-07-22)
The control plane now seeds `cover_mode` (default `off`) + `window_active`, exposed as
`--cover-mode {off,window,continuous}` and `--window-active`. `off` = an idle metronome tick is
consumed internally, **nothing is transmitted** (the default ICS mode). The strict-priority write is
**verified by readback and ABORTS on mismatch when cover is armed** (no silent fallback) — directly
addressing the stale-min-rate incident and the ICS rule that cover must always lose to real.

**CONFIRM-ON-SWITCH items:** the dp8 (pg_id, pg_port_nr) — resolved for dp9 as (2,1) by reading
`tf1.tm.port.cfg`; the strict-priority enum on `sched_cfg` — best-known, now **readback-verified with
abort-on-mismatch** (was a silent fallback).

**Silicon procedure fix found this run:** bfruntime `entry_mod` writes only the fields you give it, so
a prior `minrate R=600` arm left `max_rate_enable`/`min_rate_enable=True` + `min/max_rate=600` on the
queue, silently capping the *first* DWRR run at 660 pps. Confirmed by reading `sched_cfg` live; fixed
so `--mech dwrr` explicitly writes both enables False (verified cleared, re-ran clean).

---

## 8. Compile and resource report (real numbers)

Local `bf-p4c 9.13.1`, `--target tofino --arch tna`: **0 errors, 2 benign parser unroll warnings.**

| Resource | Used | Tofino-1 budget |
|---|---|---|
| **Ingress stages** | **6** | 12 (6 headroom) |
| Egress stages | 0 | 12 (pass-through) |
| Critical path (dep graph) | 5 | — |
| Logical tables | 48 | — |
| SRAM blocks | 32 | 80/stage |
| TCAM blocks | 1 (`oversize_guard` range) | 24/stage |
| Map RAM | 26 | — |
| Meter ALUs (registers) | 6 | pat / pend×2 / rel×2 / mech |
| Stats ALUs (counters) | 7 | the 7 `ctr_*` |
| PHV | 21 containers (9.38%), 220 bits | 4096 bits |

**On-switch confirm:** `bf-p4c 9.13.2` (SHA 1baf055) rebuilt on the switch → **0 errors, 6/12 ingress
stages, identical fit** → no 9.13.1↔9.13.2 drift.

Two placement bugs were found and fixed while building (both are known memory-note classes): a
`t[0] & altbit` runtime AND inside a gateway ("condition too complex", Class-1) — fixed by moving `P`
into `pat_state`; and nested `if{…return;}` per frame type serializing the exclusive branches into an
18-stage chain — fixed by one flat `if/else` tree with no early returns, dropping 18 → 6 stages.

---

## 9. The measurement harness

| Tool | Host | What it does |
|---|---|---|
| `harness/mb_gen_raw.py` | Hulk | stdlib AF_PACKET generator; 64 B UDP frames, dst port picks size/role class; `--interval-ms` sets sparse vs backlog; payload = MAGIC `MBQ1` + seq + tx_ns |
| `harness/mb_gen.py` | Hulk | scapy generator (same frame format) |
| `harness/mb_sample.py` | switch | **ground truth** — per-second dp9 MAC counters: input pps (`$FramesReceivedOK`), dequeue pps (`$FramesTransmittedLength_128_255` = shaped S1), REAL_S1 depth (`usage_cells`) |
| `harness/mb_read.py` | switch | all `ctr_*` + TM queue depth/watermark/drops + egress-port counter |
| `harness/mb_parse.py` | offline (scapy) | cadence conformity vs τ, release jitter, size histogram, **size-state sequence + drop-robust conformity** (count ratio + run-length), ordering (seq inversions), loss (seq gaps), real-vs-chaff mix |
| `harness/mb_analyze.py` | offline | steady-state pace + per-second clumping detection |
| `harness/mb_capture.sh` / `mb_run_hulk.sh` | Hulk | inbound-only hairpin capture on the physical dp9 NIC |

Frame taxonomy for parsing: ethertype `0x88B6` = chaff/tick cover (size = slot target); ethertype
`0x0800`, dport 20001–20006 = REAL (carries MAGIC+seq+tx_ns); else = background/fail-open. Size→state:
64→S0, 128→S1, 256→S2. Host tcpdump timestamps are **not** used for cadence (NIC coalescing) — all
rate claims use switch-side counters.

---

## 10. How it was run (exact procedure)

Per mechanism, one cycle:
1. **Arm** on the switch: `python3.8 queue_microbench_setup.py --mode final --mech <M> [--rate-pps R]
   [--dwrr-weight W]` (confirmed no bfrt exceptions on the new min_rate/dwrr writes).
2. **Launch the sampler** on the switch, backgrounded, 22 s window → `/tmp/mb_<label>.txt`
   (`nohup … & </dev/null`).
3. **Generate** on Hulk, inline (blocks): sparse = `mb_gen_raw.py --count 1300 --interval-ms 20`
   (~50 pps for ~26 s); backlog = `--count 4500000 --interval-ms 0` (~150k pps for ~30 s, longer than
   the sampler so it spans the window). sudo via `sudo -S` with the password piped from `SSHPASS`.
4. **Read** the sampler file after the generator returns (sampler already finished).
5. For DWRR backlog, also `mb_read.py` for both queue depths/drops.

Backlog rate note: the AF_PACKET raw generator blasts ~150k pps (far faster than the earlier scapy
~8100 pps), so an early attempt read the sampler before the 24 s window finished (generator done in
1.65 s) — fixed by sizing the generator to outlast the sampler.

---

## 11. Prior run (context) — the max-rate shaper (2026-07-22, `RESULTS_switchside.txt`)

- **Shaper backlog sweep** (input ~8100 pps, REAL_S1 pinned FULL): R=100 → ~441-frame clump every
  ~4.4 s, median DEQ 0; R=200 → similar; **R≥600 → smooth ~660/s**. Throughput ≈ R at all R, but
  cadence is clumpy below ~600 pps. This is GridCloak's low-PPS starvation, measured on silicon.
- **Pktgen metronome** (τ=10 ms, no host input): dp9 TX = **100–102/s every second** — manufactures a
  smooth ~100 pps cadence from nothing.
- **Sparse** (shaper R=600, input 50 pps): DEQ = 50 = input, depth 0 — **no up-pacing**. The max-rate
  shaper is a rate CAP, not a pacer.

---

## 12. This run — MIN-RATE + DWRR results (2026-07-22, `RESULTS_minrate_dwrr.txt`)

Ground truth = switch dp9 MAC counters (`mb_sample.py`). Evidence: `runs/RESULTS_minrate_dwrr.txt` +
`runs/mb_*.txt`.

### Min-rate / guaranteed-rate (sched_shaping min=max=R pinned, min_rate_enable)
| Condition | Result | Evidence |
|---|---|---|
| R=100, backlog | median DEQ **0**, mean ~105 — ~441-frame CLUMP every ~4 s (identical to max-rate at 100) | `mb_minrate_R100_backlog.txt` |
| R=600, backlog | **smooth ~660** (median 661, mean 598) — identical to max-rate at 600 | `mb_minrate_R600_backlog.txt` |
| R=600, **SPARSE (in ~50)** | DEQ = **50 = input**, depth 0 — **NO up-pacing to 600** | `mb_minrate_R600_sparse.txt` |

⇒ The guaranteed/min-rate floor is a floor-**on-backlog**, not a metronome: it does not pull a sparse
flow up to R; at low R it clumps exactly like the max-rate cap; only R≥~600 is smooth. Confirms
GridCloak `exp_tm_floor`'s G1 (the PPS floor starves below ~1200 pps without chaff).

### DWRR (round-robin, sched_cfg dwrr_weight, no rate cap)
| Condition | Result | Evidence |
|---|---|---|
| SPARSE (in ~50) | DEQ = **50 = input**, depth 0 — clean passthrough, no cadence manufactured | `mb_dwrr_sparse.txt` |
| BACKLOG both REAL queues (~154k pps in, weight 1) | S1 DEQ **~77,000 pps** (median 77174), depth 0 — the other ~77k is S2; drains at ~line rate | `mb_dwrr_backlog2.txt` |

**Byte-fair caveat:** with equal weights and *different* wire sizes (S1=128 B, S2=256 B) a truly
**byte-fair** scheduler would give **unequal packet rates** (more pps to the smaller queue). The
observed ~50/50 *packet* split (S1≈77k, S2≈77k) is therefore consistent with **packet-fair**, not
byte-fair, service. `mb_sample.py` only reads the S1 (128–255 B) TX bucket, so the per-queue byte
service ratio was **not directly measured**. Do not label this "byte-fair" until per-queue byte
counters confirm the ratio. This does not affect the architecture (DWRR is not the selected pacer).

⇒ Pure DWRR imposes **no** absolute cadence — it only arbitrates the RATIO between queues that are
**continuously non-empty** (here ~50/50 for equal weight). To pace a sparse flow it needs a port-level
cap + chaff to keep queues backlogged (the heavy-chaff Ditto route). (The first DWRR backlog read 661
because of the leftover R=600 cap — see §7 procedure fix; the clean number is 77k.)

---

## 13. Verdict

Neither **min-rate/guaranteed-rate** nor **DWRR** can pace a sparse low-rate flow directly (without
heavy chaff). Together with the prior max-rate result, the whole TM-scheduler family is a **backlog
discipline**: it paces traffic that *exceeds* the rate, but a sparse flow passes through unpaced and a
min-rate floor does not pull a sub-rate flow up. For a ~5 Hz DNP3 obfuscation cadence the only
mechanisms that clock a sparse flow are: **(1) the pktgen/recirc METRONOME** (proven: ~100 pps ±1 from
zero input) or **(2) Ditto-style CHAFF-FILL** keeping queues continuously backlogged ≥~600 pps (high
overhead). The "round-robin/min-rate could pace cheaply without chaff" idea is **refuted on silicon.**

---

## 14. The end-to-end run — what it requires

The microbench proves the *mechanism* (metronome) and the *datapath* (classify/pad/hold/release/
fail-open) with **synthetic UDP frames**, measuring **cadence**. An end-to-end run closes the gap to a
real obfuscation result. Two levels:

### Level 1 — trace-driven obfuscation evaluation (the tractable next run)
Drive the metronome with the **real DNP3 size + timing distribution** and measure conformance +
fingerprint (obfuscation) + overhead. Stays in the microbench's "wire size + timing" scope (no live
TCP master, no checksum surgery). Steps:
1. **Compute the SIZE pattern `P`** (off-switch, unprivileged): histogram every DNP3 packet type's
   size (ACK/request/each response class/CROB-Select-Operate-confirmation) across the six captures;
   choose target states that (a) cover the sizes by padding up, (b) mix devices/operations into shared
   states so a size classifier collapses, (c) bound overhead. (S0 studies exist: device-id size signal
   weak/ION-driven; CROB-count size signal strong, needs variable-length filler.) → `queue_pattern_
   sizes.json`.
2. **Pick τ / schedule**: common device-independent, capped at p95 (17 ms) or p99 (25 ms) with
   fail-open tail; not native+fixed-offset (that only shifts the mean).
3. **Real traffic source**: extend `mb_gen_raw.py` so frame sizes, inter-arrivals, and type-labels
   come from the real captures (reuse `sel751_extract.py` + the multi-CROB pcaps).
4. **Program changes** (control-plane where possible; recompile if needed): install `P` in
   `pat_state` + the per-type padding map; **add chaff generation** (a pktgen app filling empty slots
   and, for SBO hiding, making a SELECT→OPERATE occupy the same slot count as a READ — chaff is
   *required*, not optional, for SBO); decide whether to **enforce ACK-before-response** (re-add the
   zero-inversion token, extra stages) or keep it measured. Compile 9.13.1 → confirm ≤12 stages →
   9.13.2 on-switch.
5. **Run on the switch** (gated): metronome mode (the only pacer), replay the real DNP3 stream from
   Hulk, hairpin-capture on dp9.
6. **Measure conformance** (`mb_parse.py`): cadence vs τ, jitter, size-state sequence + drop-robust
   conformity, ordering (0 inversions), loss (0).
7. **Measure obfuscation vs overhead** (reuse `ack_fingerprint_eval` / size classifiers from Phases
   04b/05/S0): device-id balanced accuracy and CROB-count MI on the shaped output vs native → toward
   chance? Against padding bytes + chaff frames + added latency = the privacy-vs-overhead Pareto.
8. **Restore + record**: restore `decoy_paper3`, tear down Hulk, results doc, commit.

### Level 2 — the deployed defense (larger, separate line)
A live DNP3 master ↔ outstation through the switch, real TCP. **Primary plan (§0.5.7): a two-edge
protected outer-encapsulation path** — a sending trusted edge wraps the whole inner DNP3/TCP packet,
pads the *outer* frame, inserts cover; a second trusted edge (Vision software sanitizer / DPU / Linux
gateway / second switch) authenticates, drops cover, removes the wrapper, and forwards the original
**unchanged**. The inner TCP sequence space is untouched (no per-flow seq translator; retransmit/SACK
stay end-to-end), and the cover marker rides *inside* the encrypted/authenticated outer header
(never `0x88B6` on the WAN). The earlier **TCP sequence-space translator** (seq += Δ, ack −= Δ) is
retained only as an **alternative feasibility study** (runtime-Δ checksum = top compile risk, Class-6
ICE zone; retransmit/SACK = top rig risk) unless there is a compelling reason to modify the inner
stream. Both are out of scope for the microbench.

---

## 15. What is already done vs. still missing

**Done (silicon-proven):** the metronome mechanism; the classify/pad/hold/release/fail-open datapath;
the size-labelled queues + `pat_state`=P table; the balanced arm/release counters; the full mechanism
sweep (pktgen vs shaper vs minrate vs dwrr); the measurement harness; the 9.13.1↔9.13.2 compile
parity; the trace-derived timing candidates.

**Missing / not decided:** the SIZE pattern `P` itself (only timing candidates exist); chaff
generation (required for SBO hiding + empty-slot preservation); real DNP3 classification (currently
synthetic dports); TCP transport and seq/checksum translation (Level 2); ACK-before-response
enforcement (currently measured); the obfuscation-vs-overhead evaluation.

---

## 16. Open questions (Q) and risks — spelled out

1. **Q-P (pattern):** the SIZE pattern `P` is uncomputed. Without it there is nothing to pace. Gates
   the whole end-to-end run. *Off-switch, unprivileged — the natural first move.*
2. **Q-cover/chaff:** a *primitive filler* existed (idle tick auto-transmitted) and has been replaced
   by three explicit cover modes (OFF default). **Secure, deployable cover is not built** — it needs
   the encrypted authenticated outer format + two trusted edges + a receiving sanitizer (§0.5.7).
   Cover is **required** (not optional) for SBO hiding — per-packet padding alone leaves the SBO
   packet-count and direction sequence intact; SBO needs a *direction-aware canonical transaction
   schedule* `slot=(direction,size,timing)` with cover for missing messages (§0.5.4), plus the DoS
   controls of §0.5.9f.
3. **Q-validity:** the microbench pads wire *size* but leaves L4 length/checksum stale → **invalid
   TCP/DNP3**. Level 1 sidesteps this (measures size/timing distribution). Level 2 uses **two-edge
   outer encapsulation** (inner packet preserved exactly; §0.5.7), not inner-stream seq translation.
4. **Q-split:** on-switch splitting is infeasible — large responses must be **pre-split upstream** and
   only *paced* by the scheduler.
5. **Q-order:** ACK-before-response is measured, not enforced; enforcing it costs stages.
6. **Q-metronome:** proven at ~100 pps single-flow; multi-flow, jitter under load, and the recirc
   self-clock's `global_tstamp`/pktgen refresh behaviour (the Q1/Q2/Q3 unknowns seen on `dcrn`) need
   checking at the pattern's τ. Sparse-frame TM pacing (whether a burst-1 shaper paces a lone frame)
   is now answered = **no** (this run).
7. **Q-hosts:** a true two-host path needs Vision's dp8 link restored (found swapped/down); the dp9
   hairpin is a valid single-host stand-in but is one clock / one physical port.
8. **Q-priority:** the dp9 strict-priority enum on `sched_cfg` was best-known + fallback; confirm the
   exact field for the final chaff/real priority split.

---

## 17. Safety, gating, rollback

- **Shared single-tenant chip.** Loading this microbench **displaces** the co-resident program
  (currently `decoy_paper3`); it is not concurrency. Every switch touch is gated on explicit
  authorization.
- **Rollback:** snapshot the running `.conf` + `p4_name`; mask the sibling auto-loader; load via the
  gated `bf_switchd` swap; run the setup; **restore** by relaunching the original program + its setup
  and unmasking its loader (mirrors the proven M1 displace-then-restore).
- **STOP conditions** (abort, preserve evidence, do not multi-patch): scheduler can't produce the
  timing or hold the size order; a frame is reordered/dropped; queue occupancy grows unbounded;
  recirc traffic escapes a host port; background load shifts timing unexpectedly; the action would
  displace another live experiment; rollback not staged.
- **Current switch state: RESTORED (2026-07-22, §0.5.10).** Experiment ended and `decoy_paper3` was
  restored (per §20, the switch is not left in an experimental config for a possible future run):
  - killed the microbench `bf_switchd`; relaunched `decoy_paper3` via
    `/home/decps/decoy_paper3/launch_gf_v2b.sh` in tmux session `decoy` (`gc-switchd` stays masked);
  - **restored program:** `decoy_switch_tna`, conf `/home/decps/decoy_paper3/gf_v2b.conf`,
    `tofino.bin` sha256 `013d9e4bf974b1e0…`, `bf_switchd` PID 2432961;
  - **post-restore check:** bfruntime `bind_pipeline_config("decoy_switch_tna")` succeeded, `:50052`
    up → data plane restored. **Caveat:** a cold restart returns decoy to post-compile state; any
    runtime control-plane tables its owner installed at bring-up must be re-run by its owner (I
    restored the data plane, not the owner's controller state).
  - Hulk clean (transient generator only; no netns/rig left).
  - Microbench files remain inert in `/home/decps/queue_microbench/`; a future re-run re-displaces
    decoy under a fresh authorization.

---

## 18. File inventory

```
queue_microbench.p4                    dataplane (headers/parser/classify/pad/pattern/metronome/counters)
queue_microbench_setup.py              control plane; 4 mechanisms (pktgen/shaper/minrate/dwrr)
QUEUE_MICROBENCH_REVIEW.md             pre-authorization review (compile/resource/rollback)
QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md   this report
harness/mb_gen_raw.py, mb_gen.py       Hulk generators
harness/mb_sample.py, mb_read.py       switch-side ground-truth readers
harness/mb_parse.py, mb_analyze.py     offline pcap metrics
harness/mb_capture.sh, mb_run_hulk.sh  hairpin capture
harness/run_matrix.sh                  §4 test matrix as per-host commands
runs/RESULTS_switchside.txt            max-rate shaper results (prior)
runs/RESULTS_minrate_dwrr.txt          min-rate + DWRR results (this run)
runs/mb_*.txt                          per-second sampler evidence (5 files)
runs/shaper_R100.pcap, shaper_R200.pcap, smoke.pcap   shaper pcaps (prior)
compile/out/                           local bf-p4c 9.13.1 artifact + resource logs
```

Reproduce (gated switch window):
```bash
# SWITCH (after authorization + gated bf_switchd swap):
python3.8 queue_microbench_setup.py --mode final --mech pktgen  --tau-ms 10       # metronome (the pacer)
python3.8 queue_microbench_setup.py --mode final --mech minrate --rate-pps 100    # guaranteed floor
python3.8 queue_microbench_setup.py --mode final --mech dwrr    --dwrr-weight 1    # round-robin
python3.8 harness/mb_sample.py 22                                                  # ground-truth cadence
# HULK: sudo python3 harness/mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count 1300 --interval-ms 20  # sparse
#       sudo python3 harness/mb_gen_raw.py --iface enp59s0f0np0 --dports 20001 --count 4500000 --interval-ms 0 # backlog
```

---

## 19. Provenance and integrity notes

- All bfrt idioms are copied from GridCloak's proven, silicon-run code (cited file:line), not guessed:
  ports/pktgen/mirror/TM-cap (`gc_switch_setup_c.py`), min-rate (`exp_tm_floor.py:77-93`), DWRR
  (`legacy/gc_dwrr_setup.py`, `bfrt_gridcloak_setup.py`).
- The microbench measures **wire size + timing**, and **intentionally leaves IP/UDP length/checksum
  stale** — it is not a valid-payload instrument. Any claim about a real DNP3 conversation belongs to
  Level 2, not here.
- All cadence numbers are **switch-side MAC/queue counters**, not host pcap timestamps.
- Vision was OFF for the run; results are on the dp9 single-host hairpin (one clock, attacker-on-wire
  view), not a two-host path.
- The `dcrn_defense1/2.p4` recirc baseline is frozen and untouched; the microbench is a separate
  program that displaces the co-resident program via a gated swap.
