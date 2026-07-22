# CASE_A_QUEUE_DESIGN.md — LOCKED joint size-and-time obfuscation architecture

_Master direction Phase 3, **architecture LOCKED per Dr. Lin 2026-07-21.** `research/caseA-ditto-queue`.
Supersedes the earlier "design-space / pick-one-mechanism" framing. Builds on
`DITTO_QUEUE_RECONSTRUCTION.md`, `DITTO_TO_DNP3_MAPPING.md`, `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md`,
`GRIDCLOAK_TM_QUEUE_AUDIT.md`._

> **LOCK.** The DNP3 obfuscation mechanism is a **single joint size-and-time pattern**. Splitting,
> padding, and queue scheduling are **components of one mechanism, not alternative defenses.** Do NOT
> implement a timing-only queue that ignores the size pattern.

---

## 0. ICS REFINEMENTS (review 2026-07-22) — refine §1a/§4/§7 below; non-negotiable for ICS/SCADA

The Phase-4 microbench run + design review fixed several points. These **refine** the locked
architecture (they do not unlock it) and are authoritative where the older text conflicts. Full
detail + the implemented code: `research/tofino_dcrn_feasibility/p4/queue_microbench/QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md` §0.5.

1. **The pacer is the pktgen internal slot clock, NOT the TM scheduler.** Measured on silicon:
   max-rate, min-rate, and DWRR are all *backlog* disciplines and cannot pace a sparse ~5 Hz flow; only
   the pktgen periodic tick creates the cadence. Call the mechanism a **pktgen-driven size-state slot
   scheduler**. TM still does queue selection, real-vs-cover priority, contention, and occupancy —
   §1a step 8's "TM scheduler determines output time" holds only for a *backlogged* queue, not a
   sparse flow. Continuous-cover (Mode 2) is the only way to make the TM a true pacer, at Ditto cost.
2. **Internal clock ≠ transmitted filler ≠ secure chaff.** An idle metronome tick MUST NOT
   auto-become external cover (the earlier build did — ~100 pps of filler at idle). Implemented fix:
   `MB_METRO` = internal clock, never transmitted by default; `MB_CHAFF` = explicit external cover;
   three controller-selected **cover modes**, default OFF.
3. **Three cover modes (refines §1a step 7 "chaff" + §4 claim scope):**
   - **Mode 0 OFF (default ICS):** idle tick consumed internally, nothing transmitted. Enough for the
     Case A *timing* defenses (Defense 1 hold-ACK, Defense 2 hold-response need no external filler).
   - **Mode 1 TRANSACTION_WINDOW (preferred cover):** bounded N-slot window opened by an eligible DNP3
     transaction; hard caps (max slots, max bytes/txn, max windows/sec, cooldown, quiet-period
     termination, auto-disable on degradation); real strict-priority; cover dropped first. Trigger +
     caps + DoS controls are a follow-on; `window_active` gates it for now.
   - **Mode 2 CONTINUOUS (optional upper bound):** permanent cover; off by default; only on links with
     measured spare capacity.
4. **Claim scope now (refines §4):** claim **joint size normalization + timing control for the packets
   actually transmitted** (incl. CLRT). Do NOT yet claim **READ vs SBO indistinguishability** — that
   needs a *direction-aware canonical transaction schedule* `slot=(direction,size,timing)` with cover
   for missing messages, in **both directions**, and is where cover is *required*, not optional.
5. **Overhead is computed, not "heavy" (refines §4):** 128/256 B pattern → τ=10 ms ≈ 154 kbps/dir
   (~1.66 GB/day), τ=25 ms ≈ 61 kbps/dir. Negligible on ≥100 Mbps fiber; unacceptable on narrowband
   radio / serial-over-IP / cellular / satellite / oversubscribed WAN. Compute per candidate pattern +
   link class (NIST OT: respect performance/availability/safety).
6. **`(P, τ)` are jointly optimized (refines §5):** `P` drives latency (an S1 slot in `[S1,S2]` recurs
   every 2τ). Optimizer output = **`(P, τ, cover_mode, window)`**, not `P` then `τ`.
7. **Deployable padding/cover = two trusted edges + encrypted outer encapsulation (refines §7):** wrap
   the whole inner DNP3/TCP packet, pad the *outer* frame, insert cover; a second trusted edge
   (Vision/DPU/Linux/2nd switch) authenticates, drops cover, removes the wrapper, forwards the inner
   packet unchanged. Inner TCP seq space untouched (retransmit/SACK end-to-end). The cover marker rides
   inside the encrypted/authenticated outer header — **never `0x88B6` on the WAN.** (The per-flow TCP
   seq-space translator is now an *alternative* study, not the primary plan.)
8. **Splitting is NOT on the Tofino-only physical path (refines §7):** "pre-split upstream" = a software
   proxy modifies traffic = the **hybrid software/DPU** path, not transparent switch-only protection of
   an unmodified SEL-751. Tofino-only physical: preserve the inner packet, include a size state large
   enough for the biggest frame, pad smaller frames, **do not split.**
9. **Correctness gates before real-TCP / physical-SEL-751:** enforce ACK-before-response (restore the
   hard zero-inversion token — correctness over 1–2 stages); flow-aware per-transaction state (current
   single per-state counters can't distinguish multiple flows — start limited to *one flow, one
   outstanding transaction*); fine-grained timing measurement (1-second MAC counters ≠ 10 ms slot
   accuracy — need HW timestamps / 2nd measurement port / restored Vision receiver); mandatory priority
   readback with abort-on-mismatch (done); cover always loses to real under congestion; DoS controls on
   transaction-triggered cover.

**Corrected one-line design:** *a size-state pattern paced by an internal pktgen clock, with no
external cover by default, bounded transaction-window cover when transaction-structure hiding is
required, and continuous cover only as an optional mode on links that can safely carry it.*

---

## 1. The locked architecture

1. **Pattern states are target packet sizes.** The visible output is a predefined sequence of
   size states, e.g. `Slot0:128B  Slot1:256B  Slot2:128B  Slot3:256B` (illustrative).
2. **Padding** maps packets **smaller** than a state up to a common state — including **pure ACKs,
   DNP3 requests, and CROB / Select / Operate / confirmation** control packets. Different operations
   thus occupy the same visible size class.
3. **Splitting** maps **selected large/distinctive** responses into a predefined **sequence** of
   smaller size states (e.g. one 2407 B response → `S1 S1 S2 S1`) — used only for response classes
   that do not fit a single state efficiently. (Splitting on-switch is infeasible today — see §7; in
   the software study it is the split harness; on Tofino the "sequence" is realized by the scheduler
   emitting the pre-split components.)
4. **Size-labelled Traffic-Manager queues** hold packets assigned to each size state.
5. **The scheduler** determines state order, packet release time, inter-packet interval, protocol
   ordering (ACK before response), and the pacing of split response components.
6. **Result:** the output obfuscates **packet size, segmentation, inter-packet timing, and
   ACK-to-response timing together.**

### Decisive data flow
```
DNP3 packet classification
      ↓
Size transformation
   ├── pad small packets (ACK, request, CROB/Select/Operate/confirmation) → common size state
   ├── split selected large responses → predefined sequence of smaller size states
   └── preserve packets already matching a state
      ↓
Assign packet to a size-labelled queue
      ↓
Traffic-Manager scheduler
   ├── controls state order
   ├── controls release timing
   ├── preserves protocol ordering (ACK before response)
   └── paces split response components
      ↓
Obfuscated size-and-timing output
```

## 1a. Pattern definition and per-packet algorithm (LOCKED, Dr. Lin 2026-07-21)

**The "pattern" is an ordered SIZE-STATE list** `P = [S0, S1, …, S(L-1)]` (Ditto's architecture) —
each state `Si` specifies a **target protected-link packet size**. **Timing is the scheduler's
interval `τ` or rate `R`, supplied by the Traffic Manager — NOT a per-slot "timing pattern."** The
mechanism is represented as **`(P = [S0…S(L-1)], τ or R)`**. The **Traffic Manager does not determine
the target sizes**; it enforces the **order and transmission timing** of the states via queue
assignment, rate control, priority scheduling, and round-robin scheduling. **Do NOT implement a
timing-valued pattern as a replacement for the size pattern.**

Per incoming DNP3 packet:
1. **Select** the next eligible size state.
2. **Preserve** the packet if it already fits the state.
3. **Pad** it if it is smaller than the state.
4. **Split** it across multiple states **only where the platform has verified support for correct
   splitting** — on Tofino-1 transparent splitting is **not** verified/feasible (§7), so this branch
   is not taken on the current target; fall through to (5).
5. **Otherwise, wait** for a sufficiently large state **or fail open**.
6. **Place** the transformed packet into the **real-packet (high-priority) queue** for that state.
7. **Chaff:** use a **lower-priority chaff/filler queue** for a state when **strict preservation of
   empty pattern states is required** (so round-robin never skips a state).
8. The **TM scheduler** determines the state's output time (`τ`/`R`).

## 2. How Case A maps onto the joint pattern

### Defense 1 — delay the ACK
```
Request arrives → pure ACK retained → response becomes ready
→ ACK mapped to an ACK-compatible size state
→ response mapped to its size state (or split sequence)
→ scheduler releases ACK first, then response, in CONSECUTIVE scheduled slots
```
Output e.g. `Slot n: padded ACK · Slot n+1: first response packet · Slot n+2: second (if split)`.
The scheduler controls the final ACK-to-response gap, response segmentation, visible sizes, and
inter-segment timing. (Event-governed retention of the ACK reuses the recirc-hold + arm/release
machinery — §6.)

### Defense 2 — forward ACK, delay response
```
Pure ACK forwarded → response becomes ready
→ response padded or split into the required size states
→ response waits for the selected pattern position
→ scheduler transmits the response sequence on the common schedule
```
The response no longer leaves on the SEL-751's native processing time.

## 3. CROB / SBO in scope — evaluated at TRANSACTION level
CROB/SBO must be included in the size-and-timing analysis, **evaluated at the transaction level, not
per packet.** `SELECT → confirmation → OPERATE → confirmation` control packets are mapped to common
padded size states and released on the same public schedule as READ traffic — **no unique device- or
operation-specific schedule.** Goal: a passive observer cannot easily distinguish a **normal READ**
from a **SELECT→OPERATE** sequence by sizes and timing.

**★ Padding individual packets does NOT by itself hide SBO.** An SBO transaction has extra **packet
count** and a distinct **direction sequence** that per-packet padding leaves intact. **Strong SBO
hiding requires a canonical slot schedule + chaff (or equivalent filler) for unused slots** — so the
transaction occupies a fixed number of slots regardless of whether it is a READ or a SELECT→OPERATE.
This makes CROB/SBO privacy the concrete case where **chaff is required**, not optional (contrast the
timing-only claim scope in §4).

## 4. Claim scope (current work) — and what is deferred
**Claim:** the system *jointly reshapes packet size, segmentation, and timing* (incl. CLRT and
SBO/CROB patterns) by mapping DNP3 packets to predefined size states transmitted through a scheduled
TM pattern. **Do NOT claim complete traffic-volume independence.** Without continuous chaff, a passive
observer may still see: whether traffic exists, total transaction duration, packet count in some
cases, and unused pattern periods. **Chaff** (and any volume/count-independence claim) is deferred
until chaff is implemented and evaluated (`SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md` §4: volume/count
independence is unreachable without added cover traffic).

## 5. Open parameters (LOCKED architecture, parameters still to determine)
The architecture is locked; these knobs are set at **Phase 4.5/5.5** from the microbench + physical
device, not guessed now:
- **The size pattern `P = [S0…S(L-1)]`** — the ordered target sizes. Determined from the **DNP3
  packet-size distribution** across all packet types (ACK/request/response/control) — a **size**
  computation (this is "the pattern"). *Not yet computed; a follow-on, analogous in method to the
  CLRT characterization but on sizes.*
- **The scheduler timing `τ` (interval) or `R` (rate)** — a **common, device-independent** schedule.
  Timing is supplied by the scheduler, **not** a per-slot timing pattern. The resulting CLRT must be
  a **common absolute deadline OR common repeating schedule**, **not** native+fixed-offset (which only
  shifts the CLRT mean; the distribution shape still classifies — `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md`
  §5). The 17 ms/25 ms CLRT percentiles characterize the **native timing to reshape** and are
  **candidate targets, NOT locked** (`QUEUE_PATTERN_FROM_TRACES.md` reframed as timing-behavior
  characterization; provenance in `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md` §6).
- **Schedule structure** — slot period, `L`, state order, ACK↔response slot adjacency.
- **Split policy** — deferred: on-switch splitting is unverified/infeasible (§7), so no live-split
  size-state sequence on the current target.
- **Chaff** — required for empty-state preservation (§1a step 7) and for strong SBO hiding (§3);
  deferred as a component but no longer "optional" for those cases.

## 6. Carried-over correctness substrate + reusable machinery
Preserve (proven on silicon; the frozen recirc baseline + GridCloak audit):
- **Exact pure-ACK qualification**, response matching, **one outstanding transaction**,
  **ACK-before-response ordering**, **fail-open** on ambiguity, complete per-transaction cleanup,
  **no cold reload / zero stale state**, MAX_PASS as a safety valve only.
- **Byte preservation** for *preserved* and *held* packets (padding/splitting are byte-modifying and
  are the size components — kept explicit and separate from the byte-preserving hold path).
- **From GridCloak (`GRIDCLOAK_TM_QUEUE_AUDIT.md`):** the **pktgen periodic timer as the release
  clock** (the TM PPS shaper starves below ~1200 pps → cannot pace our ~5 Hz flow; pktgen is the
  metronome), the **recirc-hold + balanced arm/release counter registers**, size-labelled queues, and
  the pre-debugged bfrt inventory (ports/pktgen/mirror/TM-cap, `pipe_id=0` rule). Coexistence is a
  **gated bf_switchd swap** (gridcloak claims all 4 pipes), not concurrency.

## 7. Feasibility note (from `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md`)
- **Padding is Tofino-feasible** (prepend a compile-time-constant filler + per-flow seq-Δ; the
  deparser emits it, residual byte-identical).
- **Transparent on-switch splitting is NOT feasible today** (payload opacity, non-constant-time cut,
  proxy-grade reassembly/resegmentation/retransmission state). On Tofino, a "split sequence" is
  realized by the scheduler pacing **pre-partitioned** components (from the software split study),
  not by the ASIC cutting a live payload. This constrains how splitting enters the joint pattern and
  must be resolved before the size-state sequence relies on live on-switch splitting.

## 8. Next step — staged microbenchmark
The Phase-4 TM microbenchmark (`QUEUE_MICROBENCH_PLAN.md`) is **staged**:
- **v1 (first, priority):** **equal-sized** packets to **isolate TM timing behaviour** — does the
  scheduler produce the required timing (interval `τ` / rate `R`) for a sparse low-rate flow
  (metronome vs shaper, empty-vs-backlogged, jitter, ordering, loss, background load)?
- **final:** **multiple size-labelled queues** verifying **both** the emitted **size order** and the
  **inter-packet timing** together, with the real+chaff priority-queue pair per state.
Built and reviewed (source, compile/resource report, TM config, rollback, commands) **before** any
switch access or full-DNP3-program change.
