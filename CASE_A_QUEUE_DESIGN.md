# CASE_A_QUEUE_DESIGN.md — LOCKED joint size-and-time obfuscation architecture

_Master direction Phase 3, **architecture LOCKED per Dr. Lin 2026-07-21.** `research/caseA-ditto-queue`.
Supersedes the earlier "design-space / pick-one-mechanism" framing. Builds on
`DITTO_QUEUE_RECONSTRUCTION.md`, `DITTO_TO_DNP3_MAPPING.md`, `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md`,
`GRIDCLOAK_TM_QUEUE_AUDIT.md`._

> **LOCK.** The DNP3 obfuscation mechanism is a **single joint size-and-time pattern**. Splitting,
> padding, and queue scheduling are **components of one mechanism, not alternative defenses.** Do NOT
> implement a timing-only queue that ignores the size pattern.

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

## 3. CROB / SBO in scope (not a separate line)
CROB/SBO must be included in the size-and-timing analysis. `SELECT → confirmation → OPERATE →
confirmation` control packets are **mapped to common padded size states and released on the same
public schedule** as READ traffic. **No unique device- or operation-specific schedule.** Goal: a
passive observer cannot easily distinguish a **normal READ** transaction from a **SELECT→OPERATE**
sequence by sizes and timing alone (size, packet count, direction sequence, and Select↔Operate timing
are all subsumed into the common pattern).

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
- **Size states** — the set of target sizes. Determined from the **DNP3 packet-size distribution**
  across all packet types (ACK/request/response/control) — a size-pattern computation analogous to
  the timing-pattern one (`QUEUE_PATTERN_FROM_TRACES.md`). *Not yet computed; a follow-on.*
- **Timing-release policy** — a **common, device-independent** policy: a common absolute deadline OR a
  common repeating schedule (`SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md` §5). **Not** native+fixed-offset
  (that only shifts the CLRT mean; the distribution shape still classifies). The 17 ms/25 ms CLRT
  percentiles are **trace-derived candidates, NOT locked** (provenance in that doc §6).
- **Schedule** — slot period, pattern length/states, ACK↔response slot adjacency.
- **Split policy** — which response classes are split, into which size-state sequence.
- **Chaff** — deferred (§4).

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

## 8. Next step — the microbenchmark tests BOTH axes
The Phase-4 TM microbenchmark (`QUEUE_MICROBENCH_PLAN.md`) must evaluate **both**: (a) whether the
scheduler produces the required **timing** pattern; and (b) whether it preserves the required
**sequence of size-labelled states**. It is built and reviewed **before** any switch access or
full-DNP3-program change.
