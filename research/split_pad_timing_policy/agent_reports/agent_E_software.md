<!-- Agent E (software-systems implementation expert), split/pad/timing combined-policy study, 2026-07-13.
Grounded in GROUNDING.md + measured_evidence.md (this dir) and EXTENDS the prior timing-only
scheduler in research/ack_timing_normalization/software_design.md. Research/design only — NO harness
source code was changed. Deliverables covered: software_design.md (combined), the runtime engine in
combined_decision_policy.md, RQ6 (when/how to combine, decision policy), RQ7 (software feasibility),
spec sections 10 (runtime engine) and 11 (mechanism justification). Evidence labels per GROUNDING §17:
[M] measured · [S] standard · [V] vendor/official-doc · [P] paper-reported · [I] inference · [H] hypothesis. -->

# Agent E — Lowest-Overhead Software Policy Engine for Combined Split + Pad + Timing

_Scope: the **runtime engine** that decides, per DNP3 transaction, whether to split, pad, and/or
time-normalize the response, and executes that decision at lowest overhead inside the existing
dependency-free replay/split server (`dnp3_split_harness/split_server.py`). This EXTENDS the prior
timing-only scheduler (`ack_timing_normalization/software_design.md`, read in full) — the timing
stage, target-distribution strategies, deadline model, and mechanism-rejection argument are reused
from there; this report adds the **classify → split → pad → schedule** pipeline, the **per-flow FIFO
queue discipline**, the **residual-size-leakage accounting** that carries the study's honest
padding negative result into telemetry, and the **measured-RTO-fraction** safety math. Design +
literature only; no code modified._

---

## 0. Verdict (lead with the answer)

**Build the combined policy as one application-layer decision-and-release stage inside
`split_server.py`, stdlib-only, single event loop, per-flow FIFO release queue.** The server
*generates* the response bytes (`_send_chunks → socket.sendall`, `split_server.py:556`), so it owns
its own emission timing and its own framing — there is no live third-party packet to intercept.
That fact decides the entire mechanism question: **every kernel/NIC egress shaper (`tc/netem`,
ETF/`SO_TXTIME`, eBPF-TC, XDP, AF_XDP, DPDK) and every in-path option (NFQUEUE, transparent proxy)
exists to delay packets you are *forwarding*; we are *emitting*, so they add a coarser, policy-blind
second stage and strictly lose expressiveness.** [I] The combined policy is in fact *more* firmly an
endpoint concern than timing-only was, because splitting is an application-layer re-framing of a
response (deciding CRC-block groupings) that no per-packet qdisc can express, and padding (a future
phase) is a byte-level operation on the application message. [I]

The workload makes the simplest structures dominant: single-digit kbps, CONFIRM-serialized, **< 1
response outstanding per flow** [I, from prior brief §4.3], ms-scale targets sitting **~20× under the
binding TCP-RTO safety bound** [M, RTO must be measured on Vision, not assumed]. The heavy scheduling
machinery the task names — timing wheels [P, varghese1997hashed], calendar queues
[P, brown1988calendar], Carousel/Eiffel line-rate pacers [P, saeed2017carousel, saeed2019eiffel],
DPDK/AF_XDP — is built to fire **millions** of timed releases per second; we are ~7 orders of
magnitude below that regime, so those data structures are correct to **cite and reject**, not adopt.
[I] The right structure is a **per-flow FIFO deque** (never a global deadline priority-heap — that
would reorder within a flow and violate the phase rule's no-reorder constraint) plus, for the
multi-flow future, a tiny heap of *flow heads* (O(log F), F ≈ 1). [I]

**Two hard corrections to the reused draft, forced by the actual deploy box (verified this
session):** (1) the target host is **Python 3.8.10** — `time.clock_nanosleep` is not a public API
and the 3.11+ internal-`clock_nanosleep` sleep nicety the prior design invoked is **absent**;
`time.monotonic_ns()` *is* present, and 3.8's `nanosleep`/`select` sleep path still delivers ms
precision ~2 orders under budget, so the design holds, but pin/verify the interpreter and do not
claim the 3.11 sleep semantics on this host. [V, checked `python3 --version`, `hasattr(time,
'clock_nanosleep')==False`, `hasattr(time,'monotonic_ns')==True` this session] (2) the server is
deliberately **dependency-free** (no pydnp3, no numpy); keep the engine stdlib-only — use
`random.Random(seed)` for reproducible targets, **not** numpy's Generator. [V, verified
`random.Random(20260713).randint(...)` is deterministic this session]

**Plain language:** put the whole decision (split? pad? delay how long?) in a few dozen lines right
before the server writes its bytes, using only the Python standard library and one alarm-clock per
connection. Never hold a response long enough to make TCP retransmit; if anything is uncertain, send
it now. All the fancy kernel and hardware options are for delaying other people's packets — we make
our own, so we don't need them.

---

## 1. The requirement, stated precisely (combined engine)

| Property | Value (this rig) | Label / source |
|---|---|---|
| Offered load | few hundred B / ~1 s poll ⇒ single-digit kbps | [I] prior brief §4.3 |
| Concurrency (responses in flight / flow) | **< 1** (hold ms ≪ poll ≥ 1 s; CONFIRM serializes fragments) | [I] prior brief §4.3 + DNP3 CONFIRM handshake |
| Splittable payload shape | large READ = 12,204 B / 9 app frags / 49 link frames / 20 TCP segs; 2407 B READ → 141/71/36/18 chunks | [M] measured_evidence §3–4 |
| Small control response shape | SELECT=OPERATE resp 37→256 B over N=1→16 CROBs | [M] measured_evidence §2 |
| The leak(s) to attack | CROB count leaks on **timing** (0.179/0.214 ms/CROB, R²>0.99, n=1/N) **and size** (14.6 B/CROB, R²=0.9999); read size ∝ points (5.7 B/pt) | [M] measured_evidence §1–3 |
| Padding availability | **none** byte-preserving demonstrated (invalid-index CROB → OUT_OF_RANGE; partial SELECT blocks OPERATE) | [M] measured_evidence §5 (NEGATIVE) |
| **Binding safety bound** | master's **effective TCP RTO** (Linux `TCP_RTO_MIN` ≈ 200 ms floor is *not* universal) — **MEASURE on Vision** | [M/S] GROUNDING §Safety |
| Hard session ceiling | 5 s DNP3 app-response / solicited-confirm timer | [I] prior brief §4.1 (OpenDNP3 defaults) |
| Required precision | sub-ms jitter within a ms target, ≥20× under RTO | [I] derived |

This is a **low-rate, low-concurrency, coarse-precision, hard-deadline, byte-preserving** decision
problem with a **residual it cannot close** (total-response size for undersized control responses,
because split preserves total bytes and no safe DNP3 padding exists). The engine's job is to apply
the two byte-preserving levers correctly and to **account for** the size residual honestly, not to
paper over it. [I]

**Plain language:** we can reshape *when* bytes leave and *how they are cut into packets* without
touching a single DNP3 byte. We cannot yet grow a small response to hide its true size. The engine
must do the first two and truthfully log the third as a leftover leak.

---

## 2. The combined decision-policy engine (RQ6 / spec §10)

### 2.1 Pipeline (the exact task flow, as stages)

```
 request frame (last byte)                        response bytes ready
     │  t0 = monotonic_ns()                            │  tr = monotonic_ns()
     ▼                                                 ▼
 ┌──────────────┐   BYPASS (critical / unsupported / unknown-not-allowlisted)
 │ 1. CLASSIFY  │──────────────────────────────────────────────────────────► release NOW (verbatim)
 │  (req,resp)  │                                              reason = *_BYPASS ; no split/pad/delay
 └──────┬───────┘
        │ SHAPE
        ▼
 ┌──────────────┐  pick class's PUBLIC TARGET PROFILE (size target τ_size, timing target dist)
 │ 2. PROFILE   │
 └──────┬───────┘
        ▼
 ┌──────────────┐  is_splittable AND len(resp) ≥ profile.split_threshold  ⇒ split on CRC boundaries
 │ 3. SPLIT     │  (byte-preserving; b"".join(chunks)==resp asserted). Reshapes per-pkt size / #pkts /
 │ (safe bnds)  │  segment & fragment count. Does NOT change total bytes.  [M measured_evidence §4]
 └──────┬───────┘
        ▼
 ┌──────────────┐  apparent_size = total bytes (unchanged by split).
 │ 4. PAD       │  if apparent_size < τ_size:
 │ (future-     │      if cfg.padding.enabled AND approved_mechanism(class): apply   # FUTURE, none exists now
 │  gated)      │      else: residual = τ_size - apparent_size ; RECORD  (reason |= SIZE_RESIDUAL)  [M §5]
 └──────┬───────┘
        ▼
 ┌──────────────┐  τ = target_dist.sample(class, seeded rng)     # class-independent (constant/uniform/
 │ 5. TIMING    │  candidate = max(tr, t0 + τ)                    #  bucketed/decoy/size-decorrelate) — REUSED
 │  TARGET      │
 └──────┬───────┘
        ▼
 ┌──────────────┐  hard_deadline = t0 + min(op_budget, rto_guard) ; rto_guard = frac × MEASURED_rto
 │ 6. DEADLINE  │  fifo_floor  = prev_release_on_flow            # FIFO: releases monotone non-decreasing
 │  + BUDGET    │  release = max(candidate, fifo_floor)
 │  + FIFO      │  if release > hard_deadline OR cum_added > txn_ceiling OR queue_full: FAIL-OPEN (NOW)
 └──────┬───────┘
        ▼
 ┌──────────────┐  enqueue(flow, item{release, chunks}) ; scheduler wakes at head.release
 │ 7. RELEASE   │  emit chunks with inter-chunk-gap pacing (existing knob, now gap-normalized)
 └──────┬───────┘
        ▼
 ┌──────────────┐  TxnRecord → CSV/JSON (seed, residual, miss, reason, chunk sizes, queue depth)
 │ 8. RECORD    │
 └──────────────┘
```

**Plain language:** classify the transaction; if it's a critical or unknown control, send it
untouched immediately. Otherwise pick the public "disguise" for its class, cut a big response into
smaller packets on safe boundaries, note (but for now cannot fix) any size shortfall, choose a
release time, and never hold past the safety deadline. Then log exactly what was done.

### 2.2 State machine (per transaction)

States: `INGEST → CLASSIFY → {BYPASS_RELEASE | PROFILE} → SPLIT → PAD → TIMING → SCHEDULE →
{HELD | RELEASE_NOW} → EMIT → RECORD`. Every non-`RELEASE`/`EMIT` state has one and only one escape
to **`RELEASE_NOW`** (fail-open); there is no state from which a response can be dropped or held past
`hard_deadline`. `HELD` is left only by (a) the deadline firing or (b) the watchdog forcing
`RELEASE_NOW`. This is a deliberately shallow FSM: the safety property "a bug cannot cause an
RTO-tripping hold or a lost response" is provable by inspection because every edge except the timed
release lands on immediate emission. [I]

**Plain language:** the flow chart has exactly one emergency exit from every box — "send it now" —
so no coding mistake can make the server swallow a reply or sit on it too long.

### 2.3 Transaction matching & timestamp selection

- **Matching** is unchanged and reused (`CapturedExchange.match_response`, `split_server.py:361`):
  function code + application sequence, refuse-if-unmatched (never blind-dump). The engine adds no
  new matching; it consumes the matched `entry` and its `is_splittable` flag
  (`split_server.py:444`). [V, read from source]
- **Timestamps (all monotonic, never wall-clock):** `t0_ns = time.monotonic_ns()` at the instant
  `reader.next_frame()` returns the triggering request (request last byte at the app);
  `tr_ready_ns` at chunk assembly; `actual_release_ns` immediately before the first `sendall()`.
  These are the server's *intent* clock. The **authoritative evaluation** timestamp stays the
  PCAP-derived request-first-byte → response-first-byte that `analyze_ack.py:146-157` already
  computes; the server `t0` differs from the wire by kernel→app latency (sub-100 µs on this
  LAN/loopback). [V, read from source] Defer the reproducible PCAP timestamp definition to Agent F.
- **Why monotonic:** `time.monotonic_ns()` is non-settable and immune to wall-clock jumps [V,
  Python `time` docs, verified in the prior study's session — not re-fetched now]; a wall-clock jump
  would otherwise cause a spurious deadline miss. Present on 3.8+ [V, `hasattr` check this session].

**Plain language:** the engine stamps its own start/ready/send times with a clock that only ever
moves forward, so a system time change can't corrupt a deadline. For the paper's numbers, the packet
capture — not the server's clock — is the source of truth.

### 2.4 Classification & bypass (safety-first)

`classify(req, resp) -> TxnClass` over Axis-3 semantics (GROUNDING taxonomy):
`{MONITORING, EVENT, CONTROL, CRITICAL_CONTROL, UNKNOWN, UNSUPPORTED}`. Keyed on the DNP3 function
code (parsed already) and, where the captured entry exposes it, object group/variation, then filtered
through an **operator criticality allowlist** (Agent H owns the allowlist content; the engine owns
the mechanism). Design rules, all defensive:

- **DNP3 fields encode operation *type*, not physical *criticality*** [M/S GROUNDING §Safety] ⇒ the
  classifier can never *infer* that a control is safe to delay; it may only *shape* what the
  operator has explicitly allowlisted.
- **Default = BYPASS.** All control function codes, all `UNKNOWN`, all `UNSUPPORTED`, and anything
  not on the allowlist release immediately, verbatim, no split/pad/delay. `MONITORING` (Class-0
  read plane) is the fully-shapeable, zero-safety-cost class and carries the higher-value
  continuously-sampled leak [I, gaps_and_novelty §4]; it is the primary shaping target.
- **Fail-open on classifier exception** → BYPASS. [I]

Complexity O(1) per transaction (dict lookups). This is the engine-side realization of the study's
H7 answer: *never delay a control you cannot prove non-critical.*

**Plain language:** the engine assumes every control could trip a breaker unless an operator has
signed off on it in a list, so by default controls fly through untouched. Only ordinary meter-reads
get disguised, which is exactly the traffic that carries the leak we most want to hide anyway.

### 2.5 Public target-profile selection

Per class, a **public target profile** = `(size_target_bytes, timing_target_distribution,
split_threshold_bytes, target_chunk_shape)`. "Public" = published/agreed, not derived from the true
response, so it reveals nothing. Profiles are class-independent *within their scope* (all responses
of a class map to the same profile), which is what makes the observable statistically independent of
the hidden quantity. The profile is the single object the split, pad, and timing stages consult, so a
policy change is one config edit. [I]

**Plain language:** each traffic class has one agreed "costume" — a target size, a target shape, and
a target timing pattern — and every response of that class is dressed the same way, so the disguise
itself carries no information about the real message.

### 2.6 Split stage — safe-boundary discovery (byte-preserving)

Reuse `DNP3CRCSplitter` verbatim (`split_server.py:247`): boundaries are the byte offsets that
immediately follow each existing DNP3 CRC block; cutting there means every chunk ends on an
already-valid CRC and `b"".join(chunks) == response` (asserted in-process, `split_server.py:310` and
`:523`). No CRC recompute, no byte edit — this is the phase-legal lever. [V read source; M
measured_evidence §4]

Decision: **split iff `entry["is_splittable"] AND len(response) >= profile.split_threshold_bytes`.**
`blocks_per_chunk` is chosen to map the response onto `profile.target_chunk_shape` (e.g. a target
max-chunk size ⇒ `blocks_per_chunk = ceil(target_chunk_bytes / 18)` since a full CRC block is ≤ 18
wire bytes). Measured control points: bpc 1/2/4/8 on the 2407 B READ ⇒ 141/71/36/18 chunks, all
reassembled, 0 retransmit/reset [M measured_evidence §4].

**Honest limit, enforced in telemetry:** split reshapes Axis-1 *sub*-observables (largest packet,
packet count, link-frame count, TCP-segment count) but **does not change total bytes** — summing the
chunks recovers the size [M]. So split alone cannot decorrelate the *total-size* channel; that is the
pad stage's job, and it is currently unavailable (§2.7). The engine records both the realized chunk
shape *and* the unchanged total, so no reader can mistake reshaping for size-hiding. [I]

Fail path: if the byte-preservation assert ever fails (it must not, on clean input), the engine does
**not** fail-open by sending altered bytes — it falls back to **full (un-split) verbatim** delivery
of the original response and flags `SPLIT_FALLBACK`. Sending corrupted bytes is never an acceptable
fail-open. [I]

**Plain language:** we cut big responses only on the seams DNP3 already put there, so the pieces
still add up to the exact original. That changes how many packets an observer sees, but not the total
number of bytes — and the log says so plainly. If a cut ever wouldn't reassemble, we send the whole
thing uncut rather than ever send wrong bytes.

### 2.7 Pad stage — future-gated, with residual-size accounting (the honest negative)

After split, `apparent_size == native total bytes`. If `apparent_size < profile.size_target_bytes`:

```
if cfg.padding.enabled and approved_padding_mechanism(class) is not None:
    chunks, applied = approved_padding_mechanism(class).pad(chunks, target=size_target)   # FUTURE
    record.pad_applied_bytes = applied
else:
    record.residual_size_bytes = size_target - apparent_size          # RECORD, do not fabricate
    record.reason |= SIZE_RESIDUAL
```

In the **byte-preserving phase, `cfg.padding.enabled` is hard-defaulted `false` and no mechanism is
registered**, so this branch *always* records a residual for undersized responses and never emits a
padding byte. This is the study's core negative result [M measured_evidence §5: invalid-index CROB →
OUT_OF_RANGE, partial SELECT blocks OPERATE, no safe byte-preserving DNP3 padding demonstrated]
surfaced as a first-class, exported metric rather than hidden. `residual_size_bytes` summed over a
run is the quantitative size-leak that remains after the byte-preserving defense — the number the
paper must report, not bury. [I]

The interface (`PaddingMechanism.pad(chunks, target) -> (chunks, applied_bytes)`) is defined now so
the future protocol-modifying phase drops in without touching the pipeline; the registry is empty and
the capability flag is off until that phase is *explicitly* started (GROUNDING phase rule). [I]

**Plain language:** if a response is smaller than its target size, the honest thing today is to write
down how many bytes short it is, because we have no safe way to bulk it up. The code has a labelled
empty slot for a future padding method, switched off, so nobody mistakes "planned" for "done."

### 2.8 Timing target & deadline calculation

The timing stage is the **prior timing-only scheduler, reused unchanged** — target-distribution
strategies (`constant / uniform / bucketed / size_decorrelate / decoy_match`), the absolute-deadline
model, and the budget gate all come from `ack_timing_normalization/software_design.md §4`. The
combined engine only wires it after split/pad and adds the FIFO floor (§2.9). Deadline math:

```
tau              = target_dist.sample(class, rng)          # class-independent; seeded
candidate_ns     = max(tr_ready_ns, t0_ns + tau)           # predictive-mitigation release
fifo_floor_ns    = flow.prev_release_ns                    # FIFO: never release before the last one
release_ns       = max(candidate_ns, fifo_floor_ns)
rto_guard_ns     = int(cfg.rto_fraction * MEASURED_RTO_NS) # e.g. 0.5 × measured effective RTO
op_budget_ns     = cfg.op_budget_ns                        # operational latency SLA (≤ rto_guard)
hard_deadline_ns = t0_ns + min(op_budget_ns, rto_guard_ns)
```

`op_budget_ns` (operational) and `rto_guard_ns` (correctness+stealth) are **independent** ceilings;
the tighter binds. **`rto_guard` MUST be a *fraction* of the *measured* effective RTO on Vision — a
fixed 150 ms guessed against an assumed ~200 ms RTO is only 0.75× and is unsafe** [M/I GROUNDING §Safety;
gaps_and_novelty §"do-not-overclaim"]. Default operating point (15–25 ms target) sits well under a
~200 ms floor, but the number is provisional until measured. `size_decorrelate` is the recommended
default (drives the attacker's CROB→time regression β→0 at lower added latency than constant-time),
with `constant` and `uniform` as the head-to-head evaluation arms. [I/H — the P6 advantage is a
pre-registered test, not an assumed result; keeping P6 non-averageable requires the common target to
exceed the worst native time, eroding part of the advantage — per gaps_and_novelty H3/H4]

**Plain language:** hold the response until the later of "it's ready" and "the chosen delay has
elapsed," but never past a safety cutoff set as a fraction of the *measured* time at which TCP would
retransmit — measured, not guessed, and never above ~half of it.

### 2.9 Per-flow FIFO queue discipline & concurrency (the new structural part)

The phase rule forbids TCP reordering, so **within a flow, release times must be monotone
non-decreasing** — the FIFO floor in §2.8 enforces exactly this. The consequence for data structures
is the load-bearing design decision of this report:

- **Do NOT use a global deadline min-heap across all transactions.** A priority queue keyed on
  `release_ns` would happily dequeue a later-enqueued transaction before an earlier one on the same
  flow whenever its deadline is smaller — that is a reorder, and it is forbidden. [I]
- **Correct structure: one FIFO `collections.deque` per flow** (a flow = `(peer_addr, port)`),
  plus, for the multi-flow future, a **small min-heap of *flow heads*** keyed on the head item's
  `release_ns` (O(log F), F = number of concurrent flows ≈ 1 here). Within a flow: strict FIFO,
  O(1) append/pop. Across flows: heap picks the next global wake. Reordering is structurally
  impossible within a flow and irrelevant across flows (independent TCP connections). [I]
- **Today (single flow, concurrency < 1):** the deque holds ≤ 1 item in steady state (≤ 2 across a
  READ + CONFIRM-continuation). The whole "scheduler" collapses to **one blocking absolute-deadline
  sleep** on the one CONFIRM-serialized connection, which has nothing else to do — behaviorally
  identical to an async single-timer schedule, and simpler. [I]
- **Future (concurrent masters):** one `asyncio` event loop, one coroutine per connection, per-flow
  deques, the flow-head heap, and `loop.call_at(head.release_ns/1e9, …)` timer callbacks on the loop
  thread. Single thread, **no locks, no busy-wait, no thread-per-packet** (spec + GIL rationale). [I]
- **Held-packet / queue limits:** `max_queue_depth` (count) and `max_held_bytes` per flow. On
  overflow → **fail-open drain**: release the head immediately (`QUEUE_FULL`), because holding more
  risks an RTO on the *oldest* item. Defaults are generous (depth 4, a few KB) because DNP3's
  CONFIRM serialization keeps the real depth ≤ 2. [I]

**Plain language:** each connection has its own single-file line; a reply can never jump ahead of one
that arrived earlier on the same connection (that would scramble TCP). With only one master and one
reply in flight at a time, the "line" is usually just one item and a single timer. If a line ever
backs up past a small limit, we release the oldest immediately rather than risk a retransmit.

### 2.10 Fail-open catalogue (every abnormal path → immediate verbatim release)

| Condition | Reason code | Action |
|---|---|---|
| Class critical / unsupported / unknown-not-allowlisted | `CRITICAL_BYPASS` / `UNSUPPORTED_BYPASS` | release NOW, verbatim (no split/pad/delay) |
| `release_ns > hard_deadline` (op or RTO budget) | `BUDGET_EXCEEDED` | release NOW, `deadline_miss=True` |
| cumulative added latency > `txn_ceiling` (multi-fragment) | `CUMULATIVE_BUDGET` | release NOW, `deadline_miss=True` |
| per-flow queue depth / held-bytes exceeded | `QUEUE_FULL` | release head NOW |
| CRC-split byte-preservation assert fails | `SPLIT_FALLBACK` | send **full un-split** original (never altered bytes) |
| classifier / scheduler / strategy exception | `SCHED_ERROR` | release NOW, verbatim |

**No fail-closed anywhere.** For SCADA, dropping or over-holding a response to preserve privacy is
unacceptable; **privacy yields to delivery every time** [I gaps_and_novelty §"safety dominates"]. A
deadline miss is a *logged first-class outcome and a cost metric*, not an exception. The
`min(release_ns, now + rto_guard_ns)` watchdog in the release path guarantees a bug cannot produce an
RTO-tripping hold. [I]

**Plain language:** in every failure or doubt, the rule is "send it now, uncut, and write down why."
There is no code path that ever holds a reply too long or throws one away.

### 2.11 Seed handling (reproducible, stdlib-only)

One master `seed` in config → per-flow deterministic sub-stream: `flow_rng =
random.Random(seed ^ (hash(flow_key) & 0xFFFFFFFF))` (stdlib `random.Random`, **not** numpy — server
stays dependency-free [V verified this session]). The seed is written into **every** `TxnRecord`, so
the exact target sequence is replayable and diff-able across runs. Same seed ⇒ identical
`target_delay_ns` column (a unit test). [I]

**Plain language:** one seed makes the random delays repeatable and it's saved in every log row, so
two runs with the same seed produce byte-identical timing decisions — essential for a paper's
reproducibility.

### 2.12 Data structures

```python
class TxnClass(enum.Enum):
    MONITORING = 1; EVENT = 2; CONTROL = 3; CRITICAL_CONTROL = 4; UNKNOWN = 5; UNSUPPORTED = 6

class ReleaseReason(enum.Flag):
    SHAPED = auto(); READY_AFTER_TARGET = auto(); SIZE_RESIDUAL = auto()
    CRITICAL_BYPASS = auto(); UNSUPPORTED_BYPASS = auto()
    BUDGET_EXCEEDED = auto(); CUMULATIVE_BUDGET = auto(); QUEUE_FULL = auto()
    SPLIT_FALLBACK = auto(); SCHED_ERROR = auto()

@dataclass
class Profile:                       # the public target profile per class
    size_target_bytes: int
    split_threshold_bytes: int
    target_chunk_bytes: int          # → blocks_per_chunk = ceil(target_chunk_bytes/18)
    timing_policy: str               # constant|uniform|bucketed|size_decorrelate|decoy_match
    timing_params: dict

@dataclass
class FlowState:                     # per (peer_addr, port)
    queue: collections.deque         # FIFO of ReleaseItem; O(1) ends
    prev_release_ns: int = 0         # FIFO floor (monotone non-decreasing)
    rng: random.Random = None
    cum_added_ns: int = 0            # cumulative added latency across a transaction's fragments
    held_bytes: int = 0

@dataclass
class TxnRecord:                     # one row per transaction/fragment → CSV/JSON
    txn_id: int; fragment_index: int
    function_code: int; app_seq: int; txn_class: str
    is_splittable: bool; native_size: int; apparent_size: int
    chunk_count: int; chunk_sizes: list
    size_target: int; residual_size_bytes: int; pad_applied_bytes: int
    t0_ns: int; tr_ready_ns: int
    target_delay_ns: int; candidate_release_ns: int
    fifo_floor_ns: int; hard_deadline_ns: int
    actual_release_ns: int; requested_delay_ns: int; actual_delay_ns: int
    deadline_miss: bool; queue_depth: int
    reason: str; seed: int
```

- **Deadline scheduler:** per-flow FIFO deque + flow-head min-heap (`heapq`, O(log F)). Timing wheel
  [P varghese1997hashed] / calendar queue [P brown1988calendar] **explicitly rejected** — unneeded
  below thousands of concurrent flows (§3). [I]
- **Target distribution:** strategy object `sample(class, rng) -> target_delay_ns` (reused).
- **Criticality table:** `classify(req, resp) -> TxnClass` with fail-open BYPASS default.
- **Padding registry:** `dict[TxnClass, PaddingMechanism]` — **empty** this phase.

### 2.13 Pseudocode (the release decision)

```python
def decide_and_enqueue(flow, ctx, t0_ns, cfg):
    cls = safe_classify(ctx, cfg)                       # exception → UNKNOWN
    if cls in cfg.bypass_classes or cls in (TxnClass.CRITICAL_CONTROL,
                                            TxnClass.UNSUPPORTED, TxnClass.UNKNOWN):
        return release_now(flow, ctx.resp_bytes, reason=bypass_reason(cls))

    prof   = cfg.profiles[cls]

    # 3. SPLIT (byte-preserving) --------------------------------------------
    if ctx.is_splittable and len(ctx.resp_bytes) >= prof.split_threshold_bytes:
        bpc    = max(1, ceil(prof.target_chunk_bytes / 18))
        try:
            chunks = SPLITTER.split(ctx.resp_bytes, bpc)     # asserts join==resp
        except ValueError:
            return release_now(flow, ctx.resp_bytes, reason=SPLIT_FALLBACK)   # never send altered
    else:
        chunks = [ctx.resp_bytes]
    apparent = sum(len(c) for c in chunks)               # == native total (split preserves bytes)

    # 4. PAD (future-gated) -------------------------------------------------
    residual = pad_applied = 0
    if apparent < prof.size_target_bytes:
        mech = cfg.padding_registry.get(cls) if cfg.padding_enabled else None
        if mech is not None:
            chunks, pad_applied = mech.pad(chunks, prof.size_target_bytes)     # FUTURE
        else:
            residual = prof.size_target_bytes - apparent  # RECORD honest leak; no fabricated bytes

    # 5-6. TIMING + DEADLINE + FIFO ----------------------------------------
    tr        = monotonic_ns()
    tau       = prof.sample(cls, flow.rng)               # class-independent, seeded
    candidate = max(tr, t0_ns + tau)
    release   = max(candidate, flow.prev_release_ns)     # FIFO floor: monotone non-decreasing
    rto_guard = int(cfg.rto_fraction * cfg.measured_rto_ns)      # frac × MEASURED rto (never guessed)
    hard_dl   = t0_ns + min(cfg.op_budget_ns, rto_guard)
    added     = max(0, release - tr)

    if release > hard_dl or (flow.cum_added_ns + added) > cfg.txn_ceiling_ns \
            or len(flow.queue) >= cfg.max_queue_depth or (flow.held_bytes + apparent) > cfg.max_held_bytes:
        reason = (BUDGET_EXCEEDED if release > hard_dl else
                  CUMULATIVE_BUDGET if (flow.cum_added_ns + added) > cfg.txn_ceiling_ns else QUEUE_FULL)
        return release_now(flow, chunks, reason=reason | maybe(SIZE_RESIDUAL, residual))

    reason = (SHAPED if release > tr else READY_AFTER_TARGET) | maybe(SIZE_RESIDUAL, residual)
    flow.queue.append(ReleaseItem(release_ns=release, chunks=chunks, ctx=ctx, reason=reason,
                                  residual=residual, pad_applied=pad_applied, tau=tau))
    flow.held_bytes += apparent
    heap_update_flow_head(flow)                          # O(log F)

def on_timer(flow):                                     # single sleep (sync) or loop.call_at (async)
    item = flow.queue[0]
    hard_cap = min(item.release_ns, monotonic_ns() + int(cfg.rto_fraction * cfg.measured_rto_ns))
    sleep_ns = hard_cap - monotonic_ns()
    if sleep_ns > 0:
        time.sleep(sleep_ns / 1e9)                      # no busy-wait; 3.8 nanosleep path (ms is ample)
    emit_chunks(flow, item.chunks)                      # existing inter-chunk-gap pacing preserved
    flow.prev_release_ns = monotonic_ns()               # advance FIFO floor
    flow.held_bytes -= sum(len(c) for c in item.chunks)
    flow.cum_added_ns += max(0, flow.prev_release_ns - item.ctx.tr_ready_ns)
    record(item)                                        # TxnRecord → CSV/JSON
    flow.queue.popleft(); heap_update_flow_head(flow)
```

### 2.14 Computational complexity

| Stage | Cost | Note |
|---|---|---|
| classify | O(1) | dict lookups |
| split | O(n) in response bytes | single CRC-boundary scan; existing `crc_boundaries` |
| pad (this phase) | O(1) | residual = one subtraction; no byte copy |
| target sample | O(1) | one RNG draw |
| deadline + FIFO | O(1) | max/compare; FIFO floor is a field read |
| enqueue / next-wake | O(1) append / O(log F) heap | F = concurrent flows ≈ 1 |
| **per transaction** | **O(n)** (dominated by split scan) + O(log F) | n = response bytes |
| memory | O(Q) held bytes + O(F) flow state + O(1) strategy | Q ≤ a few KB (depth ≤ 2 in practice) |

Per-transaction CPU is a handful of `monotonic_ns` reads + one RNG draw + one comparison chain + one
record append ≈ **single-digit microseconds**; at a few transactions/second this is **≪ 0.1 % of one
core**. The wall-clock *delay* (ms) is intentional latency, not CPU — the CPU sleeps. Memory: one
`TxnRecord` ≈ a few hundred bytes; 10⁵ logged ≈ a few MB append-only; resident scheduler state
single-digit KB. [I — order-of-magnitude, consistent with prior brief §4.9; captured response bytes
already dominate resident memory]

**Plain language:** the decision costs microseconds of CPU and kilobytes of memory per reply. The
only real cost is the delay we add on purpose, and even a generous delay is a small fraction of the
retransmit point.

---

## 3. Mechanism comparison (RQ7 / spec §11) — justify or reject quantitatively

### 3.1 The framing that decides everything: generating endpoint ≠ in-path forwarder

`split_server.py` **emits** bytes it reconstructed from capture; it never holds a live master packet.
So the home is **application-layer emission scheduling**, and kernel/NIC/in-path shapers apply only
to a *future in-path middlebox* (a proxy/MITM — forbidden this phase). The combined policy sharpens
this: splitting decides *application-message CRC-block groupings* and padding is a *byte-level
message operation* — neither is expressible as a per-packet egress delay, so the qdisc family cannot
even represent the split/pad decisions, let alone the FIFO+deadline coupling. [I]

| Mechanism | Applies to | Fit for combined engine | Verdict | Label |
|---|---|---|---|---|
| **Synchronous monotonic-deadline sleep** | endpoint-generated | Matches today's single serialized flow; one `time.sleep` to a computed monotonic deadline; drift-free (single sleep, no re-arm); no busy-wait | **RECOMMENDED (now)** | [I]; [V] 3.8 has `monotonic_ns`, no `clock_nanosleep` |
| **asyncio `loop.call_at`** | endpoint-generated | Correct the moment concurrency > 1: single thread, per-flow coroutines, `call_at` at absolute monotonic time; no locks/threads-per-packet | **RECOMMENDED (future concurrent)** | [V] asyncio docs (verified prior session) |
| **Priority heap (`heapq`)** | endpoint-generated | Only as the **flow-head** heap (O(log F)); **NOT** a global per-transaction deadline heap (would reorder within a flow) | **Adopt narrowly; reject as global scheduler** | [I] |
| **Timing wheel** | endpoint-generated | O(1) timer start/stop for **millions** of timers; we have ≤ 1 | **Reject (cite: proof we're 10⁷× below its regime)** | [P] varghese1997hashed, saeed2017carousel, saeed2019eiffel |
| **Calendar queue** | endpoint-generated | O(1) bucketed PQ for large future-event sets (DES) | **Reject (same reason)** | [P] brown1988calendar |
| **`tc`/`netem`** | in-path forwarding | Blind per-interface/class delay; no per-txn `t0`/size/class state; cannot split or pad; can reorder | **Reject for production; keep only to *emulate* RTO/latency in the evaluation** | [V] tc-netem(8) (verified prior session) |
| **ETF qdisc + `SO_TXTIME` (EDT)** | in-path forwarding | Per-packet absolute-deadline release — the closest kernel primitive to "send this packet at time T"; but only if *we* are the skb sender, and it still has no split/pad/DNP3 policy layer | **Reject now; the right *kernel* home for a future in-path forwarder** | [V] tc-etf(8) (verified prior session) |
| **eBPF-TC (clsact egress)** | in-path forwarding | Programmable EDT/pacing in kernel; writing per-txn DNP3-aware split/pad policy in BPF is far more effort than Python for zero benefit at kbps | **Reject** | [I] |
| **XDP** | ingress hook | RX/ingress only; **no native generic egress timed-release primitive**; delaying needs redirect to userspace/AF_XDP and timing there | **Reject / unsuitable** | [V] AF_XDP kernel doc (verified prior session) |
| **AF_XDP** | high-pps userspace I/O | You'd rebuild the wheel in userspace; justified only at high pps we never reach | **Reject** | [V] AF_XDP kernel doc |
| **DPDK** | kernel-bypass line-rate | Sub-µs TSC timers but **burns a busy-poll core** and reimplements TCP/DNP3; indefensible to pace ~1 pps | **Reject** | [P] dpdk.org design (not re-fetched this session) |
| **NFQUEUE** | in-path forwarding | Hold/re-inject live packets with delayed verdict; per-packet, ms-scale; it is a MITM and adds copy overhead; nothing over app scheduling for a generating endpoint | **Reject / out of scope (phase rule)** | [I] |
| **Transparent proxy** | in-path forwarding | Full MITM; forbidden this phase; would also have to re-implement split/pad it can't see | **Reject / out of scope** | [I] |

**Ranking for THIS deliverable:** application scheduling (sync sleep now → `call_at` when concurrent)
≫ narrow `heapq` for flow-heads ≫ (ETF/EDT ≈ netem, *only* for a future in-path proxy / for emulation)
≫ eBPF/AF_XDP/DPDK (unneeded); XDP unsuitable; timing-wheel/calendar-queue rejected as
over-provisioned. [I]

### 3.2 Why the heavy machinery is quantitatively wrong here

Concurrency < 1 ⇒ the release set has n ∈ {0,1} per flow ⇒ O(1)-vs-O(log n) is a distinction without
a difference. Timing wheels/calendar queues/DPDK/AF_XDP earn their complexity at **Mpps, sub-µs,
line-rate** [P saeed2017carousel, saeed2019eiffel]; our rate is **~1 pps** and our precision need is
**sub-ms** — ~7 orders of magnitude of headroom. Spending a busy-poll DPDK core or a BPF program on
this workload would *increase* CPU by orders of magnitude for **zero** precision benefit inside our
budget. Citing them is the honest overhead framing: we name the tools, show we understand them, and
show the math that says "not here." [I]

**Plain language:** the industrial-strength schedulers are for firing millions of timers a second; we
fire about one. The simplest possible timer isn't a compromise — it's the correct engineering choice,
and the fancy options would cost far more CPU for no gain.

### 3.3 Achievable precision on the actual box (the "software is sufficient" proof)

- Nominal `clock_getres(CLOCK_MONOTONIC)` ≈ 1 ns, but achievable sleep jitter is bounded by OS
  scheduler granularity: **tens of µs on an unloaded server-class Linux**, rising to a few hundred µs
  – ~1 ms under CPU load / C-states / CFS preemption. [V clock_nanosleep(2) semantics, verified prior
  session] On **Python 3.8** the sleep goes through `nanosleep`/`select`, not the 3.11+
  internal-`clock_nanosleep` path — still ms-precise, ample here. [V `hasattr` check this session]
- **GIL** is a non-issue (single-threaded hold path). **GC** is the one real jitter source; the hold
  path does near-zero allocation, so it rarely triggers a collection; optionally `gc.freeze()` at
  startup; flag any hold whose actual delay deviates from target by > `jitter_flag_ms`. [I]
- **Verdict:** even a pessimistic 1 ms of software jitter is ≤ 5 % of a 20 ms target and ≈ 0.5 % of a
  200 ms RTO budget — inside the target distribution's own spread and the safety margin. CPython
  software scheduling is sufficient by **two-plus orders of magnitude**; the §7 micro-benchmark
  quantifies it on the rig. [I/H — to be measured, not asserted]

**Plain language:** the standard-library sleep on this machine is accurate to well under a
millisecond in practice, and our delays and safety margins are tens to hundreds of times larger, so
plain Python is comfortably good enough. We'll still measure the actual jitter on the rig.

---

## 4. Modes & configuration schema

### 4.1 Mode matrix (all flags)

- **Shape mode:** `native | split-only | timing-only | split+timing | (future) +padding` —
  orthogonal on/off for the split and timing stages; padding gated by capability flag.
- **Target distributions:** `constant (fixed) | uniform (bounded-random) | bucketed | decoy_match |
  size_decorrelate`.
- **Per-class:** independent profiles + **strict per-class budgets** (a class may cap its own added
  latency below the global RTO guard).
- **Inter-chunk-gap normalization:** on/off (existing `chunk_delay_ms` becomes a normalized gap).
- **Immediate-release fallback (fail-open):** always on, not toggleable.
- **Reproducible seed; monotonic hi-res time; no busy-wait; no thread-per-packet:** invariants, not
  options.
- **Telemetry:** `csv | json`. **PCAP-grounded correctness gate:** byte-preservation, 0
  retransmits/resets, DNP3 CONFIRM, 800-measurement count (rig bar, §7).

### 4.2 YAML schema (extends the prior timing config; every field mirrored in `lab_config.py`)

```yaml
combined_policy:
  enabled: true
  mode: split+timing            # native|split-only|timing-only|split+timing|split+timing+padding(FUTURE)
  seed: 20260713                # stdlib random.Random; logged in every record
  clock: monotonic              # invariant — never wall-clock
  safety:
    measured_rto_ms: null       # REQUIRED before any shaped rig run — measure on Vision, do NOT guess
    rto_fraction: 0.5           # rto_guard = rto_fraction × measured_rto_ms  (hard watchdog; ≤0.5)
    op_budget_ms: 20            # operational SLA ceiling (must be ≤ rto_guard once RTO is measured)
    txn_ceiling_ms: 800         # cumulative multi-fragment ceiling (< 5 s DNP3 timer / n_frag margin)
  queue:
    max_depth: 4                # per-flow FIFO depth (real depth ≤ 2 under CONFIRM serialization)
    max_held_bytes: 8192        # per-flow held-byte cap; overflow → fail-open drain
  classes:                      # per-class public target profiles (allowlist owned by Agent H)
    MONITORING:
      shape: true
      size_target_bytes: 1300
      split_threshold_bytes: 300
      target_chunk_bytes: 72    # → blocks_per_chunk = ceil(72/18) = 4
      timing_policy: size_decorrelate
      timing_params: {size_key: response_len, target_ms: 25}
    CONTROL:        {shape: false}      # bypass by default (safety)
    CRITICAL_CONTROL: {shape: false}    # never shaped
    UNSUPPORTED:    {shape: false}
    UNKNOWN:        {shape: false}      # fail-open default
  padding:
    enabled: false              # FUTURE, protocol-modifying phase only; hard-off now
    registry: {}                # empty — no safe byte-preserving DNP3 padding exists (measured_evidence §5)
    record_residual: true       # ALWAYS record size_target - apparent_size as the honest leak
  inter_frame_gap:
    normalize: true
    gap_ms: 10                  # existing chunk_delay_ms knob (segmentation channel)
  telemetry:
    format: csv                 # csv | json
    path: logs/replay/combined_records.csv
    jitter_flag_ms: 1.0
```

**Plain language:** one config file turns each disguise on or off per traffic class, sets the safety
cutoff as a fraction of the *measured* retransmit time, and keeps padding switched firmly off with a
note that we still log the size we couldn't hide.

---

## 5. Logging, metrics, and telemetry export

One `TxnRecord` (§2.12) per transaction/fragment → CSV or JSON, plus an aggregate summary at
shutdown. Exported metrics:

- **Privacy/leak:** per-class `residual_size_bytes` distribution (the honest size leak), realized
  request→response delay distribution vs the declared target (Wasserstein-1 / KS to be computed by
  the evaluation, Agent F/I), CROB→time regression β/R² before vs after (from `analyze_ack.py`).
- **Cost:** added-latency distribution, `deadline_miss` rate, per-class bypass rate, split chunk-count
  distribution, inter-chunk gap realized vs target, queue high-water, jitter-event count.
- **Correctness:** byte-preservation pass/fail count (must be 100 % pass), split-fallback count.
- **Reproducibility:** `seed` on every row; same seed ⇒ identical `target_delay_ns` column.

The server log is ground truth for **what the scheduler intended**; the PCAP is ground truth for
**what the observer sees** (packet count after GSO/coalescing may differ from the software chunk
count — the software chunk count is an *intent*, the wire is authoritative; that boundary belongs to
Agent B/F). [I]

**Plain language:** every reply produces one log row saying what class it was, how it was cut, how
long it was held, how many bytes of size leak remained, and the seed — enough to reproduce the run
and to compute the paper's privacy and overhead numbers, with the packet capture as the final word on
what actually went on the wire.

---

## 6. Error handling & safety (consolidated)

- **Fail-open everywhere** (§2.10): every abnormal path releases immediately; the watchdog caps any
  hold at `rto_fraction × measured_rto`; a deadline miss is a logged metric, not an exception.
- **Never send altered bytes:** a split-preservation assert failure falls back to **full verbatim**
  delivery, not to sending corrupted chunks.
- **Never delay an unproven control:** default BYPASS for all controls/unknown/unsupported; only the
  operator allowlist can promote a control to shapeable.
- **Measured-RTO discipline:** `measured_rto_ms` is `null` by default and the engine **refuses to run
  a shaped session** until it is set from a Vision measurement; `rto_fraction ≤ 0.5`. A fixed guess
  against an assumed RTO is a config error, not a default. [M/I GROUNDING §Safety]
- **Byte-preservation invariant** is asserted in-process on every splittable response, as today
  (`split_server.py:523`). [V]

---

## 7. Test plan (unit + integration + PCAP validation)

**Unit (stdlib `unittest`, no rig):**
1. **Classifier** — each function code / object group maps to the expected class; unknown → UNKNOWN;
   allowlist promotes/demotes correctly; exception → UNKNOWN (fail-open).
2. **Split byte-preservation** — for every `blocks_per_chunk`, `b"".join(chunks) == response`;
   forced assert failure → `SPLIT_FALLBACK` returns the full original.
3. **Residual accounting** — undersized response with `padding.enabled=false` records
   `residual_size_bytes = target − apparent` and emits **zero** padding bytes.
4. **Target determinism** — same `seed` ⇒ identical `target_delay_ns` sequence (two `random.Random`
   runs); different flow keys ⇒ independent sub-streams.
5. **Deadline math** — `candidate = max(tr, t0+τ)`; `release = max(candidate, fifo_floor)`;
   `release > hard_deadline` ⇒ `BUDGET_EXCEEDED`, `deadline_miss=True`, immediate.
6. **FIFO monotonicity** — a later transaction with a *smaller* deadline never releases before an
   earlier one on the same flow (`prev_release_ns` floor holds); cross-flow independence.
7. **Queue limits** — depth / held-bytes overflow ⇒ `QUEUE_FULL` drains the head.

**Integration — loopback smoke (127.0.0.1, fast gate):**
8. Every mode (`native / split-only / timing-only / split+timing`) runs end-to-end; byte-preservation
   holds in all.
9. **Jitter micro-benchmark** — schedule N=10⁴ releases at known monotonic deadlines, idle then under
   `stress-ng`, record `actual − target`; confirm p95 |error| sub-ms idle and characterize the loaded
   tail (this quantifies §3.3 on *this* 3.8 host).
10. **Fail-open** — `op_budget < target` ⇒ `BUDGET_EXCEEDED`; kill the classifier ⇒ `SCHED_ERROR`,
    immediate release; both logged.
11. **Export** — CSV and JSON well-formed, all fields populated, seed present.

**PCAP validation — rig (Vision master ↔ Hulk `split_server.py`), the real bar:**
12. **Correctness bar (project rule):** **800 measurements** to the per-phase CSV, a DNP3 **CONFIRM**
    observed, clean PCAP with **0 retransmits / 0 resets**, no DNP3 timeout, byte-preservation
    asserted. Do not claim rig success from loopback.
13. **RTO measured, not assumed** — first `sysctl net.ipv4.tcp_retries2` + `ip route … rto_min` on
    Vision and observe request→first-retransmit in a capture; set `measured_rto_ms`; confirm no added
    latency exceeds `rto_fraction × measured_rto` and no retransmit appears in any shaped run.
14. **Timing leak destroyed** — re-run `analyze_ack.py` under `size_decorrelate`; CROB→response-time
    slope collapses (β→0, R²→~0) vs baseline 0.179/0.214 ms/CROB; report KS/Wasserstein-1 to the
    declared target. [H — the defended run is the evidence still owed; do not pre-claim]
15. **Size residual reported honestly** — for small control responses, `residual_size_bytes > 0` is
    exported and stated as the surviving size leak (not hidden). [M measured_evidence §5]
16. **Multi-fragment** — a multi-fragment READ: both fragments shaped, CONFIRM completes, cumulative
    added latency < `txn_ceiling`, each hop < `rto_guard`, FIFO order preserved.

**Pass criteria:** byte-preservation 100 %; 0 retransmits/resets/timeouts; CONFIRM present; wire
delay distribution matches target within tolerance; timing leak β destroyed; size residual reported;
seed-reproducible.

---

## 8. Where it slots into `split_server.py` (design only — no code written)

One decision-and-release stage between response selection (`match_response`, `:361`) and the existing
chunk send (`_send_chunks`, `:556`), plus a recorder. The two invariants are untouched: byte
preservation (`:523`) and refuse-if-unmatched (`:517`).

| Component | Responsibility | New / existing |
|---|---|---|
| `FrameReader` / `parse_dnp3_request` | reassemble frames; fc, app_seq, `t0` stamp | existing (`:187`, `:106`) |
| `CapturedExchange.match_response` | select matching response; refuse unmatched | existing (`:361`) |
| `DNP3CRCSplitter` | byte-preserving CRC-boundary split | existing (`:247`) |
| **CriticalityClassifier** | class + BYPASS gate; fail-open default | **new** |
| **ProfileTable** | per-class public target profile | **new** |
| **PaddingRegistry** | future padding; empty now; residual accounting | **new (empty)** |
| **TargetDistribution** (strategy) | sample τ ⟂ class/size (constant/uniform/bucketed/decoy/size-decorr) | **reused** from prior design |
| **DeadlineScheduler + per-flow FIFO** | FIFO floor, budget/RTO guard, cumulative ceiling, queue limits, fail-open; sync sleep now / `call_at` future | **new (FIFO) + reused (deadline)** |
| **Recorder** | TxnRecord → CSV/JSON; seed, residual, jitter flag | **new** |
| `_send_chunks` | emit chunks; inter-frame-gap pacing | existing (`:556`), knob retained |
| `lab_config.py` | single source of truth for all new defaults | existing pattern extended |

**Plain language:** the new code is a self-contained middle stage — classify, split, note the size
gap, choose a delay, queue it in order, send — bolted between the two functions the server already
uses to pick a reply and to write it, without disturbing either.

---

## 9. Reuse & provenance (what I did NOT redo)

Reused unchanged from `ack_timing_normalization/software_design.md`: the target-distribution
strategies, the `max(ready, t0+τ)` predictive-mitigation release, the absolute-deadline model, the
sync-sleep-vs-`call_at`-vs-heap analysis, and the "reject timing-wheel/calendar-queue/DPDK/AF_XDP at
our rate" argument. **New in this report:** the classify→split→pad→schedule pipeline and its state
machine; the **per-flow FIFO deque + flow-head heap** discipline (correcting a global deadline heap,
which would reorder); **residual-size-leakage accounting** carrying the padding negative result into
telemetry; the **measured-RTO-fraction** watchdog (config refuses to run un-measured); the
**stdlib-only / Python-3.8** corrections verified against the actual deploy box. Version-sensitive OS
/ CPython behavioral claims marked [V] were verified in the prior study's session (asyncio, netem,
etf, AF_XDP man pages) and are reused, except the Python-version and `random.Random` facts, which I
verified **this** session; I did not re-fetch the man pages this session. DPDK is [P] from general
knowledge, not fetched.

**Single most important caveat:** the engine can only *reshape* and *time* bytes — it cannot close
the **total-size** leak on small control responses, because split preserves total bytes and **no safe
byte-preserving DNP3 padding exists** [M]. The correct engineering behavior, and the study's honest
result, is that the engine *records the residual size leak as a first-class exported metric*; do not
let the presence of a "PAD stage" in the pipeline read as "padding is solved."

---

## NEW_PAPER_MATRIX_ROWS

None. This report cites only works already in the 102-paper matrix / prior `bibliography.bib`
(`varghese1997hashed`, `saeed2017carousel`, `saeed2019eiffel`, `brown1988calendar`, plus the reused
predictive-mitigation / NetShaper / bucketing citekeys referenced via the prior software_design.md).
No new sources were introduced.

## NEW_BIBTEX

None.
