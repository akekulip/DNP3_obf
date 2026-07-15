# Agent D — Software Implementation of the Timing-Normalization Scheduler

_Scope: lowest-overhead **software** implementation of a response-time normalization
scheduler for the existing Python replay/split server (`dnp3_split_harness/split_server.py`),
plus an evidence-based comparison of software delay mechanisms. Answers **Section 7B**
(where to apply the delay, software homes), **RQ7** (software portion), and **Section 8**
(concrete first implementation). Design + literature only — no code was modified.
Grounding read in full: `GROUNDING.md`, `measured_timing_data.md`, the prior brief
`ack_timing_obfuscation_research.md`, and the server / config / analyzer sources._

---

## 0. Verdict (lead with the answer)

**Build the scheduler as an application-layer, absolute-deadline release stage inside
`split_server.py`. Do not use `tc`/`netem`, eBPF/XDP, DPDK, or AF_XDP for this
deliverable.** The replay server *generates* the response bytes, so it owns its own
`send()` timing directly — there is no live packet to intercept, and every kernel/NIC
egress-shaping mechanism in the design space exists to delay *live* packets on an
interface. Layering one of them under a byte-generating endpoint would add a second,
coarser, policy-blind delay stage and strictly lose expressiveness (size-decorrelation
and decoy-matching need per-transaction state that a blind qdisc cannot hold).

The required precision is **sub-millisecond jitter inside a millisecond-scale target,
with ~20× headroom to the binding safety bound (TCP RTO ≈ 200 ms measured)**. CPython's
monotonic clock and `clock_nanosleep`-backed sleep meet this with two-plus orders of
margin. The DNP3 workload is single-digit kbps with **< 1 response outstanding at a time
per outstation** (poll interval ≥ 1 s ≫ hold of a few ms) — so the "scheduler" is, in the
common case, one timer. The heavy machinery the task names (timing wheels, calendar
queues, DPDK, AF_XDP) exists to schedule **millions** of timed releases per second at line
rate [saeed2017carousel, saeed2019eiffel]; our rate is roughly seven orders of magnitude
below that, so the textbook data structures are correct to *cite and reject*.

Recommended realization: a small **strategy-driven deadline scheduler** — a pluggable
target-time distribution (constant / uniform / bucketed / size-decorrelation /
decoy-match), an absolute monotonic deadline, a strict budget with **fail-open immediate
release**, and a per-transaction record exported to CSV/JSON with a logged seed. In
today's single-connection server this is a single absolute-deadline sleep; the same
abstraction drops onto `asyncio.loop.call_at` unchanged if the server ever serves
concurrent masters.

**Plain language:** the replay server writes the bytes itself, so the cleanest place to
add a delay is right before it writes — a few lines that say "don't send this response
until the chosen deadline, but never hold it long enough to trip a TCP retransmit." All
the fancy kernel and hardware options are for delaying packets you don't control; we
control ours, so we don't need them.

---

## 1. The requirement, stated precisely

| Property | Value (this rig) | Source |
|---|---|---|
| Offered load | few hundred bytes / ~1 s poll ⇒ single-digit kbps | prior brief §4.3 (inference from captures) |
| Concurrency (responses in flight per outstation) | **< 1** (hold ms ≪ poll ≥ 1 s; CONFIRM serializes fragments) | prior brief §4.3; DNP3 CONFIRM handshake |
| Target delay scale | ms (current safe default 10 ms/chunk) | `lab_config.DEFAULT_CHUNK_DELAY_MS`; measured req→resp 1.014 ms |
| **Binding safety bound** | master's effective **TCP RTO ≈ 200 ms** (`TCP_RTO_MIN`); *measure on Vision* | GROUNDING §Safety; must be re-measured, not assumed |
| Hard session ceiling | 5 s (DNP3 app-response / solicited-confirm) | prior brief §4.1 (OpenDNP3 defaults) |
| Required precision | sub-ms jitter within a ms target, ≥20× under RTO | derived from the two rows above |
| The leak to destroy | processing time **linear in CROB count** (SELECT 0.179 ms/CROB R²=0.9985; OPERATE 0.214 ms/CROB R²=0.9954) | `measured_timing_data.md` (measured, this rig, this session) |

This is a **low-rate, low-concurrency, coarse-precision, hard-deadline** scheduling
problem. That profile is what makes pure software not just adequate but *dominant*: the
mechanisms that justify kernel-bypass or hardware timers (Mpps, sub-µs, line-rate
in-path holding) are all absent here.

**Per-packet vs per-transaction vs per-response.** The fingerprint the defense must kill
is *request → first response byte* (Section 2 of the prior brief). So the primary lever is
**per-response (per-triggering-request) release delay**: hold the whole matched response
until its computed deadline, then emit. The existing `chunk_delay_ms` knob is a distinct,
secondary **per-chunk inter-frame-gap** lever (the segmentation-timing channel). Both live
in the server and compose; they are not the same control. Pure **per-packet** delay (what
`netem` does) is the *wrong granularity* — it cannot express "make request→response time
independent of CROB count," because that requires per-transaction knowledge of `t0` and the
response's size class.

---

## 2. Software delay-mechanism comparison (evidence-based)

### 2.1 The framing that decides everything: generating endpoint ≠ in-path proxy

Every mechanism below splits cleanly on one question: **does it delay a packet you are
forwarding, or does it schedule a byte you are emitting?** `split_server.py` is the
latter — `_send_chunks()` calls `socket.sendall()` on bytes it reconstructed from capture
(`split_server.py:556`), and byte-preservation is asserted in-process
(`split_server.py:523`). It never holds a live master packet. Therefore the correct home
is **application-layer emission scheduling**, and the kernel/NIC shapers are relevant only
to a *future in-path middlebox* variant (out of scope this phase — that is a proxy/MITM,
forbidden by the phase rule).

### 2.2 The clocks and sleeps (what CPython actually gives you)

- **Monotonic time.** `time.monotonic()` / `time.monotonic_ns()` read a non-settable,
  monotonically increasing clock (`clock_gettime(CLOCK_MONOTONIC)` or a higher-res
  platform equivalent), immune to wall-clock adjustments (Python `time` docs, verified;
  clock_nanosleep(2) describes `CLOCK_MONOTONIC` as "nonsettable, monotonically
  increasing … measures time since some unspecified point"). **Use this, never
  `time.time()`**, for both `t0` and the deadline — the spec requires it, and wall-clock
  jumps would otherwise cause spurious deadline misses.
- **Sleep.** Since **Python 3.11**, `time.sleep()` on Unix "use[s] `clock_nanosleep()` …
  (resolution: 1 nanosecond) … or `nanosleep()`" (Python `time` docs, verified). The 1 ns
  figure is *nominal clock resolution*, not achievable jitter — see §2.6.
- **Absolute-deadline sleep.** `clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t)`
  "suspends execution … until at least the time specified by t has elapsed" and, per the
  man page, "using an absolute timer is useful for preventing timer drift problems …
  exacerbated in programs that try to restart a relative sleep" (clock_nanosleep(2),
  verified). CPython's `time` module does **not** expose `clock_nanosleep` directly, so the
  clean way to get absolute-deadline semantics in Python is either (a) compute the deadline
  once and `time.sleep(max(0, deadline_ns - time.monotonic_ns())/1e9)` (a single sleep, no
  re-arm loop, so no accumulating drift), or (b) `loop.call_at(deadline, …)` under asyncio,
  which is documented to fire at an **absolute** timestamp on the loop's monotonic clock
  (asyncio docs, verified). Both realize the drift-free absolute-deadline model.
- **Event-driven scheduling.** `asyncio` `loop.call_at(when, cb)` schedules `cb` "at the
  given absolute timestamp `when` … using the same time reference as `loop.time()`" and
  runs all callbacks on a **single thread** (asyncio docs, verified). This is the
  no-thread-per-packet, event-driven path the spec asks for — but note (below) it buys
  nothing until concurrency > 1.

### 2.3 Kernel egress shapers (for the in-path variant only)

| Mechanism | What it does | Precision / model | Fit for the replay server | Evidence |
|---|---|---|---|---|
| **`tc`/`netem`** | Egress qdisc: fixed delay + jitter + correlation + distribution (uniform/normal/pareto/paretonormal) | Per-packet, distributional; drift-free kernel timer; can **reorder** if combined with rate | **Reject.** Blind per-interface/class delay; no per-transaction `t0`/size state ⇒ cannot do size-decorrelation or decoy-match. Useful only to *emulate* RTO/latency in experiments | tc-netem(8), verified: "Delays the packets before sending … introducing a delay variation and a correlation"; distribution names confirmed |
| **ETF qdisc + `SO_TXTIME` (EDT model)** | Per-packet **absolute-deadline** release: app stamps each skb with a txtime via `SO_TXTIME`/`SCM_TXTIME`; qdisc holds in an rb-tree and dequeues "earliest txtime first"; `delta` pre-wakes to hide scheduler latency; optional NIC launch-time offload | Per-packet absolute deadline; the **closest kernel primitive to "release this exact packet at this exact time"** | **The right kernel home *if* we ever build an in-path forwarder** that re-emits skbs. Requires being the skb sender; still no DNP3 policy layer | tc-etf(8), verified: "ordered by their txtime and … dequeued following the (next) earliest txtime first … relies on the SO_TXTIME socket option" |
| **eBPF TC (clsact egress)** | Set `skb->tstamp` for EDT (with `fq`/ETF) or implement token-bucket pacing in BPF | Per-packet, in-kernel, low overhead | **Reject for now.** Programmable but writing per-transaction DNP3-aware policy in BPF is far more effort than Python and buys nothing at kbps | EDT/`skb->tstamp` model referenced by tc-etf(8) (verified); BPF policy code is engineering inference |
| **IFB (Intermediate Functional Block)** | Redirect **ingress** to a virtual device so an egress qdisc can shape inbound traffic | n/a | **Not applicable.** We shape the *response* direction (our egress); there is no ingress-shaping need | netem docs note ingress needs special handling (verified); IFB is the standard redirect (engineering inference) |
| **XDP** | Driver **RX/ingress** hook; `XDP_REDIRECT` moves *ingress* frames to other netdevs/queues | No timer/sleep primitive at all | **Reject / negative result.** XDP is an ingress hook; there is **no native generic egress "delay a packet until T" hook**. Delaying would require redirecting to a userspace/AF_XDP queue and timing there | AF_XDP kernel doc, verified: XDP "redirect **ingress** frames"; TX path is descriptor rings, doc mentions no timed-release/launch-time primitive |
| **AF_XDP** | Zero-copy userspace RX/TX rings for high-pps I/O | You would build your own wheel in userspace | **Reject.** More plumbing than plain sockets; justified only at high pps we never reach | AF_XDP kernel doc, verified (RX/FILL, TX/COMPLETION rings) |
| **DPDK** | Poll-mode kernel bypass; TSC-precision timers (`rte_timer`) | Sub-µs, but **burns dedicated cores busy-polling** and reimplements TCP/DNP3 | **Reject.** Massive overkill for single-digit kbps; a busy-poll core to pace a packet every second is indefensible | DPDK (dpdk.org) — well-known poll-mode design; *not independently fetched this session* |
| **Userspace transparent proxy / NFQUEUE** | Hold and re-inject live packets from userspace with a delayed verdict | ms-scale, per-packet | **Out of scope this phase** — it is a MITM/proxy and rewrites the path; adds copy overhead; and for a generating endpoint it adds nothing | Engineering inference (NFQUEUE is standard); flagged as a phase-rule decision |

**Ranking for THIS deliverable:** application scheduling ≫ (ETF/EDT ≈ netem, only for the
future proxy) ≫ eBPF/AF_XDP/DPDK (unneeded) ; XDP is *unsuitable* (no egress timer);
IFB is *not applicable*.

### 2.4 The scheduling data structures (and why we reject the fancy ones)

The task names token buckets, calendar queues, and timing wheels. These are the canonical
answers to "efficiently release *many* events at their deadlines":

- **Hashed / hierarchical timing wheels** give **O(1)** amortized start/stop of a timer vs
  a heap's O(log n) [varghese1997hashed]. They are what **Carousel** uses to pace traffic
  at end hosts with a single queue and deferred completions [saeed2017carousel], and what
  **Eiffel** generalizes into an efficient programmable software packet scheduler
  [saeed2019eiffel]. Both target **line-rate, millions-of-flows** shaping.
- **Calendar queues** are the O(1) bucketed priority queue from discrete-event simulation
  [brown1988calendar] — an alternative to the wheel for large future-event sets.
- **Token bucket** paces a *rate* (bytes/sec with a burst allowance); it answers "how fast"
  not "release this one response at absolute time T," so it is the wrong tool for
  first-response latency normalization (it does shape the inter-frame-gap channel, and the
  existing chunk-delay knob is effectively a fixed-gap pacer).

**Our concurrency is < 1.** With at most one outstanding response, n ∈ {0, 1}, and O(1)
vs O(log n) is a distinction without a difference — a **single timer** (or a tiny binary
heap, `heapq`, for the general async server) is the right structure. Citing Carousel/Eiffel
here is precisely to *reject* them: they are the proof that timed release scales to
line rate, and the proof that we are ~10⁷× below the regime where their machinery earns
its complexity. This is the honest overhead framing GROUNDING §Cost demands.

**Plain language:** timing wheels and calendar queues are clever ways to juggle a huge
number of alarm clocks at once. We have, at most, one alarm clock ringing at a time, so a
plain timer is not just enough — it is the *right* engineering choice, and the papers exist
in this report to show we understand what we're deliberately not using.

### 2.5 Sleep vs busy-wait vs event-driven — the decision

- **Busy-wait (spin on `monotonic_ns`)**: gives the tightest sub-µs precision but pins a
  core at 100%. **Reject** — our target precision (sub-ms) is ~1000× coarser than what a
  sleep already delivers, so spinning buys nothing and violates the "avoid busy waiting
  unless justified" rule. (It would only be justified for sub-10-µs deadlines, which we
  never have.)
- **Blocking absolute-deadline sleep** (`time.sleep` to a computed monotonic deadline):
  simplest, matches the existing synchronous server, and — crucially — **blocks nothing that
  matters**, because the master is CONFIRM-serialized and will not send its next request
  until this response is delivered and confirmed. Concurrency degree 1 ⇒ a blocking hold on
  the one serviced connection is behaviorally identical to an async single-timer schedule.
- **Event-driven (`asyncio.loop.call_at`)**: the correct structure the moment the server
  must serve **concurrent** master connections or overlap transactions. Single thread, no
  locks, no thread-per-packet.

**Recommendation:** implement the scheduler behind a `DeadlineScheduler` interface whose
*default* backend is the blocking absolute-deadline sleep (minimal diff, honors monotonic +
no-busy-wait + no-thread-per-packet), and whose async backend is `loop.call_at`. This
satisfies the spec's "schedule asynchronously" as a **model** while acknowledging — as a
senior call — that at concurrency 1 the synchronous realization is simpler and equivalent.
Naming the simpler alternative is required by the project's simplicity rule; here the
simpler alternative is also the better one for today's workload.

### 2.6 Achievable precision, GIL, and GC (the "software is sufficient" proof)

- **Nominal vs achievable.** `clock_getres(CLOCK_MONOTONIC)` reports ~1 ns, but achievable
  wake-up jitter from a sleep is bounded by **OS scheduler granularity and load**:
  typically **tens of µs on an unloaded server-class Linux**, rising to a few hundred µs to
  ~1 ms under CPU load, power-save C-states, or CFS preemption. clock_nanosleep(2) states
  the sleep may end late because "there may still be a delay before the CPU becomes free …
  to execute the calling thread" and the interval is "rounded up" to clock granularity
  (verified). asyncio call_at may also "run up to one clock-resolution early" (verified).
- **GIL** is a non-issue: the server is single-threaded, so there is no GIL contention on
  the hold path. (A thread-per-packet design would introduce GIL wake-up latency — another
  reason the spec forbids it and we comply.)
- **GC** is the one real jitter source: CPython's generational GC can inject sub-ms pauses,
  occasionally more. Mitigations, in order of preference: (1) the hold path does **near-zero
  allocation** (a couple of int subtractions and one sleep), so it rarely triggers a
  collection; (2) optionally `gc.disable()` for the brief hold and re-enable after release,
  or `gc.freeze()` at startup; (3) record any hold whose measured actual delay deviates from
  target by > a configurable threshold as a jitter event.
- **Verdict:** required precision is sub-ms within a ms-scale target that sits ~20× under
  the 200 ms RTO. Even a pessimistic 1 ms of software jitter is ≤ 5 % of a 20 ms target and
  ≈ 0.5 % of the RTO budget — comfortably inside the target distribution's own spread and
  the safety margin. **CPython software scheduling is not a compromise here; it is
  sufficient by two-plus orders of magnitude.** This is exactly the claim §7 (test plan)
  micro-benchmark quantifies on the rig.

---

## 3. Section 7B — where should the delay be applied (software homes)

Answering the software rows of the spec's list, ranked:

| Home | Verdict | Why |
|---|---|---|
| **Outstation application before `send()`** (real device) | Ideal in principle | The device knows `t0`, size, criticality; byte-preserving by construction. But we cannot modify the OpenDNP3 outstation in this study, and it wouldn't generalize to closed devices |
| **Replay/split server (our endpoint)** | **RECOMMENDED** | It *generates* the bytes ⇒ full per-transaction policy state, monotonic scheduling, byte-preserving by construction, no proxy, no seq/ack rewrite. This is the immediate zero-hardware home (GROUNDING, prior brief §3.3) |
| **Userspace transparent middlebox** (NFQUEUE / AF_XDP / proxy) | Out of scope this phase | Can delay *live* packets, but is MITM/proxy (phase rule forbids), higher copy overhead, and adds nothing over app scheduling for a generating endpoint |
| **Linux `tc`** (netem / ETF+SO_TXTIME) | Emulation + future proxy only | Blind per-packet delay with no per-transaction policy; ETF/EDT is the right *kernel* primitive for a future in-path forwarder, and netem is the right tool to *emulate* RTO/latency in the evaluation — neither is the production shaper here |
| SmartNIC / P4 ingress / P4 TM / egress queue / recirculation / FPGA delay queue | Hardware agents' domain (Agent E) | Line-rate in-path homes for later; noted, not owned here |

**RQ7 (software portion): which parts are practical on a software server.** *All* of the
timing-normalization primitives are practical in software, and more cheaply than anywhere
else, because the server controls emission: constant-time (P3), bounded randomized
normalization (P4), bucketed (P5), **size-decorrelation (P6 — the recommended headline
policy given the measured CROB slope)**, decoy-distribution matching (P7), and
inter-frame-gap normalization (P8, already partly present as `chunk_delay_ms`). The single
thing a software endpoint *cannot* do that hardware can is **line-rate in-path holding of
third-party live traffic** — but the replay server never needs that. So the software
server is not a stepping-stone with reduced capability; for policy expressiveness it is the
**most** capable home, and it is the one that de-risks the entire Tofino/DPU line.

---

## 4. Section 8 — recommended first implementation

### 4.1 Where it slots into `split_server.py` (no code written; design only)

One new release-scheduling stage, inserted between response selection and the existing
chunk send, plus a per-transaction recorder. The two existing invariants are untouched:
byte-preservation (`b"".join(chunks) == response`) and "refuse to fire at an unmatched
request." Concretely, in `TCPSplitReplayServer.serve_once()` the flow becomes:

```
t0_ns          = monotonic_ns() captured when reader.next_frame() returns the request
entry          = exchange.match_response(parsed)          # unchanged
chunks         = self._make_chunks(entry)                 # unchanged (CRC split or full)
tr_ns          = monotonic_ns()                           # response-ready time
decision       = scheduler.decide(txn_ctx, t0_ns, tr_ns)  # NEW: policy + budget
scheduler.wait_until(decision.release_ns)                 # NEW: absolute-deadline hold
self._send_chunks(conn, chunks)                           # unchanged (inter-frame gap knob)
recorder.log(decision, actual_release_ns=monotonic_ns())  # NEW
```

For a multi-fragment READ, the same path runs twice — once triggered by the READ, once by
the master CONFIRM — and the recorder threads a **cumulative added-latency** accumulator so
the transaction total also stays under budget (§4.6).

### 4.2 Data structures

```python
class ReleaseReason(enum.Enum):
    SHAPED               = "shaped"                 # held to a real target deadline
    READY_AFTER_TARGET   = "ready_after_target"     # native slower than target; no hold added
    BUDGET_EXCEEDED      = "budget_exceeded"        # target > budget ⇒ fail-open immediate
    CRITICAL_BYPASS      = "critical_bypass"        # policy table says pass-through
    CUMULATIVE_BUDGET    = "cumulative_budget"      # multi-fragment sum would exceed ceiling
    SCHED_ERROR          = "sched_error"            # exception ⇒ fail-open immediate

@dataclass                     # per-transaction state (mutable across fragments)
class TxnRecord:
    txn_id: int
    fragment_index: int
    function_code: int
    app_seq: int
    is_splittable: bool
    size_class: int            # e.g. response byte length, or CROB-count bucket
    t0_ns: int                 # request last-byte received by the app
    tr_ready_ns: int           # response bytes available
    target_delay_ns: int       # sampled τ (independent of native/size/CROB/identity)
    budget_ns: int             # allowed_budget (< measured RTO guard)
    candidate_release_ns: int  # max(tr_ready, t0 + target_delay)
    actual_release_ns: int     # just before first sendall()
    requested_delay_ns: int    # candidate_release - t0
    actual_delay_ns: int       # actual_release - t0
    deadline_miss: bool
    reason: ReleaseReason
    seed: int                  # RNG seed in force (reproducibility)
```

- **Deadline scheduler:** concurrency 1 ⇒ a single absolute deadline + sleep. General
  async backend ⇒ a `heapq` min-heap keyed by `release_ns` (O(log n)); a timing wheel
  [varghese1997hashed] or calendar queue [brown1988calendar] is **explicitly rejected** —
  unneeded below thousands of concurrent flows (§2.4).
- **Target distribution:** a strategy object with `sample(ctx, rng) -> target_delay_ns`.
- **Policy/criticality table:** `classify(ctx) -> {SHAPE, BYPASS}` keyed on function code
  (and, where the entry is parsed, object group/variation) with a **fail-open default**.

### 4.3 Scheduler architecture

```
                 ┌──────────────────────────────────────────────┐
 request ───►    │ TxnContext(t0_ns, fc, app_seq, size_class,    │
 (t0 stamp)      │            fragment_index, cum_added_ns)      │
                 └──────────────────────────────────────────────┘
                          │
      response bytes ready │ tr_ready_ns
                          ▼
     ┌───────────────┐   BYPASS   ┌───────────────────────────┐
     │ Criticality    │──────────►│ release immediately        │
     │ classifier     │            │ reason=CRITICAL_BYPASS     │
     └───────────────┘            └───────────────────────────┘
             │ SHAPE
             ▼
     ┌───────────────┐   τ = sample(ctx, seeded rng)
     │ TargetDist     │   candidate = max(tr_ready, t0 + τ)
     │ (P3/P4/P5/P6/  │   requested = candidate - t0
     │  P7 strategy)  │
     └───────────────┘
             │
             ▼
     ┌───────────────────────────────┐  requested > budget  ┌──────────────────────┐
     │ Budget gate                    │─────────────────────►│ release immediately   │
     │ budget = min(cfg.budget,       │  or cum > ceiling    │ deadline_miss=True    │
     │   rto_guard) ; cum_added check │                      │ reason=BUDGET/CUMUL   │
     └───────────────────────────────┘                      └──────────────────────┘
             │ within budget
             ▼
     ┌───────────────────────────────┐
     │ DeadlineScheduler.wait_until   │  abs monotonic deadline
     │  sync:  sleep(candidate - now) │  (single sleep, no re-arm ⇒ drift-free)
     │  async: loop.call_at(candidate)│  watchdog max-hold = min(budget, rto_guard)
     └───────────────────────────────┘
             │ fire
             ▼   send chunks (existing inter-frame-gap pacing preserved)
     ┌───────────────────────────────┐
     │ Recorder.log(TxnRecord) ──► CSV/JSON                         │
     └───────────────────────────────┘
```

### 4.4 Pseudocode (release decision + hold)

```python
def decide(ctx, t0_ns, tr_ready_ns, cfg, rng, cum_added_ns):
    if classify(ctx, cfg) is BYPASS:
        return Decision(release_ns=tr_ready_ns, reason=CRITICAL_BYPASS,
                        deadline_miss=False, target_delay_ns=0)

    tau = target_dist.sample(ctx, rng)                 # independent of native/size/CROB/id
    candidate = max(tr_ready_ns, t0_ns + tau)          # candidate_release
    requested = candidate - t0_ns
    budget    = min(cfg.budget_ns, cfg.rto_guard_ns)   # never exceed measured-RTO guard

    if requested > budget or (cum_added_ns + max(0, candidate - tr_ready_ns)
                              ) > cfg.txn_ceiling_ns:
        reason = BUDGET_EXCEEDED if requested > budget else CUMULATIVE_BUDGET
        return Decision(release_ns=tr_ready_ns, reason=reason,
                        deadline_miss=True, target_delay_ns=tau)  # FAIL OPEN

    reason = SHAPED if candidate > tr_ready_ns else READY_AFTER_TARGET
    return Decision(release_ns=candidate, reason=reason,
                    deadline_miss=False, target_delay_ns=tau)

def wait_until(release_ns, cfg):
    # single absolute-deadline sleep: drift-free, no busy-wait, blocks only this
    # CONFIRM-serialized connection (which has nothing else to do).
    hard_cap = min(release_ns, _monotonic_ns() + cfg.rto_guard_ns)   # watchdog
    remaining = hard_cap - _monotonic_ns()
    if remaining > 0:
        time.sleep(remaining / 1e9)   # CPython 3.11+ -> clock_nanosleep (verified)
```

Target-distribution strategies (all seeded):

```python
constant(τ0):           return τ0
uniform(lo, hi):        return rng.integers(lo, hi)
bucketed({5,10,20,40}): return ceil_to_next_bucket(size_or_native)     # P5
size_decorrelate(sched):return sched(ctx.size_class)   # τ chosen so observed⟂size  (P6)
decoy_match(cdf):       return sample_from_empirical_cdf(cdf, rng)     # P7
```

**Recommended default policy: `size_decorrelate` (P6/V4).** The measured leak is a clean
linear map CROB→time (`measured_timing_data.md`); size-decorrelation pads each size class
to a common size-independent schedule so the observable request→response time is
statistically independent of size/CROB, driving the attacker's regression slope β → 0 at
**lower** added latency than full constant-time (prior brief §5.2). Keep `constant` (P3)
and `uniform`/bounded-randomized (P4) as the head-to-head evaluation arms.

### 4.5 Configuration schema (YAML)

```yaml
timing_normalization:
  enabled: true
  seed: 20260713                 # logged in every record; reproducible target sequence
  clock: monotonic               # never wall-clock
  policy:
    name: size_decorrelate       # constant | uniform | bucketed | size_decorrelate | decoy_match
    constant_ms: 20              # for name=constant
    uniform_ms: [5, 40]          # for name=uniform  [lo, hi]
    buckets_ms: [5, 10, 20, 40]  # for name=bucketed
    size_decorrelation:          # for name=size_decorrelate
      schedule: pad_to_max       # pad each size class to a common target
      size_key: response_len     # response_len | crob_count
      target_ms: 25              # common size-independent target (must exceed worst native)
    decoy_match:                 # for name=decoy_match
      profile_path: decoy_profiles/rtu_class_A.json   # empirical latency CDF
  budget:
    budget_ms: 150               # allowed_budget for shaping
    rto_guard_ms: 150            # HARD watchdog < measured effective RTO on Vision
    txn_ceiling_ms: 800          # cumulative multi-fragment ceiling (< 5 s / n_frag margin)
  bypass:
    function_codes: [0x00]       # never delay CONFIRMs; extend with criticality classes
    fail_open: true              # any uncertainty -> immediate release
  inter_frame_gap_ms: 10         # existing chunk_delay_ms knob (segmentation channel)
  record:
    format: csv                  # csv | json
    path: logs/replay/timing_records.csv
    jitter_flag_ms: 1.0          # flag |actual-target| over this as a jitter event
```

Every field maps to a `lab_config.py` default so the phase-rule "one config" discipline
holds; the runner forwards `--flags` as today.

### 4.6 Multi-fragment handling (Section 7E, software side)

The CONFIRM handshake serializes fragments, so per-fragment holds **add**. The scheduler
therefore tracks `cum_added_ns` across a transaction and enforces `txn_ceiling_ms`
(< 5 s / n_fragments, each hop still < RTO guard). Concretely: fragment 1 is shaped
relative to the READ; the continuation is shaped relative to the CONFIRM; if shaping the
continuation would push the transaction sum past the ceiling, it releases immediately with
`CUMULATIVE_BUDGET`. This is exactly the "cumulative transaction deadline" the spec asks
for, and it composes with the existing `is_splittable` machinery (`split_server.py:444`)
without touching byte-preservation.

### 4.7 Failure handling and deadline-miss policy (Section 7D — safety dominates)

- **Fail-open, always.** Every abnormal path (budget exceeded, cumulative ceiling,
  classifier says critical, scheduler exception) releases **immediately** and records the
  reason. The server never holds a response longer than `min(budget, rto_guard)` — a
  hardware-style watchdog guarantees a bug cannot cause an RTO-tripping hold.
- **Deadline miss ≠ error.** A miss (native slower than target, or target > budget) is a
  first-class, logged outcome, not an exception; the evaluation counts miss rate as a cost
  metric.
- **No fail-closed.** For SCADA, dropping/holding a control response to preserve privacy is
  unacceptable; privacy yields to delivery every time.

### 4.8 Concurrency considerations

- Single master connection today ⇒ **no threads, no locks, GIL irrelevant, no busy-wait**.
  The blocking hold stalls only the one CONFIRM-serialized connection, which has no other
  work pending — so it is behaviorally non-blocking at the system level.
- **Explicitly avoid thread-per-packet** (spec + GIL wake-up latency). If concurrent masters
  are ever needed, move to **one asyncio event loop**, per-connection coroutines, a single
  `heapq`, and `loop.call_at` timer callbacks on the loop thread — still lock-free, still no
  busy-wait, still no thread-per-packet.

### 4.9 Expected CPU / memory overhead (order-of-magnitude, justified)

- **CPU (scheduler logic):** per transaction ≈ a few `monotonic_ns` reads + one RNG draw +
  one comparison chain + one dict/record append ≈ **single-digit microseconds of CPU**. At
  the DNP3 rate of a handful of transactions per second this is **≪ 0.1 % of one core**.
  The wall-clock *delay* (ms) is intentional latency, not CPU — the CPU sleeps.
- **Memory:** one `TxnRecord` ≈ a few hundred bytes; 10⁵ logged transactions ≈ **a few MB**
  of append-only log. Steady-state resident scheduler state is **single-digit KB** (one
  outstanding transaction, one strategy object, one seeded RNG). The captured response
  bytes (KB) already dominate. Order: **KB resident, MB log**.
- **Contrast (why hardware/kernel-bypass is unjustified):** those exist to hit sub-µs
  precision at Mpps [saeed2017carousel, saeed2019eiffel]; we need sub-ms at ~1 pps. Spending
  a busy-poll DPDK core or a BPF program on this workload would *increase* CPU by orders of
  magnitude for zero precision benefit inside our budget.

**Plain language:** the extra bookkeeping costs microseconds of CPU and a few kilobytes of
memory per response. The only real "cost" is the delay we add on purpose, and even a
generous delay is a small fraction of the point at which TCP would start retransmitting.

---

## 5. Section 7A note (what the server timestamps)

For the *server-internal* control loop: `t0_ns` = `monotonic_ns()` at the instant
`reader.next_frame()` returns the triggering request (request last-byte at the app);
`tr_ready_ns` = `monotonic_ns()` when the matched/spliced chunks are ready;
`actual_release_ns` = `monotonic_ns()` immediately before the first `sendall()`. These
close the loop and populate the record. The **authoritative evaluation timestamp** remains
the PCAP-derived *request-first-byte → response-first-byte* that `analyze_ack.py` already
computes (`analyze_ack.py:146-157`) — the server's `t0` differs from the wire by the
kernel→app latency (sub-100 µs on this LAN/loopback). Defer the reproducible PCAP timestamp
definition to Agent F; the server log is the ground truth for *what the scheduler intended*,
the PCAP is ground truth for *what the observer sees*.

---

## 6. Component-responsibility table

| Component | Responsibility | New / existing |
|---|---|---|
| `FrameReader` / `parse_dnp3_request` | Reassemble frames; extract fc, app_seq, `t0` stamp | Existing (`split_server.py:187, 106`) |
| `CapturedExchange.match_response` | Select matching response; refuse unmatched | Existing (`split_server.py:361`) |
| `DNP3CRCSplitter` | Byte-preserving CRC-boundary split | Existing (`split_server.py:247`) |
| **CriticalityClassifier** | `SHAPE` vs `BYPASS` by fc/obj; fail-open default | **New** |
| **TargetDistribution** (strategy) | Sample τ ⟂ native/size/CROB/identity (P3–P7) | **New** |
| **BudgetGate** | Enforce `min(budget, rto_guard)` + cumulative ceiling; fail-open | **New** |
| **DeadlineScheduler** | Absolute-deadline hold (sync sleep now / `call_at` later); watchdog | **New** |
| **Recorder** | Per-txn record → CSV/JSON; log seed, jitter flag | **New** |
| `_send_chunks` | Emit chunks; inter-frame-gap pacing (segmentation channel) | Existing (`split_server.py:556`), knob retained |
| `lab_config.py` | Single source of truth for all new defaults | Existing pattern extended |

---

## 7. Test plan

**Loopback smoke (dev box, 127.0.0.1) — fast correctness gate:**
1. **Byte-preservation unchanged.** For every policy, assert `b"".join(chunks) == response`
   still holds (the existing in-process assert, `split_server.py:523`) — timing must never
   touch bytes.
2. **Precision / jitter micro-benchmark.** Schedule N=10⁴ releases at known monotonic
   deadlines (idle, then under a `stress-ng` CPU load) and record `actual − target`. Confirm
   p95 |error| is sub-ms idle and characterize the loaded tail. This *quantifies* the
   "software is sufficient" claim and feeds §4.9.
3. **Deadline-miss path.** Set `budget_ms < target` and confirm `BUDGET_EXCEEDED`,
   immediate release, `deadline_miss=True` recorded; kill the classifier to force
   `SCHED_ERROR` and confirm fail-open.
4. **Reproducibility.** Same `seed` ⇒ identical target sequence across two runs (diff the
   `target_delay_ns` column).
5. **Export.** CSV and JSON records well-formed, all fields populated.

**Rig success bar (Vision master ↔ Hulk running `split_server.py`) — the real bar:**
6. The existing bar (per CLAUDE.md / prior work): **800 measurements** to the per-phase CSV,
   a DNP3 **CONFIRM** observed, a clean PCAP with **0 retransmits / 0 resets**, no DNP3
   timeout, byte-preservation asserted.
7. **RTO headroom, measured not assumed.** First `sysctl net.ipv4.tcp_retries2` on Vision
   and observe the effective RTO in a capture; set `rto_guard_ms` below it. Confirm **no
   added latency exceeds the measured RTO** and no retransmit appears in any shaped run.
8. **Leak destroyed.** Re-run `analyze_ack.py` on the shaped capture under `size_decorrelate`
   and confirm the CROB-count → response-time slope collapses (β → 0, R² → ~0) versus the
   measured baseline (0.179 / 0.214 ms/CROB). Report Wasserstein-1 / KS distance of the wire
   response-time distribution to the declared target.
9. **Multi-fragment.** For a multi-fragment READ, confirm both fragments are shaped, the
   CONFIRM completes, and the cumulative added latency stays under `txn_ceiling_ms` and each
   hop under `rto_guard_ms`.

**Pass criteria:** byte-preservation holds; 0 retransmits / 0 resets / 0 timeouts; CONFIRM
present; measured wire distribution matches target within tolerance; CROB slope destroyed;
seed-reproducible. Do not claim rig success from a loopback run (project rule).

---

## PAPER_MATRIX_ROWS
Carousel: Scalable Traffic Shaping at End Hosts | Ahmed Saeed, Nandita Dukkipati, Vytautas Valancius, Vinh The Lam, Carlo Contavalli, Amin Vahdat | 2017 | ACM SIGCOMM | 10.1145/3098822.3098852 | https://dl.acm.org/doi/10.1145/3098822.3098852 | yes | 3 | data-center end-host traffic (rate limiting/pacing) | NA (performance, not privacy) | single-queue timing-wheel shaper with deferred completions | packet pacing / timed release | sw | Linux end host (software, HW-timestamp optional) | testbed (Google) | NA | CPU/scalability to millions of flows | timing wheel enables scalable timed release at line rate with one queue and backpressure | not a privacy defense; DC-scale, far above our rate | canonical O(1) timed-release structure; we are ~1e7x below its scale so a single timer/heap suffices (cited to reject) | high
Eiffel: Efficient and Flexible Software Packet Scheduling | Ahmed Saeed, Yimeng Zhao, Nandita Dukkipati, Ellen W. Zegura, Mostafa H. Ammar, Khaled Harras, Amin Vahdat | 2019 | USENIX NSDI (pp. 17-32) | NA | https://www.usenix.org/conference/nsdi19/presentation/saeed | yes | 3 | software packet scheduling (general) | NA | programmable integer priority queue (FFS-based) + approximate timing wheels | rank-based / timed release | sw | Linux userspace and kernel | testbed | NA | CPU per packet, ops/sec | efficient near-O(1) programmable software packet scheduler at high rates | not privacy; complexity unjustified at low rate | reference for software scheduler data structures; confirms heap/wheel scale far beyond our need | high
Hashed and Hierarchical Timing Wheels: Efficient Data Structures for Implementing a Timer Facility | George Varghese, Anthony Lauck | 1997 | IEEE/ACM Transactions on Networking | 10.1109/90.650142 | https://doi.org/10.1109/90.650142 | yes | 3 | OS/protocol timer management | NA | hashed/hierarchical timing-wheel timer structures | timer scheduling | sw | general | NA | NA | O(1) amortized timer start/stop vs O(log n) heap | O(1) advantage only material at large n | grounds the "timing wheel is O(1) but overkill at concurrency<1" argument | high
Calendar Queues: A Fast O(1) Priority Queue Implementation for the Simulation Event Set Problem | Randy Brown | 1988 | Communications of the ACM (31(10)) | 10.1145/63039.63045 | https://doi.org/10.1145/63039.63045 | yes | 3 | discrete-event simulation event set | NA | calendar-queue O(1) bucketed priority queue | event scheduling | sw | general | NA | NA | O(1) enqueue/dequeue for large future-event sets | performance sensitive to bucket sizing / skew | alternative to timing wheel for timed release; same "unneeded at our scale" verdict | high
tc-netem(8) Linux manual page (Network Emulator qdisc) | Linux man-pages project | 2024 | Linux manual (man7.org) | NA | https://man7.org/linux/man-pages/man8/tc-netem.8.html | no | 3 | any egress IP traffic | NA | netem qdisc: fixed delay + jitter + correlation + distribution (uniform/normal/pareto/paretonormal) | fixed/jitter delay, distribution | sw | Linux tc/qdisc (egress) | NA | NA | per-packet kernel overhead | kernel can add distributional delay per packet on egress | blind per-interface/class delay; no per-transaction policy; can reorder with rate | candidate for RTO/latency EMULATION and a future in-path middlebox, not the policy engine | high
tc-etf(8) Linux manual page (Earliest TxTime First qdisc; SO_TXTIME/EDT) | Linux man-pages project | 2024 | Linux manual (man7.org) | NA | https://man7.org/linux/man-pages/man8/tc-etf.8.html | no | 3 | any egress IP traffic | NA | ETF qdisc: per-packet earliest-txtime release via SO_TXTIME/SCM_TXTIME, rb-tree ordered, delta wake-up, optional NIC launch-time offload | per-packet absolute-deadline release | sw+hw | Linux qdisc + optional NIC launch-time offload | NA | NA | rb-tree O(log n); configurable wake-up delta | kernel/NIC can release each packet at a programmed absolute time | requires being the skb sender (forwarder/proxy); no DNP3 policy layer | the right kernel primitive for per-packet timed release IF an in-path forwarder is built | high
clock_nanosleep(2) Linux manual page | Linux man-pages project | 2024 | Linux manual (man7.org) | NA | https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html | no | 3 | OS timing | NA | absolute-deadline sleep (TIMER_ABSTIME, CLOCK_MONOTONIC) | absolute-deadline hold | sw | Linux / CPython | NA | NA | one syscall per hold | TIMER_ABSTIME avoids re-arm/drift; wakeup may be late due to scheduling/rounding | our per-response hold uses exactly this; grounds the drift-free precision claim | high
Python Standard Library: time module | Python Software Foundation | 2024 | Python documentation | NA | https://docs.python.org/3/library/time.html | no | 3 | userspace scheduling | NA | time.sleep via clock_nanosleep/nanosleep since 3.11; CLOCK_MONOTONIC | sleep-based hold | sw | CPython 3.11+ | NA | NA | 1 ns nominal resolution (not achievable jitter) | time.sleep uses clock_nanosleep on Unix since 3.11 | actual jitter bounded by scheduler not the 1 ns nominal; justifies CPython adequacy for ms holds | high
Python Standard Library: asyncio Event Loop | Python Software Foundation | 2024 | Python documentation | NA | https://docs.python.org/3/library/asyncio-eventloop.html | no | 3 | userspace event scheduling | NA | loop.call_at absolute-deadline scheduling on monotonic loop.time(); single-thread callbacks | event-driven absolute-deadline release | sw | CPython asyncio | NA | NA | single-thread; may fire up to one clock-resolution early | call_at schedules at absolute monotonic timestamp; no thread-per-packet | the recommended async scaling path for the scheduler | high
AF_XDP - The Linux Kernel Documentation | Linux Kernel Documentation | 2024 | kernel.org documentation | NA | https://www.kernel.org/doc/html/latest/networking/af_xdp.html | no | 3 | high-rate packet I/O | NA | XDP redirects INGRESS frames; AF_XDP zero-copy RX/TX rings | NA (no timer primitive) | sw+hw | Linux XDP / AF_XDP | NA | NA | zero-copy, per-pps | XDP is an RX/ingress hook with no native timed-egress/sleep primitive | cannot delay packets in XDP; timed release would need userspace timing on an AF_XDP queue | grounds the "XDP unsuitable for timed release" negative result | high

## BIBTEX
```bibtex
@inproceedings{saeed2017carousel,
  author    = {Saeed, Ahmed and Dukkipati, Nandita and Valancius, Vytautas and
               Lam, Vinh The and Contavalli, Carlo and Vahdat, Amin},
  title     = {Carousel: Scalable Traffic Shaping at End Hosts},
  booktitle = {Proceedings of the Conference of the ACM Special Interest Group on
               Data Communication (SIGCOMM)},
  year      = {2017},
  publisher = {ACM},
  doi       = {10.1145/3098822.3098852}
}

@inproceedings{saeed2019eiffel,
  author    = {Saeed, Ahmed and Zhao, Yimeng and Dukkipati, Nandita and
               Zegura, Ellen W. and Ammar, Mostafa H. and Harras, Khaled and
               Vahdat, Amin},
  title     = {Eiffel: Efficient and Flexible Software Packet Scheduling},
  booktitle = {16th USENIX Symposium on Networked Systems Design and
               Implementation (NSDI)},
  pages     = {17--32},
  year      = {2019},
  publisher = {USENIX Association},
  url       = {https://www.usenix.org/conference/nsdi19/presentation/saeed}
}

@article{varghese1997hashed,
  author  = {Varghese, George and Lauck, Anthony},
  title   = {Hashed and Hierarchical Timing Wheels: Efficient Data Structures
             for Implementing a Timer Facility},
  journal = {IEEE/ACM Transactions on Networking},
  year    = {1997},
  doi     = {10.1109/90.650142}
}

@article{brown1988calendar,
  author  = {Brown, Randy},
  title   = {Calendar Queues: A Fast {O(1)} Priority Queue Implementation for the
             Simulation Event Set Problem},
  journal = {Communications of the ACM},
  volume  = {31},
  number  = {10},
  year    = {1988},
  doi     = {10.1145/63039.63045}
}

@misc{linux_tcnetem,
  title        = {tc-netem(8) --- Linux manual page (Network Emulator qdisc)},
  howpublished = {\url{https://man7.org/linux/man-pages/man8/tc-netem.8.html}},
  note         = {Accessed 2026-07-13}
}

@misc{linux_tcetf,
  title        = {tc-etf(8) --- Linux manual page (Earliest TxTime First qdisc; SO\_TXTIME)},
  howpublished = {\url{https://man7.org/linux/man-pages/man8/tc-etf.8.html}},
  note         = {Accessed 2026-07-13}
}

@misc{linux_clocknanosleep,
  title        = {clock\_nanosleep(2) --- Linux manual page},
  howpublished = {\url{https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html}},
  note         = {Accessed 2026-07-13; TIMER\_ABSTIME + CLOCK\_MONOTONIC absolute-deadline sleep}
}

@misc{python_time,
  title        = {Python Standard Library: {\tt time} --- Time access and conversions},
  howpublished = {\url{https://docs.python.org/3/library/time.html}},
  note         = {Accessed 2026-07-13; time.sleep uses clock\_nanosleep on Unix since Python 3.11}
}

@misc{python_asyncio,
  title        = {Python Standard Library: {\tt asyncio} Event Loop
                  ({\tt loop.call\_at}, {\tt loop.time})},
  howpublished = {\url{https://docs.python.org/3/library/asyncio-eventloop.html}},
  note         = {Accessed 2026-07-13}
}

@misc{kernel_afxdp,
  title        = {AF\_XDP --- The Linux Kernel Documentation},
  howpublished = {\url{https://www.kernel.org/doc/html/latest/networking/af_xdp.html}},
  note         = {Accessed 2026-07-13}
}
```
