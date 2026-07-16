# DNP3 ACK / Response-Time Manipulation — Master Report

> ## ⚠ Separate-ACK manipulation results are PROJECTED / NOT WIRE-VALIDATED
>
> Where this report describes **separate-ACK manipulation** ("how the ACK was delayed",
> ACK-delay-only, response-delay-only, independent ACK/response delay, gap
> normalization, and the ACK-gap before/after), those results are a **projection** from
> `plan_ack_response_release()` applied to captured timestamps — **not** a wire capture:
> - **No current packet-control mechanism enforces the planned pure-ACK release time.**
> - **No current PCAP demonstrates independent delay of an existing pure TCP ACK.**
> - A user-space application cannot hold or advance a kernel-owned pure TCP ACK.
>
> This label applies ONLY to the separate-ACK manipulation. The trace characterization
> (measured) and the Phase-1 combined-response time normalization (rig-validated) are
> unaffected. Numbers are retained unchanged. See `RESEARCH_CLAIMS.md` (C8) and Phase 00
> risk R1.

_Everything the `ack_delay.md` study did, in one place: the real-trace
characterization, the socket program and exactly **how the ACK was delayed** for
devices where the TCP ACK and the DNP3 application response travel **together**
(combined) versus **separately**, the byte-preserving timing policy, and the
**before/after device-fingerprinting** (classification + clustering) that shows what
the defense removes and what it leaves. Numbers below are labeled per subsection as
measured, replayed (rig), or projected — the separate-ACK manipulation is PROJECTED
(see the banner above); each section links to the detailed report and the script that
produced it._

Companion reports: `ack_trace_summary.md` (characterization), `ack_separation_rig_results.md`
(socket ACK separation on the rig), `rig_timing_matrix_results.md` (Phase-1 rig
validation), `trace_before_after.md` (timing before/after), `ack_fingerprint_eval.md`
(ACK fingerprinting before/after), `attacker_eval.md` (full attacker eval),
`ack_timing_implementation_report.md` (plan §11 outputs).

---

## 1. The one-paragraph story

A passive eavesdropper on a DNP3/TCP link can tell **which device** is answering
without decoding a single DNP3 payload byte, because each outstation has a
**timing + ACK fingerprint**. Some devices (AB1400, ION7550) let the OS piggyback
the TCP ACK onto the DNP3 response — one segment, `request → ACK-bearing response`.
One device (SEL-751) emits a **pure TCP ACK first** and the DNP3 response ~13 ms
later — `request → pure ACK → response`. That ACK-to-response gap is a cross-layer
readout of device processing time (a Formby-style fingerprint). The study builds a
**byte-preserving timing defense**: it never edits a DNP3 byte, a CRC, or a size — it
only changes **when** packets are released. Phase 1 normalizes the request→response
time of the combined-ACK devices; Phase 2 reshapes the SEL-751's ACK→response gap,
using the host kernel's own delayed-ACK timer to produce the separate ACK (no
forging). The before/after evaluation is honest: normalization **closes the timing
channel**, but response **size** and the **existence** of a separate ACK still leak,
so full device anonymization needs two further primitives (byte-preserving padding
and ACK-mode normalization).

---

## 2. What the six real traces actually show (characterization)

Source: `Traffic Trace/{AB1400,SEL751,ION7550}{,L}.pcap`, parsed per-transaction by
`characterize_ack_traces.py` → `ack_trace_characterization.csv` (22,988 transactions),
`ack_trace_summary.md`. A transaction is anchored at each payload-bearing DNP3
REQUEST and matched to the first reverse packet and the first payload-bearing DNP3
RESPONSE. Device-specific outstation flows (reference outstation 10.0.0.2 excluded):

| Device (outstation IP) | ACK mode | request→ACK (med) | ACK→response gap (med / p95 / max) | request→response (med) | response sizes |
|---|---|---|---|---|---|
| **SEL-751** (10.0.0.1) | **SEPARATE** 100% | ~3.7 ms | **12.9 / 16.6 / 166 ms** | ~16.1 ms | 37, 54 B |
| AB1400 (10.0.0.12) | COMBINED 100% | ~16.3 ms | 0 / 0 / 0 ms | ~16.3 ms | 37, 54 B |
| ION7550 (10.0.0.11) | COMBINED ~100% | ~16.0 ms | 0 / 0 / 29 ms | ~16.0 ms | 37, **61** B |

Key facts that drive everything else:

- **The expected pattern held, measured not assumed:** SEL-751 is 100% separate-ACK
  (4,298/4,298 txns); AB1400 and ION7550 are ~100% combined-ACK. 0 transactions were
  unclassifiable.
- **Terminology (kept strict):** *pure TCP ACK* = zero-payload ACK; *ACK-bearing DNP3
  response* = a response segment that also ACKs (piggyback). The DNP3 response is
  never called an "application ACK". No actual DNP3 CONFIRM function was present.
- **Two fingerprint channels beyond timing:** response **size** (ION7550's 61 B vs
  others' 54 B) and **ACK mode** (only SEL-751 is separate).

---

## 3. The socket program and **how the ACK was delayed**

### 3.1 The two regimes (why "combined" vs "separate" matters)

Whether the TCP ACK rides *with* the DNP3 response or *before* it is a **host/kernel**
behaviour, not a DNP3 rule. On Linux it is governed by the receiver's **delayed-ACK
timer**: after the outstation receives a request, the kernel wants to ACK it. If the
application `write()`s the response **quickly**, the pending ACK **piggybacks** onto
the response segment → one combined `ACK-bearing DNP3 response`. If the application
is **slow to write** (past the delayed-ACK timeout), the kernel gives up waiting and
sends a **standalone pure ACK first**, then the response follows → separate.

### 3.2 The socket program (`ack_separation_probe.py`, plan §5A)

A minimal, byte-clean TCP client/server that isolates exactly this effect — **no
DNP3 stack, no forging**:

- **Server** (`_handle_connection`, runs on the outstation host): reads a request,
  records arrival with `time.monotonic_ns()`, **sleeps a client-specified delay**,
  then `sendall()`s a fixed 2407 B response (mirrors the real DNP3 read response size
  and segment count). That sleep between arrival and `write()` **is** the
  application-write delay under test.
- **Client** (runs on the master host): for each (socket-option config, delay, rep)
  sends a request and times the round trip.
- **Capture**: a privileged `tcpdump`/`tshark` on the server egress is the ground
  truth for whether a *pure ACK* was emitted. The tool is capability-aware — it
  **probes** whether it can actually capture and, if it cannot, records
  `pure_ack_emitted = unknown` rather than guessing.
- **One-factor-at-a-time socket sweep**: baseline, server `TCP_NODELAY` on/off,
  client `TCP_QUICKACK` on. Each config differs from baseline by exactly one factor.

### 3.3 The measured result: a sharp threshold at 40 ms

Rig run (Vision master ↔ Hulk server, real 1 G link, privileged Hulk-egress capture,
1,808 transactions; `ack_separation_rig_results.md`):

| app-write delay | separate-ACK fraction |
|---:|---:|
| 0–38 ms | ≈ 0.00 (ACK piggybacks → **combined**) |
| **40 ms** | **0.93** (delayed-ACK timer fires → **separate**) |
| 42–50 ms | 1.00 (separate; kernel switches to quickack) |

Raw-packet proof from `acksep_refine.pcap`:

```
delay 38 ms (COMBINED):  REQ +0.00 → RESPONSE +38.31 (ACK piggybacked, no separate ACK)
delay 40 ms (SEPARATE):  REQ +0.00 → pureACK +40.20 (len 0) → RESPONSE +40.27
```

**Conclusion:** delaying the application write induces a pure TCP ACK before the
response **with no forging**, sharply at **40 ms = the Linux `TCP_DELACK_MAX`
delayed-ACK timeout** on this stack (Ubuntu 24.04, kernel 6.8). 0 TCP resets across
all 1,808 transactions. This is host/kernel behaviour on this stack — not a protocol
guarantee, and not necessarily how a physical device ACKs.

### 3.4 How each regime's ACK is delayed in the live replay path

The live insertion point is `split_server.py::_apply_timing` (called in `serve_once`
just before `_send_chunks`). It reads the request-arrival timestamp, asks the
`timing_policy.ReleaseScheduler` for a release deadline, and does an **absolute-deadline
wait** (`timing_policy.wait_until`) before the first byte leaves. Bytes are never
touched, so `b"".join(chunks) == response` still holds; native mode waits zero and is
wire-identical.

- **Combined-ACK devices (AB1400, ION7550):** the ACK is piggybacked, so there is no
  separate ACK to move. The defense holds the **whole response** to a class-independent
  target (Phase 1). Because the chosen targets (10–25 ms) are **below** the 40 ms
  threshold, the flow **stays combined** — normalizing the request→response time does
  not accidentally manufacture a separate-ACK signature.
- **Separate-ACK device (SEL-751):** a pure ACK and a response already exist, so the
  Phase-2 planner (`timing_policy.plan_ack_response_release`) **reschedules the two
  existing packets** and strictly enforces `ack_release ≤ response_release` (it never
  releases the ACK after the response, and never forges a packet). A host-side defense
  that wants to *create* the separate ACK holds the write **≥ 40 ms**, letting the
  kernel emit the pure ACK naturally — the cost is a ≥40 ms floor on visible
  request→response time.

---

## 4. The timing policy (byte-preserving, class-independent)

Module: `timing_policy.py` (abstractions `TimingProfile`, `TimingDecision`,
`FlowTimingState`, `ReleaseScheduler`, `BypassReason`, `plan_ack_response_release`,
`wait_until`). 22/22 unit tests pass (`tests/test_timing_policy.py`).

**The correct design (not additive jitter):**

```
target_delay    = sample from a common, class-INDEPENDENT bounded distribution
desired_release = request_received + target_delay
actual_release  = max(response_ready, desired_release)     # never send early
```

The target never depends on CROB count, response/request size, native ready time, or
device identity (unit-tested). Modes: **native** (send immediately), **fixed** (one
target), **bounded** (uniform target in [min,max], seeded/reproducible). Phase-2 ACK
modes: `native`, `ack-delay-only` (shrinks the gap), `response-delay-only` (grows it),
`independent-delay`, `gap-normalized` (pins the gap to a bounded target).

**Fail-open safety:** the response is sent immediately (and a bypass is logged) when
the deadline is already missed, the target exceeds the measured RTO-safe bound, the
per-flow queue is over the limit, the transaction is critical, or traffic is
unsupported. The binding safety bound is the **measured TCP RTO**, not a guessed
200 ms: `rto_probe.py` measured a peer RTO floor **≈ 211 ms** (Linux `TCP_RTO_MIN`),
giving a conservative safe hold ≈ 105 ms; the 10–25 ms targets sit far under it.

**Rig-validated (Phase 1):** 30 reps/config × native/fixed/bounded × full/split =
**930 timed transactions on Vision↔Hulk, 0 deadline-miss / 0 bypass / 0 reset**,
fixed-25 pinned to 25.00 ms server-side and **25.36 ms on the wire (±0.1 ms, 0
retransmits)** by tcpdump (`rig_timing_matrix_results.md`). A real pydnp3 master
(`tests/native_master_loopback.sh`) completes a full integrity poll against the
timing-enabled server with byte-preservation PASS and no DNP3 timeout.

---

## 5. Before / after of the ACK delay on the device traces

Script `trace_before_after.py` drives the shipped `timing_policy` over the **real
per-transaction native timings** from the characterization CSV (`trace_before_after.md`,
`.png`). Before = measured device timing; after = the same transactions through the
real scheduler/planner.

**Combined devices — request→response normalization (Phase 1):**

| device | native med / p95 / max | after fixed-25 (med/p95/max) | after bounded[20,30] |
|---|---|---|---|
| AB1400 | 16.32 / 17.45 / 95.29 | 25.00 / 25.00 / 95.29 | 24.95 / 29.49 / — |
| ION7550 | 15.99 / 16.76 / 97.99 | 25.00 / 25.00 / 97.99 | 25.03 / 29.44 / — |

Native request→response carries a device-specific spread; after normalization every
held transaction leaves at the same target (fixed → identical point; bounded → one
common injected distribution), so the timing channel is closed on the held path (the
rare native tail above target fails open, honestly).

**SEL-751 — observer-visible ACK→response gap (Phase 2), the literal ACK delay:**

| mode | gap median | Δ vs native |
|---|---:|---:|
| native (before) | 12.21 ms | 0.00 |
| response-delay-only (+8 ms) | 20.21 ms | +8.00 |
| ack-delay-only (+8 ms) | 4.21 ms | −8.00 |
| gap-normalized (target 20 ms) | 20.00 ms (CV → 0) | +7.79 |

`response-delay-only` and `ack-delay-only` move the *observer-visible* gap in opposite
directions **without changing true device processing time**; `gap-normalized` replaces
the device's native gap distribution with a bounded constant, erasing the per-device
gap signature.

---

## 6. Before / after device fingerprinting (classification + clustering)

Script `ack_fingerprint_eval.py` (`ack_fingerprint_eval.md`, `ack_fingerprint_clusters.png`).
11,494 device-specific transactions, **capture-level split** (train each base PCAP →
test its disjoint larger L PCAP). Supervised = random forest / logistic regression;
unsupervised = k-means / agglomerative scored by Adjusted Rand Index against the true
device. Scenarios: **native** (before) · **timing_gap_norm** (the implemented defense)
· **plus_ackmode** (a what-if upper bound that also hides the ACK mode — not
byte-preserving, shown only to expose the residual).

**Supervised device-ID accuracy (random forest; chance = 0.400):**

| feature family | native | timing_gap_norm (implemented) | plus_ackmode (what-if) |
|---|---:|---:|---:|
| ack_only | **0.810** | **0.810** | 0.400 |
| timing | 0.797 | 0.500 | 0.400 |
| size | 0.500 | 0.500 | 0.500 |
| all | 0.888 | 0.888 | 0.500 |

**Unsupervised clustering — Adjusted Rand Index (no labels, k=3):**

| feature family | native | timing_gap_norm | plus_ackmode |
|---|---:|---:|---:|
| ack_only | 0.654 | 0.658 | 0.000 |

**The three findings (honest):**

1. **The ACK channel alone is a strong fingerprint** — native `ack_only` accuracy
   0.810 (vs 0.400 chance), clustering ARI 0.654. The SEL-751 is perfectly isolated
   just by having a pure ACK before its response.
2. **Normalizing the gap magnitude does *not* defeat ACK fingerprinting** — under the
   implemented `timing_gap_norm`, `ack_only` accuracy is **unchanged (0.810 → 0.810)**
   and clustering barely moves, because a separate ACK **still exists**; pinning its
   gap to a constant does not make the device look combined. The `timing`-only channel
   *does* collapse (0.797 → 0.500). This is the key non-obvious result: **delaying the
   ACK/response changes the visible gap, not the fact that the device splits its ACK.**
3. **Only hiding the ACK mode itself closes the ACK channel** — the `plus_ackmode`
   what-if drops `ack_only` to chance (0.400) and ARI to 0.000, but that requires
   making every device present the same combined-ACK behaviour (a Phase-2A
   socket-induced primitive), which is **not byte-preserving and not implemented**.
   And even then **response size still leaks** (`all` stays 0.500 > 0.400 because
   ION7550's 61 B response distinguishes it) — closing that needs byte-preserving
   padding, a separate primitive.

The scatter figure `ack_fingerprint_clusters.png` shows this directly in the
(request→ACK, ACK→response gap) plane: BEFORE, SEL-751 sits in its own corner
(fast ~4 ms ACK, ~13 ms gap); AFTER the implemented defense its gap moves to 20 ms but
it is **still a separate cluster**; only the what-if collapses everything to one point.

---

## 7. What is proven vs what remains (strict claims, plan §12)

**Proven / validated here:**
- The trace fingerprint is real and device-specific (native all-features device-ID
  0.888–0.897 ≫ chance 0.400), and it rides mainly on **size** and **ACK mode**.
- A byte-preserving, class-independent response-time normalizer is implemented,
  unit-tested (22/22), rig-validated (930 txns, 0 miss/bypass/reset, wire-pinned).
- Delaying the application write **naturally** induces a pure ACK before the response
  at the 40 ms Linux delayed-ACK threshold — no forging (rig, 1,808 txns, 0 resets).
- The binding safety bound (TCP RTO ≈ 211 ms) is measured, and the targets sit under it.

**Explicitly NOT claimed:**
- Bounded normalization does **not** remove all leakage — **size** and **ACK mode**
  survive it (both need their own primitives).
- ACK manipulation changes only the **observer-visible** ACK-to-response gap, not the
  device's true processing time.
- The 40 ms threshold and the SEL-751 profile are **measured on this stack / trace /
  host / config**; they do not automatically generalize to other devices or kernels.
- The fingerprint before/after is a **distributional simulation on measured native
  timings**, not a fresh live capture of a defended device; a host-side capture is not
  exact wire timing; and P4 can hold existing packets but cannot safely **synthesize**
  a TCP ACK without extra state (ACK synthesis is deferred).

**Next primitives (to close the residual channels):** (a) byte-preserving size
padding for the response-size leak; (b) ACK-mode normalization (host-side ≥40 ms hold
or a P4 hold-and-release) so every device presents the same ACK behaviour; (c) full
two-host validation against **physical** SEL-751 / AB1400 / ION7550 devices; then (d)
the P4/Tofino data-plane implementation of hold-and-release.

---

## 8. Reproduce everything

```bash
cd dnp3_split_harness

# 1. characterize the six real traces  -> ack_trace_*.{csv,json}, ack_trace_summary.md
python3 characterize_ack_traces.py

# 2. unit tests for the timing policy   -> 22/22
python3 tests/test_timing_policy.py

# 3. before/after timing on the traces  -> trace_before_after.{csv,json,md,png}
python3 trace_before_after.py

# 4. before/after ACK fingerprinting     -> ack_fingerprint_eval.{json,md}, .png
python3 ack_fingerprint_eval.py

# 5. full attacker eval (device-ID, ablation, detect-the-defense)
python3 attacker_eval.py

# 6. RTO safety probe (loopback dev check)
python3 rto_probe.py --loopback --delays 0,1,2,5,10,20,50,100 --reps 20

# 7. socket ACK-separation (loopback smoke; rig commands in the notes)
python3 ack_separation_probe.py --loopback

# live defense (native = wire-identical; fixed/bounded normalize):
python3 split_server.py --delivery full --timing-mode fixed --target-delay-ms 25
python3 split_server.py --delivery full --timing-mode bounded \
    --target-min-ms 20 --target-max-ms 30 --timing-seed 12345 \
    --rto-safe-ms 105 --max-hold-ms 100 --max-queue-depth 8
```
