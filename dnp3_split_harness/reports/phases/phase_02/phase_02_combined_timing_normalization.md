# Phase 02 — Combined ACK-Bearing Response Normalization

Normalize the visible request→response time of piggybacked-ACK (combined) traffic without
changing response bytes, and measure the result. Produced by the isolated run
`20260716T111608Z_phase_02_combined_timing_normalization` (git-ignored, regenerable).

- **Code commit:** the mechanism is the existing `timing_policy.py` (native/fixed/bounded) +
  `split_server.py`; Phase 02 adds only orchestration/analysis (`phase02_*`), no timing/ACK/
  split change.
- **Tooling:** Python 3.8.10, tshark 4.4.9, scapy 2.4.3.
- **Environment constraint (decisive):** the two-host rig is not reachable this session and
  **loopback packet capture is permission-denied** (`dumpcap` is `root:wireshark` and this
  user is not in the `wireshark` group). Therefore the **sniffer-PCAP** gate items — exact
  wire timestamps and the ACK-mode-after-normalization check — **cannot be completed here**.
  They are the CONDITIONAL-PASS blocker, with exact commands below.

## What was measured (and how honestly)

- **Loopback, end-to-end, application-level** (`phase02_normalize_experiment.py`): the real
  `split_server` timing mechanism drives the request-aware replay; per transaction we record
  the **server-side** timing decision (selected target, added hold, deadline miss, bypass,
  queue depth) and the **client-observed** visible request→response time plus byte identity.
  This is real enforcement evidence — the client actually receives the response only after the
  target — but it is **not a sniffer PCAP**.
- **Projected policy property** (`phase02_projected_leakage.py`): the **shipped** scheduler
  (`timing_policy.ReleaseScheduler`, not a re-implementation) applied to the 7,195 real Phase 01
  device-specific COMBINED transactions, using each transaction's real arrival time. Labeled
  **PROJECTED**.

## Research questions

### RQ1 — does normalization reduce timing dependence on transaction characteristics?
**Yes, measured.** Loopback (wide response sizes 17 B–2407 B): the visible time's correlation
with response size drops from **−0.55 (native)** to **−0.17 (bounded)**, and with native-ready
time from **+0.68 (native)** to **+0.03 (bounded)**. Projected over the real (homogeneous)
device data: fixed/bounded pin the visible median to the target and cut the response-size
correlation to ≈**0** (0.03→0.006). (`fig02_decorrelation`, `phase02_decorrelation.json`.)

### RQ2 — does bounded normalization preserve DNP3 correctness?
**Yes.** Byte-for-byte response identity is **100% (150/150 per config)** across native, fixed,
bounded, on both `full` and `crc-boundary` delivery. `b"".join(chunks) == response` holds; no
CRC recompute, no field edit.

### RQ3 — does the configured target accidentally cause a separate pure ACK?
**Cannot be answered here — needs a PCAP.** Detecting whether the kernel emits a standalone
pure ACK requires packet capture, which is unavailable on this host. This is an open item; the
Phase 01 ION7550 exception (a ~72 ms delayed response produced a separate ACK) suggests targets
that push the response late enough *could* induce separation — to be measured on the rig with
capture, never assumed.

### RQ4 — what native-tail and deadline-miss leakage remains?
**Measured (projected).** Normalization pins transactions whose native time is below the target,
but the **native tail leaks**: transactions slower than the target keep `visible = native`.
Fixed-25 ms: **0.22%** of transactions exceed the target (deadline miss 0.22%); bounded-20 ms
floor: **0.95%**. This residual is why the projected `corr(visible, native)` stays positive
(0.87 fixed / 0.35 bounded) — the pinned bulk contributes no correlation, the leaking tail does.
Normalization cannot hide the tail downward without dropping bytes (out of scope).

### RQ5 — what latency/overhead is introduced?
The deliberate hold is the dominant added latency (≈ target − native ≈ 9 ms at the ~16 ms
native median for a 25 ms target). Client-visible time is pinned within a **±0.03 ms** CI
(fixed-25 → 25.31 ms). Scheduler compute is negligible (pure decision function). Split delivery
adds the existing per-chunk pacing without changing byte identity.

## Fail-open / safety (all bypasses reported)

A deliberate unsafe config — **fixed 300 ms target with `--rto-safe-ms 105`** — was run:
**150/150 transactions bypassed** (`bypass_reason = UNSAFE_TARGET`) and sent immediately
(visible ≈ native 0.64 ms), byte-identity 100%. The fail-open path works end-to-end.

## Results table (loopback, 2407 B Class-0 READ, n=30/config)

| config | byte-identical | bypassed | deadline miss | READ client-visible median (ms) | CI |
|---|---:|---:|---:|---:|---|
| native/full | 100% | 0 | 0 | 0.60 | [0.595, 0.611] |
| fixed25/full | 100% | 0 | 0 | 25.31 | [25.284, 25.315] |
| bounded20-30/full | 100% | 0 | 0 | 23.30 | [23.298, 23.309] |
| native/crc-split | 100% | 0 | 0 | 0.78 | [0.776, 0.792] |
| fixed25/crc-split | 100% | 0 | 0 | 25.31 | [25.294, 25.312] |
| bounded20-30/crc-split | 100% | 0 | 0 | 23.28 | [23.212, 23.331] |
| fixed300-rto105 (bypass) | 100% | 150 | 0 | 0.64 | [0.626, 0.648] |

## Tests

46 unit tests pass on Python 3.8.10 (22 timing_policy + 8 run_manifest + 9 phase01_stats +
**7 new phase02_policy**: fixed pins visible regardless of native/size; deadline accounting;
bounded-in-range; class-independent target; `wait_until` blocks to the deadline; native passthrough).

## Measured vs projected vs blocked

- **Measured (loopback, application-level):** byte identity; client-observed visible time
  tracks the target; decorrelation from response size; fail-open bypass; deadline accounting.
- **Projected (shipped policy over real device data):** median pinned to target; size-dependence
  eliminated; native-tail leakage 0.22–0.95%.
- **Blocked (needs PCAP capture or the rig):** exact wire timestamps; whether a normalized
  target induces a *separate* pure ACK (RQ3); retransmission/reset on the wire; rig realism.

## Claim discipline

Loopback timing is **not** wire timing; these results verify the mechanism and byte
preservation and measure the policy's decorrelation, not the defended device's on-wire
signature. The projected leakage is the *policy* applied to captured timestamps, not a live
capture. Nothing here claims the ACK mode after normalization — that needs a sniffer.

## Reproduction

```bash
cd dnp3_split_harness
python3 phase02_normalize_experiment.py --reps 30            # loopback enforcement + byte-identity
python3 phase02_projected_leakage.py   --run-dir <run>       # projected policy over real device data
# Blocked here; run on the rig (Vision/Hulk) or a host where this user can capture:
#   sudo dumpcap -i <if> -w wire.pcap   # then classify separate-vs-combined ACK after normalization
```

## Phase 02 gate (§11)

| Requirement | Status |
|---|---|
| native mode is wire-equivalent | PARTIAL — loopback native visible ~0.6 ms and byte-identical; *wire*-equivalence itself needs a PCAP (pending, blocked below) |
| fixed & bounded modes preserve response bytes | PASS (byte-identity 100%, 150/150 per config) |
| **actual wire timing verified by PCAP** | **BLOCKED** — no capture permission / no rig this session |
| **combined ACK behavior characterized after normalization** | **BLOCKED** — needs a sniffer PCAP (RQ3) |
| no unsafe timeout behavior | PASS (0 deadline misses in normal configs; fail-open bypass verified) |
| all missed targets and bypasses reported | PASS (bypass 150/150 logged; native-tail leak measured) |
| timing leakage reduction measured, not asserted | PASS (decorrelation measured loopback + projected) |

**Status: CONDITIONAL PASS.** The mechanism, byte preservation, client-observed enforcement,
fail-open safety, and leakage reduction are validated on loopback and by the shipped-policy
projection. Two gate items — **PCAP-verified wire timing** and **ACK-mode-after-normalization**
— cannot be completed on this host (capture permission denied; rig unavailable) and are the
remaining work, to be run on the Vision/Hulk rig. `next_phase_allowed = false`.

```
STOP: Awaiting rig PCAP validation and human authorization before Phase 03.
```
