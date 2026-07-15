# DNP3 Response-Time Normalization — Phase 1 Implementation & Evaluation

_Execution of `ack_delay.md`. Protocol-aware timing manipulation for DNP3/TCP,
layered on the existing byte-preserving replay/split harness. Timing changes only
**when** bytes leave the server; it never changes **which** bytes, so
`b"".join(chunks) == response` still holds. Loopback results here are a
mechanism/correctness check — the two-host rig (Vision/Hulk) is the real bar._

This report follows the plan's "Required outputs" (§11).

---

## 0. Completion status (audited against `ack_delay.md`)

| Plan section | Status | Evidence / what's deferred |
|---|---|---|
| §1 Characterize 6 traces | **COMPLETE** | 22,988 txns → `ack_trace_*`; profiles; terminology + expected pattern validated (measured) |
| §2 Phase-1 bounded normalization | **COMPLETE** | `timing_policy.py` + `split_server` hook; correct `max(ready, arrival+target)` design; native/fixed/bounded |
| §3 Fail-open safety + RTO probe | **COMPLETE** | all 5 bypasses; RTO **measured 211 ms** (not assumed 200); `rto_probe.py` |
| §4 Phase-1 experiment matrix | **RIG-VALIDATED** | native/fixed/bounded × full/split, **30 reps/config on Vision↔Hulk = 930 timed txns, 0 miss / 0 bypass / 0 reset**, fixed-25 pinned to 25.000 ms server-side + **25.36 ms on the wire (±0.1 ms), 0 retransmits** (tcpdump); see `reports/rig_timing_matrix_results.md`. Multi-CROB & SELECT/OPERATE dimensions still need control traffic; device size-leak closure needs real devices (rig outstation is the replay server) |
| §5A Socket ACK separation | **RIG-VALIDATED** | server-side tcpdump on Hulk eno1 across write-delays 0–50 ms (1808 txns): pure-ACK-before-response **induced at ≥40 ms (Linux delayed-ACK timeout), combined ≤38 ms** — no forging, 0 resets; raw-packet verified; see `reports/ack_separation_rig_results.md`. Bounds Phase 1 (10–25 ms targets stay combined) and enables Phase-2 gap work without forging |
| §5B Independent ACK/response delay | **PARTIAL** | `plan_ack_response_release` (5 modes + ordering) built & unit-tested; **not wired to a live separate-ACK flow** (depends on §5A → rig) |
| §6 Conceptual model | **COMPLETE** | true-processing vs request-response vs visible-gap distinction explicit in code + report |
| §7 Trace target profiles | **COMPLETE** | `profiles/*.json`; observed-vs-configured kept separate; no auto-deploy |
| §8 Attacker evaluation | **SUBSTANTIAL** | device-ID + simulated defense + detect-the-defense + ablations + metrics; **all 4 models run** (numpy NC/logreg + sklearn RF/GB — trees corroborate: native GB 0.917 / RF 0.889); defense is simulated on trace features, not a live capture |
| §9 Code architecture | **COMPLETE** | all five abstractions; per-flow FIFO; no global reordering |
| §10 Required tests | **COMPLETE (unit) / PARTIAL (integration)** | 22/22 unit; native-master + combined-with-delay + no-reset integration PASS; separate-ACK-delay & SELECT/OPERATE are rig/other-harness |
| §11 Required outputs | **COMPLETE** | this report (8 sections) |
| §12 Strict claims | **HONORED** | §9 below |

**Verdict:** Phase 1 (plan priorities 1–3) is **complete and validated with a real DNP3
stack**. Phase 2 (priorities 4–5) is the plan's explicit *follow-on* ("do this only after
Phase 1"): its logic is built and unit-tested, but its authoritative measurement needs a
privileged packet capture and the two-host rig. Priorities 6–7 (attacker eval / P4) are
done-with-caveats and assessed-not-implemented respectively, as the plan sequences them.

---

## 1. Repository assessment

- **Where requests are received:** `split_server.py`, `TCPSplitReplayServer.serve_once()`
  — `FrameReader.next_frame()` reassembles one whole DNP3 link frame from the TCP
  stream and returns it.
- **Where responses are "generated":** this is a **replay** server, so the response
  is not computed — it is looked up from the captured request→response map
  (`CapturedExchange.match_response`) and split on CRC boundaries
  (`DNP3CRCSplitter.split`). Response-ready time ≈ request-arrival time (there is no
  real device processing delay to reproduce), which makes it the ideal place to
  *impose* a controlled, class-independent response time.
- **Where bytes are sent:** `TCPSplitReplayServer._send_chunks()` — `socket.sendall()`
  per chunk over a `TCP_NODELAY` socket, with the pre-existing optional
  `--chunk-delay-ms` pause between chunks.
- **Best insertion point for timing control:** immediately before `_send_chunks`, in
  `serve_once`, after the byte-preservation check. The request-arrival timestamp is
  captured the instant `next_frame()` returns. The codebase already performed timing
  manipulation (`--chunk-delay-ms` sleeps between chunks), so a response-hold is a
  natural, in-scope extension and needed no architectural change.
- **Scope guard:** the split harness is deliberately control-free (spec-clean). No
  SELECT/OPERATE code was added; a `CRITICAL_FUNCTION_CODES` hook is present so that
  if a control-bearing request ever appeared it is bypassed (never held) by default.
  Control experiments belong to the separate multi-CROB harness / real devices.

## 2. Trace characterization (all six PCAPs)

Full per-transaction reconstruction is in `reports/ack_trace_characterization.csv`
(22,988 transactions), `.json`, and `reports/ack_trace_summary.md`. Device profiles
are in `profiles/{sel751_separate_ack,ab1400_combined_ack,ion7550_combined_ack}.json`.

Device-specific outstation flows (the shared reference outstation `10.0.0.2` excluded):

| Device (IP) | ACK mode | ACK→response gap (median / p95 / max) | request→response median | resp sizes (B) |
|---|---|---|---|---|
| **SEL-751 (10.0.0.1)** | **SEPARATE** (100%) | **12.9 / 16.6 / 166 ms** | ~16 ms | 37, 54 |
| AB1400 (10.0.0.12) | COMBINED (100%) | 0 / 0 / 0 ms | ~16 ms | 37, 54 |
| ION7550 (10.0.0.11) | COMBINED (~100%) | 0 / 0 / 29 ms | ~16 ms | 37, 61 |
| reference (10.0.0.2) | COMBINED (~99.9%) | 0 ms | ~16 ms | per-capture |

Findings that drive the design:
- **SEL-751 emits a pure TCP ACK first, then the DNP3 response** — the ACK→response
  gap (median ~13 ms) is the cross-layer response time an attacker fingerprints
  (Formby-style). This is the Phase-2 target.
- **AB1400, ION7550, and the reference piggyback** the ACK onto the response (gap 0 ms)
  — the Phase-1 target. Their only exploitable timing observable is request→response
  (~16 ms) and their response **size** (37 vs 54 vs 61 B is device-distinguishing).
- 0 transactions were unclassifiable. 93 retransmission-flagged and 4 reset-flagged
  transactions (ION7550/AB1400) were still cleanly classified; flags are recorded
  per row.
- Requests are DNP3 READ (func 1) and DIRECT_OPERATE (func 5); responses are func 129.

## 3. Implementation plan (Phase 1 first, Phase 2 after)

Phase 1 (**done**): bounded response-time normalization for the combined ACK-bearing
response — hold the prepared response until a class-independent target release time
measured from request arrival. Phase 2 (**scaffolded, rig-deferred**): induce and then
independently delay a separate pure ACK + DNP3 response. See §8 research report.

## 4. Code changes

New files (all under `dnp3_split_harness/`):
- **`timing_policy.py`** — the reusable policy module: `TimingProfile`,
  `TimingDecision`, `FlowTimingState`, `ReleaseScheduler`, `BypassReason`, the Phase-2
  `plan_ack_response_release()` helper, `wait_until()` (absolute-deadline wait), and
  CLI wiring (`add_timing_arguments` / `profile_from_args`).
- **`tests/test_timing_policy.py`** — 22 unit tests (all pass; see §7).
- **`tests/loopback_smoke.py`** — loopback integration + timing validation.
- **`run_timing_experiment.py`** — reproducible Phase-1 matrix runner.
- **`characterize_ack_traces.py`** — the trace parser (§2 outputs).
- **`rto_probe.py`** — TCP RTO / retransmission safety probe (§ safety).
- **`ack_separation_probe.py`** — Phase-2A socket ACK-separation experiment.
- **`attacker_eval.py`** — attacker classification evaluation (§8 of the plan).

Modified: **`split_server.py`** — added `import timing_policy`; a `CRITICAL_FUNCTION_CODES`
set; a `scheduler`/`rto_safe_ms` on the server; request-arrival timestamping; a
`_apply_timing()` hold-before-send hook; per-transaction `timing_decisions.jsonl`
logging; and the timing CLI flags. **Native mode is wire-identical to the previous
behavior** (hold = 0; only a timing log is added).

The correct-vs-wrong design (from the plan) is enforced in `ReleaseScheduler.decide`:
`target_delay` is sampled from a common bounded distribution and
`actual_release = max(response_ready, request_arrival + target_delay)` — normalization,
not `native + jitter`. The sampled target never depends on CROB count, response size,
request size, native ready time, or device identity (unit-tested:
`test_target_independent_of_response_size`).

## 5. Run commands

Native (unchanged behavior, adds a timing log):
```bash
python3 split_server.py --delivery full --timing-mode native
```
Fixed normalization (hold every response to 25 ms from request arrival):
```bash
python3 split_server.py --delivery full --timing-mode fixed --target-delay-ms 25
```
Bounded normalization (uniform target in [15,25] ms, reproducible):
```bash
python3 split_server.py --delivery full --timing-mode bounded \
    --target-min-ms 15 --target-max-ms 25 --timing-seed 12345
```
Fail-open safety (never hold > measured-safe bound; bypass under strict mode):
```bash
python3 split_server.py --timing-mode bounded --target-min-ms 15 --target-max-ms 25 \
    --max-hold-ms 100 --rto-safe-ms 105 --max-queue-depth 8
```
RTO safety probe (loopback) and Phase-2A socket ACK-separation (loopback):
```bash
python3 rto_probe.py --loopback --delays 0,1,2,5,10,20,50,100 --reps 20
python3 ack_separation_probe.py --loopback --delays 0,1,2,5,10,20,50 --reps 20
```
Phase-2 ACK/response modes (parameters live in `timing_policy.plan_ack_response_release`;
wire-up requires a separate-ACK flow — rig): `--ack-mode {native,ack-delay-only,
response-delay-only,independent-delay,gap-normalized}` with `--ack-delay-ms /
--response-delay-ms / --gap-target-min-ms / --gap-target-max-ms`.

## 6. Experiment scripts

- `run_timing_experiment.py` → `reports/timing_experiment_results.{csv,json}` (Phase-1
  matrix: native / fixed / bounded × full & split delivery; visible timing + server-side
  hold / deadline-miss / bypass + byte identity).
- `characterize_ack_traces.py` → the §2 outputs.
- `rto_probe.py` → `reports/rto_probe_results.{csv,json}` + `rto_probe_notes.md`.
- `ack_separation_probe.py` → `reports/ack_separation_matrix.{csv,json}` + notes.
- `attacker_eval.py` → `reports/attacker_eval_results.json` + `attacker_eval.md`.
All overwrite outputs on each run (no stale reuse) and use fixed seeds where random.

### Phase-1 matrix results (loopback, 20 reps; timed READ = 2407 B response)

| config | delivery | bytes | visible median | visible p95 | visible max | hold median | miss | bypass |
|---|---|---|---|---|---|---|---|---|
| native | full | OK | 0.655 ms | 0.716 | 0.754 | 0.0 | 0 | 0 |
| fixed-10ms | full | OK | 10.171 ms | 10.457 | 10.477 | 9.55 | 0 | 0 |
| fixed-25ms | full | OK | 25.173 ms | 25.192 | 25.203 | 24.56 | 0 | 0 |
| bounded-10-15ms | full | OK | 14.552 ms | 14.570 | 14.582 | 10.45 | 0 | 0 |
| bounded-15-25ms | full | OK | 23.940 ms | 24.332 | 24.335 | 16.39 | 0 | 0 |
| native-crc-split | crc-boundary | OK | 0.793 ms | 0.851 | 0.863 | 0.0 | 0 | 0 |
| bounded-15-25ms-crc-split | crc-boundary | OK | 23.992 ms | 24.254 | 24.469 | 16.19 | 0 | 0 |

Reading: native visible time is ~0.7 ms (the replayed response is ready almost
instantly). Under normalization the visible request→response time is pinned to the
configured target with a very tight spread (fixed-25 ms: median 25.17, p95 25.19,
max 25.20), for both full and CRC-split delivery, with **byte-identity ALL PASS** and
**zero deadline-misses / zero bypasses**. Because every transaction — regardless of its
native ready time or response size — is released at the same target, the
response-content→timing dependence is removed on the held path. (Loopback native times
are sub-ms; on the rig the native times are the real ~16 ms device times, so pick
targets ≥ the native p95 — see §7 RTO bound.)

## 7. Validation report

- **Unit tests:** `python3 tests/test_timing_policy.py` → **22 passed, 0 failed**
  (also 22 passed under `pytest`). Covers fixed/bounded release, seeded determinism,
  response-ready-before/after-target, deadline miss, per-flow FIFO, multi-flow
  independence, all five fail-open bypasses, invalid config, ACK-before-response
  ordering (no ACK after response), and the structural no-payload/no-synthesis check.
- **Byte identity:** `tests/loopback_smoke.py` → **ALL PASS** for native/fixed/bounded
  under both full and crc-split delivery. The received response equals the captured
  bytes for every transaction — timing changes did not alter bytes.
- **Timing normalization (loopback):** native visible request→response ≈ 0.3–0.8 ms;
  fixed 25 ms → 25.3 ms; bounded [20,30] → 23.3 ms. These figures are from the loopback
  smoke test (`tests/loopback_smoke.py`, which sweeps native / fixed-25 / bounded-20-30),
  distinct from the §6 matrix (`run_timing_experiment.py`, bounded-15-25 → 23.9 ms). The
  hold makes the visible time track the target rather than the (tiny) native ready time.
- **Native DNP3 stack — real pydnp3 master (`tests/native_master_loopback.sh`, ALL 7
  PASS):** a real `run_master.py --action scan-all-classes` completed a full integrity
  poll against the timing-enabled server (fixed 25 ms). The master decoded the entire
  outstation database (Binary/Analog/Counter/Double-bit/Output-status), issued its DNP3
  CONFIRM, and accepted the held continuation — with every one of the 5 responses held
  ~24.4–24.7 ms → 25.0 ms visible, **byte-preservation PASS on all, 0 deadline-misses,
  0 bypasses, 0 TCP resets, no DNP3 task timeout** (master response-timeout 2 s ≫ 25 ms
  hold). This confirms with a real DNP3 stack that a bounded response hold well under RTO
  is transparent to the master.
- **Safety / RTO boundary (measured, not assumed):** `rto_probe.py` (loopback, `ss`
  TCP_INFO backend) → 0 retransmissions, 0 resets, 20/20 responses at every hold
  0–100 ms; measured peer RTO floor **≈ 211 ms** (Linux `TCP_RTO_MIN`), rising to
  ~215 ms at 50–100 ms holds. Conservative safe hold ≈ **105 ms** (half the smallest
  observed RTO). Our targets (10–30 ms) sit far under this. **Caveat:** loopback is not
  wire behavior; the authoritative RTO comes from the Vision/Hulk rig (command in
  `reports/rto_probe_notes.md`).
- **Deadline miss / bypass:** reported per config in `timing_experiment_results.csv`.
- **Phase-2A socket ACK-separation (loopback, `ack_separation_probe.py`):** the
  delay-then-write mechanism works — round-trip tracks the applied application-write
  delay (0→0.02, 1→1.10, 5→5.19, 10→10.34, 20→20.51, 50→50.40 ms), and all 560
  exchanges returned the full 2407 B DNP3 response with 0 resets. **Whether a delay
  produces a pure TCP ACK before the response could NOT be determined on this host**:
  packet capture needs `CAP_NET_RAW`/root, which this user lacks, so every
  `pure_ack_emitted` cell is recorded as `unknown` (not guessed). A one-factor socket
  sweep (baseline / TCP_NODELAY on/off / TCP_QUICKACK) ran but its ACK-separation effect
  is capture-only and thus unresolved here. Authoritative measurement requires the rig
  with a privileged capture (command in `reports/ack_separation_notes.md`); note the
  governing knob is the *server's* delayed-ACK/QUICKACK, since it is the server that
  ACKs the request.

## 8. Research report

**What was demonstrated.** (1) The size and timing fingerprints are real and
device-specific in the traces (§2). (2) A byte-preserving, class-independent
response-time normalizer is implemented, unit-tested, and integrated into the replay
server; on loopback it makes the visible response time equal the target regardless of
response content, while preserving every response byte. (3) The binding safety
constraint (TCP RTO) was **measured** at ≈211 ms, and the chosen targets are safely
under it.

**What remains unproven (needs the rig / real devices).** The full 30–100-rep
experiment matrix on Vision/Hulk; the attacker-accuracy drop against a *live* defended
server (the §-attacker eval here uses the measured trace features plus a *simulated*
normalization, not a live capture); and Phase-2 ACK separation on real hosts.

**Limits of the current host/kernel behavior (Phase 2A).** Inducing a *natural* pure
ACK before the response by delaying the application write depends on the kernel
delayed-ACK timer and cannot be established from an unprivileged loopback capture on
this host (capture needs `CAP_NET_RAW`); see `reports/ack_separation_notes.md`. It must
be characterized on the rig.

**P4 feasibility for delaying existing packets.** Delaying packets that already exist
(hold-and-release) is the operation P4/Tofino can plausibly do with a timestamp + a
release gate; *synthesizing* a TCP ACK from nothing needs additional state/recirculation
and is deferred — hence Phase 1 (hold the existing response) is the P4-friendly primitive
and is implemented first.

**Why ACK synthesis is deferred.** It leaves the byte-preserving phase (you must forge a
segment), it is the harder dataplane operation, and Phase 1 already delivers the core
result (response-time normalization) without it.

### Attacker evaluation (plan §8 — `attacker_eval.py`, seed 42)

Device-type fingerprinting on 11,494 device-specific transactions, **capture-level
split** (train each device's base PCAP → test its disjoint larger `L` PCAP; leave-one-
PCAP-out GroupKFold as robustness). Four models ran: a numpy nearest-centroid and
multinomial logistic regression, plus scikit-learn (1.3.2) random forest and gradient
boosting; the trees also run in the detect-the-defense and permutation-importance passes.
The tree ensembles corroborate the logistic-regression finding — native all-features
device-ID is **GB 0.917 / RF 0.889** (vs logreg 0.897), and all three stay high under
timing normalization (RF 0.866–0.900, GB 0.887–0.917) — confirming the fingerprint is
model-independent and rides on the size / ACK-mode channels the timing defense does not
touch. Detect-the-defense agrees across models (constant-25 AUC: LR 0.990, RF/GB 0.999;
uniform_15_25 ≈ 0.87–0.90; uniform_10_15 ≈ 0.50), and tree permutation importance confirms
`resp_size`/`req_size` dominate while crediting the timing features slightly more than the
linear model (trees exploit SEL751's ACK-timing split that logreg under-weights).

- **Native fingerprint is real:** all-features device-ID accuracy **0.897** (95% CI
  [0.891, 0.903]), macro-F1 0.849, ROC-AUC 0.969 (chance 0.400); SEL-751 is perfectly
  separable (its separate-ACK mode is a giveaway).
- **Ablation (accuracy native → defended):** `size_only` 0.500 and `ackmode_only`
  0.800 are **unchanged** by the timing defense (it cannot touch size or ACK mode);
  `timing_only` is where normalization acts.
- **Key design finding:** a normalization floor must **exceed** the native latency
  (~16 ms) to hide anything — `uniform[10,15]` is a near-no-op (native already > 15 ms).
  **Pick targets ≥ native p95.**
- **The timing channel is thin in this trace (honest):** the fingerprint is carried
  mainly by response **size** (separates ION7550) and **ACK mode** (separates SEL-751),
  not latency. The only identity carried uniquely by response latency (AB1400 vs
  ION7550, both combined-ACK) is essentially absent **even natively** (balanced accuracy
  0.497, at the 0.5 floor). Under `constant-25` the two devices' timing vectors become
  provably identical (balanced acc 0.500): the defense does erase the small timing signal
  it targets, but that signal was not what made devices separable here.
- **Residual leakage (honest):** because size and ACK-mode carry most separability,
  all-features device-ID stays ~0.90 even after timing normalization. The timing
  defense closes the **timing channel specifically**; the size leak needs byte-
  preserving padding (not in this phase) and the ACK-mode leak needs the Phase-2 ACK-
  timing primitive.
- **Detect-the-defense:** `constant-25` is highly detectable (AUC 0.99, hard floor +
  quantization); `uniform[15,25]` AUC 0.887; `uniform[10,15]` undetectable because it
  is a no-op. Bounded jitter is less detectable than a constant target — a
  normalization-vs-stealth trade-off to report.

This is a **simulation on trace features** (normalizing recorded `req_to_resp_ms`), not
a capture of the live defended server; full details and caveats in `reports/attacker_eval.md`.

## 9. Strict research claims (honored)

This work does **not** claim: that bounded normalization removes all leakage (response
**size** still distinguishes devices — there is no byte-preserving DNP3 padding in this
phase; the timing defense closes the *timing* channel only); that ACK manipulation
reduces actual device processing time (it changes only the observer-visible gap); that
all DNP3 devices share one ACK behavior (measured: SEL-751 separate, others combined);
that the SEL-751 profile generalizes to other SEL devices; that a host capture is exact
wire timing; that socket delay always forces a separate ACK; or that P4 can safely
synthesize ACKs without extra state. Wording throughout uses "observer-visible
ACK-to-response gap", "request-to-response timing", "ACK-bearing DNP3 response",
"pure TCP ACK", and "measured on this device/trace/host/config".
