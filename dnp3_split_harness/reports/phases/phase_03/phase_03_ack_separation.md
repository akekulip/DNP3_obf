# Phase 03A — Socket-Level ACK-Separation Characterization

**Status: CONDITIONAL PASS** (measured from fresh captures; awaiting human packet inspection).
Capture is no longer blocked — `philip` was added to the `wireshark` group and all captures ran
under `sg wireshark` (a group switch, **not** sudo). No wire data is fabricated; every number
below derives from PCAPs produced this session and re-derived by the analyzer.

_Scope label (applies to every finding): **Measured on the gambit loopback interface, Linux
kernel 5.15.0-139-generic, in the tested socket and application configuration.** Do not
generalize to other kernels, the Vision/Hulk rig, OpenDNP3 in general, or the physical SEL-751 /
AB1400 / ION7550 devices._

## 1. Phase objective

Determine under what conditions delaying the application's response write causes the host kernel
to emit a **separate pure TCP ACK before the DNP3 response**, and characterize that transition.
This phase characterizes a mechanism; it is **not** the final defense and does not manipulate the
ACK independently (that is Phase 04, gated).

## 2. Research questions and answers

- **RQ1 — At what application-write delay does a pure TCP ACK appear?** A separate pure ACK for
  non-first requests first appears at **36 ms** (1/80) and reaches **100% at 40 ms**; it is absent
  (0/80) at every delay ≤ 35 ms.
- **RQ2 — Is the threshold sharp or probabilistic?** **Probabilistic (graded).** The 1 ms refined
  sweep shows a monotonic rise: 0% (35 ms) → 1.2% (36) → 7.5% (37) → 18.8% (38) → 47.5% (39) →
  100% (40), crossing 50% near **39 ms**. It is not a hard step.
- **RQ3 — Does it vary by kernel, socket options, request/response size?** Measured (one factor
  at a time, this host/kernel): **response size has no effect** (0% separate at 25 ms and 100% at
  50 ms across 17–2407 B, a 140× range); **TCP_NODELAY has no effect** (identical to baseline at
  both anchors — Nagle governs the sender's coalescing, not the receiver's ACK); **TCP_QUICKACK
  forces separation** — server-side quickack flips COMBINED→SEPARATE even at 25 ms (0→100%),
  showing the separate ACK is a delayed-ACK phenomenon that *is* controllable from user space.
  **Not varied:** kernel (single host) and request size (all replay requests are small READs) — see §16.
- **RQ4 — Is separation stable across repetitions?** Yes. At each coarse endpoint the outcome is
  uniform (0/80 for ≤35 ms, 80/80 for ≥40 ms across 20 replay sessions × 4 non-first groups); the
  graded region is monotonic and reproduced at the 35 ms and 40 ms anchors across two independent
  runs.
- **RQ5 — Does forcing separation cause retransmissions or DNP3 failure?** **No.** Across all
  2875 captured transactions: **0 retransmissions, 0 duplicate ACKs, 0 resets**, and **100%
  byte-identical** responses. Every DNP3 transaction completed.

## 3. Scope

Restricted "Phase 03A": wire capture + ACK-mode classification of the **existing** Phase 02
timing configs plus a controlled application-write delay sweep expressed through the existing
fixed-timing mode. **No ACK synthesis, no independent ACK delay, the validated Phase 02 scheduler
untouched.** Loopback (`lo`) single-host capture only.

## 4. Inputs and SHA-256 hashes

- Replay request/response set `payloads/replay/metadata.json` —
  `912b5c6bf537ced0209fa5952224fa4522d375da06f816352ab9e7c04c9b5ee2` (4320 bytes). Recorded in
  every run manifest under `inputs`.
- Result tables and their hashes are recorded in each figure's `*.metadata.json` sidecar
  (`source_tables`) and in the copied run manifests under `tables/phase03_*_manifest.json`.

## 5. Repository commit

Tooling committed at `c13453c` (`--delays-ms` refinement flag; parent `04f02fe` for the capture
runner). Results committed at **`5d4a6e73b5495f3f2d9ecb01d262cf0f88c893d2`** (`git commit --amend`
is guard-blocked, so this SHA is recorded here in a follow-up commit).

## 6. Environment

- Host `gambit`; `Linux-5.15.0-139-generic-x86_64-with-glibc2.29`; kernel `5.15.0-139-generic`.
- Capture: `dumpcap`/`tshark` **Wireshark 4.4.9**, run under the `wireshark` group via
  `sg wireshark` (process groups `wireshark sudo ollama philip`); **no sudo** used for execution.
- Interface `lo` (loopback), single host — sender == receiver, one clock, **no NIC offloads**
  (a rig run must additionally record the NIC and `ethtool -k`). `net.ipv4.tcp_low_latency = 0`.
- Analysis: Python 3.8.10, scapy 2.4.3, the Phase 01-validated extractor (`phase01_reconstruct`).
- Client sets `TCP_NODELAY`; the split_server sets `TCP_NODELAY`. Full environment JSON:
  `tables/phase03_capture_environment.json`.

## 7. Agents used and their findings

Lead session acted as PCAP/Protocol Analyst and TCP/Socket Specialist. Findings: the analyzer's
COMBINED/SEPARATE/OTHER classification (validated in Phase 01 against SEL-751 100% separate,
AB1400/ION7550 100% combined) reproduces cleanly on fresh loopback captures; the first request of
each TCP connection carries a post-handshake quickack ACK independent of the delay, so the
timing-relevant metric is computed over **non-first** requests only.

## 8. Files added, changed, moved, or deprecated

- **Changed:** `phase03_capture.py` — additive `--delays-ms` override (sweep only) and a `--mode
  socket` socket-option factorial; default coarse list and the Phase 02 scheduler unchanged.
- **Changed:** `split_server.py` — additive `--server-nodelay {on,off}` and `--server-quickack`
  (Linux TCP_QUICKACK, re-armed per request). Socket-setup only; defaults preserve shipped
  behavior (NODELAY on, no forced quickack); the timing/scheduler path is untouched.
- **Added:** `phase03_figures.py` (8 figures + metadata sidecars).
- **Added (committed results):** `reports/phases/phase_03/tables/*` (matrix + coarse + refined +
  **socket** summaries, transactions, manifests, merged `phase03_delay_sweep.csv`,
  `phase03_socket_option_summary.csv`, `phase03_environment_dependence.csv`, capture environment);
  `reports/phases/phase_03/figures/*`; `reports/phases/phase_03/validation/*`
  (`phase03_human_packet_validation.csv` + `.md` + `pcaps/`).
- **Rewritten:** this report and `phase_status.json` (BLOCKED → measured); Phase 02 wire addendum.

## 9. Exact commands

```bash
cd dnp3_split_harness
# matrix (7 configs, 25 reps x 5 groups):
sg wireshark -c 'python3 phase03_capture.py --mode matrix --reps 25'
python3 phase03_analyze.py --run-dir <matrix_run> --pcap-dir <matrix_run>/pcaps
# coarse delay sweep (0..100 ms, 20 reps):
sg wireshark -c 'python3 phase03_capture.py --mode sweep --reps 20'
python3 phase03_analyze.py --run-dir <coarse_run> --pcap-dir <coarse_run>/pcaps
# refined 1 ms sweep around the transition:
sg wireshark -c 'python3 phase03_capture.py --mode sweep --delays-ms 35,36,37,38,39,40 --reps 20'
python3 phase03_analyze.py --run-dir <refined_run> --pcap-dir <refined_run>/pcaps
# socket-option factorial (RQ3), one factor at a time at 25 ms + 50 ms anchors:
sg wireshark -c 'python3 phase03_capture.py --mode socket --reps 20'
python3 phase03_analyze.py --run-dir <socket_run> --pcap-dir <socket_run>/pcaps
# figures from the committed tables:
python3 phase03_figures.py --report-dir reports/phases/phase_03
```

## 10. Tests executed

`python3 -m pytest tests/` → **56 passed** (includes the Phase 01 Wilson-CI and extractor tests
that back the classification pipeline; the socket-option edits to `split_server.py` preserve the
shipped-default behavior these tests cover). Byte-identity asserted in-capture: 875/875 (matrix),
1400/1400 (coarse), 600/600 (refined), 600/600 (socket).

## 11. Tests skipped and why

No unit test was added for the `--delays-ms` argument parsing (a thin argparse pass-through over
the already-tested capture path); the refinement's correctness is evidenced by the captured data
and byte-identity rather than a mock. Cross-host / physical-device validation is out of Phase 03A
scope (Phase 06+).

## 12. Raw result locations

Run directories (git-ignored, regenerable): `runs/20260716T134719Z_phase_03a_wire_matrix`,
`runs/20260716T140003Z_phase_03a_wire_delay_sweep` (coarse),
`runs/20260716T142946Z_phase_03a_wire_delay_sweep` (refined),
`runs/20260716T145525Z_phase_03a_wire_socket_options` (socket factorial). Committed copies (tables
+ manifests + referenced PCAPs) under `reports/phases/phase_03/`.

## 13. Figures and tables generated

Figures (`reports/phases/phase_03/figures/`, PNG+PDF, each with a metadata sidecar):
`fig01_ack_mode_by_config`, `fig02_separation_probability_by_delay` (threshold S-curve + Wilson
95% band + transition band), `fig03_request_to_ack_cdf`, `fig04_ack_to_response_cdf`,
`fig05_request_to_response_cdf`, `fig06_example_combined_timeline`, `fig07_example_separate_timeline`,
`fig08_socket_option_comparison` (RQ3 socket-option comparison). Tables
(`reports/phases/phase_03/tables/`): matrix/coarse/refined/socket ACK summaries and transactions,
merged `phase03_delay_sweep.csv` (threshold curve with CIs), `phase03_socket_option_summary.csv`
(socket-option comparison), `phase03_environment_dependence.csv` (environment-dependence table),
capture environment, run manifests.

## 14. Main findings

1. **Normalization preserves the native COMBINED ACK.** For non-first requests, native, fixed25,
   and bounded20-30 (all full delivery) are **0/100 separate** (Wilson95 [0.000, 0.037]) — the
   fixed/bounded targets (~25 / ~23 ms) sit below the transition and behave exactly like native.
2. **Threshold curve.** Separation for non-first requests is 0/80 at every app-write delay ≤ 35 ms
   and 80/80 at every delay ≥ 40 ms; the 1 ms refinement resolves a **graded** rise across
   36–40 ms (1.2 → 7.5 → 18.8 → 47.5%), 50% near 39 ms.
3. **Separated-regime timeline.** When a separate ACK appears, the pure ACK is emitted **promptly**
   (median request→pure-ACK ≈ 0.015 ms) and the DNP3 response follows at the configured app-write
   delay (median pure-ACK→response ≈ 40.8 ms at the 40 ms point). The ACK is not itself delayed to
   the timer; the *response* is what moves past the delayed-ACK window.
4. **First-in-connection artifact.** The first request of each TCP connection always carries a
   prompt pure ACK (≈ 25 per matrix config, ≈ 20 per sweep config), independent of the delay — a
   post-handshake quickack effect, correctly excluded from the timing-relevant metric.
5. **crc-split.** Chunked responses classify as OTHER/ambiguous (multiple response segments), not
   as a timing separation — a delivery-reconstruction nuance, flagged for the human worksheet.
6. **No instability.** 0 retransmissions / duplicate ACKs / resets and 100% byte-identity across
   every config and delay (2875 characterization txns + 600 socket txns).
7. **Socket-option factorial (RQ3).** TCP_NODELAY (Nagle) has **no effect** on separation
   (identical to baseline: 0/80 at 25 ms, 80/80 at 50 ms). **TCP_QUICKACK forces separation** — with
   server-side quickack, non-first requests separate **80/80 even at 25 ms** (baseline 0/80), so the
   separate ACK is a delayed-ACK effect that is controllable from user space. Response size
   (17–2407 B) has no effect at a fixed delay.

## 15. Failed or ambiguous cases

crc-split configs produce OTHER (chunked delivery) for ~50% of non-first transactions; this is
expected and is included in the human-validation worksheet for confirmation. No retransmissions,
resets, or missing responses occurred in any config.

## 16. Threats to validity

- **Single-host loopback:** no NIC offloads, sender and receiver share one clock and stack; the
  delayed-ACK / write-scheduling interaction on a two-host rig with real NICs may differ.
- **Kernel/config specificity:** the ~36–40 ms transition reflects this kernel's delayed-ACK
  behavior and socket configuration; it is not a universal constant.
- **Partial factorial:** TCP_NODELAY (on/off), TCP_QUICKACK, and response size (17–2407 B) were
  swept; **request size** (all replay requests are small READs) and **kernel** (single host) were
  not varied.
- **Socket-option factors measured at two anchor delays only** (25 ms combined, 50 ms separate),
  not across the full delay curve; sufficient to establish direction of effect, not a full surface.
- **Mechanism interpretation:** the prompt-ACK-then-delayed-response structure is measured, but the
  full kernel-level explanation (delayed-ACK vs. quickack state machine) is deferred to the TCP
  specialist / human review rather than asserted here.
- **Human packet inspection not yet done** (the reviewer verdicts are blank by design).

## 17. Measured vs simulated vs projected

Everything in §14 is **measured** from fresh PCAPs. Nothing is simulated or projected. The
per-frame timeline figures are single measured transactions, not idealizations.

## 18. Claims supported by the phase

- On the tested host, kernel, socket configuration, and traffic pattern, a separate pure TCP ACK
  before the DNP3 response appears for non-first requests as the application-write delay crosses
  approximately **36–40 ms**, reaching 100% at 40 ms; below ~35 ms responses stay COMBINED.
- The transition is **probabilistic**, not a sharp step.
- The shipped normalization targets (fixed 25 ms, bounded 20–30 ms) keep the native COMBINED ACK
  mode and cause no retransmissions, resets, or byte changes.

## 19. Claims not supported

- No claim that "Linux always uses a 40 ms delayed ACK" — the transition is graded and
  configuration-specific.
- No claim about behavior on the Vision/Hulk rig, physical NICs, other kernels, or the real
  SEL-751 / AB1400 / ION7550 devices.
- No claim about kernel-dependence (single kernel measured) or request-size dependence (not varied).
- No claim that a separate ACK has been independently *synthesized or manipulated* — that is
  Phase 04 and was not attempted.

## 20. Remaining risks

Human packet inspection may disagree with the software classification on a corner case (esp. the
crc-split OTHER rows). Rig/physical behavior is unmeasured. The socket-option factorial gap means
RQ3 is only partially answered.

## 21. Verdict

**CONDITIONAL PASS.** The Phase 03 gate's technical criteria are met — behavior reproduced from
fresh captures, pure ACKs identified by packet fields, transition measured with repeated samples,
environment recorded, no ACK forged, instability (none) reported honestly. The one open condition
is the **human packet-inspection worksheet** (`validation/phase03_human_packet_validation.csv`),
which an AI cannot complete. `next_phase_allowed = false`.

## 22. Prerequisites for the next phase

Before any Phase 04 (independent ACK/response manipulation): (a) a human completes and signs the
packet-validation worksheet; (b) explicit human approval to advance; optionally (c) a rig /
physical capture plus kernel and request-size variation to fully generalize RQ3 beyond loopback.
None of these may be started by the agent without sign-off.

```
STOP: awaiting human review before Phase 04.
```
