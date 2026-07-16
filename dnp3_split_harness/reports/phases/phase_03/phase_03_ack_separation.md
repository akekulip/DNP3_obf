# Phase 03A — Socket-Level ACK-Separation Characterization

**Status: PASS** (2026-07-16). All technical gate criteria are met **and** the human
packet-inspection gate is complete: the PI (Philip Akekudaga) personally inspected all 13 worksheet
rows and confirmed agreement with the software on both `ack_mode` and `response_delivery` (13/13, 0
disagreements). `next_phase_allowed = false` — Phase 04 still requires explicit PI authorization.
Capture was unblocked (`philip` added to the `wireshark` group; all captures ran under
`sg wireshark`, **not** sudo). No wire data is fabricated; every number below derives from PCAPs
produced this session and re-derived by the analyzer.

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
  at a time, this host/kernel): **no response-size effect was observed at the tested 25 ms and
  50 ms anchor delays across response sizes from 17 to 2407 B** (a 140× range; 0% separate at
  25 ms, 100% at 50 ms for every size); **TCP_NODELAY has no effect** (identical to baseline at
  both anchors — Nagle governs the sender's coalescing, not the receiver's ACK); **TCP_QUICKACK
  forces separation** — server-side quickack flips COMBINED→SEPARATE even at 25 ms (0→100%),
  showing the separate ACK is a delayed-ACK phenomenon whose *appearance* is controllable from user
  space (QUICKACK forces a prompt/separate ACK; it does **not** delay an existing ACK — see §22).
  **Not varied:** kernel (single host) and request size (all replay requests are small READs) — see §16.
- **RQ4 — Is separation stable across repetitions?** Yes. At each coarse endpoint the outcome is
  uniform (0/80 for ≤35 ms, 80/80 for ≥40 ms across 20 replay sessions × 4 non-first groups); the
  graded region is monotonic and reproduced at the 35 ms and 40 ms anchors across two independent
  runs.
- **RQ5 — Does forcing separation cause retransmissions or DNP3 failure?** **No.** Across all
  2875 captured transactions: **0 retransmissions, 0 duplicate ACKs, 0 resets**, and **100%
  byte-identical** responses. **Every replay-client exchange completed and the received response
  bytes were identical.** (This phase's master is the replay client, not an OpenDNP3 master; the
  stronger DNP3-application-task-completion claim is Phase 02's pydnp3 integration result, not
  claimed here.)

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

Tooling committed at `c13453c` (`--delays-ms` refinement flag) and `70de5ed` (socket-option
controls + `--mode socket`); parent `04f02fe` for the capture runner. Characterization results
committed at **`5d4a6e7`**; RQ3 socket-option results at **`589257a0d47d7d039a026786128bbfbb12bfa8bd`**
(`git commit --amend` is guard-blocked, so these SHAs are recorded here in follow-up commits).

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
each TCP connection carries a prompt pure ACK independent of the delay — behavior consistent with a
post-handshake quick-ACK state in the tested TCP stack — so the timing-relevant metric is computed
over **non-first** requests only.

## 8. Files added, changed, moved, or deprecated

- **Changed:** `phase03_capture.py` — additive `--delays-ms` override (sweep only) and a `--mode
  socket` socket-option factorial; default coarse list and the Phase 02 scheduler unchanged.
- **Changed:** `split_server.py` — additive `--server-nodelay {on,off}` and `--server-quickack`
  (Linux TCP_QUICKACK, re-armed per request). Socket-setup only; defaults preserve shipped
  behavior (NODELAY on, no forced quickack); the timing/scheduler path is untouched.
- **Changed (per review):** `phase01_reconstruct.py` — additive `ack_mode` (COMBINED / SEPARATE /
  UNDETERMINED), `response_delivery` (FULL / MULTI_SEGMENT / AMBIGUOUS), and
  `first_payload_frame` / `final_payload_frame` / `payload_segment_count` fields, so a multi-segment
  response no longer makes the ACK mode unknowable and the worksheet can point at the true first
  payload segment. The legacy `classification` field is unchanged (Phase 01 preserved).
  `phase03_analyze.py` reports the decomposition.
- **Regenerated (per review):** `validation/phase03_human_packet_validation.csv` with orthogonal
  columns (`software_ack_mode` + `software_response_delivery` + `reviewer_ack_mode` +
  `reviewer_response_delivery` + `ack_mode_agreement` + `delivery_agreement` +
  `first_payload_frame`); the crc-split row is now COMBINED_ACK_RESPONSE / MULTI_SEGMENT with
  `first_payload_frame = 15` (the earlier `resp_frame = 39` was a later segment, not the first
  payload). `PHASE_03A_RESUME.md` marked **HISTORICAL — SUPERSEDED**.
- **Added:** `phase03_figures.py` (8 figures + metadata sidecars);
  `tests/test_phase03_ack_decomposition.py` (5 tests for the ack_mode/delivery decomposition).
- **Added (committed results):** `reports/phases/phase_03/tables/*` (matrix + coarse + refined +
  **socket** summaries, transactions, manifests, merged `phase03_delay_sweep.csv`,
  `phase03_socket_option_summary.csv`, `phase03_environment_dependence.csv`,
  `phase03_crc_split_decomposition.csv`, capture environment);
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

`python3 -m pytest tests/` → **61 passed** (includes the Phase 01 Wilson-CI and extractor tests
that back the classification pipeline plus 5 new `test_phase03_ack_decomposition` tests for the
ack_mode/response_delivery split; the socket-option edits to `split_server.py` preserve the
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
(`reports/phases/phase_03/tables/`): matrix/coarse/refined/socket ACK summaries and transactions
(with `ack_mode` / `response_delivery` columns), `phase03_crc_split_decomposition.csv`,
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
   prompt pure ACK (≈ 25 per matrix config, ≈ 20 per sweep config), independent of the delay —
   behavior consistent with a post-handshake quick-ACK state in the tested TCP stack, correctly
   excluded from the timing-relevant metric.
5. **crc-split, decomposed (per review).** ACK mode and response segmentation are now reported as
   two orthogonal properties, so a multi-segment response no longer makes the ACK mode unknowable.
   For all three crc-split configs, non-first **ack_mode = COMBINED (0/100 separate)** while
   **response_delivery = FULL for 50 and MULTI_SEGMENT for 50** per config — the 50 transactions
   the legacy single-label scheme put in OTHER are resolved as COMBINED + MULTI_SEGMENT. crc-split
   introduces no separate ACK (`tables/phase03_crc_split_decomposition.csv`).
6. **No instability.** 0 retransmissions / duplicate ACKs / resets and 100% byte-identity across
   every config and delay (2875 characterization txns + 600 socket txns).
7. **Socket-option factorial (RQ3).** TCP_NODELAY (Nagle) has **no effect** on separation
   (identical to baseline: 0/80 at 25 ms, 80/80 at 50 ms). **TCP_QUICKACK forces separation** — with
   server-side quickack, non-first requests separate **80/80 even at 25 ms** (baseline 0/80), so
   whether a separate ACK *appears* is controllable from user space (QUICKACK forces a prompt ACK; it
   does not hold/delay an existing ACK — §22). No response-size effect was observed at the tested
   25 ms and 50 ms anchor delays across 17–2407 B.

## 15. Failed or ambiguous cases

The legacy single-label classifier put ~50% of non-first crc-split transactions in
OTHER_OR_AMBIGUOUS because the first response chunk is a payload segment tshark does not tag as
DNP3. The refined ack_mode / response_delivery decomposition (finding 5) resolves these as
COMBINED + MULTI_SEGMENT; the crc-split row in the human-validation worksheet lets a reviewer
confirm the ACK-mode call on a multi-segment response. No retransmissions, resets, or missing
responses occurred in any config.

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

Human packet inspection may disagree with the software classification on a corner case. The former
crc-split OTHER rows are now decomposed into ack_mode + response_delivery and are the reason a
crc-split row was added to the worksheet for confirmation. Rig/physical behavior and kernel /
request-size variation remain unmeasured, so RQ3 generalization beyond loopback is still open.

## 21. Verdict

**PASS** (2026-07-16). The gate's technical criteria are met, the three PI-required changes are
addressed (crc-split `ack_mode`/`response_delivery` decomposition; three wording corrections;
verdicts recorded per true provenance), **and the human packet-inspection gate is complete**: the
PI (Philip Akekudaga) personally inspected all 13 worksheet rows and confirmed agreement with the
software on both properties (**13/13, 0 disagreements**, `method: manual packet inspection`). The
earlier AI-assisted cross-check remains recorded as supplementary only
(`validation/phase03_ai_assisted_packet_analysis_2026-07-16.md`, `human_gate_credit: false`) and did
not stand in for the human gate. `next_phase_allowed = false` — Phase 04 begins only on explicit PI
authorization of the mechanism-feasibility study.

## 22. Prerequisites for the next phase

Before any Phase 04: (a) a human personally inspects and signs **all 13 worksheet rows** (currently
**0 of 13**; the AI-assisted assessment does not count); (b) explicit human approval to advance;
optionally (c) a rig / physical capture plus kernel and request-size variation to fully generalize
RQ3 beyond loopback. Per the PI, Phase 04 begins with a **mechanism-feasibility analysis for
delaying the existing ACK and response packets** — not implementation.

**TCP_QUICKACK capability boundary (feasibility input, not a delay mechanism).** The RQ3 result
must not be overstated: QUICKACK influences the stack to emit a pure ACK promptly; it does **not**
let user space hold an already-generated ACK for later release.

| Capability | QUICKACK provides it? |
|---|---|
| Force a separate pure ACK | Yes (tested setup) |
| Emit the ACK promptly | Yes |
| Delay the application *response* | Yes (application scheduling) |
| Delay an *existing* pure ACK | **No** |
| Independently schedule ACK and response | **No** (not by itself) |

Delaying an existing ACK requires a packet-control mechanism — Linux `tc`/eBPF, an inline bridge,
DPDK / user-space TCP, a programmable NIC, P4/Tofino, or kernel modification. The Phase 04
feasibility analysis must distinguish these two capabilities. None of the above may be started by
the agent without sign-off.

```
STOP: awaiting human review before Phase 04.
```
