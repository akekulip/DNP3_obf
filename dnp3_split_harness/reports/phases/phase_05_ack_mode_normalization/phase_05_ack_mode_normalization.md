# Phase 05 — ACK-Mode Normalization (Authoritative Closeout)

**Status: PASS (with scoped limitations).** `next_phase_allowed = false` (advancing requires explicit
human authorization; it does not mean Phase 05 is incomplete).

_Authoritative evidence commit: `96b588b2f3a910601cc886d9868b65cfbd2461cf` (branch
`research/ack-timing-phased`) — code, tests, regenerated results, and this closeout. This provenance
stamp is recorded in a forward metadata commit (a commit cannot contain its own SHA)._

This supersedes all earlier Phase 05 prose. Where earlier drafts described the per-device
defended-wire evaluation or the two-host rig evaluation as pending, those evaluations are **complete**
and are reported below; the only remaining device-level gap is validation against the three
**physical** target devices, which are not on this rig (a deferred external-validation item, not a
Phase 05 blocker).

## 1. Objective

Demonstrate that **socket-side coalescing** normalizes the request ACK mode from
`SEPARATE_ACK_RESPONSE` to `COMBINED_ACK_RESPONSE` where the responding socket is controlled —
**without modifying DNP3 response bytes, dropping packets, or destabilizing TCP** — and evaluate the
effect on device-profile classification using **defended wire captures**.

## 2. Scoped definition of completion

Phase 05 is complete when: coalescing is confirmed on the wire; the categorical request ACK mode is
normalized; response bytes are preserved at the correct logical-response scope; the per-profile
loopback defended-wire evaluation and the two-host Vision–Hulk defended-wire replay evaluation are
done; classifier splitting is leakage-safe; feature families are named correctly; transport health is
clean; provenance is complete; and tests pass. The following are **not** Phase 05 completion
requirements and are treated as deferred external validation / a separate deployment mechanism / a
separate byte-changing line: physical target-device testing, inline `TC_ACT_SHOT` suppression for
uncontrolled sockets, Tofino implementation, and response-size padding.

## 3. Mechanism

Where the harness owns the responding socket (replay / decoy / honeypot), the combined-mode look is
obtained with **zero irreversible drops** by socket-side coalescing: leave `TCP_QUICKACK` off and
write the DNP3 response within the kernel's delayed-ACK window (~40 ms) so the kernel never emits a
separate pure ACK and the response naturally piggybacks it. No packet is removed, no DNP3 byte is
changed, no BPF is required. (The inline `TC_ACT_SHOT` drop route — for sockets we do **not** control
— is a separate, unbuilt deployment mechanism, deferred; see the feasibility report.)

## 4. Loopback wire evidence (single-server demo)

`phase05_coalescing_demo.py` (run `20260716T235547Z_phase05_coalescing`) on the actual loopback wire:
forcing `TCP_QUICKACK` produces a standalone pure ACK (separate mode); with coalescing the same
captured bytes reply combined. Non-first requests: undefended **80/80 separate → defended 0/80
separate**; **200/200 byte-identical; 0 retransmissions / 0 resets**. The residual pure ACKs in the
defended capture are handshake and CONFIRM-ACKs (non-discriminating; `is_separate` keys on the
request-ACK, which is normalized). Evidence: `coalescing_demo/`.

## 5. Loopback per-profile attacker evaluation

`phase05_defended_wire_eval.py` (run `20260717T165759Z_phase05_defended_wire2`) replays each device
profile's real request/response bytes through the coalescing server, captures on `lo`, re-characterizes,
and classifies the **defended captures** (Random Forest, capture-level split train base / test L,
chance 0.333, 119 test transactions per profile). Wire: SEL-derived separate fraction **1.00 → 0.00**;
**720/720 byte-identical per condition (2160/2160)**; **0 retransmissions / resets / duplicate ACKs**.

| feature family | native | coalesced | coalesced_edt |
|---|---:|---:|---:|
| mode_only | 0.667 | **0.333 (constant / non-discriminating)** | 0.333 (constant) |
| ack_combined | 0.709 | 0.490 | 0.233 |
| timing | 0.448 | 0.490 | 0.233 |
| size | 0.667 | 0.667 | 0.667 |
| all | 1.000 | 0.759 | 0.322 (see note) |

Note: the `coalesced_edt` (+ response-timing normalization) joint value is **unstable on loopback**
(loopback timing-normalization jitter differs between the base and L captures, so the normalized
timing features mislead across the capture-level split). The categorical `mode_only` (0.667 → 0.333)
and `size` (0.667) results are stable; the **two-host rig (Section 6) is the authoritative joint
measurement**.

## 6. Vision–Hulk wire evidence (two-host defended-wire replay)

**Two-host defended-wire replay evaluation on Vision and Hulk using profiles derived from captured
SEL-751, AB1400, and ION7550 traffic** (`phase05_rig_defended_wire.py` + `phase05_rig_replay.py`, run
`20260717T162006Z_phase05_rig_defended_wire`). Hulk (outstation side) replays each profile's real bytes
and reproduces its ACK mode over the real switched 1 G management path; Vision (master side) drives the
client; Hulk captures on `eno1` (non-sudo, wireshark group). One capture holds all 18 sessions as
distinct TCP streams. Wire: client **2160/2160 byte-identical**; SEL-derived separate fraction
**1.00 → 0.00**; **18/18 streams mapped**; **0 retransmissions / 0 resets / 0 duplicate ACKs** across
714 non-first transactions per condition, on real server NICs.

| feature family | native | coalesced | coalesced_edt |
|---|---:|---:|---:|
| mode_only | 0.667 | **0.333 (constant / non-discriminating)** | 0.333 (constant) |
| ack_timing | 0.751 | 0.524 | 0.317 |
| ack_combined | 0.751 | 0.524 | 0.317 |
| timing | 0.501 | 0.524 | 0.317 |
| size | 0.667 | 0.667 | 0.667 |
| **all** | **1.000** | **0.756** | **0.681** |

All-features confusion (rows = true, cols = predicted; 119 test txns each):

```
[native]           AB1400  ION7550   SEL751      [coalesced]        AB1400  ION7550   SEL751
  AB1400              119        0        0         AB1400               67        0       52
 ION7550                0      119        0        ION7550                0      119        0
  SEL751                0        0      119         SEL751               35        0       84
```

Coalescing removes SEL-751's separate-ACK tell, collapsing **SEL-751 ↔ AB1400** into mutual
confusion; **ION7550 stays 119/119, identified by response size**. This uses real server-grade NICs
and a switched two-host path; it reproduces device-derived traffic profiles rather than using the
three physical target devices.

## 7. Trace-transformation supporting evaluation

`ack_fingerprint_eval.py` transforms the native traces in software (not defended-wire; n = 11494,
imbalanced classes, chance 0.400). It is **supporting** context: native `mode_only` 0.800 /
`ack_combined` 0.810 / `all` 0.888; the `plus_ackmode` oracle (hide the ACK mode) collapses
`mode_only` and `ack_combined` to 0.400 and `all` to 0.500 (size still leaks). It agrees with the
wire evaluations that hiding the ACK mode closes the categorical channel and leaves size.

## 8. Feature-family decomposition

The family formerly called `ack_only` was **not** ACK-mode-only — it mixed the categorical packet
structure (`is_separate`) with ACK timing (`req_to_ack_ms`, `ack_to_resp_ms`). It is renamed
`ack_combined` and decomposed:

- `mode_only` = `is_separate` (the categorical request-ACK-mode feature alone);
- `ack_timing` = `req_to_ack_ms`, `ack_to_resp_ms` (ACK-derived timing only);
- `ack_combined` = `is_separate` + ACK timing (the former `ack_only`);
- `timing` = `req_to_resp_ms`; `size` = `req_size`, `resp_size`; `all` = the union.

After successful coalescing `is_separate == 0` for every profile, so `mode_only` is a **zero-variance
constant feature**; the classifier is reported as **non-discriminating (majority-class baseline
0.333)**, not as having learned a distinction (`constant_non_discriminating: true`, with the training
variance recorded). Balanced accuracy equals raw accuracy because the test classes are balanced (119
each). Every result records accuracy, balanced accuracy, macro-F1, confusion, per-family training
variance, the split, seed (0), and RF/LR parameters.

## 9. Full-response reconstruction audit

Because response size is the dominant remaining feature, the response-byte scope was audited
(`response_reconstruction_audit.csv`, 720 rows; producing function
`phase05_defended_wire_eval.response_segmentation_audit`):

| pcap | txns | multi-segment responses | first-segment == full | source hash == replay hash | response length (B) |
|---|---:|---:|---:|---:|---|
| SEL751 | 120 | 0 | 120 | 120 | 37–54 |
| SEL751L | 120 | 0 | 120 | 120 | 54 |
| AB1400 | 120 | 0 | 120 | 120 | 54 |
| AB1400L | 120 | 0 | 120 | 120 | 54 |
| ION7550 | 120 | 0 | 120 | 120 | 61 |
| ION7550L | 120 | 0 | 120 | 120 | 61 |
| **total** | **720** | **0** | **720** | **720** | — |

**Every selected response is a single TCP payload segment**, so the replayed first-segment bytes are
the complete logical DNP3 response; the full-response-byte and response-size claims are therefore
valid. The extractor nonetheless reconstructs the complete logical response across segments in the
general case — de-duplicating retransmitted segments by TCP sequence, ordering by sequence, stopping
at the transaction boundary — and this path is unit-tested (`test_response_reconstruction.py`).
ION7550 responses are 61 B (distinct); SEL-751 and AB1400 are 54 B (shared) — the mechanistic reason
ION7550 stays size-identifiable while SEL-751 and AB1400 collapse.

## 10. Safety and transport health

Across every authoritative condition and environment: **byte identity 2160/2160** (loopback) and
**2160/2160** (rig); **0 retransmissions, 0 duplicate ACKs, 0 resets within established replay
sessions** (any pre-connection readiness-probe SYN/RST traffic is excluded); the SEL-derived separate
fraction moves 1.00 → 0.00 with no packet loss; no bypasses or failures. Response bytes are never
modified.

## 11. Supported claims

- Socket-side coalescing normalizes the request ACK mode SEPARATE → COMBINED on the wire where the
  socket is controlled — demonstrated on loopback (single-server and per-profile) and on the real
  two-host Vision–Hulk path; byte-preserving, no dropped packets.
- Response bytes are preserved at the correct logical-response scope (720/720 single-segment; source
  hash == replay hash).
- The categorical ACK-mode feature (`mode_only`) is removed by coalescing (0.667 native → 0.333
  constant/non-discriminating), on both loopback and rig.
- Response size is the **dominant stable residual** in the evaluated feature set (ION7550 61 B stays
  identifiable; SEL-751 ↔ AB1400 collapse); full device anonymity is not achieved.
- Transport health is clean on loopback and on real two-host NICs.

## 12. Unsupported claims

- Full device anonymity — response size still separates ION7550.
- That response size is the **only** possible residual — TCP-timestamp clock-skew and higher-order
  timing-distribution features were not exhaustively ruled out (static TCP headers TTL/window/MSS/wscale
  were checked identical across the three profiles).
- A physical target-device result — all evaluations reproduce device-derived profiles; Hulk is not a
  physical SEL-751 / AB1400 / ION7550.
- Safety of inline suppression for sockets we do not control.

## 13. Threats to validity

- The loopback and Vision–Hulk evaluations reproduce **device-derived traffic profiles** rather than
  using the three physical target devices. The Vision–Hulk experiment used real server NICs and a
  switched two-host path; it is not a capture of the physical devices. The native `all` = 1.000
  reflects low-noise reproduction; a physical multi-device network would be noisier.
- `coalesced_edt` joint accuracy is unstable on loopback (timing-normalization jitter across the
  capture-level split); the rig is the authoritative joint measurement.
- Clock-skew and higher-order timing distributions were not evaluated; size is described as the
  dominant *stable* residual in the *evaluated feature set*, not the only theoretically possible one.

## 14. Deferred external validation (not Phase 05 blockers)

- Physical SEL-751 / AB1400 / ION7550 validation (external hardware, not on this rig).
- Inline predictive ACK suppression for uncontrolled sockets (separate deployment mechanism).
- Tofino implementation.
- Response-size padding (separate byte-changing research line).
- TCP-timestamp clock-skew analysis and broader timing-distribution matching.

## 15. Final verdict

**PASS (with scoped limitations).** Socket-side coalescing is confirmed on the wire; the categorical
request ACK mode is normalized; response bytes are preserved at the verified single-segment
logical-response scope; the loopback per-profile and two-host Vision–Hulk defended-wire evaluations
are complete with leakage-safe splitting, correctly named feature families, clean transport health,
and complete provenance. Response size is the dominant stable residual; full anonymity and the
physical-device validation are out-of-scope / deferred, not Phase 05 blockers.

```
STOP: Phase 05 is closed (PASS with scoped limitations). Awaiting explicit human authorization before beginning the next phase.
```
