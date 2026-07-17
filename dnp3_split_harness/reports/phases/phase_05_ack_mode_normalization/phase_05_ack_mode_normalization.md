# Phase 05 — ACK-Mode Normalization (Consolidated Closeout)

**Status: CONDITIONAL PASS** — the ACK-mode channel that egress *timing* scheduling (Phase 04)
could not close is closable, and the **safe, realizable** mechanism (socket-side coalescing on a
server we own) is **wire-demonstrated** byte-preservingly with zero dropped packets. The per-device
**defended-wire** classifier evaluation, the inline-real-device drop path, and response-**size**
normalization are **not** done and are deferred. `next_phase_allowed = false`.

_This report consolidates the two committed Phase 05 sub-reports —
`ack_mode_normalization_feasibility.md` (commit `6a3bbad`) and `coalescing_demo_result.md`
(commit `2a66344`) — into the plan's phase-report template. No new experiment was run for this
closeout; it cites already-committed evidence and a test-suite verification performed this session._

## 1. Phase objective

Determine whether the categorical **ACK-mode** fingerprint (`is_separate` — whether a device emits a
standalone pure TCP ACK before its DNP3 response) can be normalized **without packet synthesis and
without modifying any DNP3 byte**, identify the realizable mechanism, and demonstrate it on the wire.

This reprioritizes the plan's original Phase 05 ("comprehensive attacker evaluation"): that
capture-level, multi-family, leakage-controlled attacker pipeline was **already delivered in Phase
04** (`phase04_attacker_eval.py`, `reports/phases/phase_04/attacker_eval.{md,json}`). Phase 05
therefore targets the strongest *residual* leak Phase 04 exposed — the ACK mode — and reuses that
same pipeline (adding two scenarios) to measure the new mechanism's effectiveness.

## 2. Research questions

1. Can a **no-synthesis** mechanism make a naturally separate-ACK device look combined, safely and
   byte-preservingly?
2. How much of the joint device fingerprint does that actually close, on top of Phase 04's timing
   normalization?
3. What is the realizable enforcement mechanism, given that a user-space app cannot hold a
   kernel-owned pure ACK (Phase 04 finding)?
4. Does the mechanism hold on the **actual wire**, not just as a trace-transformation?

## 3. Scope

gambit loopback, Linux 5.15.0-139-generic, Python 3.8.10. The **effectiveness** result (§14, the
balanced-accuracy table) is a **trace-transformation** applied to the six real device PCAPs — the
harness has one replay server, so it cannot host a 3-device *defended-wire* classifier eval (that
needs a multi-device rig; deferred). The **wire demonstration** (§3-mechanism, §14) is a real
loopback capture. Byte preservation (`b"".join(chunks) == response`) holds throughout. No control
commands, no CRC recompute, no field/length edits, no random padding, no P4, no proxy/MITM.

## 4. Inputs and SHA-256 hashes

Six real device PCAPs (`../Traffic Trace/`), the effectiveness input:

| file | sha256 |
|---|---|
| SEL751.pcap | `519cae47ea3863ea5c08783ee435935aca7a570a31e15e86e72b17681b0e981c` |
| SEL751L.pcap | `be6159026c1b4ffff62b698eb9939cd675fd6ae8ff9f11d42029c6b084ddc2bb` |
| AB1400.pcap | `01dceb19965f42fec16fad2b6bf2a563849d3a052c53831fe6c49d47f2dc86b5` |
| AB1400L.pcap | `7c631744fe5d1f7748e517a05d1571164201a0ee63e216ac91dc3257a60f6e76` |
| ION7550.pcap | `f41681a631ed08ef6458d47d181f46222fd48c3b885e5e7c061cbe1a9ce12d6f` |
| ION7550L.pcap | `69c9dcf9c2ccf012ae5d09817bb860361acb122938892417c09c7825a06dc2b9` |

Wire-demonstration captures (`reports/phases/phase_05_ack_mode_normalization/coalescing_demo/`):

| file | sha256 |
|---|---|
| undefended_separate.pcap | `6f37dea436e7e410603bacf405ca7a77cf7b61c0618fb625be4c85bef583a961` |
| defended_coalesced.pcap | `0aebd68681f9860f2a82c4c40e9c2842313cc5fff95048d43e568b575bffa952` |
| coalescing_demo_summary.json | `364871eccd4bab1e15ebe78be648cfccc9709787f5e79aa341d7b071706eaafb` |

## 5. Repository commit

Branch `research/ack-timing-phased`. Feasibility `6a3bbad` (2026-07-16 19:52 -0400); socket-coalescing
wire demo `2a66344` (2026-07-16 19:58 -0400); this closeout committed on top of `c519788`.

## 6. Environment

Host gambit; Linux 5.15.0-139-generic; Python 3.8.10 (pydnp3-supported interpreter). Effectiveness
classifier: scikit-learn on the system `python3` (`~/.local/lib/python3.8`), not the research venv.
Capture for the wire demo ran under `sg wireshark` (group switch, non-sudo); no BPF, no netns, no
dropped packets. RTO on this setup ≈ 211 ms; safe holds ≤ ~40 ms.

## 7. Agents used and their findings

A 2-expert analysis, lead-integrated and environment-verified:
- **power-systems-expert** — established that *hold-then-decide* (buffer the pure ACK, drop it only
  once the response is seen within a deadline `< RTO`, else release) is the **safe** design: the
  response's cumulative ACK is a strict superset of the pure ACK, a pure ACK is never retransmitted,
  so the only failure path is the master's RTO, which the response beats by ~200 ms.
- **sdn-networks-expert** — established that hold-then-decide is **architecturally impossible as a
  tc-egress drop** (a tc program cannot cancel an skb already queued in `fq`; the pure ACK egresses
  *before* the response), so only an **immediate predictive `TC_ACT_SHOT`** is realizable inline —
  irreversible; and that a conditional **drop is Tofino-native** (`mark_to_drop()`, line-rate), the
  inverse of the Tofino-hostile EDT hold.
- **lead integration** — resolved the two into: the *safe* hold-then-decide behaviour **is**
  realizable, but at the **socket** (coalescing), not the qdisc, wherever we own the responding
  socket (replay/decoy/honeypot).

## 8. Files added, changed, moved, or deprecated

Added: `phase05_coalescing_demo.py`; `reports/phases/phase_05_ack_mode_normalization/`
(`ack_mode_normalization_feasibility.md`, `coalescing_demo_result.md`, `phase_status.json`,
`coalescing_demo/{coalescing_demo_summary.json, undefended_separate.pcap, defended_coalesced.pcap}`);
this `phase_05_ack_mode_normalization.md`. Changed: `ack_fingerprint_eval.py` gained the `suppress`
and `suppress_edt` scenarios (line 147). No runner / server source changed; the wire demo drives the
existing replay server via socket options only. Nothing deprecated.

## 9. Exact commands

```bash
# Effectiveness (trace-transformation; system python3 with scikit-learn):
python3 ack_fingerprint_eval.py          # emits reports/ack_fingerprint_eval.{json,md} incl. suppress / suppress_edt

# Socket-coalescing defended-wire demo (non-sudo, no BPF, no netns):
sg wireshark -c 'python3 phase05_coalescing_demo.py --run-dir runs/20260716T235547Z_phase05_coalescing'

# Test suite:
python3 -m pytest -q
```

## 10. Tests executed

`python3 -m pytest -q` → **61 passed** (verified this session). Wire demo byte-identity: **200/200**
(100/100 per config). Byte-preservation assertion (`b"".join(chunks) == response`) held on every
replayed response.

## 11. Tests skipped and why

No unit tests skipped. The **per-device defended-wire classifier eval** is not executed (deferred):
the single replay server is one "device", so a 3-device classifier on defended captures needs a rig
replaying SEL-751 / AB1400 / ION7550 characteristics. The device-level effectiveness therefore
remains the (now wire-anchored) trace-transformation.

## 12. Raw result locations

- `reports/ack_fingerprint_eval.{json,md}` — effectiveness (native / suppress / suppress_edt / oracle).
- `reports/phases/phase_05_ack_mode_normalization/coalescing_demo/coalescing_demo_summary.json` — wire counts.
- `reports/phases/phase_05_ack_mode_normalization/coalescing_demo/*.pcap` — the two captures.
- `runs/20260716T235547Z_phase05_coalescing/` — run directory of the demo.

## 13. Figures and tables generated

Effectiveness table (§14). Wire before/after table (§14). No new plots produced for this phase; the
clustering/ROC figures from the Phase 04 pipeline (`reports/ack_fingerprint_clusters.png`) remain the
reference for the shared feature space.

## 14. Main findings

**A. Effectiveness — trace-transformation; balanced accuracy; baseline majority-class 0.400 /
uniform 0.333.** `suppress` = drop the pure ACK (ACK-mode normalization); `suppress_edt` = suppress +
the Phase 04 EDT timing normalization; `plus_ackmode` = the counterfactual oracle:

| feature family | native | ebpf_edt (timing only) | **suppress** (mode only) | **suppress_edt** (mode+timing) | oracle |
|---|---:|---:|---:|---:|---:|
| ACK structure | 0.759 | 0.666 | 0.482 | **0.334** | 0.333 |
| timing | 0.482 | 0.334 | 0.482 | **0.334** | 0.333 |
| size | 0.500 | 0.500 | 0.500 | 0.500 | 0.500 |
| all | 0.856 | 0.833 | 0.599 | **0.501** | 0.500 |

- Suppression **closes the ACK-mode channel that timing normalization could not**: `ack_only`
  0.759 → 0.482 (mode only), joint `all` 0.856 → 0.599.
- Suppression **+ timing normalization reaches the counterfactual oracle** (`all` 0.501 ≈ the
  size-only floor 0.500). The two Phase-04/05 primitives together remove the ACK-mode and timing
  channels; the remaining separability is **purely response size** (out of scope — a padding
  primitive that changes the transmitted representation, a separate research line).

**B. Mechanism — the safe design is not an egress drop; it is socket coalescing.** Hold-then-decide
is safe but architecturally impossible as a tc-egress drop (can't cancel a queued skb; the ACK
egresses before the response); the only realizable inline egress drop is an **immediate predictive
`TC_ACT_SHOT`** — irreversible, proactive-fail-open only, with an irreducible slow-transaction
residual. **The safe behaviour is fully realizable as socket-side coalescing where we own the
socket**: leave `TCP_QUICKACK` off and write the response within the kernel's delayed-ACK window
(~40 ms) so the kernel never emits a separate pure ACK and the response piggybacks it — zero
irreversible drops, byte-preserving, no BPF.

**C. Wire demonstration (measured, loopback).** `phase05_coalescing_demo.py`, 20 sessions × 5
requests per config, both replaying the same captured bytes:

| config | request separate-ACK | req→ACK | req→resp | retrans / reset | byte-identical |
|---|---:|---:|---:|---:|---:|
| undefended_separate (`--server-quickack`) | **80/80 (100%)** | 0.24 ms | 5.33 ms | 0 / 0 | 100/100 |
| **defended_coalesced** (no quickack) | **0/80 (0%)** | piggybacked | 5.27 ms | 0 / 0 | 100/100 |

Coalescing flips the request ACK mode **100% → 0% separate on the wire**, byte-preservingly, with
**0 retransmissions/resets**. The 40 residual server pure ACKs in the defended capture are the
post-handshake quickack ACK and the ACK of the master's DNP3 CONFIRM — **not** request-ACKs; the
`is_separate` feature keys on the first reverse packet after the request (now the combined response),
and a CONFIRM-ACK is a standalone pure ACK for a native *combined* device too, so it is not a device
discriminator.

**D. Static TCP headers do not distinguish the devices (measured from the SYNs).** TTL 64, window
29200, MSS 1460, window-scale 7 are **identical** across SEL-751 / AB1400 / ION7550 → p0f-style
static fingerprinting does not separate them; the eval's ACK-mode/timing/size feature space is the
relevant one.

**E. Portability.** The suppression **drop is Tofino-native** (`mark_to_drop()`, line-rate; no
buffering/timer/recirculation) — the inverse of the Tofino-hostile EDT hold, so it is the *more*
portable half of the obfuscation line.

## 15. Failed or ambiguous cases

None in the wire demo (0 retrans/reset, 200/200 byte-identical). The one apparent ambiguity — 40
pure ACKs remaining in the defended capture — is resolved in finding C (handshake + CONFIRM-ACKs,
non-discriminating). The flag-based pure-ACK classifier fragility surfaced in Phase 04 (a `tcp_flags`
mask omitting PSH mis-matches PSH+ACK responses) is noted for any inline implementation: production
discriminator must be `payload_len==0 AND ACK AND !SYN/RST/FIN`, not tc flags.

## 16. Threats to validity

- **Trace-transformation, not defended-wire, for the per-device effectiveness** — the balanced-accuracy
  table transforms native traces; a per-device *defended-wire* classifier eval needs a multi-device rig.
- **The wire demo simulates a separate-ACK device** via `--server-quickack`; it is not a physical
  SEL-751. It proves the *mechanism* (separate→combined, byte-preserving, no drops), not device-level
  anonymity.
- **Loopback / single-kernel**; no two-host rig or physical NIC in this phase.
- **Two residuals the eval does not model:** the piggyback-ACK timing *distribution* shape (SEL-751's
  ~11 ms natural response is *earlier* than a combined device's ~16 ms; normalization must delay *up*
  and match higher moments/tail, not just the mean) and possible **TCP-timestamp clock-skew**
  (Kohno-style; the SYNs carry TSval — unverified whether it separates the devices).
- **RTO ≈ 211 ms is this setup only**; recompute against a real master.

## 17. Measured versus simulated versus projected

- **Measured (wire):** coalescing demo — `is_separate` 100%→0%, 200/200 byte-identical, 0 retrans/reset.
- **Measured (static):** identical TCP SYN headers across the three devices.
- **Simulated (trace-transformation):** the §14-A balanced-accuracy effectiveness numbers (suppress /
  suppress_edt / oracle applied to the real native traces).
- **Projected:** Tofino-native drop portability (analysis, not built); inline-real-device
  `TC_ACT_SHOT` behaviour (analysis, not built).

## 18. Claims supported by the phase

1. Socket-side coalescing normalizes the request ACK mode **separate→combined on the actual wire,
   byte-preservingly, with zero dropped packets** (measured).
2. In the trace-transformation eval, ACK suppression **closes the ACK-mode channel** (`ack_only`
   0.759→0.482) that timing normalization alone could not; suppression **+ timing normalization
   reaches the size-only floor** (`all` 0.856→0.501 ≈ oracle 0.500).
3. The safe hold-then-decide behaviour is realizable at the **socket** (coalescing), not as a
   tc-egress drop; the inline egress drop is limited to an irreversible immediate `TC_ACT_SHOT`.
4. The suppression **drop is Tofino-native** — the portable half of the line.
5. Static TCP-header fingerprinting does not distinguish these three devices.

## 19. Claims not supported

- **Device anonymity is NOT claimed** — response **size** still leaks (`size` 0.500 throughout; joint
  `all` bottoms at 0.500/0.501, not the 0.400/0.333 baseline). Two unmodeled residuals (timing
  distribution shape, clock-skew) remain.
- **No per-device defended-wire classifier result** — the effectiveness table is a transform; the
  wire demo is single-server.
- **No real-device / rig / physical-NIC validation** in this phase.
- **The inline-real-device egress drop is not demonstrated safe** — it is irreversible and only
  proactively fail-open; not implemented.

## 20. Remaining risks

Response **size** is the irreparable residual under byte preservation (separate padding line — do not
combine). For the not-owned-device case, the inline `TC_ACT_SHOT` drop is irreversible (proactive
fail-open only; a usually-prompt-but-occasionally-slow device strands the master for one RTO on the
slow transaction). `bpf_timer` is incompatible with the prototype's legacy `bpf_elf_map` loader → any
inline disarm must be in-band (observe the master retransmit), not timer-based.

## 21. Verdict

**CONDITIONAL PASS.** ACK-mode normalization is **feasible** and the **safe, realizable mechanism —
socket-side coalescing on a server we own — is wire-demonstrated** (request-ACK mode normalized
100%→0%, byte-identical, 0 drops/breakage). The measured effectiveness (trace-transformation) shows
mode + timing normalization reaches the size-only floor. **Conditional because** the per-device
defended-wire classifier eval (rig), the inline-real-device drop path (Tofino/eBPF), and response-size
normalization are deferred, and device-level anonymity is explicitly *not* achieved (size residual).

The plan's Phase 05 gate criteria are satisfied by the reused Phase-04 pipeline: capture-level split,
multiple attacker families (RF/LR + k-means/agglomerative), residual leakage reported (size), correct
chance baselines (0.400 / 0.333), no test-set tuning, and timing/mode improvements explicitly **not**
presented as complete anonymization.

## 22. Prerequisites for the next phase (all GATED — `next_phase_allowed = false`)

1. **Per-device defended-wire classifier eval** — a multi-device rig replaying SEL-751 / AB1400 /
   ION7550 with coalescing active; re-run the classifier on the *defended captures*, not a transform.
2. **Tofino-native drop path** for real-inline devices — hand the TNA table/register spec to
   `p4-dataplane-engineer`; carry the mandatory gating + in-band disarm.
3. **Response-size padding** — the last residual, a separate byte-changing research line; do not
   combine with the ACK-mode line.
4. If the inline-drop path is built, each BPF-load run needs a PI `sudo` invocation
   (`kernel.unprivileged_bpf_disabled=2`; capture stays `sg wireshark`, netem stays `unshare -rn`).

```
STOP: Phase 05 consolidated (CONDITIONAL PASS). ACK-mode normalization is feasible and the socket-coalescing path is wire-demonstrated; the per-device defended-wire eval, the Tofino drop path, and size padding are the recommended next lines — awaiting human authorization before Phase 06.
```
