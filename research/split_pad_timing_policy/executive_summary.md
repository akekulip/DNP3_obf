# Executive Summary — When and How to Split, Pad, and Normalize Timing

_For Philip and Dr. Lin. Synthesis of a nine-agent evidence study (2026-07-13) on combining the three
DNP3 obfuscation mechanisms — split, pad, timing normalization — for a passive on-path observer.
Research/design only; no source code changed; byte-preserving phase. Full deliverables in
`research/split_pad_timing_policy/`; builds on `research/ack_timing_normalization/`._

## The one finding that organizes everything
The secret an attacker wants — the **CROB count / request complexity** of a transaction — leaks on
**two independent channels at once**, both measured on the rig this session:
- **Size:** response size = **14.6 B/CROB, R²=0.9999** (37→256 B over N=1→16). *One sample per
  N-level, one device — a clean 10-point line, not yet a replicated law.*
- **Timing:** response processing time ≈ **0.18–0.21 ms/CROB, R²≈0.99** (same n=1-per-N caveat).

This dual leak forces the whole policy, because the three mechanisms have very different reach:
- **Timing normalization** (release on a class-independent schedule) **closes the timing channel** and,
  unlike random jitter, cannot be averaged away by a repeated-poll observer. **Available now.**
- **Splitting** reshapes segmentation but **preserves total bytes** — it does *not* close the size
  channel; worse, at fine granularity the chunk count itself scales with size (relocating the leak to
  packet count), and a lone split flow is a detectable beacon.
- **Padding** is the only thing that could close the size channel — but **no byte-preserving DNP3
  padding exists** (a measured and parser-level-confirmed negative result: invalid filler is rejected,
  valid filler becomes real data/control, and DNP3 has no length field or NUL object). Closing size
  needs a **future** encrypted-tunnel or endpoint-fixed-size phase, at ~+590% bandwidth per control
  response.

**So the honest headline is an asymmetry: timing is closeable today; size is a residual for a future
phase.** That, plus the padding negative result, is the study's strongest contribution — not a claim
to have hidden everything.

## What each mechanism accomplishes, when it's required, when it's unsafe
- **Split** — *what:* re-divide a response at safe boundaries (arbitrary offset works; CRC-block
  alignment is our auditability choice, not a master requirement). *Required:* on large read-plane
  responses, to defeat per-packet-size/segmentation classifiers. *Unsafe/useless:* on small control
  responses (few chunks, no size benefit); at fixed granularity (self-fingerprinting); without pacing
  (re-merges on the wire); ever presented as hiding total size.
- **Pad** — *what:* add apparent size/volume. *Required:* to close the size leak. *Unsafe:* in every
  in-band form now (rejected, or corrupts data/controls). *Future:* tunnel/envelope padding (safest),
  gateway inert read points, decoy reads — never padding a live control.
- **Timing normalization** — *what:* release on a class-independent schedule. *Required:* whenever
  timing depends on the secret and an observer repeats the poll (the SCADA case). *Unsafe/bypass:* on
  critical/urgent traffic, insufficient deadline budget, uncertain RTO margin, or ordering risk.

## How they compose
`classify → (bypass if critical/uncertain) → choose public target profile → split large responses
(paced) → pad if a safe mechanism exists else record residual size leak → release on a class-
independent timing schedule under the measured-RTO deadline, FIFO-preserved, fail-open.` The dominant
strategy is **shape the read plane aggressively (split + timing), bypass the control plane by
default** — because control traffic is simultaneously the lowest-privacy-value (few samples) and
highest-safety-cost class, while the read plane is the high-value, low-risk one. Binding constraint
throughout: the master's **effective TCP RTO** (measure it — Vision for holds, Hulk for splits), not
any DNP3 timer.

## Recommended implementation path
1. **Software first** (the replay/split server generates its bytes → schedules `send()` directly; no
   kernel/eBPF/DPDK needed): an application-layer, per-flow-FIFO, monotonic-deadline policy engine with
   split-only / timing-only / split+timing modes, target profiles, strict measured-RTO budgets,
   immediate-release fallback, reproducible seeds, and residual-size-leak telemetry.
2. **Tofino** Stage 1–2 (classify + chunk pacing/gap normalization) is buildable in-phase; it can
   *pace* split chunks but cannot *create* the split. First-response absolute delay is an unbuilt
   recirc-hold — future, not a result.
3. **BlueField DPU / FPGA** are the native homes for absolute-delay timed release (Accurate Send
   Scheduling / calendar queue) and the eventual home for tunnel padding.

## Main novelty and main limitation
**Novelty:** the dual-channel measurement, the parser-level padding negative result, the
split-relocates-not-removes result, and a criticality-aware conditional split/pad/timing decision
policy. **Limitation:** the flagship leaks are single-device, n=1 per N-level (replication is the first
owed experiment); the size residual has no current-phase defense; and the whole positive story is
timing-only against a repeated-poll observer.

## For Dr. Lin
The five decisions and the three strongest experiments are in `advisor_brief.md`; the staged plan is in
`implementation_roadmap.md`. The one-line ask: **is the "timing closeable now, size a future-phase
residual, padding a negative result" framing the right story to publish?** We believe it is — it is
honest, measured, and it makes the paper's contribution the *decision policy* and the *negative
results*, which survive review, rather than an over-claim that would not.
