# Advisor Brief — Split / Pad / Timing Combined Policy

_A concise meeting brief for Dr. Lin. Nine-agent evidence study, 2026-07-13. Research/design only._

## When do we split?
Only large **read-plane** responses, on CRC-block boundaries (auditability), at a **varied/decoy-
matched** (not fixed) granularity, **paced** (so it survives the wire), and **always paired with timing
normalization**. Not small control responses (few chunks, no size benefit). Split reshapes
segmentation but **never hides total bytes** — do not claim it does.

## When do we pad?
Not now — **there is no safe byte-preserving DNP3 padding** (measured + parser-level negative result:
invalid filler rejected, valid filler becomes real data/control, no length field/NUL object). Padding
that closes the size leak is a **future** phase: encrypted tunnel (safest, ~+590% bw per control
response) > gateway inert read points > decoy reads. Never pad a live control.

## When do we hide timing?
Whenever timing depends on the secret and the observer repeats the poll (the SCADA case) — via
**class-independent normalization** (not averageable, unlike jitter). Bypass on critical/urgent
traffic, insufficient budget, uncertain RTO margin, or ordering risk. Fail open.

## What can be built now?
- **Software policy engine** in the replay/split server: split-only / timing-only / split+timing,
  target profiles, per-flow FIFO, measured-RTO budgets, immediate-release fallback, residual-size-leak
  telemetry. Zero hardware, rig-validatable.
- **Tofino Stage 1–2** (classify + chunk pacing/gap normalization), in-phase.

## What requires a future phase?
Any **padding** / size-hiding (tunnel or endpoint fixed-size responses); **Tofino first-response
absolute delay** (unbuilt recirc-hold; Tofino also cannot *create* the split, only pace it); cover
traffic / silence hiding; a **≥2-device** classification study.

## The three strongest experiments
1. **Replicate the dual leak** (E1/E1′): ≥30 reps per N for both size and timing, bootstrap CIs — a
   precondition for every claim (current sweeps are n=1 per N).
2. **The database-size (Class-0 read-plane) experiment**: response time & size vs static point count —
   the channel the study is named for, currently unmeasured, and the safe-to-shape one.
3. **One defended split+timing rig run**: byte-preservation, 0 retransmits/resets, DNP3 CONFIRM,
   800-measurement count, timing-channel β/MI closure, and the sum-the-chunks + detect-the-defense
   attackers evaluated. (Precondition: measure the effective RTO on Vision and Hulk.)

## Directly supported vs still hypothesis
| Supported (measured/standard) | Hypothesis / to test |
|---|---|
| CROB count leaks on size (R²=0.9999) AND timing (R²≈0.99) | Both replicated with CIs (n=1/N now) |
| No byte-preserving DNP3 padding (parser-level) | Inert decoy points indistinguishable from real |
| Split preserves total bytes; relocates to packet count | Size/complexity-decorrelation beats jitter at lower latency |
| RTO-binding; split needs pacing; three-inequality budget | Effective RTO values on Vision/Hulk |
| Tofino S1–2 buildable; can't create split | Tofino recirc-hold absolute delay (unbuilt) |
| Normalization beats jitter vs repeated-poll observer | Device classification (needs ≥2 stacks) |

## Five decisions requiring your approval
1. **Framing.** Publish the honest asymmetry — *timing closeable now, size a future-phase residual,
   padding a negative result* — with the contribution being the **decision policy + the two negative
   results**? (Recommended.)
2. **Phase rule / tunnel.** Authorize scoping a **future encrypted-tunnel padding** line (the only
   clean size fix), or stay strictly in-band byte-preserving? Tunnel changes the threat model (payload
   hidden) and needs endpoint cooperation.
3. **Scope of claims.** Restrict to the single-device information-theoretic result (config/complexity)
   and defer any device-identity/classification claim to a ≥2-stack follow-on?
4. **Second device / real relay.** Can a second DNP3 stack or the SEL relay/RTAC be obtained? Gates the
   classification claim and a cross-device beacon/anonymity-set result.
5. **Target venue** (drives adaptation): TDSC / TSG / ToN, a systems venue (NDSS/CCS/NSDI) for the
   in-network angle, or a workshop for the negative result first?
