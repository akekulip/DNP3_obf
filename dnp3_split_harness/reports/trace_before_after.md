# Before / After of the ACK-Delay Timing Manipulation on the Real Device Traces

_Anchored to the six real-device PCAPs in `Traffic Trace/`. **Before** = the native per-transaction timing measured in `reports/ack_trace_characterization.csv`; **after** = each of those same transactions pushed through the shipped `timing_policy` module — the exact scheduler / ACK-response planner the replay server runs. No bytes are edited and no packet is forged; only release times are recomputed._

Phase-1 config: fixed **25 ms**, bounded **[20.0, 30.0] ms** (seed 12345), RTO-safe **105 ms**. Phase-2 config: response-delay **+8 ms**, ack-delay **+8 ms**, gap-target **20 ms**.

## Combined-ACK devices — request→response normalization (Phase 1)

These devices piggyback the ACK on the response (no separate ACK to delay natively), so the manipulable observable is request→response time. Native ~16 ms is device-distinguishing in its tail; normalization pins it to a class-independent target.

| device | txns | native med | native p95 | native max | native CV | after (fixed) med/p95/max | after (bounded) med/p95/max | after CV |
|---|---:|---:|---:|---:|---:|---|---|---:|
| AB1400 | 2398 | 16.32 | 17.45 | 95.29 | 0.1177 | 25.00 / 25.00 / 95.29 | 24.95 / 29.49 / 95.29 | 0.1312 |
| ION7550 | 4798 | 15.99 | 16.76 | 97.99 | 0.1077 | 25.00 / 25.00 / 97.99 | 25.03 / 29.44 / 97.99 | 0.1254 |

## Separate-ACK device (SEL-751) — observer-visible ACK→response gap (Phase 2)

The SEL-751 really emits a **pure TCP ACK before** the DNP3 response, so an attacker reads device processing time as the ACK→response gap. The Phase-2 planner reschedules the two existing packets (it never forges an ACK). `response-delay-only` grows the gap, `ack-delay-only` shrinks it, `gap-normalized` pins it to a bounded target.

**SEL751** (4298 transactions). Native ACK→response gap: median **12.21 ms**, p95 17.15, max 165.98, CV 0.5006.

| mode | gap median | gap p95 | gap max | gap CV | Δ median vs native |
|---|---:|---:|---:|---:|---:|
| native (before) | 12.21 | 17.15 | 165.98 | 0.5006 | 0.00 |
| response-delay-only | 20.21 | 25.15 | 173.98 | 0.3139 | +8.00 |
| ack-delay-only | 4.21 | 9.15 | 157.98 | 1.2344 | -8.00 |
| gap-normalized | 20.00 | 20.00 | 20.00 | 0.0000 | +7.79 |

## Reading

- **Combined devices:** native request→response carries a device-specific tail (p95/max differ per device); after normalization every held transaction leaves at the same target, so the request→response CV collapses toward the target's own tiny spread — the timing channel is closed on the held path. The response **size** channel (37 vs 54 vs 61 B) is untouched by timing and still distinguishes devices (see `attacker_eval.md`).

- **SEL-751:** the native ~13 ms ACK→response gap is the cross-layer processing-time fingerprint. `response-delay-only` and `ack-delay-only` move the observer-visible gap in opposite directions without changing the true device processing time; `gap-normalized` replaces the device's native gap distribution with a bounded target, erasing the per-device gap signature. This is the literal ACK-delay manipulation applied to the real trace.

- **Honest scope:** this is a projection of the shipped policy onto measured native times (a distributional before/after), not a fresh live capture of a defended SEL-751. Live two-host validation of the mechanism/safety is in `reports/rig_timing_matrix_results.md` and `reports/ack_separation_rig_results.md`.

