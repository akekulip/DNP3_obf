# Phase 01 — ACK / Response Trace Summary (re-derived from raw PCAPs)

_Run `20260716T024101Z_phase_01_real_trace_characterization` — 22988 transactions from the six raw PCAPs. All numbers are re-derived this run; none are carried from prior reports._

Classification per the canonical tshark extractor. Delays in ms; sizes in bytes. `request->pure-ACK` and `pure-ACK->response` are defined only for SEPARATE_ACK_RESPONSE.

| device | capture | txns | combined% | separate% | other% | req->resp med | req->resp p95 | pure-ACK->resp med (sep) | resp bytes med |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AB1400 | L | 1999 | 100.0 | 0.0 | 0.0 | 16.247 | 17.345 | n/a | 37.000 |
| AB1400 | base | 399 | 100.0 | 0.0 | 0.0 | 16.620 | 17.701 | n/a | 37.000 |
| ION7550 | L | 3999 | 99.975 | 0.025 | 0.0 | 15.984 | 16.587 | 28.754 (n=1, single obs) | 37.000 |
| ION7550 | base | 799 | 100.0 | 0.0 | 0.0 | 16.055 | 19.190 | n/a | 37.000 |
| SEL-751 | L | 3999 | 0.0 | 100.0 | 0.0 | 16.104 | 21.055 | 12.178 (n=3999) | 37.000 |
| SEL-751 | base | 299 | 0.0 | 100.0 | 0.0 | 16.985 | 21.545 | 12.898 (n=299) | 37.000 |

> Claim discipline: these describe the **captured traces of these specific devices**, not product families. The pure-ACK->response gap is a wire-visible interval, not the device's exact internal processing time. Host-side capture timestamps are not identical to wire timestamps.

