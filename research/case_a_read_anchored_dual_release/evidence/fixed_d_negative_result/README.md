# Fixed-D ACK delay — negative analytical baseline

**Authoritative copy: `research/case_a_fixed_ack_delay/`** (on `main`; study, three reproducible
gate scripts under `analysis/`, raw outputs under `evidence/`). Referenced here rather than
duplicated so there is one copy and the `main`-side references stay valid.

## What the result actually is — state it this way, not as an impossibility

Fixed-D ACK release (hold the pure ACK until `t_ACK + D`) is **implementable**, and at
`D ≥ max(CLRT)` it **does** conceal the CLRT completely — better than Defense 1, which releases
the ACK on response arrival and therefore lets the CLRT leak out whole into `READ→ACK = a + c`.
Under a constant offset, `READ→ACK = a + D`, so the CLRT appears in no observable at all.

Measured D-selection curve (n=100 steady-state, physical SEL-751):

| D | CLRT concealed | mean added latency | residual |
|---|---|---|---|
| 1 ms | 0/100 | 0 ms | below the 1.021 ms native floor — inert |
| 2 ms (originally specified) | 61/100 | 0.47 ms | 39 transactions leak `c − D` |
| 3 ms | 84/100 | 1.25 ms | 16 leak |
| 7 ms (≈p95) | 95/100 | 4.81 ms | 5 leak |
| 22 ms (≈max) | 100/100 | 19.57 ms | none |

## Why it is superseded rather than wrong

Two limitations, both structural, neither fatal on its own:

1. **Below full collapse it is invertible.** For any transaction with `CLRT_native > D` the output
   is `c − D`, and D is a constant. An adversary who retrains on defended traffic undoes it. It
   is *not* a no-op — a classifier trained only on native traffic does degrade — but it offers no
   protection against the adaptive observer that Formby's own threat model assumes.
2. **It leaves `READ→ACK` carrying the relay's native ACK latency**, shifted by a constant:
   `a + D` preserves the shape of `a` exactly (measured sd 0.391 ms either way). A multi-interval
   observer measuring `READ→ACK` still sees a device-derived quantity.

Both follow from the same root cause: **the release deadline is computed from a device-generated
timestamp** (`t_ACK`). READ-anchored dual release removes that dependency, which is why it
supersedes this design rather than merely tuning it.

## What carries forward unchanged

- The D-selection curve is the honest cost model for concealing CLRT and belongs in the paper.
- `D = 1 ms` is a **pre-registered null control**: it sits below the native floor, so any measured
  effect there indicates a broken measurement pipeline, not a working defense.
- The two correctness defects found during that study apply to **every** mechanism in this family
  and are carried into the new design: the ~10 s TCP keepalive satisfying the ACK predicate, and
  the response overtaking a held ACK inside the release tail.
- The TCP-timestamp side channel (0.144 bits, ~6% of CLRT entropy) survives any byte-preserving
  hold and must be disclosed as a residual.
