# Decoy-CROB padding — the size axis for the CONTROL path

**2026-08-04. Addendum to `DITTO_VS_DEFENSE3.md`, correcting a scope error in it.
Design study only; nothing built, no hardware touched.**

---

## 0. The correction

`DITTO_VS_DEFENSE3.md` §2 concludes that the size axis is closed. **That conclusion is
scoped to the Class-0 integrity-poll response and does not generalise to the control path.**
The evidence behind it — "one response size, 200 B, n = 300, 1 distinct value" — was measured
on Class-0 static-data polls only. Class 0 returns a fixed point set, so its length is fixed.

The control path is a different traffic class with a **large, measured size leak**:

| leak | measurement | source |
|---|---|---|
| response size vs CROB count | **14.6 B per CROB, R² = 0.9999**, 37 → 256 B over N = 1 → 16 | `research/split_pad_timing_policy/` |
| response processing time vs CROB count | 0.18–0.21 ms per CROB, R² ≈ 0.99 | same |

*(caveat carried from that study: n = 1 per N — the fit is near-perfect but thinly sampled.)*

So on the control path the secret an adversary wants is **the CROB count / request complexity
of a switching operation** — how many breakers are being operated — and it leaks on both size
and timing. That is arguably a more operationally sensitive secret than device identity, and
it is exactly what decoy padding targets.

---

## 1. Why decoy CROBs escape the two impossibility arguments

The companion document gives two arguments that kill padding on the plaintext response path.
Neither survives contact with a **valid CROB at a configured-but-unwired index**.

**P1 (strippability) — escaped.** The argument is that any filler the receiver must ignore is
self-identifying, so the observer strips it. A decoy CROB is **not ignored by the receiver**: