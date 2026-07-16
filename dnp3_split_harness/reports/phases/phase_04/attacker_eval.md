# Phase 04 — Attacker Evaluation: does the eBPF EDT mechanism reduce fingerprinting?

**Trace-transformation evaluation** (per the reviewer's labelling rule): the measured *native* per-transaction features from the six real device PCAPs are transformed by the eBPF EDT model (pin existing pure ACK to req+20 ms, response to req+40 ms; delay-only; ACK mode and sizes unchanged) and re-classified. It is **not** a capture of a defended device on the wire. Chance (majority class) = 0.400; higher = attacker identifies the device better.

## 1. Supervised random forest — accuracy per feature family (capture-level split)

| feature family | native | ebpf_edt | plus_ackmode |
|---|---:|---:|---:|
| ack_only | 0.810 | 0.800 | 0.400 |
| timing | 0.511 | 0.401 | 0.400 |
| size | 0.500 | 0.500 | 0.500 |
| all | 0.888 | 0.900 | 0.500 |

## 2. Unsupervised k-means — Adjusted Rand Index per family

| feature family | native | ebpf_edt | plus_ackmode |
|---|---:|---:|---:|
| ack_only | 0.654 | 0.656 | 0.000 |
| timing | -0.000 | -0.000 | 0.000 |
| size | 0.184 | 0.184 | 0.184 |
| all | 0.567 | 0.567 | 0.184 |

## 3. Reading

- **The eBPF EDT closes the TIMING channel cleanly.** `timing` (request→response) accuracy 0.511 → 0.401: every device's response is pinned to the common 40 ms target, so the request→response feature carries no device information — and, unlike a device-correlated gap normalization, it does not re-encode the ACK mode into timing.
- **It does NOT close the ACK-MODE channel.** `ack_only` accuracy 0.810 → 0.800: the mechanism cannot change `is_separate` (a separate-mode device still emits a standalone pure ACK; a combined device still piggybacks), and with the prototype's 20/40 ms targets the request→ACK time itself splits 20 ms (separate) vs 40 ms (combined). Both are categorical/structural leaks a no-synthesis, byte-preserving mechanism cannot remove.
- **Only hiding the ACK mode collapses it** — `plus_ackmode` drops `ack_only` to 0.400, but that is not byte-preserving and requires ACK synthesis / suppression, outside this mechanism.
- **Size is the irreducible residual.** `size` accuracy is 0.500 throughout (byte preservation forbids touching it).
- **Joint identity does not fall — it edges up (0.888 → 0.900).** The prototype's 20/40 ms targets make request→ACK itself device-correlated (20 ms for separate, 40 ms for combined), so the `all` attacker gains a small extra tell rather than losing one. A design refinement — set the ACK target equal to the response target so request→ACK no longer splits — would remove *that* artifact, but `is_separate` (a separate device still emits a distinct pure-ACK packet) and size would still leave `all` above chance.

**Verdict:** the eBPF EDT mechanism is an effective *timing* normalizer (closes the request→response channel to chance, with no re-encoding), but it does **not** defeat device fingerprinting — the ACK mode and response size remain, and joint accuracy stays at 0.900 (vs 0.400 chance). Closing the mode channel needs ACK suppression (separate→combined) or synthesis, neither available byte-preservingly in this mode; size needs a size/padding primitive out of this line's scope. This is the measured confirmation of the Phase-4 capability boundary: a no-synthesis, byte-preserving mechanism can normalize *when* packets leave, not *whether a separate ACK exists* or *how large the response is*.

_Scope: trace-transformation on the six device PCAPs (SEL-751 separate; AB1400 / ION7550 combined). Not a rig/defended-wire capture._
