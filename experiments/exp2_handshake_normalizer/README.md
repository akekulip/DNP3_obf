# Experiment 2 — handshake TCP-header normalizer (Tofino-1)

Two phases live here:

- **Experiment 2A (design):** `EXPERIMENT_2A_DESIGN.md` + `REVIEW.md` — the reviewed specification of
  a standalone Tofino handshake normalizer that removes the TCP-option-layout device fingerprint
  attributed in Experiment 1.
- **Experiment 2B (standalone compile + model):** the P4 implementation of that design, its
  compilation on bf-p4c, resource accounting, adversarial review, and the model-test harness.

## Experiment 2B status: COMPILE_PASS (functional model run pending)

The standalone normalizer `p4src/handshake_normalizer.p4` **compiles cleanly** for Tofino-1
(bf-p4c 9.13.1, `0 errors`, loadable `tofino.bin` produced) and is **stateless**. The tofino-model
+ PTF functional run is the next gate and was **not executed** in this turn — no behavioral PASS is
claimed. See `VERDICT.md`.

## The mechanism in one paragraph

The device fingerprint lives in the TCP handshake's option layout (Experiment 1). This program
rewrites **only eligible SYN / SYN-ACK** segments: it collapses the option region to a single
canonical `[MSS]` (MSS clamped to ≤1460, never raised), sets `data_offset` to 6, drops Timestamps /
Window-Scale / SACK-permitted, scrubs TTL and (for atomic datagrams) IP-ID, and recomputes both
checksums — so both endpoints negotiate a canonical minimal option set and, per RFC 7323/2018
fallback, emit no options on their own on established segments. It is **stateless / packet-bounded**:
no per-flow state, no sequence/TSval translation, no reassembly. Everything it does not fully
understand and cannot safely normalize — MD5/AO/unknown options, SYN payload/TFO, non-minimal
SYN-ACKs, established segments, `data_offset` > 11 — it **fails open** (forwards, options untouched).

## Files

- `p4src/handshake_normalizer.p4` — the standalone TNA program (203 lines).
- `scripts/compile.sh` — the pinned bf-p4c compile command + evidence capture.
- `evidence/` — raw compile stdout/stderr, `metrics.json`, `manifest.json`, source SHA-256.
- `tests/ptf/test.py` — PTF functional tests (built with scapy; fixtures verified well-formed).
- `COMPILE_RESULTS.md` — compile evidence **and the full bf-p4c-9.13.1 ICE diagnosis** (three
  coding-shape faults, each fixed with a standard idiom).
- `RESOURCE_REPORT.md` — MAU/PHV/latency accounting; the stateless proof.
- `IMPLEMENTATION.md` — how the P4 realizes the design, path by path.
- `REVIEW_2B.md` — the two adversarial reviews (Tofino correctness; TCP safety).
- `MODEL_TESTS.md` — the 26-case matrix and the exact model-run procedure (ready, not yet run).
- `VERDICT.md` — the primary verdict and what it does / does not establish.

## Gate discipline

A clean compile authorizes only the **model functional test** (next), never Experiment 3 (endpoint
safety) and never a hardware step. Both of those require separate, explicit authorization.
