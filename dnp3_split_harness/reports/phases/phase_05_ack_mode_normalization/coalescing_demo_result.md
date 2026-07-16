# Phase 05 — Socket-Coalescing Defended-Wire Demonstration: Result

**PASS** (human-authorized, 2026-07-16). On the **actual wire** (not a trace-transformation),
socket-side coalescing normalizes the request ACK mode from separate to combined —
byte-preservingly, with no dropped packet and no BPF.

## Method

The replay server (`phase05_coalescing_demo.py`, run under `sg wireshark` — no sudo, no netns, no
BPF), 20 sessions × 5 requests per config, captured on `lo`:

- **undefended_separate** — `--server-quickack` forces a standalone pure ACK (the analog of a
  naturally separate-ACK device such as SEL-751).
- **defended_coalesced** — **no** quickack, response written within the delayed-ACK window (~5 ms)
  so the kernel **piggybacks** the request ACK on the response.

Both replay the **same** captured response bytes, so byte-identity isolates the ACK-mode change.

## Result (non-first requests)

| config | request separate-ACK | req→ACK | req→resp | retrans / reset | byte-identical |
|---|---:|---:|---:|---:|---:|
| undefended_separate | **80/80 (100%)** | 0.24 ms | 5.33 ms | 0 / 0 | 100/100 |
| **defended_coalesced** | **0/80 (0%)** | none (piggybacked) | 5.27 ms | 0 / 0 | 100/100 |

Overall **200/200 byte-identical**. Coalescing flips the request ACK mode **100% → 0% separate on
the wire** — each non-first request's first reverse packet is now the ACK-bearing response, not a
standalone pure ACK — with **zero retransmissions/resets** and no change to the DNP3 bytes.

## Precision: the request-ACK is normalized; residual pure ACKs are non-discriminating

The defended capture still contains 40 server pure ACKs (vs 120 undefended), but these are **not**
request-ACKs — they are the **post-handshake quickack ACK** and the **ACK of the master's DNP3
CONFIRM**. Confirmed: the `is_separate` feature keys on the *first reverse packet after the request*
(the request-ACK), which is now the combined response (0/80 separate); the CONFIRM-ACK arrives later
and is a standalone pure ACK for a **native combined device too** (it has nothing to piggyback on),
so it is not a device discriminator (matches the safety analysis §7). The defense correctly targets
and normalizes the request-ACK — the dominant fingerprint feature — leaving only non-discriminating
pure ACKs.

## What this validates (and what it does not)

- **Validates the mechanism on the wire:** socket coalescing really does convert separate→combined
  (`is_separate` 100%→0% for requests), byte-preservingly, with no drops and no breakage — the
  safest possible ACK-mode normalization for a device we own. It confirms the Phase-05
  trace-transformation's core assumption (`is_separate`→0 is achievable on the wire), so that
  effectiveness result (suppression + timing normalization → the size-only floor, joint balanced
  accuracy 0.856→0.501) rests on a wire-verified premise.
- **Does not do a per-device defended-wire classifier eval:** the harness has one replay server (one
  "device"), so a 3-device classifier on defended wire captures needs a rig replaying SEL-751 /
  AB1400 / ION7550 characteristics. Deferred. The device-level effectiveness remains the (now
  wire-anchored) trace-transformation.
- Response **size** is unchanged (out of scope; separate padding line).

Evidence: `coalescing_demo/coalescing_demo_summary.json`, `coalescing_demo/*.pcap`.

## Status

Socket-coalescing ACK-mode normalization is **wire-demonstrated** (request-ACK mode normalized,
byte-identical, no drops/breakage) — the safe, realizable path identified in the feasibility study.
`next_phase_allowed = false`.

```
STOP: socket-coalescing ACK-mode normalization validated on the wire; per-device defended-wire classifier eval (rig) deferred.
```
