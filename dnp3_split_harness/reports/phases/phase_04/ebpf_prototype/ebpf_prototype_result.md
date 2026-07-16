# Phase 04 — eBPF EDT Prototype: Result

**PASS** (PI-run as root, 2026-07-16, run `20260716T231044Z_phase04_ebpf_prototype`). The eBPF EDT
mechanism loaded, passed the in-kernel verifier, and **independently pinned an existing separate
pure TCP ACK and the DNP3 response to their per-flow earliest-departure-times** — byte-preservingly
and without forging anything.

## Load

```
ack_edt.o:[tc] direct-action not_in_hw id 152 tag ea90ab12cd934285 jited
```

The program loaded and JIT-compiled — **the verifier accepted it** (direct packet access, bounds
checks, LRU-map lookup, `skb->tstamp` write all pass on kernel 5.15.0-139).

## Measured (non-first SEPARATE transactions, 10 sessions × 5 requests)

| metric | native (before) | eBPF EDT (targets) | measured |
|---|---|---|---|
| request → pure ACK | ~0.01 ms | 20 ms | **20.047 ms** |
| request → response | ~5 ms | 40 ms | **40.355 ms** |
| ACK → response gap | ~5 ms | 20 ms (normalized) | **20.001 ms** |
| separate / non-first | — | — | 40 / 40 |
| retransmissions / dup-ACKs / resets | — | 0 | **0 / 0 / 0** |
| byte-identical | — | 100% | **50 / 50** |

The existing pure ACK (native ~0.01 ms) and the response (native ~5 ms) were **both delayed
independently** to their targets: request→ACK to 20 ms and request→response to 40 ms, giving a
gap-normalized 20 ms — with zero retransmissions/resets and byte-identical responses. `fq` enforced
the BPF-set departure times; nothing was forged or edited.

Evidence: `evidence/ebpf_prototype_summary.json` (numbers). The PCAP is root-owned in the
git-ignored run dir (`runs/20260716T231044Z_phase04_ebpf_prototype/ebpf_prototype.pcap`);
regenerable via `run_prototype.sh`.

## What this demonstrates

The **core Phase 04 mechanism** works end to end for separate-mode flows: a loaded tc-egress BPF
program with per-flow state can schedule an existing pure ACK and response to arbitrary,
request-correlated departure times — independent, byte-preserving, synthesis-free — and the
ordering invariant (`ack_release < response_release`) holds by construction. This is the
gap-normalization / independent-delay mode of the plan's required set, PCAP-proven.

## Not yet covered (remaining Phase 04 work; still gated)

- The other required modes (native, ack-delay-only, response-delay-only, bounded-gap) and
  **configurable targets** (currently compile-time constants).
- The **combined-mode fail-open** path exercised against an actual combined-mode capture (here all
  flows were separate-mode by construction; the code fails open, but that branch was not measured).
- The **ingress+egress bridge version** (this is the loopback single-egress simplification).
- The **attacker-eval of residual leakage** (does normalizing the mode + gap actually reduce
  fingerprinting on the defended traces?).
- Any **rig / real-device** run.

`next_phase_allowed = false` — these need explicit authorization.

```
STOP: core eBPF EDT mechanism PROVEN; remaining Phase 04 modes/eval/bridge/rig await authorization.
```
