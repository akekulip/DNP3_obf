# Phase 04 — eBPF EDT prototype

Host-local proof of the narrowed §8a mechanism: independently schedule an **existing** separate
pure TCP ACK and the DNP3 response to per-flow earliest-departure-times, byte-preservingly and
without forging anything. Built; **not yet run** (BPF load needs your sudo).

## Files

- `ack_edt.c` — the tc-egress BPF program. Records each DNP3 request's arrival in an LRU map
  (keyed by the master side), and stamps the reverse pure ACK / response with an EDT
  (`request_arrival + 20 ms` for the ACK, `+ 40 ms` for the response). `fq` enforces the stamps.
  **Fail-open** for any reverse packet with no recorded request (unknown / combined-mode). Loopback
  simplification: one egress program (both directions traverse `lo` egress); a real bridge/Tofino
  needs the ingress+egress split from `ack_control_feasibility.md` §8a.
- `phase04_ebpf_prototype.py` — driver (runs in the netns as root): loads the object, drives the
  replay server (separate-ACK regime) + client, captures, and measures request→ACK / ACK→response.
- `run_prototype.sh` — turnkey root wrapper (compile → netns → load → drive → analyze → teardown).

## Run (once, as root — isolated in a throwaway netns)

```
sudo bash reports/phases/phase_04/ebpf_prototype/run_prototype.sh
```

## Expected result if the mechanism works

Native (before): prompt separate ACK (~0 ms), response at ~5 ms. With the eBPF EDT loaded, the
pure ACK and response are **pinned to their targets independently**:

- request → pure ACK ≈ **20 ms** (was ~0)
- request → response ≈ **40 ms** (was ~5)
- ACK → response gap ≈ **20 ms** (gap-normalized)
- 0 retransmissions / resets, responses **byte-identical** (EDT only delays; nothing forged/edited).

That would demonstrate independent, byte-preserving, synthesis-free ACK+response scheduling — the
core Phase 04 mechanism — for separate-mode flows. Paste the output back and I'll record it.

**Not yet covered** (later, on authorization): the other required modes (ack-delay-only /
response-delay-only / bounded-gap), configurable targets, the ingress+egress bridge version, the
attacker-eval of residual leakage, and any rig / real-device run. `next_phase_allowed = false`.
