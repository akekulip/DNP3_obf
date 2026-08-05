# Defense 4 — architecture (timing core, Priority 1)

## Topology

```
DNP3 master
   |
observed WAN            <- the single passive on-path adversary observes here
   |
one Tofino-1 (outstation edge)
   |
relay / outstation
```

One Tofino-1 at the outstation edge. **No** second switch, decoder, external-loop tunnel, slot grid, or
endpoint modification. **Tofino-1 data-plane only** — no SmartNIC/DPU, no eBPF/XDP, no host pacing, no
controller release fast-path.

## Processing pipeline

```
Incoming DNP3 traffic
        |
Protocol + transaction classification
        |
Size transformation        (Priority 2, added later — NOT in this core)
        |
Unified timing transformation   (Priority 1 — this core)
        |
Output to the master
```

Priority 1 implements only the timing transformation. A later size transformation (Priority 2) must sit
before the timing queues and must not change their release semantics:
`classify -> size transform -> ACK/RESPONSE timing queues -> output`.

## Queues (four logical queues, one internal loopback scheduler domain)

Strict-priority ladder, highest first:

```
Q_ACK_BLOCK  >  Q_ACK_HOLD  >  Q_RESP_BLOCK  >  Q_RESP_HOLD
```

- Use the behaviourally-proven **7 / 6 / 5 / 4** priority ladder (queue IDs) unless a documented Tofino
  constraint requires different IDs. **Queue ID does not prove priority** — the control plane must
  configure and **read back `max_priority`** for each queue (see `timing/control/defense4_timing_setup.py`).
  The four-level strict-priority behaviour itself is proven on silicon (see `EVIDENCE_BASELINE.md`,
  four-queue oracle, commit `6ffd5e5`).
- `Q_ACK_BLOCK` / `Q_RESP_BLOCK` hold the **blocker-token reservoirs** that starve the corresponding hold
  queue until the release condition; `Q_ACK_HOLD` / `Q_RESP_HOLD` hold the **queue-resident** real ACK
  and real RESPONSE respectively.

## Reservoir + loopback contract

- **The original ACK and RESPONSE remain queue-resident.** Only internal **blocker tokens** recirculate
  on the loopback. **No synthetic ACK or RESPONSE is ever generated.**
- **Both blocker reservoirs must be established before the earliest eligible ACK can escape.** The
  control/data plane must verify both `Q_ACK_BLOCK` and `Q_RESP_BLOCK` are ready before the first ACK is
  admitted, and that neither develops a pre-deadline empty gap (a mid-hold reservoir drain would let a
  held packet escape early). Use the **validated reservoir depth** as the initial value; it is **not**
  claimed mathematically minimal.
- `ack_committed_to_master` means the released ACK **returned from the internal loopback and was assigned
  to the normal master-facing output FIFO** — ACK arrival at the switch, or blocker-budget expiry, is
  **not** sufficient. The RESPONSE release predicate depends on this commitment (see `TIMING_SPEC.md`).
- **One active protected transaction per scheduler domain** initially. A concurrent eligible transaction
  must **fail open** (bounded release, unshaped) **without overwriting** the active transaction's state.

## Boundary with size (Priority 2)

There is deliberately no `size/` directory during Priority 1. Plaintext DNP3 function codes and semantics
remain visible; size and timing shaping are **traffic-analysis defenses, not semantic encryption**. Size
work resumes only after the timing core has its own committed PASS checkpoint.
