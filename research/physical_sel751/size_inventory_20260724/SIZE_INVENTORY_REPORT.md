# DNP3 Response Size Inventory — Phase-5 evidence (2026-07-24)

**Analysis only — no padding mechanism is chosen or implemented here.** This is the plan's first Phase-5
step ("inventory from physical + trace pcaps; candidate states must cover the physical response"). The
size *mechanism* (how to reach a cover size) is the undecided architecture decision (contradictions
C3/C4) and is explicitly left for a human. Produced in the offline fallback; read-only; no switch/relay.

Tool: `size_inventory.py` (reuses `shadow_refmodel.classify` to select func-129 responses). Raw rows:
`packet_size_inventory.csv` (23,382 responses); machine summary: `size_inventory_summary.json`.

## The four size layers (this resolves the prior "134 B" ambiguity)

A passive size-fingerprinter observes the **wire frame**, not the DNP3 length octet. For the physical
SEL-751 response the four measurable sizes are:

| Layer | Physical relay response | What it is |
|---|---|---|
| **wire frame** (`raw`) | **200 B** | full Ethernet frame — what the observer actually sees |
| IP total length | 186 B | IP datagram |
| **TCP payload** | **134 B** | DNP3-over-TCP bytes — **this is the previously-cited "134 B wire" figure** |
| DNP3 length octet | 115 B | DNP3 link-layer length field |

The earlier "134 B wire / 115 B DNP3" labeled the **TCP payload** as "wire". The true on-wire frame is
**200 B**. All four are recorded per response in the CSV so downstream analysis targets the right layer.

## Inventory (23,382 responses, 7 sources)

| Source | n | wire min–max (distinct) | TCP-payload max | DNP3-len max |
|---|---|---|---|---|
| physical_relay_300poll | 300 | **200–200 (1)** | 134 | 115 |
| trace_SEL751 / L | 598 / 7998 | 103–120 (2) | — | 43 |
| trace_AB1400 / L | 798 / 3998 | 91–120 (4) | — | 43 |
| trace_ION7550 / L | 1647 / 8043 | 91–127 (4) | — | 50 |
| **global** | **23,382** | **max 200** | **max 134** | **max 115** |

## Candidate cover states (size arithmetic ONLY — not a mechanism)

To make the response size non-identifying, every response must be brought to a common target ≥ the max
observed at the chosen observation layer:

| Observation layer | global max | single fixed ≥max | next 2ⁿ | next 128 B multiple |
|---|---|---|---|---|
| wire frame | 200 B | 200 | **256** | **256** |
| TCP payload | 134 B | 134 | 256 | 256 |
| DNP3 length | 115 B | 115 | 128 | 128 |

**Confirmed and quantified — contradiction C5:** the existing Level-1 **128 B** state does **not** cover
the physical relay response at either the wire layer (200 B) or the TCP-payload layer (134 B). A single
fixed target must be **≥ 256 B** at the wire/payload layer (or a multi-state ladder whose top ≥ 256 B).
The prior "128 covers 120" statement was true only for the ≤120 B *trace corpus*, not the physical relay.

## Explicitly NOT decided here (human-gated)

- **Mechanism** (C3/C4): prepend a black-hole DNP3 filler vs Group-110 octet-string vs per-flow TCP
  seq-space translation vs two-edge outer encapsulation. Each changes the architecture; the plan leans to
  the two-edge/second-edge split. Not chosen here.
- **Invariant change**: reaching a cover size requires abandoning strict byte-preservation for
  "append-only, integrity-correct" — a governing-spec change. Not adopted here.
- **State granularity**: single fixed 256 B vs a padded ladder (e.g., 128/256) trading overhead for
  timing/queue behavior. A joint size+overhead decision, deferred to Phase-5/6 design.

No mechanism, no P4, no byte modification was produced — this is the size evidence base the eventual
Phase-5 design must satisfy.
