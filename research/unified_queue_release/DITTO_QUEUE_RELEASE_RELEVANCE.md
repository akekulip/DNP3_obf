# Ditto queue-release relevance to GridCloak (Part C)

Verified against the **actual Ditto NDSS 2022 paper PDF** (`2022_NDSS_ditto WAN Traffic Obfuscation at
Line Rate.pdf`, Meier/Lenders/Vanbever), not the pasted explanation. No real Ditto *source* exists in the
repo — only the paper + the team's own derivative notes (`DITTO_QUEUE_RECONSTRUCTION.md`,
`DITTO_TO_DNP3_MAPPING.md`). All page cites are the paper's printed pages.

## Artifacts present vs missing

- **Present:** the paper PDF (authoritative); the team's reconstruction + DNP3-mapping notes (accurate
  secondary sources — independently re-checked against pp3–8 and they match).
- **Missing (nowhere on the machine):** `traffic_pattern_tofino.p4` / any `*ditto*.p4`, `init_pd_rpc.py`,
  `bfshell_input_tofino1.txt`, queue/port/loopback/pattern config files, and any clone of `nsg-ethz/ditto`.
  The only `chaff*.py` on the machine is Philip's own GridCloak code (unrelated to Ditto). So mechanism
  claims below are from the paper's own description of its implementation (§VI, §VIII), not byte-level source.

## Ditto's real mechanism (paper-verified)

- **Where real packets buffer:** per-pattern-state **high-priority FIFO queues** in the TM on the
  obfuscated egress port; L queues per port for a length-L pattern (p4–5). Real packets → high-priority
  queue `q_{i,r}`; chaff → low-priority `q_{i,c}` of the same state.
- **Passes:** a **fixed TWO** data-plane passes via loopback (hierarchical queueing approximation), **not**
  repeated-until-release (p7 §VIII, Fig 4). Extra passes happen only for large **padding** (a size concern,
  orthogonal to timing).
- **Why packets stay queued:** a **rate shaper + round-robin scheduler**. Each priority pair is shaped to
  1/L of port rate; the L queues are served round-robin at constant rate (p4, p6). A packet waits for its
  scheduled round-robin slot — **pure time/rate control**, not a paused queue and not an event.
- **The hierarchy:** stage-1 priority pairs (real > chaff, within a state) → looped back → stage-2
  round-robin across states → egress (p6–7).
- **Why chaff exists — the load-bearing fact:** round-robin **skips an empty queue**, which would drop a
  pattern state; chaff keeps every queue non-empty so no slot is skipped (p5). The paper is explicit that
  the *better* primitive does not exist in hardware: *"Ideally, the hardware would allow to inject a 'chaff'
  packet when the TM attempts to send a packet from an empty queue. … there was no need for such a feature
  so far and thus it does not exist"* (p6). Chaff is produced by **continuously recirculating** chaff and
  cloning it into the low-priority queues (p4).
- **Event release:** **NONE.** A real packet leaves only when round-robin reaches its queue at the shaped
  rate. Priority chooses real-vs-chaff *within one slot*; it never couples one packet's release to another
  packet's arrival. Output timing is independent of input (§IX-C, Fig 8).

## Relevance to GridCloak's question

GridCloak needs a **response-arrival event (or a deadline) to release a specific queue-resident ACK/response**,
**without external chaff** and **without continuous recirculation of the original packet**. Ditto:

1. **Provides NO event-driven release** — it is purely schedule/rate-driven, has no transaction awareness,
   and has **no equivalent** of "a response releases a stored ACK." That event→slot coupling is exactly the
   part GridCloak must invent (the team's own `DITTO_TO_DNP3_MAPPING.md:35,85-87` already says so).
2. **Requires chaff** to keep queues serviced — which **directly conflicts** with GridCloak's no-external-
   chaff requirement. And it establishes, from the paper's own words, that **Tofino hardware cannot inject
   a packet on an empty-queue service attempt** — so any "keep the queue serviced without chaff" scheme
   cannot rely on a hardware empty-queue-fill; it would need an internal token stream (pktgen metronome)
   that itself keeps the queue non-empty, i.e. the same function as chaff but internal/consumed.
3. **Uses a fixed two-pass loopback** — this *is* compatible with GridCloak's "fixed one/two-pass loopback
   permitted" rule (Ditto does NOT spin the original packet thousands of times for timing; the only
   recirculation-until-done is for oversized padding).

## Bottom line

Ditto contributes the **slot/pattern shaping primitive and the two-pass hierarchical-queueing pattern**,
both usable, but it **does not** solve GridCloak's core need: it has no event-driven release and it depends
on chaff precisely because the Tofino TM has no empty-queue-fill and no event-to-eligibility primitive. So
Ditto is a **partial building block, not the mechanism** — and it is direct evidence that the event→release
coupling and the no-chaff requirement are the hard, unsolved parts that Parts B/F must resolve on the real
Tofino-1 primitives (or report infeasible).
