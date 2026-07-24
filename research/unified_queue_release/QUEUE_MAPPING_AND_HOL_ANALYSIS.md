# Queue mapping & head-of-line analysis (Part E)

The head-of-line (HOL) problem is the crux constraint on any queue-resident hold. A TM queue is **FIFO**:
the packet at the head must dequeue before anything behind it. This alone forces most of the queue-mapping
design. (Exact Tofino-1 queue counts per port/pipe are confirmed in `TOFINO_QUEUE_RELEASE_CAPABILITY_AUDIT.md`;
this analysis states the logic and marks the count-dependent conclusions.)

## The HOL problem (the given example)

- `ACK-A` at the head of `Q_ACK_HOLD`; response A has NOT arrived.
- `ACK-B` behind it; response B HAS arrived (B is ready to release).

**Can ACK-B be released without ACK-A?** In a single FIFO queue: **NO.** ACK-A is at the head and blocks
ACK-B regardless of B's readiness. A single shared hold queue therefore serializes all transactions to the
order their ACKs enqueued — a slow/never-completing transaction A stalls every later transaction. This is
disqualifying for anything beyond a strictly one-outstanding-at-a-time flow.

**Consequence:** independent transactions that can complete out of order MUST occupy independent queues (or
the design must guarantee at most one outstanding hold at a time). There is no data-plane "dequeue the
middle of a FIFO" primitive.

## Queue-mapping options

| Option | Isolation | Queues needed | HOL exposure | Verdict (logic) |
|---|---|---|---|---|
| One shared hold queue | none | 1 | full HOL — A blocks B | only valid if ≤1 outstanding hold ever |
| One queue per flow (`flow_id`) | per TCP flow | = concurrent flows | none across flows; within-flow order = arm order | good **iff** one-outstanding-per-flow (the tested txncore invariant) |
| One queue per outstation | per device | = devices | HOL across flows to the same outstation | weak if a device multiplexes flows |
| One queue per transaction class | per class bucket | = classes | HOL within a class | coarse; HOL returns under load |
| Multiple hashed transaction queues | per hash bucket | = buckets | HOL on hash collision | needs collision handling + generation |
| Queue-per-generation | per epoch | = gens | limited | orthogonal freshness tool, not a concurrency fix |

**Best fit with the tested core:** *one queue per flow* combined with the **one-outstanding-per-flow**
invariant the transaction core already enforces and that GATE-1's traffic exhibits (the SEL-751 polls one
request at a time). Under one-outstanding-per-flow, a flow's hold queue holds at most one packet, so HOL
within a flow is moot, and cross-flow isolation is provided by distinct `qid` per flow (hashed to the
available queues). Hash collisions map two flows to one queue → HOL returns for those two → must be handled
by generation + a fail-open timeout (so a stalled collision cannot wedge the other).

## Concurrency limit (count-dependent — confirm exact number in Part B)

The maximum number of usable hold queues on the chosen egress/loopback port(s) bounds simultaneous
independent held transactions. On Tofino-1 the per-port queue count is small (order **32 queues per port**
[TO CONFIRM in the capability audit]); reserving some for real forwarding/priority leaves fewer for holds.
So the design supports **at most ~(usable-queues) concurrent independent held transactions**; beyond that,
flows either share a queue (HOL risk, mitigated by one-outstanding + timeout) or fail open (forward without
timing normalization). For the SEL-751 single-session 1 Hz polling this is not a constraint; for a
high-flow-count WAN it is a hard scaling ceiling and must be stated, not hidden.

## Failure / edge behavior (all must fail open)

- **Queue overflow** (more held packets than queue depth): fail open — forward the overflow packet unheld,
  record it. Never drop a real DNP3 packet to enforce timing.
- **Hash collision** (two flows → one queue): generation disambiguates state; a stalled head is force-
  released by the flow's timeout so the colliding flow is not wedged.
- **Queue exhaustion** (more concurrent flows than queues): excess flows BYPASS (forward, no normalization),
  recorded — a coverage gap, not a correctness failure.
- **Starvation / fairness:** a per-queue fail-open timeout bounds residence, preventing indefinite
  starvation of a held packet whose release event never comes (missing response).
- **Fail-open timeout:** every held packet has a bounded residence; on expiry it is released/forwarded and
  the flow state cleared.

## What this analysis fixes vs leaves open

Fixed (mechanism-agnostic): the HOL constraint forces per-flow (not shared) hold queues under a
one-outstanding-per-flow invariant, with generation + timeout for collisions; concurrency is bounded by the
usable queue count. Left open (Parts B/F): whether a per-flow hold queue can actually be *released on an
event or deadline* from the data plane without controller/chaff/continuous-recirc — if it cannot, the whole
queue-resident approach fails and the HOL design is academic. The count-dependent concurrency ceiling is
finalized once the audit reports the exact usable queue count.
