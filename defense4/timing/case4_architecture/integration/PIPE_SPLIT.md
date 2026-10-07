# Functional-pipe hypothesis, not a deployment candidate

The five wire-role composition compiled with separate writer/reader banks. Sharing
the actual fourteen image banks produced eight unallocated response CRC slices.
Splitting every wire CRC into two bytes preserved both bytes and comparisons but
retained the same eight-slice conflict. The next structural test removes response
carving from the authority pipe and compiles it as a separate stateless pipeline.
This is a capability experiment; it cannot qualify autonomous Case 4 behavior.

The local TNA `tofino1_arch.p4` Switch package accepts four separate Pipeline
instances. Each instance owns separate registers. Proposed authority is pipe0;
renderer is pipe1. The source experiments do not assume shared registers. The
recorded testbed has endpoint ports9 and64 and historical loopback ports8/10/11
on pipe0. Processing69, a pipe1 private ingress, both directions of a physical
cross-pipe link, their queues and service are **unverified**. No port is configured.

The complete design would keep connection, image/cache, timing, original credits,
and WorkRecord authority on pipe0. An actual fully validated response reserves a
work credit before the transfer. A private envelope carries epoch32/workGeneration32
and the original inner packet. Any actual owner-cell snapshot requires an additional
expectedCell32/event16/reserved16, giving16 bytes rather than the8-byte resubmit
limit. The worker cannot publish ownership or access authority registers. It may
only validate/render the byte operation associated with its private-port input.

Rendered pieces must return to the authority with their actual work identity and
piece identity. The authority rechecks the protected record and expected epoch,
transaction, application sequence, TCP position and piece before emission. A mere
successful worker completion is not original retirement. Work/original credits
remain live through actual final terminal outcomes. Reset/policy-off quarantines
in-flight work and drains original credits; it cannot free a slot on a timeout.
Lost, duplicated, reordered or stale returns must never publish a later image.
Sender-driven retransmission continues from the connection's committed cache.

Ordering still requires an actual guaranteed queue/admission service for first
and second segments. PRE replica IDs alone do not prove physical [28,29] order.
No finite service rate or loss-recovery time follows from compiler success.
Handoff bytes, two physical transfers per returned piece, queue bursts, heartbeat
and holding circulation must be counted independently of transform passes.

`pipe_split.p4` tests compiler placement of these separate wire roles. Its fixed
port136 is a provisional pipe1 dispatch value, not evidence of an available port.
It deliberately has no ownership envelope adapter or externally enabled defaults.
The missing private-link inventory, owner-qualified actual adapters, ordered queue
service, and complete validator/lifecycle/timing composition remain hard blockers.
