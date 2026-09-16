# The master's own retransmission timer, measured — 2026-09-16

The outstation's timer was measured on 2026-09-15. The master's never was, and the two are
different quantities governing different things. The master's timer is the one an acknowledgment
hold consumes, because it is the master that is waiting for its request to be acknowledged. This
closes that gap.

Hardware session of 2026-09-16, under explicit authorisation. Frozen program
`defense4_rrc_bor_unified12` loaded from the preserved build whose binary hashes to
`33fa3a77c732f4cf…`, configured `configure-all --mode D4 --d-a-ms 20 --d-r-ms 4 --read-len 0`,
then `shape_enable` forced to 0 and read back as 0 before any traffic.

## Method

One DNP3 connection, one READ. Everything inbound from the outstation on that connection's own
4-tuple is dropped at the master, so nothing can acknowledge the request: not a pure
acknowledgment, and not the response, whose acknowledgment field would otherwise acknowledge the
request implicitly. The master's stack therefore retransmits on its own timer, and the capture,
taken on the master's interface ahead of the filter, records every attempt.

Scoped to one 4-tuple, `192.168.10.1:33178 -> 192.168.10.7:20000`. Every `iptables` call was
checked, and removal was established by the check returning 1, which is absence, rather than by
any non-zero status. `cleanup_verified: true`.

Capture: `master_rto.pcap`, nanosecond resolution, 23 frames. Script: `master_rto.py`.

## Result

The master retransmits its 20-byte READ eight times, at these intervals:

| attempt | interval since the previous |
|---:|---:|
| 1 | **200.8 ms** |
| 2 | 208.0 ms |
| 3 | 408.0 ms |
| 4 | 856.0 ms |
| 5 | 1{,}664.0 ms |
| 6 | 3{,}264.0 ms |
| 7 | 6{,}720.0 ms |
| 8 | 13{,}312.0 ms |

Successive ratios are 1.04, 1.96, 2.10, 1.94, 1.96, 2.06, 1.98. Everything from the third gap
onward doubles, which is ordinary exponential backoff. **The first two intervals are nearly equal,
which backoff does not explain**, and that matters for what may be concluded.

**What this establishes: the first repeated request appeared after 200.8 ms on this connection.**
That is a measured repetition threshold, not a read of the sender's retransmission timer. The
capture records packets; it does not record `TCP_INFO`, the stack's current RTO, or any event
counter saying which timer fired. A tail loss probe is sent before RTO-based recovery and would
produce an early repeat followed by a near-equal one, which is consistent with the first two gaps
here; RFC 8985 defines that behaviour. We did not collect the evidence that would separate the two
explanations, so we do not assert which fired, and we do not describe the whole series as simple
exponential RTO backoff.

## What this settles

**The frozen policy's 200 ms is the right order for the timer it actually governs.**
`implementation/control/parameter_policy.py` carries 200 ms, and the 2026-09-15 diagnostic was
read as showing that value to be wrong by a factor of fifteen because the relay's timer is about
3 s. That comparison was between two different timers. The outstation's timer is about 3 s and
governs its response; the master's timer is about 200 ms and governs its request. The frozen value matches the order of the master's observed repetition threshold. It does not
follow that the campaign's socket carried exactly this value: this is a later diagnostic on a new
connection, and the campaign recorded no socket state.

`active_control/delay_admission.py` already keeps them as separate named inputs and refuses to
substitute one for the other. This measurement supplies the master's value for the first time,
so a policy can now be admitted against a measured master timer rather than an assumed one.

**A 20 ms acknowledgment hold consumes about a tenth of the master's initial timeout.** That is
the margin the evaluated configuration actually runs with, and it is comfortable but not vast: a
hold above roughly 150 ms would begin to crowd the first retransmission on a connection like this
one, well before anything the outstation's 3 s timer would notice.

## The mechanism, observed live

The same capture shows the mechanism operating on its first exchange, before the filter had any
effect on it:

| | observed | configured |
|---|---:|---:|
| request to acknowledgment release | 20.706 ms | `D_A` = 20 ms |
| acknowledgment to response | **3.996 ms** | `CLRT_new` = 4 ms |

The acknowledgment interval carries the outstation's own acknowledgment latency ahead of the hold,
which is why it exceeds 20 ms. The released interval is within 4 µs of its configured value.

## What the script does and does not control

`master_rto.py` records the return code of every `iptables` call and verifies removal by the
check returning 1. It does **not** branch on a failed installation or a failed verification: it
proceeds to the hold regardless and reports the codes afterwards. On this run all of them were
clean and `cleanup_verified` is true, so the capture is valid, but the controls are recorded
rather than enforced and the script should not be described as enforcing them. It also collects no
socket timer state, which is the measurement that would settle the paragraph above.

## Scope

One relay, one connection, one master host, at one moment. The master's timer is a property of
that host's TCP stack and its route, not of the protocol, so it does not transfer to another
deployment; that is exactly why the admission module takes it as a measured input with provenance
rather than as a constant. RFC 6298's one-second floor is a recommendation about the minimum a
sender *should* use, and this host plainly does not apply it to this route, which is a further
reason not to assume a value anywhere.
