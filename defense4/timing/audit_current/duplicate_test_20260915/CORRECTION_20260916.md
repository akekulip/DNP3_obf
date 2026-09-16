# What the duplicate trace actually shows, 2026-09-16

This corrects `RESULT.md`, which claims the duplicate-suppression risk is closed and describes a
clean 3 / 6 / 12 s timeout sequence. The capture `duplicate_suppression.pcap` is unchanged and
every number below is re-derived from it. No hardware was used and no new experiment was run.

---

## 1. The filter dropped every copy, for the whole test

`dup_test.py` installs

```
iptables -A INPUT -m length --length 101:101 -j DROP
```

for `HOLD = 25.0` seconds. That is not "drop the original response". It drops **every** inbound
packet of that length for twenty-five seconds, so no copy of the response ever reached the
master's TCP stack, the stack never acknowledged any of them, and the outstation kept
retransmitting until the connection was torn down.

The capture is taken on the master host, ahead of the firewall, so it shows packets that arrived
at the NIC and were then discarded before the stack. That distinction is the whole difference
between what this trace establishes and what `RESULT.md` claims.

## 2. The intervals are not 3 / 6 / 12 seconds

Decoded from the capture, seventeen frames, all CRCs valid:

| event | capture-relative time | gap from the previous copy |
|---|---:|---:|
| READ request | 0.210335 s | |
| original RESPONSE | 0.235595 s | |
| repeated RESPONSE | 3.204730 s | 2.969135 s |
| repeated RESPONSE | 9.205833 s | 6.001103 s |
| repeated RESPONSE | 20.245623 s | 11.039790 s |

The successive gaps are 2.969, 6.001 and 11.040 seconds. Describing this as the
3 / 6 / 12 s backoff measured in the relay RTO diagnostic overstates the agreement, and those
earlier captures have their own timestamps and roughly doubled intervals; the two are separate
observations and are not pooled here.

The last copy also cannot be attributed to a timer expiring on its own. At 20.245122 s the
outstation sends a bare acknowledgment carrying the sequence number one below its data, which is
the shape of a keepalive probe; the master acknowledges it at 20.245155 s; the response copy
follows 0.47 ms later. An identical probe and acknowledgment at 10.224835 s produced **no** copy.
Attributing every repeat to retransmission-timeout expiry from timestamps alone is therefore not
supported by this trace.

## 3. The risk is not closed, because this test did not reach it

The risk in `CORRECTION_REPORT_20260915.md` §1 is that `OUT_RESP_DUP_SUPP` **drops** a duplicate
response **while the transaction is live**. In this trace the transaction was live for about
25 ms: the request at 0.210335 s and the released response at 0.235595 s, consistent with the
configured 20 ms acknowledgment hold plus 4 ms. The first copy arrived 2.97 s later, about 120
times the length of that window.

The frozen program settles why that matters. The generation transition is a single constant add
predicated on the tag's high bit, and applying it clears that bit, so, in the program's own words,
"a duplicate, retransmitted or stale RESPONSE arriving afterwards cannot apply it again". Once the
response has been released the generation is retired, and a later copy is stale rather than a
duplicate of a live transaction. Stale tokens take `OUT_AB_STALE` / `OUT_RB_STALE`, which is a
different path from the one under suspicion.

**So the copies were forwarded because they arrived after retirement, not because duplicate
suppression preserves loss recovery.** The case where a duplicate arrives inside the live window
remains unexercised. Reaching it requires the original response to be lost downstream of the
switch and the retransmission to arrive within the hold, which on this relay means a
retransmission timer of the same order as the hold rather than 3 s.

## 4. What the trace does establish

* Four copies of the response, identical in sequence number and length, crossed the switch and
  reached the master host's NIC under a persistent receiver-side drop. The switch did not absorb
  them.
* Every frame's header and block CRCs validate.
* The connection ended in an ordinary FIN/RST exchange at about 25.23 s, when the rule was
  removed and the master closed.

## 5. What it does not establish

* **Not** that the application recovered. The application received nothing: every copy was
  dropped before the stack. TCP loss recovery was never completed in this trace.
* **Not** that duplicate suppression is safe during an active holding window, which is the actual
  risk and was never exercised.
* **Not** a clean retransmission-timeout series, for the reasons in §2.
* **Not** anything about exactly-once execution. Wire duplicates neither establish nor refute it;
  that is an application property and this is a link observation.

## 6. The transaction lifetime is not D_A + CLRT_new

Treating the live window as exactly the configured budget is wrong in both directions, and the
frozen program says so. The only paths that retire a generation are the released RESPONSE and the
fail-open budget, and the deadline pre-empts the budget; a missing RESPONSE never retires it. So:

* a transaction whose response never arrives stays live until the fail-open budget drains, which
  is counted in blocker passes rather than in time;
* a late response takes `OUT_RESP_HOLD_LATE`, which the commit map sends to `cmt_resp_hold()` and
  therefore to **qid4**, the response-hold queue. It is not a zero-queue bypass and its departure
  is not immediate merely because a nominal deadline has passed; it still waits on the queue's
  service and on whatever blockers remain.

## 7. What must not be done

Suppressing every future copy of a sequence number in the data plane would turn the open risk into
a certainty. Legitimate TCP loss recovery retransmits the same bytes and the same sequence ranges;
that is what recovery *is*. Any suppression has to be qualified by transaction liveness, and the
liveness window has to be short relative to the sender's retransmission timer, which is a property
of the deployment and not of this program.
