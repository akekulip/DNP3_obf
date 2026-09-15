# Duplicate suppression does not block loss recovery

The open risk in `CORRECTION_REPORT_20260915.md` §1 is **closed**. A loss-recovery retransmission
is delivered, not suppressed.

## The risk

`OUT_RESP_DUP_SUPP` drops a duplicate response while the transaction is live. If the original
response were lost downstream of the switch, the outstation's retransmission is exactly the packet
that recovers it, so the question was whether the mechanism would discard it.

## The test

Frozen campaign build, mode D4, D_A = 20 ms, configured CLRT_new = 4 ms, `shape_enable` read back
as 1 after `configure-all`, forced to 0 and verified before any traffic. One DNP3 connection, one
READ, no control traffic.

The relay's response is dropped **inbound at the master only**, scoped to that connection's own
four-tuple, so the kernel never acknowledges it and the relay retransmits on its own timer. The
capture sits on the interface ahead of the firewall, so it shows what the switch actually
delivered. Every `iptables` call is checked and the removal is verified rather than announced:
`install_rc 0`, `verify_installed_rc 0`, `remove_rc 0`, `still_present_rc 1`, no leftover rules.

## Result

| copy | arrival | interval |
|---|---|---|
| original | 0.236 s | |
| retransmission 1 | 3.205 s | 2.969 s |
| retransmission 2 | 9.206 s | 6.001 s |
| retransmission 3 | 20.246 s | 11.040 s |

All three retransmissions of sequence 689667692 reached the master. **The switch forwarded every
loss-recovery copy.** The backoff is the same 3 / 6 / 12 s pattern measured on 2026-09-15, which
is consistent with the relay's own timer and independent of this mechanism.

## Why the outcome was never really in doubt, and why the test still mattered

The transaction is live for about 24 ms, `D_A` plus the configured `CLRT_new`. The outstation's
retransmission timer is about 3 s. The two windows are two orders of magnitude apart, so a
retransmission cannot arrive while the transaction is still live on this relay. The test confirms
the reasoning rather than replacing it, and it confirms it on the real device rather than from the
code.

**Scope.** One relay whose retransmission timer is 3 s. A device with a timer close to the hold
would need this repeated, and the conclusion should not be carried to one without it.

## A first attempt failed, usefully

The first run matched packets of total length 89 bytes, computed as 20 IPv4 + 20 TCP + 49 DNP3.
Nothing was dropped and no retransmission followed, because this connection carries TCP timestamps
and its header is 32 bytes, making the response 101 bytes. That is exactly the assumption
`active_probe/rto_probe_plan.py` takes as an input from the observed connection rather than
hardcoding, and it is why that probe reports its length bound and margin instead of trusting them.
