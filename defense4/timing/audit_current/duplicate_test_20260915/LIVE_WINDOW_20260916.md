# The duplicate live-window risk is unreachable on this deployment — 2026-09-16

`CORRECTION_20260916.md` left one case open: `OUT_RESP_DUP_SUPP` drops a duplicate response
**while the transaction is live**, and the 2026-09-15 trace never reached it, because the copies
arrived seconds after the transaction had retired. The obvious next step was to reach it by making
the hold long enough to overlap the outstation's retransmission timer.

That is not possible here, and the hardware session of 2026-09-16 establishes why with measured
numbers rather than argument. No new loss experiment was run; what follows is three bounds, two of
them measured today.

## The three bounds

| bound | value | where it comes from |
|---|---:|---|
| what the live window must exceed | **~2.97 s** | the interval to the outstation's first response retransmission, 2026-09-15 trace |
| the control plane's enforced ceiling on `D_A` | **40 ms** | refused on hardware today, see below |
| the master's initial retransmission timeout | **~201 ms** | measured today, `../master_rto_20260916/RESULT.md` |
| the data plane's representable ceiling | 2.147 s | `D_A + CLRT_new < 2^31` ns, from the expiry test |

For a duplicate to arrive while the transaction is live, the live window `D_A + CLRT_new` must
exceed the interval at which the outstation retransmits. On this relay that is about 2.97 s. The
largest live window the control plane will configure is 44 ms, so the required condition is off by
a factor of about 67. **The case cannot be reached on this deployment by configuring it.**

Two further ceilings sit below the one that would be needed, so removing the clamp would not help:
the data plane's expiry test compares a 32-bit modular age and treats bit 31 as the sign, so any
`D_A + CLRT_new` at or above 2.147 s stops being a deadline in the future; and the master's own
retransmission timer fires at about 201 ms, so a hold anywhere near a second breaks the master's
transport long before it approaches the outstation's.

## The clamp, observed

Asking the frozen control plane for a 2200 ms hold:

```
ValueError: D = 2200.000000 ms exceeds the 40.0 ms clamp
(CONSENSUS 8.4: poll-period overlap on the 400 ms schedule). Refusing.
```

`configure-all` refused it and left `tbl_params` holding the previous configuration, read back as
`d_ticks = 20000000`, `da_dr = 24000000`. The refusal is real and it is fail-closed.

**But its own `dry-run` accepted the same input**, reporting `MODEL configure-all: PASS` and
`RESULT: PASS` for 2200 ms. The model path does not apply the clamp the hardware path enforces, so
a configuration can pass the offline model and be refused by the device. That is a defect in the
frozen tooling worth knowing about: the dry-run is not a faithful model for this input.

`active_control/timing_only_profile.py` now rejects a hold above 40 ms in `validate()`, before any
write and without a device, so the offline path and the hardware path agree. It already rejected
the 2.147 s modular limit, which turns out not to be the binding constraint.

## What this resolves, and what it does not

**Resolved for this deployment.** The live-window case is unreachable: the enforced 40 ms ceiling
is 67 times smaller than the interval a duplicate would have to arrive within, and two independent
ceilings sit below it. No configuration of this mechanism on this relay can produce a duplicate
response inside a live transaction, so `OUT_RESP_DUP_SUPP` cannot discard a loss-recovery copy
here.

**Not resolved in general.** This is an argument from three numbers, and all three are properties
of this deployment rather than of the design. A device whose retransmission timer were tens of
milliseconds rather than seconds would bring the two windows together, and then the drop would be
reachable and would need testing rather than arithmetic. The manuscript should continue to state
the separation of timescales as the reason the case does not arise, and to say that it is a
property of the evaluated relay.

**Still not demonstrated.** That a duplicate arriving inside a live window is in fact dropped. The
commit map says `OUT_RESP_DUP_SUPP : cmt_drop()`, and nothing observed here contradicts it, but no
capture in this repository exercises that path.
