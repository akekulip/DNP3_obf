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
| what the live window must exceed | **0.793 s** | the shortest interval to any response copy anywhere in the evidence, from the 2026-09-16 master capture |
| the control plane's enforced ceiling on `D_A` | **40 ms** | refused on hardware today, see below |
| the master's initial retransmission timeout | **~201 ms** | measured today, `../master_rto_20260916/RESULT.md` |
| the data plane's representable ceiling | 2.147 s | `D_A + CLRT_new < 2^31` ns, from the expiry test |

For a duplicate to arrive while a transaction is live, the live window must exceed the interval
after which a copy of the response appears. **2.97 s is not that interval**, and an earlier version
of this note wrongly used it: the 2026-09-15 duplicate trace happened to show its first copy after
2.969 s, but the 2026-09-16 master capture contains a copy **0.793 s** after the original, and its
shortest gap between successive copies is the same 0.793 s. Copies are not governed by one relay
timeout: several of these follow the master's own repeated requests, which the relay answers
again, so the governing interval is whatever is shortest in the deployment rather than a single
measured timer.

Taking the shortest interval in the evidence, 0.793 s, against the largest live window the control
plane will configure, 44 ms at the 40 ms clamp with a 4 ms target, the required condition is still
off by a factor of about **18**. The margin is smaller than the earlier note claimed and it is
still large.

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

**Narrowed, not proved.** On the evidence available, no configuration the control plane will
accept produces a live window within a factor of 18 of the shortest observed interval to a
response copy, so `OUT_RESP_DUP_SUPP` discarding a loss-recovery copy is not something this
deployment's settings can produce. That is an argument from three numbers and the shortest copy
interval anyone has happened to observe, not a proof that no shorter one exists. Network
duplication and loss recovery are not bounded by a single measured timeout.

**The live window is also not exactly `D_A + CLRT_new`.** That sum is the nominal schedule. The
transaction's actual lifetime is set by the program's retirement paths, which
`CORRECTION_20260916.md` §6 describes: the released response or the fail-open budget, the latter
counted in blocker passes rather than time. The 44 ms figure above is therefore the nominal
window at the largest configurable hold, and it is used here as an order-of-magnitude comparison
rather than as the lifetime.

**And it does not cover every duplicate path.** The OPERATE spent-marker behaviour identified in
the 2026-09-16 review is not bounded by the live window at all: the marker persists after the
command has been released and is cleared by the next SELECT, so a master retransmission of a lost
OPERATE can meet it long after any hold has ended. That path is separate from this one and is
recorded in `../OPERATE_RETRANSMISSION_RISK_20260916.md`.

**Not resolved in general.** This is an argument from three numbers, and all three are properties
of this deployment rather than of the design. A device whose retransmission timer were tens of
milliseconds rather than seconds would bring the two windows together, and then the drop would be
reachable and would need testing rather than arithmetic. The manuscript should continue to state
the separation of timescales as the reason the case does not arise, and to say that it is a
property of the evaluated relay.

**Still not demonstrated.** That a duplicate arriving inside a live window is in fact dropped. The
commit map says `OUT_RESP_DUP_SUPP : cmt_drop()`, and nothing observed here contradicts it, but no
capture in this repository exercises that path.
