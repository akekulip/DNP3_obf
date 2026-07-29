# Five-pilot port-shaper sweep — INVALID (no traffic reached the switch)

2026-07-29T00:53Z. 5 trials run, **0 completed, 5 INVALID, 0 error**. Defense 2 restored and
verified by the runner's own EXIT trap.

## Verdict: the experiment did not test what it was built to test

**Root cause: the Hulk↔dp11 link has no carrier, so the injected frames never entered the
switch.** This is upstream of the entire mechanism — it is NOT the shaper, NOT the scheduler,
NOT queue mapping, NOT DWRR, and NOT recirculation. Do **not** proceed to the `Q_GATE` fallback
on this evidence: that fallback exists for a shaper-boundary failure, and no shaper boundary was
ever exercised.

## The evidence chain

**Injection succeeded.** Every trial: `planned 130, sent 130`, randomized, seed recorded.
`CAP_NET_RAW` works; the injector is not at fault.

```
oracle_inject: trial 1: planned 130, sent 130 on enp59s0f0np0 (seed 3254779905)
```

**The gate armed correctly — and burst was NOT clamped.** This was the flagged risk and it
resolves favourably:

```
port gate readback dp8 (tf1.tm.port.sched_shaping + tf1.tm.port.sched_cfg)
  max_rate_enable=True  unit=PPS  provisioning=UPPER  max_rate=1  max_burst_size=0
PASS  gate still closed at preload check     True
```

`max_burst_size=0` was accepted and read back as 0. The concern that banked burst credit would
leak frames before release does not arise for this configuration.

**Nothing arrived.** All four queues, every trial:

```
FAIL  Q_ABLOCK demonstrably nonempty   usage_cells=0 watermark_cells=0
FAIL  Q_ACK    demonstrably nonempty   usage_cells=0 watermark_cells=0
FAIL  Q_RBLOCK demonstrably nonempty   usage_cells=0 watermark_cells=0
FAIL  Q_RESP   demonstrably nonempty   usage_cells=0 watermark_cells=0
```

`drop_count_packets = 0` on all four — the frames were not dropped by the TM, they never reached
it. The pcap fetch also failed on every trial, consistent with a capture that saw nothing.

**The link is dark**, confirmed directly on Hulk:

```
enp59s0f0np0  DOWN  3c:fd:fe:e5:f9:90 <NO-CARRIER,BROADCAST,MULTICAST,UP>
Speed: Unknown!     Link detected: no
```

## What this does and does not establish

**Established:** the injector and its capability work; the dp8 **port-level** shaper arms,
accepts `max_burst_size=0` without clamping, and holds closed across the preload window; the
occupancy and drop counters read correctly; and the transactional runner's restore path works
from a real failure, not just a rehearsal.

**Not established:** anything about dequeue ordering. The scheduler was never exercised.

## Why the link is down — the open question

The switch's 25 G fabric is healthy: dp9 (Vision) is `up` at `BF_SPEED_25G` in the pre-load
snapshot, so the pipe and optics path work for that port. The failure is specific to dp11/Hulk.
Candidate causes, in the order worth checking:

1. **dp11 may not be Hulk's port.** The dp9=Vision / dp11=Hulk mapping comes from project memory,
   and memory has already been wrong once in this session (it named the wrong switch restore
   target). This assumption has never been verified against the physical cabling.
2. **No cable, or a cable to a different dev_port.** Hulk's NIC has never linked in this session.
3. **Speed/FEC mismatch** — dp64 needed `1G / FEC_NONE / AN_FORCE_DISABLE` to come up, so a
   forced setting may be needed for dp11 too rather than the 25 G default.

Resolving (1) is cheap and does not need the oracle: configure candidate dev_ports one at a time
and watch which one makes Hulk's carrier appear.

## Restore

The runner's EXIT trap fired on a clean rc=0, detected the switch was NOT in the known-good state
(`prog='four_queue_oracle'`), performed a full relaunch, re-ran the Defense 2 control plane, and
verified:

```
PASS  p4_name                    dnp3_timing_normalizer_pktgen
PASS  strict_priority_verified   true
PASS  app_enable                 false
PASS  exactly one bf_switchd     1
```

dp11 returns to unconfigured automatically, since only the oracle's control plane ever configured
it. dp8's shaper is restored with the program reload; the pre-load snapshot recorded its original
state as `max_rate_enable=False, max_rate=25010000 BPS, burst=9216, BF_SPEED_25G` for
verification.
