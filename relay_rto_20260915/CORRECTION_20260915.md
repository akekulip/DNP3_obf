# Correction note: this diagnostic ran with the size-shaping datapath active

Written 2026-09-15, after the captures. It sits **outside** the checksummed record on purpose.
`README.md`, `SHA256SUMS`, the two pcaps and `rto_probe.py` are unchanged and still verify; no
checksum has been recalculated. Read this note alongside that README, which remains accurate
about everything except the point below, which it does not mention because it was not known
when it was written.

## What is wrong with the original account

The README describes the two runs as the Timing OFF and Obfuscated arms. That is correct about
the **timing mode**, which was set by `--mode OFF` and `--mode D4`. It is incomplete about the
rest of the configuration: **both runs also had size shaping enabled, and the campaign did not.**

## The evidence

`defense4/timing/PROVENANCE.md` establishes the rule from the wire: `shape_set.py` documents
that `shape=1` splits a response into 28 and 21 byte segments, while `shape=0` passes it as a
single 49-byte payload. Counting relay-to-master payload lengths:

| capture | payload lengths | implies |
|---|---|---|
| `campaign_v1/s01/raw_pcaps/s01_b1_native.pcap` | 49 x 480 | `shape_enable = 0` |
| `campaign_v1/s01/raw_pcaps/s01_b2_obfuscated.pcap` | 49 x 480 | `shape_enable = 0` |
| `relay_rto_timing_off.pcap` | 28 x 4, 21 x 4 | `shape_enable = 1` |
| `relay_rto_obfuscated.pcap` | 28 x 4, 21 x 4 | `shape_enable = 1` |

## Why it happened

`implementation/control/defense4_rrc_bor_unified12_setup.py` ends a successful `configure-all`
with `set_shape_enable(..., on=True)`. The campaign did not leave it there: each block's
`provenance/MANIFEST.json` records `shape_note = "configure-all leaves shape_enable=1; each
block then forces shape_set.py 0"`. This diagnostic ran `configure-all` and did **not** perform
that second step, so it kept the setup's default rather than the campaign's configuration.

That is the defect the correction pass addresses by building a timing-only activation path which
never enables shaping at any point, rather than enabling it and switching it off afterwards.

## What it does and does not affect

**Unaffected.** The retransmission timeout itself. The measured intervals of 2.9943 / 6.0004 /
12.0001 s in one run and 2.9598 / 6.0004 / 12.0000 s in the other are a property of the
SEL-751A's own TCP stack, which retransmits an unacknowledged segment on its own timer. Shaping
changes how the response is segmented on the wire, not when the relay's timer fires. The two
runs agreeing also still shows the mechanism does not acknowledge on the master's behalf.

**Affected.** Any statement that these captures were taken under the campaign's configuration.
They were not. In particular the segmentation differs, so these captures must not be used to
reason about response segment lengths, per-segment timing, or anything else where a split
response and an unsplit one behave differently. The retransmission unit here is a split
response; the campaign's is a single 49-byte payload.

**Still true.** No manuscript claim rests on this diagnostic. It is excluded by name in
`paper/rewrite/figures/clrt/clrt_source_manifest.json`, and the blocker-drain measurements in
`blocker_drain/` are unaffected by segmentation because they count loopback circulation inside
the switch rather than anything on the relay-facing wire.

## Not established by these captures

The first retransmission interval reads slightly under 3 s in both runs. These captures alone do
not explain that: the relay's timer starts when it queued the segment, which is not observable
from a master-facing capture, so the shortfall is consistent with that explanation but is not
demonstrated by it. Recorded as unexplained rather than attributed.


---

# Three further corrections to the original account

Added after the 2026-09-15 review. Same rule as above: the READMEs are checksum-covered and are
not edited, and no checksum has been recalculated. These correct claims made in
`README.md` and in `blocker_drain/README.md`.

## 1. The relay's timer is not the master's timer, and the 15x comparison is void

`README.md` says the control plane's guard band assumes `--tcp-rto-ms 200.0`, that the measured
value is 3000 ms, "a factor of 15 larger", and that this explains the campaign's lack of
retransmissions. **That comparison is invalid and is withdrawn.**

`implementation/control/parameter_policy.py` defines that constant as the **master's** minimum
retransmission timeout:

    # RTO floor: the master's minimum retransmission timeout. H must stay clear of it so a
    # late fail-open pre-empts, not collides with, the master's retransmission.
    RTO_MIN_MS_DEFAULT = 200.0

What this diagnostic measured is a different timer belonging to a different sender in the other
direction. The three constraints are separate:

| delayed packet | whose feedback is postponed | governing timeout |
|---|---|---|
| the outstation's ACK of a master request | the **master**, which sent the request | the master's TCP retransmission timer |
| the outstation's response awaiting the master's ACK | the **outstation** | the outstation's TCP retransmission timer, which is what these captures show |
| the response the application is waiting for | the master application | an application deadline, not a TCP timer |

A long relay timeout cannot show that the master tolerates a long ACK hold. The 200 ms guard is
not replaced, relaxed or validated by anything measured here, and **3000 ms must not be
substituted into it**. Establishing the master-side bound needs evidence from the master's own
DNP3 socket, time-aligned, which this diagnostic did not collect.

Zero retransmissions seen at the master also does not by itself exclude relay-side copies that
the switch absorbed, so it is weaker evidence than the README implies.

## 2. Three retransmission rounds, not four

`README.md` says the relay "retransmits its unacknowledged response four times". There are four
appearances in total: the original plus **three** retransmissions. The table in that README lists
the three correctly; the sentence above it miscounts them.

## 3. The blocker measurement is not epsilon

`blocker_drain/README.md` reports about 24.4 ms and 31.0 ms and calls the larger figure the time
to drain all blockers. What it actually measures is the **circulation and budget lifetime of the
reservoirs from the moment a transaction arms them**, which includes the intended hold. It is a
counter-based estimate, and a useful one, but it is not the quantity Dr. Lin asked for.

Epsilon is the interval **after the release deadline expires**: how long the blocker queue keeps
blocking a packet that is already due. Measuring it needs four events defined and recorded
separately, for ACK and for RESPONSE independently, which this experiment does not do:

1. the scheduled deadline;
2. the first blocker observation of expiry;
3. the last blocking action or termination;
4. the held packet's actual service or departure.

Two further limits on the reported numbers. The ACK and RESPONSE reservoirs share dp8 and its
priority scheduler, so a single dp8 counter cannot separate their two drains; only the RRC and
BOR **domains** were separated, which is a different split. And the 31.4 ms poll-bracketed span
sits between coarse samples, with the poller timestamping before a blocking gRPC read and
recording no completion timestamp, so its agreement with the 30.97 ms serialization estimate does
not establish sub-millisecond accuracy or continuous saturation.

**Epsilon therefore remains unmeasured on this build**, as it was before this diagnostic. The
on-chip timestamp registers that would measure it are declared and never executed, so it needs a
new instrumented build and a separately authorized experiment.
