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
