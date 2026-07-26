# SUPERSEDED — preserved for research history only

This is the v1 live-inline timing bundle, frozen exactly as it stood on 2026-07-25 at commit
`ead6b00`. It is kept because the underlying experiment is real and the mechanism is sound, and
because a failed or flawed artefact should be diagnosed rather than deleted.

**Do not cite any statistic, figure or claim from this directory.** It contains unreconciled
datasets and several statements that do not survive verification. Use
`meeting_package/timing_inline_v2/` instead once the corrected campaign completes.

## Why it is superseded

**Two incompatible datasets are quoted as if they were one.** The report headline uses
n = 13/13, native sd 9.514 ms, native max 37.215 ms, "329x tighter". The pcaps actually shipped in
`evidence/` are a different campaign, n = 10/11, native sd 6.261 ms, "224x tighter". Both campaigns
are real, but the bundle pairs the numbers of one with the evidence of the other, so no figure in
it can be checked against its own data. The missing pcaps have since been recovered and both
campaigns are preserved in `evidence/corrected_v2/pcaps/`.

**The terminology is wrong.** CLRT is *Cross-Layer Response Time* (Formby et al., "Who's in
Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems", NDSS 2016).
This bundle expands it as "Command Loop Response Time" throughout.

**The Tofino explanation is wrong in a way that matters.** Statements like "a Tofino has no notion
of later", "no timer to arm" and "no queues" are false. The Traffic Manager buffers and schedules
packets normally. What P4 ingress cannot do is request "release this queued packet at time T". The
mechanism controls scheduling *eligibility* indirectly, and that indirection is the actual novelty.
The v1 wording obscures the contribution by overstating the constraint.

**Claims exceed what the data supports.** "CLRT = G exactly", "every transaction looks the same",
"carries no information" and bare "entropy 0.000 bits" are stated without tying them to an observer
resolution. At finer resolutions the protected distribution is narrow, not degenerate.

**Provenance is contradictory.** The canonical P4 source header (line 8) reads "compile-only, never
loaded" while the report states the same source SHA was compiled and loaded. Both cannot be true.

**The token-isolation test is vacuous.** Captures were taken with the filter
`host 192.168.10.7 and tcp port 20000` and then searched for EtherType `0x88C1`. That filter
excludes blocker frames by construction, so the test could not have failed.

**Blocker tokens are host-seeded.** The 64 tokens are injected from the master host over an
external link. Any claim of "no external blocker traffic" is therefore unsupported for this build.

**Live byte identity is not proven.** v1 says so in its limitations section, which is correct, but
the surrounding prose ("byte for byte the packet the relay sent") reads as if it were proven.

**Port roles are not separated.** One binary accepts both `dp11` (replay injector) and `dev_port 64`
(live relay) as outstation ingress, leaving an undocumented state-injection path in live mode.

## What in here is still trustworthy

The mechanism, the topology, and the single-path proof. The relay leg was genuinely disabled and
the master genuinely lost the relay (0/3, 100 % loss), which establishes that the switch was really
inline. The direction of the effect is not in doubt: the protected distribution is dramatically
narrower than the native one. What is in doubt is the exact magnitude, the sample count, and every
claim about resolution, isolation and provenance.
