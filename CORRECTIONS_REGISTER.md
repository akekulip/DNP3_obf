# Corrections register — v1 -> corrected v2

Every item is a defect confirmed by direct verification this session, not inherited from a prior
report. "Evidence" is the check that established it. Status is DEFECT CONFIRMED until the fix is
implemented AND verified on silicon.

| # | Directive | Defect | Evidence | Status |
|---|---|---|---|---|
| 1 | §3 | Report quotes n=13/13 (sd 9.514, max 37.215, "329x") but the bundle ships the n=10/11 pcaps. Numbers and evidence come from different campaigns. | Both pcap pairs located and hashed; only campaign A was in `evidence/` | CONFIRMED, both recovered |
| 2 | §4 | CLRT expanded as "Command Loop Response Time". Correct term is **Cross-Layer Response Time**. | Formby et al., NDSS 2016 (primary source, verified this session) | CONFIRMED, 4 files |
| 3 | §5 | "no notion of later", "no timer to arm", "no queues" are false; the TM buffers and schedules normally. | Contradicted by the mechanism itself: the response IS queued in the TM | CONFIRMED, 5 files |
| 4 | §6 | Canonical P4 header line 8 says `compile-only, never loaded`; the same source IS loaded. | RESOLVED: stale inherited boilerplate. Same string appears in 7 genuinely compile-only files of the `stage_reclamation/variants/` lineage; header was copied from the predecessor and line 2 still names the predecessor's filename. Artifact chain proves LOADED. | RESOLVED — header must be corrected, see note below |
| 4b | §6 | v1 wording implies the two compiler builds are interchangeable images ("no version drift"). | **Independently verified: NOT byte-identical.** local 9.13.1 `tofino.bin` `3b6ee6d7…` vs switch 9.13.2 `180e44aa…`; 34 differing bytes (23 metadata + 11 in config-register payload). MAU footprint IS equal (10/12 stages, 60 tables, 55 SRAM, 1 TCAM). | CONFIRMED — say "equivalent MAU footprint, not byte-identical images" |
| 5 | §7 | One binary accepts BOTH `PORT_HULK` (dp11) and `PORT_RELAY` (64) as outstation ingress -> undocumented state-injection path in live mode. | parser select, `dnp3_timing_normalizer_inline.p4:302-306` | CONFIRMED |
| 6 | §8 | Blocker reservoir is host-seeded: 64 `0x88C1` frames injected from the master over an external link. Any "no external blocker traffic" claim is unsupported. | `poll.py` builds and raw-sends tokens on `enp59s0f0np0` | CONFIRMED |
| 7 | §9 | Token-isolation test was vacuous: capture filter `host 192.168.10.7 and tcp port 20000` excludes `0x88C1` by construction, then the pcap was searched for `0x88C1`. | capture cmd in `run.sh`; filter cannot match ethertype | CONFIRMED |
| 8 | §13/§23.7 | "54-byte responses/frames" conflates layers. Measured: `frame.len=120`, `ip.len=106`, `tcp.len=54`. 54 is the TCP payload. | tshark on `prot_inline.pcap` | CONFIRMED |
| 9 | §18/§23 | "entropy 0.000 bits", "carries no information", "every transaction looks the same" stated without an observer resolution. | claim appears in 7-8 files with no resolution qualifier | CONFIRMED |
| 10 | §19 | "CLRT = G exactly" ignores quantisation, deadline-recognition latency, reservoir termination latency, scheduling and timestamp noise. | protected spread is 25.003-25.083 ms, i.e. not exact | CONFIRMED |
| 11 | §12 | G-selection guard exists in source (`meta.protection`, `native_clrt`) but it was never proven to have executed in the loaded artifact. | guard scratch fields present in parser; no silicon evidence collected | UNVERIFIED |
| 12 | §14 | Live byte identity not proven; v1 prose implies it ("byte for byte the packet the relay sent"). | relay leg cannot be tapped; no before/after mirror was taken | CONFIRMED |
| 13 | §15 | Native and protected runs used different connections, cadences and sample counts; no interleaving. | campaign A vs B differ in n and invocation | CONFIRMED |
| 14 | §16 | The 22.66 / 37.22 ms observations were treated as outliers to warm away rather than characterised. | `run.sh` fires an undocumented warm-up poll | CONFIRMED |
| 15 | §17 | Campaign n is 10-13, far below the required >=100. | all four pcaps | CONFIRMED |

## Terminology fixed to

- **CLRT = Cross-Layer Response Time**, defined here as `t(DNP3 RESPONSE) - t(qualifying pure TCP ACK)`,
  observed at the master-side capture point on Vision `enp59s0f0np0`, host pcap timestamps.
  Primary source: Formby, Srinivasan, Leonard, Rogers, Beyah, "Who's in Control of Your Control
  System? Device Fingerprinting for Cyber-Physical Systems", NDSS 2016, which measures
  "the amount of time between the TCP ACK and the time when each response appears for every read
  request".

## Correct Tofino framing (replaces the "cannot hold packets" wording)

The Traffic Manager buffers and schedules packets. What P4 ingress cannot express is
"release this queued packet at absolute time T". The mechanism therefore controls scheduling
*eligibility* indirectly: the original RESPONSE stays queue-resident in a low-priority queue, a
high-priority internal blocker reservoir denies that queue service, and when the blockers terminate
on an ACK-relative deadline the RESPONSE becomes schedulable. The blockers traverse the loop; the
original RESPONSE does not. The novelty is indirect data-plane-controlled release of a
queue-resident packet, not the existence of buffering.

## Provenance verdict (§6) — chain complete and unbroken

Source `fb3b10dad575bed4…` holds a **five-way match**, independently re-verified: repo canonical,
`deliverables/`, `archive/`, the `P4_SRC_SHA256` pin in `lab.env.inline`, and the staged copy on the
switch. Both builds were tied to the source *text* (not just the filename) by reconstructing the
compiler's preprocessed `.p4pp` from its `#line` markers; the switch build has a third tie, its
compile log cites `dnp3_timing_normalizer_inline.p4(269)/(267)` and those lines match. The loaded
conf references the **switch 9.13.2 build only**; `tofino.bin` mtime==ctime equals the build
manifest's `build_date`, 7m34s before `bf_switchd` PID 228141 started. Exactly one bf_switchd, no
reload since.

**Header fix required, with a trap.** Line 2 should name the inline file; line 8 should record the
actual load. But editing the file changes its sha256, which is pinned in `lab.env.inline`, quoted in
the report, and matches the staged switch copy. The edit must be done together with re-pinning
`P4_SRC_SHA256`, re-staging the switch copy, and updating the report — otherwise fixing the comment
is what breaks the five-way match.

**UNPROVEN and carried forward:** the 11 differing config-register payload bytes are consistent with
the deparser FDE/POV delta (26→25 entries, POV 10→9) but were NOT shown to be semantically inert;
that needs a Tofino register-map decode. Also, no local compile log exists for the inline build
(`p4/compile.log` names a different program and predates the build by ~5 h), so local success rests
on `manifest.json compilation_succeeded: true` plus a complete artifact set.
