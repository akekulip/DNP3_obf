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

## Evidence reconciliation verdict (§3) — both campaigns real, wrong pair shipped

Two live runs exist and **both sets of numbers are arithmetically correct**. The defect is that the
bundle quotes campaign B's numbers in prose while shipping campaign A's pcaps as evidence, labelling
neither.

| set | campaign | timestamps | shipped? |
|---|---|---|---|
| n=10/11, sd 6.261 -> 0.028 ms, "224x" | **A** | 17:55 / 18:02 | yes, as `native_inline2` / `prot_inline` |
| n=13/13, max 37.215 ms, sd 9.514, "329x" | **B** | 18:16 / 18:22 | **no — never shipped** |

Until recovered this session, every campaign-B number in the published report was unsupported by any
pcap shipped with it. The 37.215 ms sample is genuine: `campaignB_native_n13.pcap`, ACK frame 5 ->
RESPONSE frame 6, transaction 0, exceeding G by 12.215 ms.

### ★ The headline ratios are dominated by ONE cold first poll (independently re-verified)

| campaign | txn0 (cold) | native sd all | native sd excl. txn0 | published ratio | ratio excl. txn0 |
|---|--:|--:|--:|--:|--:|
| A | 22.660 ms | 6.261 | **1.008** | 224x | **34.5x** |
| B | 37.215 ms | 9.514 | **2.320** | 329x | **80.3x** |

The steady-state improvement is real and still large, but it is 4-6x smaller than published. Any
headline quoting 224x or 329x without stating that a single connection-cold transaction drives it is
an overclaim. **Worse: `run.sh` fires a warm-up poll but `clrt.py` then counts it**, so the very
transaction the harness meant to discard is contaminating the statistics.

### ★ "entropy 0.000 bits" is FALSE on the shipped evidence

Running the bundle's own `clrt.py` unmodified on the bundle's own shipped pcaps prints:

```
  campaignA_protected_n11.pcap
    observer view @ 1 ms bins: 2 occupied, entropy 0.439 bits
```

Campaign A's protected minimum is 24.998041 ms, which straddles the 1 ms bin edge, so it occupies
**two** bins. The published "1 occupied bin / 0.000 bits" came from campaign B, whose pcaps were
never shipped. Campaign B itself only reaches zero entropy at bin widths >= 100 us (0.8905 bits at
50 us, 2.6235 bits at 10 us). Every unqualified "entropy 0", "carries no information" and "every
transaction looks the same" must go.

### Other confirmed defects

- **"329x" is a rounding artifact.** Exact-pairing gives 328.5052. (My independent naive-pairing
  pipeline gives 329.0989 — the pipelines disagree slightly, which is itself evidence for F4 below.)
- **"Every protected transaction lands on G"** is false: campaign A txn 6 measures 24.998041 ms,
  below G.
- **`interactive.html:169` "eleven samples occupy six 1 ms bins"** describes no real series. It pairs
  campaign A's protected n with campaign B's native bin count.
- **F1 — arms not like-for-like.** Campaign A polled at different rates per arm: 300.436 ms native
  vs 400.451 ms protected. Campaign B matched at ~400.43.
- **F3 — the >G pass-through failure has NEVER been observed under protection.** No protected
  transaction anywhere exceeds 25.0826 ms, and a hold cannot pull 37 ms back to 25, so the relay was
  not in a matched state across arms. The low-G miss is a prediction from source, not an observation.
- **F4 — `clrt.py:42-58` pairs by positional adjacency**: no seq/ack check, no SYN/FIN/RST exclusion,
  no stream awareness, no function-129 check. It was right here by luck of clean captures, which is
  exactly what §10 forbids.
- **F6 — outstation DNP3 link address is 0, not 10.** `CLAUDE.md:134` states 10 and is wrong
  (CRC-validated from the wire).

### Integrity that DOES hold across all four captures

0 retransmissions, 0 duplicate ACKs, 0 reorders, `tcp.analysis.flags` empty, all DNP3 CRCs valid,
every response `tcp.len=54` / `ip.len=106` / `frame.len=120`, single TCP stream per capture, clean
FIN close, 0 RST.
