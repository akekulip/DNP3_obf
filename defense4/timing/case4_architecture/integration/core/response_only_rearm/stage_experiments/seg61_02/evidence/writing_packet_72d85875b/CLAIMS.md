# Claims to evidence (directive 72d85875b, night of 2026-10-15/16)

This sheet says what the retained evidence lets the paper state, what it does not, and the one experiment
that would close each open item. Tables and figures beside it are regenerated offline by
`python3 defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/writing_packet.py`
(see `evidence_index.json`). Nothing here edits `paper/rewrite/`.

## Candidate identities

| name | source sha256 | status |
|---|---|---|
| m5_10 | `b758c98199dddd36f8df4a90ce7a1e2301b63e95c2ac766aafa20b5b9f15e981` | compiled (9.13.1, 9.13.2, N12/E12/T11), model suite passed, 14 silicon blocks plus one isolation block retained |
| m6_07 (successor) | `3335479b45a9e6b0867df3eadcb6d055c31bd6c49b14f0d4d6bdcec464b0e142` | source tests and compile pass; model: all drivers pass except contention 240/241 (a retried SELECT response lost with no counter; `model.csv`); **not frozen, no silicon run** |

Every silicon result below belongs to m5_10. None of it qualifies m6, whose dataplane differs in N.

## What can enter the paper (scoped to the tested profile)

Scope for every row: software endpoints on Vision (OpenDNP3 4648fcb8), one protected connection on the
tested tuple, the 61-octet READ (23 G10V2 flags in three ranges) and SBO (three transport segments in
one TCP payload) encodings, 950 us target CLRT, Tofino-1. Not the physical relay, not other READ sizes,
not arbitrary masters.

1. **Encoding and delivery.** Each m5 block that completed recorded exact READ values and SBO echoes,
   complete CRC and checksum checks and single callbacks. The committed-release counts match the
   exchange counts. Evidence: `qualification_table.md` rows marked PASS and their run directories.
2. **Timing objectives where they passed.** In repeated-SBO qualification b1 and characterization b1,
   READ, SELECT and OPERATE have nearest-rank p99 and maximum absolute CLRT error at or below 52 us
   (`timing_errors.csv`). With 64 or 65 samples per kind, the nearest-rank p99 equals the maximum, so
   the two columns agree.
3. **Piggyback latency.** Piggyback qualification b1 to b3 qualified in every arm.
4. **Recovery.** For m5_10, graceful and RST persistence, protected reconnect, held OPERATE (`_02`) and
   seven single-loss trials passed their recorded checks. The single-loss trials are measurement only,
   not precision qualification.
5. **Cost.** Internal work per exchange is in `costs.csv` (loop-port frames and octets, re-waits, pktgen
   seeds), and external growth per kind is in `external_growth.csv` (+12 octets READ, +24 SELECT and
   OPERATE). An arm with a failed precision gate reports a measured cost, not an accepted configuration.
6. **Design of the m6 corrections.** The paper can describe the m6 corrections as design and
   implementation, with source and model evidence only (`ctl_timing_01/DESIGN.md`, m6 section):
   reset validated by exact SEQ while a response is held, retry authority cleared only by the
   incarnation that closed, and duplicates of a held response gated through T.

## What is not supported

| claim | status | why | single next experiment |
|---|---|---|---|
| m5 meets the 100 us p99 bound in every repeated-SBO block | FAIL | b2 and b3 SELECT p99 920 and 917 us (one index-127 exchange each); char b2 SELECT 922 us; char b3 READ 1,142 us. Origin unresolved, not excluded | capture switch-ingress and host timestamps for the index-127 exchange in a matched block, to locate the delay before deciding anything |
| retried responses are never lost silently | OPEN (model) | m6_07 contention `sweep_SELECT_000ms`: 3 retry laps, then no release and no fallback for the response; passed on m6_05/m6_06 | classify where a retried response goes when it outlives T's ACK deadline, on the model with per-pass tracing |
| m6 qualified on silicon | PENDING | no m6 hardware ran: the hour-5 gate passed without a reviewed successor | the 14-block qualification set on m6_07 after a final review of its N diff and a fresh model suite, same configs on a new port range |
| N's retry path exercised on silicon | PENDING | retry laps were 0 in every silicon run; the contention probe exists offline only and its judge is under repair | the reviewed probe on a synthetic tuple, with connection rows installed for it under a recorded authorization |
| quiet new-incarnation isolation | FAIL (m5_10, `ctl_m5_stale_iso20_950_01`) | delivery was correct (c1–c3 ok, 9 commit/release, no fallback) and the permit gate worked, but 2 of 7 old READ tokens were rejected only after the pause and 2 STALE_BLOCKER rejections fell in new traffic (13 vs bound 12). The drain test proves that tokens have left the generator, not that they have been rejected inside the pipeline | make the drain test require the raw timer-stale counters to reach the population before granting the permit, attribute STALE_BLOCKER by connection, then one block |
| active-traffic isolation | PENDING | source and model only | a pre-configured pktgen schedule that overlaps c2 traffic, one bounded attempt |
| outstation RST reaches the master while T holds a response | not provided | E drops it on m5 and m6 alike (source) | decide whether the reset should be forwarded; source test first |
| classifier defeat | not evaluated | no attacker evaluation exists on any case4 build. The published classifier results (campaign_v2) are for the earlier timing-only build on the physical relay. Uniform lengths plus normalized CLRT alone do not establish classifier defeat | a separate evaluation item: the campaign_v2 Random-Forest pipeline on captures from a qualified case4 build |
| exactly-once delivery | not claimed | outside the evidence (see `CLAIMS_AND_LIMITATIONS.md`) | none tonight |
| ACK_HOLD 14,892 PPS shaping | experimental | correctness not passed (shared timing outlier); S5 held | the three order-balanced matched pairs, only after the successor's correctness and precision pass |
