# Historical versus corrected results

What this session re-derived, what it changed, and what it left alone. Written so that a
reader can tell a corrected number from an unchanged one without reading a diff.

**Headline: no published number changed.** Every quantity the manuscript reports was
re-derived and agrees. The corrections in this session are to descriptions, terminology and
provenance, plus a set of measurements that were never made before.

---

## 1. Published values against an independent re-derivation

`audit_current/tools/timeout_and_tcp_audit.py` carries its own pcap and TCP parser, written
from scratch, including the options field. It shares no code with
`evidence/campaign_v1/repro/pcap_dnp3.py` and no code with the scapy-based extractor that
produced the frozen table. Run over the same 132 captures:

| quantity | published | independent | agree |
|---|---|---|---|
| Timing OFF READ, released interval median | 2.1160 ms | 2.1160 ms | yes |
| Timing OFF READ, released interval max | 83.4579 ms | 83.4579 ms | yes |
| Timing OFF READ, request-to-ACK median | 0.5550 ms | 0.5550 ms | yes |
| Timing OFF SELECT, released interval median | 2.0499 ms | 2.0499 ms | yes |
| Timing OFF SELECT, released interval max | 24.8311 ms | 24.8311 ms | yes |
| Timing OFF SELECT, request-to-ACK median | 0.5550 ms | 0.5550 ms | yes |
| Timing OFF OPERATE, released interval median | 2.9374 ms | 2.9378 ms | yes, see §2 |
| Timing OFF OPERATE, released interval max | 24.2031 ms | 24.2031 ms | yes |
| Timing OFF OPERATE, request-to-ACK median | 0.5581 ms | 0.5581 ms | yes |
| Obfuscated READ, released interval median | 3.9999 ms | 3.9999 ms | yes |
| Obfuscated READ, released interval max | 57.1821 ms | 57.1821 ms | yes |
| Obfuscated READ, request-to-ACK median | 21.3361 ms | 21.3361 ms | yes |
| Obfuscated SELECT, released interval median | 4.0002 ms | 4.0002 ms | yes |
| Obfuscated SELECT, released interval max | 5.1498 ms | 5.1498 ms | yes |
| Obfuscated SELECT, request-to-ACK median | 21.2388 ms | 21.2388 ms | yes |
| Obfuscated OPERATE, released interval median | 3.9999 ms | 3.9999 ms | yes |
| Obfuscated OPERATE, released interval max | 5.6620 ms | 5.6620 ms | yes |
| Obfuscated OPERATE, request-to-ACK median | 20.6499 ms | 20.6499 ms | yes |
| captures | 132 | 132 | yes |
| exchanges | 63,360 | 63,360 | yes |

18 of 18 interval statistics agree, plus both corpus counts. The full pipeline was also re-run
end to end from the raw captures: 22 dataset manifests and 268 entries verified, 132 captures
validated with 0 problems, the 19-point sweep verified with 42 manifest entries and 0 problems,
131 tests passing, and the publication gate reporting 0 problems against every published
artefact.

The pipeline was run **twice**, into two fresh output directories, and the two runs agree byte
for byte on all 14 regenerated artefacts: the canonical transaction table, the per-capture
table, the validation report, the three sweep outputs, the statistics, the
shift-versus-replacement statistics, the leakage analysis and all four figure PDFs. The only
file that differs is `environment.json`, which records the git commit and whether the tree was
dirty, and those changed between the two runs. The PNG previews also matched, though the gate
does not require them to across interpreter builds.

The application-layer log was checked independently of both: 63,360 rows across the 22 grouped
runs, every row `valid = true` with `resp_func = 129`, all 5,280 SELECT and OPERATE rows
`status = SUCCESS`, and no row otherwise. The sweep's 5,860 published transactions were
reconciled by summing the 19 sweep point logs, which come to 5,860 exactly once the two restore
runs of 50 rows each are excluded.

## 2. The one difference, and why it is not a disagreement

Timing OFF OPERATE released interval median: 2.9374 ms published, 2.9378 ms independent, a gap
of 0.4 µs.

The sample has 2,640 values, an even count. The published pipeline takes the mean of the two
central order statistics, which is numpy's convention. The independent tool takes a single order
statistic. On an even sample the two differ by half the gap between the two central values.
Every odd-count and every max statistic agrees exactly, which is what that explanation
predicts. Neither is wrong; the published convention stands, and the independent tool's
convention is now stated in its own output.

## 3. Corrections that changed a description, not a number

### 3.1 The sweep's composition was misdescribed

`README.md` §3 said the sweep was "19 sweep captures (18 configured release policies and one
control)", and the claim–evidence matrix said "18-point hardware sweep".

The loaded binary arms a transaction only for `MODE_D4_DUAL`; every other mode falls through to
`OUT_ARM_BUSY` and forwards both packets unheld. The two points configured in modes D2 and D3
therefore measured native timing, 2.108 ms and 2.098 ms released interval with sub-millisecond
acknowledgment latency, where 24 ms and 20 ms holds were configured.

Corrected to **16 configured release policies, all in mode D4, and three native controls**. The
count of 19 stands. Claim C2 is unaffected: all eight points it quotes at fixed `D` = 24 ms are
D4. Derivation and consequences in `TIMING_ONLY_RERUN_PLAN.md` §2.

### 3.2 The test count was stale

Two documents said the reproduction runs 112 tests. It runs **131**. Corrected in
`README.md` and `defense4/timing/README.md`.

### 3.3 "Echo" survived in places the rename missed

The manuscript prose was corrected on 2026-09-02 and is clean. The word survived in
`defense4/timing/README.md`, `CLAIMS_AND_LIMITATIONS.md` and
`figures/schematics/README.md`, all now corrected to "the master-visible OPERATE
response-to-acknowledgment interval".

Two places are deliberately **not** corrected:

* `analysis/dnp3_timing.py` and `analysis/extract_sbo.py` read a frozen CSV column literally
  named `echo_ack_ms`. Renaming it would break reproduction of the retired dataset, so the
  column keeps its name and the mapping is recorded in `TIMING_MODEL.md` §6.
* The label text inside `fig_ladder.svg` and `fig_design.svg` still reads "echo". Correcting it
  changes manuscript Figures 1 and 3 and therefore `main.pdf`, so it is held in the proposed
  manuscript patch.

## 4. Measurements that did not exist before

None of these contradicts anything published; all are new.

| measurement | result |
|---|---|
| request and response retransmissions, all 132 captures, both arms | 0 and 0 |
| TCP resets, SACK blocks, duplicate acknowledgments | 0, 0, 0 |
| requests sent with earlier bytes still unacknowledged | 0 of 63,360 |
| acknowledgment of the request: standalone or piggybacked | 31,680 standalone per arm, 0 piggybacked |
| TCP options negotiated | MSS, window scale, SACK permitted, timestamps, both directions, all 132 |
| worst request-to-acknowledgment wait under the mechanism | 29.150 ms |
| worst request-to-response latency under the mechanism | 77.713 ms |
| release accuracy against the 4 ms target, median error | −0.0001 ms READ, +0.0002 ms SELECT, −0.0001 ms OPERATE |
| release accuracy, 99th percentile absolute error | 0.031 ms READ and SELECT, 0.029 ms OPERATE |
| exchanges whose release error exceeds 1 ms | 24 of 26,400 READ, 1 of 2,640 SELECT, 1 of 2,640 OPERATE |
| delay added beyond the configured acknowledgment offset | +0.781 ms READ, +0.684 ms SELECT (read lane, relay latency subtracted), +0.650 ms OPERATE (control lane) |
| interval from SELECT response to OPERATE send, at the master | 0.190 ms median in both arms |
| SELECT sent to OPERATE sent | 2.990 ms Timing OFF, 25.602 ms Obfuscated, max 29.968 ms |
| whole SBO at the master | 6.665 ms Timing OFF, 50.425 ms Obfuscated, max 58.934 ms |
| `NO_SELECT` statuses in 2,640 obfuscated OPERATE exchanges | 0 |
| smallest obfuscated released interval | 3.922 ms, 78 µs under target, no left tail |
| released interval on the 493 obfuscated READ exchanges with request-to-ACK above 25 ms | median still 4.000 ms, with request-to-response rising to 29.491 ms |

The last two matter for the mechanism claim. A common-anchor design predicts that a late anchor
moves both release instants together and leaves their difference untouched, and that is what the
data show. The prediction that would have shown the opposite, contention delaying only the
acknowledgment past its own deadline and shrinking the interval below `D_R`, left no visible
trace: see `TIMING_MODEL.md` §4.

## 5. A provenance gap this session found

Configuration readback evidence for `campaign_v1` is one `RESULT:` line per block, captured by
`campaign_block.sh` piping `configure-all` through `tail -1` into `_bin/campaign_5h.log`.

* That log holds **128** block headers and 128 `cfg: RESULT: PASS (n_fail=0 n_warn=0)` lines,
  and 128 `shape0: RESULT: PASS` lines.
* It covers **s02 through s22 only**. Session s03 appears twice: its first attempt was
  interrupted after two blocks and relaunched from b1 with identical seeds, which accounts for
  the two extra headers. The retained captures are from the second attempt.
* **s01 has no archived readback line at all.** Its six blocks ran before the log was opened,
  and its `MANIFEST.json` asserts *"RESULT: PASS (n_fail=0 n_warn=0) for both arms"* as text
  without a transcript behind it.

So the readback covers 126 of the 132 retained captures, as a single summary line each, never a
full transcript. This refines limitation L11 rather than contradicting it: configuration
provenance stays **PARTIAL**, and now for a stated reason. §4.5 of the rerun plan archives the
full transcript per block so a future run does not inherit this.

## 6. What is not resolved

| item | status |
|---|---|
| the master's realized TCP retransmission timeout | **UNRESOLVED**: kernel version and sysctls were never archived |
| the relay's select-validity window | **UNRESOLVED**: the setting was never read back |
| whether the relay retransmitted a held response | **UNRESOLVED**: the switch suppresses a position-matched duplicate, so it cannot be excluded master-facing |
| the switch's own release instants `e_a`, `e_r` | **UNRESOLVED**: never captured; the program latches them but the preserved control plane reads only four of six timestamp registers |
| the realized per-transaction `J`, relay-facing release, exactly-once delivery | **UNRESOLVED**: no relay-facing tap exists |
| physical operation time | **NOT MEASURED**, and no measurement of it is proposed |
| the 0.78 ms excess over the configured offset | **PARTIAL**: measured, but not attributable to the switch or the host path without `e_a` |
| configuration provenance | **PARTIAL**, refined in §5 |

No claim was newly blocked by this session, because no published number moved. Two claims are
newly **bounded**: the sweep's policy count, and the fact that no fixed-shift arm exists on this
hardware, which makes the analytical constant-shift reference the only shift comparison
available rather than one choice among several.

## 7. Provenance of this document

Every value above comes from one of: `audit_current/outputs/timeout_and_tcp_audit.json`,
regenerated 2026-09-07 from the 132 raw captures; a full run of
`evidence/campaign_v1/repro/reproduce.sh`, 0 problems, 131 tests, gate clean, on the same day;
`paper/rewrite/figures/ndss/MANUSCRIPT_VALUES.json` as published; the application-layer logs
under `evidence/campaign_v1/s[0-9][0-9]/app_jsonl/`; `evidence/campaign_v1/_bin/campaign_5h.log`
and `sweep/sweep_points.csv`; and the frozen source at
`implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`, sha256 `7ce30494…`,
quoted by line.
