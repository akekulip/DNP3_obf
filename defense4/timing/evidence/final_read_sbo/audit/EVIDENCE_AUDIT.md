# Evidence audit — timing captures of 2026-08-13

What this document does: establish, for every capture behind the timing results, where it
came from, what the switch was configured to do while it was taken, and how far that can be
proved. Everything below was checked against the files, not read off a filename.

Audit performed 2026-08-24 on branch `cleanup/timing-read-sbo-20260824`, forked from
`8a6896e` (the tip of `origin/defense4-size-native-parity-crc-split`).

---

## 1. The frozen package verifies

`defense4/size/native_parity/evidence/E_FINAL/MANIFEST.sha256` lists 63 files. All 63 hash
correctly. The only file in the tree not covered by the manifest is the manifest itself, so
coverage is complete: 64 files, 63 hashed, 0 unaccounted.

The second copy at `defense4/defense4_release/evidence/E_FINAL/` is not merely equal file
by file — it is the **same git tree object**, `1d1a5f3c94cf8d34c1b390baa1c921e47cdbc79c`.
Two paths, one tree, therefore byte-identical recursively by construction. It was created
on 2026-08-14 by the release-packaging commit `8a6896e`; the original is the
`native_parity` copy, first committed 2026-08-13 by `fc20528`.

## 2. Which captures belong to the timing result

The E-phase captures were taken in one session on 2026-08-13 between 19:49 and 19:57 local
time (UTC−4). Times come from the capture files themselves.

| capture | start (local) | duration | requests | belongs to timing? |
|---|---|---|---|---|
| `off_probe.pcap` | 19:49:47 | 0.12 s | 8 READ | no — see §3 |
| `e1_native.pcap` | 19:53:36 | 7.98 s | 1000 READ, 489 SELECT | yes |
| `e2_def.pcap` | 19:54:19 | 15.20 s | 500 SELECT | yes |
| `e2_def_read.pcap` | 19:55:31 | 15.04 s | 600 READ | yes |
| `sbo_j2.pcap` | 19:56:33 | 5.13 s | 30 SELECT, 30 OPERATE | yes |
| `sbo_j6.pcap` | 19:56:44 | 5.21 s | 1 READ, 30 SELECT, 30 OPERATE | yes |
| `sbo_j12.pcap` | 19:56:56 | 5.14 s | 30 SELECT, 30 OPERATE | yes |
| `e1_native_size_shapeoff.pcap` | **14:31:40** | 2.50 s | 100 READ | no — see §4 |

Every request in all six timing captures has both an ACK and a response. There are no
unmatched requests, no missing ACKs, and no missing responses anywhere in the set. The
per-capture accounting is in `../CAPTURE_MANIFEST.csv` and `../CAPTURE_MANIFEST.json`.

`sbo_j6.pcap` contains one stray READ transaction alongside its 30 SELECT and 30 OPERATE
transactions, and one 58-byte response. It is a leftover poll from the preceding run. It is
counted, reported, and excluded from the OPERATE analysis, which selects function 4 only.

## 3. `off_probe.pcap` is excluded

Eight READ transactions over 0.12 s, with a CLRT median of 1.24 ms and one outlier at
93 ms. No result in the frozen package depends on it: the only references to it anywhere in
the repository are the three `MANIFEST.sha256` files that list it. It is a warm-up probe. It
stays in the archived E_FINAL package and is not carried into the active timing tree.

## 4. `e1_native_size_shapeoff.pcap` is a size capture, and it is misnamed

This file is byte-identical (sha256 `e79e5e9f…`) to
`hw_campaign_20260813T172014Z/phase6_h1/h1a_defoff_100.pcap`, whose run log opens with
"H1(a) 100 READs (**size** defense OFF)". "Def off" in that log means the size carve was
off, not the timing defense.

Measured directly from the file, its CLRT median is **4.000 ms with a standard deviation of
0.009 ms** — the defended value. The timing defense was active while it was captured. It is
therefore not a native-timing baseline and cannot be used as one. It supports only the size
claim, where it shows the relay's unshaped 49-byte response. It is excluded from the timing
tree.

It also differs from the E-phase session in two other ways: it was taken at 14:31, five
hours earlier, and it carries TCP timestamp options, which the E-phase captures do not.

## 5. `shape_enable` during the timing captures — resolved

This was the open question. It is now settled by direct observation rather than by
configuration log.

`hw_campaign_20260813T172014Z/tools/shape_set.py` documents the semantics in one line:
"shape=1 -> responses split [28,21] via PRE; shape=0 -> native pass-through (no replicas)".

Measured response segmentation, from the captures:

| capture | response payloads on the wire | `shape_enable` |
|---|---|---|
| `e1_native.pcap` (native timing) | 1489 × 28 B and 1489 × 21 B | **1** |
| `e2_def_read.pcap` | 600 × 28 B and 600 × 21 B | **1** |
| `e2_def.pcap` | 500 × 28 B and 500 × 21 B | **1** |
| `sbo_j2/j6/j12.pcap` | 60 × 28 B and 60 × 21 B each | **1** |
| `e1_native_size_shapeoff.pcap` | 100 × 49 B | 0 |

**The answer is outcome 2 of the three the audit allowed: `shape_enable` was 1.** Size
processing was present during every timing capture.

The consequence is better than it first looks, and it needs stating precisely. Size shaping
was on in **both arms** of the timing comparison — the native baseline and the defended
runs. It is a held constant, not a confound between arms. The native-to-defended change in
CLRT is therefore attributable to the timing-mode toggle, which is the only thing that
differed.

What cannot be claimed is that the native CLRT figures are the relay's unmodified native
CLRT. They are the relay's CLRT measured through a datapath that was splitting and
reordering its responses. No capture in the frozen package has both interventions off, so
the relay's untouched CLRT is not available from this evidence. §9 says what a clean
timing-only capture would require.

## 6. The readback that reports `RESULT: FAIL (n_fail=1)`

`readbacks/hw_config_readback.txt` ends with `RESULT: FAIL (n_fail=1 n_warn=0)` while every
one of its 25 assertion lines is `[ok]`. That is internally inconsistent, and the
inconsistency is in the file, not in the reader.

The checker that produces these lines is `Checks.render()` in
`defense4_rrc_bor_unified12_setup.py`. It prints **every** row it holds, including any row
recorded by `Checks.fail()`, which is rendered as `[FAIL]`. A run with `n_fail=1` must
therefore print a `[FAIL]` line. This file has none, anywhere.

What the file actually is:

* 21 of its 25 rows appear **verbatim** in
  `hw_campaign_20260813T172014Z/phase8_closeout/final_configure_all.txt` — the deadline
  admissibility, tick-quantization, J-codebook and TCP-timestamp-policy assertions. That
  run is 129 lines and ends `RESULT: PASS (n_fail=0 n_warn=0)`.
* The remaining 4 rows (`reg_bor_epoch = 0`, `reg_bor_ready = 0`, `reg_bor_gen = 205`,
  `reg_bor_topj = 3283713`) appear in no archived log and are not in the format
  `Checks.render()` emits for a checked value. `reg_bor_gen = 205` is a post-run counter
  value, so these were read back **after** the OPERATE batches, not during configuration.
* The file lacks the `==== configure-all readback ====` header that every genuine run
  transcript carries.
* It was committed once, by `fc20528`, and never edited.

So the file is a hand-assembled excerpt combining a configure-all readback with a later
register readback, and its `RESULT:` line does not belong to the rows above it. Whatever
assertion failed was not captured into this file, and no archived log in the repository
records a run with `n_fail=1`. Every configure-all transcript that does exist reports
`n_fail=0`, except one mid-campaign retry that reports 28 failures and was followed by a
successful reload.

**The frozen file has not been edited.** It is preserved exactly as committed.

**Status: the configuration proof for the E-phase is PARTIAL.** The failing assertion cannot
be identified from the archived material. What can be said is narrower and worth stating:
the substantive configuration facts the timing claims rest on — the A and R deadlines, their
quantization, the J codebook entries, and the TCP-timestamp policy — are all present as
`[ok]` rows and are matched verbatim to a configure-all run that passed with zero failures;
and `shape_enable`, which this readback never covered at all, is established independently
in §5 from the captures themselves. The unidentified failure cannot be ruled out, and it is
recorded here rather than explained away.

## 7. Program provenance — one correction

`E0_testbed_preservation.md` records the experiment source as sha256
`7ce30494668df4271c5dcef5cb879a03ddb6a7901e7aad811a7ea9d92c55e861` and the repo HEAD at
capture time as `c18713840e8376c065909749d451a6bc9e6c5c4d`.

Both check out, and they agree with each other. Commit `c1871384` is dated 2026-08-13
19:38:27 −0400, eleven minutes before the first capture in the session, and its copy of
`defense4/size/native_parity/p4/defense4_rrc_bor_unified12.p4` hashes to exactly
`7ce30494…`.

**The copy of that file at the branch tip does not.** It hashes to `5b573a59…`. Commit
`8a6896e`, on 2026-08-14 — the day after the campaign — added a 21-line documentation header
to the file. The change is confined to the leading comment block; no P4 construct was
touched. The file is functionally the same program, but it is not the byte sequence that was
compiled.

`defense4/timing/implementation/exact_experiment_source/` therefore holds the `c1871384`
blob, which hashes to the recorded value. The control-plane modules and the drivers in
`implementation/` come from the same commit.

## 8. Loaded binary — two builds, one discrepancy explained

Two Tofino binaries exist for this program:

* `550b5b974b0cfde5…` — build v1, loaded in campaign phase 5 and still reported by
  `phase8_closeout/final_state.txt`.
* `33fa3a77c732f4cf…` — build v2, from `h3_prep/compile_v2/`. `BUILD_SUMMARY.txt` records
  that its ingress MAU table-to-stage placement is bit-identical to v1's.

`E0_testbed_preservation.md` records `33fa3a77` as loaded for the E phase, with a matching
"expect" value, and the OPERATE result document for the same day names the same binary. The
phase-8 closeout that names `550b5b97` is stamped by its watchdog at 18:37, more than an
hour before the 19:49 start of the E-phase captures, so it describes an earlier state of the
switch and does not contradict E0.

**Status: PARTIAL.** The loaded binary was not independently read back at capture time. The
record is consistent and comes from two documents written that day, but it rests on those
documents rather than on a readback taken alongside the captures.

## 9. What a clean timing-only capture would need

Not performed. No hardware action was taken during this audit. Recorded here so the
requirement is explicit if it is ever authorised:

A native arm captured with `--mode OFF` **and** `shape_enable=0`, and a defended arm with
`--mode D4` and `shape_enable=0`, both against the same relay in one session, with the
configure-all readback captured in full to a file for each arm and a per-run driver log
recording the exact request counts. That would separate the timing intervention from the
size datapath outright, instead of holding size constant across arms as the present evidence
does. It would require loading a program, changing switch configuration, and driving the
physical relay, none of which may happen without explicit authorisation.

## 10. Provenance status, per capture

| capture | status | what is unresolved |
|---|---|---|
| `e1_native.pcap` | PARTIAL | driver invocation and expected request count not logged |
| `e2_def_read.pcap` | PARTIAL | same |
| `e2_def.pcap` | PARTIAL | same |
| `sbo_j2.pcap` | PARTIAL | J not observed relay-facing; driver invocation not logged |
| `sbo_j6.pcap` | PARTIAL | same |
| `sbo_j12.pcap` | PARTIAL | same |

Nothing is CONTRADICTED. The two provenance gaps common to all six are the unidentified
readback failure of §6 and the absence of per-run driver logs; both are recorded above
rather than resolved.

## 11. Reproduction

Every published timing value regenerates from the raw captures. Measured values agree with
the frozen CSVs to within one microsecond — one unit in the last printed digit — which is
the difference between integer-nanosecond and float64-epoch arithmetic.

One number moves further, and it is worth being precise about why. The mutual information
for defended traffic is 0.001837 bits in the frozen `verdict_stats.json` and 0.002085 bits
when regenerated. The predeclared bin grid, `linspace(0, 12, 61)` ms, places an edge at
exactly 4.000 ms, and the defended CLRT distribution sits on top of that edge: **199 of 1098
defended observations lie within one microsecond of it**. A one-microsecond rounding change
moves 18 percent of the sample across a bin boundary. Shifting the grid phase by a fraction
of a bin moves the estimate over the range 0.000000 to 0.002085 bits.

The point estimate is thus not meaningful at the fourth decimal. What is stable is the
conclusion: under every grid phase tested the defended estimate lies inside its permutation
null, so no dependence between transaction class and CLRT is measurable. The native
estimate, 0.424356 bits, is unaffected and reproduces to six decimal places. Claims should
quote the defended value as "below 0.003 bits and inside the permutation null" rather than
to four significant figures. The frozen files were not modified.
