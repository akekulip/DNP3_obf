# Source-to-Silicon Provenance — `dnp3_timing_normalizer_inline`

**Auditor:** Agent E (source/build provenance review), read-only on the switch.
**Audit date:** 2026-07-26 (switch clock 00:22–00:26 UTC; switch TZ is UTC).
**Repo:** `/home/philip/Projects/DNP3`, branch `research/timing-inline-corrected-v2`, HEAD `ead6b008880a9ce544d15b73e9f65ee232ea9e4e`.
**Switch:** `decps@10.10.54.81` (`ufispace`), SDE 9.13.2, Tofino 1.

Every hash below was produced by a command run during this audit. Nothing is quoted from
prose, prior reports, or memory. No file on the switch was created, modified, or removed;
`bf_switchd` was not restarted and nothing was recompiled or reloaded.

---

## 0. VERDICT (read this first)

| Question | Answer |
|---|---|
| Is the source → local build → switch build → conf → loaded binary → running process chain complete? | **YES — complete and unbroken, with one characterized discontinuity (see §5) and one minor gap (see §9).** |
| Is the running `bf_switchd` executing a build of the canonical source sha `fb3b10da…`? | **YES — PROVEN by hash + preprocessed-source reconstruction + conf + switchd log + file mtimes.** |
| Are the local 9.13.1 and switch 9.13.2 `tofino.bin` byte-identical? | **NO.** Same size, 34 differing bytes. They are **equivalent in MAU resource allocation**, not identical images. Details in §5. |
| Is the header comment "compile-only, never loaded" true? | **NO — it is stale inherited boilerplate.** The program was compiled on the switch and loaded onto Tofino-1 silicon. Resolution in §8. |

---

## 1. The chain, end to end

| # | Link | Artifact | sha256 | Proven by |
|---|---|---|---|---|
| 1 | **Canonical source (repo, working tree)** | `research/timing_final/p4/dnp3_timing_normalizer_inline.p4` (50 610 B) | `fb3b10dad575bed4a5da9943530ac3776e3e7d1243c3e986f092711b0d09e94c` | `sha256sum` |
| 1a | **Canonical source (git object)** | blob `ef21faee256ac5653b561a72eee3043f3d699a9a` at commit `ead6b00` | `fb3b10da…` (identical) | `git cat-file blob … \| sha256sum`; `git status --porcelain` on that path returned empty (clean) |
| 1b | **Repo mirror copies** | `deliverables/dnp3_inline_live/p4/…`, `archive/timing-inline-v1-20260725/p4/…` | `fb3b10da…` (both identical) | `sha256sum` |
| 1c | **Config pin** | `research/timing_final/config/lab.env.inline` → `P4_SRC_SHA256=` | pins `fb3b10da…` | `cat`; all three copies of `lab.env.inline` are themselves identical (`36909eae…`) |
| 2 | **Local build, bf-p4c 9.13.1** | `research/timing_final/p4/build_inline_local/pipe/tofino.bin` | `3b6ee6d7b0d7798bfd044719abecb1de4a13687e51194074f3366e0fbcf233c1` | `sha256sum` |
| 2a | | `…/build_inline_local/pipe/context.json` | `186f3ab2424003279bb7b91b186222a99f710b1423b4b5376a1ee04c32192d85` | `sha256sum` |
| 2b | | `…/build_inline_local/bfrt.json` | `1bb4214bffa7631914cb4b1c2892d60cb9b2c3962c3e539042c942abd0f47f6e` | `sha256sum` |
| 2c | | `…/build_inline_local/dnp3_timing_normalizer_inline.p4pp` | `39a0767b7ed3b0f051c98f21020bf424d9fe3b3ba39b2332d6889ae108d84be9` | `sha256sum` |
| 3 | **Staged source on switch** | `/home/decps/timing_inline/dnp3_timing_normalizer_inline.p4` (50 610 B) | `fb3b10dad575bed4a5da9943530ac3776e3e7d1243c3e986f092711b0d09e94c` | `sha256sum` over ssh — **byte-for-byte identical to the repo copy** |
| 4 | **Switch build, bf-p4c 9.13.2** | `/home/decps/timing_inline/out_inline/pipe/tofino.bin` (1 364 530 B) | `180e44aa353fcaf709b2afaf5c4b4e72f6634ee77fe53b07cccff0dd29474076` | `sha256sum` |
| 4a | | `…/out_inline/pipe/context.json` | `3c9020ee2856b71a977db518e39dc5664404d193adba3f7885cb50cecd6bba86` | `sha256sum` |
| 4b | | `…/out_inline/bfrt.json` | `52c61b37dc175c19491d91dc27402625349b6051f7bbb1737eb35a77ac3e6883` | `sha256sum` |
| 4c | | `…/out_inline/dnp3_timing_normalizer_inline.p4pp` | `43b0adc2006660576b20e4b0102a1dcbc6478bda97faabdcd88d1cc28f8e04ad` | `sha256sum` |
| 4d | | `…/out_inline/manifest.json` | `d020321a32f4f111a2416894ae98a753b44dede015a1632ac60636b43460b12c` | `sha256sum` |
| 5 | **Switch conf (what bf_switchd was told to load)** | `/home/decps/timing_inline/tn_inline_abs.conf` (619 B) | `a2d057ba97db31826db316678a1f74b959698cc00566a691112cfb2c1bb1d4e2` | `cat` + `sha256sum` |
| 6 | **Loaded binary** | conf `config:` field → `/home/decps/timing_inline/out_inline/pipe/tofino.bin` | `180e44aa…` (= link 4) | conf text + `stat` (see §7) |
| 7 | **Running process** | PID **228141**, `bf_switchd`, root, SDE 9.13.2, `--conf-file /home/decps/timing_inline/tn_inline_abs.conf --init-mode=cold --status-port 7777` | — | `pgrep -a bf_switchd` (count = **1**), `ps -o pid,lstart,etime,cmd`, `/proc/228141/cmdline` |

**Timeline (all UTC, all read from artifacts, not asserted):**

| Time (UTC) | Event | Source of the timestamp |
|---|---|---|
| 2026-07-25 21:33 | canonical source last written on dev box | file mtime (dev box is UTC−4, `Jul 25 17:33`) |
| 2026-07-25 21:34:07 | local 9.13.1 build | `build_inline_local/manifest.json → build_date` |
| 2026-07-25 21:40:59 | source staged onto switch | `stat` mtime of `/home/decps/timing_inline/dnp3_timing_normalizer_inline.p4` |
| 2026-07-25 21:41:41 | switch 9.13.2 build finished (`tofino.bin` written) | `stat` mtime = ctime |
| 2026-07-25 21:48:44 | `tn_inline_abs.conf` written | `stat` mtime = ctime |
| 2026-07-25 21:49:15.46 | `bf_switchd` PID 228141 started | `/proc/228141` mtime; `ps` ELAPSED cross-checks |
| 2026-07-25 21:49:15.49 | conf parsed, program identified | switchd log |
| 2026-07-25 21:49:22.60 | `dev_id 0 initialized`, last log write | switchd log + log mtime |
| 2026-07-26 00:22–00:26 | this audit | `date -u` on the switch |

Ordering is internally consistent: source written → built locally → staged → built on switch →
conf written → switchd launched. No artifact postdates the process it supposedly fed.

---

## 2. Did the local build come from THIS source? — PROVEN

`bf-p4c` does not embed a source hash, so filename matching is not evidence. Instead the
preprocessed output was reconstructed and compared:

- `build_inline_local/dnp3_timing_normalizer_inline.p4pp` was split on `# <line> "<file>"`
  markers; the segments attributed to `dnp3_timing_normalizer_inline.p4` were concatenated.
- Against the canonical source with `#include`/`#`-directive lines removed and whitespace
  runs collapsed (cpp normalizes whitespace and consumes directives), the two are **exactly
  equal**: 41 662 normalized characters on both sides, `normalized equal: True`.
- `manifest.json` records
  `compile_command = /home/philip/bf-sde-9.13.1/install/bin/bf-p4c --target tofino --arch tna -g -o build_inline_local dnp3_timing_normalizer_inline.p4`,
  `compiler_version = 9.13.1 (e558d01)`, `compilation_succeeded = true`, `run_id 52f18de37b5f407c`,
  `src_root = /home/philip/Projects/DNP3/research/timing_final/p4`.

**Verdict: the local build is a build of source sha `fb3b10da…`. PROVEN** (to whitespace
normalization, which is the preprocessor's own doing and cannot alter program semantics).

---

## 3. Did the switch build come from THAT source? — PROVEN, three independent ways

1. **Hash.** The staged `.p4` on the switch is `fb3b10da…` — the same sha256 as the repo copy.
   This is a hash match, not a filename match.
2. **Preprocessed reconstruction.** The switch's `out_inline/dnp3_timing_normalizer_inline.p4pp`
   was fetched and reconstructed the same way: `SWITCH p4pp reconstructs staged source
   (whitespace-normalized): True`.
3. **Compiler diagnostics tie to the source text.** `compile_9132.log` reports the warning at
   `dnp3_timing_normalizer_inline.p4(269)` with the caret on `out ig_meta_t meta,` and the
   context line at `(267) parser IgParser(packet_in pkt,`. Lines 267 and 269 of the canonical
   source are exactly those two lines (`sed -n '265,272p'`). A log from any other revision of
   this file would not line up.

`out_inline/manifest.json`: `compiler_version = 9.13.2 (1baf055)`, `build_date = Sat Jul 25
21:41:41 2026`, `compilation_succeeded = true`, `run_id 318c14a408b941c1`, `compile_command =
/home/decps/Downloads/bf-sde-9.13.2/install/bin/bf-p4c --target tofino --arch tna -g -o
out_inline dnp3_timing_normalizer_inline.p4`. `compile_9132.log` ends `0 errors, 3 warnings
generated.`

---

## 4. Resource usage, both builds

Extracted from each build's `pipe/logs/resources.json`.

| Metric | Local (9.13.1) | Switch (9.13.2) | Same? |
|---|---|---|---|
| `nStages` (available) | 12 | 12 | yes |
| MAU stages used (`mau_stages` entries) | **10** — stage_number 0…9 | **10** — stage_number 0…9 | yes |
| Logical tables (sum over stages) | 60 | 60 | yes |
| SRAM blocks | 55 | 55 | yes |
| TCAMs | 1 | 1 | yes |
| Map RAMs | 54 | 54 | yes |
| Deparser FDE entries | 26 | **25** | **no** |
| Deparser POV size / bits | 10 | **9** | **no** |
| `compiler_version` field | `9.13.1` | `9.13.2` | n/a |

The report's stated figures — "10 of 12 ingress stages, 60 logical tables, 55 SRAM blocks,
same either way" — are **confirmed on both builds**. The one resource difference the report
does not mention is in the deparser: 9.13.2 packs the field dictionary into one fewer entry
and one fewer POV bit. That is a refinement, not a contradiction.

---

## 5. Local 9.13.1 vs switch 9.13.2 binaries — NOT byte-identical

The switch artifacts were copied to a local scratch directory (a read; nothing written on the
switch) and hashes re-verified after transfer — all matched.

- `tofino.bin`: **identical size** (1 364 530 B both), **different sha256**
  (`3b6ee6d7…` local vs `180e44aa…` switch). **34 bytes differ (0.002 %), in 10 runs.**

  | Offsets | Bytes | What sits there |
  |---|---|---|
  | 58, 61–67 | 8 | embedded `compiler_version` string: `9.13.1 (e558d01)` vs `9.13.2 (1baf055)` |
  | 129–140, 142–144 | 15 | embedded `run_id`: `52f18de37b5f407c` vs `318c14a408b941c1` |
  | 1 302 511; 1 302 522–523 | 3 | configuration-register write payload |
  | 1 360 530; 1 360 543–545; 1 360 554; 1 360 566–568 | 8 | configuration-register write payload |

  So **23 bytes are build metadata and 11 bytes are register-configuration payload.** The 11
  payload bytes sit in the tail of the image and are consistent with the deparser FDE/POV
  delta in §4, but the register semantics were **not decoded**. Therefore:
  **PROVEN** — the two images are not byte-identical and 11 non-metadata bytes differ.
  **UNPROVEN** — the assertion that those 11 bytes are semantically inert / attributable
  solely to the deparser packing change. Establishing that needs a register-map decode of the
  four affected offsets, which this audit did not perform.

- `context.json`: differs in exactly four places — `build_date`, `compiler_version`, `run_id`,
  and **one** leaf: `phv_allocation[0]/ingress[8]/records[0]/live_end` (`"deparser"` locally
  vs `0` on the switch). All tables, actions, parser states and the rest of the PHV allocation
  are identical. Total non-metadata leaf differences: **1**.

- `bfrt.json`: same size (255 492 B), different sha (`1bb4214b…` vs `52c61b37…`) — not
  further decomposed.

**Correct phrasing for any report:** the local 9.13.1 and on-switch 9.13.2 builds of the same
source are **equivalent in MAU resource allocation and near-identical in context**, but the
binaries are **not byte-identical**. Do not write "byte-identical binaries" — the hashes
refute it.

---

## 6. The conf: exactly which files were loaded

`/home/decps/timing_inline/tn_inline_abs.conf` (sha `a2d057ba…`), verbatim fields:

- `program-name`: `dnp3_timing_normalizer_inline`
- `bfrt-config`: `/home/decps/timing_inline/out_inline/bfrt.json` → sha `52c61b37…`
- `p4_pipeline_name`: `pipe`
- `context`: `/home/decps/timing_inline/out_inline/pipe/context.json` → sha `3c9020ee…`
- `config`: `/home/decps/timing_inline/out_inline/pipe/tofino.bin` → sha `180e44aa…`
- `pipe_scope`: `[0,1,2,3]`; `chip_family`: `tofino`; `agent0`: `lib/libpltfm_mgr.so`

Every referenced path is inside the **switch-side 9.13.2 build output directory**. The conf
does **not** reference the local 9.13.1 build at any point. `launch_tn_inline.sh` (the launcher
staged next to it) exports `SDE=/home/decps/Downloads/bf-sde-9.13.2` and invokes bf_switchd
with this conf — matching the running command line exactly.

---

## 7. Runtime: one process, and it is running these bytes

```
pgrep -c bf_switchd            -> 1
pgrep -a bf_switchd            -> 228141 /home/decps/Downloads/bf-sde-9.13.2/install/bin/bf_switchd
                                   --install-dir /home/decps/Downloads/bf-sde-9.13.2/install
                                   --conf-file /home/decps/timing_inline/tn_inline_abs.conf
                                   --init-mode=cold --status-port 7777
ps -o user -p 228141           -> root
/proc/228141 mtime             -> 2026-07-25 21:49:15.462491166 +0000
date -u (switch)               -> Sun Jul 26 00:22:29 UTC 2026
```

`/home/decps/timing_inline/tn_inline_switchd.log` (sha `58d02525…`, last written
21:49:22.602) contains a single, complete load sequence and no reload afterwards:

```
21:49:15.494058  bf_switchd: loading conf_file /home/decps/timing_inline/tn_inline_abs.conf...
21:49:15.494537  num P4 programs 1
21:49:15.494562    p4_name: dnp3_timing_normalizer_inline
21:49:15.494588    p4_pipeline_name: pipe
21:49:15.494664      context: /home/decps/timing_inline/out_inline/pipe/context.json
21:49:15.494689      config:  /home/decps/timing_inline/out_inline/pipe/tofino.bin
21:49:17.767016  Device 0: Operational mode set to ASIC
21:49:22.595145  bf_switchd: dev_id 0 initialized
21:49:22.595159  bf_switchd: initialized 1 devices
```

`Operational mode set to ASIC` and `ASIC detected at PCI /sys/class/bf/bf0/device` establish
this is real silicon, not the model.

**bfruntime check: deliberately SKIPPED.** The bound program name is already established from
the switchd log, which is a zero-risk read of a file. Opening even a read-only bfrt/gRPC client
against a live `bf_switchd` that is mid-experiment is a non-zero perturbation, and the task
allowed skipping when in doubt. Nothing in the verdict depends on it.

---

## 8. Is the loaded `tofino.bin` the one the switch-side 9.13.2 build produced? — PROVEN

```
stat /home/decps/timing_inline/out_inline/pipe/tofino.bin
  size=1364530  mtime=2026-07-25 21:41:41.271639854 +0000
                ctime=2026-07-25 21:41:41.271639854 +0000  inode=6292666
```

- `mtime == ctime == 21:41:41`, which is the `build_date` in the switch build's
  `manifest.json` and `resources.json` — the file is the build's own output, not a copy dropped
  in afterwards (a copy would carry a later ctime).
- The file was last modified **7 min 34 s before** `bf_switchd` started (21:49:15) and has not
  been touched since — verified again at 00:26 UTC the following day, more than 2.5 h into the
  audit window.
- Therefore the bytes hashed during this audit (`180e44aa…`) are the bytes `bf_switchd` read at
  21:49:15.

**Verdict: PROVEN**, with the standard and unavoidable caveat that mtime/ctime can be forged by
a privileged user; there is no evidence of that here and the three timestamps corroborate each
other.

---

## 9. Gaps, and exactly what is missing

| Item | Status | What is missing |
|---|---|---|
| Local build stdout/stderr log | **GAP (minor)** | There is no compile log for the local *inline* build. `research/timing_final/p4/compile.log` is **not** it: it names `dnp3_timing_normalizer.p4` (the non-inline predecessor), is dated 12:47 vs the 17:34 build, and its line references (257/259) do not even match the current non-inline file. Local build success rests on `manifest.json` (`compilation_succeeded: true`) plus the existence of a complete artifact set — which is adequate, but a captured log would close it. |
| Semantics of the 11 differing payload bytes | **UNPROVEN** | A Tofino register-map decode of offsets 1 302 511, 1 302 522–523, 1 360 530, 1 360 543–545, 1 360 554, 1 360 566–568 in the `tofino.bin` register-write stream. Until then, only "the images differ in 11 non-metadata bytes" is provable, not "the difference is inert". |
| `bfrt.json` local↔switch delta | **NOT DECOMPOSED** | Both are 255 492 B with different hashes; a structural diff was not performed. Not load-bearing: the conf loads the switch-built one. |
| Live bfruntime program binding | **SKIPPED BY CHOICE** | See §7. Program identity is established from the switchd log instead. |

None of these breaks the chain. The chain is complete.

---

## 10. Resolving the "never loaded" contradiction

**The header comment is wrong. The report is right.**

Line 8 of `research/timing_final/p4/dnp3_timing_normalizer_inline.p4` reads:

```
 *                 (Tofino 1, TNA, bf-p4c 9.13.1, compile-only, never loaded)
```

This is **stale inherited boilerplate**, not a competing factual claim, and three independent
observations show it:

1. **It is copy-paste from a lineage where it was true.** `grep -rn "never loaded" --include=*.p4`
   finds the identical string in the `research/stage_reclamation/variants/` family —
   `p12_combined.p4:4`, `p14_fcsfix.p4:4`, `p5_parser_padcode.p4:26`, `p4_size_only.p4:33`,
   `p6_egress_pad.p4:40`, `p6c_true_trailer.p4:60`, `p12_probe_noinit.p4:4` — all genuinely
   compile-only stage-reclamation experiments. The inline program is a derivative of
   `p12_combined.p4` and carried the header block forward.
2. **The same block was not updated when the file was forked.** Line 2 of the *inline* file
   still reads `dnp3_timing_normalizer.p4` — the *predecessor's* filename. The whole header was
   copied wholesale from `research/timing_final/p4/dnp3_timing_normalizer.p4` (whose line 8 is
   byte-for-byte the same sentence) and never revised. A stale filename on line 2 and a stale
   status on line 8 are the same editing miss.
3. **The artifacts say loaded.** Switch-side 9.13.2 build of that exact source sha
   (§3), a conf pointing at its output (§6), a `bf_switchd` log printing `p4_name:
   dnp3_timing_normalizer_inline` and `dev_id 0 initialized` in `ASIC` mode (§7), and a single
   live process still running it (§7). A comment in a text file cannot outweigh that.

Two other parts of line 8 are also now incomplete: the program was compiled with **both**
bf-p4c 9.13.1 (off-switch) and 9.13.2 (on-switch), and it is the 9.13.2 build that reached
silicon — so "bf-p4c 9.13.1" alone understates the build story.

### Recommended corrected header (NOT applied — I did not edit the P4 file)

Replace line 2 and line 8 of `research/timing_final/p4/dnp3_timing_normalizer_inline.p4`
(and the identical copies under `deliverables/dnp3_inline_live/p4/` and
`archive/timing-inline-v1-20260725/p4/`, which share sha `fb3b10da…`) with:

```
 * dnp3_timing_normalizer_inline.p4 — THE CANONICAL TIMING-ONLY REFERENCE for the meeting
   …
 *                 (Tofino 1, TNA. Compiled with bf-p4c 9.13.1 off-switch and 9.13.2 on the
 *                  switch — same MAU footprint both ways: 10 of 12 stages, 60 logical tables,
 *                  55 SRAM blocks. LOADED ON SILICON: bf_switchd on Tofino-1, conf
 *                  /home/decps/timing_inline/tn_inline_abs.conf, 2026-07-25 21:49:15 UTC.
 *                  Source sha256 fb3b10dad575bed4a5da9943530ac3776e3e7d1243c3e986f092711b0d09e94c.)
```

Caution when editing: **changing the file changes its sha256**, which is pinned in
`research/timing_final/config/lab.env.inline` as `P4_SRC_SHA256` and quoted in the report's
Provenance section. Any edit must be followed by re-pinning that value, re-staging the source
on the switch if the staged copy is meant to keep matching, and updating the report text —
otherwise this audit's five-way hash match is broken by the very act of correcting the comment.
The cleanest sequencing is: correct the comment, rebuild/restage only if the loaded program is
next reloaded anyway, and in the meantime record that the loaded binary derives from source
sha `fb3b10da…` (the pre-correction text).

---

## 11. Commands run during this audit

All commands were read-only. Exit codes shown are the exit status reported inline by each
command in its shell block. `E`/`EXIT`/`SSH_EXIT` markers appear in the raw session transcript.

**Dev box (`/home/philip/Projects/DNP3`):**

| Command | Exit |
|---|---|
| `git branch --show-current` / `git status --short` | 0 |
| `sha256sum research/timing_final/p4/dnp3_timing_normalizer_inline.p4` | 0 |
| `head -20 research/timing_final/p4/dnp3_timing_normalizer_inline.p4` | 0 |
| `git log --oneline -5 -- research/timing_final/p4/dnp3_timing_normalizer_inline.p4` | 0 |
| `git status --porcelain <p4>` (empty output = clean) | 0 |
| `git ls-files -s <p4>` | 0 |
| `git cat-file blob ef21fae… \| sha256sum` | 0 |
| `git log -1 --format=… ead6b00` / `git branch --contains ead6b00` | 0 |
| `ls -la research/timing_final/p4/` and `build_inline_local[/pipe]` | 0 |
| `cat research/timing_final/p4/compile.log` | 0 |
| `sha256sum build_inline_local/{pipe/tofino.bin,pipe/context.json,bfrt.json,*.conf,*.p4pp}` | 0 |
| `cat build_inline_local/manifest.json`, `head -c 1200 source.json`, `cat events.json` | 0 |
| python: parse `pipe/logs/resources.json` (stage counts, table/SRAM/TCAM/map-RAM totals, deparser) | 0 |
| python: reconstruct source from `.p4pp` `#line` markers and compare (exact → False; whitespace-normalized → **True**) | 0 |
| `tail -30 build_inline_local/pipe/logs/table_summary.log` | 0 |
| `sed -n '265,272p' dnp3_timing_normalizer_inline.p4`; `sed -n '255,262p' dnp3_timing_normalizer.p4` | 0 |
| `sed -n '1,12p' dnp3_timing_normalizer.p4` | 0 |
| `grep -rn "never loaded" --include=*.p4 /home/philip/Projects/DNP3` | 0 |
| `sha256sum` of all three repo copies of the source and of `lab.env.inline` ×3 | 0 |
| `cat research/timing_final/config/lab.env.inline` | 0 |
| `sed -n '505,516p' deliverables/dnp3_inline_live/source/report_source.md` | 0 |
| python: byte-diff local vs switch `tofino.bin` (34 bytes, 10 runs) | 0 |
| python: deep-diff `resources.json` and `context.json` local vs switch | 0 |

**Switch (`ssh decps@10.10.54.81`, all read-only; ssh exit 0 for every block):**

| Command | Exit |
|---|---|
| `whoami; hostname; date -u; uptime` | 0 |
| `pgrep -a bf_switchd`; `pgrep -c bf_switchd` | 0 |
| `ps -o pid,lstart,etime,cmd -p 228141`; `ps -o pid,user,cmd -p 228141` | 0 |
| `cat /home/decps/timing_inline/tn_inline_abs.conf`; `sha256sum` same | 0 |
| `ls -la /home/decps/timing_inline/` and `out_inline[/pipe]` | 0 |
| `sha256sum /home/decps/timing_inline/dnp3_timing_normalizer_inline.p4` | 0 |
| `cat /home/decps/timing_inline/compile_9132.log` | 0 |
| `cat /home/decps/timing_inline/launch_tn_inline.sh` | 0 |
| `sha256sum out_inline/{pipe/tofino.bin,pipe/context.json,bfrt.json,*.conf,*.p4pp,manifest.json}` | 0 |
| `grep -E "compiler_version\|build_date\|compile_command\|run_id\|compilation_succeeded" out_inline/manifest.json` | 0 |
| `cat /home/decps/timing_inline/tn_inline_switchd.log`; `sha256sum` same | 0 |
| `stat -c … ` on tofino.bin, context.json, bfrt.json, conf, staged .p4, switchd log | 0 |
| `sudo cat /proc/228141/cmdline`; `sudo readlink /proc/228141/cwd`; `sudo ls -l /proc/228141/fd`; `sudo stat -c … /proc/228141` | 0 |
| `scp` (read) of `tofino.bin`, `context.json`, `pipe/logs/resources.json`, `.p4pp`, staged `.p4` to a local scratch dir; hashes re-verified after transfer | 0 |

Nothing was written, deleted, restarted, recompiled, or reloaded on the switch. The only writes
performed anywhere were this file and
`evidence/corrected_v2/build/provenance.json` on the dev box, plus read-only copies in a
local scratch directory.
