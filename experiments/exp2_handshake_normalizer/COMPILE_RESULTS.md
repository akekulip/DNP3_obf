# Experiment 2B — compilation results

**Verdict for the compile gate: COMPILE_PASS.** The standalone handshake normalizer
`p4src/handshake_normalizer.p4` compiles cleanly for Intel Tofino-1 with the local bf-p4c, all
the way through to the loadable binary.

## Toolchain and command

- **SDE:** `/home/philip/bf-sde-9.13.1` (bf-p4c reports `p4c 9.13.1`, SHA `e558d01`). The lab
  switch runs SDE **9.13.2**; this compile is on **9.13.1** — an SDE-version seam to record. A
  clean 9.13.1 compile does not guarantee a clean 9.13.2 compile, but the program uses only
  stable TNA constructs.
- **Command:** `bf-p4c --std p4-16 --target tofino --arch tna -g -o build p4src/handshake_normalizer.p4`
- **Result:** `0 errors, 2 warnings generated.` exit 0. The two warnings are the benign
  `min_parse_depth_accept_loop` parser-padding notes (bf-p4c pads shallow parse paths; not a defect).
- **Source SHA-256:** `15e2213090f2b7ecab2280441d30f77c561234bf644c22c31359883529c804ab`
  (`evidence/source.sha256`; 203 lines).
- **Loadable artifacts produced:** `build/handshake_normalizer.conf`, `build/pipe/context.json`
  (1.55 MB), `build/pipe/tofino.bin` (1.38 MB). Raw logs: `evidence/compile_stdout.txt`,
  `evidence/compile_stderr.txt`, `evidence/metrics.json`, `evidence/manifest.json`.

## The path to a clean compile — a real bf-p4c 9.13.1 diagnosis

The first working drafts of this program hit a bf-p4c **Internal Compiler Error** — a hard crash
in the final backend lowering pass (`Internal compiler error. Please submit a bug report`), with
**no assertion text** emitted and the crash occurring *after* PHV allocation, MAU
characterization, resource allocation, `context.json`, `.bfa`, and `manifest.json` were all
written. That "crash with no message, very late" shape is what made it look like a fundamental
limit. It was not. Bisection (skeleton compiles; full parser + an *uncalled* action compiles;
minimal reproducers compile) isolated **three ordinary P4-coding faults, each of which bf-p4c
9.13.1 reports as a clean error in isolation but crashes on when they combine at full nesting:**

1. **A stats `Counter` shared across non-mutually-exclusive inline `count()` sites.** The original
   code called `ctr.count(i)` at ~12 points across nested `if`/`else` branches. bf-p4c turns each
   inline `count()` into its own implicit table; several such tables sharing one `Counter` on
   overlapping paths is rejected ("cannot share Counter … not mutually exclusive"). In isolation
   that is a plain error; inside the full program it manifested as the ICE. **Fix:** compute one
   mutually-exclusive outcome index (0–10) and call `ctr.count(outc)` exactly once per packet.

2. **Arithmetic on deparsed header fields.** The payload check
   `total_len != 20 + 4*data_offset` puts `total_len` and `data_offset` — both emitted (deparsed)
   fields — into a shift/add/compare. bf-p4c cannot place a deparsed field in the container layout
   that arithmetic needs ("deparsed exact_containers … consider @in_hash"); `@in_hash` did not
   resolve it, and copying to metadata still tripped the shift's PHV-rotation limit. **Fix:** drop
   the arithmetic entirely — the parser already branches on `data_offset`, so a small
   `data_offset → expected-length` table (`t_exp`, const entries) yields the no-payload length as a
   constant, and the check becomes a plain 16-bit equality.

3. **Deep nested gateways carrying wide-field path predicates.** Nested `if`/`else` makes each leaf
   gateway encode the *entire* enclosing path condition. With 16-bit `orig_mss` and the 8-bit
   `k0`/`l0` compared at depth, one leaf gateway's PHV input exceeds the "4 bytes + 12 bits"
   gateway limit ("condition too complex"). **Fix:** precompute every deep predicate as a **1-bit
   flag** in its own shallow gateway, so the nested outcome logic tests only 1-bit flags; and
   realize the MSS `> 1460` clamp with a **range-match table** (`t_clamp`), the correct Tofino
   idiom for a wide inequality, instead of a gateway compare.

**Conclusion:** the ICE was a *coding-shape* problem, not a target-feasibility problem. Once the
control was written in the idioms Tofino's MAU/gateway model expects, the exact same mechanism —
fixed-width `data_offset`-keyed option parse, MSS canonicalization, option-region shrink to
`data_offset` 6, TTL/IP-ID scrub, full IPv4+TCP checksum recompute, indexed telemetry — compiles
to a loadable binary. The pre-fix crashing source is preserved in git history for the bug report.

## What "compile pass" does and does not establish

- **Does:** the mechanism *fits the target and toolchain*. It is expressible in TNA, allocates on
  the pipeline, and is **stateless** — no `Register`/`RegisterAction`/`Meter` declared, no stateful
  ALU allocated (`RESOURCE_REPORT.md`). This directly answers the residual "the `data_offset`-keyed
  parser fit is a compile question" uncertainty flagged in the Experiment 2A review.
- **Does not:** prove functional correctness. A clean compile says nothing about whether a crafted
  SEL751/ION7550/AB1400 SYN is actually rewritten to the canonical layout with valid checksums.
  That is the **model functional test** (`MODEL_TESTS.md`), which is the next gate and has **not**
  been run in this turn. Endpoint safety on real stacks remains Experiment 3.

## Update — scope resolutions + safety fix (Phase 1 continuation)

The source was extended and recompiled clean (`0 errors`; final SHA-256
`23982bbceb5c3761bb1aca40cebb3d51558a3ed9c4156bbdc15015cce032bacb`):

- **data_offset 12–15** now routes to an explicit counted outcome (`ctr` index 11,
  `tcp_unsupported_do`): TCP‑normalization fail‑open, TCP header + payload byte‑identical. Not
  widened to 5–15. A 4‑bit `data_offset > 11` gateway drives it.
- **Independent TCP vs L3 outcomes:** a second `Counter ctr_l3` (0 = ttl‑only, 1 = ttl + atomic
  IP‑ID) records L3 normalization separately from the TCP outcome, so a fail‑open packet is never
  called "entirely unchanged".
- **Safety fix:** the parser gate now requires **MF clear** (unfragmented) in addition to offset 0,
  so a first fragment is never parsed/normalized. This was surfaced by the offline oracle.

Both changes compile within the same stateless envelope (adding one small stats counter and one
4‑bit gateway). Offline oracle: **27/27** (`evidence/oracle_results.txt`).
