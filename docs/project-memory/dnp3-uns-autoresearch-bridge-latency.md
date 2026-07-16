---
name: dnp3-uns-autoresearch-bridge-latency
description: dnp3-uns bridge-latency autoresearch experiment — converged at ~0.46 µs (−62%); config.cfg lives ONLY on the experiment branch
metadata: 
  node_type: memory
  type: project
  originSessionId: 354241fe-3e99-42d7-9ca8-e3cc8591b50c
---

The autoresearch experiment `engineering/bridge-latency` lives in `~/Projects/dnp3-uns` (NOT the DNP3 repo). It optimized `src/EdgeNode.cpp` in the DNP3→Sparkplug B bridge: 14 runs (2026-06-22), 7 kept / 7 reverted, baseline 1.213 µs → best 0.463 µs (−62%), re-verified 2026-07-14 at 0.454 µs with 6/6 tests passing. Theme of all wins: kill per-publish heap allocations + memoize stable values (thread_local alias memo was −44% alone).

**Why:** Two traps cost time. (1) `.autoresearch/engineering/bridge-latency/config.cfg` and `program.md` are committed **only on branch `autoresearch/engineering/bridge-latency`** — on `master` they vanish while the gitignored `results.tsv`/`run.log` remain, making the experiment look corrupted. (2) The experiment is **converged under its one-file rule**: the next real win (change `aliases_` from `std::map` to `unordered_map`) lives in `include/dnp3uns/EdgeNode.h`, which the config forbids; more `EdgeNode.cpp`-only runs are noise around 0.48 µs.

**How to apply:** To resume, `git checkout autoresearch/engineering/bridge-latency` in dnp3-uns first (restores config), eval via `bash scripts/bench_e2e_latency.sh`. For further gains, relax `target` in config.cfg + constraints in program.md to include `EdgeNode.h`; otherwise merge the branch and close. Results briefing artifact: https://claude.ai/code/artifact/e3448b12-f494-4101-bbe3-82a9ab3ab854. Related: [[lab-hosts-dnp3]].
