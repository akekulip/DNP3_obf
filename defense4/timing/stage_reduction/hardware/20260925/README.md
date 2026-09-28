# Seven-stage Tofino hardware smoke test — 2026-09-25

The user authorized loading the candidate, displacing `mvm_tna`, and running the
master and outstation. The seven-stage `defense4_timing` program was loaded on the
physical Tofino-1 at `10.10.54.81`, using the verified SDE 9.13.2 binary. It is left
running with timing enabled (D4), request anchoring enabled, and sizing absent.

Source commit: `16050715`; source SHA256:
`d2306158f59e69c622654b0577e4518e5be7a69eb927f80c3727f07f8c553090`.
`switch/loaded_identity.json` binds the live process configuration to the BFRT,
context and binary hashes in the compiler manifest (7 ingress / 0 egress stages).
Only one `bf_switchd` was running at the final identity check.

## Result

The physical path was Vision master (`192.168.10.1`, dp9) through Tofino to the
SEL-751 outstation (`192.168.10.7:20000`, dp64). dp8 and dp10 were MAC-near loopbacks;
the four data/loopback ports read UP. Captures are from Vision's `enp59s0f0np0`.

| Arm | READ successes | SELECT successes | OPERATE successes |
|---|---:|---:|---:|
| Timing OFF | 20/20 | 10/10 | 10/10 |
| Obfuscated (D4) | 20/20 | 10/10 | 10/10 |

All 80 functional exchanges passed the corrected active harness's response and
CRC checks. No stale responses were discarded. Each OPERATE followed a successful
matching SELECT; the unchanged construction guard restricted points to `{1,3}`.
There were no automatic OPERATE retries. G10V2 status reads before and after each
arm reported all 32 output-status points online and open. These are protocol
status observations, not a separate physical-contact or TRIP measurement.

| Function | Timing OFF median CLRT (ms) | Obfuscated median CLRT (ms) |
|---|---:|---:|
| READ | 2.230685 | 3.999057 |
| SELECT | 1.646837 | 4.000157 |
| OPERATE | 2.878607 | 4.000514 |

CLRT is master-visible response minus acknowledgment time. Obfuscated ACK medians
were about 20.11 ms after the request, and response medians about 24.11 ms. The
configured offsets were 20/24 ms, budget 18000, `anchor_req=1`, J codebook
`{2,6,12}` ms, and `read_len=0`. The SELECT CLRT maximum was 4.334621 ms; the small
sample does not establish a tail bound. `summary.json` retains all minima/maxima.

Both final configuration passes returned `PASS (n_fail=0 n_warn=0)` using the
unchanged strict readback checks. The explicit `--read-len 0` is required because
that retained but unused field has no hardware storage. An initial deployment
attempt used the default 18 and failed that check; a temporary permissive helper
change was discarded before the recorded OFF/D4 tests. No P4 or control-source
change was needed for the successful run.
The startup log retains BFRT diagnostics from cold bring-up, already-existing
entries and attempted parser-scope changes. The final configuration values were
verified by strict readback and the functional run by endpoint outcomes/captures.

## Evidence and reproduction

- `vision/{timing_off,obfuscated}/`: application outcomes, output-status reads,
  packet captures, capture diagnostics, and process exit statuses.
- `switch/`: successful configuration logs, BFRT configuration snapshots,
  startup/process identity, loaded configuration and recovery scripts.
- `analyze.py`: checks the source hash recovered from commit `16050715`, artifact
  hashes, configuration, application counts, output status, complete timing
  samples, and the observed median CLRT range.
- `SHA256SUMS`: hashes of the retained raw captures and execution evidence.

From the repository root:

```bash
python3 defense4/timing/stage_reduction/hardware/20260925/analyze.py
(cd defense4/timing/stage_reduction/hardware/20260925 && sha256sum -c SHA256SUMS)
```

`run_block.py` ran on Vision with `DEFENSE4_HW_AUTHORIZED=1`; it uses the unchanged
`active_harness` and frozen frame builders, a 500 ms transaction budget, 400 ms gaps
between READs/SBO pairs, and bounded capture/process lifetimes. An SBO pair has no
extra delay between its SELECT response and OPERATE. The first OFF status record's
`sbo: 0` is an exit code that overwrote the requested count; its application log and
JSONL establish the ten completed pairs. The runner now uses separate count keys.
The OFF capture contains one of the two additional output-status reads; both are
present in their application logs. All 40 functional exchanges appear in each
arm's capture; output-status reads are excluded from the timing table above.

## Runtime and recovery

The live daemon was started in tmux session `dnp3_defense4_timing` with the exact
compiled artifact under `/tmp/dnp3-stage-review-le7BdybB/seven_verified/out`.
A persistent, hash-checked copy plus hardware config and launcher is retained at
`/home/decps/dnp3_timing7_20260925/` on the switch. The Vision run directory has the
same name. The persistent launcher is for a subsequent cold start; it was not the
launcher used for this capture.

Before displacement, MVM's process, launcher, model/controller and 36 BFRT tables
were saved under the switch directory's `preflight/`. `restore_mvm.sh` cold-loads
the original program and restores its static model/forwarding setup. It does not
replay the dynamic leaf cache or counter history; the saved BFRT snapshot retains
those values for inspection. MVM was not restored because the user requested its
displacement; rollback was syntax-checked but not executed. No background test
traffic remains running.

This is a bounded hardware smoke test, not the historical paper campaign or a
complete equivalence proof. It does not observe realized J or relay-facing release
time, test loss recovery/concurrent sessions, prove exactly-once delivery, or fix
the baseline defects documented in the parent README. Independent architecture
review remains unavailable. The historical implementation and captures were not
modified.

An independent local evidence review reproduced the timing summary and verified
all 30 retained evidence hashes, with no outstanding reporting findings.
