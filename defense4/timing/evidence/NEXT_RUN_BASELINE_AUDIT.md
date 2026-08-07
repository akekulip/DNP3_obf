# NEXT RUN — baseline audit of the ae2a802 evidence system (gate REOPENED)

Date: 2026-08-07. Branch `defense4-caseA-hw-integration`. Audited boundary commit `ae2a802`.

The repository carried a **TIMING EXPERIMENTS PASS** verdict. That verdict is **reopened and
treated as invalid** until the final acceptance gate (Prompt 6) closes it. This file records the
known problems in the measurement-and-evidence pipeline, reproduced here with the exact commands
and exit codes, so the Phase 1 repair rests on evidence and not on a summary.

Every failure below is a real defect: a pipeline that reports a problem but exits 0, or swallows a
failure, lets bad data pass as clean. The Phase 1 repair makes each one fail closed.

## What "reopened" means, applied now

- The Introduction (`defense4/paper/INTRODUCTION_DRAFT.tex`, `QUARANTINE.md`,
  `INTRODUCTION_CLAIM_SOURCE_MATRIX.md`) is **quarantined again**.
- `EXPERIMENTAL_EVIDENCE_FREEZE.md` is marked **REOPENED — verdict withdrawn**.
- No claim from the ae2a802 freeze is accepted until it is re-derived from raw evidence by a
  fail-closed pipeline.

## Reproduced failures (commands + exit codes)

### F1. score_campaign.py prints ATTENTION but exits 0 on a hard anomaly
A committed pre-fix block with a real D2 RESPONSE bypass (the must-hold violation) is scored:

```
$ python3 defense4/timing/control/deploy/score_campaign.py \
    campaign_d6A_20260807T032304Z/block_A_D2_1.json \
    campaign_d6A_20260807T032304Z/ev_pre_A_D2_1.json \
    campaign_d6A_20260807T032304Z/ev_post_A_D2_1.json 60
# stdout: {... "verdict": "ATTENTION", "hard_anomalies": ["unplanned RESPONSE bypass ..."]}
$ echo $?
0            # BUG: a hard anomaly must exit nonzero
```

The scorer's `main()` always `return 0`. A caller keyed on the exit code cannot tell a clean block
from a failing one.

### F2. run_campaign.sh suppresses required failures with `|| true`
`grep -nE '\|\| true' run_campaign.sh` finds `|| true` on required operations:

- line 114 `clear-evidence`
- line 117 the sustained `campaign_driver.py` block (the block JSON itself)
- line 121 `score_campaign.py`
- line 122 the verdict readout
- line 130 the per-block PCAP copy
- line 133 `make_manifest.sh`

A driver crash, an empty block JSON, a scorer failure, a missing PCAP, or a broken manifest all let
the run continue and exit 0.

### F3. Malformed / empty / missing evidence is read as clean
```
$ echo '{"rows":[],"responded":0}' > /tmp/emptyrows.json
$ python3 .../score_campaign.py /tmp/emptyrows.json /tmp/empty.json /tmp/empty.json 60 ; echo $?
0            # empty rows -> exit 0
$ echo 'not json' > /tmp/bad.json
$ python3 .../score_campaign.py /tmp/bad.json /tmp/empty.json /tmp/empty.json 60 ; echo $?
0            # malformed JSON -> exit 0 (load() swallows the exception and returns {})
$ python3 .../score_campaign.py /tmp/nonexistent.json /tmp/empty.json /tmp/empty.json 60 ; echo $?
0            # missing file -> exit 0
```
`load()` catches every exception and returns `{}`, so a parser error, a missing file, or empty
input is scored as an empty-but-clean block.

### F4. byte_identity.py checks framing/length at one observation point
`byte_identity.py` reads only the relay-facing side (`p[IP].src == RELAY`) and checks the DNP3
start octets `0x0564` and the set of response lengths. It never compares the same frame's bytes
between the relay-facing ingress and the master-facing egress, so it cannot prove the switch
released the exact bytes it received. Its own docstring concedes the content diff is confounded by
live relay data. This is structural evidence, not byte identity.

### F6. Campaign SHA256SUMS hashes run.log before later writes
`make_manifest.sh` runs at the end of the main body (line 133), then the `on_exit` trap appends the
final "leaving Defense 4 running / rolling back" lines to `run.log`. So `run.log` changes after it
is hashed:
```
$ cd campaign_fixA_20260807T175525Z && sha256sum -c SHA256SUMS
./run.log: FAILED
sha256sum -c exit: 1
```
A manifest that fails its own verification is not a manifest.

### F5, F7-F10 (carried, closed in later phases with evidence)
- **F5**: controlled missing-ACK, missing-RESPONSE, overlap, duplicate, identity-mismatch, FIN/RST,
  combined-response, multi-segment, SELECT, OPERATE tests were **not executed** on the ae2a802
  binary. They require an isolated software outstation (Phase 2). Until executed they are OPEN, not
  scope boundaries.
- **F7**: the global manifest and canonical evidence disagree on source hashes, D2/D4 behavior,
  parameters, and verdict. Reconciled at the Phase 6 gate.
- **F8**: R11 reservoir readiness is measured, not structural. Carried to Phase 3.
- **F9**: the Introduction overstates fixed-value normalization and byte preservation. Quarantined
  now; rewritten only after Phase 6 from raw evidence.
- **F10**: the corrected-binary data supports zero *planned* D2/D4 RESPONSE bypass on the tested
  READ path, but it has late-arrival tails. The distribution is never described by its median alone
  or as an exact fixed value. A RESPONSE after T_RESP is a late safe release, not deadline
  normalization.

## Phase 1 repair (this run)

1. `score_campaign.py`: fail closed — nonzero on every hard anomaly (F1, F3), scenario/expectation
   schema so a declared negative is not read like a normal block.
2. `run_campaign.sh`: propagate every required failure, remove `|| true` on required ops (F2),
   validate PCAP count/names, finalize state + run.log **before** the manifest, then `sha256sum -c`
   (F6).
3. `pair_bytes.py`: paired relay-ingress vs master-egress exact-byte comparator (F4), replacing the
   single-point structural check.
4. `analyze_campaign.py`: fail on malformed/skipped blocks, session/block-aware statistics, full
   distributions with tails (F10).
5. Fail-closed fixtures proving each tool rejects malformed JSON, empty data, a missing PCAP, an
   injected RESP_BYPASS, an ordering inversion, a stale tag, a counter mismatch, a dropped packet, a
   one-byte payload mutation, and a bad manifest, plus one clean fixture that exits zero.

All Phase 1 work is offline. The live switch is not touched.

## Phase 1 repair — DONE and tested (offline)

The repaired pipeline lives in `../../control/deploy/`. Its fail-closed behavior is proven by
`../../control/deploy/fixtures/run_tests.sh` (regenerates deterministic fixtures, then asserts exit
codes). Result: **25 passed, 0 failed**.

| tool | before (ae2a802) | after (this run) |
|---|---|---|
| `score_campaign.py` | always exit 0; `load()` swallowed every error | exit 2 on missing/empty/malformed IO; exit 1 on any hard anomaly (bypass, ordering, stale tag, counter mismatch, token escape, queue/port drop, missing PCAP, absent counters); exit 0 only for a fully valid block. Scenario/expectation schema (`SCENARIOS`) tells a declared negative from a normal block. |
| `run_campaign.sh` | `\|\| true` on driver/scorer/copy/manifest | no `\|\| true` on required ops; aborts nonzero and preserves partial evidence; per-block PCAP validation; PCAP count/name check; manifest built in `on_exit` AFTER `run.log` is frozen, then `sha256sum -c`. `DRY_RUN` runs the whole flow offline. |
| byte preservation | `byte_identity.py`, one observation point | `pair_bytes.py`: paired relay-ingress vs master-egress, exact TCP-payload compare + preserved-header compare, MAC/offload/VLAN accounted; catches a one-byte mutation, drop, inject, reorder. `byte_identity.py` marked SUPERSEDED. |
| `make_manifest.sh` ordering | hashed `run.log` before later writes | run.log frozen before the manifest; a tampered file fails `sha256sum -c`. |
| `analyze_campaign.py` | silently skipped malformed blocks; pooled pseudoreplicates | fails on malformed/skipped/FAIL blocks; session-aware bootstrap CI; full distributions with tails (surfaces the D2/D4 late-arrival tails the median hid). |

The acceptance-only-in-Phase-6 rule stands: this repair makes the pipeline trustworthy, it does not
re-establish any experimental claim. Those are re-derived from raw evidence in Phases 2 through 6.
