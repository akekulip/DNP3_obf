# DNP3 Multi-CROB Select-Before-Operate Validation Harness

A **software-only protocol/API check**, separate from the obfuscation research line.
It answers one question: can a single DNP3 SELECT/OPERATE transaction carry and
process **multiple valid CROBs** (Control Relay Output Block, Group 12 Variation 1)
targeting multiple output indexes, in **one** command set? **Answer: yes**, and the
harness now runs a reproducible **highest-N sweep** — for the tested rig configuration
**Nmax = 16** CROBs per SBO (the OpenDNP3 outstation `maxControlsPerRequest` default;
see `reports/sweep_results.md`).

This is one of two independent harnesses split out from the original combined harness
(the other is `../dnp3_split_harness/`). It is **not** an obfuscation mechanism and is
not part of the Class 0 READ / replay / CRC-split path. It carries control-command
code deliberately, only for this validation.

**Naming rule (hard):** the internal project codename must never appear anywhere.

**Governing doc:** `docs/multi_crob_validation.md` (how to run + Wireshark steps).
Interactive explainer: `docs/multi_crob_tutorial.html`.

## Layout

- `lab_config.py` — single source of truth for lab settings (IPs, port, link addrs).
- `run_outstation.py` — outstation. `--control-test` swaps in `ControlTestCommandHandler`
  backed by **N** simulated binary output points (`--control-point-count N`, indexes
  `0..N-1`, initial state alternating even=False/odd=True; default N=2). SELECT validates
  + records each CROB; OPERATE requires a matching, unexpired SELECT (`--select-timeout-sec`,
  default 5 s), flips the point, and clears the consumed selection. A partially-failed
  SELECT batch is discarded (`Start`/`End`). Writes JSON evidence (`--run-id`).
  **Without the flag the outstation is unchanged** (controls rejected).
- `run_master.py` — master. `--action multi-crob-sbo` builds ONE `CommandSet` and issues
  one `SelectAndOperate`. `--crob-count N` is the primary path (even→LATCH_ON /
  odd→LATCH_OFF over `0..N-1`); `--crob-test {A,B,C}` and `--control-test-negative` remain
  as regression aliases. Writes a JSON summary (`--run-id`); exits non-zero on
  timeout/non-success; the SBO round-trip is measured only around `SelectAndOperate`.
- `analyze_multicrob_pcap.py` — independent DNP3 parser: reassembles TCP → link frames
  (validates all CRCs via `dnp3_crc.py`) → transport → app fragments, verifies the G12V1
  SELECT/OPERATE (+responses) carry `qualifier 0x28, Count=N`, N distinct indexes,
  identical lists, and N success statuses; emits a JSON pass/fail report.
- `run_multicrob_sweep.py` — highest-N rig sweep → `reports/sweep_manifest.csv` +
  `reports/sweep/analyze_n<N>.json` + `captures/sweep/multicrob_n<N>.pcapng`.
- `docs/`, `reports/`, `captures/` — governing doc + tutorial, results write-ups, PCAPs.

## How to run (cd into this directory first)

```bash
# outstation host:  python3 run_outstation.py --control-test
# master host:       python3 run_master.py --action multi-crob-sbo --crob-test C
```

Each staged test runs against a **freshly restarted** `--control-test` outstation
(initial state index 0=False, index 1=True) so the expected end-state is deterministic.

| Test | CROBs (one command set) | Expected outstation end-state |
|------|--------------------------|-------------------------------|
| A | index 0 LATCH_ON | index 0 → True |
| B | index 1 LATCH_OFF | index 1 → False |
| C | index 0 LATCH_ON **+** index 1 LATCH_OFF | index 0 → True, index 1 → False |
| D (`--control-test-negative`) | index 0 LATCH_ON + unsupported index 99 | index 99 rejected (OUT_OF_RANGE); no OPERATE ran; index 0 unchanged (safe) |

## Highest-N sweep

```bash
# single N, by hand (fresh outstation with N points, then N CROBs from the master):
# outstation host:  python3 run_outstation.py --control-test --control-point-count 16 --run-id n16
# master host:       python3 run_master.py --action multi-crob-sbo --crob-count 16 --run-id n16
# analyze the capture:
python3 analyze_multicrob_pcap.py --pcap captures/sweep/multicrob_n16.pcapng --expected-n 16

# full automated rig sweep (fresh outstation + PCAP per N; finds Nmax):
python3 run_multicrob_sweep.py
```

**Result (rig, 2026-07-06): Nmax = 16.** N ≤ 16 complete a clean SBO of N CROBs; at
N ≥ 17 the outstation's `maxControlsPerRequest` (default 16) rejects the excess with
`CommandStatus TOO_MANY_OPS`, the master does not OPERATE, and no controls apply. This
is a command-count limit, **not** DNP3 fragmentation (N=17/18 still fit one link frame).
Full write-up + acceptance mapping: `reports/sweep_results.md`;
per-N data: `reports/sweep_manifest.csv`. Nmax is for this exact configuration only —
not a universal DNP3 maximum.

## Boundary-index CROB test

A separate two-case experiment that **distinguishes a per-request operation-count limit
(`TOO_MANY_OPS`, the N≥17 result above) from a nonexistent-output-index rejection
(`OUT_OF_RANGE`)**. The outstation is configured with only K valid points (indexes
`0..K-1`); the master then sends N CROBs where N can equal or exceed K.

```bash
# both cases (valid K=5,N=5 and invalid K=5,N=6) on the rig:
python3 run_crob_boundary_index_test.py --user decps
# knobs: --valid-points K  --invalid-extra E (N=K+E)  --only valid|invalid|both  --no-deploy
```

Each case runs against a **freshly restarted** `--control-test` outstation with a fresh
`.pcapng`, pulls the PCAP + master/outstation JSON, and analyzes it with
`analyze_multicrob_pcap.py` (`--mode all-success` for the valid case, `--mode
boundary-index --configured-points K` for the invalid case).

| Case | Outstation K | CROBs N (indexes) | Expected |
|------|-------------|--------------------|----------|
| Valid | 5 | 5 (0–4) | all SELECT statuses SUCCESS, OPERATE sent, all 5 states match |
| Invalid | 5 | 6 (0–5) | index 5 rejected in the SELECT response; observe status + whether OPERATE fires |

Artifacts: `captures/boundary/crob_boundary_{valid_k5_n5,invalid_k5_n6}.pcapng`,
`reports/boundary/analyze_{valid_k5_n5,invalid_k5_n6}.json`,
`reports/boundary/boundary_index_manifest.csv`, `reports/boundary/boundary_index_results.md`.

**What it proves:** the exact response-side evidence (per-index `CommandStatus`) OpenDNP3
produces for a nonexistent index, and whether that differs from the `TOO_MANY_OPS`
count-limit case. **What it does not prove:** it does not implement invalid-index padding,
does not change `maxControlsPerRequest`, maps no index to a physical output, and is not a
universal DNP3 result — it characterises this one OpenDNP3 build/host/config. Task-level
master SUCCESS is not treated as proof that any output changed (per-index evidence is the
outstation JSON + PCAP).

## Invalid-index CROB "padding candidate" tests

A broader eight-case suite that characterises invalid-index **placement** (end / begin /
middle), **multiple** invalid CROBs, a **decoy-only** all-invalid command set, and the
**interaction** between invalid indexes and the operation-count limit. It uses the master's
new `--crob-plan "idx:CODE,idx:CODE,..."` (explicit, ordered CROBs; overrides `--crob-count`
/ `--crob-test`; rejects duplicate/malformed entries) to place invalid indexes at chosen
positions.

```bash
python3 run_crob_padding_candidate_tests.py --user decps      # all 8 cases
# knobs: --only <case_name>  --valid-points K  --iface  --remote-dir  --no-deploy
```

Findings (rig, this OpenDNP3 config): a nonexistent index is rejected per-index in the SELECT
response with `OUT_OF_RANGE` (12) regardless of its position; the master then does not
OPERATE and no valid output changes. Multiple invalid indexes each show a rejection; an
all-invalid "decoy" set is fully rejected. When the command count exceeds
`maxControlsPerRequest`, the excess op returns `TOO_MANY_OPS` (8) — and with K=5, N=17 both
appear in one response (`OUT_OF_RANGE` for invalid ops within the limit, `TOO_MANY_OPS` for
the 17th). Artifacts: `captures/padding_candidates/<case>.pcapng`,
`reports/padding_candidates/analyze_<case>.json`, `padding_candidate_manifest.csv`,
`padding_candidate_results.md`. **This does not implement or prove padding**; it only
characterises the response-side evidence invalid-index CROBs produce — a prerequisite to any
later cover-traffic design.

## pydnp3 / pybind11 gotcha (worked around)

`SelectAndOperate` is one combined task. On the rig's build (Python 3.12) the
non-copyable `ICommandTaskResult` delivered to the command-result callback cannot be
marshalled into Python and aborts the process; on the older build (Python 3.8) it
hangs. The master therefore does not read the per-index command result — it captures
the **task-level** completion from `OnTaskComplete(info)` (which blocks the single DNP3
thread while the main thread writes the summary and hard-exits; file I/O on the callback
thread deadlocks). Authoritative per-index evidence is the outstation log + the PCAP.

## Validation status

- **Rig re-validated 2026-07-06** for this standalone tree (Vision master → Hulk
  `run_outstation.py --control-test`), deployed via rsync, with a **PCAP captured per
  test**: A → idx0=True; B → idx1=False; C → idx0=True/idx1=False (2 selects + 2
  operates); D → index 99 OUT_OF_RANGE, no OPERATE, idx0 unchanged. All `master rc=0`,
  no aborts, summaries written. tshark decode confirms the CROBs on the wire — Test C
  `Select (0x03)` and `Operate (0x04)` each carry `Control Relay Output Block
  (Obj:12, Var:01), 2 points` (Point 0 Latch On, Point 1 Latch Off), responses
  `Control Status: Req. Accepted (0)`. PCAPs: `captures/multi_crob_{test_a,test_b,
  sbo_test_c,negative_test_d}.pcap`; original headline capture
  `captures/multi_crob_sbo.pcap`. See `reports/multi_crob_sbo_results.md`.
- Also loopback-validated (127.0.0.1) as a dev smoke test.

## Safety / scope

Software-only; no index is mapped to any physical GPIO, relay, breaker, or PLC. This
establishes only that the protocol/API accepts a multi-CROB command set — not physically
simultaneous execution, universal vendor support, atomic execution, or P4 feasibility,
and it is **not** a justification to inject controls anywhere else.

## Lab topology (rig)

- Master = Vision `10.10.54.19`; outstation = Hulk `10.10.54.158:20000`;
  dev box = gambit `10.10.54.133` (pydnp3). DNP3 link addresses: master=1, outstation=10.
