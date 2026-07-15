# Multi-CROB Highest-N (Nmax) Sweep — Results

_Run: 2026-07-06 (gambit-driven over SSH). Rig: Vision `10.10.54.19` master →
Hulk `10.10.54.158:20000` `run_outstation.py --control-test`. One SBO per N, fresh
outstation each N, default outstation config (db_size 300)._

## Result

**Nmax = 16** for this exact configuration. Every N from 1 to 16 completes a clean
Select-Before-Operate of N CROBs in one command set (all objects `SUCCESS`, outstation
final state matches the expected alternating result, and the independent PCAP analyzer
passes). N ≥ 17 fails. The first failure is **N = 17**; Nmax = 16 was reproduced **3×**.

This is **not** a universal DNP3 maximum — it is the limit of the tested OpenDNP3
build, hosts, point count, and (default) fragment/limit settings. See
`reports/sweep_manifest.csv` for the per-N record and `reports/sweep/analyze_n<N>.json`
for the per-N analyzer reports; PCAPNGs are `captures/sweep/multicrob_n<N>.pcapng`.

## Cause of the boundary — a command-count limit, not fragment size

The failure is the OpenDNP3 outstation's **`maxControlsPerRequest` (default 16)**. At
N ≥ 17 the outstation accepts the first 16 CROBs (`CommandStatus` = 0, SUCCESS) and
rejects every CROB past the 16th with **`CommandStatus` = 8 = `TOO_MANY_OPS`** in the
SELECT response. Because the SELECT is not fully successful, the master's combined
`SelectAndOperate` task does **not** issue the OPERATE — so no controls execute and the
outstation's simulated state is unchanged. The task still completes at the protocol
level (`SUCCESS`), which is exactly why task-level SUCCESS must not be read as proof
that the controls applied.

Directly observable in the captures (from the analyzer):

- N=16 SELECT-response statuses: `[0]×16` (all success).
- N=17 SELECT-response statuses: `[0]×16 + [8]` — the 17th is `TOO_MANY_OPS`.
- N=32: `[0]×16 + [8]×16`; N=64: `[0]×16 + [8]×48`; N=128: `[0]×16 + [8]×112`.

The boundary is **not** DNP3 fragmentation: N=17 and N=18 still fit in a **single**
DNP3 data-link frame, yet already fail on the count. Link-frame growth (SELECT), for
reference: N ≤ 16 → 1 frame, N=19 → 2, N=32 → 2, N=64 → 4, N=128 → 7. The analyzer
reassembles these multi-frame SELECTs into **one** logical application fragment, so a
larger-N request is still recognised as one logical SBO transaction even when it spans
several link frames.

The limit is enforced by the OpenDNP3 **stack**, not the application command handler:
for N ≥ 17 the outstation's `ControlTestCommandHandler` only ever receives `Select()`
for the first 16 indexes (all succeed) — the stack rejects the excess with
`TOO_MANY_OPS` before the handler is called. From the application's point of view the
SELECT batch succeeded and it is waiting for an OPERATE that never arrives, so the
outstation writes no failure evidence for the over-limit N. The authoritative
failing-N evidence is therefore the **PCAP + analyzer report** (which see the on-wire
`TOO_MANY_OPS` statuses), not an outstation JSON. (The application-level batch-discard
+ evidence-on-failed-SELECT still fires for handler-visible failures such as the
negative test's out-of-range index 99.)

## Method

`run_multicrob_sweep.py` (rig orchestration): for each N it starts a fresh
`--control-test` outstation with `--control-point-count N`, captures a per-N
`.pcapng` with `dumpcap`, runs `run_master.py --action multi-crob-sbo --crob-count N`,
pulls the outstation JSON + master JSON + PCAP, and runs `analyze_multicrob_pcap.py`.
A run PASSES iff master exit 0, master `task_completion == SUCCESS`, outstation
`final_state_matches_expected`, **and** the analyzer passes for N. Nmax is found by
testing the mandatory points (1, 2, 4, 8, 16, 18, 19, 32, 64, 128) plus every N in
1–19, taking the first failure in the ascending sequence, binary-searching the
boundary, then re-running Nmax three times.

## Acceptance criteria (from next_steps.md §7 / acceptance)

- **N=1 … N=19 each have a separate PCAPNG and a JSON report** — `captures/sweep/multicrob_n1..n19.pcapng` and `reports/sweep/analyze_n1..n19.json`. ✓
- **N=19 recognised as one logical SBO even across multiple data-link frames** — its SELECT spans 2 link frames and the analyzer reassembles them into one logical fragment. ✓
- **Nmax (16) has a passing PCAP report, a passing outstation JSON, and 3 successful repeats** — `analyze_n16.json` (pass), `logs/outstation/multicrob_sweep_n16.json` (`final_state_matches_expected: true`), 3× repeat rows in the manifest. ✓
- **First failing N (17) has a PCAPNG and a report explaining the failure** — `multicrob_n17.pcapng` + `analyze_n17.json`; cause = command-count limit (`maxControlsPerRequest`=16 → `TOO_MANY_OPS`), not fragment size / timeout / parser rejection. ✓

## Scope / non-claims

Software-only; no physical outputs; SELECT-then-OPERATE only (no DirectOperate); no
fake control objects, padding, chaff, replay-server changes, P4, or obfuscation. The
number 16 is the default `maxControlsPerRequest` of this OpenDNP3 build — a different
outstation configuration would characterise a different Nmax and is out of scope here.
