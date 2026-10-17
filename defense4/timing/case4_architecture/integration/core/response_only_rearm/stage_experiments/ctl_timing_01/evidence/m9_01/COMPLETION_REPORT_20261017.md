# m9_01 completion report: supported READ/SBO profile, gates, and limitations (2026-10-17)

The frozen candidate is **ctl_timing_01 m9_01**, source `6590141f…` (`freeze.json`, 45 files). `freeze.py --check`
passed before every silicon block.

**Verdict: not qualified.** The candidate passes:
- the model gate;
- the abort gate;
- every recovery block on silicon;
- all three piggyback qualification blocks;
- repeated-SBO block b2.

Qualification fails on two repeated-SBO blocks, b1 and b3, each on one exchange. The targeted isolation block also
fails its cleanup check: without the switch poller, the drain could be observed only through the harness's
detection bound. No block was rerun. Every result below is the block's first and only attempt.

## Supported profile (unchanged contract)

- **Requests and responses.** Requests stay native. Eligible READ, SELECT and OPERATE responses are transformed to
  61 bytes.
- **Timing.** Release follows the existing blocker-based timing, request-anchored, with a 950 µs target and a p99
  bound of 100 µs. The OPERATE hold J is unchanged.
- **Endpoints.** Software endpoints under the documented TCP profile: OpenDNP3 on Vision, separate-ACK and piggyback
  fixtures.
- **Not claimed.** Exactly-once delivery is not claimed; nor are size, splitting or real-relay behaviour.

## Gates

| gate | result | evidence |
|---|---|---|
| 1. Duplicate-response accounting | **PASS, defect fixed** | `../model_contention_m8_02_02/FAILURE_20261016.md`; `tests/test_reset_then_syn.py`; `NOTES_20261016.md` |
| 2. Abort handling (model) | **PASS** 79/79 | `../model_abort_m9_01_02`; attempt `_01` retained, its acceptance error resolved from source |
| 3a. Reporting | **done** | `model_summary.json` lists every attempt; m8_02 is marked blocked |
| 3b. Isolation acceptance v2 | **done** | `seg61_02/analysis/isolation_v2.py`; the v1 verdicts are unchanged |
| Model suite on m9_01 | **PASS**: all 9 drivers, latest attempt each | `model_summary.json` (`model_gate_passed`) |
| 4. Silicon recovery blocks | **PASS**, restore verified each | see the table below |
| 4. Silicon qualification blocks | **FAIL** on 2 of 6 | strict aggregate: `seg61_02/evidence/hw_campaigns/m9_01_strict_summary.json` |
| 4. Silicon isolation block | **FAIL** (v1 and v2) | `ctl_m9_stale_iso20_950_01/isolation_v2.json` |

**Gate 1, the defect.** A same-tuple SYN arriving one lap after a master RST claimed N's work cell. The RST's close
then fell through to `terminal_abort`, and N kept the old connection. That is also why the RST's ACK normalized
12 octets in one attempt and 24 in the other: N and E never armed the new connection in attempt 02.

**Gate 2, the coverage.**
- READ and SELECT aborts in both branches: held, and after release;
- OPERATE aborts, which are reachable only after release, because J > D;
- translated SEQ/ACK and checksums correct;
- no later response leakage;
- reconnect;
- the +48/+50 negatives.

## Silicon (2026-10-16 22:59 to 2026-10-17 00:06; runner logs in `seg61_02/evidence/hw_campaigns/m9_01_silicon_sequence/`)

| block | block rc | restore_verify | result |
|---|---:|---|---|
| ctl_m9_persistence_graceful_950_01 | 0 | ok | PASS (measurement_only verdicts; recovery gate) |
| ctl_m9_persistence_rst_950_01 | 0 | ok | PASS (measurement_only) |
| ctl_m9_loss_core_950_01 | 0 | ok | PASS (measurement_only) |
| ctl_m9_reconnect_950_01 | 0 | ok | PASS |
| ctl_m9_held_operate_350_01 | 0 | ok | PASS (measurement_only, 800 µs gap) |
| ctl_m9_qual_repeat_sbo_950_b1 | 1 | ok | **FAIL**: timing_only SELECT p99 error 924 µs, one exchange (index 127) |
| ctl_m9_qual_repeat_sbo_950_b2 | 0 | ok | PASS, all four arms |
| ctl_m9_qual_repeat_sbo_950_b3 | 1 | ok | **FAIL**: combined READ p99 error 908 µs, one exchange (index 117) |
| ctl_m9_qual_piggyback_950_b1, b2, b3 | 0 | ok | PASS |
| ctl_m9_stale_iso20_950_01 | 1 | ok | **FAIL**, see the isolation section below |

**Strict aggregate:** `m5_summary.py --strict --prefix ctl_m9_`, with:
- `--require` naming all 11 recovery and qualification blocks;
- `--measurement-only` naming the four recovery blocks whose verdicts are measurement_only by design: two
  persistence, loss core, held OPERATE. These blocks carry too few timed exchanges for a precision verdict. They
  gate recovery and standards behaviour, which passed (`trial.json ok` true).
- `--expected-gap` 800 µs for held OPERATE.

Result: FAIL, 11 reasons, all from b1 and b3. Contention counters and restores pass in every block.

### The two qualification failures

Each failing block has exactly one out-of-bound exchange. Every other exchange of every kind lies within
±100 µs of 950 µs.

| block, exchange | master-visible ACK latency | CLRT | round trip | the other exchanges of that kind, median |
|---|---:|---:|---:|---|
| b1 SELECT 127 | 6,612 µs | 26 µs | 6,638 µs | ACK 5,499, round trip 6,448 (max 6,486) |
| b3 READ 117 | 9,608 µs | 42 µs | 9,650 µs | ACK 8,507, round trip 9,479 (max 9,582) |

**What the captures show.**
- The outstation's own response was not late. For b1's exchange 127, the outstation-side capture (`out.pcap`) has
  the response 5,384 µs after the request; the median over the block is 5,414 µs.
- The master saw the ACK about 1.1 ms later than usual, and the response only 170–190 µs later than usual, so the
  two arrived 26–42 µs apart. Both lanes are request-anchored: the ACK was released or observed late while the
  response kept close to its own deadline.

**What they cannot show.** Whether the ~1.1 ms delay lies in the switch's ACK release or in the master host's receive
path is not observable. The switch does not timestamp releases (its timestamp registers are never written), and the
captures are host-side.

**Classification.** This is the same signature as the unresolved index-127 tail on m4 and m5. The FAIL stands. No
exchange is excluded and no bound is changed.

### Isolation

`ctl_m9_stale_iso20_950_01` was judged twice.
- **Under v1** it fails three checks: the cleanup bound (detection 18.62 s against 18.00 s), the full-run rule, and
  OUT_TOKEN_STALE 15 against the build bound 12.
- **Under v2:**
  - **rejection accounting: PASS.** Raw 7 + 4 rejections are conserved; 0 stale blockers before the permit; 4 after
    it, against an allowance of 25; and the build bound applied to blockers is 4 ≤ 12.
  - **cleanup: FAIL.** This qualification block ran without the switch poller, so v2 falls back to v1's detection
    bound, which it misses by 0.62 s.

The diagnostic D1, which had the poller, showed this overrun to be the poll phase rather than a slow drain. A
qualification-grade repair needs the poller (or another switch-side drain observation) inside the isolation block.
The bound is unchanged.

## Remaining limitations

1. **The ACK-release tail.** A ~1.1 ms master-visible ACK delay on single exchanges, cause unresolved (switch release
   or host receive). It is what fails qualification.
2. **Isolation cleanup is unobservable without the poller** in the block.
3. **The m9 reset wait** covers events that leave the owner unchanged. An owner-changing event one lap after a master
   RST still loses the RST (pinned test). The SYN that met the waiting RST is dropped, so the master reconnects on
   its SYN retransmission (about 1 s on Linux). Up to about 65 recirculation passes per RST.
4. **The m8 reset rows.** They key on distance (49/37), not on T's held state. A bare RST is forwarded untranslated.
   An RST at the distance of two held responses is dropped.
5. **OPERATE responses are never held** (J > D), so an OPERATE abort is always the released branch.
6. **Clean-checkout reproduction.** `seg61_02/hw/config/ctl_m9_stale_tokens_950.json` is untracked: it matches the
   `*_token*` ignore pattern. `build_candidate61_configs.py` regenerates it deterministically, and
   `ctl_m9_stale_iso20_950.json`, derived from it, is tracked.
7. **Deferred, unchanged:** TCP splitting, input-size generalization, other protocol profiles, stage/traffic
   optimization, real-relay compatibility, default promotion.

## Reproduce

- **Model:** `python3 ctl_timing_01/run_model.py evidence/m9_01 <driver> <attempt> --milestone m9`. The pb-injected
  drivers (smoke, packets, rearm, dup, repeat) also take `--pb 300000000`. Then
  `python3 ctl_timing_01/model_summary.py evidence/m9_01`.
- **Source tests:** `python3 -m pytest ctl_timing_01/tests`.
- **Silicon:** `m9_01_silicon_sequence/m9_silicon*.sh` and the block lists beside them. Each block is
  `run_block.sh <tool> <config> <run_id> <args> < /dev/null`, preceded by `freeze.py --check`.
- **Aggregates:** the strict command above, and `python3 seg61_02/analysis/isolation_v2.py <run_dir>`.
