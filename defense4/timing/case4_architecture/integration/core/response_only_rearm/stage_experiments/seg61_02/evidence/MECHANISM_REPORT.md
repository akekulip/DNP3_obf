# Mechanism report after the f0baa724a audit (2026-10-14)

Scope: `DNP3_Next_Implementation_Prompt_f0baa724a.md` and `DNP3_f0baa724a_Audit.md`. The work is on `main` and is not pushed. Defaults are not promoted, and production `case4_response_path` was restored and pinged after every hardware block. Every hardware run used the software endpoints on Vision; no relay OPERATE was sent.

There are two builds:
- **candidate61** (`seg61_02/evidence/full_04`, SHA256 `1b2d62d1…65aa`) is the qualified encoding baseline.
- **ctl_timing m3** (`ctl_timing_01/evidence/m3_01`, `c4819dba…9204`) has the same E, with N and T changed so that SELECT and OPERATE are timed like READ.

## Verdicts

### 1. Exact encoding and semantic correctness: PASS
- READ, SELECT and OPERATE responses are each one 61-octet TCP payload. READ uses G10V2 q0x00 0-5, q0x00 6-9, q0x01 10-22. Controls are split 15/6/1 into frames of 28/19/14. Every CRC is correct, the application octets are preserved, and requests are native.
- A per-attempt profile-exact checker (`read_reencode_01/profile_check.py`) now enforces this layout for every response attempt, retransmissions included. Legal alternative layouts pass the general standards check and fail the profile check, as the audit required.
- The 60 retained candidate61 trials pass, except `candidate61_reconnect_950_01/c2`, which was captured on the wrong port.
- ctl_timing leaves E byte-identical, so its 61-octet output is the same. Its blocks pass the same checks.

### 2. Repeated SBO and lifecycle: PASS within the supported shape
- Repeated SBO ran on one persistent connection: 64 cycles of SELECT, OPERATE and READ, crossing both the application (mod 16) and transport (mod 64) sequence wraps.
- **candidate61:** three blocks × four arms, 768/768 cycles verified per cycle. The check uses the wire echo, sequence, single attempt, one SELECT and one OPERATE callback with status SUCCESS, and timestamp order (`repeat_sbo_summary.json`).
- **ctl_timing:** six blocks, 1,536/1,536 cycles.
- Earlier lifecycle gates (persistence, seven loss classes, reconnect, stale tokens, external replay, held-OPERATE duplicates) passed in step 3 on candidate61.
- **Limitation:** a SELECT not followed by its OPERATE (an abandoned SELECT) makes N drop the connection's next request indefinitely. Only a reset recovers it (`model_abandon_03`). This is an unsupported shape with an explicit expectation, not fixed.

### 3. Timing objectives: READ normalized on candidate61; READ, SELECT and OPERATE normalized on ctl_timing; J kept; piggyback bounded

| | candidate61 | ctl_timing m3 |
|---|---|---|
| READ CLRT - 950 us | median +3..+7 us, abs p99 51-54 us (step 4) | median +4..+5 us |
| SELECT CLRT | native, about 5.3 ms | median +4 us vs gap, abs p99 55-56 us |
| OPERATE CLRT | native, about 5.3 ms | median +5..+10 us, abs p99 87-92 us |
| OPERATE command hold J (2.4 ms) | request→ACK 2.65 ms | measured master TX to outstation RX: min 2468 us |
| Piggyback request→response | 30.1 ms (readiness fallback) | about 4.12 ms (pb = 4 ms), p99 4.16 ms |

- n = 192 control exchanges per arm and fixture for ctl_timing. The 100 us p99 bound is provisional.
- Request→ACK is not normalized for any kind: the ACK is held until the response is seen (`rearm_01/TIMING_CONTRACT.md`).

### 4. Internal and external packets and bytes

| | candidate61 | ctl_timing m3 |
|---|---|---|
| external growth | 12 bytes per READ, 24 per SELECT or OPERATE response, counted once (exact in every trial) | same |
| internal RX frames per exchange, timed arms | about 530 on the repeated-SBO workload; 784 on the 500-READ eval | about 1,060 (separate ACK), about 630 (piggyback) |
| held re-waits per exchange | about 175 | about 424 |
| internal RX frames per exchange, untimed arms | 3-5 | 3-5 |

- Counted from switch snapshots by `cost_report.py`: each loop role counted once, no RX+TX double counting.
- The intentional delay is the hold (gap, J, pb). The internal receives are the re-wait laps and blockers that implement it. Low overhead is not claimed.

### 5. Resources and finite state
- **Stages:** candidate61 and ctl_timing m3 both compile at N11/E12/T11 on SDK 9.13.1 and 9.13.2, and both pass the mirror guard.
- **CRC factorization experiment** (`seg61_e_crc_01`): correct, but it recovers no stage (E stays 12, N rises to 12). The baseline is kept.
- **Singleton authority:** one transaction at a time per connection.
- **Generation use:** ctl_timing uses three lane generations per READ + SBO cycle (candidate61 uses one). Per-run headroom prechecks apply.
- **Stale blocker tokens:** a SELECT's blocker tokens can be stranded when its OPERATE opens the next lane generation. These are rejected as stale and bounded at 2k per cycle by the runner.

### 6. Reproducibility, identity, restore
- Generators reproduce every source byte for byte: candidate61, ctl_timing m1/m2/m3, and the CRC experiment.
- Configs regenerate byte-identically and pin the compiler manifests and the endpoint source and build hashes.
- Source-only checkouts skip build-tree tests with exact rebuild commands. Hardware binding fails hard without the build.
- `standards.json` carries the precision status and the qualification verdict.
- Two retained failed attempts, both fail-closed:
  - `candidate61_repeat_sbo_950_b1`: a stale endpoint build. Its source was reconstructed and rebuilt bit for bit.
  - `ctl_timing_repeat_sbo_950_b1`: the stale-token bound was inherited from candidate61.
- Model logs over 50 MiB are listed with SHA256 in the `UNTRACKED_LARGE_LOGS.sha256` ledgers.

## Tails (Gate 5)

Verdict: **unresolved**. One lead is documented and one factor is ruled out. No component is isolated.

**What the tail is.** On the off arm the switch neither holds nor rewrites, so each packet in Vision's TX capture can be matched to the same packet in its RX capture. `analysis/transit_report.py` does this per leg. Transit is normally a few microseconds. In some runs three packets per 502-request connection take 1.1 to 1.5 ms instead.

**The signature is index-exact.** When events occur, they usually sit at the same positions on the connection:
- an outstation ACK (sometimes the response) after request 127, and again after 255 (sometimes 126 and 254);
- a request at about 273 to 285.

So the period is 128 exchanges, counted per connection, and it is intermittent: some runs show nothing.

**Runs.** All are on candidate61's off arm, separate-ACK fixture, 59,570 PPS, 950 us. Summary: `evidence/tail_summary.json` (`analysis/tail_summary.py`, threshold 500 us).

| condition | runs | runs with events | 127/255/~275 signature |
|---|---|---|---|
| retained off arms (eval b1-b3, strict b1-b3) | 6 | 5 | 5 (eval b3 at 126/254/285) |
| control, coalescing unchanged (`candidate61_tail_ctl_01..10`) | 10 | 4 | 2 (ctl_03, ctl_08); ctl_05 at 210/273/338, ctl_10 one 559 us response at 10 |
| Vision `tx-frames-irq` 256 to 64 (`candidate61_tail_txirq64_01..07`) | 7 | 2 | 1 (txirq64_07); txirq64_05 at 127/246/426 |

- Each factor run went through `rearm_01/hw/tail_factor.py`. It records `ethtool -c` on Vision's parent NIC, applies one change, verifies it by read-back, runs the unchanged campaign, then restores the field and verifies the read-back again. Every run has `campaign_rc` 0 and `restore_ok` true (`tail_factor.json` in each run directory).
- **Environment recorded** (`evidence/tail_environment_vision.txt`, read-only snapshot taken after the runs, with every field back at its recorded value). The Vision NIC is i40e. Coalescing is adaptive rx/tx on, rx-usecs 50, tx-usecs 50, tx-frames-irq 256. The qdisc is fq_codel per queue.
- **Hardware timestamps:** `ethtool -T` lists hardware receive filters for PTP only, with no `all` mode, so there are no hardware timestamps for TCP. The rerun with hardware timestamps that the plan allowed for was not possible.

**What this rules out.** Changing tx-frames-irq from 256 to 64 leaves the 127/255/275 signature in place (txirq64_07), so the NIC's TX interrupt batching at 256 frames is not the cause. Seven runs per condition cannot separate the event rates (4/10 against 2/7).

**What is still open.** The index-exact period points to something that counts per-connection packets or segments: the endpoints' TCP stacks (delayed ACK, window updates), the capture path, or the endpoint applications. It does not point to wall-clock time. The next single factors to test are adaptive coalescing off, a capture with a different snapshot or buffer size, and the production program on the same traffic. Each needs Philip's go-ahead. Until a factor moves the signature, the tail attribution stays "unresolved", and nothing here attributes the tail to the switch.

## Not done
- Real-relay compatibility and default promotion. Both are Philip's decision.
- Fingerprint resistance beyond equal lengths. Plaintext object contents and the one-versus-three DNP3 frame structure remain visible.
