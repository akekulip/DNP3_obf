# Multi-CROB Select-Before-Operate Validation

Software-only validation that a DNP3 master and OpenDNP3 outstation can encode and
process **multiple valid CROB control objects in one Select-Before-Operate command
set**. This is a protocol/API validation only — **not** an obfuscation mechanism,
and it changes nothing in the existing Class 0 READ / TCP replay / CRC-boundary
split path.

## Concepts (use these terms exactly)

- **CROB** = Control Relay Output Block, **DNP3 Group 12 Variation 1**. It is an
  application-layer *object*, not a function code. A CROB carries an output point
  **index** and a **control code** (here `LATCH_ON` / `LATCH_OFF`), plus count /
  on-time / off-time.
- **SELECT** and **OPERATE** are DNP3 application **function codes**.
- **Multiple CROBs** = several indexed control objects inside **one** logical DNP3
  command set (here index 0 `LATCH_ON` and index 1 `LATCH_OFF`).
- **Select-Before-Operate (SBO)**: master SELECTs the CROBs → outstation validates
  and accepts/rejects → master OPERATEs the same CROBs → outstation executes or
  rejects each. This experiment builds **one** command set with two CROBs and runs
  SBO over it (not two independent single-CROB transactions).

`LATCH_ON` / `LATCH_OFF` are **control codes applied to a binary output point** —
not "multiple physical latches". Everything here is **software-only**: the two
control points are in-memory simulations (index 0 = feeder-A, index 1 = feeder-B).
No index is mapped to any GPIO, breaker, relay, PLC, or external device.

## What was added

- **Outstation** (`run_outstation.py`): `--control-test` swaps in a
  `ControlTestCommandHandler` backed by two simulated binary output points
  (initial state index 0 = False, index 1 = True). SELECT validates + records each
  CROB; OPERATE requires a matching prior SELECT, flips the point, logs
  `index / operation / previous state / resulting state / success`, and clears the
  consumed selection. Only indexes 0/1 and codes `LATCH_ON`/`LATCH_OFF` are
  accepted; anything else returns an explicit failure status. **Without the flag
  the outstation behaves exactly as before (controls rejected).**
- **Master** (`run_master.py`): `--action multi-crob-sbo` builds one `CommandSet`
  with the requested CROBs and issues one `SelectAndOperate`. `--crob-test {A,B,C}`
  selects the staged test (default C, the two-CROB set); `--control-test-negative`
  runs the optional negative test. Results go to `logs/master/<test>_summary.txt`.

## Highest-N (Nmax) experiment

The fixed two-CROB validation above generalises to a reproducible **highest-N**
experiment for one controlled configuration. New flags:

- **Outstation** `--control-point-count N` — N simulated control points (indexes
  `0..N-1`, initial state alternates even=False / odd=True). `--select-timeout-sec S`
  sets the SELECT lifetime (default 5 s; an OPERATE after expiry returns `NO_SELECT`).
  `--run-id ID` names the JSON evidence file `logs/outstation/multicrob_<ID>.json`.
- **Master** `--crob-count N` — builds ONE command set of N CROBs over indexes
  `0..N-1` (even → `LATCH_ON`, odd → `LATCH_OFF`); expected end-state is every even
  index True, every odd index False. Overrides `--crob-test`. `--run-id ID` writes
  `logs/master/multicrob_master_<ID>.json`.

Structured evidence (do not treat task-level SUCCESS as proof every output changed):

- Outstation JSON: `requested_n, select_seen, select_success, operate_seen,
  operate_success, rejected_indexes, pending_selection_count,
  final_state_matches_expected, final_state`.
- Master JSON: `requested_n, crob_plan, task_completion, timed_out, sbo_issued_at,
  sbo_round_trip_sec` (the SBO round-trip is measured only around `SelectAndOperate`,
  not the ~2 s channel bring-up). A timeout or non-SUCCESS task exits non-zero.

Independent PCAP analyzer:

```bash
python analyze_multicrob_pcap.py --pcap <file.pcapng> --expected-n N --json report.json
```

It reassembles TCP → DNP3 link frames (validating the header CRC and every data-block
CRC) → transport → application fragments, finds the G12V1 SELECT / SELECT response /
OPERATE / OPERATE response, and verifies `Group=12, Var=1, qualifier=0x28, Count=N`,
N distinct indexes, identical SELECT/OPERATE lists, and N success statuses. It reports
the logical-fragment and data-link-frame counts per SELECT and OPERATE (never TCP
packet count) and exits non-zero on any failure.

Automated sweep (rig orchestration; needs `dumpcap` on the outstation host):

```bash
python run_multicrob_sweep.py            # mandatory points 1,2,4,8,16,18,19,32,64,128
python run_multicrob_sweep.py --points 1,2,3,4,8,16,17 --no-deploy
```

It runs a fresh `--control-test` outstation per N, captures a `.pcapng` per N, runs
one SBO of N CROBs, analyzes the capture, finds Nmax (exponential-until-failure then
binary search), re-runs Nmax three times, and writes `reports/sweep_manifest.csv`
plus `reports/sweep/analyze_n<N>.json`. **Nmax is reported only for the exact
OpenDNP3 build / hosts / point count / fragment settings tested — it is not a
universal DNP3 maximum.**

## Topology

```
Vision (10.10.54.19)  DNP3 master     -> run_master.py --action multi-crob-sbo
Hulk   (10.10.54.158) DNP3 outstation -> run_outstation.py --control-test   (TCP/20000)
```

Loopback (single host) works too: pass `--host 127.0.0.1` to both.

## Running the tests

Each staged test runs against a **freshly (re)started** `--control-test`
outstation, so the initial simulated state (index 0 = False, index 1 = True) is
deterministic. Restart the outstation between tests.

```bash
# Terminal 1 (outstation host): start the simulated control outstation
python run_outstation.py --control-test

# Terminal 2 (outstation host): capture the exchange (no IP typed; interface only)
sudo tcpdump -i <interface> -s 0 -w captures/multi_crob_sbo.pcap tcp port 20000
#   (on the rig, dumpcap needs no sudo if the user is in the wireshark group:
#    dumpcap -i <interface> -f 'tcp port 20000' -w captures/multi_crob_sbo.pcap )

# Terminal 3 (master host): run the multi-CROB SBO (Test C)
python run_master.py --action multi-crob-sbo --crob-test C
# Stop the capture after completion.
```

Staged tests (restart the `--control-test` outstation before each):

| Test | Command | CROBs | Expected simulated result |
|------|---------|-------|---------------------------|
| A | `run_master.py --action multi-crob-sbo --crob-test A` | index 0 LATCH_ON | index 0: False → True |
| B | `run_master.py --action multi-crob-sbo --crob-test B` | index 1 LATCH_OFF | index 1: True → False |
| C | `run_master.py --action multi-crob-sbo --crob-test C` | index 0 LATCH_ON + index 1 LATCH_OFF (one set) | index 0 → True, index 1 → False |
| D | `run_master.py --action multi-crob-sbo --control-test-negative` | index 0 LATCH_ON + **unsupported index 99** | observed only (see below) |

Master result files: `logs/master/multi_crob_test_a_summary.txt`,
`..._test_b_summary.txt`, `multi_crob_sbo_summary.txt` (Test C),
`multi_crob_negative_summary.txt` (Test D). Per-index SELECT/OPERATE lines and the
before/after state block are in the outstation log (`logs/outstation/…` and stdout).

## Verifying in Wireshark

Capture with the command above, then open the pcap.

1. Filter DNP3 traffic:

   ```text
   tcp.port == 20000
   ```

   or, if Wireshark decodes it: `dnp3`.

2. Find the **master → outstation SELECT** request and expand:

   ```text
   DNP3
     Application Layer
       Function Code: SELECT (0x03)
     Object Header
       Group 12
       Variation 1
   ```

3. Verify the message carries **two** CROB/control-point instances:
   - index 0 with `LATCH_ON`
   - index 1 with `LATCH_OFF`

   The dissector may show the two objects under one Group 12 Var 1 object header,
   or as repeated indexed CROB entries, depending on the qualifier and dissector
   version. In the OpenDNP3 protocol log the same frame reads
   `012,001 Binary Command - CROB, 16-bit count and prefix [2]` — the `[2]` is the
   two CROBs.

4. Find the **outstation SELECT response** and record its status (per-CROB status
   is echoed back).

5. Find the **master → outstation OPERATE** request (Function Code: OPERATE, 0x04)
   and verify it carries the **same two CROB instances** with the same parameters.

6. Find the **final outstation OPERATE response** and record completion/status.

## Observed behavior (rig, Vision → Hulk)

- **Test C** (headline): one SELECT with two CROBs → SELECT response → one OPERATE
  with the same two CROBs → OPERATE response. The outstation validated and executed
  both: index 0 False → True and index 1 True → False. The master's SBO task
  completed `SUCCESS`.
- **Test D** (negative): the outstation accepted index 0 (`SELECT SUCCESS`) and
  rejected index 99 (`OUT_OF_RANGE`). The master did **not** proceed to OPERATE —
  a SELECT failure on one CROB prevented the OPERATE for the whole set, and the
  valid control did **not** execute (index 0 stayed at its initial value). This is
  recorded as **observed**, not assumed.

### OpenDNP3 API limitation (important)

`SelectAndOperate` is one combined task. On the rig's pydnp3/pybind11 build
(Python 3.12) the non-copyable command-result object cannot be marshalled into a
Python callback (it raises a pybind11 `cast_error` and aborts the process **after**
the protocol exchange has already completed). The harness therefore does **not**
read the per-index command result on the master; it captures the **task-level**
completion via the master `OnTaskComplete` callback and takes the **authoritative
per-index SELECT/OPERATE status and final states from the outstation log + the
PCAP**. This is why the master summary reports a task-level completion and points
to the outstation state report for per-index evidence.

## What NOT to claim

- Do **not** claim the two controls execute physically simultaneously.
- Do **not** claim one overall task success proves both outputs changed — confirm
  the final states from the outstation state report.
- Do **not** claim packet-size variation from multiple CROBs is an obfuscation
  defense at this stage.
- Do **not** claim this validates fake / unknown / non-existent control objects
  (Test D shows an unsupported index is rejected).
- Do **not** claim universal support across vendor devices, atomic execution, or
  P4/Tofino feasibility from this experiment.
