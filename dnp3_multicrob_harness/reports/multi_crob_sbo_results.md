# Multi-CROB Select-Before-Operate — Validation Results

_Run: 2026-07-03 (gambit-driven over SSH). Rig: Vision `10.10.54.19` master →
Hulk `10.10.54.158:20000` `run_outstation.py --control-test`._

## Question

Can a DNP3 SELECT/OPERATE transaction carry and process **multiple valid CROB
control objects** (Control Relay Output Block, Group 12 Var 1) targeting multiple
output indexes, in **one** command set? This is a software-only protocol/API
validation — not obfuscation, and it changes nothing in the Class 0 READ / replay /
CRC-split path.

## What was implemented (minimal, additive)

- `run_outstation.py --control-test`: swaps in `ControlTestCommandHandler` backed by
  a `ControlTestState` (two in-memory simulated binary output points, index 0=False
  / index 1=True). SELECT validates + records each CROB (index, control code, count,
  on/off time); OPERATE requires a matching prior SELECT, flips the point, logs
  index/op/prev/new/success, and clears the consumed selection. Only indexes 0/1 and
  LATCH_ON/LATCH_OFF are accepted. **Without the flag the outstation is unchanged**
  (`control_test=False`, controls rejected).
- `run_master.py --action multi-crob-sbo`: builds one `CommandSet` of the requested
  CROBs and issues one `SelectAndOperate`. `--crob-test {A,B,C}` picks the staged
  test (default C); `--control-test-negative` runs the negative test. Result →
  `logs/master/<test>_summary.txt`.
- `docs/multi_crob_validation.md`, README section 16. `split_server.py` untouched.

## Results — all tests pass on both loopback and the rig

| Test | CROBs (one command set) | Master | Outstation final state |
|------|--------------------------|--------|------------------------|
| A | index 0 LATCH_ON | task SUCCESS, rc 0 | index 0 False → **True** |
| B | index 1 LATCH_OFF | task SUCCESS, rc 0 | index 1 True → **False** |
| C | index 0 LATCH_ON **+** index 1 LATCH_OFF | task SUCCESS, rc 0 | index 0 → **True**, index 1 → **False** |
| D | index 0 LATCH_ON + **unsupported index 99** | rc 0, OBSERVED | index 99 rejected (OUT_OF_RANGE); **no OPERATE ran**; index 0 unchanged (safe) |

Each staged test ran against a freshly restarted `--control-test` outstation (initial
state index 0=False, index 1=True). Test C (the headline) shows the outstation
logging **both** SELECTs then **both** OPERATEs from one transaction:

```
CONTROL-TEST SELECT  index=0 code=LATCH_ON  count=1 on=100ms off=100ms -> SUCCESS (recorded)
CONTROL-TEST SELECT  index=1 code=LATCH_OFF count=1 on=100ms off=100ms -> SUCCESS (recorded)
CONTROL-TEST OPERATE index=0 code=LATCH_ON  prev=False -> new=True  SUCCESS (op_type=SELECT_BEFORE_OPERATE)
CONTROL-TEST OPERATE index=1 code=LATCH_OFF prev=True  -> new=False SUCCESS (op_type=SELECT_BEFORE_OPERATE)
  Index 0: True
  Index 1: False
```

**Regression:** with a normal outstation (no `--control-test`), a Class 0 READ on the
rig still delivered **2400 measurements** — the existing READ/replay/split path is
unaffected.

## PCAP evidence (`captures/multi_crob_sbo.pcap`, Test C on the rig)

Frames (master 10.10.54.19 → outstation 10.10.54.158): `SELECT (0x03)` frame 13,
its `RESPONSE (0x81)` frame 14, `OPERATE (0x04)` frame 16, its `RESPONSE` frame 17.
The exact Wireshark fields demonstrating the two CROBs:

- **SELECT (frame 13)** and **OPERATE (frame 16)** each decode as:
  `Object(s): Control Relay Output Block (Obj:12, Var:01), 2 points` /
  `Number of Items: 2` /
  `Point 0: Index 0, Control Code 0x03 = Latch On, Count 1, On 100, Off 100` /
  `Point 1: Index 1, Control Code 0x04 = Latch Off, Count 1, On 100, Off 100`.
- **SELECT response (14)** and **OPERATE response (17)**: `Group 12 Var 1, 2 points`,
  each point `Control Status: Req. Accepted/Init/Queued (0)`; all link-header and
  data-chunk CRCs `Good`.

## OpenDNP3 / pydnp3 API limitation (found and worked around)

`SelectAndOperate` is one combined task. On the rig's pydnp3/pybind11 build (Python
3.12) the non-copyable `ICommandTaskResult` delivered to the command-result callback
cannot be marshalled into Python — it raises a pybind11 `cast_error` and aborts the
process **after** the exchange has already completed; on the older build (gambit,
Python 3.8) the equivalent path instead *hangs*. The master therefore does **not**
read the per-index command result. It captures the **task-level** completion from
`OnTaskComplete(info)` (whose `TaskInfo` marshals fine), and takes the authoritative
**per-index** SELECT/OPERATE status and final states from the **outstation log + the
PCAP**. Implementation detail: `OnTaskComplete` hands the result to the main thread
and then blocks (the DNP3 manager runs one thread, so this freezes further DNP3 work
and prevents the aborting result delivery), while the main thread writes the summary
and exits — file I/O on the DNP3 callback thread deadlocks against pydnp3's C++.

## What this does NOT establish (per guide s.12)

- Not physically simultaneous execution; one task success does not by itself prove
  both outputs changed (confirm from the outstation state report).
- Not universal vendor support, atomic execution, or P4/Tofino feasibility.
- Not validation of fake/unknown/non-existent indexes (Test D shows index 99 is
  rejected); not an obfuscation mechanism and no justification to inject controls.

## Rig re-validation of the standalone harness (2026-07-06)

After `dnp3_multicrob_harness/` was split into its own independent tree, the full
matrix was re-run on the rig (Vision master `10.10.54.19` → Hulk
`10.10.54.158:20000` `run_outstation.py --control-test`), deployed via rsync, with a
**separate PCAP captured for each test** (`dumpcap -i eno1 -f "tcp port 20000"`).

| Test | Master | Outstation end-state | PCAP |
|------|--------|----------------------|------|
| A | rc 0, task SUCCESS | index 0 → True | `captures/multi_crob_test_a.pcap` |
| B | rc 0, task SUCCESS | index 1 → False | `captures/multi_crob_test_b.pcap` |
| C | rc 0, task SUCCESS | index 0 → True, index 1 → False | `captures/multi_crob_sbo_test_c.pcap` |
| D | rc 0, OBSERVED | index 99 OUT_OF_RANGE; no OPERATE; index 0 unchanged (safe) | `captures/multi_crob_negative_test_d.pcap` |

All four `master rc=0`, no tracebacks/aborts, summaries written. **tshark decode of the
captures confirms the CROBs on the wire:**
- Test C `Function Code: Select (0x03)` **and** `Operate (0x04)` each →
  `Control Relay Output Block (Obj:12, Var:01), 2 points`: Point 0 Latch On (0x03),
  Point 1 Latch Off (0x04); responses `Control Status: Req. Accepted (0)`.
- Test A/B: SELECT + OPERATE each carry a single CROB (Point 0 Latch On / Point 1 Latch Off).
- Test D: SELECT carries two points — Point 0 Latch On + **Point 99** Latch On — and the
  outstation rejects index 99 (OUT_OF_RANGE) with no OPERATE, leaving index 0 unchanged.

## Artifacts

- `captures/multi_crob_sbo.pcap` (original rig Test C) — SELECT/OPERATE with two CROBs each.
- `captures/multi_crob_test_a.pcap`, `multi_crob_test_b.pcap`, `multi_crob_sbo_test_c.pcap`,
  `multi_crob_negative_test_d.pcap` — 2026-07-06 rig re-validation, one per test.
- `logs/master/multi_crob_sbo_summary.txt` (Test C), `multi_crob_test_a_summary.txt`,
  `multi_crob_test_b_summary.txt`, `multi_crob_negative_summary.txt`.
- Outstation `--control-test` logs (per-index SELECT/OPERATE + before/after state).
- `docs/multi_crob_validation.md` (how to run + Wireshark steps).
