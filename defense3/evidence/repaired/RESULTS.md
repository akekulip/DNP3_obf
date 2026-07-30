# Rerun on the repaired build — results

**2026-07-30. Switch: Intel Tofino-1, SDE 9.13.2. Program:
`case_a_defense3_repair_candidate` compiled `-DD3_SYNTH_EVENTS -DD3_REPAIR_R1
-DD3_REPAIR_R3`, 11/12 ingress stages, critical path 10.**

Authorized rerun of the withdrawn stale-response case (`REPORT.md` §9.8) on the repaired
build, with repetitions doubled and packet capture at the master-facing observation point.
The switch was returned to the conf it was found on (`d3_abs.conf`,
`case_a_defense3_fixed_ack_delay`) and verified: exactly one `bf_switchd`.

## Summary

| gate | reps | result |
|---|---|---|
| Gate 2 — one transaction, 17 requirements | 1 | **PASS** |
| Gate 3 — consecutive transactions, no reset | **10** (was 5) | **PASS 10/10**, 18 requirements each |
| Gate 4 A — response just before the deadline | **6** (was 3) | **PASS** |
| Gate 4 B — response after the ACK released | **6** | **PASS** |
| Gate 4 C — missing response | **12** | **PASS** |
| Gate 4 D — duplicate early response | **6** | **PASS** |
| Gate 4 E — stale response, idle transaction | **6** | **PASS** |
| Gate 4 F — stale response during a live transaction | **6** | **PASS** (identity via capture, see below) |

**Across all 42 Gate-4 transactions there is now no failing requirement id.** Case F was
resolved by a fourth run that gave the stale injector its own ethertype; the section below
records how, and what the original check got wrong.

Gate 3 stability over ten consecutive transactions, generations `0xC0`→`0xC9`, no reload
and no state reset between them:

| quantity | min | max | spread |
|---|---|---|---|
| hold | 2 001 418 | 2 001 603 | **185 ns** |
| drain | 1 691 | 1 695 | **4 ns** |
| release tail (internal) | 26 | 29 | **3 ns** |
| reservoir standing | 1 232 | 1 234 | **2 ns** |
| READ→ACK | 500 009 | 500 011 | **2 ns** |

R1 therefore does not disturb the normal path: the numbers match the 5-transaction run on
the unrepaired build to within a few nanoseconds.

## A regression R1 introduced, caught by Gate 2 on silicon

The first repaired build **failed Gate 2**, and the counters named the cause exactly:

```
ARM_FRESH=1  CLONE_SEEN=1  PKTGEN_ADMIT=0  PKTGEN_DROP=64  ACK_REJECT=1  RESP_BYPASS=1
reg_tag after arming = 0x00
```

`tbl_resp_authorise` was written with a **catch-all default action that set
`meta.tag_val = 0`**. That reaches every packet, not just responses — and for every
non-response class the tag arm is `tag_rmw`, whose write is guarded by
`tag_val != TAG_NO_WRITE`. Forcing 0 turned each of them into an unconditional write of
`TAG_INACTIVE`. The READ armed the generation, the mirrored trigger clone came back ~700 ns
later, took `tag_rmw`, and wiped it — so all 64 tokens were rejected, the ACK was refused
and nothing was held.

Fixed by making "not authorised" a **CLASS_RESP table entry** rather than the table
default, and leaving the default a no-op. `tag_val`'s default of `TAG_NO_WRITE` is
load-bearing for every other class and must survive the new table.

This is worth recording for its own sake: the gate caught, on the first transaction, a
defect introduced by a repair that had already passed 2 354 offline assertions and a
compile-fit check. The offline model covers the *state machine*; it does not model which
table default reaches which packet class.

## Case F: RESOLVED, and the original assertion was the thing that was wrong

The case was withdrawn because nothing distinguished N+1's own RESPONSE from the injected
stale copy. That is now fixed at the source: the repair candidate gives the stale injector
its **own ethertype** (`0x88C8`, versus `0x88C7` for N+1's own). It costs no state, changes
nothing the mechanism can see — same session, same role, same §8.2 treatment — and makes
the two copies separable **on the wire**, which is the only place they were ever separable.

The property to test is simple. A bypassed copy is forwarded immediately; a held copy waits
for the deadline. So the sign of (stale egress − held-ACK egress) decides it. From the
master-side capture, all six repetitions:

| rep | stale `0x88C8` | held ACK `0x88C6` | held RESPONSE `0x88C7` |
|---|---|---|---|
| 1 | +0.000 ms | +1.530 ms | +1.531 ms |
| 2 | +0.000 | +1.526 | +1.528 |
| 3 | +0.000 | +1.524 | +1.525 |
| 4 | +0.000 | +1.502 | +1.502 |
| 5 | +0.000 | +1.431 | +1.476 |
| 6 | +0.000 | +1.505 | +1.505 |

**The stale copy left 1.514 ms BEFORE the held ACK in 6 of 6 repetitions** (min 1.431, max
1.530). It took the bypass path. N+1's own RESPONSE stayed behind the ACK and left with it.
`analysis/analyze_capture_f.py` scores this and carries four negative controls of its own —
a stale frame arriving *with* the ACK FAILs, and an empty capture is INDETERMINATE rather
than PASS.

**The internal timestamp reconciles exactly.** The stale copy arrives at READ + 1.000 ms and
bypasses at once; the ACK is released at READ + 2.501 ms. The difference, 1.501 ms, matches
the 1.514 ms measured on the wire. So `reg_ts_resp_bypass = READ + 1 000 019 ns` was the
stale copy all along.

**What was actually wrong was the check, not the switch.** F-09 originally asserted that the
bypass timestamp equals the stale injector's *configured* offset. It does not, because
**app 4's one-shot timer does not fire where it is configured**: `--stale-offset-ns` of
600 000 and 800 000 both realise at READ + ~1 000 000 ns. That is a harness-fidelity defect,
it is what produced the original 200 µs discrepancy that started this whole thread, and it
is now recorded as `F-11` (INFO) so it stays visible instead of being absorbed. The case
still exercises the intended condition, because the realised arrival is comfortably inside
the hold window with N+1 live and its reservoir standing.

F-09 was rewritten to assert what the register evidence can actually support — the bypassed
copy left before the held ACK — and F-10 delegates the identity question to the capture.
**Rescored, Gate 4 has zero failing requirement ids across all six cases.**

## External capture — first independent observation of the synthetic gates

Every synthetic result before today was read out of registers and counters inside the same
chip that produced the packets. Captures were taken on Vision's dp9-facing interface
(`enp59s0f0np0`, 25 Gb/s, unprivileged `dumpcap` via the `wireshark` group).

Gate 3, 10 transactions:

| observation | value |
|---|---|
| transactions producing traffic at the master | **10 / 10** |
| inter-transaction interval | median 1.2323 s (min 1.2104, max 1.2561) |
| first frame → released pair | median **2.4990 ms** (min 2.4939, max 2.5179) |
| released pair in a consistent order | **10 / 10** |

The 2.499 ms median matches the internal hold of 2.0014 ms plus the ~0.5 ms READ→ACK
offset, from an entirely independent clock. That is the first external corroboration of the
hold that this project has.

**Those ethertypes are labels, not corruption**, which is worth stating because an earlier
draft of this note had it wrong. `synth_ack()` stamps `0x88C6` and `synth_resp()` stamps
`0x88C7` deliberately, so the held ACK and the held RESPONSE survive the loopback and are
*identifiable on the wire*. The capture therefore does confirm ACK-before-RESPONSE by
header, not merely a consistently ordered pair: in every gate-3 transaction `0x88C6`
precedes `0x88C7`, and in every case-F transaction the stale `0x88C8` precedes both.

The remaining limitation is narrower: these are synthetic frames, so the capture confirms
the *ordering and timing* the mechanism produces, not that a real relay's bytes are
preserved. Byte preservation on the live path is a separate result and `REPORT.md` §10.4
already carries it.

## Files

| file | what |
|---|---|
| `20260730T162554Z/` | the full three-gate run (gate 2, gate 3 ×10, gate 4 ×6) + pcaps |
| `20260730T163127Z/` | the focused gate-4 rerun at `--stale-offset-ns 600000` + pcap |
| `20260730T162258Z/` | the run that caught the `tag_val` default regression |
| `*/gate*_runner.log` | scored output, per requirement |
| `*/d3_gate*.pcap` | master-side capture, one per gate |
| `../gate2/gate4_*/gate4.json` | the raw per-transaction records |
