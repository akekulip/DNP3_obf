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
| Gate 4 F — stale response during a live transaction | **6** | **FAIL on F-09 only** |

**Across all 42 Gate-4 transactions the only failing requirement id is F-09**, the arrival-
time discriminator added for this rerun. Every pre-existing requirement passes.

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

## Case F: what is now known, and what is not

The harness gap is closed — **app 4's generator counters are read back and show it fired**
(`trigger_counter=1`, `pkt_counter=1`, 6/6 reps). What the run shows:

```
ARM_FRESH=1  ACK_HOLD=1  RESP_HOLD_EARLY=1  RESP_BYPASS=1  RESP_DUP_SUPP=0  PKTGEN_ADMIT=64
reg_exp_relay_seq unchanged from its seeded value
reg_ts_ack_arm      = READ + 500 009 ns    (matches the configured 500 us exactly)
reg_ts_resp_bypass  = READ + 1 000 019 ns
```

The bypass timestamp lands at **N+1's own RESPONSE slot** (READ + 1 000 000 ns), not at the
stale injector's. The obvious explanation — control-plane skew across three one-shot timers
— was tested and **refuted**: moving the injector from `--stale-offset-ns 800000` to
`600000` left the bypass timestamp bit-identical at READ + 1 000 019 ns across all six
repetitions. The stamp does not track where the injector is scheduled.

So the case is still **UNRESOLVED**, but for a much narrower reason than before, and one
that is now clearly a *harness* question rather than a mechanism question:

- the mechanism completed every transaction correctly (one held, one bypassed, none
  suppressed, 64 tokens, deadline-terminated, transaction retired);
- but the two RESPONSES still cannot be told apart in the evidence, because
  `tbl_synth_role` maps **both** `app3.pid1` and `app4.pid0` to the same action
  `Ingress.synth_resp`, so no counter, register or timestamp distinguishes them.

**The next step is identified and small:** give app 4 its own role action and its own
counter in the synthetic build. Until then F-09 correctly refuses to score the case, which
is the behaviour that was missing when this case was first reported as PASS.

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

**One honest limitation.** The two released frames arrive with ethertypes `0x88c6` /
`0x88c7` rather than as parseable IPv4, so the capture confirms *a consistently ordered
pair* per transaction but cannot by itself label which is the ACK. Synthetic-build packets
are constructed by the packet generator and are not byte-faithful on egress; a live-build
capture (real relay traffic) does not have this problem, and `REPORT.md` §10.4 already
reports one. External confirmation of ACK-before-RESPONSE *by header* therefore still
belongs to the live path, not the synthetic one.

## Files

| file | what |
|---|---|
| `20260730T162554Z/` | the full three-gate run (gate 2, gate 3 ×10, gate 4 ×6) + pcaps |
| `20260730T163127Z/` | the focused gate-4 rerun at `--stale-offset-ns 600000` + pcap |
| `20260730T162258Z/` | the run that caught the `tag_val` default regression |
| `*/gate*_runner.log` | scored output, per requirement |
| `*/d3_gate*.pcap` | master-side capture, one per gate |
| `../gate2/gate4_*/gate4.json` | the raw per-transaction records |
