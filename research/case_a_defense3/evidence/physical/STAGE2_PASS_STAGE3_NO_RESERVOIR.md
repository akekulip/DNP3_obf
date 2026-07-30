# PHYSICAL STAGES 2–3 — Stage 2 **PASS**; Stage 3 **STOPPED**: the blocker app was never enabled

10/12 instrumented live build, loaded once and kept loaded. **Defense 2 not restored.**

## 1. Builds — both footprints preserved

| build | flags | ingress | egress | path | errors | artifact SHA-256 |
|---|---|---|---|---|---|---|
| **core / stripped** | none | **9 / 12** | 0 | 8 | 0 | `adab3b7e…94ead` (kept as `build_core_9.12stage_9.13.2`, report `core_9stage_compile.log`) |
| **validation** | `-DD3_LIVE_FULL_TELEMETRY` | **10 / 12** | 0 | 8 | 0 | `79e24d81…a563` (**loaded**) |
| synthetic (unaffected) | `-DD3_SYNTH_EVENTS` | 9 / 12 | 0 | 8 | 0 | — |

`D3_LIVE_FULL_TELEMETRY` adds **only** `reg_ts_last_block` and `reg_ts_last_term`, both
write-only. Verified from `bfrt.json`: `pgen_event`, `tbl_synth_role`, `synth_read`,
`synth_ack`, `synth_resp`, `reg_ts_read`, `reg_ts_clone`, `reg_ts_resp_release`,
`reg_ts_resp_bypass` — **all 0 occurrences**; the two added registers present. `pgen`
count identical to the core build, i.e. no synthetic generator application was added.
`assert_salu_asm.py` PASS on both; `test_tag_domain.py` 2 256 assertions, 0 failures.

## 2. STAGE 2 — handshake-only learning · **PASS**

Capture `evidence/physical/stage2.pcap` (13 packets), started **before** the connection.
Socket-only connect from `192.168.10.1:32997` to `192.168.10.7:20000`, held 25 s, **zero
bytes sent**, connection healthy throughout.

**Learned session, read back from the live data plane:**

| tracker | value | source |
|---|---|---|
| `reg_session_port` | **32997** | exactly the master ephemeral port in the capture |
| `reg_exp_relay_seq` | **4259981761** | the *last* master pure ACK's `ack_no` (relay ISN 4259981759, +1 for the SYN, +1 for the relay FIN) |
| `reg_exp_ack` | **0** | correct — installed only by a READ, and none was sent |

**Required absences, all confirmed:** no `ARM_FRESH`, no blocker burst (`PKTGEN_ADMIT`,
`BLOCK_LOOP` and every `ctr_deq` slot zero), no `ACK_HOLD`, `reg_deadline = 0` (no arm),
`reg_tag = 0x00` (no generation), queue drops **0** on both qid1 and qid7.

**Keepalive / non-transaction ACK guard — PASS, and exercised for the first time.** The
relay emitted pure ACKs (`Flags [.]`, length 0) at **+10.004 s** and **+20.024 s** — the
~10 s TCP keepalives — plus one acking the master's FIN. All three were classified
`CLASS_ACK` and **`ACK_REJECT = 3`**: rejected, forwarded unprotected, none armed a
deadline and none entered `Q_HOLD`. The synthetic build cannot produce a keepalive, so
this guard had never been tested before.

## 3. STAGE 3 — one Class-0 READ · **STOPPED, reservoir absent**

Frame built and verified **before** it touched the relay: 18 bytes — exactly the
configured `read_len` — `05640bc4000001002aecc0c0013c0106ff50`; link `len=11 ctrl=0xC4
dest=0 src=1`, transport `0xC0`, `app_control=0xC0` (FIR|FIN, CON=0, UNS=0), func `0x01`,
object group 60 var 1 qualifier 0x06. Class 0, read-only. **No SELECT, OPERATE, DIRECT
OPERATE, write or setting change was sent, at any point.**

A real transaction completed: capture `stage3.pcap`, 134-byte DNP3 response, TCP healthy
to the end.

| quantity | value | source |
|---|---|---|
| READ → relay ACK, at Vision | **0.480 ms** | capture |
| relay CLRT (ACK → RESPONSE) | **5.015 ms** | capture |
| `t_ACK` (`reg_ts_ack_arm`) | 4 170 929 486 | register |
| armed deadline (`reg_deadline`) | 4 172 929 281 → **t_ACK + 1 999 795 ns = D** within tick quantization | register |
| ACK commitment (`reg_ts_ack_release`) | 4 170 930 554 | register |
| **actual hold** | **1 068 ns** — not 2 ms | derived |

### What worked

`ARM_FRESH = 1` — the real DNP3 READ armed generation 0xC0 through the **live** parse
chain. `CLONE_SEEN = 1` — the mirror clone was emitted and returned on dp68.
`ACK_HOLD = 1`, `ACK_REJECT` unchanged for it — **the real relay ACK passed every §8.1
conjunct, including `tcp.seq == EXP_RELAY_SEQ`**, and the deadline armed **exactly once**
at `t_ACK + D`. `ACK_REL_RETIRE = 1` — the E1 repair fired on real traffic: nothing was
pending, so the ACK's commitment retired the transaction, `reg_tag = 0x00`.
`RESP_BYPASS = 1` — the RESPONSE, arriving after retirement, took the normal forwarding
path and was forwarded **exactly once**. No queue drops. No fail-open.

### Root cause of the missing hold

```
pktgen app 1:  app_enable = false   trigger_counter = 0   pkt_counter = 0
PKTGEN_ADMIT = 0   BLOCK_LOOP = 0   BLOCK_TERM_* = 0
```

**The K=64 blocker application was never enabled.** `config_pktgen(..., app_enable=False)`
is the Gate-1 contract — configure, arm nothing — and the synthetic driver enables app 1
explicitly before arming the event apps (that ordering *is* the F01-a fix). **The live
control-plane path has no equivalent step**: `--config` leaves app 1 disabled, and nothing
else turns it on. So `Q_BLOCK` was empty when the ACK was admitted, and the ACK dequeued in
1 068 ns.

This is a **control-plane omission in the live path, not a mechanism defect**. Given an
empty `Q_BLOCK` every observed value is exactly what the design predicts.

**Stopped here per the failure policy** — the trace is preserved, and D was not altered
and the relay was not delayed to mask the condition. The fix is the one missing enable
step, which is the same operation Gate 2 performs; it is a one-line addition to the live
arming path and needs a re-run, not a redesign.

## 4. Mechanism verdict

**Not established.** One transaction with no reservoir cannot demonstrate a D-governed
hold. What *is* established on real relay traffic: live DNP3 parse → ARM, real-ACK
predicate acceptance including the sequence conjunct, deadline arming at `t_ACK + D`
exactly once, E1 retirement at ACK commitment, single-forward of a late RESPONSE, and
keepalive rejection. No concealment, classifier or general SEL-751 claim is made from this.

## 5. Negative evidence

- The blocker app was never enabled — above.
- `reg_ts_first_block`, `reg_ts_last_block`, `reg_ts_block_term`, `reg_ts_last_term` all
  **0**: no blocker was ever admitted, so full-reservoir standing, first and final
  termination, drain and release tail are legitimately unmeasurable in this run. The two
  new registers are wired and read back cleanly — they simply had nothing to record.
- `swap_to_d3.sh` cannot load a live build over a synthetic one (it `pkill`s only Defense
  2's conf pattern); `swap_to_d3_live.sh` added.
- The 5.015 ms CLRT is a first poll on a fresh connection and is **not** offered as the
  relay's steady-state CLRT.

## 6. State

Switch: **10/12 instrumented live Defense 3 loaded**, one `bf_switchd`, `d3_abs.conf`,
fully configured, dp8 25G MAC+TM, strict priority 7 > 0, `reg_tag = 0x00` idle.
Defense 2 **not** restored.
