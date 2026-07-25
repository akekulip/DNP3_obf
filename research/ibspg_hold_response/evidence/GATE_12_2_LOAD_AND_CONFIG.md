# Gate 12.2 — load, control-plane config, strict-priority readback [MEASURED ON SILICON] PASS

Run 2026-07-25 ~03:01 UTC on switch `10.10.54.81` (SDE 9.13.2). Program
`ibspg_hold_response` (source sha `fa073cf6`, build `/home/decps/part12/compile_switch/out/`).

## What was done
The Part 11 program was displaced and Part 12 loaded in its place — a reversible program swap, the
same operation used at the Part 9 → Part 11 transition.

- **Pre-snapshot:** `bf_switchd` PID 112251 on `/home/decps/part11/part11_abs.conf` (Part 11).
- **Swap:** `sudo pkill -x bf_switchd` (rc=0) → `sudo bash /home/decps/part12/launch_part12.sh`.
- **Post:** `bf_switchd` PID 139143 on `/home/decps/part12/part12_abs.conf`; the switchd log reports
  `num P4 programs 1` / `p4_name: ibspg_hold_response`.

## Results

**Program binds over bfruntime.** `Binding with p4_name ibspg_hold_response successful!!`

**Static configuration installs cleanly** (`ibspg_paired_setup.py --prog ibspg_hold_response --config
--qb 7 --qh 1 --host-ports 9,11` — the Part 11 control plane reused as-is, not forked):

```
PART9SETUP {"prog": "ibspg_hold_response", "host_ports_up": [9, 11], "mac_loopback_L": 8,
            "Q_BLOCK_pri": {"want": "HIGH", "got_max_priority": "7", "err": null},
            "Q_HOLD_pri":  {"want": "LOW",  "got_max_priority": "LOW", "err": null},
            "strict_priority_verified": true}
```

`max_priority` — the active remaining-bandwidth strict field, and the field whose absence was the
root cause of the original IBSPG failure — is **read back from hardware** as 7 for Q_BLOCK and LOW
for Q_RESP. Two levels are all this branch needs, since the ACK is never queued.

**Every Part 12 bfrt object name resolves** (`--reset` over the full inventory):
registers 7/7, counters 11/11, zero failures. This closes the bfrt-name risk that cost time in
earlier parts, before any traffic gate depends on it.

**Link state read from hardware** (`from_hw=True`):

| port | role | UP | speed / FEC | loopback |
|---|---|---|---|---|
| dp8 | internal loopback L | True | 25G / NONE | `BF_LPBK_MAC_NEAR` |
| dp9 | Vision (master; released frames egress here) | True | 25G / RS | none |
| dp11 | Hulk (outstation; injection lands here) | True | 25G / RS | none |

## State left behind
The switch is **loaded with `ibspg_hold_response` and configured**, ready for gates 12.3+.
Rollback to Part 11 is one command: `sudo bash /home/decps/part11/launch_part11.sh`.

## Not established by this gate
Nothing about the mechanism. No packet has been injected: the hold, the deadline release, byte
identity and blocker isolation are gates 12.3–12.9 and are untested.
