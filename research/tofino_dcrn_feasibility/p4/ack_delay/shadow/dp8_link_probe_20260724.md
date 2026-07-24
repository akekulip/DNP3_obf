# dp8 (Vision) temporary link-layer probe — 2026-07-24

Authorized minimal link probe: verify whether the dp8/Vision 25 GbE link comes up at the **verified
25 G RS-FEC config**, under the **currently loaded queue microbench** (NOT the shadow), with no replay
traffic and no relay contact. Add → observe → remove. Result: **dp8 did not link.**

## Exact configuration applied
Bound to the running program `queue_microbench`; added one `$PORT` entry for dev_port 8 via BFRT:
```
$DEV_PORT=8  $SPEED=BF_SPEED_25G  $FEC=BF_FEC_TYP_RS  $AUTO_NEGOTIATION=PM_AN_DEFAULT
$LOOPBACK_MODE=BF_LPBK_NONE  $PORT_ENABLE=True
```
(This is the verified 25 G config — identical to the one dp9/Hulk links on. Removed after the read.)

## Observations
| Signal | Result |
|---|---|
| Switch dp8 `$PORT_ENABLE` (admin) | **true** |
| Switch dp8 `$PORT_UP` (oper) | **false** |
| Switch dp8 speed / FEC | 25 G / RS (REED_SOLOMON) |
| Switch dp8 `$RX_PRSNT` / `$RX_SIG_OK` | not exposed by this SDE (null) |
| Switch dp8 port-stats | **all zero** — 0 frames, 0 CRC-stomped, 0 truncated, 0 FramesWithAnyError |
| Vision `enp59s0f0np0` carrier (sysfs) | **0** |
| Vision link detected / speed / duplex | no / Unknown / Unknown |
| Vision autoneg | **off** (un-settable; i40e "Operation not supported") |
| Vision Active FEC | Off |
| Vision driver error counters | **none non-zero** (no link_down/rx_errors/fec/crc) |
| dp9 during probe | unaffected (remained absent from `$PORT`, not configured) |

## RESOLUTION — retry after SFP/DAC reconnection (2026-07-24) — dp8 LINKS

Vision's SFP/DAC to the Tofino was **reconnected on-site** (it had apparently not been seated on the
Tofino lane). Re-running the same probe (verified 25 G RS-FEC on dp8, microbench loaded, no traffic):

| Signal | Result |
|---|---|
| Switch dp8 `$PORT_UP` (oper) | **true** ✅ |
| Switch dp8 speed / FEC | 25 G / **RS-FEC** (locked) |
| Switch dp8 frames received | **6 received, 0 errors** (0 FramesWithAnyError) — Vision's NIC is transmitting cleanly |
| Vision host side | **not read — Vision management `eno1` (10.10.54.19) was unreachable** at test time (data NIC alive on the switch, so Vision is powered; mgmt path down — likely bumped/power-cycled during the physical work) |

**This resolves the fault: it was a missing/disconnected SFP/DAC between Vision and the Tofino** — not a
damaged NIC, DAC, or switch lane. The switch now RS-FEC-locks and receives clean frames on lane 15/0.
The earlier "UNRESOLVED / substitution required" conclusion is therefore **overtaken**; the substitution
test plan is **no longer needed** unless dp8 later proves unstable. **Host-side confirmation (Vision
`ethtool` carrier/speed/FEC) is still pending Vision management recovery.** dp8 was removed after this
observation; microbench restored (empty `$PORT`, operational). No shadow reload; no GATE-1 continuation.

---

## Fault assessment — CORRECTED (2026-07-24, per review) — [pre-reconnection; superseded by RESOLUTION above]

The probe establishes **only** that (a) the switch **accepted** the verified 25 G RS-FEC configuration
on dp8, and (b) enabling dp8 **did not disturb** the active microbench or dp9. It does **NOT**:
- establish that **switch lane 15/0 or its SerDes is healthy** — this SDE does not expose dp8
  RX-signal-present / SerDes lock, so a dead or degraded lane RX cannot be excluded; and
- prove the two link partners **negotiated matching RS-FEC** — Vision reported **Active FEC Off,
  unknown speed, and no carrier**, so RS-FEC was configured on the *switch* but was **never confirmed
  active on Vision**. The earlier "rules out a FEC/config mismatch" claim is therefore **WITHDRAWN**:
  the two ends were not both on active RS-FEC.

**Conclusion: the fault is UNRESOLVED among Vision NIC, DAC, and switch lane 15/0.** The measured data
(above) does not favor one over the others, and software alone cannot isolate it. The on-site controlled
substitution test (`SUBSTITUTION_TEST_PLAN.md`) is required to determine whether the fault follows the
NIC, the DAC, or the switch lane. **No Vision reboot until then.**

## Fault assessment — ORIGINAL (SUPERSEDED by the correction above; overstated — retained, not deleted)
- **Rules OUT a config / FEC / speed mismatch:** both ends are at the verified 25 G RS-FEC config and
  the link still does not come up.
- **Not the signature of a marginal/dirty cable or FEC mismatch:** those produce FEC symbol errors,
  link flap, or partial lock. Here there is **zero** error/activity on either side — no lock attempt.
- **Vision NIC is in a stuck, non-negotiating state:** autoneg off and un-settable, speed unknown,
  FEC off, no carrier — the NIC is not driving/negotiating the lane, and it survived an i40e reload.
- **Most consistent with a Vision-side NIC condition**, but the probe **cannot definitively isolate
  cable vs switch-lane 15/0 vs Vision NIC**, because this SDE does not expose dp8 RX-signal-present, so
  a dead switch-lane RX or a bad DAC cannot be excluded from software alone.

**The physical DAC cross-test is still required to split the three:** move Vision's DAC onto a
known-good lane (switch 15/1) or into Hulk's NIC, and/or put Hulk's known-good DAC on Vision via 15/0 —
whichever end/lane the fault follows identifies it (DAC vs lane vs NIC).

## Restoration — confirmed
Temporary dp8 `$PORT` entry **deleted**; `$PORT` empty again (dp8 absent, dp9 absent — baseline state);
`queue_microbench_abs.conf` still loaded, bf_switchd up, device operational. Probe script removed.
GATE-1 evidence and commits untouched. No shadow reload; no GATE-1 continuation.
