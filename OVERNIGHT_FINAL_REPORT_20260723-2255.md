# Overnight Autonomous Run — Final Report

**Run id:** `overnight-autonomy-20260723-2255` · **Start:** 2026-07-23 22:55 EDT · **End:** 2026-07-23 23:31 EDT
**Control host:** gambit · **Repo:** `/home/philip/Projects/DNP3` · **Authority:** `autunomous.md`
**Append-only log:** `OVERNIGHT_RUN_20260723-2255.md` (per-command detail).

Bottom line: **dp8 did not recover** (intermittent physical link; a warm reboot didn't clear it), so the
run pivoted to the authorized OFFLINE FALLBACK and completed a full Phase-1 regression and the Phase-2
generation-safe transaction core (logic + compile-fit measurement). **No component was hardware- or
relay-validated this run** — those remain blocked on dp8. All testbed state restored; Vision reachable.

---

## Starting state
- Branch `research/caseA-ditto-queue` @ `e3a7d01`; new work branch cut here.
- Switch: bf_switchd on `queue_microbench_abs.conf` (BF-SDE 9.13.2); `$PORT` empty.
- Vision `10.10.54.19` up (eno1=relay `192.168.10.1`, eno2 mgmt `.19`); dp8 NIC down. Hulk `.158` up.
- dp8 accepted as intermittent, root cause unisolated (per `e3a7d01`).

## Ending state
- Branch `overnight-autonomy-20260723-2255` @ `dbe2e23` (3 new commits; frozen `dcrn_defense1.p4` untouched).
- Switch: bf_switchd on `queue_microbench_abs.conf`, program bound, `$PORT` empty (dp8 removed). No stray procs.
- Vision reachable `10.10.54.19`; **eno1 = `10.10.54.19/24` + `192.168.10.1/24`, eno2 = `10.10.54.166/24`**
  (see Deviation). Hulk clean. No replay/capture processes anywhere.

## Commits created (all authored by Philip)
1. `cda5daf` — checkpoint + Stage 1 reconcile PASS + Stage 2 dp8 recovery (blocked).
2. `bef81f0` — Phase-2 generation-safe transaction-core reference model (offline).
3. `dbe2e23` — Phase-2 compile-fit measured (generation carried fits 12/12, enforcement does not).

## Files changed / added
- `OVERNIGHT_RUN_20260723-2255.md`, `OVERNIGHT_FINAL_REPORT_20260723-2255.md` (this file).
- `research/tofino_dcrn_feasibility/p4/ack_delay/txncore/`: `txncore_refmodel.py`, `tests/test_txncore.py`,
  `replay_txncore.py`, `dcrn_defense1_gen.p4`, `TXNCORE_PHASE2_REPORT.md`, `COMPILE_FIT_RESULT.md`,
  `evidence/{baseline,gen_stamp}_mau.resources.log`, `evidence/gen_enforce_placement_error.log`.
- `research/tofino_dcrn_feasibility/p4/ack_delay/shadow/dp8_link_probe_20260724.md`, `WORKING_NOTES.md`
  (dp8 conclusion correction — pre-run, commit `e3a7d01`).

## Tests run + acceptance criteria + pass/fail (all re-run at close, 23:31 EDT)
| Check | Criterion | Result |
|---|---|---|
| Phase-1 shadow replay | 300 READ / 300 RESP / 300 ACK→resp triples over committed pcap; no zero-ACK-as-DNP3; byte/order identity | **PASS** |
| Phase-1 shadow negatives | 14 synthetic edge cases classify safely | **PASS (14/14)** |
| Phase-2 txncore units | 22 cases: correlation, direction, retransmit, dup/stale ACK, resp-before-ACK, FIN/RST, timeout, 2nd request, seq wrap, gen rollover, hash-collision→stale-discard, pass-through, no-stale-state | **PASS (22/22)** |
| Phase-2 txncore replay | ARM/ACK_HELD/RESP_HELD/ACK_RELEASED/RESP_RELEASED = 300 each; 0 stale; 0 residue over committed pcap | **PASS** |
| dp8 bounded recovery | ≥5 min continuous stable link | **FAIL — dp8 never linked** |

## Switch resource reports (local bf-p4c 9.13.1)
- FROZEN `dcrn_defense1.p4`: compiles, **12/12 ingress** (0 headroom) — confirms plan §5.
- `dcrn_defense1_gen.p4` (generation carried): compiles, **12/12** (`reg_gen` at stage 5).
- generation enforced (recirc read): **table-placement failure** (does not fit) — `evidence/`.

## Hardware-validated items
- **None this run.** (Prior, unchanged: Phase-1 shadow dir-1 half on silicon — 300 RESP/302 ACK, commit `d30d1dc`.)

## Relay-validated items
- **None this run.** No SEL contact was made (Stage 4 is gated behind GATE-1, which needs dp8). A prior
  read-only 300-poll Class-0 baseline already exists (`clrt_300poll_20260723T152242`).

## Offline-only items (this run)
- Phase-1 classifier regression (replay + negatives). Phase-2 transaction-core logic (reference model +
  22 units + real-traffic replay). Phase-2 compile-fit measurement. **All offline; none silicon-verified.**

## Unresolved blockers
1. **dp8 intermittent physical/link-layer fault** — root cause unisolated (Vision NIC/PHY/firmware, DAC/
   breakout-leg, switch lane 15/0, connector, or interaction). A warm reboot did not clear it. Needs an
   on-site **cold power cycle + controlled substitution**. Blocks GATE-1 (Stage 3) and the SEL baseline (Stage 4).
2. **Phase-2 freshness enforcement does not fit** the 12/12 Defense-1 variant — needs a compact redesign
   (human-gated architecture decision, red-line #8). The generation *carried* variant compiles and fits.

## Deviation (recorded, not corrected)
The single authorized graceful reboot restored management via Vision's own persistent `eno1-dhcp` profile,
which places `10.10.54.19` on **eno1** (with relay `192.168.10.1`), not on eno2 as the doc's ideal final
state lists; eno2 holds a DHCP `10.10.54.166`. Reachability + relay requirements are met. Per the
no-NM/IP-edit rule I did **not** reshape the interfaces. To match the ideal exactly, on-site set eno2 to
`10.10.54.19/24` and eno1 to `192.168.10.1/24` only (netplan) — a human networking change, out of scope here.

## Restoration verification
- Switch: `queue_microbench_abs.conf` bound; `$PORT` empty (matches the 23:05 baseline); no stray procs. ✅
- Vision: reachable `10.10.54.19`; relay `192.168.10.1` present; SEL + Hulk reachable from Vision. ✅
- Hosts: no replay/capture/probe processes on switch, Vision, or Hulk. ✅
- Repo: frozen `dcrn_defense1.p4` unchanged; all commits Philip-authored. ✅

## Single highest-priority next action
**On-site: cold power-cycle Vision, then run one bounded read-only dp8 link verification** (enable dp8 at
25 G / RS-FEC / PM_AN_DEFAULT via `lane_probe add 8`, watch for `$PORT_UP` + ≥5 min stability). If it
links stably, GATE-1 (Stage 3) can run immediately — all inject/verify assets are staged. If it does not,
perform the controlled DAC/lane/endpoint substitution to isolate the fault before any further GATE-1 attempt.
