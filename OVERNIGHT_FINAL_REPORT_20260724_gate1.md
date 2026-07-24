# GATE-1 completion run — Final Report (2026-07-24)

**Branch:** `overnight-autonomy-20260723-2255` · **HEAD:** `814c42b` · **End:** 2026-07-24 11:39 EDT.
Continues from the dp8 fault isolation. Headline: **Phase-1 GATE-1 is COMPLETE on silicon, bidirectional**,
after isolating a dead switch lane, remapping to the measured topology, and fixing a parser defect the
remap exposed. The frozen `dnp3_shadow.p4` / `dcrn_defense1.p4` / `dcrn_defense2.p4` were never modified.

## What was achieved
1. **Fault isolated** to Tofino lane 15/0 (dp8) — Vision NIC + DAC are good (link at 25G RS-FEC elsewhere).
2. **Measured topology (definitive, per-port RX test):** Vision(master)=**dp9**=dir0, Hulk(outstation)=**dp11**=dir1
   — the *opposite* of the assumed dp11/dp9. A first variant built for the assumed mapping misclassified
   everything; the mapping was pinned by measurement, not assumption, and the variant rebuilt.
3. **Parser defect found + fixed.** First bidirectional silicon run showed the frozen parser DROPS valid
   DNP3 link-only control frames (link-length 5, 10-B payload): `parse_dnp3_dl` descends to `parse_dnp3_tp`
   on `0x0564` without checking link length → `extract` past end-of-packet → reject → drop (proven: frame
   reaches switch RX +606, class counter +605; not a capture artifact). Fixed in a hardened variant:
   (A) descend only when `0x0564` AND link `length>=10`; link-only/short → pass-through; (B) classify a
   valid `0x0564` link-only frame LINK_OTHER, never MALFORMED.
4. **GATE-1 COMPLETE:** 3 reproducible reps, **all 12 verify checks PASS**, exact hulk_cap=606 / vision_cap=605,
   300 DNP3_READ (dir0) + 300 DNP3_RESP (dir1) + 605 PURE_ACK, 0 MALFORMED, byte-for-byte identity both
   directions, 0 loss/dup/corrupt/parser-drop; the 2 formerly-dropped link-only frames now forward as
   LINK_OTHER. Links stable 5 min, 0 flaps.
5. **SEL read-only Class-0 baseline** re-confirmed: 69 points decoded from the physical relay via
   `192.168.10.1`, clean session, no writes/controls.
6. **Defense variants (offline):** parser-hardened + dp9/dp11-remapped Defense-1 (12/12) and Defense-2
   (10/12) created and compile clean — HW campaigns are the next step.

## Validation levels (honest)
- **tofino-full:** Phase-1 shadow classifier — bidirectional direction gate + classification + byte-identity
  + count-identity, 3 reps (parser-hardened dp9/dp11 variant).
- **sel:** read-only Class-0 exchange with the physical relay (69 points).
- **compiled (offline):** Defense-1/2 hardened dp9/dp11 variants (0 errors, fit).
- **offline:** all reference-model + validator + txncore suites green.
- **NOT done:** Defense-1/2 hardware campaigns (disabled regression + bounded enabled tests); generation
  enforcement, Defense-2 G_i set, recirc/qid calibration, size-regeneration mechanism — all human-gated.

## Commits this run (all Philip-authored)
`d9e2e1e` fault isolated · `9701e34` dp11/dp9 offline variant + parameterization · `f2fcffc`/`b40cc94`
first bidirectional silicon run + parser-drop finding · `36149bb` **GATE-1 COMPLETE (parser-hardened)** ·
`2f00b68` SEL Class-0 baseline · `814c42b` defense hardened variants.

## Key artifacts
- `shadow/dnp3_shadow_parser_hardened_dp9_dp11.p4`, `shadow/PARSER_HARDENING_ROOTCAUSE_20260724.md`,
  `shadow/gate1_hardened_evidence/GATE1_COMPLETE_HARDENED.md` (+ rep captures, stability log).
- `shadow/PORT_ROLE_AUDIT_20260724.md`, `shadow/dp8_link_probe_20260724.md` (FAULT ISOLATED).
- `physical_sel751/sel_baseline_hardened_20260724/`.
- `dcrn_defense{1,2}_hardened_dp9_dp11.p4`, `DEFENSE_HARDENED_DP9_DP11_STATUS.md`.

## Restored final state (verified)
- Switch: `queue_microbench_abs.conf` bound, **1** bf_switchd instance, `$PORT` empty (dp9/dp11 removed).
- Vision reachable `10.10.54.19`; **eno1 = `192.168.10.1`** (relay) present; SEL reachable. Hulk reachable `10.10.54.158`.
- Host NIC offloads re-enabled; **0** tcpdump/dumpcap/replay/probe processes on any host. Frozen P4 untouched.

## Single highest-priority next action
Run the **Defense-1 hardware campaign** on dp9/dp11 using the hardened variant: load, disabled-mode
passthrough regression (byte-identity, 0 drops incl. link-only), then bounded enabled-mode tests
(counters/latency/loss/order/resources), restoring the microbench after. Same load/verify/restore pattern
proven for the shadow. Do NOT decide G_i / calibration / gen-enforcement / size mechanism (human-gated).
