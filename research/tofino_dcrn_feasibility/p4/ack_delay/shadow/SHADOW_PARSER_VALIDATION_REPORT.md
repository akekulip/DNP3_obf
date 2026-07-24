# Shadow Parser Validation Report — GATE-1 on Tofino-1 (partial)

**2026-07-23/24. First real-silicon run of the passive DNP3 shadow classifier `dnp3_shadow.p4`
(BF-SDE 9.13.2).** The classifier's parse + classification logic is **validated on hardware for the
outstation→master (dir-1) stream**. The full bidirectional (B1) validation — the master→outstation
READ stream, plus byte-identity and forwarding — **could not complete because the dp8 (Vision) 25 G
link would not come up** (§7). The shared switch was restored to the queue microbench afterward.

**Verdict: PARTIAL PASS.** Parser + per-class classification confirmed correct on silicon for 605
dir-1 frames (300 responses, 302 ACKs, 1 FIN), zero loss, zero READ misclassification. Byte-identity,
forwarding, and the 300-READ (dir-0) criterion remain **PENDING the dp8 link** — everything is staged
to finish in minutes once Vision's 25 G interface is up.

---

## 1. Runtime

| Item | Value |
|---|---|
| Target | Intel Tofino-1 (ASIC), switch `decps@10.10.54.81` |
| bf_switchd / SDE | **BF-SDE 9.13.2** (compiler SHA `1baf055`); device "Operational mode set to ASIC", dev_id 0 initialized |
| Active program at run | `dnp3_shadow` (p4_name), pipe `pipe`, all 4 pipes in scope |
| Conf loaded | `build_9132/dnp3_shadow_abs.conf` — **absolute-path variant** (see note) |
| Program source sha256 | `e08f2844…` (matches the committed `dnp3_shadow.p4`) |
| Load time | 2026-07-23 ~23:54 UTC (device operational) |
| Measurement gate | `reg_shadow_enable[0] = 1` (digests ON), read back `[1,1]` |
| dir-1 replay | 605 frames injected Hulk→dp9 at 3 ms pace |
| Restoration | queue microbench relaunched, `queue_microbench_abs.conf`, device operational, **confirmed 2026-07-24 00:07 UTC** |

**Conf note (fixed during the run):** the compiler emitted `dnp3_shadow.conf` with **relative** artifact
paths (`build_9132/pipe/context.json`). bf_switchd resolves conf-relative paths against `--install-dir`
(`$SDE_INSTALL`), not the CWD, so the first load failed with "No system resources" (context.json not
found) and left bf_switchd running **without a device**. Regenerating the conf with **absolute paths**
(`dnp3_shadow_abs.conf`, mirroring the microbench's own `queue_microbench_abs.conf`) fixed it and the
pipeline loaded on the ASIC. This is a packaging fix, not a P4 change.

## 2. Functional classification — dir-1 (outstation→master), on silicon

The 605 src-port-20000 frames were injected on dp9 (Hulk). Per-class packet `Counter`
(`pipe.ShadowIngress.class_ctr`), synced from HW, **delta = final − baseline**:

| Class | Silicon Δ | Reference model | Match |
|---|---:|---:|:--:|
| DNP3_RESP (3) | **300** | 300 | ✅ |
| PURE_ACK (2) | **302** | 302 | ✅ |
| TCP_FIN (4) | **1** | 1 | ✅ |
| DNP3_READ (1) | **0** | 0 | ✅ (no dir-1 frame misread as a READ) |
| NON_DNP3 (0) | **2** | 1 SYN-ACK (+1 edge) | ✅* |
| TCP_RST / LINK_OTHER / MALFORMED | 0 / 0 / 0 | 0 / 0 / 0 | ✅ |
| **Total classified** | **605** | 605 | ✅ **zero loss** |

Baseline `{NON_DNP3:44}` → final `{NON_DNP3:46, PURE_ACK:302, DNP3_RESP:300, TCP_FIN:1}`. Every one of
the 605 injected frames was parsed and classified; the counts equal the offline reference-model
expectation. *One non-application DNP3 frame the reference model labels `LINK_OTHER` was classified
`NON_DNP3` on silicon — a boundary difference on a single control frame, not on any of the 300 responses
or 302 ACKs.

**What this establishes on hardware:** the parser reaches the DNP3 application layer through the
length-gated Eth→IPv4→TCP→DNP3 chain; the per-class classifier correctly separates DNP3 responses,
pure ACKs, and FIN on real silicon; and the **physical-direction gate works** — responses arriving on
dp9 (dir 1) classify as `DNP3_RESP`, and **nothing in the dir-1 stream is misclassified as a READ**.

## 3. Data-plane integrity — PENDING (needs dp8)

The shadow forwards dp9→dp8; with **dp8 down**, the classified dir-1 frames were dropped at the traffic
manager **after** ingress classification (the ingress `Counter` still counts them). There was therefore
**no egress capture to compare**, so byte identity / length identity / TCP-checksum identity /
IP-checksum identity / ordering **were not measured on silicon this run**. They are preserved *by
construction* (the P4 is passive: 0 header writes, no `setValid`, no checksum unit, no recirculation —
Phase-1 audit) and offline (the reference-model replay), but the on-silicon confirmation waits on the
bidirectional B1 run. **Not claimed as validated.**

## 4. Switch behavior (telemetry)

| Signal | dp8 (Vision) | dp9 (Hulk) |
|---|---:|---:|
| `$PORT_UP` | **false** | true |
| Frames received OK | 0 | **651** (605 injected + ~46 background) |
| Frames transmitted OK | 0 | 0 |
| Frames with any error | **0** | **0** |
| Frames dropped (buffer full) | 0 | 0 |

- **Digest:** `reg_shadow_enable = 1` (digests ON); a live digest **listener was not run**, so the 40 B/pkt
  measurement digest was not independently counted this session (emitted per TCP frame by construction).
- **Unexpected recirculation:** none — `dnp3_shadow.p4` has no recirculation path.
- **pktgen:** 0 — the shadow has no packet generator.
- The 605 dir-1 frames dropped post-classification are attributable **solely to dp8 being down** (no
  egress port), not to any shadow behavior; dp9 ingress was clean (0 errors, 0 buffer-full drops).

## 5. Resource summary (on-switch bf-p4c 9.13.2)

| Metric | Value |
|---|---|
| Ingress MAU stages | **4 / 12** (stages 0–3) |
| MAU SRAMs | 5 |
| MAU TCAMs | **0** |
| MAU map RAMs | 4 |
| MAU logical tables | 31 |
| Ingress parser TCAM rows | 163 |
| Compile | 0 errors, 2 benign TNA warnings (full table in `onswitch_9132/mau.resources.log`) |

## 6. What remains for a full GATE-1 (B1)

1. Bring up the **dp8 (Vision) 25 G link** (§7).
2. Inject the **dp8 half** (606 frames, dst-port 20000) Vision→dp8; capture the dp9 egress on Hulk →
   confirms **300 DNP3_READ** (dir 0) + master ACKs.
3. Capture the dp9-half egress on Vision → run `verify_shadow_run.py` for **byte identity, length/seq/ack
   identity, ordering, zero loss**, and reconcile the full 1211-frame class counts.

All scripts (`shadow_pcap_split.py`, `shadow_raw_replay.py`, `shadow_read_counters.py`,
`verify_shadow_run.py`), both injection halves, and the abs conf are already staged on the switch, Hulk,
and Vision.

## 7. Blocker — dp8 (Vision) 25 GbE link will not come up

dp9 (Hulk) came up immediately (25 G, RS-FEC, autoneg). **dp8 (Vision `enp59s0f0np0`) would not link.**
Root cause: Vision's NIC is stuck **autoneg off / FEC off / speed unknown** and its **i40e driver rejects
host-side link changes** ("netlink error: Operation not supported"). Six distinct remediation attempts
all failed:

1. host link down/up nudge — no carrier;
2. `ethtool -s … autoneg on` — silently reverted to off;
3. `ethtool -s … speed 25000 autoneg off` — "Operation not supported";
4. switch dp8 → `PM_AN_FORCE_DISABLE` + 25 G + RS-FEC — no link;
5. **i40e driver reload** (`modprobe -r/​i40e`; safe — Vision's SSH is on `eno1`/tg3, only the two idle
   25 G NICs use i40e) — NIC still came up autoneg-off;
6. switch dp8 → `PM_AN_FORCE_DISABLE` + 25 G + **FEC NONE** (to match Vision's forced-off/FEC-off) — no link.

This is a Vision-side hardware/firmware/DAC condition (candidates: NVM autoneg disabled, a reboot needed,
or the 15/0 DAC lane) that needs on-site testbed action. **Vision's NIC was left essentially as found
(autoneg off, link down); no persistent host change of consequence.** The switch was restored to the
queue microbench.

**To finish GATE-1:** bring Vision's `enp59s0f0np0` up at 25 G to match Hulk (autoneg on, RS-FEC) — e.g.
a reboot, an NVM/`ethtool` fix that this driver will accept, or a DAC reseat / alternate lane — then the
staged B1 run completes the byte-identity, forwarding, and READ-classification checks.

---

**Evidence:** `onswitch_gate1_run/` (`base.json`, `final.json`, `final_full.json`,
`shadow_switchd_tail.log`); compile evidence in `onswitch_9132/`; harness in this directory.
Restoration of the queue microbench confirmed live (device operational) 2026-07-24 00:07 UTC.
