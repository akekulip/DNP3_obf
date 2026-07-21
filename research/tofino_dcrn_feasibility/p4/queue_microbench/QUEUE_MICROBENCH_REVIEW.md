# QUEUE_MICROBENCH_REVIEW.md — Phase-4 TM microbenchmark, review-for-authorization

_Built LOCALLY (no switch touched, no `bf_switchd` restart, frozen `dcrn_defense1/2.p4` untouched).
This is the artifact set that `QUEUE_MICROBENCH_PLAN.md` §6 requires **before** any switch access.
Status: **compiles + fits locally; NOT loaded, NOT run.** `hardware_authorized = false`._

Directory: `research/tofino_dcrn_feasibility/p4/queue_microbench/`

| File | What it is |
|---|---|
| `queue_microbench.p4` | the microbench dataplane (641 lines) — both modes, both mechanisms, 8-step algorithm |
| `queue_microbench_setup.py` | bfrt control plane — ports, pktgen metronome, size-labelled TM queues, mech/pattern seed, mirror |
| `harness/mb_gen.py` | HULK generator — 64 B UDP frames on the classification dports; arrival patterns |
| `harness/mb_capture.sh` | VISION capture wrapper (tcpdump) |
| `harness/mb_parse.py` | pcap → §3 metrics incl. drop-robust size-state conformity |
| `harness/run_matrix.sh` | the §4 test matrix as concrete per-host commands |
| `compile/out/` | the local bf-p4c artifact + logs (resource evidence) |

---

## 1. What it measures (one sentence)
Whether a size-labelled Traffic-Manager queue + scheduler can, for a sparse ~5 Hz DNP3-cadence
flow, release packets **(a)** on a required timing (interval `τ` / rate `R`) **and (b)** in a required
size-state order `P = [S0…S(L-1)]` — comparing a **pktgen metronome** against the **TM PPS shaper**,
because GridCloak proved the shaper starves below ~1200 pps.

## 2. Design decisions (and why)

**Locked semantics honored.** The "pattern" is an ordered SIZE-state list `P`; timing is the
scheduler's `τ`/`R`, not a timing-valued pattern (`CASE_A_QUEUE_DESIGN.md` §1a). `P` is realized as
the control-plane table **`pat_state`** (slot index → target state + chaff-pad): the table literally
*is* the ordered list, so mode is a table-entry change, not a recompile.

**8-step per-packet algorithm mapping** (`CASE_A_QUEUE_DESIGN.md` §1a):
1. *select next state* → `advance_pat` slot counter → `pat_state` lookup (`meta.slot_state`).
2. *preserve if it fits* → `mb_classify` action `PAD_NONE` (the PRE dports).
3. *pad if smaller* → deparser emits a compile-time-constant filler (`pad_s1`=64 B, `pad_s2`=192 B);
   base 64 B → S1 128 B / S2 256 B.
4. *split* → **not taken on Tofino** (no verified transparent split, §7); the host pre-splits and each
   component enters as an ordinary per-state frame (SPLIT dports).
5. *else wait / fail open* → `oversize_guard` range table: larger than the biggest state → forward
   unchanged.
6. *real (high-prio) queue per state* → `QID_REAL_S1=1`, `QID_REAL_S2=3`.
7. *low-prio chaff queue per state* → `QID_CHAFF_S1=2`, `QID_CHAFF_S2=4`; in metronome mode the tick
   itself becomes the slot's chaff cover when no real is pending (step-7 empty-state preservation).
8. *scheduler sets output time* → pktgen period `τ` (metronome) or TM rate `R` (shaper).

**Two mechanisms, control-plane selected** (`mech_reg`): `MECH_PKTGEN` recirc-holds reals on dp68 and
releases one per `τ` tick in pattern order (reuses GridCloak Mechanism-C machinery); `MECH_SHAPER`
sends reals straight to the per-state REAL queue paced by `R`.

**Two modes, control-plane selected** (no recompile): **v1** = `P=[S1]`, PAD_NONE everywhere →
equal-sized 64 B frames to isolate TM timing (the PRIMARY reviewable artifact); **final** =
`P=[S1,S2]` alternating with chaff padded to state → verify size ORDER + timing together, with a
real+chaff priority-queue pair per state.

**Reused from GridCloak (cited):** pktgen periodic timer as the release clock
(`gc_switch_setup_c.py:122-143`), recirc-hold + **balanced** arm/release counter registers
(`gridcloak_c.p4:330-356,419-454`), the TM-queue shaper *cap* call + `pipe_id=0` rule
(`gc_switch_setup_c.py:163-177`), port bring-up (`:92-104`), pktgen `port_cfg` (`:106-111`), mirror
(`:145-156`). **Deliberately NOT copied:** the pad-ladder/nibble-decode parser, the A,A,A,B calendar,
DWRR byte-fair weighting, the constant-rate chaff reservoir (GridCloak B10/B7/B2 — dead weight here).
Counters count at a **single site** each (avoids the GridCloak B4 double-count); `ctr_encap` lives
only on the host-encap path.

**tofino-p4 constraint classes applied preemptively:** wide `bit<8>` flags/states (Class-3, no
sub-byte fields); exact-match classification, no 32-bit gateway magnitude compare (Class-1); the
oversize compare is a **range table** on 16-bit `total_len` (Class-1/2); one `RegisterAction` per
action, controller-seeded `mech_reg` sentinel (Class-8); no reused `Hash` (none used). No checksum
end-around-carry is needed — the microbench measures wire size + timing, not L4 semantics, so
`ip/udp` length/checksum are intentionally left stale (a **microbench-only** simplification; the real
byte-preserving size-normalizer's seq/checksum translation is separate and out of scope here).

**The two placement bugs found and fixed while building** (both are *my own* memory-note classes):
- `sb = t[0] & altbit` inside a gateway → *"condition too complex"* (Class-1). Fixed by moving `P`
  into the `pat_state` table so the gateway tests one field.
- nested `if { … return; }` per frame type → `hasReturned` predication **serialized** the mutually
  exclusive frame branches into an 18-stage chain; `pendS1_add` landed 12 stages from `pendS1_take`
  → *"Table placement was not able to allocate … along with Register pendS1_reg."* Fixed exactly as
  `dcrn.p4` did (17-deep chain > 12 stages): **one flat `if/else` tree, no early returns**, so bf-p4c
  overlaps the exclusive branches. Result dropped from 18 → **6 stages**.

## 3. Local compile + resource report (REAL numbers)

**Toolchain:** local `bf-p4c 9.13.1 (e558d01)`, `--target tofino --arch tna`. (The authoritative
switch SDE is 9.13.2; `dcrn.p4` showed 9.13.1↔9.13.2 parity, but the on-switch confirm remains a
gated step — see §5 STOP/open items.)

**Command (reproducible):**
```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o compile/out queue_microbench.p4
```
**Result: 0 errors, 2 warnings** (both benign parser `max_loop_depth` unroll notices — same class as
`dcrn.p4`). `queue_microbench.p4` sha256 `7f1cd2a3e847c535554c1377852b2b6343801f42a68e2e3eaa198ba5c3674d39`.

| Resource | Used | Tofino-1 budget | Note |
|---|---|---|---|
| **Ingress stages** | **6** | 12 | 6 stages headroom |
| Egress stages | 0 | 12 | egress is pure pass-through |
| Critical path (dep graph) | 5 | — | below the stage count (placement spread) |
| Logical tables | 48 | — | no `*` over-scope flag |
| SRAM blocks | 32 | 80/stage | comfortable (per-stage max ≈ 12.5%) |
| TCAM blocks | 1 | 24/stage | the `oversize_guard` range table only |
| Map RAM | 26 | — | register/counter backing |
| Meter ALUs (registers) | 6 | — | pat/pend×2/rel×2/mech |
| Stats ALUs (counters) | 7 | — | the 7 `ctr_*` |
| PHV | 21 containers (9.38%), 220 bits | 4096 bits | very light |

The large constant pad headers (`pad_s1`=512 b, `pad_s2`=1536 b) are emitted from **deparser
constants**, not data-path PHV — the same mechanism GridCloak's 2048 b `pad256` uses (proven on
silicon), which is why PHV stays at 9.38%. Raw logs: `compile/out/pipe/logs/table_summary.log`,
`.../mau.resources.log`, `.../phv_allocation_summary_0.log`; stderr `compile/compile.stderr.log`.

## 4. Exact TM / port / pktgen configuration (`queue_microbench_setup.py`)

- **Ports (`$PORT`, `pipe_id=0xffff`):** dp9 Hulk (generator), dp8 Vision (observe), all 25G RS-FEC,
  add-then-mod idempotent.
- **Recirc/pktgen (`tf1.pktgen.port_cfg`, dp68):** `recirculation_enable=True`, `pktgen_enable=True`.
- **Metronome (`tf1.pktgen.app_cfg`, app_id 1):** `trigger_timer_periodic`, `timer_nanosec = τ`
  (default 10 ms), one 64 B `MB_METRO` tick/fire, `pkt_len = 64-6`, template ethertype `0x88B6` at
  `buf[6:8]`, `is_tick` at `buf[8]` (the pktgen 6 B header lands in the eth dst-MAC).
- **dp68 hold-loop cap (`tf1.tm.queue.sched_shaping`+`sched_cfg`, `pipe_id=0`):** `qid 6`,
  `max_rate = 100000 PPS`, `UPPER`/`PPS` — churn control so a held real can't crowd out ticks
  (GridCloak B3).
- **Size-labelled queues on dp8 (`pipe_id=0`):** `REAL_S1=1`, `CHAFF_S1=2`, `REAL_S2=3`, `CHAFF_S2=4`;
  real strict-HIGH vs chaff strict-LOW priority; `pg_queue = pg_port_nr*8 + qid`.
- **Shaper mode:** each REAL queue paced at `R` (default 100 pps — deliberately below the ~1200 pps
  starvation floor to reproduce GridCloak B1; raise >1200 to show it works there).
- **`mech_reg`** (`pipe.Ingress.mech_reg`, key `$REGISTER_INDEX`, data `Ingress.mech_reg.f1`): 0=pktgen,
  1=shaper. **`pat_state`** (key `meta.pat_lo`, action `Ingress.set_slot_state(st,chaff_pad)`): v1 = 8×S1,
  PAD_NONE; final = S1/PAD_S1, S2/PAD_S2 alternating. (Names read off the compiled `bfrt.json`.)
- **Mirror (`$mirror.cfg`, sid 2 → dp8):** configured but off unless the P4 arms `mirror_type`.

**CONFIRM-ON-SWITCH (flagged, guarded — cannot verify locally):**
1. The **(pg_id, pg_port_nr) for dp8**'s REAL/CHAFF queues. GridCloak only TM-shaped dp68; the dp8
   per-state queues are new. `pg_queue = pg_port_nr*8 + qid` holds, but the port→PG numbers must be
   read from the switch's port map. Defaults are a formula guess, guarded by `--skip-dp8-queues`
   (the metronome path does not need dp8 TM shaping).
2. The **strict-priority field name/enum** on `tf1.tm.queue.sched_cfg`. Written best-known with a
   try/except fallback to default scheduling; metronome mode does not depend on it.

## 5. Rollback plan + STOP conditions

**The chip is shared and single-tenant per load.** gridcloak declares `pipe_scope:[0,1,2,3]` — it
owns all four pipes, so "coexist" is a **gated `bf_switchd` swap**, not concurrency
(`GRIDCLOAK_TM_QUEUE_AUDIT.md` §6). Loading this microbench = **displacing** whatever program is
currently loaded — **check first; do not assume it is gridcloak** (recent DNP3 work displaced
`decoy_paper3`). All of this is gated on explicit Philip authorization (master §10).

**Rollback discipline (before any load):**
1. Snapshot the current program: which `.conf` `bf_switchd` was launched with, the running `p4_name`,
   and the co-resident program's setup script + files.
2. Stop/mask the sibling's auto-loader (e.g. `gc-switchd`) so it can't respawn and fight the swap.
3. Load the microbench conf via the approved gated restart; run `queue_microbench_setup.py`.
4. **Restore:** relaunch the original program's `bf_switchd` + its setup script; verify its ports/
   pipeline are live again; unmask its loader. (This mirrors the proven M1 displace-then-restore of
   `decoy_paper3`.)

**STOP conditions (abort, preserve evidence, do not multi-patch — plan §7):** scheduler cannot
produce the timing pattern OR cannot hold the size-state sequence · a frame is reordered/dropped/
lost · queue occupancy grows unbounded · loopback/recirc traffic escapes a host port · background
load shifts timing unexpectedly (report, don't hide) · the action would displace another live
experiment · rollback not staged.

**Open items only a real load/run can settle (do not claim these as done):** 9.13.2 on-switch
compile parity; whether a burst-1 TM shaper paces a *single sparse* frame at all (GridCloak never
tested it — B1 was always backlogged); the dp8 pg map + priority enum (§4); real cadence jitter and
whether `global_tstamp`/pktgen refresh on recirc affects hold timing; end-to-end loss under load.

## 6. Exact commands (per host)

```bash
# [SWITCH decps@10.10.54.15] — GATED, only after authorization + gated bf_switchd swap
python3.8 queue_microbench_setup.py --mode v1    --mech pktgen                 # PRIMARY (v1 timing)
python3.8 queue_microbench_setup.py --mode final --mech pktgen --tau-ms 10     # size order + timing
python3.8 queue_microbench_setup.py --mode final --mech shaper --rate-pps 100  # shaper (expect B1 starve)
python3.8 queue_microbench_setup.py --dry-run --mode final --mech pktgen       # print, no writes

# [VISION] capture the obfuscated output on the dp8 NIC
sudo ./harness/mb_capture.sh <dp8-iface> runs/a_final_pktgen.pcap 15

# [HULK] generate (64 B frames on the dp9 NIC)
sudo python3 harness/mb_gen.py --iface <dp9-iface> --dports 20001 --count 1                    # sparse
sudo python3 harness/mb_gen.py --iface <dp9-iface> --dports 20001 20002 --count 200 --interval-ms 10

# [PARSE anywhere] metrics incl. drop-robust size conformity
python3 harness/mb_parse.py --pcap runs/a_final_pktgen.pcap --tau-ms 10 --pattern S1 S2

# full §4 matrix as per-host command sheet
./harness/run_matrix.sh
```

## 7. Which plan metric each §4 test produces

| §4 cell | Produces (from `mb_parse.py` unless noted) |
|---|---|
| a. sparse first-packet | first-packet release + size (padded to state?), pktgen-vs-shaper on a lone frame |
| b. empty vs backlogged | empty-slot behaviour: chaff cover present (metronome) vs round-robin skip; queue occupancy |
| c. chaff/metronome requirement | `chaff` count on a silent flow → is chaff REQUIRED to hold P (claim-scope input, §4 of design) |
| d. background load | IPG/jitter/loss/reorder + size-state conformity per background level (0/low/mod/high) |
| e. release jitter | cadence block: within-`τ` fraction + `|jitter|` p50/p90/p99/max |
| f. ordering | seq inversions (=0 target) + size-state run-length vs `P` (drop-robust, B5) |
| g. loss | loss block: missing / `loss_frac` over real seq (=0 target) |
| h. vs recirc baseline | rerun same patterns against `dcrn_defense*`; compare delay percentiles, load sensitivity, loss, reorder, resource cost/complexity |

Residence-time / latency percentiles need a synced Hulk-tx capture (PTP or a single-host hairpin
rig); the Vision-only parse gives cadence/IPG/jitter/size/order/loss without clock sync.

---
_Verification done locally: bf-p4c 0-error compile (real logs in `compile/out/`), `mb_parse.py`
exercised on a synthetic mixed real/chaff pcap with an injected drop (drop-robust ratio held; the
gap surfaced in cadence p99). Nothing was loaded or run on the switch._
