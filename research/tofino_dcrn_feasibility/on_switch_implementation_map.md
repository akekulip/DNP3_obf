# On-Switch DCRN ACK-Delay — Tofino-1 Implementation Map

*Authored by p4-dataplane-engineer (2026-07-18), verified by the main session against the real
a co-resident program source and the `tofino-p4` skill references. Design/planning only — nothing was compiled,
loaded, or run; no SSH to the switch. Evidence tags: **[M]** measured on the two-host rig · **[V]**
vendor/standard doc · **[L]** confirmed from working lab code in `a co-resident program's source tree` ·
**[P]** paper-reported · **[I]** inference on an unbuilt design · **[H]** hypothesis. Any Tofino
stage/SALU/latency number not confirmed from lab code this session is [I] — **a first `bf-p4c` compile
on the switch's SDE 9.13.2 remains the only proof of stage/SALU fit.***

## Readiness statement

The on-switch recirc-hold is grounded on **this** chip rather than on placeholders. The recirculation
self-clock port is resolved: **dev_port 68 is a usable pipe-0 internal recirculation port that needs no
cable**, and the "shaped self-clock" is a **TM `max_rate` PPS shaper on dp68's queue** — both proven in
the co-resident program's own bring-up code (`the co-resident bring-up script` enables recirc on dp68 via
`recirculation_enable=True` and caps a recirc-hold loop at `HOLD_LOOP_PPS = 100000`) [L, verified]. The
data path is pinned to the real topology (request Vision dp8 → Hulk dp9; response Hulk dp9 → Vision dp8,
all pipe 0; empty lanes dp10/dp11 stay unused). The load model is pinned: `a co-resident program` occupies all four
pipes [L], so a DCRN program **replaces** it via a **gated `bf_switchd` restart** with a DCRN `.conf` —
there is no hitless swap in the tree and none is safe against `the co-resident auto-load service` respawn. Every bf-p4c
constraint the design touches is mapped to one of the eight skill classes with a preemptive workaround
(deadline compare → 32-bit SALU predicate, not a gateway or range key; flags widened to `bit<8>`; one
Hash instance per tuple shape; registers controller-seeded, no in-SALU `v==0`).

**What only the first compile / hardware probe can resolve** (carried honestly through the plan): (1)
the real MAU stage/SALU count and whether the sliced 32-bit deadline compare fits an SALU predicate; (2)
which timestamp intrinsic gives a wall-clock that **refreshes on each recirc re-entry in ingress**; (3)
whether a **single sparse** held frame is actually paced by a burst-1 `max_rate` shaper (a co-resident program's
proof runs continuous chaff, a different regime); (4) the true per-pass latency and recirc-port bandwidth
on this silicon; (5) a re-measured Vision RTO to set the fail-open cap. None blocks writing the P4 — they
are what the staged milestones expose one at a time.

---

## Part 1 — Hardware constraint ledger

| # | Fixed fact | Source | Implication for the build |
|---|---|---|---|
| H1 | **Compile + run on the switch's SDE 9.13.2** (`/home/decps/Downloads/bf-sde-9.13.2`); laptop copy is 9.13.1, reference only | [V] skill build-deploy.md; [L] `the co-resident launch script` (`SDE=/home/decps/Downloads/bf-sde-9.13.2`) | All `bf-p4c`/bfrt runs on the switch. Never mix the 9.13.1 laptop tree into a switch build. `cmake $SDE/p4studio … && make -j4 <prog> && make install`. |
| H2 | **`a co-resident program` auto-loads and owns all 4 pipes** (`pipe_scope [0,1,2,3]`); `the co-resident auto-load service` respawns it whenever any `bf_switchd` dies | [L] `the co-resident program's conf`; [V] testbed.md | DCRN cannot co-reside — it **replaces** a co-resident program. Load = `systemctl stop && mask the co-resident auto-load service`, then a gated `bf_switchd` restart on a DCRN conf; `unmask` to hand back. (Part 5.) |
| H3 | **dev_port map, pipe 0:** dp8 = Vision (15/0, master), dp9 = Hulk (15/1, outstation / `split_server.py` replay), 25G RS-FEC, both UP | [V] connectivity map; [L] `the co-resident bring-up script` (`LAN_PORT,WAN_PORT = 9,8`) | Request arms on **ingress dp8**; response classifies + holds on **ingress dp9**; release egresses to **dp8**. Enable exactly dp8+dp9 after any restart. |
| H4 | **dp10 / dp11 are empty breakout lanes** (no DAC), removed from `$PORT` after diagnosis to stop empty-lane FSM retries | [V] connectivity map | Do **not** re-enable as data ports. Available only as a *fallback* physical-loopback self-clock (Part 2); doing so re-invites the FSM-retry log noise. |
| H5 | **dp68 = pipe-0 internal recirculation port**, enabled via bfrt `tf1.pktgen.port_cfg` (`recirculation_enable=True`); no cable/DAC | [L] `the co-resident bring-up script` (`WANSEG_PORT=68`, recirc on dp68) | DCRN's self-clock port — **resolved** (the prior "~dev_port 68" is confirmed). Part 2. |
| H6 | **Self-clock = TM `max_rate` PPS shaper** on dp68's queue; a co-resident program caps its recirc-hold loop at `HOLD_LOOP_PPS = 100000` (queue `PG_PORT_NR*8 + qid`) | [L] `the co-resident bring-up script` | `max_rate` on dp68's queue paces the loop: ~100k PPS ≈ 10 µs/pass, ~10k PPS ≈ 100 µs/pass. **Caveat [I]:** a co-resident program runs continuous chaff (always backlog); a *sparse* DCRN frame paced by a burst-1 shaper is a probe item (M2/Q3). |
| H7 | **No L3 on the data path**; each workload brings its own IP/ARP | [V] connectivity map | DCRN is bump-in-the-wire L2 port-forward for non-DNP3 traffic; parses IPv4/TCP only to classify DNP3 port-20000 flows. No routing table. |
| H8 | **Switch OS Ubuntu 20.04 / kernel 5.4**; control plane bfrt gRPC `localhost:50052`, thrift `localhost:9090` | [V] connectivity map; [L] `bfrt_starter.py` | Controller = bfrt_python via `/home/philip/tools/bfrt_starter.py`. Freely restartable (re-installs tables/seeds); the data plane is not. |
| H9 | **Hosts Ubuntu 24.04 / kernel 6.8, Intel XXV710 (i40e), data iface `enp59s0f0np0`, mgmt `eno1`**; live mgmt IPs `.19`/`.158` | [V] connectivity map | `run_master.py` on Vision, replay on Hulk. Capture at the wire-facing `enp59s0f0np0` on Vision. `source ~/.lab_env` → `$SSHPASS`, `$LAB_USER=decps`; switch is key-based. |
| H10 | **Byte-preservation + fail-open are hard invariants** — a dropped or RTO-overshot DNP3 response trips a passive Zeek `dnp3` IDS | [M] DCRN spec / GROUNDING | Recirc carries the frame verbatim (only egress-port + intrinsic metadata change). Every guard's default action **forwards, never drops**. |

---

## Part 2 — The recirculation / self-clock port, resolved for this chip

**Recommendation: use the internal recirculation port dev_port 68 (pipe 0). Do not use a physical
empty-lane loopback unless a probe shows dp68 self-pacing fails.**

### Why dp68, concretely
- **It exists and is usable with no cable.** dp68 is the pipe-0 internal recirc port; `a co-resident program`
  already enables it (`recirculation_enable=True` via `tf1.pktgen.port_cfg`, `dev_port=68`) and uses it
  for a recirc-hold loop [L]. dp8/dp9 are pipe-0 ports and dp68 is the pipe-0 recirc port, so the held
  frame never leaves the pipe — no cross-pipe hop, no SerDes, no DAC.
- **The self-clock is a proven pattern.** a co-resident program paces its loop with a TM `max_rate` shaper on dp68's
  queue (`HOLD_LOOP_PPS = 100000` on queue `PG_PORT_NR*8 + QID_PASSTHRU`) [L]. DCRN reuses exactly this:
  recirculate the held frame out dp68, cap dp68's hold queue with `max_rate`.

### How it is configured (bfrt, mirrors the working a co-resident program calls)
```python
# 1. Enable recirculation on dp68 (pipe-0 recirc port).  [pattern from the co-resident bring-up script]
pc = bfrt_info.table_dict["tf1.pktgen.port_cfg"]           # DCRN needs NO pktgen — recirc only
pc.entry_mod(dev_tgt,
    [pc.make_key([gc.KeyTuple("dev_port", 68)])],
    [pc.make_data([gc.DataTuple("recirculation_enable", bool_val=True)])])

# 2. Pace the hold loop: TM max_rate (PPS) shaper on dp68's hold queue.
#    ~10_000 PPS -> ~100 us/pass (target);  100_000 PPS -> ~10 us/pass (a co-resident program's cap)
HOLD_LOOP_PPS = 10_000
pgq = 0 * 8 + QID_HOLD                                      # PG_PORT_NR=0 for dp68, dedicated qid
sched = bfrt_info.table_dict["tf1.tm.port.sched_shaping"]   # exact table/field is an M0 SDE check
sched.entry_mod(dev_tgt,
    [sched.make_key([gc.KeyTuple("dev_port", 68), gc.KeyTuple("pg_queue", pgq)])],
    [sched.make_data([gc.DataTuple("unit", str_val="PPS"),
                      gc.DataTuple("max_rate", val=HOLD_LOOP_PPS),
                      gc.DataTuple("provisioning", str_val="min")])])
```
The exact TM shaping table/field names are the ones to confirm against 9.13.2 at M0 (a co-resident program proves
the *capability* and the `max_rate`/PPS semantics; the precise bfrt path is an SDE-version detail to read
off the switch, not assert from memory).

### Per-pass latency and shaping toward ~100 µs/pass
- **Bare recirc pass** ≈ 0.3–1 µs [P/I]. Bare → a 42 ms hold ≈ 42,000–140,000 passes, ~2.4–4.8 Gbps per
  held frame — affordable but wasteful.
- **Shaped to ~100 µs/pass** (dp68 `max_rate` ≈ 10k PPS): a 42 ms hold ≈ 420 passes, ~24 Mbps per held
  frame [I]. Target operating point; mirrors a co-resident program's design intent.
- **Load-bearing unknown [I]:** a co-resident program's shaper proof runs with *continuous* pktgen backlog. Whether a
  burst-1 `max_rate` shaper spaces a *single sparse* held frame to the cap (vs releasing immediately on an
  empty queue) is the one self-clock assumption a probe must settle (M2). If it does **not**, fallbacks
  in order: (a) accept bare recirc + count passes against a real refreshed clock (bandwidth still <0.1%
  of budget, so correctness is unaffected); (b) inject a low-rate "metronome" recirc packet to keep
  minimal backlog (exactly what a co-resident program's pktgen tick does — proven feasible); (c) physical-lane
  loopback below.

### Recirc-bandwidth headroom
~100 µs self-clock, ~300 B frame → ≈24 Mbps per held frame [I]. This rig carries one master↔outstation
pair at a time (2 flows), peaking at 2 concurrent held frames in the separate case → peak ≈ ~48 Mbps —
a small fraction of one recirc port and ~0.003% of the ~1.6 Tbps aggregate on-chip recirc budget [P].
Even bare recirc (2 × ~4.8 Gbps ≈ 9.6 Gbps) fits one recirc port. **Bandwidth is not a constraint for
this workload;** the rate ceiling that flips the verdict is ~20–60× away.

### Physical-lane loopback — the fallback, not the default
Empty lanes **dp10/dp11** can be put in MAC/PCS near-end loopback via the `$PORT` `$LOOPBACK_MODE` field
(`BF_LPBK_MAC_NEAR`). Rejected as default: (1) re-enables lanes deliberately removed from `$PORT` to stop
FSM-retry log noise [H4]; (2) consumes a MAC + SerDes for no benefit dp68 doesn't already give cable-free;
(3) at 25G a looped frame serializes in ~100 ns, so it does **not** inherently give 100 µs/pass either —
you'd still need the same `max_rate` shaper. Keep only as the contingency if dp68 self-pacing is disproven
at M2.

---

## Part 3 — Pipeline data-path plan on the real topology

**Bump-in-the-wire, pipe 0.** Non-DNP3 traffic port-forwards dp8↔dp9 untouched. DNP3 port-20000 flows
get the DCRN treatment. All DCRN logic lives in **ingress** (the recirc loop re-enters ingress each
pass); **egress** carries telemetry only.

| DCRN step (`corrective.md`) | Where, on the real topology | Notes |
|---|---|---|
| **Arm t0** (record request arrival) | **Ingress, dp8** payload-bearing master→outstation DNP3 READ (dst port 20000, `payload_len>0`, FC on allowlist) | Only a real DNP3 request arms; handshake/ACK-only never arm (spec §6). Compute `flow_id`, read `t0`, write `reg_req_tstamp`/`reg_deadline`, `state=armed`, forward to dp9. |
| **Classify pure-ACK vs combined** | **Ingress, dp9** (outstation→master, src port 20000) | `payload_len == (ip.total_len − ihl*4 − dataOffset*4) == 0` → pure ACK; `>0` covering the armed request → ACK-bearing RESPONSE (spec §7). Widen mode/flags to `bit<8>` (Class 3). |
| **Enter recirc-hold** | **Ingress**, on the armed reverse frame and every recirc re-entry (frames on **dp68**) | Read `reg_deadline[flow_id]`; if `now_tick < deadline_tick` → `ucast_egress_port = 68` (recirculate) + bump pass counter in recirc metadata; else → release. |
| **Release toward Vision** | **Ingress** sets `ucast_egress_port = 8` when `now_tick >= deadline_tick` (or a fail-open guard fires) | Frame egresses to Vision byte-identical. |
| **Dual-case FIFO** (ACK before response) | **guard-delta ≥ one recirc pass** on the response's deadline | Pure ACK deadline `= T`; response deadline `= T + guard_delta`, `guard_delta ≥ one dp68 pass`. Response eligible ≥1 lap after the ACK → ACK enters dp8's egress queue first → FIFO on the wire. Maps DCRN's measured ~0.19 ms host guard-delta onto "≥1 self-clock pass." |
| **Telemetry** | **Egress** (dp8) | Per-flow held-count, pass histogram, deadline-miss counters; optional mirror. Kept out of ingress to save stages. |

### Why the hold is ingress-side, and the one timestamp caveat
Only ingress can set `ucast_egress_port`, so the "recirculate vs release" decision must be made in
ingress on each pass: ingress → (deadline not met) → dp68 → re-enters ingress parser → deadline
re-checked → … → (deadline met) → dp8.

**Open hardware detail [I], flagged for M2:** the deadline compare needs a wall-clock that **refreshes on
each recirc re-entry in ingress**. Candidate: `ig_intr_md.ingress_mac_tstamp[47:16]` (48-bit ns → 32-bit
tick, 65.5 µs resolution). Whether that intrinsic is re-taken for a recirculated packet (vs stale from
first entry) is a Tofino-1 behavior the probe must confirm. If it does **not** refresh in ingress, the
fallback is the compare in **egress** against `eg_intr_md_from_parser.global_tstamp` with the recirc
decision carried back via a bridged/resubmit signal — a heavier structure to reserve only if needed.

### Stage / table / SALU / register sketch (all counts [I] until compiled)
Ingress, estimated **~5–7 of 12 MAU stages** [I]:
```
S0  parse complete; derive direction, is_dnp3_req, is_ack_bearing, payload_len==0, FC;
    canonical flow-key muxes (server = port-20000 side)               [gateways + exact-match]
S1  flow_id = Hash(canonical 5-tuple)                                 [1 Hash instance — Class 7]
S2  REQUEST: txn_counter SALU++ ; bounded_target table -> Di          [1 SALU + 1 table]
S3  REQUEST: SALU reg_req_tstamp[flow_id]=t0 ;
            SALU reg_deadline[flow_id]=t0+Di (single-op add — Class 5) [2 SALU]
    RESPONSE: SALU read reg_deadline[flow_id]                         [1 SALU]
S4  deadline compare now_tick >= deadline_tick (32-bit SALU pred — Class 1/2 avoided);
    wrap guard (deadline<req); watermark SALU reg_held_count          [1–2 SALU]
S5  recirc metadata pass-counter++ ; max-pass guard ;
    set ucast_egress_port = 68 (hold) | 8 (release) | forward (fail-open)
EGR telemetry counters (held-count, pass histogram, deadline-miss); optional mirror
```
| Register / table | Type | Purpose |
|---|---|---|
| `reg_req_tstamp` | `Register<bit<32>, bit<16>>` (65 536 flows) | `t0` tick per flow |
| `reg_deadline` | `Register<bit<32>, bit<16>>` | absolute `t0+Di` tick |
| `reg_state` / mode flags | `bit<8>` fields (Class 3) | armed / ack_seen / resp_seen / bypass |
| `reg_held_count` | `Register<bit<32>,bit<1>>` global | fail-open watermark |
| `txn_counter` | `Register<bit<32>,bit<1>>` global | BOUNDED table index source |
| `bounded_target` | exact-match table, ~256 entries | `txn_counter[7:0]` → `Di` (action-data constant) |
| `fc_allowlist` | exact-match table | READ-only initially; else → bypass |
| pass-counter | recirc **metadata** (not a register) | stuck-frame cap |
| `Hash` | 1 instance, 1 tuple shape | canonical bidirectional flow key |

---

## Part 4 — Constraint-class pin-down (Tofino-fittable on the first compile)

| Element | bf-p4c class | Preemptive workaround (baked into Part 3) |
|---|---|---|
| **32-bit deadline compare** `now_tick >= deadline_tick` | **Class 1** (gateway ≤44-bit) **+ Class 2** (range key ≤20-bit) | Do it as a **32-bit SALU predicate** on the pre-sliced tick — not in a gateway (a 32-bit magnitude compare + any second predicate overflows 44 bits) and not a TCAM range key (would force a coarse `[43:24]` ~1 ms slice). Slicing `ingress_mac_tstamp[47:16]` to 32 bits exists to fit the SALU operand width. |
| **Deadline arithmetic** `deadline = t0 + Di` | **Class 5** (single-stage action) | `Di` is controller-installed **action data** (a per-entry constant), so `t0 + Di` is a single-runtime-operand add → one ALU op, one stage. Never compute `Di` from multiple runtime operands in this action. |
| **Per-flow state registers** | **Class 3** (byte-align) **+ Class 8** (no `v==0` sentinel) | Every flag/mode field is `bit<8>` even for one meaningful bit (avoids `invalid SuperCluster` next to 32-bit register outputs). "Empty slot" is **not** an in-SALU `v==0` branch — the controller **seeds all register slots at startup** and the SALU branches on `state`/`generation`, not zero. |
| **Flow-key hash** (canonical bidirectional) | **Class 7** (one tuple shape per Hash) | Canonicalize request and response to the **same** tuple (the port-20000 side is "server") so a single `CRCPolynomial`+`Hash` instance sees one field list. No second `.get()` with a different tuple. |
| **Recirc metadata** (pass counter, carried fields) | Class 3 alignment | Pass counter + carried fields byte-aligned; pass counter in metadata, not a register. |
| **BOUNDED distribution table** (`Di ~ [Dlow,Dhigh]`, deterministic seed) | Class 5 + reproducibility | Controller pre-samples 64–256 `Di` values host-side with the deterministic seed and installs them; data plane indexes by `txn_counter[7:0]`. On-chip `Random<>` avoided — it cannot reproduce the host seed the leakage-safety argument depends on. |
| **Fail-open guards** (RTO cap, watermark, max-pass, wrap, policy-absent) | Class 1 (magnitude compares off gateways) | **RTO cap costs zero data-plane logic** — the controller guarantees every installed `Di ≤ rto_cap_ticks`, so no runtime compare. Watermark/max-pass compares live in SALU predicates or narrow `bit<8/16>` fields. Wrap = `deadline<req` SALU check. Default table action **forwards**. |

Two constructs have **no** TNA primitive and are handled by construction, not a native feature: the
absolute per-packet departure time (`skb->tstamp`) — approximated only by the recirc-hold — and per-flow
FIFO on equal deadline (`fq`) — approximated by the guard-delta ≥ one pass. These are the design's
genuine risk surface (Part 7).

---

## Part 5 — Shared-chip coexistence + deploy procedure

**Loading a DCRN program requires a `bf_switchd` (re)start — a GATED operation needing explicit approval.
It cannot be done hitless on this rig.** Reasoning, grounded in the tree:
- `a co-resident program` is baked into the conf and bound at `bf_switchd` cold start (`the co-resident launch script` →
  `--conf-file …/the co-resident program's conf --init-mode=cold`) and occupies all four pipes (`pipe_scope
  [0,1,2,3]`) [L]. A different program is a different conf → a new `bf_switchd` load.
- There is **no config-swap / `p4runtime_update_config` helper** in `/home/philip/tools`,
  `/home/philip/Projects/Tooling`, or `a co-resident program's source tree` (searched — zero hits). A
  P4Runtime `SetForwardingPipelineConfig` push is theoretically possible but (a) reprograms the MAU (a
  data-plane blip, not truly hitless on Tofino-1), (b) requires a P4Runtime-managed `bf_switchd` mode not
  currently used, and (c) would still lose to `the co-resident auto-load service` reseizing the chip. Treat as unverified [H].

**Safe hand-off sequence** (the `sudo`/restart lines are gated — run only with approval, via the
interactive `!` prefix):
```bash
# 0. Preflight (M0): switch reachable (ssh decps@10.10.54.15), consult the connectivity map,
#    DCRN build present + `make install`ed.

# 1. Take the chip from a co-resident program (prevents auto-respawn):        [gated]
sudo systemctl stop the co-resident auto-load service
sudo systemctl mask the co-resident auto-load service
pkill -f the co-resident launch script

# 2. Load DCRN — the GATED bf_switchd restart (needs Philip's approval):   [gated]
#    keep stdin open, LD_LIBRARY_PATH from the SDE env, cold init, under tmux.
export SDE=/home/decps/Downloads/bf-sde-9.13.2 ; export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH
tail -f /dev/null | "$SDE_INSTALL/bin/bf_switchd" --install-dir "$SDE_INSTALL" \
    --conf-file /home/decps/<dcrn>/dcrn_abs.conf --init-mode=cold --status-port 7777

# 3. Enable ports 8 + 9, enable recirc on dp68, seed registers, install tables — THEN start the
#    controller (after register init, or transient `coarse_time write failed` floods appear).

# 4. Hand the chip back to a co-resident program when done:                   [gated]
sudo systemctl unmask the co-resident auto-load service
sudo systemctl start the co-resident auto-load service
```
Symptom that you skipped step 1: `Failed to find BfRtInfo for program <dcrn>` + `coarse_time write
failed` floods (a co-resident program reseized the chip). The **controller is freely restartable** — bounce that,
never `bf_switchd`, when iterating on control logic.

---

## Part 6 — Staged build plan (each stage = what to build + the check that proves it)

**M0 — Preflight + port/self-clock config (no P4 logic yet).**
*Build:* confirm switch reachable, connectivity map current, `~/.lab_env` sourced; draft `dcrn.conf`;
write the bfrt controller skeleton (`bfrt_starter.py` boilerplate) that enables dp8/dp9, enables recirc
on dp68, and applies the dp68 `max_rate` shaper; resolve the exact 9.13.2 TM-shaping table/field names.
*Acceptance:* dp8/dp9 read `UP / BF_SPEED_25G`; dp68 shows recirc enabled; the shaper entry installs
without error.

**M1 — Compile-only classify + arm skeleton (first real stage/SALU-fit evidence).**
*Build:* parser (Eth/IPv4/TCP/DNP3 FC at fixed offset, skip TCP options via `advance`); ingress that
classifies direction / pure-ACK-vs-combined / FC-allowlist, computes `flow_id`, arms
`reg_req_tstamp`/`reg_deadline` on a dp8 request, and **forwards everything unchanged** (no hold).
Controller seeds all registers, installs `fc_allowlist` + `bounded_target`.
*Acceptance:* `bf-p4c` **compiles clean on the switch SDE** and `make install` succeeds; the resource
report shows the **32-bit deadline compare fits an SALU predicate** and total ingress stages ≤ ~7. This
upgrades every "[I] fits" claim to fact. On any opaque/empty error → constraints.md (Class 6 silent-ICE
first). Live check: dp8↔dp9 forwarding intact, byte-identical.

**M2 — Recirc-hold, single frame (combined case) + the two probe items.**
*Build:* add the deadline compare + recirc loop (release to dp8 when `now≥deadline`, else recirc via
dp68); carry the pass counter in recirc metadata; combined ACK-bearing response only.
*Acceptance:* one combined-profile transaction Vision→Hulk. On a Vision capture, **req→response flattens
to target** (reproduce native ~16.8 → FIXED ~32.7 ms) [M target]; **byte-identical** (SHA-256), 0
retrans/reset. **Probe (a):** confirm the ingress clock refreshes on recirc re-entry (else the egress-
global fallback). **Probe (b):** read dp68 pass counts + `reg_held_count` to confirm a single sparse
frame is actually paced by the shaper (else a Part-2 fallback). These are the last real hardware unknowns.

**M3 — Dual-case + BOUNDED table.**
*Build:* separate case (pure ACK + response, both armed, response deadline `= T + guard_delta`,
`guard_delta ≥ one dp68 pass`); wire `bounded_target` + `txn_counter`.
*Acceptance:* SEL-751-style separate profile — pure ACK and response both move to the common target,
**ACK egresses before response** (FIFO on the Vision capture, 0 dup-ACK / 0 reorder), ACK→response gap
collapses to ~one pass. BOUNDED targets reproduce from the deterministic seed across runs.

**M4 — Fail-open guards.**
*Build:* watermark (`reg_held_count > held_max`), max-pass, wrap-detect, policy-absent/non-allowlist
bypass; RTO cap enforced at controller install (`Di ≤ rto_cap_ticks`).
*Acceptance:* fault-inject each guard → the frame is **forwarded, never dropped, no retransmit, never
held beyond the RTO cap**. Killing the controller leaves forwarding transparent.

**M5 — Two-host rig validation.**
*Build:* full campaign — `run_master.py` on Vision ↔ replay (`split_server.py`) on Hulk through the
switch, capture at Vision `enp59s0f0np0`, across P0_NATIVE / P1_FIXED / P2_BOUNDED and the three device
profiles.
*Acceptance:* (1) timing flattens to target, req→response distributions overlap across profiles; (2)
timing-only classifier balanced accuracy approaches chance 0.333 under BOUNDED (match host 0.289 [M]);
(3) byte-identical, 0 retrans / 0 reset / 0 dup-ACK / 0 reorder; (4) fail-open forwards-never-drops under
fault injection; (5) residuals confirmed on-chip — response size still leaks CROB count (~14.6 B/CROB)
and ACK mode unchanged. Only then is the on-switch hold "proven," not inferred.

---

## Part 7 — Open questions / risks only the first compile or a hardware probe resolves

| # | Open item | Resolved by | Fallback |
|---|---|---|---|
| Q1 | **Stage/SALU fit** — does the whole ingress fit ≤ ~7 stages, and the 32-bit deadline compare fit an SALU predicate? All counts [I] now. | **M1 `bf-p4c` compile + resource report** | Move telemetry fully to egress; coarsen the tick to `[43:24]` + range table (Class 2, ~1 ms) if the SALU predicate won't fit. |
| Q2 | **Recirc-refreshed clock in ingress** — does `ingress_mac_tstamp` re-take on a recirculated packet? | **M2 single-frame probe** | Compare in egress against `global_tstamp`, signal the recirc decision back via bridge/resubmit. |
| Q3 | **Sparse-frame self-pacing** — does a burst-1 `max_rate` shaper on dp68 space a lone frame to ~100 µs/pass? (a co-resident program runs continuous chaff.) | **M2 pass-count read** | Bare recirc + pass-count against a real clock; or a low-rate metronome recirc packet; or dp10/dp11 loopback. |
| Q4 | **True per-pass latency + recirc bandwidth** on this silicon | **M2 measurement** | Only affects headroom, not correctness — DNP3 load is ~0.003–0.6% of budget. |
| Q5 | **a co-resident program coexistence specifics** — clean stop/mask, no residual chaff, ports reset for DCRN | **M0/M5 on the real switch** | Documented gated restart (Part 5); controller re-seed clears transient floods. |
| Q6 | **Vision RTO re-measurement** — the ~150 ms cap rests on a measured Vision RTO ~211 ms that must be re-confirmed on kernel-6.8 before it bounds `Di` | **M5 preflight on Vision** | Lower the controller-installed `Di` cap; mark any class with no safe sub-RTO target as unsupported/bypass (never invent a target). |
| Q7 | **Hitless load** — is a P4Runtime config push viable to avoid the gated restart? Currently [H], no tree evidence. | A separate gated investigation | Do not pursue for the build; the gated `bf_switchd` restart is the sanctioned path. |

**Two invariants hold across every stage and are never traded for fit:** byte-preservation (recirc
carries the frame verbatim; no CRC/field edits; deparser emits original headers) and fail-open (every
guard forwards, never drops, never overshoots the RTO cap). A `bf-p4c` compile on the switch's 9.13.2
remains the only proof that the Part-3 stage/SALU sketch fits; until M1 runs, those counts are honest
inference, not fact.

---

### Files a P4 author starts from
- **This map** — the build plan.
- `corrective.md` — authoritative DCRN spec (arm/classify/dual-case/BOUNDED/fail-open).
- `research/tofino_dcrn_feasibility/agent_contributions/p4_tofino_hardware_feasibility.md` — the quantified recirc-hold this map operationalizes.
- `a co-resident program's bring-up script` — **working bfrt reference** for dp68 recirc-enable + `max_rate` hold-loop cap + `$PORT` config (copy the call patterns).
- `a co-resident program's launch script` + `.../the co-resident program's conf` — the conf/load template DCRN's `.conf` mirrors.
- `/home/philip/tools/bfrt_starter.py` — controller connection boilerplate (`localhost:50052`).
- `~/.claude/skills/tofino-p4/references/{constraints,build-deploy,testbed}.md` — the eight bf-p4c classes, compile flow, shared-chip landmines.
