<!-- P4/Tofino data-plane feasibility contribution for the DCRN timing-normalization study.
Design/analysis ONLY — no P4 written, compiled, or loaded; no scope change. Evidence labels:
[M] measured-rig · [S] standard · [V] vendor-doc · [P] paper-reported · [I] inference · [H] hypothesis.
Tofino resource/latency/buffer numbers not re-verified against the live SDE this session are tagged
[I] or carry the prior doc's [V]/[P] with its source named. -->

# Tofino-1 (TNA) Hardware Feasibility for DCRN Timing Normalization

*P4/data-plane feasibility half of the DCRN feasibility study. Design/analysis only — no P4 written, compiled, or loaded. Evidence labels: [M] measured-rig · [S] standard · [V] vendor-doc · [P] paper-reported · [I] inference · [H] hypothesis. Tofino resource/latency/buffer numbers I did not re-verify against the live SDE this session are tagged [I] or carry the prior doc's [V]/[P] with its source named — per the study's integrity rule I do not assert them fresh from memory.*

---

## 0. Verdict (up front)

**The ~16–42 ms per-flow absolute-deadline hold that DCRN requires is FEASIBLE WITH CONSTRAINTS on Tofino-1 — but only for the DNP3 traffic profile, only via the unbuilt self-clocked recirculation-hold loop, and only as a design that has not been compiled or run. It is not a native TNA primitive and does not become one. For any traffic profile denser than DNP3 polling it becomes INFEASIBLE ON-SWITCH and the hold must stay at the edge (the host/bridge/SmartNIC where DCRN already runs and passed).**

The tension in the brief is real and I confirm it: the TNA Traffic Manager shapes **rate**, not per-packet **absolute latency**, and nothing in the pipeline "sleeps" a packet for tens of milliseconds. The **only** on-switch path to an absolute hold is to keep the frame in flight by recirculating it and checking a clock each lap. Two prior-art documents in this repo take opposite tones on that path, and reconciling them is the core of this analysis:

- `dnp3_split_harness/reports/phases/phase_04/ack_control_feasibility.md` §Q7 [correct, pessimistic read]: bare recirculation "to emulate 25 ms would need tens of thousands of passes per packet … destroying line rate." True for **bare** loopback (per-pass latency ≈ hundreds of ns).
- `research/split_pad_timing_policy/tofino_design.md` §6 [correct, optimistic read]: a **shaped/self-clocked** loopback port cuts a 200 ms hold from ~200,000 passes to ~2,000, and because DNP3 is single-digit kbps and small-frame, at most a fraction of one frame is ever in the loop — "the affordability inversion."

**Both are right within their assumptions.** Bare recirc is prohibitive; self-clocked recirc is affordable **only because DNP3's request→request spacing (~1 s) is ~20–60× the hold (~42 ms)**. That duty-cycle ratio, not any Tofino resource limit, is the number that decides the verdict.

**The single quantified deciding ceiling:** recirc saturates when `concurrent_held_frames × frame_bytes / per_pass_latency` approaches the on-chip recirc budget (~1.6 Tbps [P, Wu 2019 via tofino_design.md §6.4]). For DNP3 the left side is ≈ 0.4–1.5 Gbps (≈ **<0.1 %** of budget); the hold (~42 ms) sits ~3.5× under the RTO-safe cap (~150 ms, below the measured Vision RTO ≈ 211 ms [M, `ack_control_feasibility.md` §9]). Both margins are large. The verdict is *constrained* rather than *clean* not because a resource ceiling is hit, but because the mechanism is unbuilt, needs a dedicated program load, and the separate-ACK dual-packet case needs an ordering guard that TNA does not give for free.

*Plain language: the switch can hold DNP3's rare, tiny replies for 16–42 ms by bouncing each one around an internal loop until a target time, and for DNP3 that is cheap. But it is a trick, not a built-in, it has not been built, and it only stays cheap because DNP3 traffic is slow. Since the host version already works, the switch should probably do the watching-and-classifying and leave the holding to an edge box unless the hold specifically must be on the chip.*

---

## 1. Reconciling the prior design to the DCRN requirement

`tofino_design.md` §6 was written for **split-chunk pacing** (normalize inter-chunk gaps of an already-split response). DCRN is a different shape: it does **not** split, **does not touch the TM shaper for pacing**, and holds **whole packets** to an **absolute per-flow deadline** = `t0 + Di` (request arrival + a class-independent target). Three DCRN requirements the split-pacing design did **not** cover, and how the recirc-hold must change to meet them:

| DCRN requirement (`corrective.md`) | Was it in §6? | Reconciliation |
|---|---|---|
| Absolute deadline `t0 + Di`, `Di` class-independent | Yes (§6.1 `deadline_tick = req_tick + target_delay`) | Directly reusable. `target_delay` must be class-**independent** (§6.1 already flags class-dependent targets as leaky). |
| **Dual-case**: pure TCP ACK vs combined ACK-bearing response | **No** — §6 assumed the 9/9 piggyback (combined only) | New. Combined = one packet, clean. Separate = **two** packets to one deadline with FIFO order — the hard new case (§2.5). |
| **BOUNDED** target sampled from `[Dlow,Dhigh]`, deterministic seed | No — §6 used a per-class constant | New. On-chip bounded sampling has no clean seed-reproducible form (§2.6) — a genuine mapping gap. |
| No split, no pacing queue | §5 built a UC1 shaper for pacing | DCRN drops Stage 2 entirely. The only queue DCRN needs is the **loopback self-clock** port. Simpler than §6's build. |

Net: DCRN is **simpler** than the split-pacing design on the pacing axis (no Stage 2) but **harder** on two new axes (dual-case ordering, bounded sampling). The §6 recirc-hold quantities carry over; the dual-case and bounded-sampling wrinkles are new work.

---

## 2. Q1 — The recirc-hold against the DCRN requirement, quantified

### 2.1 The actual hold-time derived from DCRN's measured numbers

DCRN rig result [M]: native req→resp median **16.8 ms** → FIXED **32.7 ms** → BOUNDED **37.8 ms**. The Tofino is bump-in-the-wire; it sees the outstation's response arrive ~16.8 ms after it forwarded the request. To release at `t0 + Di`, the **incremental on-switch hold** is:

- Combined case, median device: `32.7 − 16.8 ≈ 16 ms` (FIXED), `37.8 − 16.8 ≈ 21 ms` (BOUNDED).
- Worst case (a fast device / low-quantile native ready time, or the pure ACK which is ready sub-millisecond after the request): hold approaches the **full target ≈ up to ~42 ms**.
- Separate case: the **pure ACK** is ready almost immediately, so it must be held nearly the full ~42 ms; the response is held ~16–21 ms. **Two** held frames per transaction.

So the binding requirement is: **hold a single ~90–320 B frame for up to ~42 ms, on up to 2 frames per separate-mode transaction, never overshooting the RTO cap.** 42 ms is comfortably below the ~150 ms RTO-safe cap (measured Vision RTO ≈ 211 ms [M], `TCP_RTO_MIN` 200 ms floor [S]) — DCRN's holds fit with ~3.5× headroom. **Hold-time is not the binding ceiling for DNP3.**

### 2.2 Per-flow state — registers, SALUs, stages

Directly reuses `tofino_design.md` §4.3/§6.5, minus the pacing objects:

| Object | Type | Purpose | Cost |
|---|---|---|---|
| `reg_req_tstamp` | `Register<bit<32>, bit<16>>` keyed by `flow_id` | store `t0` (32-bit tick) at request ingress | 1 SALU |
| `reg_deadline` | `Register<bit<32>, bit<16>>` | store `t0 + Di` absolute deadline | 1 SALU |
| `reg_state` / flags | `bit<8>` fields (Class 3 — widen sub-byte flags) | armed / ack_seen / resp_seen / bypass | in-action |
| recirc pass-counter | carried in recirc metadata, not a register | cap stuck frames (§2.7) | metadata |
| `reg_held_count` | global `bit<32>` | fail-open watermark | 1 SALU |

MAU budget [I, extending §9]: classify + arm + deadline-compute + SALU compare + guards ≈ **5–7 of 12 ingress stages**. Fits standalone. **Co-residency flag [I, §9]:** a 12-stage co-resident program leaves no room — DCRN needs its own program load and its own handoff of the shared chip (mask/unmask the co-resident auto-load service, `testbed.md`).

### 2.3 Timestamp width, resolution, wraparound

Reused verbatim from §6.2 and validated against the skill's gateway/SALU constraint classes:

- `global_tstamp` / `ingress_mac_tstamp` = **48-bit ns** [V, relayed from §6.2]. Slice to `now_tick = global_tstamp[47:16]` → **32-bit tick, 65.5 µs resolution, ~78 h span**.
- A 42 ms hold spans `42 ms / 65.5 µs ≈ 641` ticks (~10 bits of dynamic range), but the **absolute** deadline needs the full 32-bit tick to stay unambiguous across the free-running counter.
- **The deadline-compare tax is the load-bearing bf-p4c constraint.** `now_tick >= deadline_tick`:
  - **Not** in a gateway — gateway predicate input ≤ **44 bits** and a magnitude compare burns the field width [V, skill constraints.md **Class 1**]. A combined 32-bit `>=` plus any second predicate overflows.
  - Must be a **32-bit SALU predicate** — the SALU operand width is ≤ 32 bits [I, §6.3]. This is *why* the pre-slice to 32-bit `now_tick` exists.
  - If instead moved to a TCAM range table, the range key is ≤ **20 bits** (5 nibble pairs) [V, skill **Class 2**] → would need a coarser `[43:24]` (~1 ms tick) slice. The 32-bit SALU path is preferred.
- **Wraparound** once per ~78 h: detect `deadline_tick < req_tick` ⇒ overflow ⇒ **fail open** for that one frame [I, §6.2].

### 2.4 Recirc bandwidth and concurrency — the affordability inversion

- **Per-pass latency L** [P/I, §6.4]: bare on-chip loopback ≈ 0.3–1 µs; **shaped** loopback tuned to ≈ **100 µs/pass**.
- **Passes for a 42 ms hold:** bare (L=1 µs) → **42,000 passes**; shaped (L=100 µs) → **420 passes**. (This is the §Q7-vs-§6 reconciliation in one line: bare is the "tens of thousands of passes" that `ack_control_feasibility.md` correctly calls prohibitive; the self-clock is what makes it ~420.)
- **Recirc BW per held frame** = `frame_bytes / L`. DNP3 response on the wire ≈ 90–320 B ([M] DNP3 app 37→256 B over N=1→16 CROBs + Eth/IP/TCP framing). At ~300 B: L=100 µs → **≈24 Mbps**; L=1 µs → ≈2.4 Gbps.
- **Concurrency** [I, §6.4]: poll spacing ≥ 1 s, hold ≤ 42 ms → duty cycle ≤ ~4 % per outstation → **<1 held frame per outstation on average**; the separate case doubles the peak to ~2 per outstation. A substation of, say, 8–32 outstations → **~16–64 concurrent held frames** peak → **~0.4–1.5 Gbps** recirc at the 100 µs self-clock.
- Against the ~1.6 Tbps on-chip recirc budget [P, Wu 2019 via §6.4] → **<0.1 %**. Register cap `bit<16>` = 65,536 flows (realistic substation 256–4096). **Negligible for DNP3; would explode if request spacing approached the hold time** (§5 ceiling).

*Plain language: to hold a reply ~42 ms the switch bounces it ~420 times around a deliberately slowed internal loop. Each looping reply eats ~24 Mbps of internal bandwidth, and because DNP3 replies are rare only a handful are ever looping at once — well under a tenth of a percent of the loop's capacity. This is cheap only because DNP3 is slow; speed the traffic up and it stops being cheap.*

### 2.5 Dual-case handling — the new requirement, and where TNA does not help for free

- **COMBINED case (AB1400/ION7550-style, one ACK-bearing response):** one frame → one recirc-hold to the deadline. Clean; no ordering problem. This is what §6 already covered.
- **SEPARATE case (SEL-751-style, pure ACK then response):** **two** frames, both to the same deadline, and DCRN requires the pure ACK to egress **before** the response, FIFO (`corrective.md` §8). On the host, `fq` gives this for free (equal EDT → FIFO by enqueue order). **On Tofino recirc it is not free:** two frames recirculating independently both satisfy `now >= deadline` in the same or adjacent pass → a race that can **reorder** them (ACK after response = a duplicate ACK, a fingerprint *and* a fast-retransmit risk, `ack_control_feasibility.md` §9).

  **Reconciliation — DCRN's own guard-delta solves it, and it is the same residual DCRN already measured.** `corrective.md` §8 assigns the response `deadline = target + guard_delta`. If `guard_delta ≥ one recirc pass (L ≈ 100 µs)`, the response becomes eligible **at least one lap after** the ACK → order preserved by construction. DCRN's measured host guard-delta residual was **≈ 0.19 ms** [M] — larger than a 100 µs pass — so the host's calibrated guard-delta maps onto Tofino as "≥ 1 self-clock pass" and enforces separate-case FIFO for free. **The same ~0.19 ms scheduler guard that made DCRN_FIXED leak on the host (balanced-acc 0.740) reappears on Tofino as the recirc quantization** — so a Tofino FIXED build inherits the same device-correlated residual, and the study's "use BOUNDED" verdict [M] carries over to the switch.

### 2.6 BOUNDED policy on-chip — a real mapping gap

DCRN's P2_COMMON_BOUNDED samples `Di` from `[Dlow,Dhigh]` with a **deterministic reproducible seed, no PRNG reset per device/session** (`corrective.md` §4). On TNA:

- A `Random<bit<N>>` extern gives per-packet uniform bits but **not** a seed reproducible against the host PRNG, and not the "same distribution, one seed across the whole run" guarantee DCRN's leakage-safety argument rests on.
- **Cleaner:** the controller installs a small **distribution table** (e.g. 64–256 pre-sampled `Di` values drawn host-side with the deterministic seed) and the data plane indexes it by the transaction counter / stable transaction id (`corrective.md` §4 permits target selection to depend on "transaction counter or stable transaction identifier"). This preserves reproducibility and keeps device-independence, at the cost of one table + one index register. **This is the recommended on-chip BOUNDED realization** [I/H] and should be validated on the rig.

### 2.7 Fail-open — mandatory, and cheap

Five guards, all cheap SALU/gateway checks, default action forwards [reused §6.6, aligned with `corrective.md` §10 and `ack_control_feasibility.md` §7]:

1. **RTO cap:** `deadline − req > rto_cap_ticks` (controller-set below measured Vision RTO) → forward now.
2. **Watermark:** `reg_held_count > held_max` → stop holding new frames.
3. **Max-pass:** per-frame pass counter exceeded → force-emit (stuck-frame guard).
4. **Wrap:** deadline overflow (§2.3).
5. **Policy absent / controller death / non-allowlisted FC** (SELECT/OPERATE/unsolicited/CONFIRM — `corrective.md` §10) → forward.

**Fail-open = native forwarding, never drop** (a dropped or RTO-overshot DNP3 response is the loudest tell to a passive observer and trips a Zeek `dnp3` IDS [M/S, GROUNDING]). **Do not use an in-SALU `v==0` sentinel** for "empty slot" — bf-p4c flattens that branch [V, skill **Class 8**]; seed register slots from the controller at startup.

---

## 3. Q2 — Non-recirc alternatives (validating/extending §6.7)

Each evaluated specifically for **absolute per-flow first-response latency**, not rate:

| Alternative | Absolute per-flow deadline? | Hard limit | Verdict for DCRN |
|---|---|---|---|
| **TM queue shaper / meter** | **No** | Token/leaky-bucket delays a frame only when backlog exists; a lone response at an idle, token-replenished queue (always, at ~1 s poll spacing) leaves **immediately** [I, §5.3]. Shapes rate, not first-frame wall-clock. | Cannot hold. This is the exact seam the brief names. |
| **Timed/scheduled dequeue (802.1Qbv TAS)** | Cyclic-quantized only | Gives *time-quantized cyclic* release, not arbitrary per-frame absolute delay; demonstrated on **Tofino 2** via an internal control-frame stream [P, preprint via §6.7]. On **Tofino 1** a per-queue time-gate hold is **not** an exposed primitive. | Only if policy is a fixed cadence, not a per-frame deadline. Not DCRN. |
| **Deflect-on-drop** | No | Reroutes on congestion; not a controlled hold. Any use risks reorder/loss. | Unusable for a hold. |
| **Packet generator (pktgen)** | No | Has one-shot/periodic/timer triggers [V, §6.7] but emits **new** packets from its buffer — cannot re-emit a specific held frame's exact bytes unless copied into the pktgen buffer (= payload storage, §7-off-ASIC). | Only as a control-loop tick, not a hold. Also would violate no-synthesis if it emitted a frame. |
| **TM buffer / storage queues** | No | TM's ~20–22 MB is **transient egress buffering, not random-access storage** [V, §7]; holding an in-flight frame is fine, parking/re-injecting a specific one is not. | Cannot park a frame for 42 ms addressably. |
| **PFC / pause** | No (and unsafe) | Pauses a whole link, not one flow; back-pressures the outstation and corrupts other traffic. | Rejected — coarse and dangerous on an ICS conduit. |
| **PIFO / SP-PIFO deadline scheduling** | Relative only | Programmable schedulers release in deadline **order** [P, §6.7] but impose no **absolute** wall-clock hold. | Useful as the release discipline *once frames are held*, not as the hold. |

**§6.7 validated and extended:** absolute first-response delay on Tofino-1 is reachable **only** via the recirc-hold; every native alternative gives rate, cyclic cadence, or relative order — **none gives an absolute per-flow deadline.** The extension for DCRN: PIFO is the natural companion to enforce the separate-case FIFO *if* the guard-delta approach (§2.5) is judged insufficient.

---

## 4. Q3 — DCRN construct → TNA mapping (direct / indirect / none)

| DCRN construct (`corrective.md`) | TNA equivalent | Fidelity |
|---|---|---|
| Ingress arm: record `t0` on payload-bearing request | `ingress_mac_tstamp`/`global_tstamp[47:16]` → `reg_req_tstamp[flow_id]` | **DIRECT** |
| Per-flow 5-tuple state (`BPF_MAP_TYPE_HASH`/`LRU`) | Register arrays keyed by a canonical bidirectional flow hash (§4.2), controller-seeded | **DIRECT** (LRU eviction → **none**; use controller/dead-man cleanup) |
| Classify pure ACK vs combined (`payload_len == 0`, exact) | Shallow parse `ip.total_len − ihl×4 − dataOffset×4 == 0`, exact-match/action | **DIRECT** — same exact discriminator eBPF uses (`ack_control_feasibility.md` §Q4) |
| Absolute deadline compare `now >= t0+Di` | 32-bit SALU predicate on pre-sliced tick (§2.3) | **DIRECT (with the pre-slice tax)** |
| **`skb->tstamp` / EDT (per-packet departure time)** | **No field exists.** Closest = the recirc-hold self-clock loop | **NONE — approximated only by recirc** |
| **`fq` qdisc (release at EDT, per-flow FIFO on equal deadline)** | **No equivalent.** TM shaper = rate; PIFO = relative order; recirc = absolute part | **NONE — the single largest gap; fq gives DCRN's whole release engine for free, TNA gives none of it** |
| Separate-case FIFO (ACK before response) | Guard-delta ≥ one recirc pass (§2.5), or PIFO | **INDIRECT** (works, but by construction not by primitive) |
| BOUNDED sampling `Di ~ [Dlow,Dhigh]`, deterministic seed | Controller-installed distribution table indexed by txn counter (§2.6) | **INDIRECT** (reproducibility preserved off-chip; on-chip `Random` cannot match the seed) |
| Fail-open (native forwarding) | Default table action forwards; SALU/gateway guards (§2.7) | **DIRECT** |
| RTO-safe hold clamp | `rto_cap_ticks` guard, controller-set below measured RTO | **DIRECT** |

**The two constructs with no TNA equivalent — `skb->tstamp` and `fq` — are precisely DCRN's release engine.** Everything DCRN does *before* release (arm, classify, per-flow state, deadline math, fail-open) maps directly; the *release* itself has no primitive and is the entire reason the recirc-hold has to exist.

---

## 5. Q4 — Verdict and the deciding ceiling

**FEASIBLE WITH CONSTRAINTS**, constraints named precisely:

1. **Unbuilt, non-native.** The hold exists only as the self-clocked recirc loop — a design, not a compiled artifact. There is no packet-sleep and no EDT on Tofino-1. Every cost here is [I] on an unbuilt design.
2. **DNP3-rate-bound.** Affordable only because request spacing (~1 s) ≫ hold (~42 ms). Not general.
3. **Dedicated program load.** ~5–7 stages standalone is fine, but it cannot co-reside with a 12-stage sibling; requires its own load and shared-chip handoff.
4. **Dual-case ordering** (separate ACK+response) relies on `guard_delta ≥ one recirc pass` (§2.5) — validated by DCRN's own measured ~0.19 ms residual, but an on-chip assumption to prove.
5. **BOUNDED via a controller distribution table**, not on-chip PRNG (§2.6) — else the seed-reproducibility DCRN's leakage safety depends on is lost.
6. **Fail-open must be watertight** — never drop, never overshoot RTO (five guards, §2.7).

**The single quantified deciding ceiling:** the recirc-hold's affordability is governed by the duty-cycle inequality

```
concurrent_held_frames × frame_bytes / per_pass_latency   ≪   on-chip recirc budget
    ~16–64            ×   ~300 B     /   ~100 µs   ≈ 0.4–1.5 Gbps   ≪   ~1.6 Tbps  (<0.1%)
```

and, independently, `worst_hold (~42 ms) ≪ RTO-safe cap (~150 ms)` (~3.5× headroom). **Both clear with 3–4 orders of magnitude / 3.5× margin — so the ceiling that flips the verdict to INFEASIBLE is not any Tofino resource but the traffic rate itself: the moment inter-request spacing falls toward the hold time, `concurrent_held_frames` and duty cycle rise together, recirc saturates, and the hold must move off-switch.** For DNP3 that crossover is ~20–60× away.

**Bottom-line engineering recommendation (matching `ack_control_feasibility.md` §Q7's "Tofino-native half vs Tofino-hostile half"):** DCRN's **classify + measure + arm** half is a clean, native fit for Tofino-1 and worth building there. DCRN's **hold** half is Tofino-*hostile* and already runs correctly at the edge (host eBPF+`fq`, measured PASS [M]). Unless the hold specifically must live on the ASIC, the honest split is **Tofino does the decision; an edge element in the same inline position (the host we own, a two-NIC bridge, or a SmartNIC with native EDT) does the hold.** A SmartNIC/bridge gives the identical bump-in-the-wire position **and** has real per-packet departure timing — so it buys DCRN's release for free where Tofino must abuse recirc for it.

---

## 6. Q5 — On-rig validation plan (Hulk / Vision / Tofino-1, bf-p4c)

If the on-switch hold is pursued, build the **minimal DCRN Tofino program** — classify + arm + recirc-hold + fail-open, **no** Stage-2 pacing (DCRN doesn't split) — and prove the hold on the wire.

**Preflight** [V, `testbed.md`]: consult `/home/philip/Projects/Tooling/tofino_25g_connectivity_map.md`; `sudo systemctl stop/mask the co-resident auto-load service` before loading a non-a co-resident program program; enable ports **8 (Vision/master)** + **9 (Hulk/outstation or `split_server.py`)**; **never restart `bf_switchd` without approval** (only the Python controller is freely restartable); compile on the switch's SDE (9.13.2), not the laptop.

**Minimal build to compile:**
- Shallow parse: Eth/IPv4/TCP + DNP3 FC at fixed offset 12 (skip TCP options via runtime `advance`) — direction, `is_ack_bearing`, pure-ACK-vs-combined by `payload_len==0`.
- `reg_req_tstamp`, `reg_deadline`, `reg_held_count`; deadline compare as a 32-bit SALU predicate (pre-sliced `global_tstamp[47:16]`).
- One shaped **loopback/recirc port (~dev_port 68, [I])** tuned to ~100 µs/pass; carry `deadline_tick` + pass-counter in recirc metadata.
- Controller (bfrt_python): FC allowlist (READ only initially, `corrective.md` §10); `target_delay`/BOUNDED distribution table; `rto_cap`/`held_max`; **seed all registers** (Class 8).

**What to measure (reproduce the DCRN host result on-chip):**
1. **Combined case (AB1400/ION7550 profile):** drive `run_master.py` on Vision ↔ replay on Hulk through the switch. Capture on Vision at the wire-facing interface. **req→response must flatten to the target independent of device**, reproducing native 16.8 → FIXED 32.7 / BOUNDED 37.8 ms [M]. Read `reg_held_count` watermark + per-frame pass counts.
2. **Separate case (SEL-751 profile):** confirm **pure ACK and response both move to the common target**, ACK egresses first (FIFO), and the ACK→response gap collapses to ~one recirc pass. Verify the guard-delta ≥ one pass held ordering across all transactions.
3. **Attacker check:** run the pure-timing classifier from the DCRN harness on the *Tofino-captured* traces — timing-only balanced accuracy should approach chance (0.333) under BOUNDED, matching the host 0.289 [M], and FIXED should retain the device-correlated residual (matching host 0.740) — confirming the recirc-quantization = guard-delta reconciliation (§2.5).
4. **Transport health (byte-preservation invariant):** `tcpdump` on Vision → **SHA-256 byte-identical** DNP3 payloads; **0 retransmits / 0 resets / 0 duplicate ACKs / 0 reordering** attributable to the hold (matching the host DCRN clean-transport result [M]).
5. **Explicit residuals:** confirm on-chip that **response size still leaks CROB count (14.6 B/CROB [M])** and **ACK mode is unchanged** — timing normalized, size and mode not (`corrective.md` scope; GROUNDING).
6. **Fault injection (fail-open):** force `held_count > held_max` and `target > rto_cap` → verify frames are **forwarded, never dropped, no retransmit**.

**Observability** [V, §10/`testbed.md`]: port counters `$FramesReceivedOK`/`$FramesTransmittedOK` (`from_hw=True`); register reads `from_hw=True`, max across pipes; report the **quantized** loopback shaper rate beside the requested (PACKETS-mode mantissa/exponent quantization). offered = Δ(port 9 RX), passed = Δ(port 8 TX).

*Plain language: build the smallest program that watches the request, remembers when it arrived, and bounces the reply (and, for SEL, its separate ACK) around an internal loop until the target time — then prove on a Vision capture that the reply timing flattens across the three device profiles, the bytes are identical, TCP stays clean, and if anything goes wrong the reply just leaves early rather than being dropped. And show plainly that the reply's size still gives the device away, because timing is the only thing this closes.*

---

## 7. Provenance note

Skill-verified this session (cited directly): gateway ≤44-bit (Class 1), range key ≤20-bit (Class 2), widen sub-byte flags to `bit<8>` (Class 3), no in-SALU `v==0` sentinel (Class 8), testbed dev_port map (Vision 8 / Hulk 9). Relayed from prior-art `tofino_design.md` with its original evidence label (48-bit ns timestamp [V], ~1.6 Tbps on-chip recirc / per-pass latency [P, Wu 2019], TM 8 queues shaped in bps/pps [V], ~20–22 MB transient TM buffer [V]) — I did not re-verify these against the live SDE this session, so they carry the prior doc's citation, not a fresh check. Measured DCRN/DNP3 facts [M] from `corrective.md`, the phase-04b rig result, `GROUNDING.md`, and `ack_control_feasibility.md` (Vision RTO ≈ 211 ms). Recirc pass-counts, per-held-frame bandwidth, concurrency, and stage estimates are [I] on an unbuilt design.

**Source files (absolute paths):**
- `/home/philip/Projects/DNP3/research/split_pad_timing_policy/tofino_design.md` — §6 recirc-hold this reconciles to DCRN
- `/home/philip/Projects/DNP3/dnp3_split_harness/reports/phases/phase_04/ack_control_feasibility.md` — §Q7 Tofino-native/hostile split
- `/home/philip/Projects/DNP3/corrective.md` — authoritative DCRN spec
- `/home/philip/Projects/DNP3/research/split_pad_timing_policy/GROUNDING.md` — measured-fact base
- `/home/philip/.claude/skills/tofino-p4/references/{constraints,testbed}.md` — bf-p4c constraint classes and rig topology

**Integrity flag for synthesis:** all Tofino resource/latency/buffer numbers are relayed from prior-art vendor/paper citations or are inference on an unbuilt design — none re-verified against the live SDE this session, and nothing was compiled (research-only constraint). A bf-p4c compile on the switch remains the real proof of the stage/SALU fit.
