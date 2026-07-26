# INLINE_TOPOLOGY_DESIGN.md — taking the DNP3 timing normalizer live inline against the physical SEL-751

**Status: DESIGN ONLY.** Nothing in this document has been executed. No switch was touched, nothing was
compiled, no lab host was contacted while writing it. Every physical change, control-plane change and
P4 change described here is gated on Philip's explicit authorization.

**Date:** 2026-07-25
**Branch:** `research/timing-final-meeting`
**Mechanism under discussion:** `research/timing_final/p4/dnp3_timing_normalizer.p4` (the Part-12
HOLD_RESPONSE normalizer), documented in `research/timing_final/TIMING_REFERENCE_IMPLEMENTATION.md`.

---

## 0. Executive summary

The mechanism is proven on silicon but only against **replayed** frames injected by Vision (dp9) and
Hulk (dp11). To protect a **live** master↔relay session the Tofino must forward every DNP3 packet,
because the defense can only hold a packet it forwards. Today it forwards none of them: the relay and
Vision's `eno1` sit on the same unmanaged TP-Link switch, so master↔relay traffic is switched locally
and the Tofino's E1/33 leg sees only flooded broadcast.

The recommended fix is smaller than expected, and it dissolves the hardware blocker recorded in project
memory twice over:

1. **Tofino-1 can terminate the relay leg directly.** Front panel E1/33 = dev_port 64 links at
   `BF_SPEED_1G` with FEC none and auto-negotiation force-disabled (measured this session). The
   "Tofino is 10G+ only" blocker is dissolved.
2. **The unmanaged TP-Link, reduced to exactly two active ports, *is* the active 100M→1G rate
   adapter** that was being shopped for. An unmanaged switch with one 100M RJ45 port and one 1G SFP
   uplink and nothing else attached is functionally a store-and-forward media/rate converter. No new
   hardware is required.

So the entire physical change is: **unplug one cable** (Vision `eno1` out of the TP-Link) and move the
master onto the 25G NIC that is already cabled to dp9. The relay then has exactly one path to the
master, and it runs through the Tofino.

The P4 change is three lines (one new constant, one parser select entry, one `fwd_port` assignment).
The control-plane change is one per-port speed override, because the existing setup script hard-codes
every host port to 25G.

The genuinely new engineering risk is **not** cabling and **not** rate mismatch. It is four live-TCP
behaviours that replay structurally could not exercise, listed in §7. Two of them (a response admitted
to `Q_RESP` with no armed deadline, and a multi-segment response) can stall or reorder a live SCADA
session and both have cheap mitigations that are identified below.

---

## 1. Corrected physical topology

### 1.1 What is wrong today

```
                 ┌──────────────── unmanaged TP-Link ────────────────┐
  SEL-751 ───────┤ port 1 (100M RJ45)                                │
  192.168.10.7   │                          port 25 SFP (1G) ────────┼──── Tofino E1/33 = dp64
                 │ port N ◄── Vision eno1 (192.168.10.1)             │        (sees flood only)
                 └───────────────────────────────────────────────────┘
```

Master↔relay unicast is learned and switched *inside* the TP-Link. The Tofino is a stub: it receives
broadcast and unknown-unicast flood and forwards nothing that matters. This is confirmed by the fact
that Vision can ping the relay with the Tofino port administratively down.

Note the second-order problem, which is worse than the first: even if the Tofino leg were carrying
traffic, `eno1` and the dp9-facing NIC would both be in the same L2 broadcast domain, giving the relay
**two** paths to Vision. That is a bridging loop through a device (the Tofino) that does not run STP and
does not do MAC learning. It must not be allowed to exist even transiently.

### 1.2 Recommended topology (Option A)

```
   Vision                              Tofino-1 (UfiSpace)                    TP-Link (2 ports live)
   192.168.10.1/24  ── 25G SFP28 ──►  E15/1 = dp9 ◄──┐                    ┌── port 25 SFP  1G
   enp59s0f0np0        (existing)                     │  P4 cross-connect │
                                                      └─► E1/33 = dp64 ───┘
   eno1  ── UNPLUGGED, de-addressed, NM-disabled                          └── port 1  100M RJ45
                                                                                     │
   Hulk  ── 25G SFP28 ──► E15/3 = dp11   (blocker-token injector only)          SEL-751 192.168.10.7
                                          no DNP3 traffic, never forwarded
                          E15/0 = dp8     MAC-near loopback, no cable
                                          Q_BLOCK qid7 HIGH / Q_RESP qid1 LOW
```

Cable-by-cable change list:

| # | Action | Detail |
|---|---|---|
| A1 | **Unplug** Vision `eno1` from the TP-Link | Remove the cable from the switch end, coil and label it `EMERGENCY BYPASS — see §5`. Do not leave it dangling in a port. |
| A2 | **Verify** exactly two TP-Link ports are lit | Port 1 (relay, 100M) and port 25 (SFP uplink, 1G). Any third lit port re-creates a short-circuit. |
| A3 | **Leave** TP-Link port 25 SFP → Tofino E1/33 as-is | Already links at 1G. |
| A4 | **Leave** Vision 25G → Tofino E15/1 (dp9) as-is | Already links at 25G RS-FEC. |
| A5 | **Leave** Hulk 25G → Tofino E15/3 (dp11) as-is | Repurposed from "outstation surrogate" to "blocker-token injector". No recabling. |
| A6 | **Move** `192.168.10.1/24` from `eno1` to `enp59s0f0np0` | Host-side, §1.4. |

Nothing is bought, nothing else is moved. The relay leg keeps its existing 100M→1G adaptation; the
master leg keeps its existing 25G link; the loopback and the token injector are untouched.

Why this is the recommendation: it makes the Tofino a true two-port bump-in-the-wire while changing the
**smallest possible amount of already-validated state**. dp8, dp9, dp11 and the entire TM/queue
configuration stay bit-for-bit as they were in the passing Part-12 and live-demo runs, so any new
failure is attributable to the one new leg (dp64) and the one new traffic source (a real relay).

### 1.3 Alternatives considered

**Option B — master on Hulk/dp11 instead of Vision/dp9.**
Rejected. It buys nothing and costs several validated invariants: `PORT_VISION` is the master-side
constant throughout the P4 (`dnp3_timing_normalizer.p4:133`, and every `from_*` parser state's
`fwd_port`, lines 313–318), the released response is documented and measured as egressing dp9, and
Vision is the host that has the DNP3 master (pydnp3), the relay-subnet address and the capture
tooling. Swapping master and injector sides would force a P4 constant swap *and* a harness swap for no
benefit. Keep the master on Vision/dp9.

**Option C — insert the Tofino between the relay and the TP-Link, leaving the master on `eno1`.**
Rejected on three counts. (i) It needs a *second* 1G-capable Tofino port plus a second media step, and
the only other cabled front-panel leg, E1/1 = dev_port 132, does not link at any speed. (ii) dev_port
132 is **pipe 1**, which breaks the mechanism outright (§2.4). (iii) It keeps `eno1` energised on the
relay subnet, which is precisely the failure mode we are trying to eliminate. Strictly worse.

**Option D — keep `eno1` plugged in but only remove its IP address.**
Rejected, and this is worth stating explicitly because it is the tempting shortcut. De-addressing is
*not* sufficient:

- The interface still participates in L2. The relay's broadcasts and ARP still reach Vision by two
  paths, and the Tofino bridges the two legs, so a frame can loop TP-Link → dp64 → Tofino → dp9 →
  Vision *and* TP-Link → `eno1` → Vision.
- Linux ARP flux: with `arp_ignore=0` (the default) Vision may answer an ARP for `192.168.10.1` out of
  `eno1` even when the address lives on another interface, silently pinning the relay's ARP cache to
  the wrong port and restoring the short-circuit for all subsequent unicast.
- NetworkManager will happily re-apply a saved `192.168.10.1/24` profile on a link-up event, a
  `NetworkManager` restart, or a reboot — silently, mid-experiment.
- Source-address selection and a stale `192.168.10.0/24` route can send master traffic out `eno1` even
  with the address moved, if the old route survives.

**Unplug the cable.** Then also do the software belt-and-braces of §1.4 so that re-plugging it by
accident does not immediately re-create the short-circuit.

### 1.4 Host-side single-path enforcement on Vision

```bash
# 1. take eno1 out of service (in addition to unplugging it)
sudo nmcli device disconnect eno1
sudo nmcli device set eno1 managed no
sudo ip addr flush dev eno1
sudo ip link set eno1 down

# 2. put the master address on the dp9-facing NIC
sudo ip addr add 192.168.10.1/24 dev enp59s0f0np0
sudo ip link set enp59s0f0np0 up mtu 1500        # NOT jumbo — see §3.3

# 3. belt and braces against ARP flux if eno1 is ever re-plugged
sudo sysctl -w net.ipv4.conf.all.arp_ignore=1
sudo sysctl -w net.ipv4.conf.all.arp_announce=2
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
```

`VIS_RELAY_IFACE` in `research/timing_final/config/lab.env` (line 31) must then be **pinned** to
`enp59s0f0np0` rather than left empty for auto-detection, because auto-detection keys on whichever
interface holds `VIS_RELAY_ADDR` (line 30) and would silently follow the address back to `eno1` if the
address ever reappeared there. Pinning turns a silent misroute into a loud mismatch.

Note that `VIS_DATA_IFACE` (line 32) and the relay-facing interface now become **the same interface**.
That is intended: the live master's DNP3 traffic and the dp9 leg are the same wire. Any harness logic
that assumes those two are distinct must be reviewed before a live run.

### 1.5 Proving there is exactly one path

Six checks, in order. Check 6 is the definitive one and it is simply the inverse of the diagnostic that
already demonstrated the fault.

1. `ip -br addr | grep 192.168.10` shows the address on `enp59s0f0np0` and **nowhere else**.
2. `ip route get 192.168.10.7` resolves `dev enp59s0f0np0`.
3. `ip neigh show 192.168.10.7` shows the relay learned on `enp59s0f0np0` only.
4. `ethtool eno1 | grep "Link detected"` reports `no`.
5. TP-Link front panel: exactly two link LEDs lit.
6. **Negative test.** With the Tofino's dev_port 64 administratively disabled
   (`$PORT_ENABLE=False`), `ping -c3 192.168.10.7` from Vision **must fail**. Today it succeeds — that
   success *is* the bug. Re-enable dev_port 64 and the ping must succeed again. Only when this test
   flips both ways is the Tofino genuinely inline.

### 1.6 Observation-point caveat (threat model)

A bump-in-the-wire normalizer only normalizes what is downstream of it. After this change:

- A tap **between the Tofino and the master** (the dp9 leg) observes the normalized CLRT ≈ G.
- A tap **between the relay and the Tofino** — on the 1G fibre, on the 100M copper, or by mirroring
  inside the TP-Link — observes the **native** CLRT, completely unprotected.

This is inherent and must be stated in the paper: the adversary model is an observer on the *upstream*
(control-centre) side of the normalizer. The TP-Link becomes a new, physically accessible, unprotected
observation point. In a real deployment the normalizer would sit at the substation edge with nothing
observable between it and the outstation.

---

## 2. Port map and control-plane changes

### 2.1 Front-panel to dev_port map (measured this session — ground truth)

| Front panel | dev_port | pipe | status |
|---|---|---|---|
| 15/0 | 8 | 0 | internal MAC-near loopback, no cable — blocker ring + hold queues |
| 15/1 | 9 | 0 | Vision 25G, `BF_SPEED_25G` / `BF_FEC_TYP_RS` / `PM_AN_DEFAULT` |
| 15/2 | 10 | 0 | unused |
| 15/3 | 11 | 0 | Hulk 25G, same settings |
| 33/0 | **64** | **0** | **NEW relay leg.** Links at `BF_SPEED_1G` / `BF_FEC_TYP_NONE` / `PM_AN_FORCE_DISABLE`. 10G and 25G do **not** link. |
| 33/1–33/3 | 65–67 | 0 | unused |
| 1/0–1/3 | 132–135 | **1** | E1/1 does not link at any speed; nothing live is cabled |
| 34/* | — | — | does not exist |

### 2.2 `$PORT` configuration for dev_port 64

The existing setup script brings every host port up at 25G unconditionally —
`research/ibspg_paired/control/ibspg_paired_setup.py:68-83` builds one `data` tuple with
`$SPEED="BF_SPEED_25G"`, `$FEC="BF_FEC_TYP_RS"`, `$AUTO_NEGOTIATION="PM_AN_DEFAULT"` and applies it to
every dev_port in `--host-ports`. **Passing `64` in that list will not work**: the port will be
configured at 25G and will stay down, exactly as measured.

The relay leg needs its own tuple:

```python
# dev_port 64 — relay leg, 1G, no FEC, AN force-disabled (MEASURED to link)
key  = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", 64)])]
data = [port_tbl.make_data([
    gc.DataTuple("$SPEED",            str_val="BF_SPEED_1G"),
    gc.DataTuple("$FEC",              str_val="BF_FEC_TYP_NONE"),
    gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
    gc.DataTuple("$LOOPBACK_MODE",    str_val="BF_LPBK_NONE"),
    gc.DataTuple("$PORT_ENABLE",      bool_val=True)])]
port_tbl.entry_add(tgt, key, data)          # entry_mod on the retry path, as at :76-82
```

Minimal, reviewable change to the script: replace `--host-ports 9,11` with two lists, e.g.
`--host-ports-25g 9,11` and `--host-ports-1g 64`, sharing the add/modify retry block at
`ibspg_paired_setup.py:76-82` and differing only in the three string values. Do **not** silently change
the existing default — `03_configure_tm.py:100` passes `--host-ports %s,%s` from `DP_VISION`/`DP_HULK`,
and that call site must be updated in the same commit so the two cannot drift.

Note that dp8 keeps its own distinct tuple (`ibspg_paired_setup.py:93-98`: 25G, FEC none, AN
force-disable, `BF_LPBK_MAC_NEAR`, with the delete-then-add dance because a live entry rejects a
loopback-mode change). **Do not touch it.** The loopback staying at 25G is what makes §3 easy.

### 2.3 Every place a port constant must change

**P4 — `research/timing_final/p4/dnp3_timing_normalizer.p4`** (three functional lines):

| Line | Now | Change |
|---|---|---|
| 132–134 | `PORT_L = 9w8`, `PORT_VISION = 9w9`, `PORT_HULK = 9w11` | **add** `const PortId_t PORT_RELAY = 9w64;  /* outstation side, 1G */` |
| 302–307 | `select(ingress_port) { PORT_L; PORT_HULK; PORT_VISION; default: accept }` | **add** `PORT_RELAY : from_outstation;` — the relay leg reuses the existing state verbatim |
| 317 | `state from_master { ... meta.fwd_port = PORT_HULK; ... }` | → `meta.fwd_port = PORT_RELAY;` so the READ reaches the relay, not Hulk |

`dp11` deliberately **stays** in the select and keeps `port_ok = 1`, because Hulk remains the
blocker-token injector (§4.2). It simply never receives a forwarded frame any more: nothing sets
`fwd_port = PORT_HULK` after this change, and blocker tokens are forced to `to_block()` →
`PORT_L` (`:566-570`) by the parser's ethertype override (`:331-336`).

Two comments should be corrected in the same commit so the file does not lie: `:129`
(`DIR_OUT ... (dp11) or loopback`) and `:694` (`only dp8 / dp9 / dp11 are in the topology`).

This is a genuinely three-line diff because the relay leg is *semantically identical* to the old
outstation leg — same direction, same forward target, same role classification. That is worth stating
in the paper: the normalizer is port-agnostic by construction.

**Resource expectation:** the change adds one entry to a parser select on `ingress_port` and changes one
compile-time constant. It should not move the 10/12 ingress stage count, the 0 egress stages, or the
critical path of 8. **This must still be re-measured** — `TIMING_REFERENCE_IMPLEMENTATION.md:10` pins a
source SHA-256 and `config/lab.env.example:47` pins `P4_SRC_SHA256`; both must be updated, and gate G1
(§6) exists to confirm the resource fit rather than assume it.

**Control plane / configuration:**

| File | Line | Change |
|---|---|---|
| `config/lab.env.example` | 50 | `DP_HULK="11"` — re-comment as *token injector*, not outstation |
| `config/lab.env.example` | — | **add** `DP_RELAY="64"`, `RELAY_SPEED="BF_SPEED_1G"`, `RELAY_FEC="BF_FEC_TYP_NONE"`, `RELAY_AN="PM_AN_FORCE_DISABLE"` |
| `config/lab.env.example` | 31 | `VIS_RELAY_IFACE` — pin to `enp59s0f0np0`, stop auto-detecting (§1.4) |
| `config/lab.env.example` | 89 | `BUDGET="2000000"` — **reduce**, see §7.1. This bounds the worst-case stall. |
| `scripts/03_configure_tm.py` | 70 | read `DP_RELAY` alongside `DP_VISION`/`DP_HULK` |
| `scripts/03_configure_tm.py` | 100 | pass the split 25G/1G host-port lists |
| `scripts/00_preflight.sh` | 85–89 | topology banner still prints Hulk as the outstation; must print the relay leg |
| `scripts/make_pub_figures.py` | 48 | figure label `"Hulk\noutstation\ndp11 (dir1)"` is now wrong for live runs |

**Unchanged, deliberately:** the queue configuration. `ibspg_paired_setup.py:104-135` configures
`tf1.tm.queue.sched_cfg` only for the loopback port group (`--pg-l 2`), setting `Q_BLOCK` qid7 to
`max_priority=HIGH` and `Q_RESP` qid1 to `LOW`, keyed by `pg_queue = pg_l_nr*8 + qid` (`:107`). Since
both hold queues live on dp8 and dp8 is untouched, none of this moves. Likewise the C3 shaper-clear on
`Q_BLOCK` (`03_configure_tm.py:113-123`) is unchanged.

**New check needed:** dev_port 64's own queues have never been configured by this project, and the
switch normally runs `queue_microbench`, which *does* install max-rate shapers. A stale shaper on
dev_port 64 qid0 would rate-limit the master→relay READ path and would be very hard to diagnose from
the DNP3 layer. Extend the existing `tm_shaper_clear.py` invocation to also clear and verify dev_port
64's qid0 — this is the same class of bug as the documented C3 finding, applied to the new port.

### 2.4 Pipe assumption — stated explicitly

On Tofino-1, `dev_port = (pipe_id << 7) | local_port`. Therefore:

- dev_port 8, 9, 11, 64 → all `< 128` → **all pipe 0**. ✅ The assumption holds for the recommended
  topology, and it is consistent with the measured map (E1/* = 132–135 = 128+4… = pipe 1).
- Derived port groups (`pg = local_port / 4`, `nr = local_port % 4`): dp8 → pg 2 nr 0, dp9 → pg 2 nr 1,
  dp11 → pg 2 nr 3 — which matches `lab.env.example:52-53` (`PG_L=2`, `PG_L_NR=0`) exactly. By the same
  arithmetic **dev_port 64 → pg 16, nr 0**. *DERIVED, not measured* — read back `tf1.tm.port.cfg` for
  dev_port 64 to confirm before relying on it. It is only needed if a queue on dp64 is ever configured.

**What breaks if a leg lands on pipe 1** (e.g. if someone cables the relay to E1/1 = dev_port 132):

Registers and counters on Tofino are **per-pipe**. A single P4 program is loaded to all pipes, but each
pipe has its own physical copy of `reg_tag`, `reg_deadline`, `reg_t_ack` and every counter. The state
machine therefore silently splits:

- The relay's pure ACK ingresses on pipe 1 and arms **pipe 1's** `reg_deadline`
  (`dnp3_timing_normalizer.p4:739-743`).
- The blocker tokens ingress on dp8, which is pipe 0, and evaluate **pipe 0's** `reg_deadline`, which
  was never armed. `meta.expired` never becomes 1 (`:785`).
- Consequence: **no transaction ever releases on its deadline.** Every response is held until a blocker
  exhausts its pass budget (`:721-723`, `:789-792`), i.e. roughly 3.4 s at the current `BUDGET=2000000`
  with K=64. That is a multi-second SCADA stall per poll, and it would present as "the defense sort of
  works but the timing is wrong", which is the worst possible failure signature.
- Secondarily, the control plane would read zeros: `03_configure_tm.py` and the counter readers use
  `pipe_id=0xffff` (all-pipe) for `$PORT` but the queue config uses `pipe_id=0`
  (`ibspg_paired_setup.py:61`, `tgt0`), and the register/counter readers are prefixed `pipe.Ingress.*`.
  Per-pipe register readback would need explicit per-pipe targets.

**Rule to carry forward: every port in this pipeline — the master leg, the outstation leg, the token
injector and the loopback — must be in the same pipe as `PORT_L`.** dev_port 64 satisfies this. E1/*
(132–135) does not. This constraint should be asserted in `00_preflight.sh` as
`(DP_VISION|DP_HULK|DP_RELAY|DP_LOOP) >> 7 == 0`, so it can never be violated silently.

---

## 3. Rate and MTU mismatch analysis

### 3.1 The key structural fact: the hold does not happen on either host leg

This is the point that makes the whole rate question much less scary than it looks. Both hold queues
live on the **internal loopback dp8**, not on any host-facing port:

- `to_block()` sets `ucast_egress_port = PORT_L; qid = QID_BLOCK` (`dnp3_timing_normalizer.p4:566-570`).
- `to_resp()` sets `ucast_egress_port = PORT_L; qid = QID_RESP` (`:571-575`).
- Only on release does the dequeued response re-enter ingress from dp8, take the `from_loopback`
  parser state (`:313-314`, which sets `fwd_port = PORT_VISION`), and egress via `to_fwd()`
  (`:579-583`, `:806`).

dp8 is configured at `BF_SPEED_25G` with `BF_LPBK_MAC_NEAR` (`ibspg_paired_setup.py:94-98`) and is
**unchanged** by this design. Therefore:

- The blocker reservoir circulates at 25G, as validated.
- The held response waits in a 25G queue, as validated.
- The release path is dp8 → ingress → dp9 at 25G, as validated.

**The 1G relay leg is nowhere in the hold or release path.** It only affects (a) how long the response
takes to *arrive* at the Tofino and (b) how fast a READ is delivered to the relay.

### 3.2 Does the K ≥ 64 result still hold?

Yes, and the reason is invariance rather than re-derivation.

Honest statement of what is actually known: the number 64 is **not derived anywhere in the project
record**. `IBSPG_HOLD_RESPONSE_RESULT.md:40` states only that the "reservoir K=64 [was] validated for
the tested 11-stage program", inheriting it from Part 9, and scopes every claim to "the tested reservoir
depth K=64" (`:409`). The only sub-64 data point ever measured is K=0, where the response egressed in
2.10 ms tracking the injector's own spacing — "without a blocker reservoir nothing holds the response"
(`:150-156`). Behaviour for 0 < K < 64 is **NOT MEASURED**. The `K < 64` guard in
`scripts/lib/trial.sh:31-32` encodes the empirical setting, not a derivation.

Given that, the correct argument for carrying K=64 forward is: **every quantity K could plausibly depend
on is unchanged.** The reservoir port, its speed (25G), its loopback mode, the queue priorities, the
token frame, the pipeline depth and the number of MAU stages traversed per pass are all identical to the
validated configuration. The one thing that changes — the relay leg's line rate — is not in the loop.
K=64 therefore carries over **unchanged and for the same unexamined reasons it worked before**. It is
not newly justified by this design, and it should not be presented as if it were.

The related empirical anchors that also carry over unchanged: the single-token dp8 MAC-near loop RTT of
408 ns (jitter 403–415 ns), and the release tail of ≈1.72 µs — median 1,720 ns, sd 1.14 ns over n=100
(`IBSPG_HOLD_RESPONSE_RESULT.md:15, 224, 234-235`). Note the project record explicitly **withdraws** the
description of that tail as "one loopback RTT" (`:12-18, 390-392`); it is ≈4.2× the loop RTT and its
internal composition is instrumented nowhere (`:238-239`). Treat it as a constant implementation offset
that a deployment compensates by programming `G' = G − 1.72 µs`, not as a modelled quantity.

### 3.3 Rate and MTU: what actually changes

**Serialization added by the relay leg.** Store-and-forward through the TP-Link means a frame is fully
received at one rate before being sent at the other:

| Frame | at 100M | at 1G | TP-Link one-way add (100M→1G) |
|---|---|---|---|
| 60 B ACK | 4.8 µs | 0.48 µs | ≈ 5 µs |
| ~300 B response | 24 µs | 2.4 µs | ≈ 25 µs |
| 1500 B response | 120 µs | 12 µs | ≈ 120 µs |

Effect on the measurement: `native_clrt` is computed **at the Tofino** as `t_resp_arrival − t_ack` via
`reg_t_ack`'s difference-SALU (`dnp3_timing_normalizer.p4:826-836`). Both events cross the same relay
leg, so the leg contributes only the *difference* in serialization between the response and the ACK —
roughly 20–115 µs. Against a native CLRT of order 12 ms and a G of 17–25 ms this is 0.1–1%, i.e.
negligible for the defense but worth one sentence in the paper's measurement-fidelity note, because the
reported "native CLRT" is then the relay's internal latency *plus* a bounded, deterministic media
conversion.

Crucially it is **deterministic, not jitter**: with only two active TP-Link ports there is no
contention, so store-and-forward adds a fixed per-size delay rather than a queueing distribution. And
the response's arrival jitter is structurally irrelevant anyway — the release time is `t_ack + G`
regardless of when the response arrives, provided it arrives before the deadline. The mechanism is
arrival-time-insensitive by design; that is a robustness property worth claiming.

**MTU.** No encapsulation, no header insertion, no size change anywhere: the ingress deparser emits in
extraction order (`:861-878`) and egress is a byte-preserving pass-through that extracts only Ethernet
(`:887-917`). So the Tofino introduces no MTU pressure. The risk is entirely host-side: if Vision's 25G
NIC is left at a jumbo MTU, Vision could emit a >1518 B frame that the Tofino forwards happily and the
TP-Link or the relay then drops, producing an intermittent black hole with no counter anywhere to
explain it. **Pin `mtu 1500` on `enp59s0f0np0`** (§1.4) and verify with a DF-bit ping sweep in gate G3.

**TM buffering, 25G → 1G on the master→relay direction.** DNP3 polling is a few hundred bytes every few
hundred milliseconds, so the steady-state buffering requirement is nil. The real hazard is an
*unrelated* burst on Vision's data NIC — a stray `iperf`, an OS update, an mDNS storm — filling dev_port
64's egress queue and consuming shared TM buffer. Because the held response is sitting in the *same*
shared TM buffer on dp8's `Q_RESP`, sustained buffer exhaustion could tail-drop it. That is a **new
failure mode introduced by the rate mismatch, and it is a drop, not an early release** — strictly worse
than fail-open, because the master sees a lost response rather than an unprotected one.

Mitigations, in order of preference:
1. Keep `enp59s0f0np0` dedicated to the relay subnet. No other addresses, no other services. Disable
   IPv6 and mDNS on it.
2. Install a per-queue buffer cap on dev_port 64 qid0 so a master-leg burst cannot consume the shared
   pool. (Uses the same `tf1.tm.*` tables the project already drives; specific table/field
   **UNVERIFIED** — needs a schema check on 9.13.2 before it is written.)
3. Add a preflight gate that dev_port 64's TX drop counter is zero before and after each run.

### 3.4 New fail-open risks introduced by the topology

| Risk | Mechanism | Severity | Mitigation |
|---|---|---|---|
| dp8 link/loopback flap | reservoir dies; `Q_BLOCK` empties | Held response in `Q_RESP` is lost; subsequent responses pass through unprotected | Fail-*open* for new traffic (safe). Monitor dp8 TX/RX counters; alarm on stall. |
| dev_port 64 flap | relay leg down | DNP3 session drops; master reconnects | Same as any link failure; §5 |
| TM buffer exhaustion via dp64 | shared pool | Held response **dropped** | §3.3 mitigations |
| Stale `queue_microbench` shaper on dp64 qid0 | READ path rate-limited | Silent latency inflation on master→relay | Extend the C3 shaper-clear check to dp64 (§2.3) |

---

## 4. Live-session mechanics that replay did not exercise

Replay supplied every packet on a schedule the harness controlled. A live relay does not. Two
consequences deserve their own section before the TCP budget.

### 4.1 The reservoir must be established *inside* the ARM→response window

`IBSPG_HOLD_RESPONSE_RESULT.md:156` and `PART12_HOLD_RESPONSE_PLAN.md:56-61` state the constraint
plainly: *"Established-before-admit is a harness obligation, not a P4 one"* — if a response reaches
`Q_RESP` while `Q_BLOCK` is empty, it egresses immediately and the deadline never governs it.

The ordering constraint is tighter than "before the response", because of how the generation tag works:

- A blocker token's generation is `hdr.ib.gen` (`dnp3_timing_normalizer.p4:331-336`).
- A transaction's generation is the DNP3 **application control byte** of the READ,
  `meta.gen_in = hdr.dnp3_app.app_control` (`:397`), constrained to `0xC0..0xCF` by the ARM select leaf
  (`:405-409`) — FIR=FIN=1, CON=UNS=0, with the low nibble being the application sequence that
  increments per poll.
- The READ **takes** the tag (`:713-715`, `:641`), so a token injected *before* the READ carries the
  *previous* poll's generation, fails `tag_diff == 0` on its next pass (`:644`, `:781-784`), and
  terminates as stale.

So the valid injection window is **strictly between the READ and the response**, and the tokens must
carry that READ's `app_control`. The replay harness satisfied this by construction: `scripts/lib/trial.sh:15-16`
runs the plan builder with `--selftest`, which "asserts each blocker token's gen byte == the guarded
READ's DNP3 app-control byte (0xC0..0xCF) before use", and the schedule places the READ first, tokens at
`TOK_LEAD_MS=20` before the ACK, the ACK at `ACK_LEAD_MS=70`, and the response `RESP_DELAY_MS=2` after it
(`trial.sh:67-69`, `lab.env.example:91-94`).

Live, the window is the relay's native CLRT — roughly 12 ms — and nobody schedules it. Three options:

**Option 4.1-a (recommended for first live bring-up): reactive trigger from the master host.**
A small sniffer on Vision's data NIC with `PACKET_OUTGOING` matching on the DNP3 READ it just
transmitted, extracting `app_control`, and sending a one-datagram UDP trigger to Hulk over the
management LAN (10.10.54.0/24). Hulk emits K tokens stamped with that generation on dp11. Latency
budget: sniff ≈100 µs + management-LAN RTT ≈200 µs + emit ≈100 µs, well under 1 ms against a ~12 ms
window. Advantages: master-agnostic (works with a vendor master, not just pydnp3), preserves the exact
`--selftest` generation invariant, needs no P4 change, and keeps tokens off both production legs.

**Option 4.1-b: generation-sweep burst.** Emit 16×K tokens covering `0xC0..0xCF`; exactly K match the
live tag and survive, the other 15K terminate stale on their first pass (`:781-784`). At 64 B per token
that is 1024 frames ≈ 65 KB ≈ 26 µs on a 25G link — free. This removes the need to know the generation
but **not** the need to land inside the window, so it still needs a trigger; it is a simplification of
4.1-a, not a replacement. It is the right fallback if reading `app_control` on the fly proves awkward.

**Option 4.1-c: free-running injector.** Rejected for steady-state use. Tokens carrying the current tag
survive indefinitely (`BUDGET=2000000` ≈ 3.4 s at K=64), so bursting every few ms between polls
accumulates thousands of live tokens in `Q_BLOCK` — hundreds of kilobytes of TM buffer and an
ever-growing loop population. Shortening `BUDGET` to bound the accumulation is **actively dangerous**
because budget exhaustion sets `TAG_INACTIVE` and retires the *live* transaction (`:721-723`),
manufacturing spurious fail-opens. Do not free-run.

**Longer term:** the defensible production answer is to generate the burst on-chip with the Tofino
packet generator, triggered by the ARM, removing the host entirely from the arming path. That is new
P4/control-plane work, out of scope here, and worth naming as future work in the paper.

### 4.2 Hulk's new role

Hulk keeps its dp11 cable and becomes a **dedicated blocker-token generator** with no DNP3 role. This is
deliberate: tokens must not appear on either production leg. An 0x88C1 frame on the dp9 master leg would
be a glaring artifact for exactly the passive observer the defense is defending against, and on the
relay leg it would reach the SEL-751. Keeping them on dp11 means they are visible only on a wire that
carries nothing else and terminates at the loopback.

The P4 already guarantees containment: the parser **forces** `ROLE_BLOCK` on ethertype 0x88C1
regardless of any field in the frame (`:329-336`), and `ROLE_BLOCK` can only reach `to_block()`
(`:751-752`) or `drop_pkt()` (`:782, :786, :790`). The existing "0 external blocker frames" gate from
the live demo should be retained verbatim.

---

## 5. Live-TCP timing budget

### 5.1 The constraint, stated correctly

The held packet is the DNP3 **response**, and its TCP sender is the **relay**. So the binding timer is
the **outstation's** retransmission timeout, not the master's. The relay starts its RTO on transmitting
the response and stops it when the master's acknowledgement returns.

Let:
- `C` = native CLRT (relay's ACK → relay's response), measured ≈12.9 ms for the SEL-751 in the corpus;
- `G` = programmed guard interval, target band 17–25 ms;
- `R` = one-way master-leg latency + the master's ACK generation delay;
- `D` = the master's delayed-ACK delay, 0 if the DNP3 CONFIRM piggybacks the acknowledgement, up to
  40 ms on a Linux master if it does not.

The response is released at `t_ack + G + 1.72 µs`, so the delay the mechanism *adds* to the relay's
perceived round trip is `G − C`. The constraint is:

> **(G − C) + R + D  <  RTO_relay**, and simultaneously **G > C** (else no protection is applied at
> all, which the G-guard already detects and counts via `ctr_response_zero_hold` /
> `reg_protection`, `dnp3_timing_normalizer.p4:837-844`).

The operating band for G is therefore bounded on **both** sides:

```
   native CLRT p99  +  margin   <   G   <   RTO_relay  −  R  −  D  −  margin
```

With `C ≈ 12.9 ms` and `G = 25 ms`, the added delay is ≈12.1 ms. If the master's CONFIRM piggybacks
(the normal DNP3 case) `D ≈ 0` and the total perceived RTT is ~13 ms. Even with a pathological 40 ms
delayed ACK it is ~53 ms. Against any plausible RTO — Linux floors at 200 ms, RFC 6298 mandates a 1 s
initial value — there is a comfortable margin.

**`RTO_relay` for the SEL-751 is UNVERIFIED.** It is an embedded stack; its minimum RTO, its initial
RTO and whether it implements RFC 6298 at all are unknown. Everything above is an argument that the
margin is *likely* large, not a measurement. Gate G6 exists to measure it.

### 5.2 Timers that are *not* the binding constraint, and why

- **The master's RTO on the READ.** Not affected: the relay's pure ACK is forwarded immediately and is
  never queued (`:759-767`, and `TIMING_REFERENCE_IMPLEMENTATION.md:40`). The master sees its READ
  acknowledged on the native schedule.
- **The DNP3 application response timeout on the master.** Typically 5–10 s, configurable; 25 ms is
  three orders of magnitude below it.
- **DNP3 link-layer confirm timeout.** Only relevant if link confirms are enabled; they are not in this
  harness, and the timeout would still be ≫25 ms.
- **TCP keepalive, zero-window, Nagle.** Irrelevant at this scale and traffic volume.

### 5.3 How to verify

Capture on **both** legs simultaneously — on Vision's `enp59s0f0np0` (master leg) and via a span/tap or
the relay-leg counters — for N ≥ 100 transactions at the target G, then:

1. `tshark -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"` → **must be zero**.
2. `tshark -Y "tcp.analysis.duplicate_ack"` → **must be zero**.
3. Relay-perceived RTT: the interval from the relay's response to the master's acknowledgement of it.
   Report median and p99; it must be comfortably below the RTO located in step 4.
4. **Locate `RTO_relay` empirically.** Sweep G upward (25, 40, 60, 80, 120, 160, 200 ms…) until the
   first retransmission appears, in short bounded runs. The G at which retransmission begins gives a
   direct measurement of the relay's effective RTO, which is both a safety bound and a genuinely
   interesting result for the paper: *the achievable normalization interval on a real outstation is
   bounded above by that outstation's TCP retransmission timeout.* That reframes G-selection from an
   arbitrary policy choice into a measured device property, and it strengthens the contribution.
5. Confirm the response is acknowledged by a piggybacked DNP3 CONFIRM rather than a delayed pure ACK
   (measure `D`), since `D` enters the budget directly.

---

## 6. Bypass and failover

This is a live protection relay. Three things must be true before any live run.

### 6.1 The safety argument, stated first

The normalizer sits on the **SCADA telemetry path** (DNP3 polling over TCP/20000), not on any
protection path. An SEL-751 executes its protection functions locally and autonomously; loss or delay of
DNP3 degrades *visibility at the control centre*, not the relay's ability to trip. A 25 ms hold and even
a complete session loss are therefore availability events on the monitoring plane.

Two conditions bound that argument and both must be enforced:
- **READ-only.** No `DIRECT_OPERATE`, no `SELECT`/`OPERATE`, no cold restart through this path during
  live runs. The P4's ARM leaf already only matches `func_code == 1` (`:405-409`), so control commands
  are classified `ROLE_BYPASS` and forwarded unheld — but the *policy* must also hold, because a control
  command riding a session that the defense can stall is a different risk conversation.
- **Time-boxed.** Live runs are scheduled, attended and bounded, with the bypass procedure rehearsed
  before the first run.

### 6.2 Soft bypass — instant, no switch access, no reconfiguration

**Stop the token injector.** With `Q_BLOCK` empty, a response admitted to `Q_RESP` is the highest
eligible queue and egresses immediately. This is not a hack; it is exactly the `native` mode the
validated harness already uses (`scripts/lib/trial.sh:25` — `native) mode="bypass"; RUN_K=0`), and it
is the same K=0 condition measured in `IBSPG_HOLD_RESPONSE_RESULT.md:150-156`.

Properties: takes effect within one token pass-budget drain of the *currently* circulating tokens (bound
it by choosing `BUDGET` per §7.1), requires no switch login, no bfrt call and no reload, and leaves the
forwarding path fully intact. **This is the primary bypass and it should be a single command on Hulk.**

Second soft bypass, if the injector cannot be reached: `make configure-tm G_MS=0`, i.e.
`03_configure_tm.py --set-g --g-ms 0`. With G=0 the deadline is already expired when the ACK arms, so
the first blocker pass terminates and the response releases within microseconds. Slower than stopping
the injector (needs switch access) and it does not stop already-circulating tokens from being replaced,
so treat it as secondary.

### 6.3 Hard bypass — restore native connectivity

Re-plug the labelled `eno1` cable into the TP-Link and restore its address. Physical, unambiguous,
~30 seconds including the address change, and it works even if the Tofino is dead, wedged, or
unreachable. The short-circuit that is a *bug* during the experiment is the *emergency bypass* outside
it — which is exactly why the cable must be labelled rather than merely unplugged.

Rehearse this before the first live run and time it.

### 6.4 Failure modes

| Event | Effect on the relay leg | Effect on a held response | Recovery |
|---|---|---|---|
| **Token injector stops** (crash, or deliberate) | none — forwarding intact | released as soon as the reservoir drains | none needed; this is the soft bypass |
| **dp8 flap** | none — forwarding intact | **lost** (queue destination goes down) | fail-open for all subsequent traffic; master retries the poll |
| **dev_port 64 flap** | link down; DNP3 session drops | lost | master reconnects; DNP3 session re-establishes |
| **Program reload** (bf_switchd relaunch) | ports flap, session drops | lost | ~30–60 s; master reconnects. `PART12_HOLD_RESPONSE_PLAN.md:81-82` documents the reload/restore as reversible |
| **bf_switchd death** | **UNVERIFIED** — see below | lost | hard bypass (§6.3) |

**The bf_switchd question must be answered by test, not by assumption.** On Tofino the ASIC data plane
runs independently of the control-plane process once programmed, so a *crashed* `bf_switchd` may leave
the pipeline forwarding; a *clean exit* typically de-initialises ports and would black-hole the leg.
Which of these this box does is not recorded anywhere in the project — `IBSPG_HOLD_RESPONSE_RESULT.md:130-131`
only notes that a non-destructive on-switch compile left `bf_switchd` running (PID unchanged). Determine
it deliberately in gate G8 with a `kill -9` and a clean `SIGTERM`, before a live relay depends on the
answer.

### 6.5 Watchdog

A host-side watchdog on Vision during live runs, checking every second and alarming (not
auto-remediating) on:
- no DNP3 response for > 3 poll periods;
- `ctr_release_fail_open` or `ctr_block_term_timeout` incrementing;
- `reg_protection == 0` on consecutive transactions (a silent low-G condition);
- dev_port 64 or dp9 link state change;
- any TCP retransmission on the master leg.

Alarming rather than auto-remediating is deliberate: an automatic bypass triggered by a transient would
be its own source of confusing, unreproducible results.

---

## 7. Live hazards that need a decision before the first run

These are behaviours of the *existing, frozen* program that replay could not surface. None of them is a
bug in the mechanism; all of them are consequences of a real relay generating real TCP.

### 7.1 A response with no armed deadline is still admitted to `Q_RESP` — bound the stall

`dnp3_timing_normalizer.p4:755-758` admits **every** `ROLE_RESP` arriving from the outstation direction
to `Q_RESP`, unconditionally. There is no check that a deadline is armed. If the relay ever piggybacks
its acknowledgement instead of emitting a separate pure ACK — under load, after a retransmission, or on
a different application function — no `ROLE_ACK` arms the deadline, yet the response is still queued
behind an occupied reservoir. Nothing then expires (`:785`), and the response waits until a blocker
exhausts its pass budget (`:721-723`, `:789-792`).

At the current `BUDGET=2000000` (`lab.env.example:89`) that is **≈3.4 s** at K=64
(`IBSPG_HOLD_RESPONSE_RESULT.md:418`). A 3.4-second stall on a live SCADA poll is unacceptable and will
likely blow the master's application timeout.

**Mitigation — cheap, no P4 change.** The budget is carried in `hdr.ib.seq`, which the *injector* sets.
Reduce `BUDGET` so the worst-case unarmed hold is bounded at ~100–200 ms. Scaling from the measured
anchor (2,000,000 passes ≈ 3.4 s at K=64), ≈100,000 passes gives ≈170 ms. Verify empirically rather than
trusting the linear scaling, and keep the bound comfortably **above** the maximum G plus margin so it
never pre-empts a legitimate deadline release. This single configuration change converts a multi-second
stall into a bounded one.

Note the interaction with §4.1-c: this is the *right* reason to shorten `BUDGET`, whereas shortening it
to bound a free-running injector's token accumulation would be the *wrong* reason, because it would
manufacture fail-opens on live transactions. The distinction is that here the budget is being sized
against a genuine watchdog requirement, and it must stay well above the deadline it is backstopping.

**Also gate it:** confirm over N ≥ 100 live transactions that the SEL-751 always emits a separate pure
ACK. The corpus says it does (that is what makes it a Case-A device), but the corpus is a capture, not a
guarantee under live load.

### 7.2 A multi-segment response is only partly protected

If the DNP3 response exceeds the TCP MSS (≈1448 B with RFC 7323 timestamps, which the SEL-751 uses —
`data_offset = 8`, `:358`), the master's stack sees several segments. Only a segment whose bytes at the
DNP3 offset present `0x0564` and `func_code == 129` is classified `ROLE_RESP` (`:383-411`); a
continuation segment that does not is `ROLE_BYPASS` and is **forwarded immediately**, overtaking the
held first segment.

Consequences: visible reordering on the master leg, dup-ACK/SACK from the master, and a partially
normalized interval. TCP still reassembles correctly, so this is a fidelity and stealth problem rather
than a correctness one — but a reordering artifact is itself a fingerprint, which undercuts the defense.

**Decision required before the first live run:** choose a poll whose response fits in one segment
(measure it in the native baseline, gate G4), or accept and document the limitation. Related and
equally important for claim discipline: a **multi-fragment** DNP3 response gets only its *first*
fragment normalized, because the deadline is armed once per ACK and is already expired by the time the
second fragment arrives. The honest scope statement for the paper is **single-fragment, single-segment
responses**.

### 7.3 A relay retransmission produces a duplicate held response

If the relay's RTO fires (which §5 is designed to prevent), the retransmitted response is another
`ROLE_RESP` and is queued behind the first. Both are released. The master's TCP discards the duplicate,
so the application is unharmed, but the byte-identity accounting and the observable frame count are
both perturbed. This is one more reason the zero-retransmission gate in §5.3 is a hard PASS criterion
and not a nicety.

### 7.4 Unsolicited responses bypass the defense

An unsolicited response carries `func_code == 130`, which does not match the `ROLE_RESP` leaf
(`:406`, which requires `DNP3_FC_RESPONSE = 129`, `:118`). It falls through to `accept` → `ROLE_BYPASS`
and is forwarded unheld. Unsolicited responses are disabled in this harness by policy, and should stay
disabled; if they were ever enabled they would constitute an unprotected timing channel straight
through the normalizer. Worth one line in the limitations section.

---

## 8. Staged gate list

Mirrors the Part-12 gate style: each gate has one explicit PASS criterion, and no gate is attempted
until the previous one passes. Gates G0–G2 touch nothing live; G3 onward require authorization.

| Gate | What | PASS criterion |
|---|---|---|
| **G0** | Design review | This document reviewed and the three §7 decisions taken (BUDGET value, single-segment poll, unsolicited disabled). No hardware touched. |
| **G1** | **Compile** the 3-line P4 change (§2.3) locally with bf-p4c 9.13.1 | 0 errors; **10/12 ingress stages, 0 egress stages, critical path 8** — identical to the frozen baseline (`TIMING_REFERENCE_IMPLEMENTATION.md:16-19`). Any change in stage count halts the gate. New source SHA-256 recorded and `P4_SRC_SHA256` updated. |
| **G2** | Control-plane dry run | `03_configure_tm.py --dry-run` and the modified `ibspg_paired_setup.py` emit the expected commands including the 1G tuple for dev_port 64. Preflight asserts all four dev_ports are pipe 0. Nothing executed on the switch. |
| **G3** | **Single-path proof** (relay still on native path, Tofino leg down) | All six checks of §1.5 pass. Decisive criterion: with dev_port 64 disabled, `ping 192.168.10.7` from Vision **fails**; with it enabled, it succeeds. MTU 1500 confirmed by a DF ping sweep. |
| **G4** | **Native CLRT baseline through the new path**, defense OFF (injector stopped, K=0) | N ≥ 100 DNP3 polls complete with **0 TCP retransmissions, 0 dup-ACKs, 0 resets**. Report native CLRT median/sd/p99. Report **response segment count == 1** for the chosen poll (§7.2). Report ACK mode == separate for 100% of transactions (§7.1). This is the reference the protected run is compared against, and it must be taken through the *inline* path, not the old one. |
| **G5** | **Port bring-up and L2 byte-identity**, program loaded, injector still off | dev_port 64 `PORT_UP` at 1G/FEC-none/AN-force-disable and dp9 `PORT_UP` at 25G/RS. DNP3 session establishes end to end. **Every forwarded DNP3 payload byte-identical** between the two capture points (the ingress-deparser emission-order guarantee, `:861-878`, plus the empty egress, `:887-917`). 0 external blocker frames on either production leg. dp11 TX == 0. |
| **G6** | **Protected CLRT at G = 25 ms** | Observed CLRT median within `TOL_MS` of G; `reg_protection == 1` and `ctr_response_actually_held` increments for every transaction; `ctr_release_deadline == N`, `ctr_release_fail_open == 0`; `ctr_block_term_deadline == K` per transaction with `timeout == 0` and `stale == 0`. **0 TCP retransmissions and 0 dup-ACKs on both legs** — the live-TCP gate §5 does not exist in the Part-12 record and is the single most important new criterion. |
| **G7** | **RTO location sweep** | G swept upward in short bounded runs until the first relay retransmission appears. PASS = the retransmission threshold is located and is ≥ 2× the operating G. Produces the measured `RTO_relay` bound for the paper. |
| **G8** | **Failure-mode rehearsal** (scheduled, relay owner informed) | Soft bypass (stop injector) restores native timing within one budget drain. Hard bypass (re-plug `eno1`) restores connectivity, timed. bf_switchd `SIGTERM` and `kill -9` behaviours **observed and recorded** (§6.4). Port flap on dp64 and dp8 recovers without manual intervention beyond a master reconnect. |
| **G9** | **Sustained live campaign** | N ≥ 100 transactions at the operating G with all G6 criteria held, plus zero watchdog alarms, plus switch restored to `queue_microbench` afterwards with a restoration report (matching the existing live-demo discipline). |

---

## 9. UNVERIFIED items register

Everything below is an assumption or a derivation, not a measurement. None of it should be presented as
established, and each needs a check before it is relied upon.

| # | Item | How to verify |
|---|---|---|
| U1 | dev_port 64 → port group 16, nr 0 | Read back `tf1.tm.port.cfg` for dev_port 64. Derived from `pg = local_port/4`, which matches dp8/dp9/dp11 exactly, but not measured. |
| U2 | `RTO_relay` for the SEL-751 | Gate G7. Currently unknown; the entire §5 margin argument rests on it. |
| U3 | bf_switchd death behaviour (data plane keeps forwarding or not) | Gate G8. Not recorded anywhere in the project. |
| U4 | SEL-751 always emits a separate pure ACK under live load | Gate G4. Corpus evidence is a capture, not a guarantee. |
| U5 | SEL-751 response fits one TCP segment for the chosen poll | Gate G4. Data-dependent on the poll and point count. |
| U6 | The 3-line P4 change does not move stage count / critical path | Gate G1. Expected but must be measured. |
| U7 | Per-queue buffer cap table/field names on dev_port 64 (9.13.2) | Schema check against the on-switch bfrt info before writing §3.3 mitigation 2. |
| U8 | `BUDGET ≈ 100,000` yields ≈170 ms | Linear scaling from the single measured anchor (2e6 ≈ 3.4 s at K=64). Measure directly. |
| U9 | Vision's 25G NIC driver (i40e vs ice) and whether source-pruning or MTU defaults bite | `ethtool -i enp59s0f0np0`; relevant because a prior campaign needed `disable-source-pruning on`. |
| U10 | The relay's DNP3 self-FIN configuration is resolved | Prerequisite recorded in project memory: the relay accepted TCP then FIN'd itself in ~1.9 ms with 0 DNP3 exchanged. **G4 cannot pass until this is fixed on the relay** (session enabled / master-IP allowlist / single session). This is a relay-configuration blocker, not a network one, and it is independent of everything in this document. |
| U11 | K ≥ 64 has no published derivation | Carried forward on invariance (§3.2), not re-justified. If the reservoir port, its speed or the pipeline depth ever change, K must be re-validated from scratch. |

---

## 10. Change summary

**Physical (Philip):** unplug Vision `eno1` from the TP-Link and label the cable. That is the entire
physical change. No adapter purchase, no recabling of dp9/dp11/dp8, no change to the relay's own cabling.

**Host (Vision):** move `192.168.10.1/24` from `eno1` to `enp59s0f0np0`, pin MTU 1500, disable `eno1` in
NetworkManager, set the ARP-flux sysctls.

**Host (Hulk):** repurpose from outstation surrogate to blocker-token injector; add the reactive
trigger (§4.1-a).

**P4:** three lines in `dnp3_timing_normalizer.p4` — a new `PORT_RELAY = 9w64` constant, one parser
select entry routing dev_port 64 into the existing `from_outstation` state, and `from_master`'s
`fwd_port` changed from `PORT_HULK` to `PORT_RELAY`. Plus two stale comments.

**Control plane:** a 1G/FEC-none/AN-force-disable `$PORT` tuple for dev_port 64 (the existing script
hard-codes 25G for all host ports), a `DP_RELAY` entry in `lab.env`, a reduced `BUDGET`, a pipe-0
assertion in preflight, and an extension of the C3 shaper-clear check to dev_port 64's qid0. The dp8
loopback configuration and the entire queue/priority configuration are **unchanged**.

The mechanism itself — the reservoir, the strict-priority starvation, the deadline SALU, the G-guard,
the byte-preserving deparser — is untouched. That is deliberate: the frozen feasibility baseline stays
frozen, and everything new is confined to which physical port carries the outstation side and who
triggers the token burst.
