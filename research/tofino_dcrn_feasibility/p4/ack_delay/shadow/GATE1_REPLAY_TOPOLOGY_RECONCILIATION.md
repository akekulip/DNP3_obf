# GATE-1 Replay Topology Reconciliation — DNP3 shadow classifier

**2026-07-23. Read-only reconciliation only. Nothing was loaded, no port state was
changed, no interface was brought up, no traffic was transmitted, and the SEL-751 was
not contacted.** This document answers a single question: *does an unambiguous,
evidence-backed inline replay path exist to prove the passive shadow classifier
(`dnp3_shadow.p4`), and if so, what is it?* It supersedes the "port discovery is
ambiguous" stop recorded in `onswitch_9132/SHADOW_ONSWITCH_9132_COMPILE.md` §"STOP
before load" — the ambiguity is now **resolved** by a grounded cabling map plus a live
MAC match (see §1–§2). It does **not** authorize the load; the load remains gated.

---

## 0. Scope and rules honored

- **Authorized read-only actions performed:** switch `$PORT` inspection (bound to the
  running program, `entry_get`), Hulk and Vision `ip -br link` + `ethtool` + `/sys`
  MAC read, repo/switch evidence inspection, source read of the shadow bring-up
  controller. All are non-mutating.
- **Not performed (held per the GATE-1 hold):** `bf_switchd` start, `.conf` load, any
  `$PORT_ENABLE`, any host `ip link set up`, any capture/replay transmit, any relay
  contact.
- **Inference discipline (per the hold's §5):** I do **not** infer dp8→NIC from
  convention — it is evidence-backed (§1). I do **not** claim dp9 is "observation-only".
  I do **not** assume the 25 G link is safe to enable — that is flagged as a gated,
  later action (§8). I report what `dnp3_shadow_setup.py` *code* brings up and mark its
  *runtime* success **unverified** (§6). I do **not** treat the prior hairpin as suitable
  for a symmetric inline test — it is explicitly ruled out (Candidate C, §7).

---

## 1. Known facts, each with its evidence source

| # | Fact | Value | Evidence source |
|---|------|-------|-----------------|
| F1 | Front-panel port carrying the 25 G rig | **QSFP28 port 15**, 4×25 G passive-DAC breakout | `~/Projects/Tooling/tofino_25g_connectivity_map.md` §1 |
| F2 | dev_port 8 ↔ host | **15/0 = dp8 → VISION `enp59s0f0np0`** | connectivity map §1, §3 |
| F3 | dev_port 9 ↔ host | **15/1 = dp9 → HULK `enp59s0f0np0`** | connectivity map §1, §3 |
| F4 | dev_port 10 / 11 | **15/2, 15/3 — empty / unused** | connectivity map §1 |
| F5 | Vision data-NIC MAC | `3c:fd:fe:cc:5d:c0` | connectivity map §3 **and** live `ip link`/`/sys` (this session) — **MATCH** |
| F6 | Hulk data-NIC MAC | `3c:fd:fe:e5:f9:90` | connectivity map §3 **and** live `ip link`/`/sys` (this session) — **MATCH** |
| F7 | Second NIC cage on each host | **`enp59s0f1np1` is an EMPTY cage** (no module) | connectivity map §2 |
| F8 | Data lanes per host | **exactly one** 25 G data NIC into the switch per host | derived from F2/F3/F7 |
| F9 | P4 port constants (shadow) | `PORT_VISION=8`, `PORT_HULK=9`, `PORT_RECIRC=68` | `dnp3_shadow.p4` |
| F10 | Shadow forwarding semantics | **two-port bump-in-the-wire dp8↔dp9**, passive, no mutation, no recirc | `dnp3_shadow.p4` (0 header writes, no `setValid`, no Checksum, no recirc — Phase-1 audit) |
| F11 | Nominal link rate | 25 G, RS-FEC, autoneg | connectivity map §3 |
| F12 | dp68 | recirculation port, **no cable** | shadow/defense sources + prior evidence |

**The load-bearing correlation (resolves the prior ambiguity):** the cabling map's
host↔dev_port assignment is anchored by MAC, and the **live MACs read this session
match the map byte-for-byte** (F5, F6). That is a two-independent-source agreement
(documented map + live device identity), not a convention. **dp8 = Vision, dp9 = Hulk**
is therefore evidence-backed, and it coincides with the P4's own `PORT_VISION=8 /
PORT_HULK=9` naming (F9).

---

## 2. Live current state (read-only, this session)

| Element | Observed state | Note |
|---|---|---|
| Active switch program | `queue_microbench_abs.conf` (queue microbench) | unchanged; restore path known (`launch_mb.sh`) |
| Switch `$PORT` table | **empty on full scan** under the microbench | dp8/dp9 **not configured/up** now (consistent with earlier `n/a`) |
| dp68 (recirc) | down | microbench state |
| Vision `enp59s0f0np0` | **admin-UP, NO-CARRIER, Link=no, Speed unknown**, MAC `3c:fd:fe:cc:5d:c0` | interface already admin-up; carrier absent because dp8 is down |
| Hulk `enp59s0f0np0` | **admin-UP, NO-CARRIER, Link=no, Speed unknown**, MAC `3c:fd:fe:e5:f9:90` | interface already admin-up; carrier absent because dp9 is down |

**Reconciliation with the 2026-06-03 map:** the map records both links "UP" at 25 G;
today both are **link-down**. This is **not** a cabling change — the host NICs are still
admin-up and their MACs still match — it is simply that the **switch-side ports dp8/dp9
are not enabled** under the current queue-microbench program (the microbench ran a
single-port dp9 hairpin with dp8/Vision intentionally down). Bringing the link up is a
**switch-side `$PORT_ENABLE` action** on dp8 and dp9; the host interfaces need no
`ip link set up` (they are already admin-up and will take carrier when the switch ports
come up). This distinction matters for the GATE-1 hold: **no Hulk interface bring-up is
required** — see §8.

---

## 3. Current topology (as it physically stands now)

```
 VISION ──25G DAC (15/0)──► dp8 ┐
                                 │  (switch running queue_microbench;
 HULK   ──25G DAC (15/1)──► dp9 ┘   dp8 & dp9 DOWN → both host links NO-CARRIER)
 (dp10/15-2, dp11/15-3 empty)   dp68 = recirc (no cable), down

 Management plane (separate, 1 GbE, unaffected): Vision eno1, Hulk mgmt → lab switch.
 SEL-751 relay: on the ordinary lab switch (port 13), NOT on any Tofino 25 G lane.
```

Both 25 G data links are physically cabled and identity-confirmed, but electrically
down because their switch ports are disabled under the current program.

## 3a. Prior topology (queue microbench — for contrast)

The queue microbench was a **single-port hairpin on dp9 (Hulk)**: Hulk generated frames
on `enp59s0f0np0` → dp9, the microbench P4 **hairpinned** them back out dp9, and Hulk
captured the return on the same NIC. dp8 (Vision) was down. That worked **only because
the microbench P4 contained hairpin logic**. The shadow does **not** hairpin — it
forwards dp8↔dp9 (F10) — so the microbench rig is **not** a template for the shadow test
(this is exactly the Candidate C dead-end, §7).

---

## 4. Candidate replay topologies

The shadow is a **two-port dp8↔dp9** bump-in-the-wire (F10). dp8 and dp9 terminate on
**two different single-NIC hosts** (F2, F3, F8). Every candidate is evaluated against
that hard physical constraint.

### Candidate A — single-host, two-interface transit  → **PHYSICALLY INFEASIBLE**

*Idea:* one host holds two NICs, injects on the interface wired to dp8, captures on the
interface wired to dp9; the shadow forwards between them.

*Verdict:* **Not possible with the current cabling.** Each host has exactly one 25 G
data NIC into the switch; the second cage (`enp59s0f1np1`) is empty (F7, F8). No single
host owns both dp8 and dp9. Candidate A would require re-cabling a second lane
(15/2 = dp10 or 15/3 = dp11, both empty) to the *same* host — a physical change, out of
scope, and not evidence-backed. **Ruled out.**

### Candidate B — two-host transit (Vision ↔ Hulk through the shadow)  → **RECOMMENDED**

*Idea:* the natural bump-in-the-wire. One host's data NIC injects the replay; the shadow
forwards across dp8↔dp9; the other host's data NIC captures. Two sub-modes:

- **B2 (single-direction inject — simplest, proves the core criteria):** inject the
  **entire** committed 300-poll pcap from **Hulk `enp59s0f0np0` → dp9**; the shadow
  forwards every frame out **dp8 → Vision `enp59s0f0np0`**, which captures. The shadow
  classifies each frame by its **TCP ports** (dst 20000 ⇒ request/READ, src 20000 ⇒
  response/ACK), *independent of physical ingress port* (confirmed in `shadow_refmodel.py`
  and mirrored in the P4), so all 300 READs, 300 RESPONSEs, and the CLRT ACKs classify
  correctly from one inject/capture pair. **B2 validates parser correctness, packet
  preservation, telemetry correctness, byte identity, packet ordering, and passive
  classification for replayed traffic in one forwarding direction (dp9→dp8). Bidirectional
  forwarding behavior remains to be validated separately** (that is B1's role).

- **B1 (per-direction inject — full fidelity):** split the pcap by direction and inject
  each half from the physically correct side — **master→outstation** frames (dst 20000)
  from **Vision → dp8** (captured on Hulk/dp9), and **outstation→master** frames
  (src 20000) from **Hulk → dp9** (captured on Vision/dp8). This reproduces the true
  inline bump-in-the-wire in both physical directions.

*Requirements (both sub-modes):* switch **dp8 AND dp9 enabled** @ 25 G RS-FEC (via the
shadow's own bring-up, §6); both host data NICs carrier-up (follows from the switch
ports); `tcpreplay`/`scapy` on the injecting host and `tcpdump` on the capturing host.
Because dp8 and dp9 are on different hosts, **any** dp8↔dp9 test is inherently two-host —
there is no single-host variant (that was Candidate A).

*Verdict:* **Every physical mapping this needs is evidence-backed** (F2, F3, F5, F6,
F8–F11). **Recommended**, starting with **B2** (simplest path to the §G criteria), with
**B1** as the fidelity upgrade.

### Candidate C — controlled single-host switch hairpin  → **DOES NOT FIT THE SHADOW**

*Idea:* reuse the queue-microbench single-port hairpin (inject + capture on one host via
dp9), letting the switch loop the frame back.

*Verdict:* **Not applicable.** The shadow forwards dp8↔dp9; it has **no hairpin path**
(F10). A hairpin would require *modifying the shadow* to send dp9→dp9, which changes its
semantics, is not authorized, and would **not** prove realistic two-port inline
behavior. The microbench hairpin worked only because that P4 hairpinned. **Ruled out for
the shadow** (kept here only to document why the prior rig does not transfer).

---

## 5. What each candidate can prove

| Property to prove | A (infeasible) | **B2 (single-dir)** | **B1 (per-dir)** | C (n/a) |
|---|:---:|:---:|:---:|:---:|
| Parser reaches DNP3 & classifies (digests) | — | ✅ | ✅ | — |
| Correct class per frame (READ/RESP/ACK/…) | — | ✅ (TCP-port based) | ✅ | — |
| Bidirectional classification | — | ✅ (by TCP port) | ✅ (by physical port too) | — |
| No zero-payload ACK mislabeled DNP3 | — | ✅ | ✅ | — |
| Byte identity (ingress == egress payload) | — | ✅ | ✅ | — |
| Length / IP-len / TCP seq&ack identity | — | ✅ | ✅ | — |
| Order preserved | — | ✅ | ✅ | — |
| Zero loss (count in == count out) | — | ✅ | ✅ | — |
| Telemetry/digest correctness vs refmodel | — | ✅ | ✅ | — |
| **Realistic two-port physical inline** | — | ⚠️ partial (one physical dir) | ✅ | — |

**Recommendation:** run **B2 first** — it validates parser correctness, packet
preservation, telemetry correctness, byte identity, packet length/seq/ack identity,
packet ordering, zero loss, and passive classification for replayed traffic in **one
forwarding direction (dp9→dp8)** from a single, simple inject/capture pair;
**bidirectional forwarding behavior remains to be validated separately** (B1). **Do not
recommend A or C.**

---

## 6. Exact cabling and the bring-up path (evidence + one unverified runtime step)

- **Cabling required:** **none new.** The rig is already cabled: Vision `enp59s0f0np0`
  → 15/0 → dp8; Hulk `enp59s0f0np0` → 15/1 → dp9 (F2, F3, MAC-confirmed F5, F6).
- **Switch ports:** dp8 and dp9 must be **enabled @ 25 G / RS-FEC / LPBK_NONE**. Reading
  `dnp3_shadow_setup.py` (source, read-only): its `--run` bring-up loop iterates
  `[(PORT_VISION=8, "Vision/master"), (PORT_HULK=9, "Hulk/outstation")]` and sets
  `$SPEED=BF_SPEED_25G`, `$FEC=BF_FEC_TYP_RS`, `$AUTO_NEGOTIATION=PM_AN_DEFAULT`,
  `$LOOPBACK_MODE=BF_LPBK_NONE`, `$PORT_ENABLE=True` on **both**. **This is the code's
  intent; its runtime success (carrier + RS-FEC lock on both lanes) is UNVERIFIED until
  it runs** — it must be confirmed live before injecting, not assumed.
- **Host interfaces:** already admin-up (§2); they will take carrier when dp8/dp9 come
  up. **No Hulk (or Vision) `ip link set up` is needed.**
- **Inject / observation / return points (Candidate B):**
  - **B2:** inject point = Hulk `enp59s0f0np0` (→ dp9); observation/capture point =
    Vision `enp59s0f0np0` (← dp8); packet direction through the switch = dp9→dp8 for
    every frame.
  - **B1:** inject points = Vision→dp8 (master-side half) and Hulk→dp9 (outstation-side
    half); capture points = Hulk/dp9 and Vision/dp8 respectively; directions = dp8→dp9
    and dp9→dp8.
- **Replay source/sink:** source = the committed, unmodified physical-relay pcap
  `research/physical_sel751/clrt_300poll_20260723T152242/evidence/clrt_300poll_20260723T152242.pcap`
  (the only authorized replay input); sink = a fresh `tcpdump` capture on the peer host.

---

## 7. Risks and restoration

**Risks**
- **Shared-switch blast radius:** loading the shadow **displaces the queue microbench**
  (single Tofino, single pipe). Anyone relying on the microbench is interrupted for the
  duration. Restore is required afterward.
- **25 G bring-up is a state change on a shared switch** (dp8/dp9 enable). It is gated
  and must be authorized explicitly (§8); it is not covered by "read-only".
- **Runtime port bring-up unverified (§6):** if RS-FEC does not lock on a lane, no frames
  flow — stop and diagnose, do not force.
- **Vision availability:** B1 (and B2's capture) needs Vision's data NIC live. Vision was
  powered off in some prior sessions; confirm it is up before relying on it.
- **No relay involvement:** the SEL-751 is on the ordinary lab switch, not the 25 G
  lanes; a pcap replay cannot reach it. This is a property, not a risk — but it means the
  test proves the *classifier*, not live-relay behavior (that is a later gate).

**Restoration**
- Active program before = `queue_microbench_abs.conf`; known-good restore =
  `/home/decps/queue_microbench/launch_mb.sh` (captured verbatim in
  `onswitch_9132/RESTORE_launch_mb.sh.txt`). Restart `bf_switchd` with that `.conf`
  (`--init-mode=cold`) to return the switch to its prior state, then re-verify the
  microbench is live.

---

## 8. Direct answers to the reconciliation questions

1. **Exact read-only evidence inspected:** the cabling map
   `~/Projects/Tooling/tofino_25g_connectivity_map.md` (front-panel↔dev_port↔host↔MAC);
   live switch `$PORT` (bound to `queue_microbench`, empty scan → dp8/dp9 not up); live
   Hulk & Vision `ip -br link` + `ethtool` + `/sys/class/net/*/address` (both data NICs
   admin-up/no-carrier, **MACs match the map**); the shadow sources
   (`dnp3_shadow.p4` port constants + passive semantics; `dnp3_shadow_setup.py` `--run`
   bring-up loop); the prior compile record (`onswitch_9132/`).
2. **Topology facts confirmed:** dp8 = Vision `enp59s0f0np0` (MAC `…5d:c0`); dp9 = Hulk
   `enp59s0f0np0` (MAC `…f9:90`); dp10/dp11 empty; one 25 G data NIC per host, second
   cage empty; shadow forwards dp8↔dp9 passively; dp68 = recirc, no cable; nominal
   25 G/RS-FEC.
3. **Unresolved facts:** whether dp8 **and** dp9 achieve **runtime** carrier + RS-FEC
   lock under the shadow's bring-up (code intent known, runtime unverified — §6);
   whether Vision is powered on and its data NIC live at test time.
4. **Safest viable candidate:** **Candidate B, sub-mode B2** — single-direction inject
   (Hulk→dp9, capture Vision←dp8). Every physical mapping it needs is evidence-backed; it
   validates parser correctness, packet preservation, telemetry correctness, byte
   identity, length/seq/ack identity, ordering, zero loss, and passive classification for
   replayed traffic in **one forwarding direction (dp9→dp8)**; **bidirectional forwarding
   behavior remains to be validated separately** (B1). **A is physically infeasible; C
   does not fit the shadow.**
5. **Information that must be supplied manually / confirmed live before load:**
   confirmation that Vision is powered on with its data NIC available; and a live check
   (during the authorized load) that the shadow bring-up actually brings **both** dp8 and
   dp9 to carrier/RS-FEC — treat a lock failure as a stop, not a workaround.
6. **Is a physical cable trace required?** **No.** The host↔dev_port mapping is fixed by
   two agreeing independent sources — the documented map and the live MAC identity of
   each NIC (F5, F6). A manual cable trace would add nothing.
7. **Must Hulk's 25 GbE interface eventually be enabled?** The **Hulk interface itself is
   already admin-up** and needs no bring-up. What must be enabled is the **switch-side
   port dp9** (and dp8), which restores carrier on both host links. So: **yes, the 25 G
   *link* must be brought up, but as a switch `$PORT_ENABLE` on dp8/dp9 — not as a host
   `ip link set up`.** This is a shared-switch state change and **remains gated on
   explicit authorization** (it is exactly what the shadow's `--run` bring-up does).
8. **Proposed revised GATE-1 command sequence (to run only under a fresh authorization —
   NOT executed here):**
   1. Save microbench restore state (already captured in `onswitch_9132/`).
   2. `bf_switchd … --conf-file …/dnp3_shadow/build_9132/dnp3_shadow.conf --init-mode=cold`
      (loads the passive shadow, displacing the microbench).
   3. `python3.8 dnp3_shadow_setup.py --run` → brings up dp8+dp9 @ 25 G RS-FEC; **verify
      both reach `$PORT_UP=True` / RS-FEC lock before continuing** (stop if not).
   4. Start `tcpdump` on the capture host (Vision `enp59s0f0np0` for B2), writing a fresh
      pcap.
   5. `tcpreplay -i enp59s0f0np0 …/clrt_300poll_20260723T152242.pcap` on the inject host
      (Hulk for B2) — the **committed pcap only**, no other input.
   6. Collect: ingress/egress captures, classification digests, port state, counters.
   7. Verify §G: 300 READ + 300 RESPONSE + CLRT ACKs classified; **no** zero-payload ACK
      as DNP3; byte/length/seq/ack identity; order preserved; zero loss; digests match
      `shadow_refmodel.py`; **no** recirc/pktgen/timing-defense/fail-open.
   8. Restore: reload `queue_microbench_abs.conf` via `launch_mb.sh`; re-verify microbench
      live.
9. **Commit hash:** recorded on commit (below), Philip's name only.

**Bottom line:** the earlier "port discovery ambiguous" blocker is resolved — an
evidence-backed inline replay path exists (**Candidate B / B2**), needs **no re-cabling**
and **no host interface bring-up**, and requires exactly one gated switch-side action
(enable dp8/dp9, i.e. the shadow's own `--run`). **No candidate is recommended beyond B;
A is infeasible and C does not fit.** The load stays held pending a fresh authorization
that specifically covers the dp8/dp9 25 G enable.
