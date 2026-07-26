# INLINE_RELAY_SAFETY_AND_CONFIG.md

**Design/analysis only.** No hardware was touched, no host was contacted, no relay was probed to
produce this document. Every quantitative statement is traced to a file in this repository or is
marked UNVERIFIED. Date 2026-07-25, branch `research/timing-final-meeting`.

**Question answered:** what has to be true, and what can go wrong, when
`dnp3_timing_normalizer.p4` (silicon-proven on replayed frames, `TIMING_FINAL_RESULT.md`) is placed
as a bump-in-the-wire in front of the **physical SEL-751** and driven by a **live** DNP3 session.

---

## 0. Findings first

**F1 — The first thing that will break is not DNP3, it is the switch port topology.** The P4 program
treats the set of legal ingress ports as a *compile-time constant*, not a table:

```
const PortId_t PORT_L      = 9w8;   /* internal loopback            */
const PortId_t PORT_VISION = 9w9;   /* master side                  */
const PortId_t PORT_HULK   = 9w11;  /* outstation side              */
...
transition select(ig_intr_md.ingress_port) {
    PORT_L : from_loopback; PORT_HULK : from_outstation; PORT_VISION : from_master;
    default : accept;      /* port_ok stays 0 -> dropped in the MAU */
}
...
apply { if (meta.port_ok == 8w0) { ctr_bypass.count(8w1); drop_pkt(); } ... }
```

(`research/timing_final/p4/dnp3_timing_normalizer.p4`, lines 132–134, 302–307, 693–696.)

The relay leg is **dev_port 64**. 64 is not in {8, 9, 11}, so **every frame from the relay is
dropped in ingress** — ARP included. The relay does not "fail to speak DNP3"; it vanishes from the
network entirely. The symptom you are seeing right now (relay not answering ARP from the master)
is exactly what this produces, and it is also what the *currently loaded* program
(`queue_microbench`, restored after the live demo per `evidence/live_demo/restoration_report.txt`)
would produce, because that program has no reason to bridge dp64 to dp9 either. **INFERENCE, not
measured** — but it is the first hypothesis to test, and it is testable from switch port/drop
counters alone.

Fix: change one constant (`PORT_HULK` → `9w64`), recompile, and update `DP_HULK` in
`research/timing_final/config/lab.env`. Two places must move together, and `P4_SRC_SHA256` in
`lab.env` must be restamped — `00_preflight.sh` checks it. See §5, gate G1.

**F2 — The timing margin is not close.** At G = 25 ms every DNP3 and TCP timer that could react is
between 8× and 200× away (§3). The first symptom of an over-large G is a **TCP retransmission of
the held response by the relay**, at G on the order of the relay's minimum RTO (200 ms – 1 s), long
before any DNP3 application-layer symptom (≥ 5 s). The 17–40 ms band is safe against everything on
the upper side.

**F3 — The real risk is the *lower* bound on G, and it fails silently.** Native CLRT for this relay,
n = 300, direct path: median 1.899 ms, p95 7.426 ms, **max 15.649 ms**
(`research/physical_sel751/clrt_300poll_20260723T152242/CLRT_EXPERIMENT_REPORT.md`); the timing
campaign's native p99 is 11.42 ms. The 8-poll live re-check on 2026-07-25 gave 1.0–5.07 ms. **G = 17 ms
sits below the observed native maximum** — tail transactions arrive already late, the deadline has
passed, the mechanism degenerates to pass-through, and nothing in the wire trace announces it. Only
the in-switch `zero_hold` / `protection` guard registers reveal it. Recommend **G = 25 ms**, and
treat any run at G < 20 ms as requiring a zero-hold count of exactly 0 to be reportable.

**F4 — Protection function is not at risk; SCADA visibility is.** On an SEL-751 the protection
elements act on locally sampled analog inputs through local logic to local output contacts. DNP3 is
a monitoring/telemetry service on the communications card. Holding, delaying, or even completely
losing DNP3 cannot inhibit a trip. What *is* at risk is everything that depends on the wire: the
DNP3 session's continuity across switch reloads, remote control, event upload, and relay
manageability (§2).

**F5 — The mechanism carries exactly one transaction slot.** All state registers are executed at
index 0 (`tag_rmw.execute(0)`, `deadline_rmw.execute(0)`, `t_ack_*.execute(0)`). One master, one
outstanding request, one DNP3 conversation on the segment. The unmanaged TP-Link switch on the relay
leg is a hazard here: any *other* device on it shares the 1 G uplink, enters the pipeline on the same
dev_port, and is forwarded straight to the master leg by the static `fwd_port`. If any of it looks
like DNP3 function 129 it contends for the single slot. The relay must be alone on that switch.

**F6 — The relay's response changed size between 2026-07-23 and 2026-07-25** (115 B DNP3 link frame /
69 points, versus 54 B payload). Either the read differs or the relay's point map/config was
changed. Native CLRT scales with response assembly work, so the 2026-07-23 n = 300 distribution may
no longer describe the device. Re-baseline before selecting G (§5, gate G4).

---

## 1. Session preconditions (the connectivity blocker is SOLVED — recorded, not re-analyzed)

Per the coordinator's correction and
`research/ibspg_dnp3_replay/evidence/relay_live/RELAY_CONNECTIVITY_SOLVED.md` (commit 9f7f4f5), the
"accepts TCP then FINs with zero DNP3 bytes" behaviour had two confirmed causes, both fixed on the
live device. They are now **operating preconditions**, not open questions:

| precondition | value | why it constrains the inline build |
|---|---|---|
| master source IP | **192.168.10.1** (relay setting `DNPIP1`, read in QuickSet) | The relay's DNP3 map allowlists one master address. Whichever NIC becomes the **master leg into dp9 must carry 192.168.10.1**, and no other interface on Vision may hold it. This is a topology constraint, not just a host setting. |
| outstation DNP3 link address | **0** (not 10; 10 came from the 10.0.0.x corpus) | Any live master, probe, or replay spec pointed at the physical relay must use dst = 0. Found read-only with a Request Link Status (function 9) scan; only dst = 0 answered with a Link Status (function 11) frame. |
| master DNP3 link address | 1 | — |
| relay | 192.168.10.7/24, MAC 00:30:A7:02:4C:A2, TCP 20000 | — |
| ACK behaviour | **separate ACK — Case A, has a real CLRT** | Defense 2 (HOLD_RESPONSE) applies. Terminology per `CASE_A_TERMINOLOGY.md`. |
| TCP header | **data_offset = 8** (RFC 7323 timestamps negotiated) | Covered by the timing classifier — the pure-ACK arm matches `(flags 0x10, doff 8, total_len 52)` and the response path matches `(doff 8, total_len ≥ 65)` via the `opt12` state (P4 lines 358, 369, 376). The *size* normalizer, built for doff = 5, cannot fire on this device; that is a size-axis limitation and does not affect this work. |

Two consequences worth stating explicitly, because they bite at cabling time:

1. **The allowlist forces the master leg's identity.** Today `192.168.10.1` lives on Vision's `eno1`
   (the interface that reaches the TP-Link directly), while the dp9-facing NIC is
   `enp59s0f0np0` (`config/lab.env`). Going inline means moving `192.168.10.1` onto
   `enp59s0f0np0` **and removing it, and `192.168.10.100`, from `eno1`** — otherwise Linux will
   route relay traffic out the old interface and the Tofino will never see it.
2. **A leftover direct path invalidates the experiment silently.** If `eno1` stays plugged into the
   TP-Link, the master reaches the relay without traversing the switch, the run looks perfectly
   healthy, and the measured CLRT is simply the native one. This is a *result-integrity* failure
   mode, not a connectivity one, and it produces no error. Gate G0 exists for it.

---

## 2. Operational safety of a bump-in-the-wire in front of a protection relay

### 2.1 The two risk classes are not comparable

| | loss of SCADA visibility / telemetry | loss of protection function |
|---|---|---|
| what it means here | master stops seeing measurements, events, and status; remote control unavailable | relay fails to trip, or trips late, for a real fault |
| can the inline device cause it? | **Yes** — trivially. A program load, a port flap, a bad P4 constant, or a switch reboot takes the session down. | **No**, for autonomous protection on an SEL-751 — see §2.2. |
| exposure in this lab | full: this is the only path from master to relay | none, unless §2.3 applies |

### 2.2 Is DNP3 polling protection-critical on an SEL-751? No.

Grounded in the device architecture (device-class knowledge; confirm against the SEL-751 instruction
manual before this appears in a paper — see the UNVERIFIED register in §6):

- The SEL-751 is a feeder protection relay. Its protection and control elements (overcurrent 50/51,
  over/undervoltage 27/59, frequency 81, the arc-flash and motor options, and the SELOGIC control
  equations) execute in the relay's own processor on **locally sampled CT/PT inputs**, at a fixed
  sub-cycle processing interval, and drive **local output contacts**. Nothing in that loop leaves
  the relay chassis.
- **Ethernet is an option card.** DNP3 LAN/WAN is a service offered *by* that card to a remote
  master. It is a consumer of relay data, not a participant in the protection decision.
- Consequently: delay the DNP3 response by 25 ms, delay it by 25 seconds, or drop it entirely, and
  the relay's trip decision is bit-for-bit unchanged. Loss of Ethernet raises communications/self-test
  status (Relay Word bits and SER entries — exact bit names UNVERIFIED), not a protection block.

This is the property that makes the whole defense deployable at all, and it should be stated in the
paper: the mechanism is inserted into a **non-protection-critical** data path by construction.

### 2.3 Where that answer stops being true

Three carve-outs, all of which must be checked once, before insertion:

1. **Communications-assisted protection on the same physical port.** If the relay is configured for
   IEC 61850 GOOSE publishing/subscription, or MIRRORED BITS over Ethernet, or any pilot/teleprotection
   scheme, then that Ethernet port *is* protection-critical and inserting a switch into it is a
   protection-affecting change. Our P4 forwards such traffic transparently (any non-IPv4 ethertype,
   GOOSE 0x88B8 included, falls to `ROLE_BYPASS` at parser line 325), but "forwarded transparently"
   is worthless during a `bf_switchd` restart, when the link is simply down. **Verify no such scheme
   is configured before insertion.**
2. **Remote control.** DNP3 CROB open/close, settings-group change, and remote reset ride the
   master→outstation direction. The mechanism never holds that direction: only DNP3 function 129
   responses from the outstation side are enqueued to the hold queue (P4 lines 406, 755), function 1
   READs are forwarded immediately (line 768–772), and SELECT/OPERATE/DIRECT_OPERATE fall to
   `ROLE_BYPASS` (line 408). **Control latency is unchanged.** But an inline device that is down
   blocks control entirely.
3. **Unsolicited reporting.** Function 130 unsolicited responses are *not* matched by the response
   classifier (`func_code == 129` exactly), so alarms and event reports are forwarded with no added
   delay. Good for safety; note for the paper that it is also an un-normalized timing channel.

### 2.4 The honest availability statement

The *mechanism* fails open: a blocker token that exhausts its pass budget releases the response
rather than black-holing it (`ctr_release_fail_open`, P4 lines 789–792, 809–810), bounded by the
`BUDGET = 2000000` pass count. The *platform* does not fail open — a switch that loses power, reboots,
or reloads a program is a hard break in the wire. In IEC 62443-3-3 terms this is an availability
(SR 7.1/7.2) consideration for any real deployment, and in a NERC CIP environment an inline device in
front of a BES Cyber Asset is itself in scope for CIP-005 (electronic security perimeter) and CIP-010
(configuration change management). None of that binds a bench lab, but the paper's deployment
discussion should say it out loud rather than have a reviewer say it.

### 2.5 What is and is not at risk in this lab, plainly

At risk: the DNP3 session (will drop on every program load); relay manageability over the same port
(telnet/FTP/QuickSet/web — all bypass-forwarded, but all lost while the switch is reloading); the
experiment's validity if a bypass path exists; the relay's own single-session policy, which may hold
a stale half-open session after an abrupt link loss and refuse the next connection until its own
timeout expires (duration UNVERIFIED).

Not at risk: protection elements, trip outputs, relay settings (we never write), the relay's
firmware, and any primary equipment — the bench relay is not protecting a real circuit.

---

## 3. DNP3 and TCP timing tolerance for a hold of G

### 3.1 The budget

Native CLRT for this device, from the repository:

| source | n | median | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|
| 300-poll direct-path campaign (2026-07-23) | 300 | 1.899 ms | 7.426 ms | — | **15.649 ms** |
| timing-final native characterization | 120 | 2.03 ms | — | 11.42 ms | — |
| live re-check after the session fix (2026-07-25) | 8 | 2.93 mean | — | — | 5.07 ms |

Every timer that could react to an added G:

| timer | value | source | ratio to G = 25 ms |
|---|---|---|---|
| relay's own application-confirm wait | not running — captured responses carry **CON = 0**, so no confirm is requested | `SEL751_DIRECT_CONNECTIVITY_REPORT.md` | n/a |
| DNP3 data-link confirm | not running — the exchange uses **unconfirmed user data (link function 4)**; IEEE 1815-2012 deprecates link confirmation over TCP | repo capture decode | n/a |
| master application response timeout (opendnp3 `MasterParams::responseTimeout`) | **5 s** default, `MasterParams.h:41` in `~/Projects/opendnp3-community` | verified in source | **200×** |
| master `taskRetryPeriod` / `taskStartTimeout` | 5 s / 10 s, `MasterParams.h:66,72` | verified in source | 200× / 400× |
| outstation solicited-confirm timeout (opendnp3 reference value; the SEL's own equivalent is a relay setting) | 5 s, `OutstationParams.h:44` | verified in source | 200× |
| outstation select timeout | 10 s, `OutstationParams.h:41` | verified in source | 400× |
| TCP RTO floor, RFC 6298 | round up to **1 s** | RFC 6298 §2.4 | 40× |
| TCP RTO floor, Linux `TCP_RTO_MIN` | **200 ms** | implementation | 8× |
| TCP delayed ACK on the master | up to ~40 ms (Linux) | implementation | contributes, not a limit |
| master poll cadence in our runs | 1 s (1 Hz) | `clrt_experiment.py` | 40× |

**Verdict: a 25 ms added CLRT is safe on a live session, with the nearest hard edge 8× away.** With
TCP timestamps negotiated (data_offset = 8) the relay gets clean RTT samples that now include G, so
its SRTT rises to roughly G + path RTT + the master's delayed-ACK contribution — order 25–65 ms.
That is still below any plausible RTO floor, so no retransmission is triggered; the estimator simply
tracks a slower peer.

### 3.2 Where it starts to matter, in order

Increasing G:

1. **~150–200 ms** — G approaches a 200 ms minimum RTO. The relay begins to retransmit the response
   it believes was lost. **This is the first symptom, and it is a TCP symptom, not a DNP3 one.** On
   the wire you see a duplicate response segment; in the switch you see a second `ROLE_RESP` enqueue
   and a mismatch between `ctr_resp_enq` and the transaction count. If the relay's stack uses the
   RFC 6298 1 s floor instead, this threshold moves to ~1 s.
2. **~1 s** — retransmissions become certain for any stack.
3. **5 s** — the master's `responseTimeout` expires: the task fails, opendnp3 retries after
   `taskRetryPeriod`, the SOE shows a gap. This is the first *DNP3 application-layer* symptom.
4. **≥ 5 s, multi-fragment reads only** — if a response sets CON = 1, the relay waits for the
   master's application CONFIRM, which cannot arrive until after the hold; the relay's own confirm
   timeout (a relay setting; the opendnp3 reference default is 5 s) expires and the fragment is
   retransmitted or the transaction aborted.

Decreasing G:

5. **G below the native CLRT tail** — no protocol symptom at all, and *no protection*. At G = 17 ms
   the observed native maximum (15.649 ms) leaves 1.35 ms of headroom; at G = 25 ms the headroom is
   9.35 ms. This is the direction that actually threatens the result.
6. **G approaching the poll interval** — with a single transaction slot, an overlapping poll disarms
   the deadline early and the held response is released before G. At 1 Hz polling and G ≤ 40 ms this
   is 25× away, but it is why the checklist fixes a minimum poll interval of 20 G.

### 3.3 Recommendation

Run at **G = 25 ms**. Report the 17 ms point only if the in-switch zero-hold counter is exactly 0
across the whole campaign. If the paper needs a G sweep on the live relay, sweep upward
(25/30/40 ms) rather than downward — the upper side is provably quiet, the lower side is where the
claim breaks.

---

## 4. What the relay sees

The hold is applied **downstream of the relay**, to a packet the relay has already transmitted. The
relay's DNP3 application state machine has no visibility into when the master receives it. The one
coupling is TCP.

| relay-side mechanism | affected by a 25 ms hold? | reasoning |
|---|---|---|
| DNP3 application confirm | **No** | Responses carry CON = 0 — no confirm requested, no timer armed. Would only apply to multi-fragment reads, and then at seconds scale. |
| DNP3 data-link confirm | **No** | The session uses unconfirmed user data (link function 4). No link-layer ACK is awaited. |
| TCP retransmission of the response | **No at 25 ms** | The master's ACK returns ~G + RTT + delayed-ACK later, i.e. 25–65 ms. Below any RTO floor (200 ms Linux, 1 s RFC 6298). With RFC 7323 timestamps active the RTT sample is accurate and simply larger. |
| TCP RTT/SRTT estimator | **Yes, benignly** | SRTT and RTTVAR inflate by roughly G. Observable only inside the relay; no wire consequence until G nears the RTO floor. |
| TCP keepalive | **No** | Keepalive probes are ACK segments with 0 or 1 byte of payload; they match neither the pure-ACK arm (`total_len == 20 + 4·doff` exactly) nor the DNP3 gate (`≥ 13 bytes payload`), so they fall to `ROLE_BYPASS` and are forwarded immediately. Timers are seconds-to-minutes. |
| TCP session teardown / setup | **No** | SYN, FIN, and RST are excluded by the flag mask `0x17` on the pure-ACK match, and by `SYN=FIN=RST=0` on the DNP3 match. Handshake and teardown pass transparently. |
| relay DNP3 inactivity/session timeout | **No** | Seconds scale at minimum; the session is continuously active. Exact relay setting UNVERIFIED. |
| relay's view of frame content | **No** | The response is queue-resident and byte-identical on release — 100/100 in the campaign, 30/30 unmatched-zero in the live demo. No CRC recompute, no field edit, no MAC rewrite. |

**Answer: yes, the hold is transparent from the outstation's point of view at G in the tens of
milliseconds.** The only relay-side state that moves is its RTT estimator, and it moves inside a
margin of at least 8×.

Two second-order items worth watching in the pcap rather than assuming away:

- **If a retransmission ever does occur** (from any cause), the retransmitted response is classified
  as a fresh `ROLE_RESP` and enqueued again. If the deadline has already been consumed the copy is
  released promptly, so the master sees a duplicate segment that TCP discards by sequence number —
  harmless at the transport layer, but it perturbs the byte-identity accounting and the
  `resp_enq == resp_release == n_txn` gates. Treat any nonzero retransmit count as a run-invalidating
  event, not a nuisance.
- **A response that arrives with no armed deadline** (second fragment, or a response with no
  preceding qualifying ACK) is still enqueued to the hold queue, but the unarmed sentinel reads as
  already expired, so the blocker reservoir terminates immediately and the frame egresses after the
  loopback hop (order microseconds). It is not stranded. Worst case, if the reservoir somehow never
  drains, the pass budget releases it: 2,000,000 passes at the measured ~408 ns loop RTT is roughly
  0.8 s — under the master's 5 s timeout, by design.

---

## 5. Go/No-Go checklist for the first live inline run

Ordered. **G1 is the most likely failure mode and it must be cleared before anything is cabled to
the relay.** Each gate is a precondition with a pass criterion; a failed gate is a NO-GO, not a
"proceed carefully".

### G1 — Port topology matches the program (MOST LIKELY FAILURE) — NO-GO until proven

- [ ] Confirm the relay-leg dev_port with the switch's own port table (`bfshell` port show / `pm show`),
      not from the front-panel label. **Flag:** on Tofino-1, `dev_port = (pipe << 7) | port` and pipe 0's
      internal port block starts at 64; on the reference SDE port map dev_port 64 is the CPU/PCIe port,
      while on several platforms the extra front-panel SFP cages are wired through that same port block.
      Confirm dev_port 64 is a real external MAC on this chassis, that it is in **pipe 0** (same pipe as
      the dp8 loopback — the recirculation design requires it), and that it does not collide with the
      PCIe packet path. UNVERIFIED here by construction: I cannot query the switch.
- [ ] Set `PORT_HULK = 9w64` in `research/timing_final/p4/dnp3_timing_normalizer.p4` **as a new,
      separately named variant** — the frozen artifact (sha `82f572ce…`) must not be edited in place,
      per the project's freeze rule.
- [ ] Set `DP_HULK="64"` in `research/timing_final/config/lab.env` and restamp `P4_SRC_SHA256`
      (`00_preflight.sh` verifies it). The P4 constant and the control-plane variable are two
      independent places and desync silently.
- [ ] Recompile and confirm the resource fit is unchanged (10/12 ingress stages, 0 egress, 0 TCAM).
- [ ] Confirm the relay-side port is brought up at **1 G** by the switch-side launch/port script and
      that it survives a `bf_switchd` restart. That script lives on the switch
      (`/home/decps/timing_final/launch_tn.sh` and whatever it calls) and is **not in this repo** —
      UNVERIFIED whether it currently knows about dev_port 64.
- Pass criterion: with the program loaded and the relay cabled, the master can ARP and ping
      192.168.10.7, and the switch's `ctr_bypass[1]` (bad-port drops) stays at 0.

### G0 — Proof of path (result-integrity gate)

- [ ] `192.168.10.1` lives on the **dp9-facing** NIC (`enp59s0f0np0`) and on nothing else.
- [ ] `192.168.10.100` and any other relay-subnet address are removed from `eno1`; `eno1` is
      unplugged from the relay segment.
- [ ] Positive proof the traffic traverses the switch: switch ingress counters on the relay-leg
      dev_port increment during a poll, and a deliberate port-disable makes the poll fail.
- Pass criterion: no reachable path from master to relay that bypasses the Tofino.

### G2 — Relay leg is quiet and exclusive

- [ ] The SEL-751 is the **only** device on the TP-Link switch. Anything else on it shares the 1 G
      uplink, enters the pipeline on the relay dev_port, is forwarded straight to the master leg, and
      can contend for the single transaction slot (F5).
- [ ] No IEC 61850 GOOSE / MIRRORED BITS / pilot scheme configured on the relay's Ethernet port
      (§2.3, carve-out 1).

### G3 — Session preconditions (from §1)

- [ ] Master sources from 192.168.10.1; outstation link address **0**; master link address 1; TCP 20000.
- [ ] Master is configured read-only and non-automatic: no startup integrity poll, no unsolicited
      enable/disable, `timeSyncMode = None`, `ignoreRestartIIN = True`, no control, no write.
- [ ] **No auto-retry.** Single-connect transport or a very long `ChannelRetry` minimum — the
      2026-07-23 incident produced 55 reconnects/s off a relay-side close. An inline switch makes a
      retry storm worse, not better.
- [ ] Poll interval ≥ 20 × G (≥ 500 ms at G = 25 ms); one outstanding request at a time.

### G4 — Native re-baseline through the inline path, before any holding

- [ ] Program loaded, relay inline, **blocker reservoir not started** (no tokens). Run n ≥ 100 polls.
- [ ] Confirm: zero TCP retransmissions, zero RSTs, one session, byte-identity of every response,
      and added one-way latency in the microsecond range.
- [ ] Record the native CLRT distribution **through this path** (it now includes the TP-Link's
      store-and-forward and the 100 M relay leg). Resolve F6 — is the response 54 B or 115 B, and does
      the CLRT distribution still match 2026-07-23?
- [ ] Choose G ≥ measured max + 8 ms. Default 25 ms.
- Pass criterion: the inline path is transparent with the mechanism idle. If this stage is not clean,
      holding will not make it cleaner.

### G5 — Mechanism configuration

- [ ] `K = 64` blocker reservoir (below 64 the queue gate opens between arbitration cycles).
- [ ] G set via `p13_guard.py` with tick alignment and control-plane read-back verification.
- [ ] Strict priority confirmed: Q_BLOCK qid 7 `max_priority` set (not just `min_priority` — this was
      the 2026-07-24 root cause), Q_RESP qid 1 low.

### G6 — Instrumentation, given that the relay leg cannot be tapped

- [ ] Master-side capture on Vision (dp9 NIC).
- [ ] **Relay-side ground truth comes from the switch, not a tap**: the unmanaged TP-Link has no SPAN,
      and adding a Tofino mirror session would change the program. Use the in-switch registers the
      program already exposes — `native_clrt_w`, `protection_w`, `ctr_ack_arm`, `ctr_resp_enq`,
      `ctr_resp_release`, `ctr_release_deadline`, `ctr_release_fail_open`.
- [ ] Read the G-selection guard after the run. **`zero_hold` > 0 means protection was silently absent
      for those transactions** — the run is not reportable at that G.

### G7 — Verifier gates (unchanged from the proven campaign)

- [ ] `08_verify.py` mode `hold_resp`: unmatched frames 0, external blocker frames 0,
      `resp_enq == resp_release == n_txn`, `release_fail_open == 0`, `block_term_timeout == 0`,
      reservoir depth ≥ 64.
- [ ] Protected CLRT median within tolerance of G, sd at the 10 µs scale.

### G8 — Abort criteria (stop the run, do not iterate live)

- Any relay-originated FIN or RST mid-campaign.
- Any TCP retransmission.
- `ctr_release_fail_open` > 0.
- `zero_hold` > 0 at the reported G.
- Relay unreachable at the management level for more than one poll interval.

### G9 — Rollback, rehearsed before the run starts

- [ ] Known-good restore: `12_restore.sh` back to `queue_microbench`, verified by
      `restoration_report.txt`.
- [ ] Physical rollback: relay returns to the direct TP-Link path to Vision's `eno1` at
      192.168.10.1, and the session is re-proven with a single read-only poll.
- [ ] Do every program load and TM reconfiguration **before** the DNP3 session is established. Each
      load takes the link down; the relay's single-session policy may hold a stale half-open session
      afterward.

---

## 6. Model, assumptions, and what is not verified

### Model in force

| aspect | assumption |
|---|---|
| grid model | none — this is a communications-path analysis. No power-flow, no protection-element modelling. The relay is a bench unit with no primary equipment. |
| protocol model | DNP3 over TCP (IEEE 1815-2012), single master, single outstation, serialized transactions, unconfirmed link service, single-fragment responses, CON = 0, unsolicited disabled. |
| timing model | per-transaction, snapshot: CLRT = t(response) − t(pure ACK) measured at the switch. Native CLRT is autocorrelated (moving-block bootstrap used in the source campaign), so tail statistics, not means, govern the choice of G. |
| topology model | relay (100 M RJ45) → unmanaged TP-Link → 1 G SFP uplink → Tofino dev_port 64 → P4 pipeline → dp9 → Vision. Two-port transparent bridge with static port pairing, no MAC learning, no VLANs. |
| defense model | hold only outstation→master DNP3 function 129; forward everything else, both directions, unmodified. |

### UNVERIFIED register

| item | status | how to settle it |
|---|---|---|
| dev_port 64 is a front-panel MAC in pipe 0 and not the CPU/PCIe port on this chassis | UNVERIFIED — I could not query the switch | `bfshell` port show / `pm show -a`; platform port-map JSON in the SDE |
| the switch-side launch/port script knows about dev_port 64 at 1 G | UNVERIFIED — that file is on the switch, not in this repo | inspect `/home/decps/timing_final/launch_tn.sh` and its port configuration |
| the relay is currently unreachable *because* of the port-set drop | INFERENCE, matches the symptom | check the bad-port drop counter and the currently bound program name |
| the relay's TCP minimum RTO | UNVERIFIED (assumed ≥ 200 ms) | force a loss on a bench copy, or infer from a retransmit interval if one ever occurs |
| the relay's DNP3 session inactivity timeout and its half-open session hold time | UNVERIFIED | relay settings via QuickSet/console; not needed if G8/G9 are honoured |
| exact SEL-751 Relay Word bit and setting names for comms status and DNP3 confirm timeouts | UNVERIFIED — the only setting name confirmed from the device is `DNPIP1` | SEL-751 instruction manual; `SHO` from the relay console at access level 1 |
| SEL-751 protection processing rate (samples/cycle, elements/cycle) | UNVERIFIED — deliberately not quoted, because the argument in §2.2 does not need it | SEL-751 data sheet, processing specifications |
| whether the relay's response is now 54 B or 115 B, and whether the native CLRT distribution moved | UNVERIFIED — the two dates disagree | gate G4 re-baseline |

### Standards and specifications leaned on

- **IEEE 1815-2012 (DNP3)** — data-link function codes used and observed in our own captures:
  3 confirmed user data / **4 unconfirmed user data** (what this session uses), **9 request link
  status** / **11 link status** (the address scan that found outstation 0); application function
  1 READ, **129 response** (held), **130 unsolicited response** (not held); the application-layer
  confirm and its CON bit, which is 0 in every captured response. Link-layer confirmation is
  deprecated over TCP, consistent with what the relay does.
- **RFC 6298** — TCP RTO computation and the 1 s rounding floor (§2.4); **RFC 7323** — TCP timestamps,
  which this relay negotiates (data_offset = 8) and which make its RTT samples include G.
- **IEC 62443-3-3** — availability requirements for an inline component; the mechanism fails open at
  the packet level, the platform does not.
- **NERC CIP-005 / CIP-010** — an inline device in front of a BES Cyber Asset is in scope for the
  electronic security perimeter and for configuration change management. Not binding in the lab;
  belongs in the paper's deployment discussion.
- **opendnp3 defaults** — verified in source at `~/Projects/opendnp3-community`:
  `MasterParams.h:41` `responseTimeout = 5 s`, `:66` `taskRetryPeriod = 5 s`, `:72`
  `taskStartTimeout = 10 s`; `OutstationParams.h:41` `selectTimeout = 10 s`, `:44/:47`
  solicited/unsolicited confirm timeouts.
