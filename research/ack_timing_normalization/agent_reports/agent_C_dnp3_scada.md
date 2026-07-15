# Agent C — DNP3 / SCADA / Protection-System Timing-Shaping Safety Report

_Scope: which DNP3 transactions may SAFELY tolerate bounded, byte-preserving timing
shaping (hold/delay/pace of already-existing ACK-bearing response packets) and which must
BYPASS it. Evidence-only; no code changed. Grounded on GROUNDING.md, measured_timing_data.md,
the prior brief, the multi-CROB validation doc, and the OpenDNP3 community fork source
(cited file:line). Standards/spec behavior is distinguished from measured/inferred._

---

## 1. Findings first (grid-engineering terms)

1. **The DNP3 timer stack is not the binding constraint — TCP RTO is.** Every application
   and link timer in this deployment is 5–60 s (verified in source, §3). The Linux master's
   TCP retransmit timeout floor (`TCP_RTO_MIN` ≈ 200 ms) fires **two-plus orders of magnitude
   sooner**, and a spurious TCP retransmit is the single loudest tell to both a passive
   fingerprinter and a DNP3/Zeek correctness IDS. **"Stay under the master's measured effective
   RTO" is simultaneously the correctness bound and the stealth bound.** This confirms the
   prior brief and is re-verified against the fork.

2. **There is no link-layer ACK to delay.** OpenDNP3's sole user-data transmit path formats
   `PRI_UNCONFIRMED_USER_DATA`; the confirmed-data formatter is compiled but has **zero
   callers** (§3.3). No `SEC_ACK` secondary confirmation exists on this wire, so the entire
   "delay the link ACK" surface is empty. The manipulable timing surface reduces to exactly
   (a) the TCP-ACK-fused outstation **response**, and (b) the application **CONFIRM** handshake
   for multi-fragment responses.

3. **SELECT/OPERATE tolerate shaping on the RESPONSE side with large margin; the risk is
   cumulative, not per-exchange.** SELECT and OPERATE are two independent request/response
   exchanges. Shaping the SELECT response delays the master's OPERATE request (the master
   waits for the SELECT reply), so the whole SELECT→OPERATE wall-clock must stay under the
   **outstation select timeout = 10 s** (verified default). At ms-scale baselines (measured
   SELECT-resp 1.1–3.9 ms, OPERATE-resp 1.6–4.9 ms) a fixed 10–20 ms normalization deadline
   kills the CROB-count leak with a **~500× margin against the 10 s select timeout** and a
   ~10–20× margin against a 200 ms RTO floor. Safe.

4. **The crown-jewel leak lives on exactly the SELECT/OPERATE responses.** The measured
   CROB-count regression (SELECT-resp 0.179 ms/CROB, R²=0.9985; OPERATE-resp 0.214 ms/CROB,
   R²=0.9954) is a **response-side, outstation→master** signal — the same direction and same
   byte-preserving mechanism as read shaping. So the traffic that carries the most valuable
   leak is also shapeable; the only reason to bypass it is **physical-consequence safety of
   the control action**, which the switch cannot infer from DNP3 fields (Finding 6).

5. **Multi-fragment reads compound through the CONFIRM handshake — schedule the whole logical
   response to a single completion deadline, never per-fragment independently, and never
   touch a CONFIRM.** Delay adds across serialized fragments; each inter-fragment hop must
   still clear RTO; suppressing/synthesizing a CONFIRM breaks flow control and the
   event-buffer flush (§6, Section 7E).

6. **DNP3 fields reveal operation TYPE, not physical CRITICALITY.** Function code, object
   group/variation, point index, and link/IP addresses let a switch tell a control from a
   read, an event poll from an integrity poll, and one outstation from another — but the
   protocol nowhere encodes whether CROB index 5 is a nuisance light or a feeder breaker.
   **An in-network element cannot infer consequence from DNP3 alone; it needs an
   operator-supplied (outstation, function, index)→criticality allowlist** (Section 7F). And
   the highest-consequence real-time traffic — protection tripping — is generally **not on
   this DNP3 wire at all** (§7).

---

## 2. Model and assumptions

| Dimension | This study's setting | Source |
|---|---|---|
| Stack | OpenDNP3 community fork, software outstation on Hulk; software master on Vision | measured_timing_data.md; fork |
| Transport | DNP3-over-TCP, single persistent connection, `TCP_NODELAY` | prior brief; split_server |
| Link service | **Unconfirmed only** (`PRI_UNCONFIRMED_USER_DATA`); no `SEC_ACK` | fork LinkContext.cpp:158 (verified) |
| Unsolicited | **Off** (`allowUnsolicited=false`, `disableUnsolOnStartup=true`) | fork (verified, §3) |
| Balanced/unbalanced | N/A (this is a comms/protocol study, not a power-flow study) | — |
| Snapshot/time-series | Time-series of request→response exchanges; periodic polling + occasional SBO | measured_timing_data.md |
| Shaping lever | Hold/delay/pace of packets that **already exist**; `b"".join(chunks)==original` holds | GROUNDING HARD phase rule |
| Threat model | Passive on-path observer, reads unencrypted DNP3, no inject/block; regresses per-exchange timing to recover device model / DB-size proxy / load | GROUNDING; prior brief §2 |
| Binding constraint | Master effective **TCP RTO** (Linux floor ≈200 ms) — MUST be measured on Vision, not assumed | GROUNDING; prior brief §4.1 |
| Scope caveat | Single device, single rig, single implementation — no cross-device claim | measured_timing_data.md |

**Assumption to flag:** the 200 ms RTO floor is a Linux default (`TCP_RTO_MIN`), not a
universal value. The effective RTO on Vision must be read (`sysctl net.ipv4.tcp_retries2`
and the RTO observed in a capture) before any budget is fixed. All budgets below are stated
as fractions of the *measured* RTO for that reason.

---

## 3. Verified stack facts (OpenDNP3 community fork, cited file:line)

All defaults below were read from the fork this session — these are **implementation-current
verified facts**, not recalled values.

| Timer / parameter | Default | Source (file:line) | Standard vs impl |
|---|---|---|---|
| Outstation **select timeout** | **10 s** | `cpp/lib/include/opendnp3/outstation/OutstationParams.h:41` | impl default of a standard timer |
| Outstation **solicited-confirm timeout** | **5 s** (`DEFAULT_APP_TIMEOUT`) | `OutstationParams.h:44` + `cpp/lib/include/opendnp3/app/AppConstants.h:34` | impl default |
| Outstation unsolicited-confirm timeout | 5 s | `OutstationParams.h:47` | impl default (unsol off) |
| `allowUnsolicited` | **false** | `OutstationParams.h:65` | impl default |
| `maxTxFragSize` | 2048 B (`DEFAULT_MAX_APDU_SIZE`) | `OutstationParams.h:59` + `AppConstants.h:31` | impl default |
| Master **application response timeout** | **5 s** | `cpp/lib/include/opendnp3/master/MasterParams.h:41` | impl default |
| Master `disableUnsolOnStartup` | **true** | `MasterParams.h:47` | impl default |
| Master `taskRetryPeriod` | 5 s | `MasterParams.h:66` | impl default |
| Master `maxTaskRetryPeriod` | 1 min | `MasterParams.h:69` | impl default |
| Master `taskStartTimeout` (non-recurring, e.g. commands) | **10 s** | `MasterParams.h:72` | impl default |
| Link `Timeout` (confirmed service) | 1 s | `cpp/lib/include/opendnp3/link/LinkConfig.h:63` | **not exercised** — unconfirmed only |
| Link `KeepAliveTimeout` | 1 min | `LinkConfig.h:64` | idle-only |

### 3.3 Link layer is unconfirmed-only (no ACK to delay) — verified

- Sole user-data transmit path formats **unconfirmed** frames:
  `FormatPrimaryBufferWithUnconfirmed()` → `LinkFrame::FormatUnconfirmedUserData()` at
  `cpp/lib/src/link/LinkContext.cpp:158`.
- The confirmed-data formatter `LinkFrame::FormatConfirmedUserData()`
  (`cpp/lib/src/link/LinkFrame.cpp:145`) has **no caller anywhere in `cpp/lib/src/`**
  (grep confirmed). `SEC_ACK`/`SEC_NACK` exist only as inbound-parse cases.

**Consequence:** the prior brief's Mechanism table (there is no L2 DNP3 ACK on this wire) is
re-confirmed in source. Nothing at the link layer is available to hold.

---

## 4. The delay budget hierarchy (the safe envelope, quantified)

Ordered from tightest (hit first) to loosest (never reached in practice):

```
effective TCP RTO on master   ≈ 200 ms floor (Linux TCP_RTO_MIN; MEASURE on Vision)   <-- BINDING
   |  overshoot => spurious TCP retransmit = loudest tell to observer AND Zeek dnp3 IDS
master app response timeout    = 5 s   (per fragment / per exchange)
outstation sol-confirm timeout = 5 s   (per CONFIRM wait)
outstation select timeout      = 10 s  (whole SELECT->OPERATE wall-clock)
master taskStartTimeout        = 10 s  (command task must start)
link keepalive                 = 60 s  (idle only)
```

**Engineering rule:** bound *every per-packet hold* AND the *cumulative added latency of a
transaction* below the measured effective RTO (conservatively ≤ ~50 % of it). Do that and no
DNP3 timer is ever approached — the 5–60 s timers are a safety backstop, not the operating
constraint. A fixed **10s-of-ms normalization deadline** (e.g. pad each response to a constant
15–20 ms) destroys the measured ms-scale processing-time leak while keeping 10–100× margin on
every timer and ~10× margin on a 200 ms RTO floor. Current 10 ms/chunk default already sits
~20× under RTO (prior brief §4.2).

---

## 5. Traffic-class → {SHAPE | BYPASS} determination table

Direction "O→M" = outstation→master (response, the byte we generate/hold); "M→O" =
master→outstation (request/confirm, our defense does not originate these).

| Class | FC / object | Dir | Verdict | Reason | Safe per-class budget |
|---|---|---|---|---|---|
| **Integrity / Class-0 READ** | READ `0x01`, g60v1 (static) | O→M | **SHAPE (full normalization / size-decorrelation)** | Primary periodic traffic and the main leak surface; no control semantics; byte-preserving | Per-fragment hold < effective RTO; cumulative < 5 s master response timeout; recommend fixed 15–20 ms completion deadline (kills processing-time regression, ~250× select-timeout margin) |
| **Event READ** | READ `0x01`, g60v2/3/4 (Class 1/2/3), or event object groups (g2/g32 var2) | O→M | **SHAPE but with a TIGHTER bound** | Events carry alarms / SOE; excessive hold defers operator awareness of a real state change | Small fixed bound (≤ a few tens of ms), well under RTO; **never** suppress the CONFIRM that flushes the event buffer; do not let added latency approach any operator alarm-latency SLA |
| **SELECT response** | SELECT `0x03`, g12v1 (CROB) | O→M | **SHAPE (pad to N-independent deadline)** | Carries the measured crown-jewel CROB-count leak (0.179 ms/CROB); shaping it is the whole point; byte-preserving | Fixed N-independent deadline; each exchange < RTO; **SELECT-resp + master turnaround + OPERATE-resp ≪ 10 s select timeout** (recommend cumulative < 1 s, ~10× margin). BYPASS if the SBO targets an operator-flagged critical control |
| **OPERATE response** | OPERATE `0x04`, g12v1 (CROB) | O→M | **SHAPE with tight budget; BYPASS if control is flagged critical** | Carries the CROB-count leak (0.214 ms/CROB) but is the control-completion acknowledgement — command latency and physical-consequence safety dominate privacy | Pad to fixed deadline < RTO; **never** delay a config-flagged critical/protection control; default tight (≤ 20 ms) so command latency is imperceptible for supervisory control |
| **Application CONFIRM** | CONFIRM `0x00` | M→O | **BYPASS** | Master-originated; our defense shapes outstation responses, not master frames. Holding it risks the 5 s outstation sol-confirm timeout; suppressing it stalls multi-fragment reads and the event-buffer flush | Do not shape. If ever held: < outstation solConfirmTimeout (5 s) AND < RTO; never suppress/synthesize |
| **Unsolicited response** | UNSOL_RESP `0x82` | O→M | **BYPASS in this deployment (off by default); if enabled, minimal-shape only** | Spontaneous, event/alarm-driven — the direction most likely to carry urgent state change; latency-sensitive | If enabled: minimal bound, never beyond unsolConfirmTimeout (5 s); treat as event-class urgent |
| **Link-layer ACK** | `SEC_ACK` | — | **N/A** | Does not exist on this wire (unconfirmed link only, §3.3) | — |
| **DIRECT_OPERATE / _NR** | `0x05` / `0x06` | O→M (resp) / M→O | **BYPASS control-side by default** | Direct control without SBO arming; consequence safety dominates; `_NR` has no response to shape anyway | Treat like OPERATE: bypass if flagged critical; never delay control completion |

**Reading of the table for the candidate policy:** apply the `max(response_ready,
request_time + target_delay)` scheduler to the **O→M response classes only**, cap
`target_delay` per class per the budget column, and route SELECT/OPERATE/DIRECT_OPERATE
through an operator-configured criticality allowlist that can force immediate pass-through.
Never apply it to CONFIRM or any M→O frame.

---

## 6. RQ5 (DNP3 side): normalize timing without causing DNP3 timeouts, SELECT→OPERATE failures, or excessive command latency

**(a) Avoiding DNP3 timeouts.** Because every DNP3 timer is 5–60 s and the binding constraint
is the master's TCP RTO (~200 ms floor, measure it), *any* shaping schedule that keeps each
hold and each transaction's cumulative added latency under the measured RTO cannot trip a
DNP3 timer — it trips a TCP retransmit first, and that is the failure to design against. So
the correctness target reduces to a single inequality per released packet:
`hold + queueing < effective_RTO_margin`. The DNP3 5 s app timers are a backstop only.

**(b) Avoiding SELECT→OPERATE failures.** The failure mode is the **10 s outstation select
timeout**: the armed selection expires if OPERATE arrives too late, and the outstation then
rejects OPERATE (per-object status, no execution) rather than firing a stale control. Our
mechanism does not hold the master's OPERATE *request*, but it does hold the SELECT
*response*, and the master will not emit OPERATE until it sees that response. Therefore treat
the SELECT→OPERATE pair as one unit and bound
`(SELECT-resp hold) + (master turnaround) + (OPERATE-resp hold) ≪ 10 s`. With ms-scale
baselines and a fixed 10–20 ms deadline, the added latency is < 1 % of the select timeout —
no risk. The only way to induce a select-timeout is to hold the SELECT response for seconds,
which the RTO rule already forbids.

**(c) Avoiding excessive command latency.** OPERATE completion latency is what an operator
(or an automated control loop) feels. For human supervisory control, ms-scale added latency
is imperceptible; for a fast automated control loop it may not be. Because DNP3 fields cannot
identify a safety-critical control (Section 7F) and **safety dominates privacy** (GROUNDING),
the conservative default is: give OPERATE/DIRECT_OPERATE a **tight** budget and let an
operator allowlist force immediate pass-through for flagged controls. The privacy cost of
bypassing control traffic is small — control operations are infrequent and bursty, so a
passive attacker gets few CROB-count samples to regress; the periodic READ processing-time
leak (continuously sampled) is the higher-value target and is fully shapeable at zero safety
cost. **Recommended posture: fully shape the read plane; shape SELECT/OPERATE responses only
to a fixed small N-independent deadline under an allowlist; bypass anything flagged critical.**

Standards context: IEEE 1815 (DNP3) is a supervisory application/protocol standard and
imposes **no minimum-latency or real-time delivery guarantee** — there is no spec clause a
bounded, sub-RTO hold violates. The shaping element is a transparent latency element, the
same compliance posture as the existing CRC-boundary splitter.

---

## 7. Section 7E: multi-fragment response handling policy

DNP3 multi-fragment responses are **serialized by the application CONFIRM handshake**: the
outstation sets the CON bit in the application control octet, the master must return an
application CONFIRM (FC `0x00`) before the outstation transmits the next fragment, and (for
event data) the CONFIRM is also the signal that lets the outstation flush those events from
its buffer. Consequences for shaping:

1. **Delay compounds; it is a cumulative deadline, not per-fragment independent.** For an
   n-fragment response the total added latency is the sum of per-fragment holds plus n
   normalized inter-fragment gaps. Budget the **whole logical response to a single completion
   deadline D** and pace fragments to land by D, rather than adding an independent delay to
   each fragment. Size-decorrelation should target the response *completion time*, since that
   is what a passive observer regresses.
2. **Each per-fragment hop must still clear RTO.** The master's 5 s response timeout resets
   per fragment (time-to-next-fragment), so a single 5 s cap is not the binding limit — but
   every inter-fragment hop that overshoots RTO produces a TCP retransmit. So the per-hop rule
   is unchanged: each fragment's release < effective RTO. `D_max` per fragment ≈ RTO margin;
   practical target = a fixed small gap (tens of ms) that also **normalizes the inter-fragment
   regeneration-time fingerprint** (a real leak per prior brief §2).
3. **Never suppress or synthesize a CONFIRM.** Suppressing the master→outstation CONFIRM stalls
   the read (outstation aborts to Idle at the 5 s sol-confirm timeout, **no retransmit**;
   events stay buffered, reported next poll — not lost, but the read fails). Synthesizing a
   CONFIRM makes the middlebox an unauthorized DNP3 speaker and desynchronizes sequence
   numbers. Both leave the byte-preserving regime — out of scope this phase.
4. **Do not shape the CONFIRM itself.** It is M→O; leave it untouched (table §5).
5. **Fragment count is itself a size fingerprint** (∝ point count via `maxTxFragSize` = 2048 B).
   Timing shaping cannot hide it — that is the CRC-splitting primitive's job. Keep the two
   primitives composable: define the timing schedule over whatever frames splitting produces.

**Policy statement:** compute one completion deadline D for the whole logical response; pace
fragments to arrive by D with a fixed normalized inter-fragment gap; hold each hop < effective
RTO; leave every CONFIRM verbatim and un-shaped; assert `b"".join(chunks)==original` before
release.

---

## 8. Section 7F: identifying urgent/critical traffic from DNP3 fields (and the hard caveat)

What a switch **can** read from unencrypted DNP3:

| Field | Signal it gives | Example |
|---|---|---|
| **Application function code** | Operation type | CONFIRM `0x00`, READ `0x01`, WRITE `0x02`, SELECT `0x03`, OPERATE `0x04`, DIRECT_OPERATE `0x05`/`0x06`, RESPONSE `0x81`, UNSOLICITED_RESPONSE `0x82` (standard-defined, IEEE 1815) |
| **Object group / variation** | Data class & semantics | g12v1 = CROB (control); g60v1/v2/v3/v4 = Class 0/1/2/3 (integrity vs event poll); g1/g2 = binary input static/event; g30/g32 = analog input static/event; g20/g21 = counters. A READ for Class 1 (g60v2) implies an event/alarm poll (more urgent) vs Class 0 (g60v1) integrity |
| **Qualifier + point index** | Which point(s) | CROB to index 5; range/count qualifier — but index→consequence is site config |
| **Link addresses + IP 5-tuple** | Which master/outstation pair | Prioritize a specific outstation *if* configured |
| **UNSOL vs solicited** | Spontaneity | Unsolicited (`0x82`) is device-initiated, usually alarm-driven → most likely urgent |

**The hard caveat (state it loudly in the paper).** These fields encode the **type** of a
transaction, never its **physical criticality**. DNP3 does not carry a "this control trips a
115 kV breaker" bit. A CROB to index 5 is indistinguishable at the protocol layer from a CROB
to index 6 whether one toggles a status LED and the other opens a feeder. **Therefore an
in-network switch/middlebox cannot infer physical criticality from DNP3 fields alone; it
requires an operator-supplied configuration/allowlist mapping (outstation address, function
code, object group, point index) → criticality/priority.** The defense should ship with a
default-conservative allowlist (all control function codes → bypass unless explicitly
whitelisted for shaping) so the failure mode is "shaped less than possible," never "delayed a
critical control."

**Protection scoping (verify-and-scope, per task).** The highest-consequence real-time OT
traffic — protection tripping — is generally **not carried by DNP3 at all**. DNP3 (IEEE 1815)
is a supervisory SCADA protocol with **no minimum-latency requirement**. Sub-cycle protection
(bus/line/transformer trips, on the order of a quarter cycle, ≈ 4–5 ms at 50/60 Hz) is carried
by **hardwired trip circuits or IEC 61850 GOOSE**, whose performance classes P2/P3 target a
trip transfer time on the order of **3 ms** (IEC 61850-5; the specific figure is from the
performance-class literature, not read from the standard text here). So a shaping element on a
DNP3 supervisory link is architecturally *upstream* of the protection path and will not sit in
a sub-cycle trip loop under a correct substation design. **Do not** claim a specific relay
(e.g., SEL-751A) latency capability — no vendor doc was consulted, and none should be asserted.
The residual risk is a **misengineered** site that carries an automated control through DNP3
OPERATE with a tight loop deadline; the operator allowlist (bypass) is the mitigation.

---

## 9. Citation tiering summary

- **Tier 1 (verified, directly on-target, peer-reviewed):** 3 — Formby et al. NDSS 2016
  (CLRT response-time device fingerprinting on read/response ICS protocols incl. DNP3 — the
  attack our defense counters); Lin, Kalbarczyk, Iyer, RAINCOAT, IEEE TSG (the differentiation
  anchor; advisor = Hui Lin); Xiang & Han, TIDF, NPC 2025 (timing/processing-time device
  fingerprinting for PLCs — corroborates the processing-time leak on ICS hardware,
  **metadata/abstract-level read only**).
- **Tier 2 (verified, supporting):** 2 — Lin et al., "Adapting Bro into SCADA" CSIIRW 2013
  (specification-based DNP3 IDS — evidence a correctness IDS validates DNP3 semantics/CRCs and
  passes timing-only manipulation while flagging malformed frames); Barbosa, Sadre, Pras, PAM
  2012 (SCADA traffic is periodic/predictable — why supervisory latency tolerates a bounded
  fixed pad and why timing is a stable observable).
- **Tier 3 (verified metadata, preprint):** 1 — Jeon et al. 2016, passive SCADA fingerprinting
  (arXiv 1608.07679; no peer-reviewed venue confirmed → labeled preprint).
- **Tier 4 (standards, metadata-level):** 2 — IEEE 1815-2012 (DNP3: function codes, SBO, app
  confirm, no min-latency requirement); IEC 61850-5 (protection message performance classes —
  cited for the protection-not-DNP3 scoping, **not read; figure from secondary literature**).

**Single most important caveat:** the crown-jewel CROB-count leak sits on the SELECT/OPERATE
control responses, so killing it means shaping control-side responses — which is safe on the
*response* timing (huge timer margin) but must be gated by an operator criticality allowlist
because DNP3 fields cannot certify that a given control is not safety-critical, and the switch
must never delay a critical control to buy privacy.

---

## PAPER_MATRIX_ROWS
Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems | David Formby, Preethi Srinivasan, Andrew M. Leonard, Jonathan D. Rogers, Raheem A. Beyah | 2016 | NDSS (Network and Distributed System Security Symposium) | NA | https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf | yes | 1 | ICS/DNP3 & Modbus read-response traffic | passive on-path fingerprinter (identify device type) | CLRT (Cross-Layer Response Time) device-type fingerprinting; also physical operation-time fingerprinting | NA (attack, not defense) | sw + testbed | commodity ICS devices + lab | classification accuracy of device type | NA | response-time distribution is a stable device-type fingerprint on read/response ICS protocols; only needs read/response messages | requires read/response protocol; device-type granularity | establishes that the exact request->response timing we normalize IS a fielded device fingerprint (the attack we defeat) | high
RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers | Hui Lin, Zbigniew T. Kalbarczyk, Ravishankar K. Iyer | 2019 | IEEE Transactions on Smart Grid, vol. 10, no. 5, pp. 4893-4906 | 10.1109/TSG.2018.2870362 | https://ieeexplore.ieee.org/document/8466028 | yes | 1 | power-grid control-center data acquisition (DNP3/SCADA) | reconnaissance attacker preparing FDIA; RAINCOAT misdirects | randomize acquisition/communication schedule to mislead about grid state | randomization (add entropy/misdirection) | sw + simulation | IEEE bus-system simulation | attacker uncertainty / attack window | comms overhead | randomizing data-acquisition schedule increases attacker uncertainty and shrinks the attack window | endpoint-cooperating; defends grid-content not device identity | THE differentiation anchor: our work normalizes (indistinguishability, device-identity) vs RAINCOAT randomizes (misdirection, grid-content); advisor is an author | high
TIDF: Timing-Based Device Fingerprinting for PLCs | L. Xiang, H. Han | 2025 | IFIP Int'l Conf. on Network and Parallel Computing (NPC 2025), Springer LNCS | 10.1007/978-3-032-10466-3_11 | https://link.springer.com/chapter/10.1007/978-3-032-10466-3_11 | yes | 1 | ICS/PLC network traffic | detect unauthorized/spoofed PLC via timing | fingerprint via communication processing time + clock-pulse period (DBSCAN + OCSVM) | NA (detection) | sw + testbed | 13 real PLCs (Siemens, Xinje) | classification accuracy / robustness to forgery | low overhead (claimed) | communication processing time is a discriminative PLC fingerprint; robust to basic forgery | metadata/abstract only; PLC-scope; single testbed | corroborates that processing-time (our leaked quantity) fingerprints ICS hardware, on real PLCs not just software | med
Adapting Bro into SCADA: Building a Specification-based Intrusion Detection System for the DNP3 Protocol | Hui Lin, Adam Slagell, Catello Di Martino, Zbigniew Kalbarczyk, Ravishankar K. Iyer | 2013 | 8th Annual Cyber Security and Information Intelligence Research Workshop (CSIIRW '13), ACM | NA | https://www.semanticscholar.org/paper/03fb870d3a721719d7a8f3b664ac05ca3e9568c0 | yes | 2 | DNP3 SCADA traffic | malformed/semantically-invalid DNP3 (correctness IDS) | specification-based DNP3 parser + protocol-validation policy in Bro/Zeek | NA (detection) | sw + testbed | DNP3 network traces | detection of spec violations | NA | a spec/correctness IDS validates DNP3 semantics and CRCs and sees a well-formed session | correctness-focused; not a timing-side-channel detector | evidence a Zeek dnp3 correctness IDS is blind to byte-preserving timing-only shaping but flags malformed frames / TCP anomalies | high
Difficulties in Modeling SCADA Traffic: A Comparative Analysis | Rafael Ramos Regis Barbosa, Ramin Sadre, Aiko Pras | 2012 | Passive and Active Measurement (PAM 2012), Springer LNCS 7192, pp. 126-135 | 10.1007/978-3-642-28537-0_13 | https://link.springer.com/chapter/10.1007/978-3-642-28537-0_13 | yes | 2 | SCADA network traffic | NA (measurement study) | NA | NA | measurement | real SCADA network traces | traffic-model fit | NA | SCADA traffic is dominated by periodic polling, lacks diurnal/self-similar structure; differs from IT traffic | descriptive; specific sites | supports that supervisory polling is periodic/predictable, so a bounded fixed pad is tolerable and timing is a stable observable | med
Passive Fingerprinting of SCADA in Critical Infrastructure Network without Deep Packet Inspection | Sungho Jeon, Jeong-Han Yun, Seungoh Choi, Woo-Nyon Kim | 2016 | arXiv preprint arXiv:1608.07679 | 10.48550/arXiv.1608.07679 | https://arxiv.org/abs/1608.07679 | preprint | 3 | SCADA network traffic | passive fingerprinter without DPI | identify SCADA ports/field-devices/masters from intrinsic traffic characteristics | NA (attack) | sw + testbed | ~1.5 months real CI traces | F-score of SCADA identification | NA | passive fingerprinting identifies SCADA roles at F-score ~1 without DPI | preprint, no peer-reviewed venue confirmed; role-granularity | shows passive fingerprinting of SCADA is practical without payload inspection, motivating timing-side defenses | med
IEEE Standard for Electric Power Systems Communications-Distributed Network Protocol (DNP3) | IEEE Power and Energy Society | 2012 | IEEE Std 1815-2012 | 10.1109/IEEESTD.2012.6327578 | https://ieeexplore.ieee.org/document/6327578 | yes | 4 | DNP3 | NA (standard) | NA (defines function codes, SBO, app confirm, timers) | NA | standard | NA | NA | NA | defines SELECT/OPERATE (SBO), application CONFIRM, function codes; no minimum-latency/real-time requirement | not read in full this session (metadata + secondary sources); function-code hex values are frozen standard facts | authoritative source for SBO semantics, app-confirm handshake, and the no-min-latency scoping | high
Communication networks and systems for power utility automation - Part 5: Communication requirements for functions and device models | IEC | 2013 | IEC 61850-5:2013 | NA | https://webstore.iec.ch/publication/6012 | yes | 4 | IEC 61850 substation automation | NA (standard) | NA (defines message performance classes) | NA | standard | NA | NA | NA | protection trip messages fall in fast performance classes (P2/P3, ~quarter-cycle / ~3 ms); protection is not DNP3-carried | not read this session; 3 ms figure is from secondary literature, not the standard text | scopes protection out of the DNP3 timing budget (sub-cycle, GOOSE/hardwired, not DNP3) | med

## BIBTEX
```bibtex
@inproceedings{formby2016whos,
  title     = {Who's in Control of Your Control System? Device Fingerprinting for Cyber-Physical Systems},
  author    = {Formby, David and Srinivasan, Preethi and Leonard, Andrew M. and Rogers, Jonathan D. and Beyah, Raheem A.},
  booktitle = {Proceedings of the Network and Distributed System Security Symposium (NDSS)},
  year      = {2016},
  note      = {No DOI; stable PDF via Internet Society},
  url       = {https://www.ndss-symposium.org/wp-content/uploads/2017/09/who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf}
}

@article{lin2019raincoat,
  title   = {RAINCOAT: Randomization of Network Communication in Power Grid Cyber Infrastructure to Mislead Attackers},
  author  = {Lin, Hui and Kalbarczyk, Zbigniew T. and Iyer, Ravishankar K.},
  journal = {IEEE Transactions on Smart Grid},
  volume  = {10},
  number  = {5},
  pages   = {4893--4906},
  year    = {2019},
  doi     = {10.1109/TSG.2018.2870362},
  url     = {https://ieeexplore.ieee.org/document/8466028},
  note    = {IEEE Xplore document 8466028; early access 2018. Volume/issue/pages verified against secondary sources.}
}

@inproceedings{xiang2025tidf,
  title     = {TIDF: Timing-Based Device Fingerprinting for PLCs},
  author    = {Xiang, L. and Han, H.},
  booktitle = {IFIP International Conference on Network and Parallel Computing (NPC 2025)},
  series    = {Lecture Notes in Computer Science},
  publisher = {Springer},
  year      = {2025},
  doi       = {10.1007/978-3-032-10466-3_11},
  url       = {https://link.springer.com/chapter/10.1007/978-3-032-10466-3_11},
  note      = {Metadata/abstract verified only; full text not read this session}
}

@inproceedings{lin2013adapting,
  title     = {Adapting Bro into SCADA: Building a Specification-based Intrusion Detection System for the DNP3 Protocol},
  author    = {Lin, Hui and Slagell, Adam and Di Martino, Catello and Kalbarczyk, Zbigniew and Iyer, Ravishankar K.},
  booktitle = {Proceedings of the 8th Annual Cyber Security and Information Intelligence Research Workshop (CSIIRW '13)},
  publisher = {ACM},
  year      = {2013},
  note      = {DOI not verified; metadata verified via dblp/Semantic Scholar; ACM DL entry},
  url       = {https://www.semanticscholar.org/paper/03fb870d3a721719d7a8f3b664ac05ca3e9568c0}
}

@inproceedings{barbosa2012difficulties,
  title     = {Difficulties in Modeling SCADA Traffic: A Comparative Analysis},
  author    = {Barbosa, Rafael Ramos Regis and Sadre, Ramin and Pras, Aiko},
  booktitle = {Passive and Active Measurement (PAM 2012)},
  series    = {Lecture Notes in Computer Science},
  volume    = {7192},
  pages     = {126--135},
  publisher = {Springer},
  year      = {2012},
  doi       = {10.1007/978-3-642-28537-0_13},
  url       = {https://link.springer.com/chapter/10.1007/978-3-642-28537-0_13}
}

@article{jeon2016passive,
  title   = {Passive Fingerprinting of SCADA in Critical Infrastructure Network without Deep Packet Inspection},
  author  = {Jeon, Sungho and Yun, Jeong-Han and Choi, Seungoh and Kim, Woo-Nyon},
  journal = {arXiv preprint arXiv:1608.07679},
  year    = {2016},
  doi     = {10.48550/arXiv.1608.07679},
  url     = {https://arxiv.org/abs/1608.07679},
  note    = {Preprint; no peer-reviewed venue confirmed}
}

@standard{ieee2012dnp3,
  title        = {IEEE Standard for Electric Power Systems Communications--Distributed Network Protocol (DNP3)},
  author       = {{IEEE Power and Energy Society}},
  organization = {IEEE},
  number       = {IEEE Std 1815-2012},
  year         = {2012},
  doi          = {10.1109/IEEESTD.2012.6327578},
  url          = {https://ieeexplore.ieee.org/document/6327578},
  note         = {Not read in full this session; function-code and SBO semantics are frozen standard facts}
}

@standard{iec2013part5,
  title        = {Communication networks and systems for power utility automation -- Part 5: Communication requirements for functions and device models},
  author       = {{IEC}},
  organization = {International Electrotechnical Commission},
  number       = {IEC 61850-5:2013},
  year         = {2013},
  url          = {https://webstore.iec.ch/publication/6012},
  note         = {Not read this session; performance-class trip-time figures from secondary literature}
}
```
