# DNP3 Protocol Correctness and Relay Safety Review — Size Obfuscation Mechanisms

**Workstream:** Size + Timing Co-Residency Committee — protocol/safety seat
**Author role:** power-systems / ICS-OT protocol reviewer
**Date:** 2026-08-10 · **Mode:** reading and analysis only — no switch, no relay, no hardware
**Scope:** the two size mechanisms in `CHARTER.md:16-19` — (a) CROB padding to unwired output points, (b) CRC-boundary splitting of large READ responses.

Evidence is cited `file:line` for repo claims and by clause/topic for IEEE 1815-2012 (DNP3). Byte figures marked "(measured this session)" come from scapy analysis of the repo PCAPs run during this review; SEL-751 firmware-specific behavior I cannot read off the wire is marked **UNVERIFIED** with the test that would settle it.

---

## BOTTOM LINE UP FRONT

1. **CROB semantics are predictable enough to be padding — but padding in the wrong direction and the wrong object class.** A CROB exchange is small and fixed-size (measured: 1 CROB = 35 B request → 37 B response; each added CROB = +13 application bytes, linear). The response an adversary fingerprints is the *outstation→master READ response* (134 B on the physical relay). A 37 B `g12v1` control echo does not blend with a 134 B `g30` READ response — different size, different object group, different function code. As a size-masking source CROB is weak.

2. **"Electrically inert" is NOT a safety argument. Reject it.** On an SEL-751 a CROB to a mapped-but-unwired output still *succeeds at the logic layer*: it sets a Remote Bit / latch, mutates relay state, and writes a Sequential-Events-Recorder (SER) entry. Electrical inertness is a property of the *wiring today*; the command still lands on the protection element's control path, pollutes the event record, and is one setting change or one rewire away from moving a breaker. This is not a hedge — it is a hard no for the physical relay.

3. **The standing rule conflict is real for the physical relay and must be escalated; it is already resolved for the simulated one.** `CLAUDE.md:41` ("Physical SEL-751 stays READ-only") and the governing spec `CLAUDE.md:82` ("No control commands") are safety rules, not scope preferences. Issuing CROBs to a *simulated* outstation is already sanctioned and done (`dnp3_multicrob_harness`, `multi_crob_validation.md:24-26`) — no conflict. Issuing CROBs to the *physical* SEL-751, or having the P4 data plane synthesize CROBs, violates both rules and cannot be waived by the "unwired" claim.

4. **The single most valuable result: you do not need a control command to make outstation traffic of controllable size.** A larger READ (bigger range / more classes / more points) grows the response linearly — measured ~5.7 B per analog point (`baseline_segmentation.md:53-55`), no control, no state change, fully in-spec. That is the correct chaff source. Full ranking in §4.

5. **CRC-boundary splitting is correct for master reassembly — because at the DNP3 layer it changes nothing.** TCP is a byte stream; the master reassembles regardless of where you cut. The CRC-boundary constraint buys the *no-DNP3-byte-modified* invariant and a DNP3-block-clean wire picture, not master correctness per se. The real correctness surface is at TCP/L3 (sequence numbers, checksums, retransmission), not DNP3. Failure modes in §5.

6. **Even with both mechanisms perfect, a passive observer still recovers the relay's DNP3 fingerprint** from poll cadence, class structure, function-code sequence, IIN bits, CONFIRM behavior, and the Case-A separate-ACK timing signature. Size/segmentation obfuscation does not touch any of these. Details in §6.

---

## 1. CROB protocol semantics on the wire (measured)

**What a CROB is.** Control Relay Output Block = DNP3 **Group 12 Variation 1**, an application-layer *object*, not a function code (`multi_crob_validation.md:11-14`). It carries: control code (1 B), count (1 B), on-time (4 B), off-time (4 B), status (1 B) = **11 B object body** per IEEE 1815-2012 §11 (object library, g12v1). With qualifier `0x28` (2-byte count, 2-byte index prefix) each point adds a 2-byte index prefix → **13 B per CROB point** in the application layer.

**Three ways to deliver it (IEEE 1815 application function codes):**

| Mode | Function codes | Frames on the wire | Response? |
|---|---|---|---|
| Select-Before-Operate (SBO) | SELECT `0x03` then OPERATE `0x04` | 4 (SELECT req, SELECT resp, OPERATE req, OPERATE resp) | yes, two responses |
| Direct Operate | DIRECT_OPERATE `0x05` | 2 (req, resp) | yes, one response |
| Direct Operate, no response | DIRECT_OPERATE_NR `0x06` | 1 (req only) | **no response** |

SBO is the safety-critical form (the SELECT arms, the OPERATE fires, an unmatched OPERATE returns `NO_SELECT`); Direct Operate is single-phase; `0x06` is fire-and-forget with no reply (chipkin DNP3 control guide; IEEE 1815 §... control function codes).

**Measured sizes (this session, from the repo captures):**

| Exchange | Object count | Request wire / LEN | Response wire / LEN | Source |
|---|---|---|---|---|
| SBO SELECT / OPERATE | 1 CROB | 35 B / 26 | 37 B / 28 | `multi_crob_test_a.pcap` (measured) |
| SBO SELECT / OPERATE | 2 CROB | 50 B / 39 | 52 B / 41 | `multi_crob_sbo_test_c.pcap` (measured) |
| **DIRECT_OPERATE** (`0x05`) | 1 CROB | **35 B / 26** | **37 B / 28** | `Traffic Trace/SEL751.pcap` (measured) |

**Per-CROB increment: +13 application (LEN) bytes, +13-15 wire bytes** (the extra 0-2 wire bytes appear when the added object pushes the user data across a 16-byte block boundary and forces one more 2-byte block CRC). Response size as a function of object count N: application `LEN ≈ 15 + 13·N`. **This is as controllable and linear as the READ-size lever** (analog reads grow ~5.7 B/point, `baseline_segmentation.md:53`).

**What an unwired point returns — the status field (IEEE 1815 command status enumeration, mirrored in opendnp3 `CommandStatus`):**

`0 SUCCESS · 1 TIMEOUT · 2 NO_SELECT · 3 FORMAT_ERROR · 4 NOT_SUPPORTED · 5 ALREADY_ACTIVE · 6 HARDWARE_ERROR · 7 LOCAL · 8 TOO_MANY_OPS · 9 NOT_AUTHORIZED · 10 AUTOMATION_INHIBIT · 11 PROCESSING_LIMITED · 12 OUT_OF_RANGE · 13 DOWNSTREAM_LOCAL · 14 ALREADY_COMPLETE · 15 BLOCKED · 16 CANCELLED · 17 BLOCKED_BY_OTHER_MASTER · 18 DOWNSTREAM_FAIL · 19 NON_PARTICIPATING`.

Which one an "unwired" SEL-751 point returns is the crux for §2, and it is **not one answer** — it depends on whether the DNP3 index is *unmapped* or *mapped to an unwired output*:

- **Unmapped index** → `OUT_OF_RANGE (12)` or `NOT_SUPPORTED (4)`. The demonstrated harness reproduces this: index 99 rejected `OUT_OF_RANGE`, no OPERATE ran (`multi_crob_validation.md:129`, `multi_crob_sbo_results.md:36`). This is inert *and* rejected — but then the command does nothing and the "padding" is a rejection echo.
- **Mapped index, output contact not physically wired** → `SUCCESS (0)`. The relay sets the Remote Bit / latch, the logic state changes, an SER event is written — the contact simply drives nothing downstream. **This is the dangerous case and the one "electrically inert" actually describes.**

**Predictability verdict:** response size is predictable and dial-able (linear in N). **But** the response is a 37-B `g12v1` control echo — it does not resemble the 134-B `g30` READ response it is supposed to mask (§0 point 1). CROB gives you *volume*, not *size-distribution cover* for the READ fingerprint.

---

## 2. Is "electrically inert" actually safe? — VERDICT: NO for the physical relay

A CROB is a control command to a protection relay. Electrical inertness of a point *today* does not remove the following, every one of which is a real operational hazard:

**(a) The command succeeds in relay logic.** On SEL relays, DNP3 binary-output/CROB indices map to Remote Bits (RBnn) or Relay Word bits used in control (SELOGIC) equations (SEL-751 datasheet: "operate remote bits and I/O"; DNP3 map exposes "Relay Word bits, contact I/O, ... setting group selection"). A `LATCH_ON` to a mapped-but-unwired index still asserts the bit. If that bit later appears in *any* SELOGIC equation — trip, close, group change, breaker-failure arm — the "inert" point is now live. Inertness is a wiring accident, not a protocol guarantee. **UNVERIFIED (SEL-specific):** exact map of which indices are mapped to RBs on Philip's unit — settles by exporting the relay's AcSELerator settings and DNP3 map, read-only.

**(b) SER / event-log pollution.** SEL relays record control operations and RB assertions in the **Sequential Events Recorder (SER)**. Every chaff CROB that succeeds writes an SER row. A protection relay's SER is legal-grade evidence for post-event fault analysis and disturbance review; injecting thousands of decoy control events **corrupts the forensic record** an engineer relies on after a real fault. This alone would fail a NERC CIP disturbance-analysis expectation and any utility's relay-maintenance practice. **UNVERIFIED (SEL-specific):** whether an unwired-but-mapped CROB writes SER on this firmware — settles by issuing one SBO to a known unwired index on a *bench* relay and reading `SER` at the console.

**(c) DNP3 event-buffer pressure and IIN side effects.** Each successful control generates a binary-output-status change → a Class 1/2 **event** in the outstation's event buffer. A flood of chaff controls can fill the event buffer; when it overflows the outstation sets **IIN2.3 (EVENT_BUFFER_OVERFLOW)** and begins discarding events. That IIN bit is visible to the real master and to any observer — it is a *new* fingerprint, and it means real events can be lost. Chaff meant to hide the device instead lights up an alarm bit.

**(d) Sequence-number and application-state coupling.** Controls advance the application sequence and (for SBO) create SELECT arm-state with a timeout. Interleaving chaff SELECT/OPERATE with the real master's transactions on the same session risks `NO_SELECT`/timeout races and sequence confusion with the legitimate master's polling. On separate sessions it needs a second DNP3 master identity to the relay — which the relay's master-allowlist will reject (the physical unit already enforces an allowlist: `SEL751_DIRECT_CONNECTIVITY_REPORT.md:8-12`).

**(e) Rewire / remap risk over the relay's service life.** A relay lives 15-20 years. Panels get rewired, points get remapped, firmware gets upgraded. A design whose safety rests on "index k is unwired" is a latent hazard: the day someone lands a wire on that output or maps the RB into a trip equation, the accumulated chaff traffic becomes live control. Protection engineering does not accept "safe because currently disconnected."

**(f) Downstream historian / operator pollution.** The real master and any SCADA historian subscribed to that outstation will log the binary-output-status changes as genuine control operations. Operators see spurious "output operated" events; the historian's control audit trail is falsified.

**Would a utility accept this?** No. A design that issues control commands to a protection relay to generate cover traffic is a non-starter under **NERC CIP** (unaudited control origin, corrupted SER/BES-cyber-system logging), **IEC 62443** (violates least-function / integrity of the safety-instrumented control path), and basic protection practice. The moment the *switch* (P4 data plane) is the thing emitting CROBs, you have created an **unauthenticated in-network control-injection device sitting in front of a protection relay** — that is the exact threat these standards exist to prevent, now built on purpose.

---

## 3. The standing-rule conflict — plain statement

**The rules.** `CLAUDE.md:41`: "Physical SEL-751 stays READ-only." `CLAUDE.md:82`: governing spec "No CRC recompute. No DNP3 field/length modification. No random padding. No P4. No proxy/MITM. **No control commands.**" The split line is explicitly control-free (`CLAUDE.md:97-98`, `split_server.py:96-99`).

**Is it safety or scope?** `CLAUDE.md:41` is a **safety rule** — it protects a physical protection relay. It is not a stylistic scope boundary. `CLAUDE.md:82`'s "no control commands" is a **phase rule** for the obfuscation line that can be advanced to a next phase *by Philip explicitly* — but only along a path that never puts a control on the physical relay or into the data plane.

**Therefore:**

- **Simulated / emulated outstation — NO conflict, already allowed and done.** The multi-CROB line issues SELECT/OPERATE against in-memory simulated points with no GPIO/breaker/relay behind any index (`multi_crob_validation.md:24-26`), in a *separate* harness that "deliberately issues controls" (`CLAUDE.md:99-101`). CROB-padding research belongs here. Proceed on the simulator without escalation.

- **Physical SEL-751 — GENUINE SAFETY CONFLICT, escalate.** Any CROB to the physical relay violates `CLAUDE.md:41`. The "unwired point" argument does not clear it (§2). This requires Philip's explicit, on-the-record authorization; it is not a choice a committee member or the data plane may make.

- **P4 data plane emitting CROBs — categorical no, independent of the relay.** A switch that synthesizes control commands is a control-injection appliance (§2 closing). Keep the size axis to *segmentation of existing bytes* and *chaff that is not a control*.

**If Philip elects to revise the phase rule, the minimum conditions are:**

1. **Simulated/emulated outstation only** for all CROB-size experiments (default path). No physical-relay CROBs at all.
2. If a physical control path is ever required, use a **dedicated non-production bench relay**, physically isolated from any energized primary plant, with (a) output contacts confirmed unwired by *terminal-block inspection*, (b) DNP3 map exported and the target index confirmed **not** present in any SELOGIC trip/close/group equation, (c) SER monitored throughout, (d) **SBO only, never DIRECT_OPERATE**, with an abort between SELECT and OPERATE, (e) written authorization naming the relay, the index, and the window.
3. **The production SEL-751 stays READ-only, full stop** — no revision proposed here touches `CLAUDE.md:41` for the production unit.
4. **The obfuscation data plane never originates a control** — chaff must come from §4 non-control mechanisms.

---

## 4. Alternatives to CROB as a padding source — RANKED (the key deliverable)

Goal restated in grid terms: make the **outstation→master response stream** size-uninformative *without issuing a control command and without changing relay state*. Scored on four axes plus SEL-751 support. "Direction" matters: the fingerprinted quantity is the response (outstation→master); request-direction chaff does not mask it.

| # | Mechanism | Size controllability | Protocol legality | Operational harmlessness | SEL-751 support | Verdict |
|---|---|---|---|---|---|---|
| **1** | **Larger / ranged READ of static data** (Class 0, or `g30`/`g1` over a wider index range) | **High** — linear, ~5.7 B/analog point, measured (`baseline_segmentation.md:53`) | **Full** — READ `0x01`, the base traffic | **High** — pure read, no state change, no event, no SER | **Yes** — it is the existing baseline poll | **BEST.** Dial response size by *what you read*, not by control. Directionally correct (grows the response). |
| **2** | **Event-class polling (Class 1/2/3 READ)** to pull buffered analog/binary events as response filler | **Medium-High** — grows with event backlog; less deterministic than static | **Full** — READ of event classes | **Medium-High** — read-only, but *consumes/acks events*, altering the real master's event view if shared session | **Yes** — SER/events are DNP3-mapped | Good #2, but coordinate with the real master's event consumption. |
| **3** | **CRC-boundary segmentation of the existing response** (mechanism b) | **Segmentation only** — changes chunk *count/boundaries*, not total size | **Full** — no byte changed (`split_server.py:297-319`) | **High** — no DNP3 or relay state touched | **Yes** — TCP-transparent to the master | Complements #1; it reshapes segmentation, it does not change total bytes. See §5. |
| **4** | **Dummy analog/binary INPUT points in a simulated outstation** the master reads | **High** — add as many input points as needed | **Full** — INPUT points, READ only | **High on a simulator**; **N/A on the physical relay** (can't add points read-only) | Simulator yes; physical no | Excellent for the emulator track; cannot touch the physical unit. |
| 5 | **Device attribute objects, Group 0** (READ g0) | Low-Medium — a few fixed-size attributes | Full — READ | High (read-only) | **UNVERIFIED** — many SEL builds expose limited g0 | **Counter-productive for obfuscation:** g0 *reveals* vendor/model/firmware — it de-anonymizes the device. Reject for this purpose. |
| 6 | **Unsolicited responses** (outstation-initiated event reports) | Medium — size via event content | Legal, but requires ENABLE_UNSOLICITED and changes reporting posture | **Low** — flips the relay from polled to push; repo keeps unsolicited OFF for clean captures (`CLAUDE.md:212-214`) | Yes (config) | Invasive; changes device behavior and adds a new fingerprint. Avoid. |
| 7 | **File-transfer objects, Group 70** | High (large transfers) | Legal where supported | Low-Medium — touches device files | **UNVERIFIED / unlikely** for arbitrary read on a feeder relay | Reject: uncertain support, touches files, heavy. |
| 8 | **Delay-measurement (`0x17`) / time-sync request-response** | Very low — tiny fixed | Legal | Time-sync **writes the clock** — not harmless; delay-meas is benign but tiny | Partial | Too small to matter; time-sync is a write. Skip. |
| ✗ | **Cold/Warm restart (`0x0D`/`0x0E`)** | n/a | Legal function code | **NONE — reinitializes the device** | Yes | **REJECT outright.** A restart of a protection relay is a control-equivalent hazard. Never a padding source. |
| ✗ | **CROB to unwired output (mechanism a)** | High (linear in N) | Legal function code | **Low — §2** | Yes | **REJECT for the physical relay**; simulator-only if pursued (§3). |

**Recommendation.** For the physical relay: build the size axis from **#1 (ranged static READ)** as the volume lever and **#3 (CRC-boundary segmentation)** as the shape lever — both are pure-read / byte-preserving and touch no control path. For the emulator track: add **#4 (dummy input points)**. Retire CROB (mechanism a) from the physical-relay design; keep it only as a simulator protocol study where it already lives.

---

## 5. CRC-boundary splitting correctness

**The core correctness fact, stated precisely.** DNP3 over TCP is a **byte stream**; the master's TCP stack reassembles whatever bytes arrive, in order, regardless of how they were segmented, then hands the reassembled octets to the DNP3 link-layer parser. The parser keys on the `0x0564` start octets and the LEN field (`map_response.py:98-100`, `split_server.py:166-187`) — **it never sees TCP segment boundaries.** Consequently:

- **Cutting on a CRC boundary is not what makes the master reassemble.** *Any* TCP cut point reassembles correctly, because TCP is byte-oriented. The `b"".join(chunks) == original` assertion (`split_server.py:317-318`, `docs/implementation_guide.md:547-550`) guarantees byte identity, and byte identity is all the master needs. The split creates **no new DNP3 frames** — it only changes TCP write boundaries within the same frames.
- **What the CRC-boundary constraint actually buys:** (i) the *no-DNP3-byte-modified / no-CRC-recompute* invariant (`CLAUDE.md:82-87`) — you never straddle a CRC in a way that would tempt a rebuild; (ii) a wire picture where each emitted TCP segment ends on a self-consistent DNP3 block, which only matters against a **DNP3-block-aware** passive observer or middlebox. For the master it is a no-op semantically. This is the important reframing: CRC-boundary splitting is a **TCP-segmentation** manipulation with a DNP3-aware cut rule, not a DNP3 re-fragmentation.

**Where correctness actually lives (and the failure modes):**

1. **Transport FIR/FIN and application FIR/FIN/CON are inside the payload and unchanged.** The physical relay's real Class-0 response is a **single fragment, FIR=FIN=1, CON=0** (`SEL751_DIRECT_CONNECTIVITY_REPORT.md:16-17,42`) — no application CONFIRM requested, so there is no CONFIRM handshake to break. The large synthetic read is 9 fragments with CON=1 on non-final fragments (`baseline_segmentation.md:27`, `field_map_results.md` shows `app_con=1`); the split server correctly splits the READ fragment *and* its CONFIRM-triggered continuation and waits for the master CONFIRM (`split_server.py:437-452, 584-585`). **Failure mode:** if a future re-framing (not this design) ever changed a FIN bit or fragment count, the master would stall waiting for a continuation or mis-assemble — the current byte-preserving split cannot do this, and must not be replaced by a recompute splitter (`CLAUDE.md:136-138` marks the recompute line archived/not-default).

2. **TCP sequence numbers, lengths, and checksums — the real data-plane obligation.** To split one segment into two on the switch, the data plane must emit **two valid TCP segments**: correct per-segment sequence numbers, correct IP total-length and TCP data offsets, and **recomputed IP and TCP checksums** (the DNP3 CRCs are untouched; the L3/L4 checksums are not DNP3 bytes, so this is consistent with `CLAUDE.md:82`). Get any of these wrong and the master drops the segment as corrupt. This is the guarantee the P4 program must provide, and it is orthogonal to DNP3.

3. **Retransmission / out-of-order / SACK.** If the switch resegments and one sub-segment is lost, recovery depends on who retransmits with what boundaries. A **stateless** cutter that lets the outstation retransmit the *original* (unsplit) segment produces overlapping byte ranges at the master — TCP tolerates overlap (byte stream), but only if the switch keeps sequence/ack arithmetic consistent across the rewrite. Out-of-order arrival is fine at the master's TCP layer; it is **not** fine for a DNP3-block-aware *observer* (the obfuscation value degrades), and it is a correctness hazard for the switch's own seq bookkeeping. **Data-plane guarantee required:** monotonic, gap-free sequence numbering across emitted sub-segments; consistent handling (or transparent pass-through) of retransmitted original segments; no ACK-number divergence between the two directions.

4. **Timeouts / RTO.** Adding inter-chunk delay (`split_server.py:671-672`, `--chunk-delay-ms`) or holding for the timing axis must stay under the master's fragment/response timeout and the TCP RTO, or the master retransmits or aborts the transaction. The timing engine already tracks an RTO-safe bound (`split_server.py:644 rto_safe_ms`); the size axis must respect the same bound. The charter's open retirement defect (`CHARTER.md:53-62`) must not gate the size path — keep segmentation independent of the ACK-retirement lifecycle, as the charter requires.

**Verdict:** master-side reassembly is **preserved and essentially trivial** because nothing at the DNP3 layer changes; the assertion `b"".join(chunks)==original` is the correct and sufficient software invariant. The correctness risk is entirely in the **TCP/L3 rewrite** the data plane must perform (seq/len/checksum, retransmission consistency), not in DNP3.

---

## 6. What a passive observer still learns (both mechanisms working)

Size and segmentation are two channels; the DNP3 semantic channel is untouched. A passive on-path observer still recovers, from DNP3 alone:

- **Poll cadence and rhythm.** The master's Class-0 integrity poll interval (here ~1 Hz, `SEL751_DIRECT_CONNECTIVITY_REPORT.md:33-35`) is visible in packet timing regardless of size. Cadence is a strong device/master fingerprint.
- **Function-code and class structure.** READ (`0x01`) → RESPONSE (`0x81`) pairs, which classes are polled (0/1/2/3), ENABLE/DISABLE_UNSOLICITED handshakes at startup, and any control function codes all sit in the payload the observer can parse. The SEL751 corpus signature — interleaved READ + DIRECT_OPERATE — is a behavioral fingerprint on its own (measured this session: 198 READ + 400 DIR_OP in `SEL751.pcap`).
- **Object groups.** The response's first object header (`g30v3` analog vs `g1v2` binary, `field_map_results.md`, measured `g30v3` on the corpus) reveals the data model. Splitting on CRC boundaries does not hide the group; padding with `g12v1` echoes actually *adds* an identifying object class.
- **IIN bits.** IIN1/IIN2 in every response leak device state: `DEVICE_RESTART` (IIN1.7 = `0x80`) persists on the physical relay because no clearing WRITE is sent (`SEL751_DIRECT_CONNECTIVITY_REPORT.md:42`); an event-buffer-overflow bit would appear under chaff pressure (§2c). These are 2 bytes of high-signal state in *every* response.
- **CONFIRM behavior.** Whether the outstation requests application confirmation (CON bit) and whether multi-fragment responses occur reveals response size *class* even if byte-size is normalized — a single-fragment CON=0 device (the physical SEL-751) looks different from a 9-fragment CON=1 device.
- **Case-A separate-ACK timing signature.** The SEL-751 emits a **separate pure TCP ACK then the response** with a characteristic CLRT (median ~1.9 ms, `SEL751_DIRECT_CONNECTIVITY_REPORT.md:47-49`). That two-part ACK/response structure is a device-class fingerprint the *timing* engine targets — the size axis does nothing for it. This is exactly why the charter demands both axes co-reside (`CHARTER.md:5-12`); it is also why size obfuscation alone is insufficient.

**Net:** size+segmentation obfuscation narrows one channel. The adversary still classifies the device by *how it talks DNP3* — cadence, classes, function-code sequence, IIN, CONFIRM, and the separate-ACK timing. Any claim of "cannot fingerprint the SEL-751" must be defended on all channels, not size alone.

---

## Model and assumptions

| Item | Assumption / value | Basis | Certainty |
|---|---|---|---|
| Physical relay posture | SEL-751 READ-only; hardware gated on explicit authorization | `CLAUDE.md:41`, `CHARTER.md:34` | Repo rule (certain) |
| Governing obfuscation spec | No CRC recompute, no DNP3 field/length change, no padding, no control commands | `CLAUDE.md:82-87` | Repo rule (certain) |
| CROB = g12v1, 11 B body + 2 B index prefix = 13 B/point | IEEE 1815-2012 object library; qualifier 0x28 | spec + measured +13 LEN delta | High |
| 1-CROB sizes 35 B req / 37 B resp; +13 app B per CROB | scapy on `multi_crob_*.pcap`, `SEL751.pcap` | **measured this session** | High |
| DIRECT_OPERATE present in corpus (400 / 4000 frames) | scapy on `SEL751.pcap` / `SEL751L.pcap` | **measured this session** | High |
| Physical Class-0 response 134 B wire / 115 B DNP3, 1 fragment, 69 pts, CON=0 | physical connectivity report | `SEL751_DIRECT_CONNECTIVITY_REPORT.md:16-17,42` | High |
| Read-size lever ~5.7 B/analog point; large read → 12,204 B / 49 frames / 20 TCP seg | scapy on `large_read.pcap` | `baseline_segmentation.md:26-55` | High |
| CROB status enumeration (0..19) | IEEE 1815 command status / opendnp3 `CommandStatus` | spec | High |
| Unwired-but-mapped CROB returns SUCCESS and writes SER on SEL-751 | SEL RB/SELOGIC + SER model | SEL-751 datasheet (general); not read on this unit | **UNVERIFIED** — settle by bench SBO + `SER` console read + settings export |
| Master reassembles any TCP cut point | TCP byte-stream semantics; `b"".join==original` invariant | `split_server.py:317-318` | Certain |
| Data plane must rewrite TCP seq/len/checksums to split | TCP/IPv4 framing | RFC 793/9293, RFC 791 | Certain |
| Group 0 / File-transfer / unsolicited support on SEL-751 | device profile dependent | not confirmed on this unit | **UNVERIFIED** — settle by reading the relay's DNP3 device profile |

---

## Recommendations (with the clause/standard that backs each)

1. **Do not issue CROBs to the physical SEL-751; do not have the P4 data plane originate any control.** Keep CROB-size work on the simulated outstation where it already lives (`multi_crob_validation.md:24-26`, `CLAUDE.md:99-101`). Basis: `CLAUDE.md:41,82`; NERC CIP (control-origin auditability, BES cyber-system logging integrity); IEC 62443 least-function / control-path integrity.
2. **Build the physical-relay size axis from ranged READ (volume) + CRC-boundary segmentation (shape), not CROB.** Basis: `baseline_segmentation.md:53-55` (READ lever), `split_server.py:297-319` (byte-preserving split), `CLAUDE.md:82-87` (no control, no byte change). This is §4 rows 1 and 3.
3. **Treat CRC-boundary splitting as a TCP-layer operation and specify the data-plane guarantee accordingly:** monotonic gap-free TCP sequencing across emitted sub-segments, correct IP/TCP length and recomputed L3/L4 checksums, retransmission consistency; DNP3 bytes and CRCs untouched. Basis: §5; RFC 9293 (TCP), RFC 791 (IPv4); invariant `split_server.py:317-318`.
4. **If a physical control path is ever authorized, escalate to Philip explicitly and use a bench (non-production) relay under the five conditions in §3** — SBO-only, unwired index confirmed by terminal-block inspection *and* map export, SER monitored, abort between SELECT and OPERATE. Basis: §2, §3; IEC 62443 zone/conduit isolation.
5. **Do not claim "cannot fingerprint the SEL-751" from size obfuscation alone.** Report the residual DNP3 semantic channels (§6) as out-of-scope-for-size and covered (or not) by the timing axis. Basis: `CHARTER.md:76-80` success criterion (c) "normalizing fields an adversary actually reads."
6. **Settle the three UNVERIFIED SEL-specifics before any physical-relay decision:** (a) does an unwired-but-mapped CROB return SUCCESS and write SER; (b) the relay's DNP3 map (which indices are RB-mapped, whether any sit in SELOGIC); (c) the relay's device profile (g0 / g70 / unsolicited support). All three are settled **read-only** by exporting AcSELerator settings + one bench test — no production-relay control required.

---

### One-line answer to Philip's design

Keep CRC-boundary splitting (mechanism b) — it is correct and safe, though its correctness is at TCP, not DNP3. Retire CROB-to-unwired-points (mechanism a) from any design that touches the physical relay or the data plane: it is a control command, "electrically inert" is a wiring accident not a safety property, and you can get the same controllable outstation-side volume from a larger READ with zero relay-state impact.
