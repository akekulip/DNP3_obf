# Native DNP3 mechanisms for a device-independent transcript — one-Tofino testbed

> **Reading note (documentation correction, `CORRECTION_LOG.md` §"Second correction").** Preserved as the
> analysis record; read with these corrections: (a) "DNP3-blind" is superseded — Defense 4 is DNP3-aware,
> and the limitation is bounded per-packet parsing and state without arbitrary TCP-stream reassembly or
> application-level store-and-forward; (b) the `ignore = strip` result is a **design hypothesis / conditional
> lemma** pending formal assumptions, not a settled fact; (c) any statement that a fabricated/premature
> CONFIRM **permanently deletes the SEL-751's SER/SOE records** is corrected to: a valid premature
> application confirmation can **retire acknowledged events from the DNP3 event buffer and prevent their
> later delivery to the master**; SEL-specific SER/event-report effects are unproven and the three stores
> are distinct. Corrected conclusions are in `DECISION_MEMO.md` and `ARCHITECTURE_CANDIDATES.md`.

**Question answered.** Without encryption and without a decoding peer, can DNP3-native mechanisms
(fixed templates, decoy points, safe CROBs, native chaff) SAFELY make the plaintext DNP3 transcript
on the master-facing link independent of the protected outstation, on unchanged endpoints, for a
declared public transaction class `c` (READ or SBO)?

**Topology this file assumes (binding).** `Master <-> Tofino-1 <-> Outstation`. No proxy, gateway,
sidecar, second switch, tunnel, split-TCP, SmartNIC, or endpoint software change. Master and
outstation are stock plaintext DNP3/TCP endpoints. The Tofino may use internal pktgen / TM queues /
multicast / mirror / recirculation / loopback and may be configured once by a control plane that
reads counters, but the control plane does not pace individual packets or make per-transaction
release decisions and is not in the live path. Observer = passive, on the master-facing side of the
Tofino, sees both directions, all plaintext bytes, headers, sizes, counts, and fine-grained timing.

**Secret `X`** = physical outstation identity plus response-dependent size / timing / count / stack
behaviour. **Public `C`** = transaction occurrence plus operation class. No pattern parameter may
depend on device identity, actual response size, response values, response readiness, natural ACK
timing, or natural response timing.

Labels used on every finding: **[verified fact]** (read off a repo artifact or an IEEE 1815 clause),
**[inference]** (follows by construction from a verified fact), **[hypothesis]** (plausible, not yet
tested), **[falsification result]** (a candidate mechanism shown to fail its own claim),
**[open question]** (needs a measurement or a Philip decision).

---

## Bottom line up front

1. **The central answer is NO.** Native DNP3 traffic cannot SAFELY make the plaintext transcript
   device-independent on unchanged endpoints. The one thing that would make cover indistinguishable —
   filler that is byte-identical to a real device response — is exactly the thing an unmodified,
   non-cooperating switch cannot produce in plaintext DNP3, and the one thing that *is* provably
   inert to inject (a prepended black-hole link frame) is strippable/labelable by the observer in a
   single subtraction. This is the strippability theorem applied to the whole transcript, not just
   the size axis. **[falsification result]** — `research/size_timing_coresidency/reports/adversary-model.md:430-464`.

2. **Family 1 (fixed request/response templates): FALSIFIED as a device-independence mechanism.**
   Turning a device that natively returns 12 objects into a fixed 34-object template requires either
   the switch to ADD DNP3 application objects (CRC recompute + app-layer surgery, barred by the
   governing spec `CLAUDE.md:82`, and structurally impossible on Tofino-1 because the DNP3 bytes are
   the unparsed deparser residual and never enter the PHV) or the outstation to genuinely return 34
   real objects (device-dependent point map and secret values — still `X`). A master will
   *protocol-accept* extra objects, but switch-fabricated objects are false measurements injected into
   the master's data model — a false-data-injection attack on the EMS, not a safe template. **[falsification result]**.

3. **Family 2 (SBO / decoy CROBs): REJECT for this physical testbed.** A decoy CROB is a control
   command to a protection relay. "Electrically inert" is a wiring accident, not a safety property: on
   an SEL-751 a mapped-but-unwired point still asserts a Remote Bit, writes a Sequential-Events-Recorder
   (SER) row, and pressures the DNP3 event buffer (IIN2.3 `EVENT_BUFFER_OVERFLOW`). It also does not
   even help privacy — a 37-byte `g12v1` control echo is trivially labelable against a 134-byte `g30`
   READ response. Sanctioned only against the *simulated* outstation where the multi-CROB line already
   lives; that is not the physical relay in this testbed. **[verified fact]** —
   `research/size_timing_coresidency/reports/dnp3-safety-review.md:65-104`.

4. **Family 4 (native chaff / duplication): the only provably inert native filler is trivially
   labelable, and everything indistinguishable is barred or unsafe.** A prepended black-hole link
   frame carries its own `LEN`; the observer skips it in one subtraction (labelable). TCP
   retransmissions and duplicate ACKs are labelable by sequence/ack number and can perturb the peer's
   TCP window. Any injected DNP3 *application* frame runs the master's `ProcessIIN` unconditionally
   (writes to the live relay). A fabricated application CONFIRM makes the outstation permanently
   delete SOE records the real master never received. **[verified fact]** —
   `research/ditto_comparison/DITTO_VS_DEFENSE3.md:90-105`.

5. **The single safest viable native mechanism is not a chaff mechanism at all.** It is a
   **fixed-count, fixed-schedule CRC-boundary segmentation of the genuine response**, with a fixed
   public READ-polling class on the request side and a fail-open path. It changes no DNP3 byte, issues
   no control, writes nothing to the relay, and the master receives exactly what it requested. It
   closes the **count** and **release-schedule** axes for the public class `c`, but it does **not**
   close the size-aggregate axis or the outer-header axis — those need an encrypted envelope. So the
   honest deliverable of the native path is a **bounded partial pattern (K + schedule)**, not full
   device-independence. **[inference]** from `dnp3-safety-review.md:129-146` + `adversary-model.md:430-464`.

6. **The single most dangerous safety risk is a fabricated DNP3 application CONFIRM**, which causes
   the outstation to permanently purge Sequential-Events-Recorder / event-buffer records — silent,
   irreversible loss of protective-event forensic evidence on a protection relay. Runner-up: any
   injected application frame triggering an unconditional `ProcessIIN` WRITE to the live relay
   (time-sync g50, clear-restart). **[verified fact]** — `DITTO_VS_DEFENSE3.md:97-99`,
   `adversary-model.md:516-519`.

---

## Model and assumptions

| Item | Value / assumption | Basis | Certainty |
|---|---|---|---|
| Topology | `Master <-> Tofino-1 <-> Outstation`; no proxy/peer/tunnel/endpoint change | task constraint; `README.md:24-29` | given |
| Observer vantage | passive, master-facing side of the Tofino; both directions; all plaintext, headers, sizes, timing | `THREAT_MODEL.md:9-41` | given |
| Secret `X` | device identity + response-dependent size/timing/count/stack behaviour | task; `THREAT_MODEL.md:43-70` | given |
| Public `C` | transaction occurrence + operation class (READ or SBO) | task; `THREAT_MODEL.md:59-70` | given |
| Governing obfuscation spec | no CRC recompute, no DNP3 field/length change, no random padding, no control commands | `CLAUDE.md:82-87` | repo rule (certain) |
| Tofino-1 cannot touch DNP3 bytes | DNP3 payload is the unparsed deparser residual; never enters the PHV | `DITTO_VS_DEFENSE3.md:80-82` | verified fact |
| Master reassembles any TCP cut point | TCP is a byte stream; `b"".join(chunks)==original` invariant | `dnp3-safety-review.md:129-134`, `split_server.py:317-318` | verified fact |
| Physical Class-0 response | 134 B wire / 115 B DNP3, 1 fragment, FIR=FIN=1, CON=0, `g30v3` | `dnp3-safety-review.md:158,174` | verified fact |
| CROB = `g12v1`, +13 app bytes/point; Nmax=16 (this config) | IEEE 1815-2012 §11 object library; qualifier 0x28; `maxControlsPerRequest` | `dnp3-safety-review.md:30,50`; `dnp3_multicrob_harness/README.md:74-77` | verified fact |
| SEL-751 posture | READ-only; hardware gated on Philip's explicit authorization | `CLAUDE.md:41` | safety rule (certain) |
| Whether an unwired-but-mapped CROB returns SUCCESS + writes SER on *this* firmware | dangerous case; not read on this unit | `dnp3-safety-review.md:69-71,177` | **open question** |

---

## Family 1 — Fixed DNP3 request/response templates

**Claim under test.** Transform each transaction into a fixed protocol-valid template (fixed READ
object sets/ranges, configured decoy measurement points, fixed object counts, stable qualifier and
variation choices) so the observed request and response are identical across devices.

**The pivotal sub-question — does the master safely accept ADDITIONAL objects, or must the Tofino
REMOVE objects?**

- **Master protocol-acceptance of extra objects: YES.** A DNP3 master parses whatever object headers
  a response fragment carries and routes each to its measurement/SOE handler by index; a Class-0
  integrity poll explicitly asks for "all" objects. So at the wire-parse level a master will not
  reject a 34-object response where it expected 12. **[verified fact]** (IEEE 1815-2012 §4/§11 response
  parsing; corpus response is `g30v3`, `adversary-model.md:444-446`).
- **But "protocol-accept" is not "safe-accept."** If the *switch* fabricated the extra 22 objects,
  those are measurement values that never came from the device. They enter the master's data model
  and any SCADA historian as genuine readings. That is a false-data-injection (FDIA) attack on the
  EMS, executed by the defense. **[inference]** — same harm class as injected unsolicited responses,
  `DITTO_VS_DEFENSE3.md:92`.

**How the additional objects would be produced — every path fails:**

1. **Switch ADDs objects to the outstation's response.** Requires rebuilding the DNP3 application
   fragment and recomputing the DNP3 block CRCs (barred, `CLAUDE.md:82`), plus rewriting TCP
   seq/len/checksums. On Tofino-1 it is not merely barred but *structurally impossible*: the DNP3
   bytes are the unparsed deparser residual and never enter the PHV, so the pipeline cannot read or
   edit application objects. **[verified fact]** — `DITTO_VS_DEFENSE3.md:80-82`.
2. **Outstation genuinely returns the fixed 34.** Then the switch would have to rewrite the master's
   READ request to a wider range (same app-surgery + CRC-recompute barrier), and even then a device
   with only 12 real points cannot return 34 real objects — it returns fewer or an error, and the
   values it does return are the secret. Size and structure stay `X`-dependent. **[falsification result]**.
3. **Configured decoy measurement (input) points on the outstation.** This is the one clean version —
   *but it requires modifying the outstation's DNP3 map*, i.e., an endpoint change, which the testbed
   forbids (stock endpoints). Valid only on a simulated/emulated outstation, not the physical relay.
   `dnp3-safety-review.md:117` row 4 marks dummy input points "Excellent for the emulator track;
   cannot touch the physical unit." **[verified fact]**.

**The removal direction and the vantage subtlety the task raised.** To template 34 objects down to a
fixed 12, the switch must REMOVE objects (again app-surgery + CRC-recompute, barred/infeasible).
On the vantage question — "if removal happens before the observed master-facing link, does the
original size leak return?" — in *this* topology the observer is master-facing and the switch sits
between outstation and master, so a master-facing observer would only see the post-removal traffic
and the original 34-object size would *not* leak to it. **[inference]**. That apparent win is void for
three reasons: (a) removal is still barred and structurally infeasible (points 1–2); (b) removal
*drops real measurements/events* the master needed — data loss to the EMS, a safety regression; and
(c) it holds only under the exact master-facing vantage — an in-path or outstation-facing observer
sees the original. **[inference]**.

**Family 1 verdict: FALSIFIED as a device-independence mechanism on this testbed.** A fixed *request*
template is trivially available (the master already polls a fixed READ class, which is exactly the
public `C`), but a fixed *response* template independent of the device is unreachable without either
endpoint modification (barred) or switch-side DNP3 surgery (barred + structurally impossible + an FDIA
on the master). The only safe fragment of Family 1 is: **treat the fixed public READ class as `C` and
carry it on the request side unchanged** — which reveals only what `C` already publishes and closes
nothing about the device.

---

## Family 2 — SBO and decoy CROBs

**Evidence base (upstream, simulated outstation).** The multi-CROB harness establishes, on the rig
against a *simulated* `--control-test` outstation, that one SBO command set can carry and process
multiple valid CROBs (`g12v1`), with a measured configuration maximum `Nmax = 16`
(`maxControlsPerRequest`); N≥17 returns `TOO_MANY_OPS (8)` and no OPERATE runs; a nonexistent index
returns `OUT_OF_RANGE (12)` per-index in the SELECT response, and a partially failed SELECT batch is
discarded so no OPERATE fires; an OPERATE after the SELECT lifetime (default 5 s) returns `NO_SELECT`.
**[verified fact]** — `dnp3_multicrob_harness/reports/multi_crob_sbo_results.md:29-49,70-91`;
`README.md:74-77,131-141`; `docs/multi_crob_validation.md:49-50`.

**Run the safety/security battery against a decoy CROB on the *physical* relay:**

- **Is count independent of `X`?** A decoy-CROB pattern can fix the number of control objects, so
  count can be `X`-independent by construction. **[inference]** — the only battery item CROBs pass.
- **Are sizes independent of `X`?** The exchange is a fixed ~35 B request / ~37 B response, +13 B/point
  — dial-able and `X`-independent *as a control echo*. But it does not resemble the READ response it
  must mask (different function code, object group `g12v1` vs `g30`, and size), so the observer labels
  it instantly. **[verified fact]** — `dnp3-safety-review.md:14,61`.
- **Can the observer label real vs cover?** Yes, trivially — function code `SELECT(0x03)`/`OPERATE(0x04)`
  and object group `g12v1` are in the plaintext the observer parses. **[verified fact]**.
- **Does the decoy alter control / event / diagnostic state?** Yes on a real relay. A mapped-but-unwired
  point returns `SUCCESS`, asserts a Remote Bit / latch, writes an SER row, and each successful control
  emits a binary-output-status *event* into the Class 1/2 buffer; a flood sets IIN2.3
  `EVENT_BUFFER_OVERFLOW` and discards real events. SBO also creates SELECT arm-state with a timeout,
  racing the real master's polling on a shared session (`NO_SELECT`/sequence confusion), or needing a
  second master identity the relay's allowlist rejects. **[verified fact]** — `dnp3-safety-review.md:69-79`.
- **Does the master receive exactly the semantics it requested?** No — the real master's data model and
  the SCADA historian log spurious "output operated" events; the control audit trail is falsified.
  **[verified fact]** — `dnp3-safety-review.md:79`.
- **Does the outstation receive only safe operations?** No — it receives control commands to a
  protection element. The switch emitting CROBs is an unauthenticated in-network control-injection
  appliance in front of a protection relay, which NERC CIP and IEC 62443 exist to prevent.
  **[verified fact]** — `dnp3-safety-review.md:81`.

**Family 2 verdict: REJECT for the physical testbed.** Decoy CROBs pass only the count-independence
item, fail every other privacy and safety item, and violate `CLAUDE.md:41` (physical relay READ-only)
and `CLAUDE.md:82` (no control commands). The multi-CROB evidence is a valid *protocol/API
characterization on a simulator* and nothing more; it is not a viable native mechanism against the
physical relay. **[verified fact]**. Whether an unwired-but-mapped index on this specific SEL-751
firmware actually returns `SUCCESS` and writes SER is an **[open question]** settled read-only by a
bench settings/DNP3-map export — but the verdict does not depend on it, because even the fully inert
case is observer-labelable and buffer/SER-polluting.

---

## Family 4 — Native chaff / duplication

**Claim under test.** Protocol-valid READs, safe decoy operations, TCP duplicates, retransmission-like
packets, ACKs, or other cover packets fill scheduled slots and are indistinguishable from real traffic.

Per-candidate safety/security battery (endpoint effect, observer labelability, relay-state effect,
whether pktgen can generate it continuously):

| Candidate | Endpoint effect (accept / ignore / reject / act) | Observer can label it? | Alters relay/master state? | Verdict |
|---|---|---|---|---|
| Injected **unsolicited response** (`0x82`) | master **acts**: measurements enter SOE / data model with no request correlation, no sequence validation | yes — funccode `0x82`, no matching poll | yes — pollutes master data model (FDIA) | **forbidden** [verified fact] `DITTO_VS_DEFENSE3.md:92` |
| Any injected **application frame** (even one the outstation rejects) | master runs `ProcessIIN` **unconditionally**: `NEED_TIME`→g50 time-sync **WRITE** to the live relay; `DEVICE_RESTART`→clear-restart **WRITE**; class bits→extra READs | yes — parseable DNP3 | yes — **writes to the protection relay** | **forbidden** [verified fact] `DITTO_VS_DEFENSE3.md:93`, `adversary-model.md:516-518` |
| Fabricated application **CONFIRM** | outstation **permanently deletes SOE records** the real master never received | yes — transport/app CON bit | yes — irreversible loss of protective-event record | **categorically forbidden** [verified fact] `DITTO_VS_DEFENSE3.md:97`, `adversary-model.md:518-519` |
| Extra **polls** / second **TCP session** | outstation answers; doubles relay load; can displace the operational master's session | yes — extra READ cadence / new 5-tuple | yes — session/load impact | **forbidden** [verified fact] `DITTO_VS_DEFENSE3.md:100` |
| **Link-layer keepalive** chaff | drives `OnLinkStatus`/`OnRequestLinkStatus`, mutates link state, may reply toward the relay | yes — link-layer function | yes — link-state mutation | **reject** [verified fact] `DITTO_VS_DEFENSE3.md:101` |
| **TCP retransmission-like** packet / **duplicate ACK** | peer TCP may fast-retransmit or advance/ignore per seq/ack; no DNP3 app effect if payload is a pure dup | yes — duplicate seq/ack number is definitional | possibly — perturbs peer TCP window / triggers fast-retransmit | **reject** [inference] (TCP semantics; observer labels by seq) |
| Bare **TCP ACK** (no payload) | never reaches DNP3 app layer; `ProcessIIN` does not run (Defense 2/3 already hold/release bare ACKs) | yes — 0 TCP payload + ACK flag is definitional | no, *if* seq/ack kept consistent (else window disruption) | **safe but useless as cover** — carries no size, trivially labelable [inference] |
| **Prepended black-hole link frame** (own `LEN`, discarded before transport) | discarded before transport: no measurement delivery, no IIN, no keepalive restart, stream stays in frame sync | **yes — observer reads `LEN`, skips `10+LEN'+2·⌈…⌉` bytes in one subtraction** | no | **the only provably inert native filler — but strippable/labelable** [verified fact] `DITTO_VS_DEFENSE3.md:103`, `adversary-model.md:450-451` |

**Can native chaff be made observer-indistinguishable WITHOUT encryption? NO.** The two properties are
mutually exclusive in plaintext, self-describing DNP3. Any filler that is byte-indistinguishable from a
real device response has to be produced by the endpoint (device-dependent → still `X`, or an endpoint
change → barred) or fabricated by the switch (CRC-recompute + app-surgery → barred + structurally
impossible on Tofino-1). Any filler the switch *can* inject carries its own self-describing
group/length/sequence fields, so the observer's strip-rule is the same rule the receiver's ignore-rule
uses — it is written in the packet. **[falsification result]** — `adversary-model.md:458-462`. Can pktgen
generate the safe filler continuously and fill every slot? Yes for the bare ACK / black-hole frame
(in-switch pktgen, no relay contact) — but that filler is labelable, so filling slots buys availability
padding, not indistinguishability. **[inference]**.

**Family 4 verdict: NO safe *and* indistinguishable native chaff exists.** The safe subset (bare ACK,
black-hole link frame) is trivially labelable; the indistinguishable subset (real-looking DNP3
objects, CONFIRMs) is barred or actively dangerous to the relay/master.

---

## The endpoint-safety argument

**Safe to send toward the unchanged master (master-facing egress):**
- The genuine outstation response, verbatim, re-segmented on existing DNP3 CRC-block boundaries with
  the L3/L4 (IP/TCP) checksums recomputed and monotonic gap-free TCP sequencing — no DNP3 byte changed.
  The master reassembles the identical octet stream (`b"".join(chunks)==original`). **[verified fact]**
  — `dnp3-safety-review.md:129-146`.
- Bare TCP ACKs with consistent seq/ack (as Defense 2/3 already do). **[verified fact]**.
- **Never safe toward the master:** fabricated DNP3 application objects (FDIA into the data model),
  fabricated unsolicited responses, or fabricated CONFIRMs.

**Safe to send toward the unchanged outstation (outstation-facing egress):**
- Nothing new. The outstation stays READ-only under the master's own polling. The switch must not
  originate any application frame toward the relay, because `ProcessIIN` and CONFIRM handling turn even
  a *rejected* frame into a WRITE or an SOE deletion, and any CROB is a control on a protection element.
  **[verified fact]** — `adversary-model.md:516-519`, `dnp3-safety-review.md:81`.

**What a passive master-facing observer can still label even with the safe set applied:** object group
and variation (`g30` vs `g12v1`), function-code sequence (READ/RESPONSE, SELECT/OPERATE), IIN bits
(`DEVICE_RESTART 0x80` persists on this relay; `EVENT_BUFFER_OVERFLOW` would light under chaff), CON-bit
/ fragment-count class, poll cadence, the Case-A separate-ACK CLRT signature, and the outer-header
fingerprint (IPv4 TTL, TCP data-offset, TCP-timestamp slope). Segmentation and any native filler touch
none of these. **[verified fact]** — `dnp3-safety-review.md:150-161`, `THREAT_MODEL.md:82-97`.

---

## Mapping to the pattern states and their counters

The pattern-state counters in `OBSERVABLE_TRANSCRIPT_SPEC.md:91-111` record **privacy and availability**
outcomes; they do **not** meter relay-safety hazards — those must be prevented by construction (never
emit a control, a CONFIRM, or any application frame toward the relay). **[inference]**.

- **PATTERN_NORMAL** — genuine response present, fits the fixed template, emitted as the fixed cell
  count on the fixed schedule. The invariance/privacy claim is made only here.
- **PATTERN_OVERFLOW** — the real response exceeds the template's provisioned cells (e.g., a 12,204-byte
  large READ against a small-poll template). The privacy claim is void for that epoch.
- **AVAILABILITY_BYPASS** — a missing/late response (readiness) forces a real packet onto the wire
  outside the pattern (the Defense-4 fail-open path). Any interval with this counter nonzero is
  *excluded* from the privacy claim, not averaged in.
- **PATTERN_DROP** — a scheduled cell was deliberately skipped (a skipped slot is itself observable).
- **RECOVERY_MODE** — returning to PATTERN_NORMAL after any of the above.

Where each failure of this analysis is recorded: a **strippable/labelable filler** (Family 4) or a
**device-dependent response size** (Family 1) means the transcript-invariance test simply *fails inside
PATTERN_NORMAL* — there is no separate "chaff-detected" counter; the audit records it as the invariance
property not holding, and any real packet forced out increments **AVAILABILITY_BYPASS**. A **decoy CROB
altering relay state** (Family 2) is *not* captured by any of these counters — it is a hard safety
violation outside the privacy accounting entirely. **[inference]**.

---

## Answers to the required return items

**Single safest viable native mechanism (one line).** A fixed-count, fixed-schedule CRC-boundary
re-segmentation of the genuine outstation response (request side = the already-public fixed READ
class `C`), with L3/L4 checksum/seq rewrite only and a fail-open path — no DNP3 byte changed, no
control, no write to the relay, master receives exactly what it requested. It closes count and release
schedule for the public class but not size-aggregate or outer headers.

**Can native chaff be made observer-indistinguishable WITHOUT encryption? NO.** In a plaintext,
self-describing application protocol the receiver's ignore-rule and the observer's strip-rule are the
same rule and it is written in the packet, so the only indistinguishable filler is filler the endpoint
genuinely produces — which a stock endpoint and a non-cooperating, DNP3-blind Tofino cannot synthesize.
The safe filler is labelable; the indistinguishable filler is barred or dangerous.

**Most dangerous safety risk (one line).** A fabricated DNP3 application CONFIRM, which makes the
outstation permanently delete Sequential-Events-Recorder / event-buffer records the real master never
received — silent, irreversible loss of protective-event forensic evidence on a protection relay
(runner-up: any injected application frame triggering an unconditional `ProcessIIN` WRITE to the live
relay).

**File path.** `/home/philip/Projects/DNP3_fixed_transcript/analysis/native_dnp3_mechanisms.md`.

---

## Open questions (read-only to settle; none change the verdicts)

1. **[open question]** Does an unwired-but-mapped CROB index on *this* SEL-751 firmware return
   `SUCCESS` and write an SER row? Settled read-only by an AcSELerator settings + DNP3-map export and
   one bench SBO (`dnp3-safety-review.md:69-71,177,191`). The verdict (reject) holds either way.
2. **[open question / Philip decision]** Is operation type in `C` (public) or `X` (secret)? If READ-vs-SBO
   is secret, the request-side template must be identical across operations, which native mechanisms
   cannot deliver without hiding function codes (`THREAT_MODEL.md:72-79`).
3. **[open question]** Is a local encapsulation function near the outstation deployable at all? If not,
   the size-aggregate and outer-header axes stay open on the native path, and the deliverable remains a
   bounded partial pattern (`README.md:71-72`, `OPEN_QUESTIONS_FOR_PHILIP.md`).
</content>
</invoke>
