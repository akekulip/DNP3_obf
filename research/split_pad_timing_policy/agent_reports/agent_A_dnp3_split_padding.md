# Agent A — DNP3 Protocol Analysis of Split Boundaries (RQ2) and Padding Feasibility (RQ3)

_Scope: enumerate every legal vs illegal split boundary in the DNP3-over-TCP stack; assess
byte-preserving padding feasibility across the 9 GROUNDING categories (DNP3-semantic ones in
depth); document transaction-semantics interactions with split/timing; classify every mechanism.
Design/analysis only — no code changed. Grounded on GROUNDING.md, measured_evidence.md, and Agent
C's DNP3/SCADA report (built on, not redone). All OpenDNP3 facts read from the community fork this
session, cited file:line; standard facts from IEEE 1815-2012 (`ieee2012dnp3`, in matrix). Labels:
[M] measured · [S] standard · [V] vendor-doc · [P] paper · [I] inference · [H] hypothesis._

---

## 1. Findings first (protocol-engineering terms)

1. **The master reassembles ANY byte-offset split, not only CRC-block splits — because the
   receiver's link layer is stream-oriented.** [S][I, source-grounded] OpenDNP3's `LinkLayerParser`
   accumulates the TCP byte stream in a `ShiftableBuffer` and finds frame boundaries by *content*
   (sync `0x05 0x64` + LENGTH field), waiting until `NumBytesRead >= frameSize` before validating
   (`LinkLayerParser.cpp:88-138`). It never inspects where TCP segment boundaries fall, and TCP
   guarantees reliable in-order byte delivery. **Therefore an on-path splitter can cut the stream at
   *any* byte offset and the master reconstructs byte-identical frames.** The measured CRC-boundary
   result (2407 B → 141/71/36/18 chunks, 0 retransmits [M]) is a *sufficient* legal split, but
   CRC-block alignment is **not a reassembly requirement** — it is a defense-design / auditability
   choice (every emitted chunk ends on a completed, already-valid CRC block, so no observer or Zeek
   `dnp3` analyzer ever sees a bisected CRC and the "no byte modified" invariant is self-evident).
   The measured note "cannot split inside a CRC block (out of phase)" is true **only of the harness's
   CRC-boundary mode** (it enumerates block boundaries); it is **not** a master-side rejection. State
   this precisely in the paper — claiming the master rejects a mid-block TCP cut would be false.

2. **What the master genuinely rejects is byte MODIFICATION, not byte-preserving re-segmentation.**
   [S][I, source-grounded] Every 16-byte data block carries its own 2-byte CRC and the header carries
   a CRC over its first 8 bytes; `ReadHeader` and `ValidateBodyCRC` reject on any CRC mismatch and
   the frame is dropped (`LinkLayerParser.cpp:157-189`, `LinkFrame.cpp:51-69`). So modifying a data
   byte, editing the LENGTH field, or inserting non-block bytes all fail (bad CRC + framing desync).
   This is why the phase rule forbids CRC recompute/field edits — and why splitting (which touches no
   byte) is safe while padding-by-insertion is not.

3. **No byte-preserving, semantically-inert DNP3 padding exists at the application layer — this is a
   source-level generalization of the measured invalid-index negative result.** [M][S][I] The APDU
   parser loops `while (copy.length() > 0)` and requires the buffer to be **fully consumed by
   well-formed, known objects** (`APDUParser.cpp:60-112`): each object's group/variation must resolve
   to a known `GroupVariation` (else `UNKNOWN_OBJECT`), the qualifier must be exactly one of **7**
   accepted codes (`QualifierCode.cpp:42-63`; everything else → `UNDEFINED` → `UNKNOWN_QUALIFIER`),
   and the APDU has **no length field** (header is fixed 2 B request / 4 B response, remainder is all
   objects — `APDUHeaderParser.cpp:33-59`). There is no NUL/comment/padding object group in IEEE
   1815. Consequently: (a) trailing filler after the last object → parse error; (b) invalid-object
   filler → `UNKNOWN_OBJECT`/`OUT_OF_RANGE` (the measured [M] dead end); (c) *valid* filler is
   consumed by `MeasurementHandler::ProcessMeasurements` as real data / by the command handler as a
   real control → semantic change. All three roads are blocked. **No padding is insertable this phase.**

4. **The measured size leaks are therefore residual and cannot be closed by any current-phase
   byte-preserving DNP3 mechanism.** [M][I] Split preserves total bytes (§4), and padding is blocked
   (§5), so CROB count on SELECT/OPERATE responses (14.6 B/CROB, R²=0.9999 [M]) and read-plane
   response size ∝ point count (~5.7 B/analog point [M]) leak on the size axis with no in-scope fix.
   Closing them needs a **future** encrypted/tunneled-envelope padding phase (only place padding is
   standards-legal and strippable) or endpoint-emitted fixed-size responses. Record it; do not invent
   DNP3 padding.

5. **Splitting and CONFIRM-serialized multi-fragment responses are composable but the CONFIRM is
   inviolable.** [S][I] Multi-fragment reads are serialized by the application CONFIRM (CON bit;
   master confirms only when `ParseResult::OK`, `MasterContext.cpp:257-262`). You may re-split the
   link frames *within* any fragment freely, but you must not merge across the CONFIRM handshake,
   reorder fragments, or suppress/synthesize a CONFIRM — the last also flushes the outstation event
   buffer (Agent C §7E, re-confirmed in source here).

_Plain language: the master doesn't care where you chop the byte stream — TCP plus a stream-reading
link parser put it back together no matter what, so chopping is safe. What it does reject is changing
any byte (bad checksum). And DNP3 has nowhere to hide filler bytes: every byte of a message must be a
real, recognized object, so you can't pad without either breaking the parse or lying about the data.
That means the size clues we measured stay leaked for now._

---

## 2. Model and assumptions

| Dimension | Setting | Source |
|---|---|---|
| Stack | OpenDNP3 community fork; SW outstation (Hulk) ↔ SW master (Vision) | measured_evidence.md; fork |
| Transport | DNP3-over-TCP, single persistent connection, `TCP_NODELAY` (each write ⇒ a segment) | CLAUDE.md; split_server |
| Link service | Unconfirmed only (`PRI_UNCONFIRMED_USER_DATA`); no `SEC_ACK` | Agent C §3.3 (verified fork) |
| Frame geometry | 10 B header + ≤250 B user data in ≤16 blocks (16 data + 2 CRC each); ≤292 B/frame | `LinkLayerConstants.h:28-35` [S] |
| Transport TPDU | 1 B header (FIR/FIN/6-bit SEQ) + ≤249 B; 1 TPDU per link frame (250==250) | `TransportHeader.h`, `TransportConstants.h:28-30` [S] |
| APDU header | request 2 B (AC+FC), response 4 B (AC+FC+IIN); **no length field** | `APDUHeaderParser.cpp:33-59` [S] |
| Max APDU fragment | `maxTxFragSize` = 2048 B (impl default) | Agent C §3 (`OutstationParams.h:59`) |
| Shaping lever | Split at safe boundaries + hold/pace existing packets; `join(chunks)==original` | GROUNDING HARD phase rule |
| Binding timing constraint | Master effective **TCP RTO** (~200 ms Linux floor; MEASURE on Vision) | Agent C §4; GROUNDING |
| Threat model | Passive on-path observer; reads plaintext DNP3; regresses size/segmentation/timing | GROUNDING |
| Scope caveat | One device, one rig, one implementation; no cross-device / DB-size-timing claim | measured_evidence.md |

---

## 3. RQ2 — Split-boundary enumeration (every candidate, LEGAL vs ILLEGAL)

Wire layout of one link frame (from `LinkFrame.cpp` / `LinkLayerConstants.h` [S]):
`[0x05 0x64 | LEN | CTRL | DEST(2) | SRC(2) | HdrCRC(2)]` then repeated
`[≤16 data bytes | CRC(2)]` blocks. Header CRC covers bytes 0–7 (`LI_CRC=8`). Each block CRC covers
its ≤16 data bytes (`ValidateBodyCRC`, `LinkFrame.cpp:51-69`).

| # | Candidate split boundary | Byte-preserving? | Master reassembles? | Class | Notes / source |
|---|---|---|---|---|---|
| B0 | **Arbitrary TCP byte offset** (any position, incl. mid-block, mid-header) | **YES** (`join==orig`) | **YES** | byte-preserving | Stream-oriented link parser + reliable TCP; boundary-agnostic (`LinkLayerParser.cpp:48-138`) [S][I]. Requires `TCP_NODELAY` or Nagle re-coalesces small writes. |
| B1 | **DNP3 CRC 16-byte-block boundary** (after header; after each 18-B block) — the harness primitive | **YES** | **YES** | byte-preserving | Subset of B0; every chunk ends on a completed valid CRC block. **Measured**: 2407 B → 141/71/36/18 chunks (bpc 1/2/4/8), 0 retransmits, master delivers 800 meas + CONFIRM [M]. Preferred for auditability + IDS-cleanliness. |
| B2 | **Link-frame boundary** (between whole `0x0564` frames, ≤292 B) | **YES** | **YES** | byte-preserving | Coarsest CRC-aligned split; each chunk = ≥1 complete frames. Large READ = 49 link frames [M]. |
| B3 | **Transport-segment (TPDU) boundary** | **YES** | **YES** | byte-preserving | 1 TPDU ⇔ 1 link frame (MAX_TPDU 250 == max user data 250), so **B3 ≡ B2** on this wire. `TransportRx` concatenates by FIR/FIN/SEQ (`TransportRx.cpp:55-136`) [S]. |
| B4 | **Application-fragment (APDU) boundary** (≤2048 B, CON-serialized) | **YES** | **YES, but** | byte-preserving *with constraint* | Fragment boundary is set by the outstation's `maxTxFragSize`; fragments are **serialized by the master CONFIRM**. You may re-split frames *within* a fragment, but must not merge/reorder across the CONFIRM or touch it (§5, Agent C §7E). |
| X1 | **Modify a data byte inside a block** | NO | **NO** — block CRC fails ⇒ frame dropped/resync | invalid | Requires CRC recompute (forbidden). `ValidateBodyCRC` (`LinkFrame.cpp:51-69`) [S]. |
| X2 | **Edit LENGTH / any header byte** | NO | **NO** — header CRC fails + framing desync | invalid | `ReadHeader` returns false ⇒ `FailFrame` (`LinkLayerParser.cpp:157-170`) [S]. LENGTH drives `frameSize`. |
| X3 | **Insert bytes that aren't a complete block** | NO | **NO** — shifts CRC positions ⇒ CRC failures | invalid | Any insertion inside a frame breaks block alignment. |

**Split-benefit note (honest):** B1 gives maximal fragmentation on the read plane (2407 B → 141 tiny
segments) but SELECT/OPERATE responses are small (37–256 B [M], ~1 frame, ≤16 blocks), so splitting a
control response yields few chunks and does **not** hide its total size — the CROB-count size leak
survives (Finding 4). Splitting reshapes Axis-1 {largest-packet, packet-count, segment-count,
per-packet-size} but never Axis-1 {total bytes}.

_Plain language: you can safely cut the traffic at four kinds of natural seams — anywhere in the byte
stream, at the 18-byte checksum blocks (what we use), at whole DNP3 frames, or at whole DNP3
messages. What you can't do is change or insert bytes: that breaks a checksum and the frame is thrown
away. Cutting makes many small packets out of one big read, but the small control replies barely
split, so their tell-tale size stays visible._

---

## 4. RQ3 — Padding feasibility across the 9 GROUNDING categories

DNP3-semantic categories (1–4) are assessed against the fork's parser; the rest are scoped to the
correct layer/agent.

| Cat | Padding idea | Feasible byte-preserving? | Why (source/measured) | Class |
|---|---|---|---|---|
| **1** | **Semantic DNP3 padding** — append real objects to inflate size | **NO** | Adds real object counts/values ⇒ changes total bytes AND semantics (master ingests as real data; a control's `CommandSet` changes). | protocol-valid-but-semantic-changing (FUTURE, protocol-modifying) |
| **2** | **Valid dummy/inert DNP3 object** — an object that parses, is known, but is inert | **NO (none exists)** | Parser requires known group/variation + one of 7 qualifiers + valid content, buffer fully consumed (`APDUParser.cpp:60-112`, `QualifierCode.cpp:42-63`). **No NUL/padding object group in IEEE 1815.** Any valid object in a RESPONSE → consumed by `MeasurementHandler::ProcessMeasurements` as real data (semantic change); in a CONTROL → real command. A count-0 header (~4 B) is not inert enough, is anomalous (distinguishable), and too small to be size-padding. | protocol-valid-but-semantic-changing / implementation-specific |
| **3** | **Invalid-object padding** — invalid-index CROBs / unknown objects | **NO (measured dead end)** | [M] Invalid G12V1 indexes → **OUT_OF_RANGE (12)** per index, visible; partial SELECT blocks OPERATE ⇒ not insertable into live SBO. Source: unknown group/var → `UNKNOWN_OBJECT` ⇒ whole APDU fails; for unsolicited, **no CONFIRM queued** (`MasterContext.cpp:257-262`) ⇒ loud retransmit. | invalid |
| **4** | **Padding outside the DNP3 message but in-band** — trailing bytes after last object / after the frame | **NO** | Intra-APDU trailing bytes → `NOT_ENOUGH_DATA_FOR_HEADER` / `UNKNOWN_OBJECT` (no length-slack; parser consumes to empty). Post-frame in-stream bytes → link parser `Sync` **skips them with a WARN** (`LinkLayerParser.cpp:88-103`) — observable, and they are extra bytes (not byte-preserving of the transaction) or they desync framing. | invalid (in-band) |
| **5** | **Tunnel / encrypted-envelope padding** — TLS/IPsec/DNP3-SA wrapper strips padding at peer | **Only with tunnel + endpoint/gateway cooperation** | A TLS record / IPsec ESP trailer legally carries strippable padding of arbitrary length — the **only** standards-blessed length-hiding padding. DNP3-SA (SAv5) adds HMAC/aggressive-mode *auth* objects, not free filler. Needs an encrypted envelope; not on-path byte-preserving. | future-proxy / endpoint-cooperating |
| **6** | **Cover traffic / decoy transactions** — extra polls/reads | Additive, not DNP3-byte-preserving | Changes activity volume; a separate mechanism (issue extra reads); master must not treat decoys as real data. | future / other-mechanism |
| **7** | **Packet-count padding** — empty/extra TCP segments | Network-layer, not DNP3 | Split (RQ2) already inflates packet count byte-preservingly; zero-payload segments are a TCP trick. | network-agent scope |
| **8** | **Silence hiding** | Timing axis | Not size padding. | Agent C / timing |
| **9** | **Timing-only "padding" (delayed release)** | Timing axis | Not size padding. | Agent C / timing |

**Reconciliation with the measured negative result.** measured_evidence.md §5 tested exactly one
padding realization (invalid-index CROB, category 3) and found it rejected + non-insertable. This
report **strengthens and generalizes** that: at the source level, categories 1–4 are all blocked —
invalid filler is rejected at object validation, *valid* filler is accepted-as-real (semantic
change), and there is no length-slack anywhere in the APDU (no length field; parser consumes to
empty; qualifier is a 7-value whitelist). So the honest claim is not merely "invalid-index padding
fails" but **"no byte-preserving, semantically-inert DNP3 padding exists in this stack, at any
layer."** Do not claim padding is solved.

**Residual size leakage (record, do not paper over).** Because split preserves total bytes and no
in-scope padding exists, the following measured size channels remain **open**:
- SELECT/OPERATE response size ∝ CROB count: 14.6 B/CROB, R²=0.9999, 37→256 B (N=1→16) [M].
- READ response size ∝ point count: ~5.7 B/analog point; large all-types READ = 12,204 B [M].
Closing either requires a **future** protocol-modifying phase (category 5 tunnel padding, or endpoint
fixed-size responses). This is the study's core size-axis negative result.

_Plain language: DNP3 gives you nowhere to legally stuff filler. Fake/invalid filler gets rejected
and is noisy; real-looking filler gets read as real measurements or real commands, which corrupts the
data. There's no length field to lie about and no "ignore me" object. The only real way to hide
message size is to wrap DNP3 in an encrypted tunnel (which pads legally) or have the device itself
send fixed-size replies — both are future work. So for now the size of a reply still reveals how many
points or control blocks it carries._

---

## 5. Transaction semantics × {split | timing hold}

| Transaction | FC | Dir | Split? | Timing/CONFIRM handling | Source |
|---|---|---|---|---|---|
| Integrity / Class-0 READ response | resp `0x81` | O→M | **Yes** (B1–B4), often multi-fragment | Schedule whole logical response to one completion deadline; each hop < RTO; never touch CONFIRM | Agent C §7E |
| Event READ response (Class 1/2/3) | resp `0x81` | O→M | **Yes**, tighter timing bound | CONFIRM also flushes event buffer — never suppress/synthesize | Agent C §5 |
| SELECT | `0x03` | req M→O / resp O→M | Response splittable but small (few chunks) | SELECT→OPERATE as one unit; whole wall-clock ≪ 10 s select timeout | Agent C §6; measured 37–256 B [M] |
| OPERATE | `0x04` | req/resp | Same as SELECT | Bypass if control flagged critical; tight budget | Agent C §5–6 |
| DIRECT_OPERATE / _NR | `0x05` / `0x06` | req/resp | `_NR` has no response to split | Consequence-safety gating; `_NR` = no CONFIRM/response | Agent C §5 |
| Application CONFIRM | `0x00` | M→O | **Do not split** (tiny) | **Never** suppress/synthesize/hold beyond outstation solConfirm (5 s); best left verbatim | Agent C §7E (verified `MasterContext.cpp:257-262`) |
| Unsolicited response | `0x82` | O→M | Off by default; if on, minimal | Master confirms only on `ParseResult::OK` — padding that breaks parse suppresses the confirm ⇒ loud retransmit | `MasterContext.cpp:249-265` [S] |
| Link confirmation | `SEC_ACK` | — | **N/A** — does not exist (unconfirmed link) | — | Agent C §3.3 (verified) |

_Plain language: reads (especially big ones) are the safe, high-value thing to split and time-shape;
control commands split poorly and must defer to a safety allowlist; and the little CONFIRM handshake
packets must be left completely alone — dropping or faking one stalls the read and can strand the
device's event buffer._

---

## 6. Master classification of every mechanism discussed

- **Byte-preserving (allowed this phase):** arbitrary-TCP-byte split (B0), CRC-block-boundary split
  (B1, the primitive), link-frame split (B2), transport-segment split (B3 ≡ B2), app-fragment split
  (B4, CONFIRM-constrained); timing hold/pace of existing packets (Agent C).
- **Protocol-valid-but-semantic-changing:** appending real DNP3 objects (cat.1); count-0 object
  header (cat.2). Change the master's database/command set — FUTURE, protocol-modifying only.
- **Implementation-specific:** count-0-header inertness; post-frame "skipped bytes" WARN behavior;
  the exact 7-value qualifier whitelist (another stack might mask the qualifier reserved bit).
- **Invalid (rejected / breaks correctness):** mid-block byte edit (X1), LENGTH/header edit (X2),
  non-block insertion (X3), invalid-index CROB padding (cat.3, measured), unknown group/variation
  padding, reserved-bit qualifier (`UNDEFINED`→`UNKNOWN_QUALIFIER`), trailing non-object bytes (cat.4).
- **Future-proxy / endpoint-cooperating work:** encrypted/tunneled-envelope padding (cat.5,
  TLS/IPsec/DNP3-SA wrapper); cover traffic / decoys (cat.6); endpoint fixed-size responses; any
  CRC-recompute frame rebuild (the archived `future_work/` codec).

---

## 7. Deliverable-section coverage & caveat

Feeds `split_analysis.md` (DNP3 side): §3 boundary enumeration + B0/B1 reassembly mechanism + §5
transaction table. Feeds `padding_analysis.md` (DNP3 side): §4 nine-category feasibility + source-
level generalization of the negative result + residual size-leak record.

**Single most important caveat:** the headline correction is that CRC-block alignment is a
*defense/auditability* choice, **not** a master-reassembly requirement — the receiver accepts any
byte-preserving TCP re-segmentation, and what it truly rejects is byte *modification* (bad CRC). Do
not overclaim that the master enforces CRC-block splitting. And do not claim any current-phase DNP3
mechanism hides message size: no byte-preserving DNP3 padding exists at any layer, so the measured
CROB-count and point-count size leaks are residual and belong to a future tunnel/endpoint phase.

---

## NEW_PAPER_MATRIX_ROWS
_None. All facts trace to the OpenDNP3 community fork (source, cited file:line), IEEE 1815-2012
(`ieee2012dnp3`, already in the 102-paper matrix), and this study's measured_evidence.md. No new
external works are cited._

## NEW_BIBTEX
_None._
