# DNP3 / IEEE 1815 Legality of Appended Response Filler

*Contribution from power-systems-expert (2026-07-18). Source-grounded in the rig's actual master (`opendnp3-community`, wrapped by pydnp3).*

## VERDICT — CONDITIONAL YES (source-confirmed on the rig master; master-dependent in general)
**There is exactly one spec-legal, master-tolerated, constant-block filler for a READ response: a Group 110 (Octet String) object.** Arbitrary appended bytes = hard NO (parsed as an object header → UNKNOWN_OBJECT → master discards the ENTIRE response incl. real data; same failure class as the CROB negative). Octet String escapes the trap because in OpenDNP3 it is (a) ALWAYS recognized regardless of variation, and (b) self-describing in length.

**Exact minimal filler (one 16-octet application unit = one data-link block):**
```
6E 0B 00 F0 F0  00 00 00 00 00 00 00 00 00 00 00
6E = group 110 (Octet String, static)
0B = variation 11 (each string is 11 octets long)
00 = qualifier 0x00 (1-octet start / 1-octet stop range)
F0 = start index 240 ; F0 = stop index 240  → COUNT = 1
then 11 constant payload octets (content free; 0x00 shown)
```
App-layer cost = 5 header + 11 payload = **16 octets = exactly one DNP3 data-link data block** → Tofino appends one 18-octet on-wire block `[16 data | 2 CRC]` with a compile-time-CONSTANT CRC. Repeat N times to hit target (caveats §4). Use reserved high index band (0xF0–0xFF) so filler never collides with a real point.

CONDITIONAL because: (1) relies on master supporting Group 110 — CONFIRMED in the rig master's source; NOT universal across commercial masters (per-master check needed). (2) parser is fail-closed two-pass — filler must be PERFECTLY well-formed (recognized group, supported qualifier, byte-exact declared length, correct CRCs) or the whole response drops; no partial tolerance. (3) byte-constant framing holds ONLY for in-frame padding (within one link frame, LENGTH ≤ 255); crossing a link-frame boundary makes transport SEQ response-dependent. (4) capped by master max receive fragment (~2048 default — confirm harness config).

## 1. Frame structure / length fields / CRCs
Three layers in the TCP payload. Crux: **the application layer has NO fragment-length field** — objects are parsed until the reassembled stream is exhausted, so trailing bytes are NOT ignored, they are re-parsed as another object header.
- **Data-link (FT3):** header block 10 B (`05 64` | LENGTH(1) | CONTROL(1) | DEST(2 LE) | SRC(2 LE) | CRC(2 LE)); data blocks ≤18 B (≤16 user octets | CRC(2 LE)). LENGTH counts CONTROL+DEST+SRC+user = 5+user, range 5–255 → **max 250 user octets/link frame**. CRC-16/DNP: poly 0x3D65 (reflected 0xA6BC), init 0x0000, final XOR 0xFFFF, little-endian (confirmed `dnp3_crc.py` self-test vs captured header).
- **Transport:** one octet/link frame, first user octet: FIN(b7)|FIR(b6)|SEQ(b5..0). Segments one app fragment across link frames.
- **Application (response):** APP CONTROL (FIR/FIN/CON/UNS/SEQ) | FUNC=0x81 | IIN(2) | object headers. Object header = group(1)|variation(1)|qualifier(1)|range-or-count. NO object body length field — body length = point_size(group/var) × count(range/qualifier).

What must change to append filler: link LENGTH (+= user octets, saturates 255) YES; link header-block CRC (LENGTH changed → 256-entry precomputed table) YES; CRC per appended 16-octet block (constant if content constant) YES; last PARTIAL block CRC (if extended, content-dependent — AVOID by appending only on a block boundary); transport octet(s) only if crossing a link frame (new frames: FIR/FIN/SEQ=prev+1 mod 64, response-dependent); application control UNCHANGED (filler stays inside the same app fragment — add objects, not a new fragment); real-data object headers UNCHANGED. **Distinction: app-layer FIN/FIR (multi-FRAGMENT) untouched; only transport-layer FIN/FIR/SEQ (link SEGMENTATION) change, and only if padding pushes past 250 octets.**

## 2. Why arbitrary / "skip-me" filler is NO (rig master source)
`APDUParser.cpp`: (a) **two-pass fail-closed** — pass 1 validates the ENTIRE APDU with no delivery; only if OK does pass 2 deliver → ANY parse error anywhere discards ALL measurements incl. the real reading. (b) **unknown object → whole-fragment reject** — `if (GV.enumeration == UNKNOWN) return UNKNOWN_OBJECT;`. Arbitrary bytes read as group|var|qual → unrecognized → UNKNOWN_OBJECT → dropped.
- Reserved/unsupported "skip" object: NO — DNP3 has no skip-unknown; can't skip an object whose body length isn't computable.
- Duplicate real measurement object: UNSAFE — constant block = stale/wrong values delivered as real SOE data (semantically corrupting).
- Qualifier/range tricks: the legit path is declaring filler POINTS via a supported qualifier — exactly what the octet string does. Unsupported qualifier → UNKNOWN_QUALIFIER (also fail-closed).
- Layer: application only (link/transport have no padding unit; extra octets reassemble into the app stream and re-parse as objects).

## 3. Group 110 Octet String — the unique escape hatch (three source facts)
(i) **Always recognized** — `GroupVariationRecord.cpp`: any variation of group 110/111/112/113 → `Group110Var0`, never UNKNOWN. (ii) **Self-describing length** — `RangeParser::ParseRangeOfOctetData`: `size = variation × count`; consumes exactly `variation` octets/point → subsequent objects stay aligned (variation 0 rejected INVALID_OBJECT "requests only" → use variation 1–255). (iii) **Delivered, whitelist-clean, inert** — `MeasurementHandler`: `IsAllowed(...) return true` (never whitelist-rejects); dedicated octet-string handlers for range + prefix qualifiers; delivered to ISOEHandler as an opaque blob, semantically inert (master doesn't act on it like a binary/analog/counter measurement).
Net: g110, variation 1–255, supported qualifier, byte-exact length, correct CRCs → parses OK both passes, passes whitelist, delivered inert, real reading NOT dropped. Source-confirmed for opendnp3-community/pydnp3.
Supported qualifiers (`APDUParser::ParseQualifier`): 0x00 (1-octet start/stop), 0x01 (2-octet start/stop), 0x07/0x08 (count), 0x17/0x28 (count+index prefix). NOT 0x06 ALL_OBJECTS (request-only). Prefer 0x00 (smallest header).

## 4. Constant-block + repetition feasibility
Content constant; framing metadata is the constraint. Repetition is parser-safe: duplicate indices legal (repeating start=stop=0xF0 delivers N octet strings at 0xF0, parsed without error, handler called N times); no global object count to overflow; master doesn't set IIN.
- **In-frame padding = FULLY compile-time constant** (LENGTH ≤ 255, ≤250 user octets total): only LENGTH octet, header-block CRC (256-entry table), constant appended data-block CRC(s) change. Budget = 250 − current final-frame user octets ≈ up to ~245 octets.
- **Multi-frame padding = NOT fully constant**: new frames' transport SEQ = prev+1 mod 64 (response-dependent increment); original final frame's FIN=1 must clear to 0 (re-CRCs an existing block, content-dependent). Still Tofino-feasible but light per-packet arithmetic, not a pure constant.
- **Better-scaling alternative (no duplicate indices):** one aggregated octet-string with a range — `6E 01 00 <start> <stop> <run of constant octets>` — variation 0x01 (1 byte/point) over a reserved band → up to ~245 unique-index filler octets in ONE header, all-constant body (every full 16-octet block byte-identical → constant CRC), header overhead paid once.
- **Fragment ceiling:** OpenDNP3 default master maxRxFragSize ~2048 (confirm harness). Above it → multi-APPLICATION-fragment → changes app FIR/FIN + requires per-fragment CONFIRM (out of scope). Keep target ≤ maxRxFragSize.

## 5. Failure modes + IDS
- Application: NO app NAK; parse error → silently discard whole fragment + WARN log. If outstation set CON bit, master won't CONFIRM the unparsable fragment → outstation times out/RETRANSMITS — the loudest observable symptom to watch on the rig.
- Link: bad block CRC → frame discarded at link layer. So Tofino CRCs must be correct.
- **Passive Zeek dnp3 IDS:** repo's default dnp3.log records only fc_request|fc_reply|iin → a size-normalized-but-structurally-VALID response is INVISIBLE to default Zeek (also why size-fingerprinting works despite Zeek — it isn't logging size). Residual: Zeek binpac walks objects internally; g110 coverage uneven in older binpac → a length/qualifier mismatch could raise a binpac-exception weird. Confirm empirically vs the Zeek version in `zeek_run/`. IDS-clean is kept by a VALID object (recognized g110, supported qualifier, exact length, correct CRCs).

## 6. Verdict table + empirical confirmations
Arbitrary bytes NO · reserved "skip" object NO · duplicate measurement UNSAFE · **Group 110 Octet String CONDITIONAL YES** · constant repeatable block YES in-frame / multi-frame needs transport-SEQ arithmetic · IDS-clean YES for default Zeek (confirm binpac g110).
Must confirm empirically on the rig BEFORE building the Tofino path: (1) append the §3 filler to a captured READ response (new byte-modifying mode, explicitly GATED) → master SOE for REAL points byte-identical to baseline, no parse/CRC WARN, CONFIRM still appears, 0 retrans/reset (same bar as existing rig runs). (2) SOE side-effect: does run_master's handler record octet strings (extra rows at 0xF0–0xFF to filter, or dropped if no OctetString overload). (3) read maxRxFragSize, keep target under it. (4) run padded pcap through zeek_run/ → check weird.log for g110/binpac exception. (5) cross-master: source guarantee is OpenDNP3/pydnp3 ONLY; commercial masters (SEL/ION/AB) need per-master g110 check — a master without g110 → UNKNOWN_OBJECT-rejects → defense degrades to config approach.
Fallback if a target master rejects strict append: expose a benign octet-string point in the OUTSTATION's Class-0 map (configured always-read filler point), normalize by how many are read — every byte spec-native for every master, at the cost of touching outstation config instead of the Tofino.

## SCOPE NOTE
This append is byte-MODIFYING (recomputes LENGTH + CRCs) → OUTSIDE the current split-harness phase rule ("No CRC recompute. No DNP3 field/length modification."). Legal DNP3 + rig-testable, but a NEW explicitly-gated phase, not the current CRC-boundary-splitting line.

## Source files
opendnp3-community: `cpp/lib/src/app/parsing/APDUParser.cpp` (two-pass, UNKNOWN_OBJECT reject) · `app/GroupVariationRecord.cpp` (g110 always-recognized) · `app/parsing/RangeParser.cpp` (octet length = variation×count) · `master/MeasurementHandler.h` (whitelist-open, octet handlers) · `app/parsing/ParseResult.h`. DNP3 repo: `dnp3_split_harness/dnp3_crc.py` (CRC params self-tested) · `map_response.py` (frame offsets) · `Traffic Trace/dnp3.log`, `broscript/weird.log` (Zeek scope).
