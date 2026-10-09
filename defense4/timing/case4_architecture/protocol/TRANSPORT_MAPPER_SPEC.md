# Response-side transport mapper: specification

Scope: Option B′ pads an outstation→master DNP3 response in place (49 → 58 bytes for the READ
profile, 37 → 58 for a SELECT/OPERATE echo; `framework/size/case4_pad58b.py`, realized by
`case4_pad58b_wire.p4`). Padding one TCP segment changes the length of the outstation's byte
stream as the master sees it. This document specifies the per-connection sequence/ACK/window
translation that keeps both endpoints' TCP state consistent. It covers outstation→master
responses only, one padded image per original response, and no splitting. It does not cover
request-side padding (the `payload_mapping/` work) or response splitting (a separate work item);
nothing here assumes a segment is unsplit except where marked "one-segment profile".

Reference implementations:

- software model: `framework/size/case4_response_mapper.py`
- tests against the oracle: `framework/tests/test_case4_response_mapper.py`
- P4 realization (padder + mapper in one egress pass): `case4_architecture/protocol/case4_response_path.p4`
- control-plane entries with the same-pipe check: `case4_architecture/protocol/response_path_cp.py`
- correctness oracle (read-only): `framework/size/case4_transport.py` (`RequestLedger`)

## 1. Terms

All sequence quantities are TCP sequence numbers modulo 2^32. "Native" means the outstation's own
sequence space; "wire" means the sequence space the master sees. `s` is a forward segment's
sequence number, `L` its payload length, `Leff = L + FIN`. `a`, `w` are a master ACK number and its
16-bit advertised window. Signed comparisons use serial arithmetic: `x ≥ y` means
`(int32)(x − y) ≥ 0`.

An **image** is the padded replacement of one complete native response frame that occupied the
native range `[e_start, e_end)` (`e_len = e_end − e_start`, 49 or 37). Its wire image occupies
`[ws, we)` with `we − ws = 58` for both profiles; its growth is `d = 58 − e_len` (9 or 21).

## 2. Insertion boundary

The inserted bytes sit at the **native end of the response**, `e_end`. This is the oracle's
convention (`case4_transport.py`: "places each size delta at the native request end"): offsets
inside `[e_start, e_end)` are not shifted individually; the whole native range is *replaced* by the
58-byte image, which starts at the same wire position the native frame would have started at. Every
native byte at or after `e_end` is shifted by the cumulative growth `D` of all images so far.

So for the latest image, with `D_prev = ws − e_start` (growth before it) and `D = we − e_end`
(growth through it):

| native position | wire position |
|---|---|
| `s ≥ e_end` | `s + D = we + (s − e_end)` |
| `s < e_end` (only legal as a replay starting at `e_start`, or a zero-length segment) | `s + D_prev = ws + (s − e_start)` |

The padded image differs from the native frame in more than its tail (link length byte, header
CRC, last user block and its CRC), so no native byte inside `[e_start, e_end)` is ever forwarded on
its own once the image is committed; a forward segment that overlaps the image without starting at
`e_start` and covering the whole frame is dropped (§5).

## 3. Per-connection state and why it is this small

Six registers, one row per connection slot, 200 bits per connection (8 + 32 + 64 + 3 × 32):

| register | width | holds | written by |
|---|---|---|---|
| `mode` | 8 | 0 = native passthrough, 1 = mapped | outstation SYN-ACK only |
| `front` | 32 | `N`, the native frontier (next never-seen native sequence number) | forward segments at the frontier |
| `acct` | 32+32 | `W`, the wire frontier (`= N + D`); `U = W − A`, wire bytes not acknowledged by the latest master ACK `A` | both words: forward at frontier; `U`: reverse |
| `img_end` | 32 | `e_end` of the latest image | forward commit |
| `img_start` | 32 | `e_start` of the latest image | forward commit |
| `img_wend` | 32 | `we` of the latest image (`ws = we − 58`) | forward commit |

There is exactly **one image slot** per connection. A single cumulative offset is not enough: a
retransmission of the latest response must be placed at `s + D_prev`, not `s + D`, and an ACK inside
the latest image must be held back to the image start, which needs both image edges. One slot is
enough because of the commit rule in §4: a new image may only be committed when the master has
acknowledged every wire byte sent so far (`A == W`). At that moment the previous image is fully
acknowledged, so the only packets that could still refer to it are stale in-flight duplicates of
acknowledged data, and those need no exact placement (§5, case F5).

**Compaction / retirement rule.** A commit overwrites the slot. Retirement of the previous image is
implicit and is only permitted when `A == W` (everything acknowledged). There is no separate
retirement event to lose.

**Exhaustion.** Capacity is one unacknowledged image. An eligible response that arrives while
`A ≠ W` (the previous image or any later byte is still unacknowledged) is **refused**: it is
forwarded at native length with its translated sequence number, it advances `N` and `W`, and it is
native forever (its retransmissions can never be committed, because they are below `N`). Refusal
leaks that one response's size; it never corrupts the stream. Under DNP3's strict request/response
discipline the master's next request carries an ACK of the whole previous response, and that ACK
passes the switch before the request reaches the outstation, so refusal only happens after loss or
an application-layer retry, **or** whenever the outstation has a second response in flight before the
master's ACK of the first image reaches the switch: a master that pipelines requests, or an
unsolicited response that crosses a request. Refusal is not a liveness risk in any of these: the next
ACK that covers everything sent brings `U` back to 0 and the next response commits normally (tested:
`test_reordered_older_ack_only_refuses_a_commit`, `test_refused_response_is_native_forever`). The
connection table (16 slots in the P4) is the only other capacity: a connection that gets no slot is
never armed and stays native.

## 4. Commit: exactly once per original byte range

A forward segment commits an image if and only if all of the following hold:

1. the connection is in `mode = mapped` and its per-connection `pad_enable` policy bit is set;
2. the padder's verdict says the segment is **exactly** one complete, eligible, CRC-valid native
   frame of class READ (`d = 9`, `L = 49`) or CONTROL (`d = 21`, `L = 37`), with no SYN, RST or FIN —
   a first transmission that coalesces a frame with further bytes is never committed;
3. `s == N`: the segment begins exactly at the native frontier, i.e. these bytes have never been
   forwarded in any form;
4. `A == W` (`U == 0`): the latest master ACK covers every wire byte sent so far.

`A` is the *latest* master ACK the switch has seen, not a running maximum: the P4 keeps
`U = W − A` because a Tofino-1 stateful-ALU compare takes only one memory operand, and with that
encoding a maximum cannot be taken. A reordered older ACK therefore makes `U > 0` until the next
current ACK; it can only refuse a commit, never permit one.

On commit: `e_start := s`, `e_end := s + L`, `we := (we_old + (s − e_end_old)) + L + d`,
`W := W + L + d`, `N := s + L`. The segment leaves at wire sequence `we_old + (s − e_end_old)` and
is padded.

Exactly-once follows from (3): `N` only moves forward, so a byte range can be "at the frontier" on
its first transmission only. A retransmission (`s < N`) never commits; a refused range is never
committed later; repeated READs commit one image each, on their own first transmissions.

A forward segment with `s > N` (bytes the switch never saw before `s`) is dropped; the outstation's
retransmission of the missing bytes arrives at `s == N` and the stream proceeds. This keeps `N`
and `W` exact without gap accounting.

## 5. Forward (outstation → master) segments

Evaluated in order, with `q = s − e_end`, `p = s − e_start`:

| case | condition | wire sequence | payload |
|---|---|---|---|
| F1 commit | §4 holds | `we_old + q` | padded image |
| F2 translate | otherwise, `q ≥ 0` | `we + q` | native |
| F3 zero length | `q < 0`, `Leff = 0` (keepalive, pure ACK) | `ws + p` | none |
| F4 replay | `p = 0`, `q + Leff ≥ 0` (starts at the image and covers it), leading frame eligible | `ws` | padded image, then any native suffix |
| F5 stale | `q < 0`, `p + Leff ≤ 0` (wholly before the image) | `ws + p` | native |
| F6 drop | anything else: partial overlap with `[e_start, e_end)`, or `s > N` | — | — |

F4 is how retransmissions reconstruct the same wire image: the native retransmission is the same
bytes, the padder is a pure function of those bytes, and the mapper places it at the same `ws`. A
replay may carry more than the frame: a FIN, or native bytes after it when the outstation collapses
several unacknowledged segments into one retransmission (Linux `tcp_retrans_collapse=1`, the
default). The suffix lands at `e_end + D`, exactly where the image ends, which is what the oracle
produces for the same merged segment. A replay whose leading frame is not eligible (e.g. corrupted
in transit) is dropped, never passed native. **The Tofino-1 realization supports the whole frame and
the whole frame + FIN, but drops a replay carrying native suffix bytes** (counted as
`OUT_DROP_MERGED`, §10); the software model reproduces that with `merged_suffix_ok=False`.
F5 is exact (equal to the oracle) when `s` lies after the previous image; for older stale
duplicates the wire end is still at or below the master's `rcv_nxt` (all of it was acknowledged
before the commit), so the master discards it and re-ACKs.

The P4 does not compare retransmitted payload bytes with the original (it stores none). TCP
guarantees retransmissions carry the same bytes; the oracle's conflicting-bytes error has no P4
counterpart.

## 6. Reverse (master → outstation) ACKs and both window edges

`U := W − a` (i.e. `A := a`) on every reverse segment with the ACK flag. Then with `r = a − we` the
left edge maps through the monotone inverse

| range of `a` | native ACK |
|---|---|
| `a ≥ we` (`r ≥ 0`) | `e_end + r` (= `a − D`) |
| `ws ≤ a < we` (`−58 ≤ r < 0`) | `e_start` (withhold the whole response) |
| `a < ws` | drop the segment (stale or reordered ACK) |

The **right edge** `a + w` goes through the same inverse, and the native window is the difference:

| left | right `r2 = r + w` | native window |
|---|---|---|
| `r ≥ 0` | — | `w` (unchanged) |
| `−58 ≤ r < 0` | `r2 < 0` (right edge inside the image) | `0` |
| `−58 ≤ r < 0` | `r2 ≥ 0` | `min(r2 + e_len, 65535)` |

**ACKs inside the image.** The oracle withholds one native byte: an ACK in the inserted tail maps to
`e_end − 1`, and an ACK inside the native-length part maps to `a − D_prev`. Both make the
outstation retransmit a *suffix* of the response, and the oracle replays the matching suffix of the
cached image. A P4 pipeline cannot regenerate an arbitrary suffix of the image (it would need the
image bytes per connection and a parse path per suffix length). The mapper therefore withholds the
whole response instead: any ACK in `[ws, we)` maps to `e_start`, so the outstation's retransmission
is always the whole native frame (case F4), which the padder reconstructs exactly. This is a
deliberate, tested refinement of the oracle, not a divergence in safety:

- outside `(ws, we)` the native ACK and window equal the oracle's exactly;
- inside, the native ACK is ≤ the oracle's and both are < `e_end`, so the outstation never retires a
  response whose image the master has not completely acknowledged (no stranded tail);
- the inverse is monotone in both edges, so the native window is never negative and the native
  right edge never exceeds the master's real right edge translated to native. The 65535 clamp only
  lowers the right edge.

Zero windows: a zero master window stays zero whenever `r ≥ 0`; with the left edge inside the image
it is zero until the master's right edge passes `we`.

## 7. Wraparound

All state and arithmetic are modulo 2^32 and all ordering tests are serial (`int32` of a
difference). Correct as long as every compared pair is within 2^31 of each other: the outstation's
unacknowledged span plus 58, and the master's window, are many orders of magnitude below that.
Equality tests (`s == N`, `A == W`, `p == 0`) are exact at any distance.

## 8. Lifecycle, policy and unsupported shapes

- **Arming.** Only the outstation's SYN-ACK arms a slot. If its TCP header carries exactly one
  option and it is MSS (`offset = 6`, kind 2, length 4), the slot becomes `mapped` with
  `N = W = A = e_end = we = ISN + 1` and `e_start = ISN + 1 − 58` (a virtual zero-growth image, so
  the formulas of §2 are the identity before the first commit). Any other SYN-ACK (window scaling,
  SACK-permitted, timestamps or anything else) sets `mode = native`: that connection is passed
  untouched for its whole life and never padded. A retransmitted SYN-ACK *before any data* re-arms
  with the same ISN (idempotent). A SYN-ACK arriving after data has flowed (a late duplicate, or a
  new connection reusing the slot) re-arms and discards the live mapping; on the direct links of this
  deployment a late duplicate cannot occur, and stragglers of an old connection are not quarantined
  (profile limit).
- **Mapped connections drop what they cannot translate.** On a mapped connection, any segment that
  is not a plain IPv4 (IHL 5, unfragmented) TCP segment with a 20-byte header (or a SYN) is
  dropped, as are F6 and stale-ACK cases. Passing such a packet native would put an untranslated
  sequence or ACK number into a stream whose offset is already non-zero. Dropping is always safe in
  TCP terms (the sender retransmits; ACKs are cumulative).
- **Policy off mid-connection.** `pad_enable` only gates new commits (§4 condition 1); it is changed
  by modifying the `conn` entry, never by deleting it (`Registry.set_enable`). Translation
  is never switched off on a live mapped connection: turning it off would re-expose native
  numbering to a peer that has been seeing wire numbering. A connection slot may be removed only
  after the connection has ended (FIN/RST seen and the control plane has observed the close) or
  when `W == N` (zero cumulative growth) and `A == W`.
- **FIN/RST.** FIN occupies one sequence number (`Leff = L + 1`) and is translated like data; it
  never commits. RST is translated like any other segment. State is reset only by re-arming.
- **Outstation ACK field / master SEQ field.** Untouched: only the outstation's byte stream changes
  length.
- **Same pipe (hard requirement).** All six registers live in the egress pipeline, and Tofino
  registers are per pipe. Forward packets leave on the master-facing port and reverse packets on the
  outstation-facing port, so both ports must be in the same pipe; otherwise the reverse side never
  sees the armed image (ACKs pass untranslated, corrupting the outstation's view) and the forward
  side never sees `U` return to 0 (every response after the first is refused).
  `response_path_cp.Registry` builds the connection rows *and* the `Ingress.forwarding` rows that
  decide those egress ports from the same `Endpoint` objects, so the checked ports are the installed
  ports; it raises `PipeMismatch` for a cross-pipe pair before writing anything. On this rig the master
  is dev_port 9 and the outstation relay leg dev_port 64
  (`~/Projects/Tooling/tofino_25g_connectivity_map.md`): both pipe 0. A forwarding entry installed
  outside the registry is not seen by this check; the registry is the only supported writer.
- **Control-plane invariants (`response_path_cp.Registry`).** All rows of a connection are validated
  against what is installed before any write (slot, 4-tuple, host pair, forwarding consistency); a
  switch refusal mid-install deletes the rows already added, so no partial install survives. One mapped
  connection per (master, outstation) host pair, because `odd_ip_t` keys on the pair: a master that
  reconnects from the same IP is refused until the old slot is removed. Policy changes go through
  `set_enable`, which modifies the `conn` entry and never deletes it. `remove` enforces the retirement
  rule below: the caller asserts the connection closed, or passes a register readback with `W == N`
  and `U == 0`. Forwarding rows are reference-counted across slots on the same port pair.
- **Mapper tables are not keyed on `mode`.** On a native-mode or unconfigured connection the register
  tables still run and update their (unused) rows; only the classifiers, `img_wend` and the pad gate
  are gated on `mode`, so nothing on the packet changes. Harmless today, but "native means untouched"
  holds for packets, not for register contents; a re-arm resets the row.
- **Integration assumptions (for combining with the timing/queue mechanism):** the mapper is keyed on
  the TCP 4-tuple, not on the egress port or pass, so any recirculation, mirror copy or hold loop that
  sends the same segment through this egress pipeline twice advances it twice (a second frontier
  pass, a second ACK update). A combined design must run the mapper on exactly one pass per wire
  segment, or mark the other passes and skip it. Policy-off and reset must use `set_enable`, never
  delete the `conn` entry.
- **Profile limits, not handled:** a one-byte persist probe of *already-sent* image bytes overlaps
  the image and is dropped (stacks that probe with a zero-length segment at `snd_una − 1`, as Linux
  does, are unaffected; the master's window update then reopens the window); IP-options or fragment
  packets carry no parsed ports, so their slot is found by host pair alone, which assumes one mapped
  connection per (master, outstation) host pair, as in this DNP3 deployment.

## 9. The fused pass: padder and mapper in one egress pipeline

`case4_response_path.p4` contains the `case4_pad58b_wire.p4` padder (parser layout, profile tables,
native-CRC hashes and gateways, transform and output CRCs, unchanged) and the mapper. The frozen,
model-verified `case4_pad58b_wire.p4` itself is not modified. What changed in the fusion:

- **Pad gate.** The transform runs only when the mapper's classifier says commit or replay
  (`m.pad`). A refused response, a CRC-invalid frame, a native-mode connection and an unconfigured
  flow are never padded (model cases `crc_invalid_never_committed`, `refused_response_is_native`,
  `native_mode_never_pads`, `unconfigured_flow_eligible_frame_untouched`). The standalone padder
  pads every eligible frame and must not be deployed on its own.
- **One verdict.** The mapper's commit and replay decisions read the padder's own profile flags and
  native-CRC flags directly; there is no separate stand-in.
- **Parsing.** The leading DNP3 frame is parsed whenever the segment is at least 37 payload bytes
  long, selected by the link length byte, so a merged retransmission's frame is parsed and its
  suffix stays unparsed payload.
- **One TCP checksum.** Every changed frame (translated, padded or both) gets one incremental update:
  the parser residual subtracts seq, window and the old checksum and every header extracted after
  it; the deparser adds back the current seq, the ACK (old ACK removed through `~ack` carried in
  metadata), the window, the TCP-length growth (`len_delta`, 9 or 21) and every frame header. The
  IPv4 checksum is recomputed in full on padded frames.

## 10. P4 realization: measured shape and findings

Final build `evidence/transport_mapper_02/fused_12` (bf-p4c 9.13.1, local SDE): **padder + mapper
in 12 egress stages, critical path 11**, 6 stateful tables, 1 ingress stage (port forwarding). Model
run `fused_12/model_01`: **165/165**; all table rows, forwarding included, come from
`response_path_cp.Registry`, and two cases run its remove/re-install and same-host-pair refusal on the
real BFRT tables. Every output frame is byte-identical to the software model's
expectation, where the padded image comes from the `case4_pad58b` codec and both checksums are
recomputed in full by the driver. Every packet increments exactly the outcome counter the model
predicts, and the six registers equal the model's state at the end. `fused_01`–`fused_09` are the
retained intermediate builds (`fused_10`/`fused_11`: the program before the explicit tail zeroing and metadata pins, 163/163); what each one taught is listed below.

The two standalone builds came first. `evidence/transport_mapper_01` and the top level of
`evidence/transport_mapper_02` are the mapper alone, with 12 egress stages and 111/111 on the model.
Their source is kept only as the snapshot in each build's `source/`, because the fused file
supersedes it (and the standalone role table let an offset-6 non-SYN segment through untranslated).

**Stage fit.** The first fusion (a scratch compile, not retained) placed in 13 stages against a critical path of 11. The reverse tables
were serialized behind the padder's output-CRC tables even though no packet uses both. Making the
reverse branch the `else` of the pad branch, so the compiler can see they are exclusive, and setting
the bookkeeping outcome before the classifiers fit it in 11 (critical path 10). Widening `ip.len`
through an identity hash (below) costs the twelfth. **Headroom is zero**; any addition to this pass
needs a cut first. The outcome counter (`count_t`) is observability only; `settle_t` is not, because
it drops untranslatable shapes on mapped connections and sets `m.result` on paths no classifier
writes.

Register discipline: each register is touched by exactly one table keyed on `(dir, shape)`. Forward
runs `mode, front → acct → img_end, img_start → img_wend`; reverse runs `mode → acct → img_end,
img_start → img_wend` and writes only `acct.hi`, in the same stateful ALU that makes the forward
commit decision. That is what avoids the early-reader/late-writer wall of
`integration/core/M_RECIRCULATION_VERDICT.md`.

Compiler and target facts this work measured, each written into the source with its reason:

- `acct` holds `U = W − A`, not `A`: a Tofino-1 SALU compare takes one memory operand
  (`v.lo == v.hi` fails in the assembler). Hence `A` is the latest ACK, not a maximum (§4).
- A stateful ALU reads at most two PHV fields across all its actions; per-role operands are staged
  into shared metadata (`prep_t`, `derive_t`).
- `rv = 1` in one branch compiles to `output predicate`; its numeric value is not assumed, so every
  `grant` match lists `grant == 0` first and the wildcard second.
- **Parser copies of header fields are wrong on the model and draw no compiler message.**
  `m.x32 = (bit<32>)hdr.ip.len` and the same-width `m.x16 = hdr.ip.len` both loaded the first IPv4
  halfword (`0x4500`) instead (`fused_01`, `fused_03`). Widening goes through identity hashes. A
  16-bit metadata operand in a 32-bit add drew "invalid container action within a Tofino ALU", so
  the window is widened by a hash as well.
- **The deparser checksum adds the containers of absent headers.** An absent header overlaid with
  live metadata (`m.ina`, which holds the ACK) put the arriving ACK's low half into every TCP
  checksum (`fused_04`–`fused_05`). Every payload-header field in the update list is pinned with
  `@pa_no_overlay`, as are the two metadata words in the list that are not live from parse to
  deparse (`len_delta`, `ack_inv`); `mss` (only on never-rewritten SYNs) is left out of the list. A
  header that *was* parsed and is then invalidated (the native tail `rtn`/`ctn` when padded) is a
  different case: its containers still hold the original bytes. bf-p4c inserts hidden
  `egress_reset_invalidated_checksum_fields` tables that zero them, and the pad actions now also
  zero them explicitly (`fused_12`'s `.bfa`: `set hdr.rtn.data_last, 0`, `set hdr.rtn.crc2, 0`,
  `set hdr.ctn.{on_lo,off,status,crc1}, 0`), so the checksum does not depend on how the target
  treats invalid headers.
- **Merged retransmission with a native suffix.** Both growths are odd, so padding moves the suffix
  to the other byte parity and its contribution to the TCP checksum changes from `S` to `swap(S)`.
  The parser never sees those bytes. Measured (`fused_08`): the error is exactly `swap(S) − S`.
  Two attempts to derive `S` from parser checksum engines did not converge (`fused_07`–`fused_09`).
  A scratch debug build (not retained) wrote both engine values into header fields; it showed that the residual already holds the suffix byte-swapped, while the second
  engine's value matched no derivation. So the realization drops such a replay explicitly
  (`OUT_DROP_MERGED`) instead of emitting a bad checksum. Its plain-copy retransmissions still
  complete delivery (model case `plain_copies_after_merge_replay_then_translate`). **Liveness
  consequence:** an outstation stack that *always* collapses a retransmission of an unacknowledged
  image with later unacknowledged bytes would stall the connection. That needs a second response in
  flight behind an unacknowledged image (§3 refusal cases) and a collapsing stack; whether the SEL-751
  stack collapses has not been checked and needs a capture on the rig.
