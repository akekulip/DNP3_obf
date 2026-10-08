# Hardware feasibility and cost of the common size-pattern options (Phase B input)

Scope: the hardware-feasibility and cost half of the Phase B scoring table. This document does not
score leakage; a parallel analysis does that. It does not pick the final pattern. All sizes are
**TCP-payload bytes** unless a value is explicitly marked as Ethernet-frame bytes
(`INTEGRATION_CONTRACT.md` §2). No hardware was contacted; the only new evidence is a set of local
compile-only probes (§6).

## 1. Resolved facts

### 1.1 The payload49 `(dofs, total_len)` pairs

The pairs in `RRC_DESIGN.md` §3 and the parser of `defense4_rrc_kernel.p4` (`9ffa9102`,
`parse_tcp`, the `dl_p49`/`opt4_p49`/`opt8_p49`/`opt12_p49` states) are **TCP data offset (32-bit
words) and IPv4 total length**, with `total_len = 20 (IPv4, IHL 5) + 4*dofs + 49`:

| dofs | TCP header | IPv4 total_len | TCP payload |
|---:|---:|---:|---:|
| 5 | 20 | 89 | 49 |
| 6 | 24 | 93 | 49 |
| 7 | 28 | 97 | 49 |
| 8 | 32 (NOP,NOP,timestamp) | 101 | 49 |

They are not DNP3 application bytes and not a second size target. Every pair describes the same
49-byte TCP payload, and every pair is compatible with a 49-byte common target. The physical relay
case was dofs 8, total_len 101 (`RRC_HW_RESULTS.md`, measured values).

Unit trap to remember: the current Case 4 sources match `ip.len == 97` for the 57-byte response with
dofs 5 (`20+20+57`). The value 97 also appears in the payload49 table, where it means dofs 7 and 49
bytes. Any combined parser must key on `(dofs, total_len)` together, never on `total_len` alone.

### 1.2 DNP3 byte arithmetic used below

A DNP3 link frame is a 10-byte header (including its CRC) followed by user-data blocks of up to 16
bytes, each followed by a 2-byte CRC. TCP payload = 10 + user + 2·ceil(user/16).

The G12V1 CROB body is 11 bytes: control code (1), count (1), on-time (4), off-time (4), status (1).
**A CROB has no quality-flags field.** The status byte is the only per-point status, and it is zero
in a request. Quality flags belong to static/event point objects (for example G1/G10) and only
appear in READ responses. The index prefix is 1 byte under qualifier `0x17` and 2 bytes under
`0x28`.

| Message | Construction | App bytes | User (tp + app) | TCP payload | Source |
|---|---|---:|---:|---:|---|
| Native SELECT/OPERATE request | ctrl, func, `0C 01 28 01 00`, idx16, CROB11 | 20 | 21 | **35** | `case4_padding.expand_control` accepts exactly `len(user)==21`, header `0c01280100` |
| Native SELECT/OPERATE response | + IIN (2) | 22 | 23 | **37** | derived; matches 57 − 20 below |
| Case 4 padded request | + separate `0C 01 28 01 00`, idx16, CROB11 (18 B) | 38 | 39 | **55** | `CASE4_SOFTWARE_EVIDENCE.md` / prompt §2.6 |
| Case 4 padded response | 22 + 18 | 40 | 41 | **57** → `[28,29]` | same |
| Historical 2-CROB SELECT request (master-built) | `0C 01 17 02`, 2×(idx8 + CROB11) | 30 | 31 | **45** | `RRC_REQUEST_PROFILES.txt` |
| Historical 2-CROB SELECT response | + IIN | 32 | 33 | **49** → `[28,21]` | `READSBO_NORMALIZATION_RESULT.md` ("32 B G12 echo") |
| Historical READ request (23-pt G10V2) | | | | 20 | `RRC_REQUEST_PROFILES.txt` |
| Historical READ response (23-pt G10V2) | ctrl, func, IIN, `0A 02 00 00 16`, 23 B | 32 | 33 | **49** | `RRC_HW_RESULTS.md` |

### 1.3 Is 49 too small for SELECT/OPERATE?

**No.** The native single-CROB control response is **37 B**, so it fits inside 49 B with no loss of
real fields. The obstacle is different: no padding construction that preserves the native object's
exact bytes lands on exactly 49.

- Going from 37 to 49 needs +12 TCP bytes, which is exactly +10 application bytes (user 23 → 33).
- A separate G12V1 header object, as the current codec builds it, costs at least 16 application bytes
  (`0x17`/count 1, or a `0x00` start-stop range) or 18 (`0x28`). It overshoots: 37 → 55 or 57.
- Raising the native object's count from 1 to 2 under `0x28` adds 13 application bytes (user 36),
  which gives **52**, not 49.
- The historical 49 came from a **master-built** 2-CROB `0x17` command. Reproducing it in the switch
  would mean rewriting the native object header: qualifier `0x28` → `0x17` (lossless only while
  index < 256) and count 1 → 2. That contradicts the current codec invariant ("the original object is
  never reconstructed"). It is a correctness and policy decision, not an ASIC limit.
- Exactly +10 application bytes is reachable with a different object type, for example one G41V2
  analog-output block under `0x28` (5 + 2 + 3), or G41V3 under `0x17` (4 + 1 + 5). **Unverified and
  probably risky:** whether the outstation (SEL-751) accepts a mixed CROB + analog-output SELECT and
  still echoes the object at full length is an endpoint question I did not check. It is listed only so
  the endpoint owner can rule it in or out.

**The smallest common response size that preserves every native control field is 37 B** (no
padding). The smallest common size reachable with the current preserve-native-bytes construction is
**55–57 B**. Any READ target is set by the master's poll definition (point count), not by the switch.
For example, a 13-point G10V2 READ gives a 37 B response and a 31-point read gives 57 B. That is
arithmetic only; whether the operator can choose the poll is outside this analysis.

## 2. What actually constrains the carve (applies to A, B, C)

Both carve implementations in the repository use the same mechanism, and the cut is a compile-time
constant in both:

- `9ffa9102:defense4_rrc_kernel.p4` (silicon-proven): 49 → `[28,21]`. The egress parser selects on
  `egress_rid` and extracts `dnp3_dl`(10) + `blk0`(18) + `blk1`(18) + `res3`(3). The RID-1 and RID-2
  actions invalidate the other window, subtract a constant from `total_len`, add a constant to
  `seq` (RID 2), and clear PSH/FIN on the prefix. The deparser `Checksum` recomputes the IPv4 and TCP
  checksums over the emitted fields, options included.
- `case4_architecture/protocol/carving.p4` (`evidence/carving_01`, local 9.13.1): 57 → `[28,29]`,
  the same structure with a `rendering` table keyed on `egress_rid`. **Ingress 7 / egress 3 stages,
  critical path 4.** The 7 ingress stages are the optional in-switch DNP3 CRC validator (four CUSTOM
  CRC-16 hashes plus a profile match). The carve itself is egress-only.

Consequences:

1. **Choosing a new fixed cut is a parameter change, not a new mechanism.** You change the header
   widths and three constants. The cut does **not** need to sit on a DNP3 CRC-block boundary. Payload
   bytes are extracted into fixed-width headers at whatever byte boundary is required. My probes
   compile cuts at 9, 18, 19, 26 and 38 (§6). The `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md` (`2ce9910a`)
   point that checksum recomputation is not the blocker holds here too: the checksum is already
   recomputed per child.
2. **The binding cost of a carve is PHV, not stages.** Every carved payload byte must be in PHV,
   because the deparser checksum and the selective emit both operate on PHV fields. Egress stages
   stayed at 3 in every probe.
3. **The hard blocker is unchanged and is a different thing.** `SIZE_SPLIT_PAD_SHAPING_ANALYSIS.md`
   §3 rules out partitioning *arbitrary* payload at a *runtime* offset into a *runtime-variable*
   number of packets. RRC never does that. The cut is fixed, eligibility is an exact parser match on
   a finite `(dofs, total_len)` set, and the child count is fixed by the PRE group. A finite set of
   compile-time profiles chosen by size and RID is feasible (§6). An unbounded set of input sizes, or
   a cut that depends on payload content, remains infeasible.
4. **Splitting cannot equalize different totals.** The observer sees TCP sequence numbers (contract
   §1), so the sum of child payloads (49 vs 57) stays visible whatever the cut. The `[28,21]` versus
   `[28,29]` mismatch is therefore a **total-size** mismatch. Only padding, or a master-side choice of
   request content, can close it; the cut cannot. This is why Option C on its own does not solve the
   problem (§4).
5. **Order is a separate, open requirement.** The historical captures recorded wire arrival `[21,28]`
   while TCP sequence order was `[28,21]` (prompt §2.5). This applies equally to every carve option,
   and it gets harder with 3 or more children. Its cause (capture, PRE L1 node order, or something
   else) is unresolved, and nothing here resolves it.

## 3. Integration constraint shared by every option

The master-facing ports (`dp9`, and `PORT_RELAY = 9w64` on the relay side) are both in **pipe 0**
(port ID bits [8:7]). On a Tofino-1 the carve runs in the egress of the pipe that owns the output
port, so any carve lands in pipe 0's egress, next to the N + final-emitter program.

`installed_nf_05` (SDK 9.13.2, `out/p0/logs/phv_allocation_summary_0.log`): ingress 12/12, egress
4/12. Normal PHV containers used: 8b 39/64, 16b 50/96, **32b 62/64**. Tagalong collections are
mostly full. About 1,000 normal-PHV bits remain, nearly all in 8b/16b containers.

- **Egress stages:** a carve adds about 3 egress stages to a 4-stage egress. The budget is 12, so
  this is not a stage risk (inferred, because the two programs have not been compiled together).
- **PHV:** the real risk. A 49–57 B carve needs about 392–456 payload bits plus small metadata, and
  the remaining room is mostly 16b/8b containers. **It plausibly fits, but this is unverified.** The
  contract forbids "concatenate fitting components and assume the result fits", so this needs one
  combined compile before any option is called feasible.
- **Fallback if pipe 0 PHV fails:** send the PRE replicas to a port in another pipe, carve there, and
  recirculate to dp9. That adds a pass per child plus a TM crossing, and it makes the order problem
  (§2.5) worse. It is a cost, not a blocker.

## 4. Feasibility and cost table

Legend: **HB** = hard ASIC blocker; **CT** = cost tradeoff (feasible, at the stated price); **P** =
correctness or policy obligation (not the ASIC). Stage and PHV numbers come from the cited compiles;
"inferred" marks anything not compiled in the combined target.

| | Option | New P4 mechanism beyond proven? | Data-plane cost (carve side) | Padding/transport cost | Hard blocker? | Main risks |
|---|---|---|---|---|---|---|
| **A** | Converge both roles on 49 → `[28,21]` | **None for the carve.** Silicon-proven (R1–R6), with the READ+SELECT `[28,21]` parity already captured. Control needs +12 TCP bytes to reach 49 | Egress ~3 stages, ~392 payload bits PHV, 1 MGID / 2 L1 nodes (proven) | Reaching 49 from native 37 needs an in-stream insertion of +10 application bytes. That is **not achievable with a separate G12V1 object** (≥16 B). It requires either rewriting the native header (`0x28`→`0x17`, count 1→2; **P**) or a non-CROB filler object (**P**, endpoint unverified). Any insertion inherits the full M sequence/ACK/window mapper, which **does not currently fit** (`M_RECIRCULATION_VERDICT.md`; open, not refuted in general) | No ASIC blocker. The barrier is P (no field-preserving 49 B construction with the current codec) | Endpoint acceptance of the filler; mapper fit |
| **A′** | Converge on the native 37 B control size (no padding); READ poll chosen to give 37 B; optional split, for example `[28,9]` | No (same carve; or no carve at all, since equal totals need no split to be equal) | 0 to ~3 egress stages; ~296 bits PHV if a carve is kept | **None in the switch.** No insertion, so no mapper | None | Depends on an operator/master-side READ definition (**P**). The request direction still differs (READ 20 B vs control 35 B); that is outside this response-side carve. Leakage is for the parallel analysis |
| **A″** | Converge on 57 → `[28,29]`, matching READ (31-point poll) to 57 | No (the 57 carve is already compiled, `carving_01`) | Egress 3 stages; ~456 bits PHV | Control keeps the current 35→55 insertion and its mapper (already required by the current Case 4 profile, still not fitted) | No ASIC blocker. Mapper fit is open | The same mapper risk the current plan already carries; READ poll choice (**P**) |
| **B** | N-state shared pattern (L = 3–6), with each finite input size mapped to fixed child vectors | Multiple **compile-time** profiles selected by `egress_rid` (plus an ingress size match to choose the MGID). **Not** a runtime offset. Compiled locally (§6): 6 profiles, including 3-child ones | Egress **3 stages, constant** across 1→6 profiles. PHV ≈ 8×(sum of profile bytes) with naive per-profile headers (2,701 bits for 6), but ≈ 8×(largest profile) with a shared chunk refinement (677 bits for 6, vs 565 for 1). Egress parser TCAM 23→47 rows; FDE 42→48. PRE: one MGID per child-count shape, K same-port L1 nodes (K=2 proven on silicon; K=3 **not** silicon-tested) | Any state larger than the real chunk needs padding, and so the mapper (as in A). Chaff, if the pattern needs it, is a separate pktgen/queue cost not assessed here | No, as long as the input-size set is finite and cuts are fixed. **HB** only if the pattern needs payload-dependent or unbounded cuts | 3+ children worsen the ordering problem (§2.5), add wire bytes per extra child (~54 B Ethernet/IP/TCP headers each), and add PRE nodes |
| **C** | A different common fixed cut | No. Any byte boundary compiles; CRC alignment is not required (§6) | Same as A (~3 egress stages, PHV ≈ total) | Same as A. **A cut alone cannot equalize 49 vs 57 totals** (§2.4) | None | Only meaningful once totals are already equal; then it is a free parameter for the leakage analysis |
| **D** | Single uniform pad target, no split | DNP3-valid in-stream padding. Compiled as `protocol/padding.p4`: **11 ingress stages standalone** (`evidence/padding_02`), and `selected_padding.p4` 12/12 (`evidence/selected_01`). It must regenerate the DNP3 header and data CRCs because block boundaries move. Deparser-constant filler is cheap in stages (`queue_microbench`: PHV 9.38%, pad headers 64/192 B), but it only gives byte-*valid* DNP3 if the filler is a whole constant frame or block | Ingress-heavy (11–12 stages standalone in a pipe whose ingress is already full; needs its own pipe, which is M's role today). Egress carve not needed | Full mapper (seq/ACK/window translation, retransmission of inserted tails). The old `single128` target is **Ethernet-frame bytes**: 128 − 14 − 20 − 20 = **74 B TCP payload at dofs 5**, or 128 − 66 = **62 B at dofs 8**. Its `fits_existing_p4` flag described a synthetic UDP microbenchmark, not DNP3/TCP. Ethernet-trailer padding does not change `ip.len`/`tcp.len` and therefore does not count (prompt §3) | No ASIC blocker in principle. The **mapper fit is unresolved** and is the gating cost | Highest cost of all options; the "parsing observer removes cover" finding (`DESIGN_DECISION_v2.1.md`, scoped) bears on a whole-frame constant filler |
| **E** | Keep per-role profiles (READ 49 `[28,21]`, control 57 `[28,29]`) | No | Two carve profiles: egress 3 stages; PHV ~456 bits shared-chunk (v5: 631 bits including headers) | Status quo: the control insertion and mapper stay | None | **Cheap, but it does not solve the problem.** The totals differ, so READ and control remain separable by size |

## 5. Ranked recommendation (hardware angle only)

1. **A′ — common native-size target with no switch padding** (37 B for both roles, carve optional).
   It needs no new mechanism, no in-stream insertion, no sequence/ACK mapper, and at most the proven
   3-stage egress carve. It is the only option that avoids the unresolved M mapper entirely. Its
   price is a master/operator constraint on the READ definition and an unchanged request-direction
   difference. Whether those are acceptable belongs to the leakage scoring and the supervisor.
2. **A″ / A at a common padded total with a fixed `[28,·]` cut** (57 B is the one the current codec
   already reaches). The carve side is proven or compiled. The cost is entirely the insertion
   mapper, which the current Case 4 plan carries anyway and which has not been fitted. Exactly 49 is
   **not** reachable with the current field-preserving construction (§1.3); prefer 55/57 over
   inventing a header rewrite.
3. **B — a small finite N-state set of fixed profiles.** Feasible: egress stages stay constant and
   PHV stays near the largest profile if shared chunks are used. Rank it below A only because 3+
   children are not silicon-tested, add wire bytes and packets, and make the open ordering problem
   harder. Any padding states inherit the mapper.
4. **C** is a free parameter, not a solution. Rank it as a sub-choice of A/B.
5. **D** is the most expensive: an 11–12-stage ingress padding stage plus the mapper. It is not
   blocked by the ASIC, but it is the hardest to fit.
6. **E** is the cheap fallback that leaves the size distinction in place.

Gate for every option: one combined compile of the carve inside pipe 0's egress next to
`installed_nf_05`, which has only 2 free 32-bit containers, before calling it feasible (§3).

## 6. Local compile evidence (scratch only, not committed)

Location: `/tmp/claude-1002/-home-philip-Projects-DNP3/db04a002-eb4e-45b0-ac5b-b5c1bc10aaf5/scratchpad/carve_probe/`
(session scratchpad; artifacts are not in git). Compiler: local `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c
--target tofino --arch tna -g -o out <probe>.p4` (9.13.1, not the switch's 9.13.2).

Each probe is carve-only: an ingress size→MGID table and an egress RID interpreter with deparser
IPv4/TCP checksum recomputation, supporting dofs 5 and 8. The probes are not integrated with N/M/E/T
and were not run in the model.

| Probe (generator) | Profiles (TCP-payload B → children) | Exit | Ingress / egress stages | Normal PHV bits (of 4096) | Egress parser TCAM rows |
|---|---|---:|---|---:|---:|
| `v1_p49` (`gen.py`) | 49→[28,21] | 0 | 1 / 3 | 565 | 23 |
| `v2_p49_p57` | + 57→[28,29] | 0 | 1 / 3 | 1,025 | 28 |
| `v3_p49_p57_p57x3` | + 57→[19,19,19] | 0 | 1 / 3 | 1,487 | 31 |
| `v4_six_profiles` | + 37→[28,9], 52→[26,26], 61→[28,18,15] | 0 | 1 / 3 | 2,701 | 51 |
| `v5_shared_p49_p57` (`gen2.py`, shared chunks) | 49→[28,21], 57→[28,29] | 0 | 1 / 3 | 631 | 28 |
| `v6_shared_six` (`gen2.py`) | the six profiles of v4 | 0 | 1 / 3 | 677 | 47 |

One finding came out of the first attempt. Selecting on `(ip.len, egress_rid)` in a single egress
parser state fails with "Ran out of parser match registers … 1x16b, 2x8b". Select on `egress_rid`
alone, as the historical RRC kernel does, and gate size in ingress.

SHA-256: `gen.py` 940169e2…d5b09d, `gen2.py` 9c4e9b06…bbe31; probe sources v1 8e0182ac…, v2
5507c6b7…, v3 5f1ee776…, v4 93480cd0…, v5 cc8a0ada…, v6 2b87a81b…

## 7. Not verified

- CROB/SELECT sizes are **derived** from the codec and the DNP3 framing arithmetic, cross-checked
  against the recorded 35/55/57/45/49 values. I did not decode a new capture.
- Endpoint behavior of any non-G12 filler (G41) and of a rewritten `0x17` header: not checked.
- Fit of a carve inside pipe 0 together with `installed_nf_05`: inferred, not compiled.
- PRE with 3 or more same-port L1 nodes per MGID: compiled logic only; silicon-tested for 2.
- Wire order of carved children: open (prompt §2.5).
- Probe stage and PHV figures are from SDK 9.13.1. The switch uses 9.13.2.
