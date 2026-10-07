# Step 3 design: the ordinary unfragmented control path (placement, interfaces, pinning, tickets, gates)

**Historical design — current execution authority is [PLAN.md](../../PLAN.md),
linked from [HANDOVER.md](../../HANDOVER.md).** The later Task1 source already
implements OPERATE-response association and replay kind12 and repairs foreign-epoch
bank stores. Current evidence and remaining gaps are in the handover. The old
phase3 inspection/one-confirm proposal below is superseded by atomic downstream
pending/commit phases, a real image-ready return, geometry plus ledger publication
before departure, and genuine final terminal. Carry actual expected owner and
captured decoy fields; current replay Work and cached producer identities differ.
Do not execute superseded tickets or treat this note's inferred fits as evidence.

Status: design note, no code, nothing compiled or run for this note. Author role: D3 (design, read-only except this file).
Base: main with the working tree described in the session `gitStatus`. Binding assignment:
`defense4/Codex_Case4_Hardware_Architecture_Prompt.md`. Plan reference: `PLAN.md:37-54` (step 3 scope),
`PLAN.md:55-57` (both boundaries and wrap belong in step 3), `PLAN.md:66` (step 3 test row),
`PLAN.md:106-128` (shared contracts). Authorization context: `defense4/CLAUDE.md` hard rule "Current Case 4 scope
(2026-10-06)": offline code, tests, isolated model work and compiler evidence are authorized; new live padding, SELECT or
OPERATE runs need their own recorded authorization and physical OPERATE is attended-only.

Paths are relative to `defense4/timing/case4_architecture/` unless they start with `defense4/`.
Markers: **[V]** read in a file or evidence directory this session, with file:line. **[I]** inferred, not verified.
Compiler and model numbers are quoted from retained evidence, not re-run.

## 0. Verdict in six lines

1. Step 3 needs three pipes of the Tofino-1 and one new hop pattern. N (connection authority) stays in pipe 0 ingress
   and is already full (12 of 12 stages). The payload roles (padding, two-boundary translation, replay decision,
   carve decision) become a new role M in pipe 1 ingress. The shared image banks and carve rendering sit in pipe 0
   egress (role E), because every front-panel port lives in pipe 0. T (READ timing) takes pipe 2. Pipe 3 is reserved
   for step 4 (assembly).
2. The central new mechanism is a **held pin**: N does not free its WorkRecord at its last pass for control
   packets. It forwards under the pin to M, M and E do their shared-state work, and a small confirm return from E
   frees the pin. This makes "owner/work pin before cache access, no reuse until terminals" literal instead of
   inferred, and it removes the `work_record.p4:9-10` hazard ("No shared bank write may follow a terminal that
   permits reuse").
3. Today N cannot carry the full exchange even in source: it has no binding for the response to OPERATE,
   it hard-codes a 20-byte ACK offset, and the response path was never exercised by the model fixtures
   (section 1, items 6 to 9). These are step-3 prerequisites, not optional repairs.
4. After the first insertion every supported-tuple packet in both directions must leave through M. Today N forwards
   unqualified or busy traffic natively (section 1, item 10), which would corrupt the transformed stream.
5. Feasibility is conditional. Every individual role has a compile or model result; the integration has none.
   The binding unknowns are cross-pipe forwarding, the M stage and PHV fit, the e2e mirror confirm, and physical
   carve order. Nothing here is hardware evidence.
6. Hardware: nothing in this note may run on the switch without the gates in section 10.

## 1. Findings that shape the design (all read this session)

1. **N is full.** `native_11`: 12 ingress stages, critical path 11, PHV 51.6 percent, no egress (`LEDGER.md` entry
   "2026-10-07 native READ", `integration/evidence/native_11`). `Egress` is empty (`connection/binding/native_binding.p4:375`
   region, `control Egress ... apply{}`). Only table rows can be added to N without a new compile risk (`STEP2_DESIGN.md:282-286`).
2. **T is full.** `read_timing_03`: 12 ingress, 0 egress, critical path 12 (`evidence/read_timing_03/manifest.json`).
3. **N and T disagree on the handoff port.** N sends READ events to `READ_HANDOFF_PORT = 9w66`
   (`native_binding.p4:15`); T receives on `T_IN = 9w69` (`read/ports.p4:14`). Both are pipe-local numbers; neither is
   a cross-pipe device port. Provisional on both sides (`ports.p4:8-12`).
4. **N's WorkRecord is one global cell.** `Register<expected_work_cell_t,bit<1>>(1,{0,4}) work`
   (`connection/binding/work_record.p4:14`). Claim only from phase 4 (`:18`). Return and inspect use full generation plus
   expected phase equality (`:21-34`). Dispatch already has `inspect` rows for expected phase 1, 2, 3 (`:53-55`) next to the
   `return` rows (`:49-51`). Consequence: at most one claimed work is in flight, which already serializes cache writes,
   and a lost recirculating packet pins it forever ("Lost original/producer remains pinned", `native_binding.p4:7`).
5. **What N does with a validated control packet today.** Four passes: pass 0 claims and snapshots
   (`native_binding.p4:199`), pass 1 owner claim, pass 2 owner publish, pass 3 terminal. At pass 3 the work is returned
   (phase 3 to 4) and `read_terminal_t` default `terminal_strip` removes the envelope and forwards the **native** frame
   to `m.output_port` (`:314-316`, `:367`). N does no padding, no mapping and writes no image. Model pass count: 4
   (`evidence/model_23/RESULT.md` section 3, 109-byte frames, 3 x 109 = 327 bytes on port 68 for SELECT).
6. **N has no binding for the response to OPERATE.** `first_event` accepts kind 6 only at owner phase 9
   (`(8w6,8w1,8w1,32w0x90000&&&32w0xffff0000):first_response()`, `:214`) and kind 7 only at phase 10
   (`first_operate`, same line). `claim_response` and `publish_response` both set phase 10 (`:185-186`). After OPERATE the
   owner is 12 (`publish_operate`, `:188`) and nothing in the table returns it to 5. So the second response and the
   return to idle do not exist in N. [V by reading the entry list; no test claims otherwise.]
7. **N hard-codes the ACK offset.** `action ack_native(){m.ack_native=hdr.tcp.ack-32w20;}` (`:164`) is applied to every
   response (`diff_response`, `:166`). Correct only for the response to SELECT (one insertion). The response to OPERATE
   acknowledges native plus 40 (REPORT of the mapping primitive: second boundary total 40,
   `protocol/payload_mapping/REPORT.md` "Behavior and independent checks"). So even with item 6 fixed, kind 6 after OPERATE
   would fail `sequence_guard`.
8. **The model never exercised N's response binding.** `model_23` reports "57-byte response: 1 pass", whereas every
   bound packet takes 4. The guard row for kind 6 requires `m.enabled == 1` (`guard`, `:322`), and `enabled` comes only from
   `data_connection`, keyed on the forward tuple (`:102`). The test topology installs one `data_connection` entry, the
   client-to-server tuple (`integration/core/harness/vectors.py:67-71`), so the reverse-orientation response is
   never enabled and is forwarded unbound in one pass. [I: this is the likely cause; the model result alone does not
   prove it. A red test in ticket S3-1 settles it.] Also the fixture decoy index is `0x0001` (`vectors.py:70`),
   not the production 201.
9. **N's busy path forwards natively and silently** (M2 in `LEDGER.md` native READ entry, pinned by
   `test_native_invariants.BusyWorkRecord`). After the first insertion a natively forwarded client packet has the wrong
   sequence number. N also has no catch-all for the supported tuple: `ip` selects only lengths 40, 44, 75, 97, 60, 89
   (`native_binding.p4:43`); a one-byte retransmission (IP length 41) or any other length is not parsed,
   `network_valid` stays 0, and the `ports` route forwards it (`:87`) untouched.
10. **Established pure ACKs are forwarded unchanged** by the kind-8 path (`LEDGER.md` step-1 entry), and server pure
    ACKs are not even claimed (`direction_guard` has no (3,2) entry, `LEDGER.md` correction). Both need translation after
    insertion.
11. **The payload roles exist as separate compiled programs.** Forward mapping `forward_03`: 10 ingress / 0 egress.
    Reverse mapping `reverse_12`: 11 / 0. Overlay of read, forward, reverse, cache and carving roles by ingress port and IP
    length, `egress_selected_wire_04`: 10 ingress / 7 egress (`HANDOVER.md:24-34`, dispatch at `egress_selected_wire.p4:989-996`).
    Model-verified: forward 89/89, reverse 153/153 (model_08, model_09), composed roles 385/385 (model_14), carve bytes
    exact for both pieces (model_16) (`evidence/model_17/RESULT.md`).
12. **The mapping primitives take their geometry from a configured table, not from live state.**
    `connection{key={src,dst,sport,dport,work.epoch}} configure(first,second,valid,direction)`
    (`protocol/payload_mapping/forward.p4:44-45`, `reverse.p4:47`). With valid 3 the REPORT requires `second - first = 35`
    (`REPORT.md:53-54`), that is OPERATE must follow SELECT back to back in the client byte stream. They parse only
    ingress port 68 plus the 16-byte envelope `epoch32|generation32|expected_cell32|event16|reserved16` (`forward.p4:6,13`),
    which is exactly N's envelope. They validate headers only, never payload (`REPORT.md` "Remaining required seams").
13. **The cache is keyed by slot only.** Image registers are `Register(2,0)` x14 addressed by `descriptor.slot[0:0]`
    (`egress_selected_wire.p4:82-178`). The descriptor carries `generation`, but the egress apply only tests
    `generation != 0` (`:199`) and never stores it. Replay context (generation, wire_start, native_last, slot) is a
    configured table keyed by tuple and sequence (`:64-65`). The executable counterexample
    `protocol/review/test_current_composition.py:82-103`: an old replay descriptor (generation 2) replays the image that
    generation 3 wrote into the reused slot, emitting generation-3 bytes at the generation-2 sequence. A second
    counterexample, `protocol/review/test_egress_admission.py:22-40`: a descriptor-free frame whose MAC bytes 8 and 9
    equal operation 2 and slot 0 mutates all 14 banks if it reaches the egress parser.
14. **Carving emits a third frame** (`model_17` defect 5): `route` assigns `ucast_egress_port` and `split` assigns
    `mcast_grp_a` (`egress_selected_wire.p4:857-859`), so the TM sends a unicast copy as well. Physical order of the two
    replicas is unmeasured (`HANDOVER.md:64`, `PIPE_SPLIT.md:39-41`).
15. **Retained evidence that a handshake build does not load**: table size 8 with 9 constant entries
    (`model_17` defect 1). The step-3 compile of every pipe must run `core/scan_static_entries.py` before the model.
16. **A model exists now.** `HANDOVER.md:75-77` ("target model startup failed") is stale: `model_03` to `model_23` ran on
    the local Tofino-1 model (`core/launch_model.sh`, SDE 9.13.1). The model has no recirculation limit, pads short
    frames, hides truncation inside the 4-byte FCS, and has no timing (`model_23` section 2 and 3). It is functional
    evidence only. `MODEL_INT_PORT_LOOP` exists as a launcher option for per-pipe internal loopback
    (`core/launch_model.sh` header), which is the hook for the cross-pipe tests below.
17. **Pipe topology on record is thin.** Endpoint ports 9 and 64 and historical loopbacks 8, 10, 11 are on pipe 0.
    A pipe-1 private ingress, both directions of a cross-pipe link, their queues and service are unverified
    (`PIPE_SPLIT.md:15-20`).

## 2. Placement decision

### 2.1 Roles and pipes

| Pipe | Ingress program | Egress program | Source family | Stage state |
|---|---|---|---|---|
| 0 | **N** connection authority and validator | **E** image banks, slot tag, carve rendering | N: `connection/binding/native_binding.p4` (generated). E: `cache_Egress` and `carving_Egress` lifted from `integration/egress_selected_wire.p4:81-204,883-888` | N 12/12 [V]. E 7/12 for the existing overlay [V `egress_selected_wire_04`], about 8 to 9 with a tag stage [I] |
| 1 | **M** payload role: produce, translate, replay decision, carve decision, geometry and ledger state | pass-through (`bypass_egress=0` only toward pipe 0 egress) | new, assembled from `forward.p4`, `reverse.p4` and the construct and output-CRC part of `cache_Ingress` (`egress_selected_wire.p4:31-74`) | existing parts 10 to 11 [V]; new registers unknown [I] |
| 2 | **T** READ timing | none | `read/read_timing.p4` | 12/12 [V] |
| 3 | reserved | reserved | step 4 fragment assembly (its layouts already fail PHV, `HANDOVER.md:65-68`) | not used in step 3 |

Why E belongs in pipe 0: egress registers are per pipe and the egress pipeline that runs is the pipe of the egress port.
Every cache write and replay leaves toward the relay (port 64) and every carved replica leaves toward the master (port 9),
both pipe 0 (`PIPE_SPLIT.md:17-18` [V]). N's egress is empty, so pipe 0 egress is free. This is also why the cache
register banks need no cross-pipe state.

Why M cannot share pipe 0 ingress with N: N is 12/12 with zero margin, and a chain-lengthening addition fails the fit
(`STEP2_DESIGN.md:13-20`, `native_03` 19 stages before restructure). M's smallest known pieces are 10 and 11 stages.

Why T gets its own pipe rather than sharing M's: both are 10 to 12 stage programs and T's hold loop and pktgen generate
continuous internal traffic that must not compete with N's recirculation port or M's input (`STEP2_DESIGN.md:337-343`
already assumes N and T are in different pipes so that two local port 68 roles do not collide).

### 2.2 Decision record

| Option | Verdict | Reason |
|---|---|---|
| A. Everything in pipe 0 ingress | rejected | N alone is 12/12 [V] |
| B. N in pipe 0 ingress, M roles in **pipe 0 egress** (same pipe, no cross-pipe hop) | **fallback**, not primary | removes the cross-pipe unknown, but the mapping and construct code exist only as ingress programs; an egress port needs a fresh compile and a new carve and drop model (egress cannot choose the port). Unverified on the compiler. Keep as the plan if S3-0 shows cross-pipe forwarding is not usable |
| C. N pipe 0, M pipe 1, E pipe 0 egress, T pipe 2 | **primary** | reuses the compiled and model-verified ingress roles, keeps one authority (N), keeps all shared registers per-pipe local |
| D. Move M's registers into N | rejected | N has no stage margin; a SALU in a new stage lengthens the chain |

Consequence of C: the packet path of every supported-tuple packet is front door (pipe 0) to M (pipe 1) to front door
(pipe 0 egress). Section 3 gives the ports, section 4 the passes.

## 3. Private interfaces

Port numbers are pipe-local values plus a device-port base. The base rule `dev = pipe*128 + local` is the usual one and
is [I] here; no configuration in this repository confirms it (`STEP2_DESIGN.md:340`). All private ports are
PROVISIONAL until gate G-PORTS.

| Link | From to | Proposed port | Notes |
|---|---|---|---|
| front door | endpoints to N | 9 (master side), 64 (relay side), pipe 0 | `PIPE_SPLIT.md:17-18` [V] |
| N recirculation | N to N | 68, pipe 0 | `native_binding.p4:14` [V] |
| N to M | pipe 0 ingress to pipe 1 ingress | pipe-1 loopback or recirculation port, dev 196 if `128+68` | **cross-pipe, unverified (G-XPIPE)**. Egress bypass on the target pipe |
| M to E | pipe 1 ingress to pipe 0 egress | `ucast_egress_port` 64 (to relay) or 9 (to master), `bypass_egress=0` | TM crossbar carries it; the only path that may set `bypass_egress=0` |
| E to N confirm | pipe 0 egress to pipe 0 ingress | e2e mirror session to port 68 | new; mirror session is controller state |
| N to T | pipe 0 to pipe 2 | pipe-2 port (replaces the 66 versus 69 mismatch, finding 3) | step 2 interface, unchanged format |
| T to M | pipe 2 to pipe 1 | same M input as N to M | replaces T's direct `RELAY_PORT` and `FORWARD_PORT` forwarding (`ports.p4:17-18`) so READ traffic is translated |

### 3.1 Envelopes

- **E1, N to M (existing format, no new bytes).** The 16-byte envelope of N: `epoch32 | work_generation32 |
  expected_cell32 | event16 | reserved16`, followed by the original, unmodified Ethernet frame (`native_binding.p4:28-31`
  headers, `forward.p4:6`). `event = stage<<8 | kind`. Kinds toward M: 5 SELECT produce, 7 OPERATE produce, 6 response
  translate and carve, 12 replay (new), 8 map forward original, 13 map reverse original (new). `reserved` must be 0 and
  generation nonzero (the existing parser rule). `expected_cell` carries N's owner snapshot, whose high 16 bits are the
  owner phase, from which M derives the slot (9 means SELECT outstanding, 12 means OPERATE outstanding). The envelope is a
  reference to N's protected record, never a validity flag (`PIPE_SPLIT.md:28-29`). Cost: 16 bytes per pass.
- **E2, M to E descriptor (existing shape, widened by 4 bytes).** Today `cache_descriptor_h` is generation32, wire_start32,
  operation8, slot8, reserved16 = 12 bytes (`egress_selected_wire.p4:13`). Proposed 16 bytes: add `epoch32` so the slot tag is
  the full WorkRef (epoch32, generation32), plus a fixed magic in the reserved field. The egress parser accepts only
  operation 1 (load) and 2 (store), slot 0 or 1, magic present. Cost: 16 bytes on the M-to-E hop, stripped in E.
- **E3, E to N confirm.** An e2e mirror clone of the departing packet, truncated to Ethernet plus a 16-byte envelope
  `epoch32 | generation32 | expected_cell32 | event16 (stage 4, kind 14) | reserved16`, sent to port 68. N's parser select
  list gains `0x040e` (`native_binding.p4:41` lists the accepted events explicitly). The pass is consumed
  (dropped) after the work return.
- **E4, N or T to M for READ.** Same E1 format with kinds 8 and 13. T must emit the envelope in front of the original
  when it releases (T already parses N's `tev` and holds the epoch). No new field.

### 3.2 Pass counts and bytes (design numbers; N's four passes are measured, the rest are not)

Frame sizes from the IP lengths in the parsers: native SELECT or OPERATE IP 75 gives 89 bytes (93 with FCS, 105 with the
16-byte envelope, 109 with both, matching the model's "109 bytes"); padded request IP 95 gives 109; native-size response
IP 97 gives 111; carved pieces IP 68 and 69 give 82 and 83; pure ACK IP 40 gives 54 (60 minimum frame); the one-byte replay
input IP 41 gives 55; READ request IP 60 gives 74; READ response IP 89 gives 103.

| Packet | N ingress passes | M | E egress | confirm pass | T | Recirculated bytes on N port 68 | Basis |
|---|---:|---:|---:|---:|---|---:|---|
| SYN, SYNACK, final ACK | 4 | 0 | 0 | 0 | 0 | 3 x 80 for SYN (model) | N measured (model_23 s3). No translation needed before the first insertion |
| Established client pure ACK | 4 | 1 | 0 | 0 | 0 | 3 x 74 [I] | N measured, M design |
| Server pure ACK | 1 today | 1 | 0 | 0 | 0 | 0 | today unclaimed; step 3 routes it to M [design] |
| SELECT | 4 | 1 | 1 | 1 | 0 | 3 x 109 = 327 (model) | N measured, rest design |
| OPERATE | 4 | 1 | 1 | 1 | 0 | 327 (model) | same |
| Response (either) | 4 | 1 | 2 replicas | 0 | 0 | 3 x 131 = 393 [I from 111+16+4] | N response binding unverified (finding 8) |
| Replay (IP 41) | 4 | 1 | 1 | 1 | 0 | 3 x 75 [I] | N kind 12 does not exist yet |
| READ request | 4 | 1 (after T) | 0 | 0 | 4 admit passes | 3 x 94 [I] | `STEP2_DESIGN.md:250-255` |
| READ held ACK or response | 4 | 1 (after T) | 0 | 0 | 3 + loop + terminal | 3 x 74 / 3 x 119 [I] | same |

Totals per control packet: SELECT or OPERATE = 6 ingress passes (4 N, 1 M, 1 N confirm) plus 1 egress traversal plus 1
mirror clone. A full SBO exchange is four control packets, four pure ACKs of the exchange and the carved responses; in
bytes the accepted fixed scenario is about 762 bytes per control operation on both external links and 13.3 kbit/s overall
(`integration/REPORT.md` "Executable accounting"). Internal amplification is at most about 6 times, so recirculation
bandwidth is not a binding constraint at the declared workload [I]. What binds is **serialization by the single
WorkRecord** (finding 4): one control chain at a time. Latency per pass and per cross-pipe hop is unmeasured anywhere
in the repository; no rate or latency claim follows from these counts.

## 4. Packet path per class

Notation: N0 to N3 are N's four passes (N0 is the front-door pass, N1 to N3 arrive on port 68 with the envelope).

### 4.1 Handshake (SYN, SYNACK, final ACK, and the coalesced final ACK + SELECT)
N0 to N3, terminal forwards the original to the opposite front port as today (kinds 1, 2, 3; `owner_command`, `:193`). No
M pass: geometry is empty, translation is the identity. The coalesced final ACK + SELECT is a SELECT first contact at
owner phase 4 (`first_event`, `:214`) and follows 4.3. The epoch minted at SYN is the geometry tag, so a new connection
cannot read an old geometry (section 5.3).

### 4.2 READ
Unpadded. N0 to N3 (kind 9, 10 or 11), terminal builds `tev` and sends to T (existing step-2 path). T admits, holds,
releases ACK then response. **Change for step 3:** T releases into M (E4 envelope, kind 8 for the request toward the relay,
kind 13 for the ACK and the response toward the master) instead of straight to the front port, so the first insertion's
20-byte offset is applied to the request sequence and removed from the ACK and window values. T keeps observing the wire ACK
before inverse mapping (PLAN step 2). M adds a fixed latency to both releases, so the gap is preserved to first order
but the departure is later than T's internal commitment [I]; the existing rule that commitment is not departure stands.

### 4.3 SELECT (native 35 to padded 55)
1. N0 (port 9): parse, validate profile and all CRCs, tuple, epoch, sequence, application, object bank compare, claim work
   (phase 1), snapshot, send to 68.
2. N1: owner claim CAS (4 or 5 to 8), client position bank stores seq+35. N2: owner publish (8 to 9).
3. **N3 (changed):** `work.inspect` (expected phase 3), not `return`. The pin stays at phase 3. Emit the E1 envelope with
   kind 5 and send the original to M.
4. **M1:** parse envelope; compare identity against the slot ledger (monotonic generation, refuse stale); build the 55-byte
   padded image (`construct`, three output CRCs, `crc_render`, `egress_selected_wire.p4:56-62`), SELECT sequence shift 0;
   write geometry `first = seq`, `valid |= 1`; write slot ledger {slot 0, epoch, generation, wire_start, native_last};
   attach E2 store descriptor; `ucast_egress_port = 64`, `bypass_egress = 0`.
5. **E:** slot tag compare-and-store, then the 14 image words, then strip descriptor and envelope; e2e mirror clone toward 68
   (E3); the padded frame leaves port 64.
6. **N4 (confirm):** expected-phase-3 `return_work` frees the pin, the clone is consumed.

### 4.4 OPERATE (native 35 to padded 55, sequence +20)
Same as 4.3 with kind 7, owner 10 to 11 to 12, M uses geometry `valid = 1` to apply the constant +20 shift to this packet
and then writes `second = seq` (must equal `first + 35`, finding 12), `valid |= 2`, slot 1 ledger. The +20 for this one
packet is a constant, not the 10-stage general mapping, because N already proved the packet is the OPERATE that follows
the matched SELECT (`object_match`, `first_operate`, `native_binding.p4:214,345-352`). The general mapping is still used
for all later packets.

### 4.5 Response (57 bytes, to the master as two carved pieces)
N0 to N3 on the reverse direction (port 64) for kind 6, with the fixes of section 5 (reverse `data_connection` entry,
ack offset by exchange, owner transitions). N3 returns the work (no shared bank is written later: M's response role reads
geometry only) and sends the E1 kind-6 envelope to M. **M:** reverse mapping of ack and window (inverse offsets, both window
edges, `reverse_12` logic reading registers instead of the configured table), plus the carve decision (`split(mgid)`), with
no unicast assignment on that path (finding 14). **E:** carve rendering by `egress_rid` 1 and 2 (`:886-888`), checksums
recomputed in the egress deparser. The master receives pieces of 28 and 29 bytes. Order is by the PRE replica order, which
is not proven (gate G-ORDER).

### 4.6 Pure ACKs, window updates, other supported-tuple packets
Client to server: N0 to N3 (kind 8 pattern, no owner command), then M mapping-only (forward role: sequence shift by
geometry). Server to client: N claims it (new, today unclaimed) or, if not claimed, routes it to M reverse mapping-only.
Any frame of the supported tuple that N does not otherwise classify (including unknown lengths) goes to M mapping-only, or is
dropped and counted if M's header checks refuse it. It is never forwarded natively once translation is active (finding 9).
Before the first insertion M applies the identity map (`valid = 0`).

### 4.7 Retransmission and tail replay
Sender retransmission of the last native byte (IP 41) after an ACK inside an inserted tail (the mapping withholds exactly the
final native byte, `REPORT.md` "Behavior"): N parses it (new state), checks tuple, epoch, owner phase in {9, 12} and
`seq == client_bank - 1`, runs the four passes (kind 12, nonmutating like kind 8) and holds the pin; M reads the slot ledger
(slot from owner phase), checks the byte equals `native_last` and the identity equals the ledger entry, and sends an E2 load
descriptor; E checks the tag, loads the image, renders the full padded packet at `wire_start` (IP 95), and confirm returns.
No ACK is manufactured. Whole-segment loss of a padded request (the sender resends all 35 native bytes) arrives at N as a
sequence duplicate, which N drops after burning a generation (`model_23` s3); that case is step 4's and must be an explicit
counted outcome in step 3, not silent (open question Q3).

## 5. What N already provides and what must be added

### 5.1 Provided [V]
Full frame and profile validation with every DNP3 CRC; tuple, link, epoch and sequence qualification; owner CAS phases
(SELECT 8 and 9, response 10, OPERATE 11 and 12); the object-set banks (`pair_*`, `application`, `frozen_decoy_off`) and
`matched` for response and OPERATE; the four-pass WorkRecord protocol and its H1 and H2 fixes; READ kinds 9 to 11 and the
16-byte `tev`; kind-8 forwarding.

### 5.2 Must be added or changed (all rows or parser edits; any new dependency edge breaks the 12-stage fit)
| # | Change | Where | Red test first |
|---|---|---|---|
| N-a | terminal for kinds 5, 6, 7, 8, 12, 13: send to M with E1 envelope; kinds 5, 7, 12 use `inspect` at pass 3 and free on the confirm pass (kind 14, stage 4, expected phase 3) | `work_record.p4:49-55` dispatch already has both operations; `native_binding.p4:367` terminal; parser event list `:41` | harness: SELECT leaves pass 3 with WorkRecord phase 3 and generation unchanged; phase 4 only after the confirm injection |
| N-b | response to OPERATE: first_event row for kind 6 at owner 12, owner transition 12 to 5; ack offset by exchange | `:214`, `:185-186`, `:164-166` | harness: full SELECT, response, OPERATE, response sequence ends at owner 5 with banks equal to the codec oracle |
| N-c | reverse-orientation `data_connection` (response guard needs `enabled`) with the same decoy parameters, production index 201 | controller state, `:102`; harness `vectors.py:70-71` | red: current fixture response takes 1 pass (finding 8) |
| N-d | replay kind 12 (IP 41) parser state, `network` and guard rows, `seq == client-1` test | parser `:43`, `network :92`, `guard :322` | harness: replay at phase 9 and 12 bound; at phase 5 refused; wrong byte refused downstream |
| N-e | supported-tuple catch-all to M mapping-only; busy WorkRecord becomes counted and mapping-aware (M2) | parser default of `ip` select, `connection` result, `:345` region | harness: every packet class injected while the work is pinned is either mapped or dropped and counted, never forwarded native |
| N-f | known limit: client position bank stored under a foreign epoch (`LEDGER.md` native READ entry) | `client_t` | harness: SYN of epoch e+1 cannot read epoch e's bank |
| N-g | `READ_HANDOFF_PORT` and every private port come from one table (`ports.p4` rule, `test_read_ports.py`) | `native_binding.p4:14-15` | extend the port-uniqueness test to N |

Compile after every row batch into a fresh evidence directory; the 12-stage limit is the acceptance, not a hope
(`native_10` is the retained 13-stage failure).

## 6. M and E in detail

### 6.1 M registers (new, epoch-tagged, lazily re-armed, never cleared)
All cells follow the cookie-tag pattern of T (`read_timing.p4:9-16`): the cell carries its identity, a newer identity
re-arms it, an equal one accumulates, an older one is ignored. [I that the SALU predicates fit; the pattern is compiled in
`original_credit_native.p4:73-80` for two 32-bit fields.]

| State | Fields | Written by | Read by |
|---|---|---|---|
| geometry A | epoch32, first32 | SELECT produce | forward and reverse mapping |
| geometry B | epoch32, second32 | OPERATE produce (requires `second - first == 35`) | forward and reverse mapping |
| geometry valid | epoch tag plus bits 0 and 1 | produce | mapping |
| slot ledger x2 | epoch32, generation32, wire_start32, native_last8 | produce (monotonic generation) | replay decision |

All accesses to one register are actions of one table (the one-table-one-register rule, `MEMORY.md` note on Tofino
registers). Replacing the configured `connection` table of the mapping primitives by these reads is the removal of the
"geometry seam".

### 6.2 What M does not do
It does not re-run DNP3 CRC and profile validation. N validated the immutable bytes once (assignment section 3 "Validate
immutable packet content once where safe; revalidate the necessary ownership and phase at later events"). M keeps only
structural checks: exact IP length, header checks of the mapping admission (`REPORT.md` "Network admission"), exact envelope
rules. Cost avoided: the validation hash stages of `cache_Ingress` (`:36-58`). The risk this accepts is that M trusts bytes
that crossed a private link; the pin recheck on confirm (section 7) is the mitigation, and pipe 1 has no front-panel port
(gate G-PORTS must confirm that).

### 6.3 Egress E
Keep the 14 image registers and the carve rendering. Add one tag register (size 2, {epoch32, generation32}) at the first
egress stage. Store: write the tag and the image words. Load: compare tag to the descriptor identity, load the words
unconditionally (read-only), and drop with a counter on mismatch. This replaces the `generation != 0` test (`:199`) and
closes the first counterexample of finding 13. Tighten the egress parser so the descriptor must carry the magic and must
arrive with `egress_rid == 0`, and make a program-level invariant that no ingress action of N, T or the carve role sets
`bypass_egress=0`; only M's store, load and carve actions may. That closes the second counterexample of finding 13. For
carving, split the route and split actions so `ucast_egress_port` is never assigned on the multicast path (finding 14, the
compiler tracks assignment as validity [I]).

### 6.4 Stage budget (to be replaced by compiler evidence)
| Role | Known | Added by step 3 | Estimate | Evidence required |
|---|---|---|---|---|
| N | 12/12 [V] | rows only | 12/12 | compile `native_12`, `scan_static_entries` clean |
| E | 7 egress [V] | tag stage, mirror emit | 8 to 9 of 12 [I] | `egress_selected_wire_05` style egress compile |
| M | 10 for the five-role overlay, forward 10, reverse 11 [V] | three or four registers, envelope parser, ledger, replay compare, constant +20 | 10 to 12 [I] | **canary compile first (S3-3)** |
| T | 12/12 [V] | envelope emit toward M (deparser only) | 12/12 [I] | `read_timing_04` |

## 7. How the shared banks are pinned (the stale-descriptor defect)

The defect (finding 13) has two parts: a descriptor from an older work reads a slot a newer work rewrote, and an unqualified
frame can look like a descriptor. The design closes both with four independent layers.

1. **Authority and ordering: held pin.** From N0 (claim) to the confirm pass the WorkRecord is at phase 3 and no other work
   can start (`work_record.p4:18`). Therefore every M ledger write and every E store happens under a live pin, and no new
   claim, hence no new slot write, can start before the confirm. This implements `PLAN.md:114-122` literally ("reuse requires
   actual terminal credits").
2. **Identity in the data.** Every slot carries the tag (epoch32, generation32) in E and the same identity in M's ledger. A
   load is honored only when descriptor identity equals the stored tag. A stale descriptor (generation 2 after generation 3
   wrote) is dropped and counted. This is the direct fix of `test_old_nonzero_descriptor_replays_reused_slot_without_lifetime_authority`.
3. **Lifecycle in the owner.** A slot is writable only after its predecessor is terminal, and N's owner CAS already enforces
   that without any state in M or E: SELECT requires owner 4 or 5, OPERATE requires 10, and the new return to 5 is reached
   only by an accepted response whose ACK covers the whole padded request (`sequence_guard` requires exact `ack_native`, `:164-172`).
   Replay requires owner 9 or 12 (request outstanding). Reset and close move the owner to 6 or 7, so replay becomes
   unreachable, and a new epoch invalidates every tag.
4. **Admission to the egress banks.** Only M reaches them (descriptor magic, `egress_rid` check, `bypass_egress` invariant).

Residual hazards, stated plainly:
- A lost mirror clone or lost M or E packet leaves the pin at phase 3 forever. The same property exists today for any lost
  recirculating packet (`native_binding.p4:7`). The recovery is a controller-side reset of the WorkRecord after a counter
  check (allocated minus freed generations), which does not exist yet. Ticket S3-8 adds the counters and the red test; a
  hardware watchdog is not proposed.
- The in-order argument between a store and a later replay or store relies on one egress queue for port 64 [I]. If the TM can
  reorder them, layer 2's tag compare still refuses the stale one.

## 8. Feasibility: what binds

| Constraint | Effect on this design | Status |
|---|---|---|
| 12 stages per pipe | forces the role split; N and T have zero margin (findings 1, 2) | binding, [V] |
| One register per table, one SALU access per pass | geometry, ledger and tag each live in one table; multi-pass N chain exists because of it | binding, pattern verified in N |
| PHV | N at 51.6 percent. M's PHV with envelope parser plus mapping scratch is unknown. Assembly layouts failed PHV at 460 slices (`HANDOVER.md:65-68`) and are out of step 3 | M unknown |
| Resubmit 8 bytes | not used: N recirculates with a 16-byte envelope (`PLAN.md:114-116`). The 8-byte WorkRef fits inside it | satisfied |
| Recirculation bandwidth | 327 bytes per SELECT on port 68, about 13.3 kbit/s external load: not binding at the declared workload [I]; hold and heartbeat loops are isolated in pipe 2 | not binding [I] |
| Cross-pipe latency | unmeasured, adds two hops per control packet | unknown |
| Single WorkRecord | serializes control chains; busy-window packets need a mapping-aware path (N-e) | binding, design item |
| Egress state per pipe | forces E into pipe 0 | satisfied by placement |
| TM replication order | physical [28,29] order unproven; PRE rid does not prove it | unknown |
| e2e mirror | confirm path depends on a mirror session and truncation; behavior at egress timing unverified | unknown |
| Static entries versus table size | `model_04` failure class; scan every build | mitigated by tool |

### 8.1 Unverified on hardware (everything below is open)
Every pipe-1 and pipe-2 port role; cross-pipe unicast to a recirculation port; pipe-1 egress bypass; e2e mirror to port 68;
PRE replica order and queue FIFO between cache operations; pktgen on pipe 2; model-versus-silicon differences already
listed (FCS-hidden truncation, no recirculation limit, `Checksum.subtract` semantics, `model_23` s2); all timing,
queue service, physical departure; endpoint acceptance of the 57-byte response and the inert object; the 9.13.2 build.
No step in this note is hardware-verified.

## 9. Ordered tickets (TDD; red first; new files unless a row says edit)

Rules for all tickets: frozen sources and evidence are untouched (`defense4/CLAUDE.md`); every compile goes to a fresh
`evidence/<name>_NN` directory with `core/scan_static_entries.py` first; failures are retained; builder, then qa-verifier,
then code-reviewer per the operating manual; commits by the lead with Philip's identity and no trailers.

| # | Ticket | Files | Red test first | Acceptance |
|---|---|---|---|---|
| S3-0 | Cross-pipe and mirror probe (gate G-XPIPE on the model) | `integration/core/xpipe/xpipe_probe.p4`, `core/cases/xpipe_cases.py` | a packet sent from pipe 0 ingress to a pipe-1 loopback port never arrives (probe absent) | model shows: pipe 0 to pipe 1 ingress arrival, pipe 1 to pipe 0 egress at port 64, e2e mirror clone to port 68 returns, pipe-2 pktgen. Any refusal is recorded and triggers option B of 2.2 |
| S3-1 | N prerequisites N-b, N-c, N-g (response to OPERATE, ack offset per exchange, reverse `data_connection`, port table) | edit `connection/binding/generate.py` plus new `connection/binding/tests/test_step3_exchange.py`; harness `vectors.py` topology gains the reverse entry | the 1-pass response (finding 8) and the OPERATE response abort at owner 12 | harness: full SELECT, response, OPERATE, response ends at owner 5, banks equal the independent oracle (`connection/reference.py` plus the codec), 4 passes each; compile still 12 stages |
| S3-2 | N supported-tuple catch-all, replay kind 12, busy path (N-d, N-e, N-f) | `generate.py`, `test_step3_catchall.py` | native forward of an unqualified supported-tuple frame at insertion `valid>0`; IP 41 frame unparsed | interleave matrix (every class injected after every pass of a pinned chain): no packet leaves native-forwarded; counters tick; compile 12 stages |
| S3-3 | **M canary compile** | `integration/core/m/m_skeleton.p4` (envelope parser, geometry, ledger registers, read of the existing mapping tables turned to registers, no logic yet) | none (resource canary) | stage count and PHV recorded. If above 12, decide before any further M work (devil's advocate 2) |
| S3-4 | M produce SELECT and OPERATE from the handed-off native frame | `m/produce.p4`, `m/tests/test_produce.py` | produce today needs the cache role's own validation and configured `connection` | bytes equal the independent codec (`protocol/fixtures` `expand_control`) for SELECT and for OPERATE with +20; CRC and TCP checksum equal Scapy; real CROB and inert 201 objects present; stale generation refused |
| S3-5 | M two-boundary translation from register geometry (forward, reverse, window edges, wrap) | `m/map.p4`, `m/tests/test_map.py` | 204 sealed vectors rerun against register-backed geometry; contiguity violation (`second != first+35`) must refuse | all 204 `payload_mapping/verification_01` vectors plus the new geometry-write cases match the serial-arithmetic oracle |
| S3-6 | E: slot tag, descriptor magic, load refusal, confirm mirror, carve single-copy | `egress/e_cache.p4`, `egress/tests/test_tag.py` | the two counterexamples of finding 13 and the stray frame (finding 14) | both counterexamples now refused and counted; carve emits exactly two frames; all 14 banks untouched by a lookalike frame |
| S3-7 | N terminal re-target, held pin, confirm pass (N-a) | `generate.py`, `test_step3_pin.py` | SELECT frees at pass 3 (today) | work phase stays 3 until the confirm; lost confirm leaves the pin and counts; claim during the pin is refused counted |
| S3-8 | Liveness counters and controller reset procedure | `core/work_counters.py` plus test | none | allocated minus freed visible; reset clears; rehearsed on the model |
| S3-9 | T release into M, ports unified | `read/read_timing.p4` edit (deparser emit, ports), `read/ports.p4`, `read/tests/test_read_ports.py` | T forwards READ native after an insertion | READ request and ACK and response translated; T still observes wire ACK before inverse mapping; 12 stages |
| S3-10 | Per-pipe composition compile: pipe 0 (N plus E), pipe 1 (M), pipe 2 (T) as one `Switch` | `integration/core/step3_switch.p4` and `build.py` entry | none | compile evidence per pipe with source hashes; fit stated honestly; all failures kept |
| S3-11 | Multi-pipe source harness: N interpreter, M interpreter, E interpreter, TM stubs for unicast, bypass, multicast, mirror | `integration/core/harness/pipes.py`, `tests` | harness cannot move a packet between programs | source-level execution of every path in section 4, labelled source-level |
| S3-12 | Model differential on the compiled `Switch` | `core/cases/step3_cases.py`, evidence `model_NN` | none | per step: emitted frames, pass counts, every register of every pipe equal the harness; counters; the 8-pass bound for any packet that can loop |
| S3-13 | Independent oracle and loss tests | `core/oracle_step3.py`; netem tests if the harness supports them | tail replay without ACK fabrication | expected bytes from the independent codec for: SELECT, response, OPERATE, response, tail loss and replay, wrap |
| S3-14 | Real OpenDNP3 SBO over TCP through the model (when the namespace allows) | `core/cases/opendnp3_sbo.py` | none | one supported SELECT, OPERATE exchange completes against a pinned OpenDNP3 pair; or recorded skip with reason |
| S3-15 | Step-3 hardware package (inert, reviewable) | `integration/core/HW_PACKAGE_STEP3.md` | none | section 10 gates satisfied in text; no action taken |

Dependency order: S3-0 and S3-3 first (they decide whether C or B is the plan), then S3-1 and S3-2 (independent of M), then
S3-4 to S3-7, then S3-8 to S3-10, then verification tickets.

## 10. Verification plan and hardware gates

### 10.1 What runs where
| Check | Source harness | Local model | Hardware |
|---|---|---|---|
| N exchange, owner phases, banks, 4-pass chain | yes (`integration/core/harness`) | yes | no |
| M produce, mapping, replay decision | yes (source interpreters of M) | yes (compiled M) | no |
| E tag, descriptor admission, carve bytes | yes (E interpreter) | yes | no |
| Cross-pipe forward, mirror confirm, loopbacks | no (TM stubs only) | **yes, first** (S3-0) | gate |
| Physical [28,29] order | no | model shows only model order, not silicon | **gate G-ORDER** |
| Stage and PHV fit | no | no | compiler evidence only (SDE 9.13.1 now, exact 9.13.2 for qualification) |
| Timing, queue service, departure | no | no | gate |

Expected packets and register results come from the independent codecs and the serial-arithmetic oracle, not from a second
transcription of the P4 (`PLAN.md:70-75`). Label every result with the milestone: primitive implemented, compiled,
composition compiled, target-model verified, loaded, configured, hardware-measured. The model result is not hardware.

### 10.2 Gates Philip must authorize before anything touches the switch
| Gate | What it covers | Notes |
|---|---|---|
| G-PORTS | read-only inventory: pipe membership of ports 9 and 64 and 8, 10, 11; which pipe-1 and pipe-2 ports are loopback-capable; cable check | uses the existing cabling recipe (read-only `bfshell`, needs a pty, `MEMORY.md` cabling note). No traffic |
| G-LOAD | load of the exact step-3 binaries, restore of the saved workload | the bf_switchd restore is unrehearsed (`MEMORY.md` framework track entry). Rehearse the restore before the first load. 9.13.2 build required |
| G-XPIPE | live check of cross-pipe forwarding and the confirm mirror with a synthetic non-DNP3 frame | confirm the S3-0 model result first |
| G-ORDER | capture of the two carved pieces at the master side | order is a wire observation, not a compile result |
| G-SELECT | non-actuating SELECT with padding to the endpoint | needs its own authorization naming exact configuration and protocol; existing OFF-smoke or timer authorization is not blanket (`defense4/CLAUDE.md` hard rule 1) |
| G-LOSS | induced loss of the inserted tail to exercise replay | link-level loss or a drop entry; capture first |
| G-OPERATE | **attended** inert OPERATE only, independently verified inert point | physical OPERATE is attended-only; never autonomous |

Campaign stays 44 blocks and 16,168 attempts within 18,360 (`integration/REPORT.md`); no step-3 gate enlarges it.

## 11. Devil's advocate: three ways this could be wrong

1. **Cross-pipe forwarding or placement does not work as assumed.** Cross-pipe unicast to another pipe's recirculation port,
   egress bypass on that pipe, an e2e mirror into port 68, multicast across pipes and pipe-2 pktgen are all [I]. If one fails,
   option C collapses and the confirm path with it.
   *Catching test:* S3-0 on the model first, then G-PORTS and G-XPIPE on hardware. Pre-committed fallback: option B
   (M in pipe 0 egress), which needs its own compile (and which may fail on the egress side, in which case the honest answer
   is that N must first shrink, as `STEP2_DESIGN.md:86-90` already said).
2. **M does not fit, or fits only without the new state.** The existing 10 and 11 stage figures are for stateless programs
   with configured tables. Replacing the table with two epoch-tagged registers, a ledger, an envelope parser and a replay
   compare may need 13 stages or fail PHV; the same pattern already failed in T (13 then 12) and in N (19 then 12).
   *Catching test:* S3-3, the canary compile, before S3-4 to S3-6 are written. A fail there changes the design (move the
   ledger to E, or give the replay decision to N), so it must precede coding.
3. **The held pin is wrong or hides a hole.** (a) The single global WorkRecord makes "no reuse until terminals" true
   vacuously in the happy path, so tests that never create a second claimant prove nothing. (b) A lost mirror clone wedges all
   control traffic, and while the pin is held, busy-window packets must be mapped or dropped, not forwarded natively. (c) The
   claim that FIFO order on port 64 makes a store precede a later replay is [I].
   *Catching tests:* the interleave matrix of S3-2 and S3-7 (inject every packet class after every pass of a pinned chain),
   loss injection of the confirm clone and the M packet in S3-8 and S3-12, and the tag-refusal test of S3-6 that must pass
   even if order is assumed broken. A passing happy-path test alone must not be accepted.

Smaller risks to test, not assumed away: contiguity `second = first + 35` against what the real master sends between SELECT
and OPERATE (read an OpenDNP3 capture, S3-14); the response is accepted by the master with the extra inert object echo
(endpoint behavior, hardware gate G-SELECT); `ack_native` for retransmitted responses; the two `data_connection` entries
share `size=2` so any third flow cannot be configured.

## 12. Questions for Philip (decisions, not assumptions)

- Q1. Is OPERATE holding (the J hold of the claim boundaries) part of step 3, or does step 3 forward the padded OPERATE
  immediately? `PLAN.md` step 3 does not list it; `defense4/CLAUDE.md` claim boundaries say OPERATE is held for J. This note
  assumes immediate forwarding with T's OPERATE hook untouched.
- Q2. When the WorkRecord is busy, drop and count, or map and forward pure ACKs only? This note recommends drop for data
  classes and mapping-only for pure ACKs.
- Q3. Is whole-segment loss recovery of a padded request (sender resends 35 native bytes) step 4, with an explicit counted
  outcome in step 3? The plan's step-3 test row lists only the lost inserted tail.
- Q4. Is a controller-driven WorkRecord reset (S3-8) acceptable as the only liveness mechanism, or is an in-switch timer
  wanted?

## 13. What was read, what was not done

Read: `PLAN.md`, `HANDOVER.md`, `LEDGER.md`, `Codex_Case4_Hardware_Architecture_Prompt.md`, `integration/PIPE_SPLIT.md`,
`integration/read/STEP2_DESIGN.md`, `ports.p4`, `read_timing.p4` header, `connection/binding/native_binding.p4` (parser,
tables, control), `work_record.p4`, `integration/egress_selected_wire.p4` (cache, carving, read, roots),
`protocol/payload_mapping/forward.p4` header and `REPORT.md`, `integration/REPORT.md` accounting, `evidence/model_17` and
`model_23` summaries, `model_22/cases.json` meta, `core/harness/README.md`, `core/harness/vectors.py` topology,
`core/launch_model.sh` and `model_driver.py` headers, `protocol/review/test_current_composition.py` and
`test_egress_admission.py` (counterexamples), manifests of `read_timing_01..03`, `pipe_split_01`.
Not read in full: `shared_cache*.p4`, `cache_authority.p4`, `protocol/egress/shared_egress.p4`,
`integration/connection/selected.p4` (superseded by N's object banks per the file list), `protocol/assembly`.
Not done: no compile, no test run, no model run, no packet, no hardware. Items marked [I] are inferences and each has a
named test above.
