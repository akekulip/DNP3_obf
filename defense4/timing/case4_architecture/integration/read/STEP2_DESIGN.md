# Step 2 design: one real READ timing path (join, budget, ports, state machines, tickets)

Status: design note, no code. Author role: B-design (read-only except this file).
Base: main at `78a0b50da`. Binding assignment: `defense4/Codex_Case4_Hardware_Architecture_Prompt.md`.
Plan reference: `PLAN.md:31-36` (step 2 scope), `PLAN.md:65` (step 2 test row).

Paths are relative to `defense4/timing/case4_architecture/` unless they start with `defense4/`.
Markers: **[V]** means read in a file this session (file:line quoted). **[I]** means inferred and
not verified. Nothing here was compiled or run. Compiler numbers are quoted from retained evidence.

## 0. Findings that shape the design

0.1 **Two programs already fill the pipe on their own.** [V]
- Native binding `integration/evidence/native_03/out/pipe/logs/table_summary.log:2-6`: 72 tables,
  19 ingress stages, critical path 18, Tofino-1 limit 12 (`compile.log:44`).
- Held timing primitive `ownership/evidence/held_timing_expected_02/out/pipe/logs/table_summary.log:1-6`
  (first allocation 13 stages) and the second allocation reports 12 stages, 71 tables,
  critical path 11. `HANDOVER.md:34` lists it as 12/0.
- Conclusion: the timing role has zero spare stages, and the connection role is already 7 over.
  A READ join that adds a dependent edge to either role makes the fit worse. See section 2.

0.2 **The held-timing fixture is hard-wired in four places the join must replace.** [V]
- Association is a constant: `ownership/p4/held_timing_expected_probe.p4:158`
  `Register<timing_binding_t,bit<1>>(1,{1,1}) timing_binding` (epoch 1, cookie 1).
- D_A is a constant: `held_timing_expected_probe.p4:271` `md.normal_deadline = md.t0 + 32w4999936`
  (5 ms only). Readiness `:272` 29,999,872. Gap `:273` 999,936.
- The anchor is the first protected original-admission relay, not request arrival:
  header comment `:15-16`, register `:168-179`, `successful_admission` `:262-267`.
- No register is ever cleared: `anchor_arm` only writes when `value == 0` (`:174`),
  `observation_record`/`release_service` only OR bits (`:192`, `:209`). The probe comment
  admits it is a fixed-cohort primitive (`:7-9`). Repeated READs need a reset or a tag.

0.3 **Gaps in the probe's timing semantics versus the contract.** [V]
- No response release without an ACK commit. `ready_service` requires
  `md.response_eligible == 1` (`:243-248`) and `response_eligibility` requires the response
  deadline armed (`:307-312`). `POLICY_CONTRACT.md:98-100` requires FALLBACK_NO_ACK (response with
  no ACK is released at readiness expiry). Not implemented in the probe.
- No 40 ms cap. `grep` for the cap finds only the comment at `:26`; `ownership/heartbeat_spec.json`
  records `policy_cap_ns: 40000000` as specification only.
- `ack_commit` (`:296-301`) and `release_snapshot` (`:293-294`) are declared but never applied
  in `apply` (`:470-555`). Do not cite them as implemented behavior.
- Heartbeat service record pins on loss: `REPORT.md` (ownership) says "A lost HB service packet
  pins its separate service record; later HB grants are refused". A single lost service pass
  wedges all later timing progress. See ticket T-HB.

0.4 **Probable defect in the step-1 repair that READ must not copy (needs a check by the step-1 owner).** [I from V]
- `network` table (`integration/connection/binding/native_binding.p4:77`) keys on `m.kind` and has
  rows for kinds 0,1,2,3,4,255,5,6,7 only. `grep -n 8w8` finds no kind-8 row there; kind 8
  appears only in `return_kind_guard` (`:273`) and the `forward_original` test (`:311`).
  A kind-8 return (stage 1..3) therefore has `network_valid == 0` and reaches
  `else if(m.stage!=8w0){deny();}` (`:317`).
- The step-1 tests do not exercise it: `integration/connection/binding/tests/test_native_binding.py:107-117`
  runs only `epoch_diff_t`, `owner_command`, `owner_t` and the tail `chain`; it never applies
  `network` or the parser. So "forwarded" at fragment level may be a drop on the target.
- Action for step 1 (not this design): add `(8w1,8w8,<flags 2|18|16>,...)` rows to `network`.
  Action for READ: the same rows are needed for kinds 9, 10, 11, and `size=16` is too small
  (14 rows today, about 22 after READ). Mark verified only after a compile and a packet test.

0.5 **Native kinds 9..11 numerically collide with "data" predicates.** [V]
`m.packet_kind>=8w5` gates the object-bank chain at `native_binding.p4:295` and `:297`, and
`packet_kind==5||6||7` gates validation at `:279`. READ kinds 9..11 satisfy `>=5` and would
enter SELECT/OPERATE object comparison. Those predicates must become explicit `{5,6,7}` tests
before any READ row is added (ticket T-NATIVE-READ, first step, red test first).

## 1. The exact join

### 1.1 Roles and placement (decision)

Two roles, each keeping one authority (`PLAN.md:106-112`: one connection authority, one separate
timing generation).

| Role | Owns | Source family |
|---|---|---|
| N, connection and validation | frame/profile/CRC validation, tuple/link/epoch/sequence qualification, owner phase, client/server sequence banks, 4-pass WorkRef pin | `integration/connection/binding/native_binding.p4` (generated by `generate.py`) |
| T, timing and holding | request clock t0, association cookie, observations, release bits, response deadline, ACK/response original receipts, heartbeat, policy-off, quarantine | evolved from `ownership/p4/held_timing_expected_probe.p4` |

**Placement: N in pipe 0, T in a separate `Pipeline` instance (pipe 1).** Reasons, all from 0.1:
the union chain cannot be shortened by overlaying roles, because placement is static
(for example `return_kind_guard` sits at stage 4 for every role because it depends on `data_guard`
at stage 3, `table_summary.log` N rows "stage 3/4"). T alone is 12 of 12.
This is architecture family 3 of the assignment (`Codex_...Prompt.md:99-105`).
The TNA `Switch` package accepts four `Pipeline`s with separate registers
(`integration/PIPE_SPLIT.md:12-14` [V]). Unverified and blocking: pipe-1 ports, N-to-T and T-to-front-panel
forwarding across pipes, queue service ([V] `PIPE_SPLIT.md:17-20` lists them as unverified).

**Honest alternative if cross-pipe verification fails [I]:** same-pipe is impossible until N
drops to roughly 6 to 7 stages before T is added, and T has 0 spare. What would have to move out of N:
the bank-compare/object-match chain (native_03 stages 12-15) into a later pass, and the
`mint_t`/`work.dispatch` serialization (stages 6-7). That is step-3/step-1 structural work, not
READ work. This note does not claim it can be done.

### 1.2 What is captured, where, and with which clock bits

- **Pass:** pass 0 of N, the raw READ request (dp9 -> N, IP length 60). Parser admits it at
  `validator.p4:21` (`(4w4,4w5,8w6,16w60)`) and the same selector must be added to `native_binding.p4:39`
  (today 40, 44, 75, 97 only [V]).
- **Clock:** `t0q = (bit<32>)ig_prsr_md.global_tstamp & 32w0xffffff00`, identical to
  `held_timing_expected_probe.p4:257`. Low 32 ns bits, 256 ns resolution, matches `PLAN.md:110-111`
  and `reference.py:118-119` (`quantize`). Bit 0 is reserved as the "armed" marker
  (`anchor_arm` writes `value | 1`, `:174`).
- **SDK semantics:** `ownership/REPORT.md` states `global_tstamp` is ingress arrival time, so
  t0q is request arrival at the switch, not the first admission relay [V, REPORT text]. Whether
  `global_tstamp` shares one time base across pipes is [I]: carrying t0q inside the handoff header
  means T never samples its own clock for t0, but T's `now` (`:257`) is compared with N's t0q, so the
  shared time base is required. Test T2-CLK-XPIPE must measure the offset before any claim.
- **Where it is stored:** not in N. N carries `t0q` in the typed event (1.4) to T. T writes it into the
  anchor register at the end of the ADMIT passes (1.5). The anchor cell becomes a 64-bit
  `{cookie32, t0q|1}` cell (`[I]` SALU form follows `NativeOriginalCredit`, `original_credit_native.p4:73-80`
  which already compares two 32-bit fields in one SALU) so a stale writer or reader of an older
  cookie cannot arm or read a new association. This replaces explicit clearing (0.2).

### 1.3 Identity reconciliation (single proposal)

Three identities exist today. They are never mixed.

| Identity | Width | Minted by | Lives in | Used for |
|---|---|---|---|---|
| connection epoch | 32 | N, at SYN: `first_syn: hdr.envelope.epoch=m.generation` (`native_binding.p4:186`); written by `store_epoch` (`:122`, `:124`) | N `epoch` bank; copied into every typed event | authority over connection incarnation |
| WorkRef = epoch32 + work generation32 | 8 bytes | N's allocator `allocate` (`:66`), T's own allocator (`held_timing_expected_probe.p4:338-344`) | N `ExpectedWorkRecord` (`work_record.p4:14-19`), T's own instance | pinning one producer through its passes only |
| timing cookie16 (zero-extended to 32 on interfaces) | 16, non-wrapping | **T**, by `OwnerCell.arm_cell` (`ownership/p4/owner_cell.p4:23-26`: `if (value < 65535) value=(value+1)|0x10000`) | T lifecycle cell low 16; credit words `cookie16<<16` (`original_credit_native.p4:56-62`); `AssociationBinding.key` (`association_binding.p4:5-9`) | one READ association, per-kind original receipts, stale-return rejection |

Rules:
1. **WorkRef never crosses the N/T boundary as authority.** `tev.wgen` (below) is carried for
   diagnostics only; T validates nothing against it.
2. **The cookie is not the N owner low 16 bits.** N's owner low16 is minted once per connection at SYN
   (`claim_syn` adds `0x10001`, `native_binding.p4:162`). Original receipts need a fresh cookie per
   READ because the issued bit survives debit (`original_credit_native.p4:56-62`, `reference.py:210-216`).
   `PLAN.md:106-107` already states timing generation is separate.
3. **Association key at T = (epoch32 from N, cookie16 minted by T).** N proves the packet belongs to the
   live connection and matches sequence/application; T proves identity of the timing association.
4. Cookie budget: 16-bit non-wrapping, refuse at 65535 (`owner_cell.p4:26`, `reference.py:44`).
   The accepted campaign is 16,168 attempts (`Codex_...Prompt.md:158`), under 65,535.
   [I] No controller rearm is authorized by Task1. Saturation is a counted persistent refusal
   (T2-EXHAUST); resetting only the counter is refused. Any future fresh, quiescent
   initialization must qualify all tagged state separately.

### 1.4 Private events and kinds

N private envelope is the existing 16 bytes (`native_binding.p4:24-27`, `reference.py:189-207`):
epoch32, work generation32, expectedCell32, event16, reserved16. Event = stage<<8 | kind.
`reserved16` stays 0 (checks at `native_binding.p4:36`, `:277`, `:292`). **No change to the envelope size.**

Existing kinds [V]: 1 SYN, 2 SYNACK, 3 ACK, 4 close, 5 SELECT, 6 response, 7 OPERATE, 8 forward original
(added in `78a0b50da`, `native_binding.p4:196-199`), 255 abort.

New kinds (all three READ kinds are new; kind 8 is reused only as a *pattern*):

| Kind | Packet (validated) | Direction | Owner command | Path |
|---|---|---|---|---|
| 9 READ_REQ | 20-byte DNP3 request, IP len 60, TCP 16 or 24 | client to server (dir 1) | mutating: claim then publish | like SELECT (kind 5): 4-pass, bank store client := seq+20 |
| 10 READ_ACK | pure ACK from outstation, IP len 40, flags 16 | server to client (dir 2) | **none** (kind-8 pattern: no owner command, no carry, no CAS) | 4-pass work, then handoff instead of forward |
| 11 READ_RSP | 49-byte DNP3 response, IP len 89, flags 16/24 | server to client (dir 2) | mutating: claim then publish | like kind 6: server bank store := seq+49 |

Native owner states: established idle is 5 [V from `native_binding.p4:162-167` and `first_event` row
`(8w3,...,0x40000)`, `:195`; SYN 1->2, SYNACK 3->4, ACK 5; SELECT 8->9, response 10, OPERATE 11->12].
New states 13 (0xd READ claimed), 14 (0xe READ outstanding). READ_RSP publishes back to **5**, so a
later SELECT still matches `first_select` (observed 0x4 or 0x5, `:195`).

Parser selection additions (`native_binding.p4:37`, `envelope_event`): add
`0x0109 0x010a 0x010b 0x0209 0x020a 0x020b 0x0309 0x030a 0x030b` (nine values, same shape as the
kind 5..8 loop in `generate.py`'s `for s in (1,2,3) for k in (5,6,7,8)`).
`ip` select (`:39`): add `(4w4,4w5,8w6,16w60):read_ip_flags` and `(4w4,4w5,8w6,16w89):read_response_ip_flags`.
New parser states mirror `native_ip_flags/native_tcp/native_dl` and `response_*` (`:47-52`) and set
`m.packet_kind` 9 (request) and 11 (response). Pure ACK length 40 already parses (`:41`, state `ack`).

Table additions (rows only; no new dependency edge, see 2.2):

| Table (line) | Rows added |
|---|---|
| `network` (`:77`) | kinds 8, 9, 10, 11 with their TCP flags; `size` 16 to 24 |
| `direction_guard` (`:87`) | `(9,1)`, `(10,2)`, `(11,2)` as NoAction; size 8 to 11 |
| `return_kind_guard` (`:273`) | `(9,9)`, `(10,10)`, `(11,11)` NoAction; size 12 to 15 |
| `short_shapes` (`:85`) | none; pure ACK from server needs `(2,16)` ack shape. Today only `(1,16)` exists; `direction_guard` has no `(3,2)` so reverse ACK is unclaimed [V `:85`, `:87`, test at `test_native_binding.py:172`]. READ_ACK is a **new kind 10**, not kind 3. |
| `sequence_diff` (`:153-155`) | `(2,16): diff_reverse` for kind 10 (client_diff := seq-server, server_diff := ack-client) |
| `data_sequence_diff` (`:152`) | kind 9 `diff_forward` (client/server diff against banks), kind 11 `diff_read_response` with `ack_native` = ack (no 20-byte shift: READ is unpadded) |
| `next_seq_t` (`:142`) | `next_read_request` +20, `next_read_response` +49 |
| `client_t` (`:130-131`), `server_t` (`:137-138`) | `(1,9,1,2): store_client`, `(1,11,1,2): store_server` |
| `owner_command` (`:176-178`) | `claim_read`(5->13), `publish_read`(13->14), `claim_read_rsp`(14->15), `publish_read_rsp`(15->5); size 16 to 20 |
| `first_event` (`:193-195`) | kind 9 observed 0x50000, kind 11 observed 0xe0000; kind 10 gets its relabel via `forward_event` style rows with observed 0xe0000 |
| `forward_event` (`:197-199`) | add kind 10 (READ_ACK) rows, observed 0xe0000, sequence_valid 1 |

Changing the 16-byte envelope's role at the final pass: N stage-3 terminal currently does
`setInvalid` on the four envelope headers and emits the original (`:313`). For kinds 9, 10, 11 it instead
**replaces** the envelope with the T typed event below and sends to T. For kind 9 the request itself
is carried to T and forwarded by T after admission (1.5), so exactly one copy exists at a time.

T typed event `tev_h` (new, 16 bytes, prefixed to the original frame, the original is never parsed beyond Ethernet in T except for requests):

| Field | Bits | Meaning |
|---|---|---|
| epoch | 32 | N's verified connection epoch (`m.epoch`) |
| wgen | 32 | N WorkRef generation, diagnostics only |
| t0q | 32 | N-sampled request arrival, quantized; meaningful for kind 9, zero otherwise |
| kind | 8 | 9 READ_REQ, 10 READ_ACK, 11 READ_RSP, 4 RESET |
| stage | 8 | 0 on arrival from N |
| reserved | 16 | must be 0 (parser rejects nonzero, same discipline as `held_timing_expected_probe.p4:101-105`) |

T typed parse rule: `(kind,stage,reserved) in {(9,0,0),(10,0,0),(11,0,0),(4,0,0)}` else reject.
The request's req_end (`seq+20`) and server next sequence (`ack`) are computed by T from the original
TCP header inside the typed packet (T needs no extra words). N has already validated them against its own
banks (`diff_forward` for kind 9; `diff_reverse` for kind 10; `diff_read_response` for kind 11),
so T does not repeat the association match (it would add 2 stages to T's chain, see 2.3).

T's held-loop envelope is unchanged (`held_timing_expected_probe.p4:37-40`, 20 bytes,
`reference.py:246-259`).

### 1.5 Flow, pass by pass (READ exchange)

READ_REQ (kind 9):
1. N P0 (raw, dp9): parse, network/direction/profile/CRC validate (profile = `validator.p4:43-44`
   row; CRC = `validator.p4:55-56`, `:75-76`), `t0q` sample, `connection` table, mint+claim work
   (`:291`, `:293`), snapshot with event `0x0109`.
2. N P1 (`0x0109`): epoch/owner claim `5->13`, `client := seq+20`, carry.
3. N P2 (`0x0209`): owner publish `13->14` (publication requires full epoch and owner word,
   `native_binding.p4:311`).
4. N P3 (`0x0309`): terminal. Envelope replaced by `tev(kind 9, t0q)`, sent to T port `T_IN`.
5. T ADMIT passes (the request frame is the carrier; 4 passes, because one Register array is accessed once per pass,
   `ownership/REPORT.md` "Three indexed installs cannot release their producer on the same early SALU stage"):
   - A1: `lifecycle.arm` (mint cookie, refuses at 65535 or if phase not idle) plus read `OriginalDebt` (must be 0; `original_debt.p4:11-37`).
   - A2: `NativeOriginalCredit.install(idx0 ACK)` with `cookie16<<16`, epoch from `tev`.
   - A3: install idx1 (response). Index 2 (OPERATE) unused in READ.
   - A4: write anchor `{cookie, t0q|1}`; install `AssociationBinding` key (epoch, cookie).
   Then T forwards the **original request** to `dp64` (table kind to port). If A1 refuses (busy, exhausted,
   policy off) the request is forwarded unchanged and counted `BYPASS_BUSY` (`POLICY_CONTRACT.md:101`).
   Install barrier [V]: `original_credit_native.p4:89-97` requires the caller to hold a genuine producer
   pin and zero owned bits before install. A1's debt check plus lifecycle-idle plus T's own WorkRecord pin is that barrier.

READ_ACK (kind 10) and READ_RSP (kind 11):
1. N P0..P3 as above (kind 10 uses the kind-8 nonmutating pattern; kind 11 mutates server bank and owner).
2. T R1 (arrival): read credit word (`result`) to learn the active cookie; check `tev.epoch == association epoch`;
   claim a T work pin (T's own `ExpectedWorkRecord`, `held_timing_expected_probe.p4:500`).
3. T R2/R3: `OriginalCredit.admit` for idx0 or idx1 with `expected_credit`; this is `role 2`
   (`:503`, `:527-531`); successful admission sets `seen_mask` 1 (ACK) or 2 (response) via
   `successful_admission` (`:262-267`, `:259-261`).
4. T R4: loop in `HELD_RETURN` (`role 7`, `:548`) until `original_eligibility` (`:318-332`) fires or policy-off.

Release rules (kept from the probe, with the 0.3 gaps closed by tickets):
- ACK eligible when `seen == 3` and `now >= t0q + D_A` (`heartbeat_eligibility` row 1, `:287`) or readiness `now >= t0q + 29,999,872` (row 2, `:288`).
- ACK commit: `response_clock` row `(5,1,2,2,1,_)` writes `response_deadline = now + 999,936 | 1` (`:234`, `:273`, `:224-226`).
- Response eligible when `response_ready == 1` (`:324-326`), set by heartbeat service once `now >= response_deadline` (`:307-312`, `:243-248`).
- e_A = max(t0 + D_A, t_A, t_R) is realized as "seen==3 AND now >= t0+D_A", evaluated by heartbeat (every 100 us requested,
  `heartbeat_spec.json`) and by each held loop pass. e_R = actual ACK commit + 999,936 ns
  (`ownership/REPORT.md` "Timing and heartbeat": anchor is the commit service packet, not ideal t0+D_A).
- Internal commitment is not physical departure (`PLAN.md:112`, `POLICY_CONTRACT.md:20`, `Codex_...Prompt.md:72`).
  Do not report timestamps from T as departures.

## 2. Pass and stage budget

### 2.1 Pass count per exchange (normal path)

| Packet | N passes | T passes | Extra bytes per T pass | Notes |
|---|---|---|---|---|
| READ_REQ | 4 | 4 (ADMIT) | 16 (tev) | request forwarded after T A4; delay not measured |
| READ_ACK | 4 | 3 producer + loop L_A + 1 terminal | 20 (held envelope) | L_A unknown, depends on loop latency |
| READ_RSP | 4 | 3 producer + loop L_R + 1 terminal | 20 | same |
| heartbeat | 0 | 1 pktgen + 3 service (`:481-499`) | 28 (`heartbeat_service_t`, `:32-35`) | independent of originals |

Per-exchange recirculated bytes are payload-dependent: ACK frame 54 bytes, response 103 bytes (14+20+20+10+49-... [I] exact layout from `first_h/second_h/tail_h`, `validator.p4:12-14`).
Loop packet rate is `1/loop_latency` per held original and is **not measured** anywhere in the repository
([V] `ownership/REPORT.md` lists "packet spacing/queue latency" as unverified). Ticket T-BW records it.

### 2.2 Role N: where READ lives without lengthening the chain

From `native_03/.../table_summary.log` (stages as allocated) [V]:

| Stage | Existing tables | READ rows or tables added (parallel, no new dependency) |
|---|---|---|
| 0 | `ports`, `network` | rows for kinds 8-11 (0.4) |
| 1 | `connection`, `input_head_t`, CRC tables, `data_connection`, `profile`, `response_profile`, conditions | `read_request_profile`, `read_response_profile` (ternary rows as in `validator.p4:43-46`), `request_crc`, READ response CRC tables (3) |
| 2 | CRC comparison conditions | READ CRC compares |
| 3 | `data_guard` | READ rows only; `m.profile` set by the READ profile tables |
| 4 | `return_kind_guard` | rows |
| 5 | `direction_guard`, `next_seq_t` | rows |
| 6 | `mint_t` | none |
| 7 | `work.dispatch` | none |
| 8 | `epoch_t`, `client_t`, `server_t` | store rows |
| 9 | `epoch_diff_t`, `ack_native_t`, `sequence_diff` | `(2,16)` row |
| 10 | `data_sequence_diff`, `owner_command` | rows |
| 11 | `sequence_guard`, `owner_t` | none |
| 12-15 | bank compare chain, `object_match` | **not entered by READ** (0.5 predicate fix) |
| 15-18 | `snapshot_t`, `first_event`, `forward_event`, `next_stage_t` | rows |

Net: READ in N is chain-neutral by construction. It does **not** repair 19/12. After READ rows the acceptance
for N is: stage count unchanged (19, or lower if the step-1 owner shrinks it) and critical path 18 unchanged. [I] Hash-unit
pressure at stages 1-2 (native already has `hash_head`, `hash_body`, `hash_tail`, `hash_first`, `hash_second`,
`hash_response_tail`, `native_binding.p4:93-113`; READ adds up to 4 more) is untested. If the compiler
refuses, serialize READ CRC tables one stage later (legal: they feed only `data_guard` at stage 3).

### 2.3 Role T: where the join lives, and the honest fit

Baseline critical path from `held_timing_expected_02/.../table_summary.log` [V]:
work/heartbeat_work dispatch (stage 4) -> `held_dispatch`/`admission` (5) -> `successful_admission`/`terminal` (6)
-> `timing_authority` (7) -> `ready_event`/`release_event`/`timing_admission` (8) -> `original_eligibility`
and `anchor_event`/`observation_event` (9) -> `credits.event` (10) -> `response_clock` and byte writers (11) -> forwarding tables (12).

Changes and their stage effect:

| Change | Stage effect | Basis |
|---|---|---|
| D_A, readiness, gap from table action data | none (same table, non-const default action) | `:270-275` |
| 40 ms cap as an extra `heartbeat_eligibility` ternary row | none | `:283-292` |
| FALLBACK_NO_ACK: add `readiness_delta` ternary to `response_eligibility` | none; `md.readiness_delta` exists at stage 3 | `:276-280`, `:306-312` |
| Cookie-tagged anchor, observations, releases, ready, response deadline (64-bit cells) | none if the SALU predicate fits; **[I] unverified** | pattern `original_credit_native.p4:73-80` |
| Remove OPERATE original (kind 3, `abort_unsent_operate`, bit0 release), ports 69/70 parser states | frees tables, not stages | `:27-28`, `:99-106`, `:424-429` |
| Remove `heartbeat_work` pin; protect service by cookie tag instead | removes one stage-4 SALU instance | `:157`, `:494-499` |
| Add `lifecycle` (OwnerCell arm) at stage 6-8 | none **only** if placed beside `successful_admission`; **[I] unverified**; ACK-COMMITTED is derived from the response-deadline armed bit, not stored (one-table-one-register trap) | `owner_cell.p4:23-26`, MEMORY note "A Tofino table may access only ONE Register" |
| Association match (seq/ack/app) inside T | **would add about 2 stages** (ctx register -> diff -> guard before `successful_admission`) | therefore done in N (1.4) |

Fit statement: T with these changes is expected to stay at 12 stages **only if** every row above is chain-neutral.
Nothing here is compiled. If `lifecycle` forces a 13th stage, drop it and derive phase from the existing
registers plus the cookie tag; the arm then becomes the `AssociationBinding.install` write in A4. Record
the first compile as evidence; do not report a fit before it exists.

### 2.4 What this does and does not do to native_03 (19/12)

- Does not make it worse by construction (2.2). Compile the delta to prove it (ticket T-NATIVE-READ acceptance).
- Cannot fix it. The fix is a step-1/step-3 structural move (1.1 last paragraph). If someone asks for same-pipe,
  the answer is: not without removing at least 7 stages of N, and T has no slack.

## 3. Port plan

Sources disagree today. [V]

| Role | Probe/source value | Where |
|---|---|---|
| master side, ingress of requests; egress target of ACK/response | 9 | `integration/egress_wire.p4:988-994`, `defense4/timing/response_ready/src/defense4_response_ready.p4:190` |
| outstation relay | 64 | `egress_wire.p4:991-994`, `defense4_response_ready.p4:196` |
| N private work recirculation | 68 | `native_binding.p4:14`, `protocol/payload_mapping/forward.p4:13`, `protocol/assembly/producer.p4:1762` |
| heartbeat pktgen source | 68 | `held_timing_expected_probe.p4:81`, `ownership/heartbeat_spec.json` |
| ACK fixture input | 69 | `held_timing_expected_probe.p4:27`; response-ready uses 69 as a validated handoff, `defense4_response_ready.p4:24` |
| typed producer seam | 70 | `held_timing_expected_probe.p4:28`; `split.py:19` uses 70 as `VALIDATION_RETURN_PORT` |
| held return | 71 | `held_timing_expected_probe.p4:29` |
| forward sink | 72 | `held_timing_expected_probe.p4:30` |
| heartbeat service return | 73 | `held_timing_expected_probe.p4:82` |
| known loopbacks on this testbed | 8, 10 (11 is the Hulk replay leg) | `defense4_response_ready.p4:189-205`, `PIPE_SPLIT.md:17-18` |

Conflicts:
- 68 is both the pktgen source and the N recirculation port in the existing sources. With N in pipe 0 and T in
  pipe 1 the two roles sit on different pipes' local port 68, so the collision disappears. [I] depends on dev-port
  numbering (pipe 1 local 68 is dev 196 by the usual `pipe<<7|local` rule; not read from a config in this repo).
- 69 and 70 carry different meanings in `held_timing_expected_probe.p4`, `split.py` and `defense4_response_ready.p4`.
- 72 and 73 are above local port 71. Tofino-1 has 72 local ports per pipe (local 0..71) [I]. These two values cannot be valid
  as written; they are provisional compile roles.

Proposed assignment (all private roles provisional until a topology check, gate G-PORTS):

| Role | Pipe | Port | Change |
|---|---|---|---|
| client, relay | 0 | 9, 64 | unchanged. READ stays `bypass_egress=1` (`validator.p4:36`, `egress_wire.p4:922`); egress 9/64 dispatch by `egress_rid` (`egress_wire.p4:1030`) is untouched |
| N recirculation | 0 | 68 | unchanged |
| N to T handoff target (`T_IN`) | 1 | one pipe-1 loopback port | new; replaces probe 69/70 |
| T held loop (`HELD_RETURN`) | 1 | one pipe-1 loopback port | was 71 |
| T heartbeat service return (`HB_RETURN`) | 1 | one pipe-1 loopback port | was 73 |
| T pktgen | 1 | local 68 | was 68 |
| T to client/relay forwarding | 1 -> 0 | 9 and 64 via a controller-written `kind -> port` table | replaces probe 72; T sets `bypass_egress=1` (`:480`) so N egress never sees READ |

Three private loopback ports in pipe 1 are required. The repository does not show which pipe-1 ports are loopback-capable.
Alternative needing one port: one private header with a leading role byte (cost 1 byte per pass), decided by `ingress_port`
plus role. Not recommended before G-PORTS because it perturbs every existing parser.

Mechanical guard (ticket T-PORTS): a unit test parses every `PortId_t` constant and every `9w<N>` literal in the READ sources and fails
if one numeric port has two ingress roles, or if a value above 71 is used as a local port.

## 4. State machines

### 4.1 State variables (T) and their derivation

| Variable | Representation | Stage placement |
|---|---|---|
| association phase | IDLE, ACTIVE, ACK_COMMITTED, QUARANTINE, derived from cookie word, response-deadline armed bit, and a quarantine tag; ACK_COMMITTED = response deadline armed | `reference.py:10-13` for the phase constants |
| anchor | `{cookie, t0q|1}` | stage 9 (`anchor_event`) |
| seen | `{cookie, mask}` bit0 ACK, bit1 response | stage 9 (`observation_event`) |
| release | `{cookie, mask}` bit1 ACK release (bit0 unused in READ) | stage 8 (`release_event`) |
| response deadline | `{cookie, (now+999936)|1}` | stage 11 (`response_clock`) |
| response ready | `{cookie, 0/1}` | stage 8 (`ready_event`) |
| receipts | 2 indexed credit words `cookie16<<16 | owned bit0 | issued bit8` | stage 10 |
| debt | 0..3 aggregate | `original_debt.p4` |
| policy | register read every pass | `:347-350`, `:479` |

Clock: `due(now,deadline) = ((now-deadline) mod 2^32) < 2^31` (`reference.py:113-115`), implemented as the sign bit of the 32-bit delta
(`:287-289`, `:310`). Valid while intervals are under 2^31 ns (2.147 s); the 40 ms cap is far inside.

### 4.2 Held-ACK

| State | Event | Guard | Next | Action | Test |
|---|---|---|---|---|---|
| ACTIVE, ACK not seen | N kind 10 arrives | epoch ok, cookie active, credit idx0 unissued | ACK_HELD | admit receipt, seen bit0, loop | T2-EARLY, T2-LATE |
| ACK_HELD | heartbeat | seen==3 and now>=t0+D_A | ACK_ELIGIBLE | release bit1 OR-ed | T2-DA-5/10/15/20 |
| ACK_HELD | heartbeat | now>=t0+29,999,872 and seen!=3 | ACK_ELIGIBLE (fallback) | release bit1 OR-ed | T2-ABSENT |
| ACK_ELIGIBLE | held pass | release bit1 and cookie valid | ACK_COMMITTED | debit receipt, commit response deadline now+999,936, forward original once | T2-DELAYED-COMMIT |
| ACK_HELD | duplicate ACK original | credit issued bit set | unchanged | suppress | T2-DUP |
| any | policy off | `(4,0,1)` | ACK_RELEASED | debit receipt, forward unchanged | T2-POLICY-OFF |
| any | cap t0+40 ms | now>=cap | ACK_ELIGIBLE | forced release (**row to add**) | T2-CAP |

### 4.3 Response

| State | Event | Guard | Next | Action | Test |
|---|---|---|---|---|---|
| ACTIVE | N kind 11 arrives | epoch, cookie ok, credit idx1 unissued | RSP_HELD | admit, seen bit1, loop | T2-EARLY |
| RSP_HELD | ACK committed (deadline armed) and heartbeat | now>=response_deadline | RSP_ELIGIBLE | `ready_response := 1` | T2-DELAYED-COMMIT |
| RSP_HELD | no ACK, readiness expiry | now>=t0+29,999,872 and deadline unarmed | RSP_ELIGIBLE (fallback no-ACK) | `ready_response := 1` (**row to add**, 0.3) | T2-ONE-LOST |
| RSP_ELIGIBLE | held pass | ready==1 | RSP_RELEASED | debit, forward once | T2-LATE |
| RSP_HELD | duplicate response original | issued bit | unchanged | suppress | T2-DUP |
| response arrives after fallback | ACK already released, association finished | cookie mismatch or quarantine | forwarded natively | count LATE_RESPONSE (`POLICY_CONTRACT.md:101`) | T2-LATE |
| response before ACK, ACK after | owner back at state 5 after publish | ACK not READ_ACK | forwarded unheld, counted `READ_ACK_LATE` | **unsupported outcome, explicit** | T2-ACK-AFTER-RSP |

### 4.4 Heartbeat (independent of originals)

| State | Event | Guard | Next | Action | Test |
|---|---|---|---|---|---|
| any | pktgen tick (100 us requested) | service allowed (cookie-tag protection, no pinned record) | service P1 | snapshot anchor, seen, response deadline | T2-HB-INDEP |
| service P1/P2 | return | emitted phase equals expected | P2/P3 | compute eligibility | T2-HB-INDEP |
| service P3 | terminal | cookie matches current | idle | OR release, set ready | T2-HB-INDEP |
| lost service pass | none | none | next tick proceeds | no wedge (**requires dropping `heartbeat_work`**) | T2-HB-LOSS |
| both originals lost | ticks continue | now>=readiness | association stays QUARANTINE with debt>0 | no fabricated terminal | T2-BOTH-LOST |

### 4.5 Policy-off, reset quarantine, reuse

| State | Event | Guard | Next | Action | Test |
|---|---|---|---|---|---|
| held original | policy register 0 | `held_dispatch (4,0,1)` | terminal | debit by actual receipt, forward ACK/response, abort nothing in READ | T2-POLICY-OFF |
| ACTIVE or ACK_COMMITTED | RESET typed event (kind 4 from N, validated FIN/RST) | epoch equal | QUARANTINE | held originals flush on next pass; cookie debited; no new admit | T2-RESET |
| QUARANTINE | credits all zero, debt 0 | heartbeat | IDLE | retain nonwrapping cookie; no counter-only rearm | T2-REUSE |
| QUARANTINE | credit still owned | lost original | stays QUARANTINE | reuse refused until controller drain | T2-BOTH-LOST |
| any | clock wraps | `now-deadline` crosses 2^32 | unchanged semantics | modular compare | T2-WRAP |

Transitions tied to every item in the `PLAN.md:65` list: early, late, absent response (4.2/4.3 rows), D_A 5/10/15/20 (4.2 row 2),
delayed actual ACK commitment (4.2 row 4 and 4.3 row 2), one or both blockers lost (4.4; see Devil's advocate 5.2 for what a "blocker" is here),
independent heartbeat (4.4), duplicate originals (4.2/4.3 dup rows), policy-off while held (4.5), clock wrap (4.5).

### 4.6 Independent expected-output reference

Do not write another P4 transcription as the sole oracle (`PLAN.md:70-75`). Use `ownership/reference.py`
`Schedule` (`:122-147`), `due` (`:113-115`), `quantize` (`:118-119`), `HeldCredits` (`:210-243`), `HeldPacketLoop` (`:269-332`)
as libraries. Packet bytes from the existing codecs and checksum helpers. A new class is allowed only for the T
lazy-cookie reset (not in `reference.py`) and for N kinds 9-11; keep it under 120 lines and cross-check it against `Schedule`.

## 5. Devil's advocate

5.1 **Wrong or unfaithful: t0 is request arrival, but the ACK is not necessarily held from request arrival.**
The assignment says D_A is request-relative and not automatically the actual ACK hold (`Codex_...Prompt.md:72`,
`POLICY_CONTRACT.md:19`). This design samples t0q at N pass 0 and delivers it to T after 8 passes plus a
cross-pipe hop. If the outstation ACK arrives before T finishes ADMIT (A4), T has no association and the ACK is
forwarded unheld, silently bypassing the timing path. That would look like a pass in an aggregate and hide a violation.
Catching test: **T2-RACE-ACK**, an ACK emitted before ADMIT completes must be counted `READ_ACK_BEFORE_ADMIT` and excluded
from the timing denominator, never counted as normal. Also T2-CLK-XPIPE (shared time base across pipes).

5.2 **Wrong or unfaithful: "blocker" has no analogue.** `PLAN.md:65` says "one/both blockers lost", written for the old pktgen
blocker tokens. The held-original design carries the original packet itself in its holding loop and has no separate
blocker (`ownership/REPORT.md` "Actual packet holder"; `POLICY_CONTRACT.md:107-110` "conserves original envelopes, not blocker arrivals").
I defined the analogue as loss of the circulating held ACK and/or response original. If the reviewer meant
queue-resident blocker packets, this design does not cover them. Catching test: **T2-ONE-LOST / T2-BOTH-LOST** drop the circulating
original mid-hold and assert (a) heartbeat keeps advancing (needs the `heartbeat_work` removal), (b) the other original is released by
readiness, (c) no fabricated terminal, (d) reuse stays refused until controller drain, (e) the 40 ms cap still applies to what remains.
Ask the plan owner to confirm this reading.

5.3 **Wrong or unfaithful: splitting N and T across pipes may be unbuildable, and then the join is a paper design.**
Cross-pipe handoff, pipe-1 ports and cross-pipe forwarding are unverified, and an internal-link loss is indistinguishable from
network loss, so a lost handoff packet silently loses an original. It would also move the request forwarding point (T forwards the request).
Catching tests: **T-XPIPE-MODEL** (gate; requires legitimate target-model execution, currently blocked by the CAP_NET_RAW failure,
`HANDOVER.md:75-77`), plus **T2-HANDOFF-LOSS**: drop the N-to-T packet in the packet harness for each of request, ACK, response, and assert
the owner state and cookie state remain consistent (no owned credit without an original, and TCP recovery is not claimed).

5.4 **Smaller risks**
- The cookie-tagged 64-bit SALU predicates are inferred; the ADMIT barrier (zero owned bits, `original_credit_native.p4:89-97`)
  spans multiple passes; a refused compile forces explicit clears. Test: T2-REARM (back-to-back READs, first fully terminal, second sees zero state).
- Retransmitted READ request (seq below client bank) fails `sequence_valid` and is dropped by the current abort path (`HANDOVER.md:51`
  "out-of-sequence duplicate ACKs are still dropped"). Step 4 owns the repair; step 2 must not claim retransmission support.
- Timing accuracy is bounded by heartbeat period (100 us requested) for ACK eligibility and by loop latency for the gap. The 10 us median and 50 us 99.9% criteria
  (`Codex_...Prompt.md:162`) are for the gap, not for e_A; do not mix them.

## 6. Ordered build list (small TDD tickets)

Each ticket starts with a red test that fails for the stated reason. New files only under the listed paths.
No frozen sources are edited. Commits by the lead with Philip's identity (`CLAUDE.md` hard rules), no trailers.

| # | Ticket | Files | Red first | Acceptance |
|---|---|---|---|---|
| 0 | **Gate G-PORTS and G-XPIPE** (human/lead, no code): verify pipe-1 ports, cross-pipe forwarding, `global_tstamp` offset between pipes | `integration/read/GATES.md` (new) | none | written result; if negative, stop and decide same-pipe restructure; tickets 8 and later depend on it |
| 1 | READ join reference | `integration/read/join_reference.py`, `tests/test_read_join_reference.py` | e_A, e_R equations vs `reference.Schedule` for D_A 5/10/15/20, early/late/absent, clock wrap | 100 percent of matrix equal to `Schedule`; fallback finite at 30 ms; cap at 40 ms |
| 2 | Port constants + uniqueness | `integration/read/ports.p4`, `tests/test_read_ports.py` | duplicate role or value >71 detected | single source of every private port; test green |
| 3 | N predicate fix and `network` rows (step-1 defect 0.4/0.5) | `integration/connection/binding/generate.py` (extend only via a new generator step in a new file `integration/read/native_read_rows.py` that edits the generated text) | new fragment test applying `network` for kind 8 fails | `network` has rows for kinds 8-11, size 24; `packet_kind` predicates are `{5,6,7}`; existing 22 binding tests plus new pass |
| 4 | N READ parser, tables, owner commands (kinds 9, 10, 11) | `integration/read/native_read_rows.py`, `integration/read/tests/test_native_read.py` | READ request at state 5 is dropped today | request claims 5->13->14, ACK nonmutating at 14, response 14->15->5; foreign tuple, epoch, link, CRC, wrong app seq never mutate owner; compile delta reports stage count not above native_03 (19) |
| 5 | `tev_h` and N terminal replacement | `integration/read/native_read_rows.py` | terminal still emits original | N P3 emits `tev(kind,t0q)` with original bytes unchanged, reserved 0; `t0q` low 8 bits zero |
| 6 | T program: parametrized D_A, readiness, gap, cap | `integration/read/read_timing.p4` (new, copy-evolved from the probe, probe untouched), `tests/test_read_timing_params.py` | D_A is the constant 4,999,936 | all four D_A offsets and the cap come from action data; source hash recorded; compile ≤12 stages or the failure preserved |
| 7 | T cookie-tagged state, lazy rearm, drop `heartbeat_work` | `read_timing.p4`, tests T2-REARM, T2-HB-LOSS | second READ sees first READ's anchor | stale cookie cannot arm, read, or OR; lost service pass does not wedge |
| 8 | T ADMIT passes (A1-A4) and request forward | `read_timing.p4`, `tests/test_read_admit.py` | no cookie mint exists | cookie minted once per READ, refuse at 65535, `BYPASS_BUSY` forwards request unchanged, debt/lifecycle barrier honored |
| 9 | T ACK/response original admission + hold + release | `read_timing.p4`, `tests/test_read_originals.py` | none of the READ release rules implemented for ACK/response only | T2-EARLY, T2-LATE, T2-ABSENT, T2-DA matrix, T2-DELAYED-COMMIT, T2-DUP |
| 10 | Fallback no-ACK and cap rows | `read_timing.p4` | response with no ACK never released | T2-ONE-LOST, T2-BOTH-LOST, T2-CAP |
| 11 | Policy-off and reset quarantine | `read_timing.p4`, N kind 4 to T `RESET` event | policy-off leaves held originals | T2-POLICY-OFF, T2-RESET, T2-REUSE |
| 12 | End-to-end packet harness for the join | `integration/core/` (planned in `PLAN.md:70-75`), `integration/read/tests/test_join_packets.py` | harness absent | real frame bytes through both roles; compares to `join_reference.py`; T2-RACE-ACK, T2-HANDOFF-LOSS; unavailable pieces reported as skips |
| 13 | Compile evidence | `build.py` fresh evidence dirs `read_join_01...` | none | N delta, T, and both recorded with source hashes; fit stated honestly; failures preserved |
| 14 | Bandwidth/loop accounting | `integration/read/BANDWIDTH.md` | none | pass and byte counts of 2.1 filled with measured values when the model runs; until then marked unmeasured |

Commands to reuse (from `PLAN.md:94-98`): the three existing `unittest discover` runs, plus the new tests above.

## 7. Verification of this note

Files read: `PLAN.md`, `HANDOVER.md`, `LEDGER.md`, `Codex_Case4_Hardware_Architecture_Prompt.md`, `integration/read/validator.p4` and README,
`ownership/p4/held_timing_expected_probe.p4`, `original_credit_native_probe.p4`, `original_credit_native.p4`, `expected_work_record.p4`,
`owner_cell.p4`, `association_binding.p4`, `original_debt.p4`, `ownership/reference.py`, `ownership/REPORT.md`, `ownership/heartbeat_spec.json`,
`integration/connection/binding/native_binding.p4`, `work_record.p4`, `generate.py`, the binding tests, `integration/egress_wire.p4`,
`integration/PIPE_SPLIT.md`, `defense4/timing/response_ready/README.md`, `POLICY_CONTRACT.md` (lines 19-130), and the two compile logs quoted.
Not done: no compile, no test run, no packet execution, no hardware. Items marked [I] are inferences.

### Task1 reviewed cancellation boundaries

Pinned request returns sample current policy and full-epoch quarantine. Refusal
is carried on stages12/13 to the genuine expected-generation/phase terminal;
the request forwards once. Mint requires the actual phase2 Work grant. Cancel
before mint leaves the counter untouched; cancel after ACK-receipt installation
retains the consumed cookie and that receipt, with no response receipt, binding
or anchor publication. The next permitted request consumes the next cookie.
No production reset/rollback authority is introduced. Current source52b43d5a
fits12 ingress stages; stage4 occupancy1SALU/9tables/63xbar is a resource concern,
not the earlier unchanged stage4 claim. Local model boundary presets are
functional diagnostics, not a physical coherent-state mutation procedure.
