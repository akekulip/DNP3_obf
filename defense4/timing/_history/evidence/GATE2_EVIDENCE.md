# Gate 2 — compile evidence + verdict

**Verdict: Gate 2 = FAIL.** Commit `b9ac9e8` (`defense4_timing.p4`) is preserved as a **negative compile
probe**: it compiles clean but is a materially incorrect design with many defects (below). It must be
**replaced**, not incrementally patched (see `IMPLEMENTATION_PLAN.md` / directive §4). `READY_FOR_HARDWARE
_REVIEW.md` is NOT written; Gate 3 is NOT started; no hardware touched.

## Verified compile facts (from the committed logs)

| item | value |
|---|---|
| source | `defense4/timing/p4/defense4_timing.p4` |
| source sha256 | `c877bedd7ef6fca1a10eb443cee8a728dc80a4785d3fb7fae075dd78c8e75cac` |
| compiler | `p4c 9.13.1 (SHA e558d01)` — BF-SDE 9.13.1 (offline; switch not loaded) |
| exact command | `bf-p4c --target tofino --arch tna -g -o build_final defense4_timing.p4` |
| ingress stages | **12 / 12** |
| egress stages | 0 |
| critical path | **12** |
| logical tables | 51 |
| SRAM | 26 |
| Map RAM | 14 |
| TCAM | 2 |
| meter / stateful ALUs | 6 |
| statistics ALUs | 1 |
| PHV containers | 36 |
| PHV used bits | 608 |
| PHV allocated bits | 739 |
| compile result | **0 errors, 3 warnings** |

The committed logs (`table_summary.log`, `mau.resources.log`, `phv_allocation_summary_0.log`,
`gate2_compile_transcript.log`) support those values. **The `context.json` and `.bfa` bytes are NOT
committed**, so the previously listed `context.json`/`.bfa` sha256 (`c951…` / `84b1…`) are **locally
recorded only, not independently verifiable from the repository.** CP 12 = fully serial, at the ceiling.

## Correction: this is NOT "only four properties short"

The earlier note ("four properties short") understated the problem. The compiled design is **semantically
incorrect** across deadlines, modes, tokens/reservoirs, and transaction state:

### Deadline + timestamp failures
1. `T_RESP` is written on **RESPONSE arrival using the RESPONSE packet timestamp**, so D2 approximates
   `t_R + D_R`, **not** `t_A + D_R`.
2. **One deadline register is shared** by the ACK and RESPONSE blockers → D4 cannot preserve `T_A` and
   `T_RESP` simultaneously.
3. Returning and duplicate ACKs **re-arm** the deadline.
4. `dl_arm` returns `age` against the **old** value while writing the new one, so the current packet can
   decide against stale state.
5. Timestamp masked to `0xFFFFFF00` + low-byte marker `1`; expiry also requires an all-zero age low byte.
   Unless `D_A` and `D_TOTAL` are **multiples of 256** timestamp units, expiry cannot match — this
   quantization requirement is **neither enforced nor documented**.

### Mode failures
- `OFF`: RESPONSE has **no release entry** → repeatedly enters `Q_RESP_HOLD`.
- `D1_EVENT`: ACK forwards directly; the ACK blocker **never tests the RESPONSE event**; ACK commitment is
  not obtained.
- `D2_RESPONSE_DEADLINE`: ACK forwards directly instead of traversing inactive `Q_ACK_HOLD`, so normal
  commitment is **never established**.
- `D3_ACK_DEADLINE`: the returning ACK **re-arms `T_A`**; both token roles still use the same expiry.
- `D4_DUAL_DEADLINE`: ACK and RESPONSE **overwrite the same deadline**.
- `FAIL_OPEN`: collision/budget expiry affects only the **current** packet/token — it does not establish
  **generation-qualified shared fail-open** state releasing both held originals.

### Token + reservoir failures
- Both token roles use the **same termination predicate** instead of their per-mode ACK/RESPONSE conditions.
- Tokens carry **no scheduler-domain or flow index**.
- Token parsing stops before IPv4/TCP, yet the program **hashes invalid IPv4/TCP fields** to select
  transaction state.
- EtherType `0x88C1` is **trusted from master and relay ports**; internal token admission is not restricted
  to an authorized pktgen/loopback origin.
- `hdr.tok.budget` is **read before token validity is established**.
- **No token creation, stamping, reservoir seeding, readiness handshake, or not-ready fail-open path** exists.
- `PORT_PGEN` is declared but not parsed/handled — unused.
- Data ACK/RESPONSE carry **no generation-qualified internal shim** through loopback.

### Transaction failures
- Mode + offsets are **not captured as transaction state**; tokens read parameters from their current role,
  not the admitted transaction.
- **Collision detection happens after** deadline/response/ACK-commitment/event state can already change.
- A new request **unconditionally** increments the generation and overwrites the fingerprint.
- **No scheduler-domain owner guard** although all flows share the same four queues.
- No exact **expected ACK number, relay sequence, ports, DNP3 sequence, or one-shot admission** state.
- `reg_event` is **not cleared** on transaction opening or retirement.
- **No complete generation-qualified retirement** path.
- **Combined-response classification + explicit bypass absent**; `predecessor_satisfied` is declared but the
  combined-response `pred_true` behavior is **not actually selected**.

## Consequence
The design must be **replaced** (directive §4), not patched. Before rebuilding, the **reservoir bootstrap**
(established-before-admit without per-transaction external action) must be resolved (directive §3) — if it
cannot be, that is a **Defense 4 FEASIBILITY BLOCKED** outcome, not something to defer to the hardware
phase. **Complete Defense 4 remains NOT DEMONSTRATED.**
