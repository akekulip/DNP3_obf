# Defense 4 upstream contract — the bounded timing primitive a fixed-transcript scheduler may rely on

**Purpose.** State the exact, bounded scope of the upstream Defense 4 timing proof so a downstream
fixed-transcript scheduler can build on it without over-claiming. Defense 4 is a **frozen** upstream result;
this document reads it, it does not rewrite it. All citations are to the source repo at pinned commit `7c4a5a7`.
"Defense 4" here is the upstream working name for that timing result; this project is `DNP3_fixed_transcript`.

**Authoritative sources.**
- `defense4/timing/evidence/EXPERIMENTAL_EVIDENCE_FREEZE.md`
- `defense4/timing/evidence/final_run/NORMALIZATION_ANALYSIS.md`
- `defense4/timing/evidence/final_run/TARGETED_CASES.md`
- `defense4/timing/evidence/final_run/campaign{A,B}_*/blocks.jsonl` (raw fail-closed scorer)
- `defense4/timing/p4/defense4_caseA.p4` (deployed source, sha256 `1242ca4d…`, fix commit `e47bcaa`)

---

## 1. What D4 proves — and what it explicitly does not

**Proves (bounded, accepted).** On the corrected binary, on the physical SEL-751, READ-only: the response-deadline
(D2) and dual-deadline (D4) modes hold the outstation's ACK and RESPONSE inside the switch and release each at a
fixed deadline, normalizing the master-facing CLRT and holding every response with zero bypass, reproduced across
two campaigns (`EXPERIMENTAL_EVIDENCE_FREEZE.md:64-71`). The lifecycle fix, fail-open bounding, and generation
rollover are proven by on-silicon counters (`EXPERIMENTAL_EVIDENCE_FREEZE.md:33-37`).

**Does NOT prove** (`EXPERIMENTAL_EVIDENCE_FREEZE.md:48-62`):
- No size, segmentation, cover-traffic, or full-fingerprint concealment. This is a **timing-only** result
  (`NORMALIZATION_ANALYSIS.md:34-41`).
- No cross-device fingerprint-defeat. It is one physical device; a second comparable separate-ACK (Case A) device
  does not exist in the testbed (`EXPERIMENTAL_EVIDENCE_FREEZE.md:58-61`).
- No claim on the software-outstation negatives (missing ACK/RESPONSE, FIN/RST, combined, multi-segment,
  SELECT/OPERATE) — built and offline-validated 58/58, not run live (`EXPERIMENTAL_EVIDENCE_FREEZE.md:50-54`).
- Live byte-identity is by construction (the switch edits no packet) but a live paired dual-capture proof is not
  available on the single master-facing setup (`EXPERIMENTAL_EVIDENCE_FREEZE.md:55-57`).
- **R11 reservoir readiness** remains a measured margin, carried OPEN (`EXPERIMENTAL_EVIDENCE_FREEZE.md:62`).

**Downstream consequence.** A fixed-transcript scheduler may rely on the **release-timing primitive** below. It may
NOT assume D4 has closed the size/segmentation channel (leakage study Findings 4-9), the TCP-stack channel
(TTL/data_offset device fingerprint, Finding 11), or the TCP-timestamp channel (TSval survives arrival shaping,
Finding 12). Those are separate, still-open axes.

---

## 2. Tested scope (the envelope the guarantees hold inside)

- One switch (Intel Tofino-1) at the outstation edge; master → observed WAN → switch → relay.
- One physical SEL-751 (Case A = separate pure ACK, has a CLRT), READ-only.
- Single-segment responses; one active protected transaction at a time; sequential polling, one sustained TCP
  connection carrying 60 READs per block, DNP3 app-control octet C0..CF rolling over (`TARGETED_CASES.md:24-31`).
- No induced loss or retransmission (raw `blocks.jsonl`: `retransmit:0`, `dup_ack:0`, `dup_resp:0`,
  `multi_segment_resp:[]`, `rst_polls:[]`, `fin_midblock:[]` on every block).
- Modes OFF / D1 (event) / D2 (response deadline) / D3 (D_R=0) / D4 (dual deadline). Deployed policy: D4 with
  **D_A = 4 ms, D_R = 10 ms, budget = 18000** (`EXPERIMENTAL_EVIDENCE_FREEZE.md:75`).

---

## 3. The 240/240 result (source-anchored)

Re-derived by summing the raw fail-closed scorer over both corrected campaigns
(`final_run/campaignA_corrected_binary/blocks.jsonl`, `final_run/campaignB_corrected_binary_seed20260807/blocks.jsonl`):

| mode | transactions | held (early + late) | RESP_BYPASS | RELEASE_DEADLINE |
|---|---:|---|---:|---:|
| D2 (D_A=0) | 240 | 0 + 240 | **0** | **240** |
| D4 (4/10) | 240 | 180 + 60 | **0** | **240** |

Every block `"verdict":"PASS"`, `"exit_code":0`. Matches `EXPERIMENTAL_EVIDENCE_FREEZE.md:24-27`
(pre-fix was D2 240/240 bypass, D4 80/240; fix `e47bcaa`). CLRT normalization
(`NORMALIZATION_ANALYSIS.md:13-17`): D2 p5-p95 spread 0.12 ms (45.6× reduction), D4 spread 0.05 ms (118×);
entropy 3.63 → 1.23 (D2) / 1.10 (D4) bits, i.e. ~12 → ~2 effective timing states, with an honest late tail
(D2 max 16.6 ms, D4 max 18.8 ms, `EXPERIMENTAL_EVIDENCE_FREEZE.md:31`).

**Scope note for the scheduler:** "zero bypass" is proven for **D2 and D4 only**. D3 (D_R=0) shows 39 counter
"bypass" increments across A+B, reframed as its by-design immediate forward, not a lifecycle bypass
(`EXPERIMENTAL_EVIDENCE_FREEZE.md:27`).

---

## 4. The four response-arrival buckets and the fail-open / bounded-release guarantee

Every outstation RESPONSE, once its transaction is armed, lands in exactly one of four buckets (scorer counters
in `blocks.jsonl`; mechanism from `defense4_caseA.p4`, fix `e47bcaa`):

1. **HOLD_EARLY** (`delta_cf_RESP_HOLD_EARLY`). RESPONSE arrives before the ACK is released (release-generation
   diff > 0). Held to the RESPONSE deadline `T_RESP`, released via `RELEASE_DEADLINE`.
2. **HOLD_LATE** (`delta_cf_RESP_HOLD_LATE`). RESPONSE arrives after the ACK release, same generation
   (`rel_diff == 0`). **Still held** — this is precisely the property the fix restored (`e47bcaa` change G:
   `rel_diff==0 -> CF_RESP_HOLD_LATE`, was bypass). Released via `RELEASE_DEADLINE`.
3. **FAIL-OPEN RELEASE** (`delta_cd_RELEASE_FAILOPEN`, with `ARM_FRESH`). The K=64 blocker reservoir drains
   before the deadline (per-token budget exhausted). The held packet is released immediately — **bounded, never
   stranded** — and the transaction re-arms. Proven on silicon: targeted test at budget 800 (fail-open horizon
   1.37 ms, shorter than response arrival) gave responded **30/30**, `RELEASE_FAILOPEN = 30`,
   `RELEASE_DEADLINE = 0`, `ARM_FRESH = 30`, reg_tag idle afterward (`TARGETED_CASES.md:32-45`).
4. **BYPASS** (`delta_cf_RESP_BYPASS`) — RESPONSE forwarded unprotected at native timing. **This is the
   privacy-failure bucket.** Post-fix D2/D4 in the tested scope: **0** (§3).

**Guarantee.** In the tested scope, buckets 1+2 account for all 240 D2 and 240 D4 responses (bucket 4 = 0, bucket
3 = 0 under normal budget; bucket 3 is the deliberate escape valve, exercised and bounded separately). Every
response is delivered (`responded 60/60` per block) and released either at the deadline or via the bounded
fail-open path — never held indefinitely, never emitted unprotected once armed.

---

## 5. The interface D4 exposes to a scheduler

The deployed program is a four-queue Case-A timing engine (`defense4_caseA.p4:328-335`): qid7 = ACK blocker
reservoir, qid6 = held ACK, qid5 = RESPONSE blocker reservoir, qid4 = held RESPONSE. Real ACK/RESPONSE stay
queue-resident (qid6/qid4); only K=64 blocker tokens loop on the internal scheduler. The primitive a downstream
fixed-transcript scheduler can build on:

- **DNP3 transaction recognition.** Ingress classifies each packet: `ROLE_ARM` = the DNP3 READ that takes the
  generation tag and clears the deadline (`defense4_caseA.p4:304`); `CLASS_ACK` = the relay's pure TCP ACK
  (`:538`); `CLASS_RESP` = the relay's DNP3 RESPONSE (`:540`); `CLASS_ACK_REL` = the released ACK on its return
  pass (`:541`); `ROLE_BLOCK` = the 0x88C1 blocker token (`:296`).
- **ACK / RESPONSE eligibility (two deadlines).** `T_A = t_A + D_A` (ACK deadline); `T_RESP = T_A + D_R`
  (RESPONSE deadline) — `defense4_caseA.p4:544`, TIMING_SPEC §1/§2. D_A, D_R and the budget are **runtime
  parameters** (`defense4_caseA.p4:86-88`), so a scheduler sets them per policy without recompiling.
- **Transaction matching (data-plane learned, no control-plane per-flow install).** The READ installs
  `EXP_ACK = READ.tcp.seq_no + read_len` and the 5-tuple session (`reg_exp_ack`, `reg_session_port`,
  `defense4_caseA.p4:80,524`). A RESPONSE is bound to the transaction only after its seq/ack/port conjuncts are
  checked (R1, `tbl_resp_authorise`, `defense4_caseA.p4:11,143`) — spoofed or mismatched frames are not marked.
- **TM release timing.** A held packet is released when its blocker token, looping on the internal loopback
  scheduler, observes its deadline expired. So the packet is eligible at `t_eligible = t_trigger + D` (ACK:
  `t_ACK + D_A`; RESPONSE: `T_A + D_R`) and leaves at the first loopback pass `τ_i` at or after eligibility:

  > **t_wire = min{ τ_i : τ_i ≥ t_eligible }**

  Properties the scheduler may rely on: (a) **t_wire ≥ t_eligible always** — the deadline is a floor, the packet
  is never released early (this is the lifecycle property "response obligation survives the ACK release",
  `TARGETED_CASES.md:9-22`); (b) the **release tail** `t_wire − t_eligible` is bounded by the loop granularity —
  measured p5-p95 spread 0.12 ms (D2) / 0.05 ms (D4) (`NORMALIZATION_ANALYSIS.md:15-17`), with an honest upper
  tail (D2 max 16.6, D4 max 18.8 ms). A fixed-transcript schedule that supplies target release times τ therefore
  gets each armed packet emitted at `min{τ_i : τ_i ≥ t_eligible}`, never earlier, with small bounded positive jitter.
- **Privacy-failure / fail-open accounting.** The escape valve is explicit and counted: a budget-exhausted token
  records its generation in `reg_failopen` and leaves `reg_tag` unchanged (R2, `defense4_caseA.p4:12,131-134`);
  the next READ re-arms (`ARM_FRESH`). Fail-open releases (`RELEASE_FAILOPEN`) and unprotected forwards
  (`RESP_BYPASS`) are separate counters, so a scheduler can read the on-silicon privacy-failure rate directly
  (in the tested scope: `RESP_BYPASS = 0`, `RELEASE_FAILOPEN = 0` under normal budget; both non-zero only when
  deliberately provoked). Budget default 18000 (`defense4_caseA.p4:398`).

---

## 6. Boundary conditions a scheduler must re-verify before relying on this

- **Timing only.** D4 normalizes CLRT for one device. Size, segment count, transaction duration, TSval, and the
  static TCP-stack fields are untouched and remain device-identifying (Findings 6, 10-12 in `EVIDENCE_LEDGER.md`).
- **In-scope traffic only.** The guarantees are for single-segment READ responses, one active transaction, no
  induced loss. Multi-segment responses, retransmission, teardown, and control (SELECT/OPERATE) are offline-validated,
  not proven live (`EXPERIMENTAL_EVIDENCE_FREEZE.md:50-54`).
- **Reservoir margin (R11) is OPEN.** The K=64 hold-continuity margin is measured, not closed
  (`EXPERIMENTAL_EVIDENCE_FREEZE.md:62`); a scheduler that raises the offered hold rate must re-measure it.
- **Stale sibling document.** `research/size_timing_coresidency/CHARTER.md:53-59` (2026-08-10) still describes the
  retirement defect as OPEN using pre-fix numbers; it is stale relative to the fix `e47bcaa` and this contract.
  Trust `EXPERIMENTAL_EVIDENCE_FREEZE.md` and the raw `blocks.jsonl`, not the CHARTER paragraph, for the current
  D2/D4 state.
