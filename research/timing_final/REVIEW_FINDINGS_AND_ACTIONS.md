# §4 review — consolidated findings and actions

Seven independent cold reviews of `dnp3_timing_normalizer.p4` (sha `d6fcd530`) + the harness + the
security claim. This tracks every finding and the action taken. **No review found a functional P4
defect** — all P4-structural checks pass. Findings are operational (control-plane), harness
hidden-failure downgrades, and claim/analysis discipline.

Reviews collected: ALL 7 — A parser, B packed-state/generation, C TM/priority, D arithmetic,
E fail-open, F harness, G security.

## A — parser (all 6 checks PASS)
The historic pure-ACK drop is provably closed (a zero-payload segment's `total_len` is always below
the DNP3 range threshold for every data_offset 5–15, so DNP3 extraction is unreachable). `0x88C1`
forced to ROLE_BLOCK; `meta.role` never reassigned. **Action A1 [doc]:** DNP3 responses with TCP
`data_offset > 8` silently bypass unheld with no counter — byte-safe but a blind spot if the relay's
TCP option profile ever changes. Record as an assumption in the reference doc.

## B — packed state / generation safety (checks 1,5,6,7 PASS; 2 partial; 3,4 FAIL — the one substantive defect)
The tag/deadline packing math, blocker-generation gate, fail-open and next-transaction recovery are
sound, and **no defect causes a premature release** — every failure mode over-holds or mis-measures,
so the confidentiality invariant (response withheld ≥ until deadline) survives. But:
- **B-D1 [defect — highest value, the ACK-arming path]:** deadline arming is **not idempotent and not
  generation-gated**. Every qualifying pure ACK re-arms `reg_deadline` (anchors to the LAST ACK), so
  (check 3) a duplicate/retransmitted ACK moves the deadline out, and (check 4) a stale ACK can arm a
  new transaction — pure ACKs carry no generation (`gen_in=0`). Two consequences: a chatty/retransmitting
  connection holds until fail-open, and — the important one — the measured CLRT becomes
  `(t_lastACK − t_firstACK) + G`, leaking ACK count/spacing back into the interval the defense
  normalizes. **Fix:** arm only when `reg_deadline` is not already armed (test the marker inside the
  SALU → anchor to the FIRST ACK); this closes checks 3, 4, the fingerprint leak and D4 at once.
  **Campaign impact:** the physical SEL-751 sends exactly ONE separate pure ACK per transaction
  (verified: 30 polls → 30 pure ACKs), and the replay injects one ACK per transaction, so the single
  qualifying ACK anchors correctly and the campaign result is a valid "exactly G" — the defect is not
  exercised by the replay. It IS a real gap for the live/multi-ACK case. **Decision: fix it** (targeted
  first-ACK idempotency), because it directly strengthens the headline claim and the security review's
  ACK-spacing objection; delegated to the P4 engineer, then recompile + re-verify before the campaign.
- **B-D3 [control-plane, CRITICAL for the campaign]:** the generation is now the DNP3 app-sequence
  `0xC0..0xCF` (per poll), so **blocker tokens must carry `gen` = that poll's app-control byte** or
  every token is stale-on-arrival and NOTHING holds (fail-safe but non-functional). The campaign
  token injector already does this (verified earlier: per-txn gen 0xC0,0xC1,…); pin it as a gate.
- **B-D-docfix [doc]:** generation reuse distance is **16 (the 4-bit DNP3 app sequence), not 254** —
  `PACKED_STATE_DESIGN.md §5` is stale (described a full-byte generation). Correct it; the wrap is safe
  only while blocker lifetime ≪ 16 poll intervals (seconds), which holds, but the margin is 16× smaller
  than documented.
- **B [doc]:** the file's `tag_diff==0 <=> active AND my generation` is imprecise — it is
  `gen_in == stored_tag`, active only for the legitimate `0xCn` token domain; a spoof token with
  `gen∈{0x00,0xFF}` can loop during IDLE/INACTIVE only (self-heals on next ARM, cannot corrupt a live
  hold). Combined with E-sec1, add the host-port `0x88C1` ACL.

## C — TM / strict priority (points 1,2,3,5 PASS; point 4 CONDITIONAL)
Queue mapping and `max_priority` strict-priority (the Part-3 fix) are correct and read back; distinct
levels make a DWRR fair-split leak structurally impossible. Starvation holds **conditional on three
off-file preconditions**. Actions for the campaign (all pinned into the runner + plan):
- **C1 [control-plane]:** the setup script defaults `--prog ibspg_controlled_drain` → **must invoke
  `--prog dnp3_timing_normalizer`** or it binds the wrong pipeline. **Load-bearing.**
- **C2 [control-plane]:** run **without `--paired`** (two-level config), `--qb 7 --qh 1`.
- **C3 [control-plane]:** explicitly **clear any max-rate shaper on Q_BLOCK (qid7)** in config — the
  restore target (queue microbench) uses shapers; a stale shaper makes Q_BLOCK ineligible when
  over-rate and Q_RESP leaks (eligibility, not priority).
- **C4 [gate]:** assert **K ≥ 64** and per-token pass budget sized so **`ctr_release_fail_open == 0`**
  (every release deadline-attributed) — pre-trial gates.
- **C5 [honesty]:** the readback is `from_hw:False` (driver-cache, not silicon) — state as such.
- **C6 [trap]:** `pg_l=2, pg_l_nr=0` is dp8-specific; must not be reused for another loopback port.

## D — deadline / timestamp arithmetic (all 6 checks PASS)
Wrapping compare correct within `|now−deadline| < 2^31 ns ≈ 2.147 s` (hard failure only at
`G ≥ 2.147 s`; ms-scale G is 50–430× inside). Tick quantization bounded to < 256 ns (< 0.005 % of a
ms-scale G). `deadline==0` sentinel ambiguity **eliminated by parity** (armed deadline is always odd),
residual probability exactly 0. Actions:
- **D1 [control-plane, DONE]:** enforce G tick-alignment (low byte zero) in `p13_guard.py` — a G with
  a non-zero low byte corrupts the armed marker. Committed `06a4950`.
- **D2 [doc]:** correct "mathematically equal" → "equal to within one 256 ns tick" (the deadline
  compare is tick-floored; the G-guard compare is full-ns; they can disagree within ≤256 ns — which is
  exactly what the on-chip cross-check surfaces).
- **D3 [doc]:** `native_clrt` with no qualifying preceding ACK is telemetry-only (the hold is driven by
  `reg_deadline`, not by `reg_protection`) — caveat the readout.

## F — harness integrity (no fabricated PASS; 5 hidden-failure downgrades to fix)
Counter-delta discipline, `ctr_bypass[1]` read at index 1, isolation observation, and byte comparison
are all genuine. But a green RESULT must not be trusted until these are fixed:
- **W1 [harness]:** stale verdict/pcap under a re-used RUNID — `rm` prior artifacts at trial start,
  make RUNID timestamped/mandatory, check `scp` exit and abort on failure.
- **W2 [harness]:** injector return codes (`VRC`/`HRC`) captured then ignored — abort the trial FAIL if
  either injector exited non-zero (the fast "injected nothing" signal).
- **W3 [harness]:** the tshark cross-check is advisory, not gating, and its pairing rule differs from
  the in-house parser — make it **gate** (exit non-zero on disagreement > tolerance or on tshark
  unavailable when requested) and align the pairing rules.
- **W4 [harness]:** join-key (seq/ack) mutation is mislabeled `INCONCLUSIVE_CAPTURE` instead of FAIL —
  assert `unmatched_frames == 0` (DNP3-port frames unmatched by seq ⇒ FAIL, i.e. a real byte-mutation
  is a dataplane fault, not an observer problem).
- **W5 [harness]:** release-cause gate is `deadline > 0` and fail-open is never gated — assert
  `ctr_block_term_deadline delta == nresp` **and** `ctr_block_term_timeout delta == 0` for hold modes
  (matches C4). Also S1 (compare full frame length), S2 (gate on G readback `verified`).

## E — fail-open / cleanup (6 of 7 checks PASS; one race defect; two hardening items)
Fail-open is bounded (monotone `bit<32>` budget), releases the response byte-identically via the
shared release path, no blocker escapes on the timeout path, the fingerprint (1 budget + K−1 stale)
is a leak-*absence* signature, and a normal ~25 ms hold completes ~8× before Linux `TCP_RTO_MIN`
(200 ms) — no retransmit storm on the normal path. Actions:
- **E-7b [defect, correctness-under-race]:** the fail-open `TAG_INACTIVE` write is unconditional on
  generation and happens before stale-detection, so a budget-exhausted straggler of transaction A can
  clobber a newer transaction B's tag if B's ARM arrives during A's ~K×pass-time drain window
  (~640 µs at K=64/10 µs), prematurely releasing B (B not normalized). **Not** a safety violation
  (byte-identical, no leak, no stuck state). **Campaign mitigation [DONE by design]:** the campaign
  paces transactions 0.5 s apart ≫ 640 µs drain, so A's reservoir is fully drained before B's ARM —
  the race cannot occur in the planned runs. **Deployment mitigation [control-plane]:** confirm A's
  `ctr_block_*` terminations sum to K (reservoir empty) before admitting B, or gate B's ARM. A P4 fix
  (gate the tag write on generation) is a state-machine change with placement risk and is deferred
  past this week's replay deliverable; documented as a known limitation.
- **E-sec1 [control-plane, hardening]:** a host-injected `0x88C1` with `seq=0xFFFFFFFF` would loop
  ~4.3e9 times (hours of Q_RESP starvation) — token *egress* is blocked but token *ingress* from a
  host port is not. **Add a control-plane ACL dropping `0x88C1` on dp9/dp11** (the tokens are internal;
  in the replay campaign they are injected by us on the trusted path, so this is a deployment gate).
- **E-sec2 [doc]:** generation is the 4-bit DNP3 app sequence (0xC0–0xCF), wrapping every 16 polls;
  the budget wall-clock must stay below 16 poll intervals so a straggler cannot ABA-alias a live
  transaction — another reason to size the budget short. Caveat in the reference doc.
- **E [doc]:** the reference doc's "state cleared" overstates it — fail-open clears `reg_tag` but not
  `reg_deadline`/`reg_t_ack` (the next ARM resets both); correct to "tag cleared; deadline/t_ack reset
  on next ARM."

## G — adversarial security claim (mechanism strong; security claim must be reframed)
- **O1 [claim, FATAL for a security venue]:** anonymity-set-of-one — only the SEL-751 has a CLRT, and
  ACK-mode + TCP-stack are already at balanced accuracy 1.000, so on this corpus closing CLRT yields
  **zero marginal adversary-accuracy reduction**. The entropy figure measures within-device value
  spread, not cross-device discrimination. **Action:** narrow the headline to a **mechanism** result
  ("schedules the ACK→response interval as a data-plane-scheduled policy constant, chaff-free,
  byte-preserving") plus a **conditional/analytical** security argument. Honor §10's non-claims (no
  device anonymity) and state the residual channels prominently. This is compatible with the
  directive's allowed claim; add the anonymity-set caveat explicitly.
- **O2 [claim, MAJOR]:** per-device G is itself a fingerprint; true anti-fingerprinting needs a
  **shared G** across an anonymity set (≥ the slowest member's native CLRT). No multi-device corpus
  exists → frame as feasibility, not demonstrated anonymity.
- **O3 [doc contradiction, MAJOR — FIX NOW]:** the G-guard is described as **built** in
  `TIMING_REFERENCE_IMPLEMENTATION.md` but as "does not exist / not yet built `[OPEN]`" in
  `END_TO_END_RESULT.md` and `COMPREHENSIVE_REPORT.md` (which predate this session's build). Reconcile:
  the guard is now **compiled and verified (§3) but not yet exercised on traffic** — add dated forward
  notes to the older docs.
- **O4 [claim, MAJOR]:** the sd-collapse is partly tautological (holding to G forces output sd≈0); the
  real increment of the real-frame runs is **classifier correctness**, not the sd number; and it is
  replay, not a live inline held session. Keep the replay caveat load-bearing in every claim.
- **O5 [analysis, MINOR→MAJOR]:** native entropy from n=30 is upward-biased (~1 sample/bin); recompute
  on the **full 300-sample** SEL-751 native set with a bias-corrected estimator (Miller-Madow/NSB) +
  bootstrap CIs.
- **O6/O7 [framing]:** sharpen the novelty-vs-Ditto delta (chaff-free, byte-preserving, interval not
  continuous pattern, data-plane deadline release without controller); specify the observer location
  and adversary goal in the threat model.

## Disposition
No P4 change required (all structural checks pass; A1 is a doc note, not a fix). Batch before the
campaign: the harness fixes W1–W5/S1–S2, the control-plane fixes C1–C4 baked into the runner, the
doc reconciliations D2/D3/O3 and the claim reframing O1/O2/O4, and the analysis plan O5. The campaign
then runs with `--prog dnp3_timing_normalizer`, no `--paired`, Q_BLOCK shaper cleared, K≥64, and the
hardened verifier gating on fail-open==0 and unmatched==0.
