# Defense 4 §3 v4 — stage-optimization brainstorm (menu, NOT yet implemented)

v4 places at a tight **12/12** ingress stages. The §4 timing core extends this bootstrap with
deadline/release logic and needs headroom. Two P4/TNA experts independently analysed v4 (compile-
verified probes; the real file was untouched). This is the ranked menu of ways to reclaim stages —
**analysis only, nothing here is implemented.** Decisions are Philip's.

## Ground truth (both experts, verified)
The program is **dependency-depth-bound**, not resource-packing-bound: every inter-stage edge from
stage 2–11 is a `match` dependency. Register→stage: `gen@0 · ident_resp@2 · resp_stage@3 ·
ident_ack@4 · pop@6 · resp_gen@7 · active@8 · failopen@10 · native_decide@11`. So the lever is
**dependency-edge removal**, not bit-packing. The tail blocker is **`reg_resp_gen`**: it sits
between `pop@6` and `active@8` only because of the author-imposed `resp_gen < active` ordering
(added to break the resp_gen/active/failopen SCC), holding two otherwise-independent native reads
(`pop_read`, `active_read`) one stage apart.

## ★ Recommended — reclaim 2 stages AND close the flagged residual (one change)
**Eliminate `reg_resp_gen` by carrying the held-RESP generation in the loopback shim, then
co-locate `reg_active` into `reg_pop_packed`'s stage.**
- **−2 stages, 12 → 10, compile-verified** (`pop@6 · active@6 · failopen@8 · decide@9`; 0 errors).
- **Semantics-preserving** under the single-outstanding DNP3 assumption v4 already relies on, and
  **strictly more robust** for overlapping/pipelined transactions.
- **This is the same loopback-generation shim Philip named for the `reg_resp_gen` residual** (the
  overlapping-transaction wrong-clear): stamp the 31-bit generation into the held RESPONSE on its way
  to `PORT_L` (a 4-byte shim behind ethernet, distinct ethertype, parsed on the from-loop path,
  stripped before the final hop to master); completion compares `shim.gen == cur_gen` instead of
  `resp_gen_read`. So it **reclaims 2 stages AND closes the one disclosed residual**, and frees a
  32-bit SALU for §4.
- Implementation risk: **MEDIUM** (parser/deparser + one stamp action). The register-packing expert
  proved `reg_resp_gen` is the binder (pinning `active@6` fails while `resp_gen` is present; removing
  it lands cleanly at 6).

## Alternative for the same −2 (simpler, mild semantic cost)
**Break the `active → failopen` edge** (architecture expert L1): drop `reg_active` from the native
readiness test (`ready = pop==BOTH_READY`), move teardown to `pop_reset` instead of `active_clear`.
`failopen` then shares `active`'s stage and the standalone `ready`-AND stage vanishes. −2, 12 → 10,
single-pass, control-flow only. Tradeoff: the `active` liveness flag no longer participates in
readiness. Use this only if the shim is deemed too heavy for §3 — but it does NOT close the residual,
whereas the recommended option does.

## Deeper cut (only if §4 needs it, real tradeoff)
**Move the ACK-seed staging gate DP → CP** (architecture expert L3): have the control plane withhold
ACK-seed pktgen until it reads `reg_resp_stage == K`, deleting the `resp_stage → ident_ack` edge so
the two ident registers share a stage. Compiles at **8 stages**. **Tradeoff:** relocates the staging
enforcement into the control plane (polling latency + a race window) — this is the lever most likely
to threaten R11 continuity (already unverified on silicon). Not recommended unless §4 genuinely needs
8 stages and Philip accepts re-opening the continuity question.

## Rejected by both experts (do NOT pursue)
- **Merge `reg_ident_resp` + `reg_ident_ack`** → re-introduces a static cycle. (The packing expert
  pinpoints it as **ident↔shadow**, not the ident↔pop cycle v3 hit: a merged ident must sit both
  before and after `resp_stage@3`.) L3 gets the same stage-sharing without merging.
- **Pack `reg_active` + `reg_failopen` contents into one register** → dual-output SALU blocker
  (`tbl_native_decide` needs two independent keys, `ready` and `fo_eq`); high SALU risk, low payoff.
  Note: the recommended option already **co-locates** them in a stage by breaking a dependency, so a
  content-merge on top is both unnecessary and risky.
- **Fold `reg_resp_stage` into `pop`** → re-creates the exact pop↔ident_ack cycle the shadow exists
  to break; violates the contract.
- **Egress redistribution / two-pass recirculation** → a Register lives in one physical MAU stage
  regardless of pass, so this saves **zero** ingress stages here; egress cannot feed an ingress
  admit/hold decision. (Egress is the right home for §4's *size* plane, not the bootstrap.)
- **Register-slice masked compare to drop `cur_gen_conf`** → compiler-dead (`slice of register value
  in condition is not supported`); independently confirms the two-comparator seed-dedup is
  load-bearing (validating the comment fix already made).

## Composition
The recommended option is a superset win. If more is needed later, the architecture expert's L1 and
the packing expert's co-location target the same tail, so they do not simply add beyond 10 stages;
reaching 8 needs L3's DP→CP tradeoff. All three compose with front-register bit-packing, but once
`active`+`failopen` share a stage by dependency-breaking, do NOT also content-merge them.

**Nothing here is implemented.** The standout — the loopback-gen shim — both reclaims 2 stages and
closes the disclosed `reg_resp_gen` overlapping-transaction residual, so it is the natural next change
if Philip authorizes a v5. Still §3; R11 OPEN; no §4/Gate 3/size/TM/switch/hardware.
