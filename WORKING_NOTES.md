# Working Notes — DNP3 project (repo root)

**Authoritative resume order: `RESUME_STATE.md` (top block) → `dnp3_split_harness/WORKING_NOTES.md`.**
This root file's per-task sections below are HISTORICAL (multi-CROB week8 series + a stale
2026-07-17 handoff that wrongly says the two-host rig is BLOCKED — that is superseded).

## Current focus (2026-07-21): Case A defenses proven on Tofino; Case B (combined) defense DESIGNED
- **Read `RESUME_STATE.md` top block (2026-07-21) first** — it has the full checkpoint. This block is a
  short pointer.
- **LOCKED taxonomy** (`memory/dnp3-clrt-case-taxonomy.md`): **Case A = separate-ACK (SEL-751)** →
  **Defense 1** (hold ACK, `dcrn_defense1.p4`) + **Defense 2** (hold response, `dcrn_defense2.p4`) — BOTH
  **PASS_MEASURED_ON_TOFINO** (SDE 9.13.2; Defense 1 CLRT→~0.026 ms, Defense 2 CLRT→~107 ms). **Case B =
  combined-ACK (AB1400/ION7550)** — no CLRT, currently bypassed, NO defense built.
- **This session (2026-07-21) = presentation + figures + design; NO switch touched.** Deliverables in
  `research/tofino_dcrn_feasibility/p4/ack_delay/`: weekly slide deck for Dr. Lin (Artifact, 13 slides,
  `evidence/visualization/dnp3_slides_meeting.html`), `ACK_DELAY_TECHNICAL_REPORT.md`, real-device
  figures/pcaps (`evidence/visualization/`, `evidence/pcap_clean/`), artifact zip
  (`evidence/dnp3_ack_delay_artifacts_2026-07-21.zip`); Netronome on-box inspection (Agilio CX 2×40G on
  Vision) `../netronome_vision_onbox_inspection.md`.
- **Case B (combined) defense design study DONE** (5-agent) → `case_b_defense_design.md`,
  `memory/case-b-combined-defense-design.md`. Composition **B-E5 + B-SIZE + B-MODE**; **fake-ACK
  REJECTED** (all 4 experts, live path). DESIGN ONLY, `next_phase_allowed=false`.
- **NEXT (gated, Philip's call):** the **offline AB-vs-ION byte-transform smoke test** (unprivileged, no
  switch/P4) — cheapest test of the core Case-B hypothesis (does closing timing+size → coin-flip).

## Current focus (2026-07-18): Tofino/P4 timing-normalization feasibility study
- Phase 04B (DCRN dual-case timing normalizer) = **PASS_MEASURED** on the two-host Vision↔Hulk rig
  (kernel 6.8, real NICs, 2026-07-18, commit `1c6c0c3`). Use BOUNDED (FIXED leaves a device-correlated
  ~0.19 ms guard residual). Timing channel closed; ACK-mode + response-size residuals persist (out of
  byte-preserving scope). Authoritative status: `dnp3_split_harness/reports/phases/phase_04b_dual_case_timing/phase_status.json`
  (`next_phase_allowed=true`, PI authorized advance 2026-07-18).
- **NEXT PHASE (authorized, IN PROGRESS) = Tofino/P4 implementation feasibility + research.** Core
  tension: DCRN holds each response ~16–42 ms to an absolute deadline, but Tofino is wire-speed (TM
  shapes RATE, not per-packet LATENCY). Question: realize the hold on-switch (recirculation-hold loop),
  re-express (rate shaping / scheduled dequeue), or split (decide-on-switch + hold-at-edge)?
- Prior art reconciled: `research/split_pad_timing_policy/tofino_design.md` (§5.3 TM-shapes-rate,
  §6 recirculation-hold loop, §6.7 alternatives), `GROUNDING.md`, `corrective.md` (DCRN spec).
- **Study DONE 2026-07-18** (3 parallel agents: p4-dataplane-engineer / sdn-networks-expert /
  principal-investigator → synthesized). Report: `research/tofino_dcrn_feasibility/tofino_dcrn_feasibility_report.md`
  (raw contributions in `agent_contributions/`). **VERDICT: hold the ms-scale timing at the EDGE, not
  on the Tofino-1 ASIC** — the two DCRN release constructs (`skb->tstamp` EDT + `fq`) have NO TNA
  equivalent. On-switch recirc-hold (option B) is FEASIBLE-WITH-CONSTRAINTS but UNBUILT and DNP3-rate-bound
  (affordable only because ~1 s poll spacing is 20–60× the ~42 ms hold; deciding ceiling = traffic RATE,
  not chip resource). Pure on-switch rate-shaping RULED OUT (shaper delays only on backlog; lone frame
  leaves immediately + size-coupling). Recommended: edge hold (host qdisc-EDT owned / inline SmartNIC-DPU
  unowned), Tofino = classify + telemetry + policy distribution. Size + ACK-mode residuals unchanged.
- **DECISION (2026-07-18): build the ACK-delay ON THE SWITCH** (Philip's call; venue set aside).
  Implementation map committed: `research/tofino_dcrn_feasibility/on_switch_implementation_map.md`
  (authored by p4-dataplane-engineer, grounded in real HW via /Projects/Tooling + a co-resident program's source,
  main-session verified). RESOLVED: recirc self-clock = **dp68** (pipe-0 internal recirc port, no cable;
  a co-resident program enables it + caps a hold loop at HOLD_LOOP_PPS=100000 via TM max_rate — [L] verified);
  compile on switch **SDE 9.13.2**; DCRN **replaces** a co-resident program via a **gated bf_switchd restart** (no
  hitless swap); data path pipe-0 arm@ingress-dp8 / classify+hold@ingress-dp9 / release→dp8; all bf-p4c
  constraints pinned to the 8 classes (deadline compare=32-bit SALU predicate; byte-preservation
  sidesteps the Class-6 checksum ICE). Staged plan M0→M5; first `bf-p4c` compile (M1) is the only proof
  of stage/SALU fit. Open probes: recirc-refreshed ingress clock (Q2), sparse-frame self-pacing (Q3),
  Vision RTO re-measure (Q6). Nothing compiled/loaded yet — bf_switchd restart needs explicit approval.
- **FULL CODE-LEVEL IMPLEMENTATION PLAN DONE (2026-07-18)** — `research/tofino_dcrn_feasibility/on_switch_dcrn_implementation_plan.md`
  (STEP 1 = ACK-delay/DCRN timing normalizer; size-normalization parked per Philip). Complete TNA P4 skeleton
  (headers/parser/ingress control/RegisterAction SALU bodies/deparser), registers+tables, dp68 recirc self-clock (bridge
  encap/decap = byte-preserving, popped before dp8 egress; **CORRECTION: TM tables = `tf1.tm.queue.sched_shaping`/`sched_cfg`
  keyed pg_id/pg_queue, NOT tf1.tm.port.***), bfrt control plane, BOUNDED calibration (deterministic seed, RTO cap at
  install, guard-delta 4 ticks), gated build/deploy runbook, milestones M0-M5 + acceptance tests, rig validation, Q1-Q7
  risks. Grounded in real lab P4: a reference DNP3 parser (parse+tcp_overhead+Hash), a reference register/SALU program (Register/RegisterAction/ctor-seed),
  a co-resident program's P4 source (recirc-hold+bridge). **One compile-critical unknown = check_deadline SALU predicate vs a RUNTIME operand
  (lab SALUs only compare vs constants) → M1 compile resolves. Class-6 unreachable (no checksum recompute).** NEXT = M0/M1
  (author dcrn.p4 + compile-only classify+arm skeleton); all switch/bf_switchd steps GATED.
- **CODE WRITTEN + LOCAL COMPILE LOOP UNDERWAY (2026-07-19)** — `research/tofino_dcrn_feasibility/p4/dcrn.p4`
  + `dcrn_setup.py` (grounded in real lab .p4/.py). **KEY UNLOCK: there IS a local bf-p4c 9.13.1 at
  `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c` → M1 compile-fit can be driven LOCALLY, no gated switch
  (compile: `PATH=.../bf-sde-9.13.1/install/bin:$PATH bf-p4c --target tofino --arch tna -g -o OUT dcrn.p4`;
  authoritative 9.13.2 switch compile stays the final confirm).** `dcrn_setup.py` py_compile PASS.
  dcrn.p4 compile iteration (all found LOCALLY): (1) request-path TCP-options dropped by advance() [review]
  → fixed (extract per-data_offset opt headers, re-emit); (2) set_overhead `total_len - ov` = action-data
  subtrahend forbidden → fixed (add negated overhead); (3) ctr_passthru shared across 2 non-exclusive
  tables → fixed (added ctr_other, my edit); (4) [RESOLVED, see M1 bullet below] "Dependence chain (17) > 12 available stages"
  — the nested single-pass ingress (recirc-branch + request-arm + response-classify-hold, reg_deadline
  touched 3×) serializes too long → p4-dataplane-engineer RESTRUCTURING to fit ≤12 stages (flatten
  mutually-exclusive paths, shorten arm chain, unify check_deadline, telemetry→egress). Iterative: agent
  rewrites → I re-compile → feed next error. check_deadline runtime-operand SALU predicate (Q1 semantic)
  not yet reached (downstream of the fit fix). Nothing on the switch touched.
- **M1 COMPILE-FIT PASS (2026-07-20, local bf-p4c 9.13.1)** — the restructure above compiled: **0 errors,
  fits in 9/12 ingress stages** (critical path 9, 33 logical tables, 37 SRAMs, 0 TCAMs, power 1.73).
  **BOTH genuine unknowns resolved:** (a) the 17-deep dependency chain now fits (9 stages); (b) the
  `check_deadline` runtime-operand SALU predicate (`meta.now_eff >= stored word` — the one SALU shape not
  seen in lab code, where SALUs only compare vs constants) **lowered cleanly** -> the constant-biased
  two-RegisterAction fallback is NOT needed; resolves the compile side of Q1. **HONEST DEVIATION: 9 stages,
  above the plan's ~7 soft estimate** (well within the hard 12-stage wall; the `dcrn.p4` comment and plan
  should be corrected to "9 measured"). Evidence: `research/tofino_dcrn_feasibility/p4/M1_local_compile_result.md`
  + `p4/build_local_9.13.1/logs/`.
- **★ ON-SWITCH 9.13.2 COMPILE CONFIRMED (2026-07-20, Philip authorized the on-switch M1 confirm).** Ran the
  authoritative `bf-p4c 9.13.2` (p4c 9.13.2 SHA 1baf055) directly on the switch `decps@10.10.54.15`
  (`ufispace`), work dir `/home/decps/dcrn_m1`, **non-destructively** (direct compile only — bf_switchd NOT
  restarted, a co-resident program untouched). Byte-identical source both machines (sha256 204823d8). **0 errors; resource
  fit IDENTICAL to local: 9 ingress stages, 33 tables, 37 SRAMs, 0 TCAMs → no 9.13.1->9.13.2 drift.** The
  "9.13.2 is the final confirm" risk is RESOLVED; compile half of M1 met. Evidence: `p4/build_switch_9.13.2/logs/`.
  **STILL PENDING for full M1 (all need the gated switch load):** `make install` (loadable artifact) + the
  dp8<->dp9 byte-identical WIRE-forwarding test (needs the gated bf_switchd restart displacing a co-resident program +
  a `dcrn.conf` + Vision<->Hulk harness), and all of M2+ (recirc-hold, clock-refresh probe, dual-case,
  fail-open, rig). The gated bf_switchd restart is pre-authorized but not yet executed — a shared-hardware
  displacement, do it with preflight.
- **★ WIRE-TEST LOAD FULLY PREPPED, BUT BLOCKED ON HOST-SIDE (2026-07-20) — a co-resident program NOT displaced.**
  Prep DONE (all non-destructive; a co-resident program bf_switchd PID 2283977 left running untouched): `dcrn.conf`
  authored + JSON-validated on the switch (`/home/decps/dcrn_m1/dcrn.conf`, program-name `dcrn`, points
  DIRECTLY at the `dcrn_build/` bf-p4c output — bfrt.json/pipe/context.json/pipe/tofino.bin all present, so
  NO separate `make install` needed); `launch_dcrn.sh` mirrors `the co-resident launch script`; passwordless sudo on the
  switch CONFIRMED. **Co-resident-program restore recipe:** it's just a bf_switchd on its own conf (no live
  controller/tmux) → restore = relaunch that program's own launch script (exact `/home/decps/...` path
  kept in private project memory only). CAVEAT: a cold restart returns it to post-compile (const-entry)
  state; any runtime tables its own
  controller installed at bring-up (friction_tables.py/watermark_tables.py) would need re-running by its
  owner — I can relaunch its bf_switchd but not faithfully reproduce its control-plane. **BLOCKER (why the
  wire test did NOT run):** the host data path is NOT ready. Authoritative topology = Vision dev_port 8 / data
  IP 10.0.1.10, Hulk dev_port 9 / data IP 10.0.2.10 (both /16, shared L2 through the switch). Hulk's data NIC
  `enp59s0f0np0` is UP at 10.0.2.10/16 ✓. **BUT Vision's documented data NIC `enp59s0f0np0` (Intel, MAC
  3c:fd:fe:cc:5d:c0 per the 2026-06-08 connectivity map) NO LONGER EXISTS** — Vision now shows down
  `enp59s0np0sX` breakout interfaces with a different MAC (`00:15:4d:...`, a Netronome/Corigine SmartNIC OUI),
  all DOWN/NO-CARRIER, no data IP. So Vision's data-plane NIC was physically swapped/reconfigured since June;
  the connectivity map is stale for Vision; bringing the Vision↔dp8 link up is an open-ended hardware task of
  unknown duration. **DECISION: did NOT kill a co-resident program's 14-day run to embark on an indefinite Vision
  data-plane bring-up — that shared-resource risk needs Philip's informed call (he may know about the Vision
  NIC change / want to fix the host side first / be fine banking the 9.13.2 compile confirmation).** Switch
  left exactly as found (a co-resident program running); staged DCRN files sit inert in `/home/decps/dcrn_m1/`.
- **★★ PARTIAL M1 = PASS ON REAL SILICON (2026-07-20). Philip authorized displacing a co-resident program (Vision
  is POWERED OFF → Hulk + switch only).** Displaced decoy (targeted `pkill -x bf_switchd`; the co-resident auto-load service already
  masked, left masked), loaded DCRN, ran the partial, then **RESTORED decoy** (relaunched on the co-resident conf,
  `p4_name the co-resident program` reloaded — verified back up). Proven on hardware: **(1)** DCRN LOADS on Tofino-1
  9.13.2 (bf_switchd binds `p4_name: dcrn` from dcrn_build context/tofino.bin; bfruntime up on :50052; no
  BfRtInfo error); **(2)** full control plane installs CLEANLY (`dcrn_setup.py --policy P1_FIXED`, exit 0) —
  resolves ALL M0 bfrt-name unknowns: ports up, recirc dp68, **TM shaper `tf1.tm.queue.sched_shaping`/`sched_cfg`
  installs**, fc_allowlist + all 256 bounded_target entries install (register `.f1` re-seed still unexercised,
  constructor cold-seeds); **(3)** dp9/Hulk `PORT_UP=True` 25G/RS-FEC, dp8/Vision `PORT_UP=False ENABLE=True`
  (Vision off, expected); **(4)** pipeline LIVE — `events[PASSTHRU]` climbs 23→29 on a deterministic Hulk
  ARP/ping burst. **NOT done (Vision-blocked):** dp8<->dp9 byte-identical DNP3 round-trip + timing normalization
  (needs Vision as master). Evidence: `p4/M1_on_switch_partial_result.md` + `p4/build_switch_9.13.2/dcrn_switchd_load.log`.
  **Restore caveat:** decoy got a fresh cold restart → its runtime control-plane tables (if any) need re-running
  by its owner; I restored its data plane, not its controller state. **NEXT (Vision-gated):** when Vision is
  powered on, sort its data NIC (10.0.1.10 on the SmartNIC lane wired to dp8), then re-load DCRN + run the
  Vision<->Hulk DNP3 forwarding/byte-identity + timing test = completes M1 and opens M2.
- **★★ END-TO-END DCRN ON REAL HARDWARE (switch + Hulk only, Vision off) = 2026-07-20.** First true
  request->response test. Hulk hosts BOTH DNP3 roles in two netns (master 10.0.1.10 / outstation 10.0.2.10,
  VEPA macvlans); the unused **dp8 in MAC-near loopback** hairpins traffic so DCRN arms on the dp8/dir0
  pass + holds the response on the dp9/dir1 pass, both returning to Hulk (design validated by
  p4-dataplane-engineer; single host = one clock, attacker-on-wire view). Real pydnp3 master
  (`run_master.py --action scan-class0`) ↔ `run_outstation.py`. Two host fixes were load-bearing: i40e
  **`disable-source-pruning on`** (else the NIC drops reflected self-MAC frames), and **strip the stale
  10.0.2.10 off the root NIC** (NM had auto-assigned it, masking ns_out). tcpdump on macvlans captures
  nothing (quirk) → capture on the physical NIC (frames appear 2x: VEPA TX + reflected-RX). **RESULTS:
  (1) end-to-end WORKS** — channel OPEN, all Class-0 polls complete, multi-seg responses (292+1263B);
  switch counters P1_FIXED **ARMED=12 HELD=12 RELEASED=12**, 0 retrans. **(2) BYTE-PRESERVATION PERFECT** —
  all 26 response payloads (incl 23 large reads) byte-identical P0_NATIVE vs P1_FIXED. **(3) TIMING HOLD
  WORKS BUT CAPPED ~2.9ms not 33ms** — native response spread 0.10ms → P1 held ~2.88ms (clear ~29x hold),
  short of the 33ms FIXED deadline. **ROOT CAUSE CONFIRMED:** dcrn.p4 sets ucast_egress_port=PORT_RECIRC
  but NEVER sets `ig_tm_md.qid`, so the recirc frame uses dp68's DEFAULT queue, NOT the qid-5 queue the
  shaper is on → recirc runs at bare line rate (~0.70us/pass) → hits MAX_PASS=4096 in ~2.87ms → fail-open
  (4096×0.70us=2.87ms ≈ measured 2.88ms). This is the design's flagged **Q3 sparse-frame self-pacing**
  unknown, now seen on silicon. **NEXT (M2 to reach 33ms): set `ig_tm_md.qid=QID_HOLD(5)` on both recirc
  paths (P4 edit+recompile+reload); confirm the shaper paces a lone sparse frame (else metronome packet);
  confirm global_tstamp refreshes on recirc (raise MAX_PASS to disambiguate).** Evidence:
  `p4/M2_e2e_singlehost_result.md` + `p4/e2e_evidence/` (P0/P1 pcaps + analyze.py) + `p4/dp8_loopback.py`.
  Co-resident program displaced-with-authorization then RESTORED; Hulk netns torn down, NIC handed back to NM.
- **★ FOLLOW-UP: pushed for the full 33ms hold (2026-07-20).** (1) **qid fix** (set `ig_tm_md.qid=QID_HOLD(5)`
  on both recirc paths) → NO change, still ~2.97ms: the shaper doesn't pace even with the frame on qid5
  (its pg_id=17/pg_queue=5 key may not map to dp68's qid5, or max_rate doesn't space a lone frame = Q3).
  (2) **Raised the fail-open cap** `MAX_PASS 4096→65536 (2^16)` + widened `pass_count bit<16>→bit<32>`
  (a large non-power-of-2 cap forces a full 16-bit magnitude compare that blows the Class-1 gateway 44-bit
  limit; power-of-2 reduces to a cheap high-bits check). Compiles 11/12 stages. **Result: holds jumped to
  42–82ms, aggregate MIN 32.95ms ≈ the 33ms FIXED deadline, byte-identity still 26/26 perfect.** SO: the
  recirc-hold DOES reach the ms-scale target on silicon (42–82ms vs 2.9ms), and global_tstamp DOES advance
  on recirc (the 33ms floor). **BUT not a clean 33ms** — holds are variable + cap-dominated (~82ms = 65536×
  ~1.25us/pass at 11 stages), and only the 292B first segment is held (the 1263B 2nd segment passes through
  0.10ms). → **global_tstamp refresh on recirc is INTERMITTENT + multi-segment not uniformly held** (the
  Q1/Q2 recirc-clock unknown, now characterized). **CLEAN 33ms needs (real M2):** pass-count self-clock
  (release after calibrated N passes, immune to timestamp refresh; needs gateway-friendly threshold) and/or
  fix the shaper pacing (verify dp68 pg_id; confirm max_rate spaces a lone frame or add a metronome pkt);
  and hold ALL response segments uniformly. Current dcrn.p4 carries qid fix + bit<32> pass_count + MAX_PASS=2^16.
  Evidence: `p4/e2e_evidence/dcrn_P1big_wire.pcap`. Co-resident RESTORED again; Hulk torn down.
- **SPLIT/PAD CHALLENGE (size axis) = NOT byte-preservingly on-switch.** The switch CANNOT create a
  split (needs TCP re-segmentation: seq/len + checksum recompute = proxy/MITM, forbidden) — it can only
  PACE upstream-created chunks via a shaped egress queue (TM rate-shaping = the right tool for inter-chunk
  gaps, wrong tool for first-response latency). Padding CANNOT conceal size on-switch (adds bytes → CRC +
  TCP/IP length/checksum recompute = byte modification + Class-6 ICE risk; DNP3-level padding is a proven
  negative: invalid-index CROB→OUT_OF_RANGE). Size (~0.99 classifier, 14.6 B/CROB) is the dominant
  residual, out of byte-preserving scope → belongs upstream (split_server) or off-ASIC (DPU/FPGA).
- **REOPENED as a RESEARCH LINE (2026-07-18, Philip's direction "go into research mode, this IS doable,
  develop something new"):** in-network integrity-correct DNP3 response SIZE-NORMALIZATION on Tofino-1 —
  a NEW primitive beyond the byte-preserving phase (it necessarily adds bytes + handles CRC/checksum,
  but stays DNP3-semantically-valid + integrity-correct). Workspace `research/inline_dnp3_size_normalization/`.
  THESIS to test: **append-only recirculation carousel** — per recirc pass append ONE fixed constant DNP3
  filler block (constant precomputed CRC-16/DNP + constant checksum delta via Class-6-safe guarded add);
  variable pad = pass count, not a P4 loop; original payload never enters the PHV. Hard kernels: (a) will
  a real DNP3 master parse-and-tolerate appended filler (power-systems)? (b) can TNA emit a trailer after
  an UNPARSED payload / how to append to the tail (p4)? (c) SOTA on in-network payload resizing (sdn/lit).
  5-agent research team → SYNTHESIZED. **Design doc: `research/inline_dnp3_size_normalization/research_design.md`**
  (raw contributions in `agent_contributions/`). **VERDICT: BUILDABLE — path to YES.** Key resolutions:
  (1) crux dissolves — PREPEND a constant benign frame, don't append (DNP3 self-delimiting framing makes
  before≡after; a co-resident program pad-before-residual geometry is PROVEN on the chip [L]). (2) CRC/checksum already
  run on this chip (a reference on-chip CRC program computes CRC-16/DNP + IP/TCP checksum for a DNP3 response [L]; constant frame →
  CRCs baked in). (3) filler EXISTS, source-confirmed on the rig master: Candidate 2 = 10-B black-hole DNP3
  link frame (master discards at data-link layer, master-AGNOSTIC) [recommended]; Candidate 1 = Group 110
  octet-string object (inert, but needs g110 support). (4) THE ONE HARD NEW THING (found by p4 AND sdn
  independently): per-flow TCP **seq-space translator** (seq+=Δ/ack-=Δ for the connection's life) — lighter
  than a proxy, NetWarden-proven on Tofino, but the runtime-Δ checksum is the top compile risk (Class-6 ICE
  zone) + retransmit/SACK is the top rig risk. Novelty = FIRST non-cooperative, integrity-correct,
  DNP3-semantics-preserving in-network response size-normalizer on a commodity switch. Eval: privacy-vs-
  overhead Pareto (MI + classifier), append-only ceiling (I=0 only at B=1; heavy-tail k=1 reported
  separately). **NEW byte-modifying phase (real response bytes stay byte-identical; outer TCP/IP envelope
  changes).** Verdicts A/B/C pre-registered. **RECOMMENDED NEXT = S0 offline byte-transform smoke test**
  (unprivileged, no switch/P4 → first real privacy number; early knee → green-light rig+P4). S1-S6 all GATED.
  Memory: [[dnp3-size-normalization-research]].
- **S0 DONE (2026-07-18)** — `research/inline_dnp3_size_normalization/s0_smoke_test.py` +
  `s0_results/S0_FINDINGS.md`. Pipeline validated on the 6 read-response captures (n=22,988). Read-data
  size fingerprint is MODEST (native size-only bal-acc 0.493, MI 0.487 bits; driven ENTIRELY by ION7550's
  distinct 61B; AB1400/SEL751 both 37/54, collapse). **KEY FINDING: exact bucketed up-padding collapses it
  to chance (B=1: bal-acc→0.333, MI→~0) — BUT ONLY with a VARIABLE-LENGTH filler. A constant-18B-block
  filler (the baked-CRC variant) does NOT collapse it** (37→73, 54→72, 61→61 = 3 distinct sizes; gaps not
  block-multiples) → MI stays 0.487. **REFINEMENT: use variable-length octet-string filler + RUNTIME CRC
  (a reference on-chip CRC program proves runtime CRC-16/DNP on-chip), not a constant baked-CRC block.** Over-bucketing (B≥4)
  re-isolates ION7550's 61B (k=1 residual) → buckets must MIX devices, not naive quantiles. Gates G1/G9
  PASS; overhead ≤24B ≪ MSS. **SCOPE: the strong ~0.99 size fingerprint is on CONTROL/CROB responses (14.6
  B/CROB), NOT this read dataset → rerun S0 on control-response sizes is the natural next step.**
- **S0 CONTROL-RESPONSE DONE (2026-07-18)** — `s0_control_smoke_test.py` + `s0_results/control_response_sizes.csv`
  (per-N SBO response sizes extracted from dnp3_multicrob_harness pcaps via tshark). Secret = CROB count N
  (operator-action privacy, NOT device). STRONG signal: 16 distinct sizes 37→256B, size↔N bijection, native
  N-recovery 1.000, MI 4.0 bits (=full H(N)). **Clean privacy-vs-overhead PARETO: idealized bucketing drives
  N-recovery 1.000→0.0625 (chance 1/16), MI 4→0 bits, overhead 0→110B mean; B=4 hides N to a quartile at
  +22B.** No heavy-tail residual (uniform N → equal-count buckets mix cleanly; the read-data residual was
  distribution-shape-specific). **★★ DECISIVE: the constant-18B-block filler gives ZERO privacy at EVERY B
  (pads the 16 sizes to 256,257,258,... = 16 distinct → N fully recoverable) → CONSTANT baked-CRC block
  REFUTED for the size axis; MUST use variable-length filler + RUNTIME CRC (a reference on-chip CRC program proves on-chip).** Two
  privacy targets now demonstrated on real data: device-id (read, weak) + CROB-count (control, strong).

---

- **★★ NEW PHASE — Dr. Lin ACK-CENTRIC CLRT control (`test_cases.md`, 2026-07-20): PI 5-agent planning DONE (GATE 0-1).** `test_cases.md` overturns the current DCRN direction: it FORBIDS the generic request-relative both-hold (§22) and mandates ACK-centric control of Formby CLRT = t(response)−t(pure ACK). CASE A = hold ONLY the pure ACK, release on response arrival, response after tiny guard δ (reduce CLRT, low latency); CASE B = forward ACK now, hold response to t_ack+G_i (increase CLRT). Current `dcrn.p4` (request-relative both-hold) = the §22-forbidden construction → needs a NEW ACK-anchored state machine. **§5.A measured (real captures): SEL751=SEPARATE (CLRT median 12.9ms), AB1400+ION7550=COMBINED (no CLRT).** Convened 5 experts (PI/p4-dataplane/power-systems/research-scientist/sdn) — consensus: on this corpus CLRT is NOT the device discriminator, **ACK MODE is** (SEL751 = only separate = anonymity-set-of-one); Case A **relocates** the signal into req→ACK → attacker eval must include a req→ACK/joint classifier. **PI build-order: CASE A FIRST** (event-governed ACK release via `reg_ack_gone`+shared-FIFO = zero-inversion, IMMUNE to the broken recirc clock; Case B is deadline-governed → needs the clock fix = bridge back egress global_tstamp + fix dp68 qid5 pacing; MAX_PASS = fail-open only). Safe Case-B band ~25-40ms. **Deliverables:** `research/tofino_dcrn_feasibility/p4/ack_delay/{ACK_DELAY_POLICY,_STATE_MACHINE,_EXPERIMENT_PLAN,_CURRENT_STATUS}.md` + `evidence/`. **NEXT (no switch): Python reference model of Case-A + unit tests → local bf-p4c 9.13.1 Case-A compile. NO switch window until they pass.** `run_master.py` unsolClassMask change must go behind `--suppress-startup-unsolicited`. Philip decisions: confirm Case A first; ≥3 SEL751 config profiles / 2nd separate-ACK device; authorize eventual C1-C4 switch probe. **GATE 1 + GATE 3 DONE (off-switch, 2026-07-20): reference model `p4/ack_delay/refmodel/defense1_state_machine.py` + `tests/` (12 tests PASS) validate the Case-A zero-inversion invariant in sim (monotone register visibility, jitter, guard variation → 0 inversions); `dcrn_defense1.p4` compiles clean on bf-p4c 9.13.1 = 0 errors, 11/12 ingress stages (1 headroom), tofino.bin produced. 6 placement fit-fixes; 2 flagged reductions safe in single-flow scope (watermark decrement deferred; recirc gen-staleness deferred). Semantic-fit risk = 9.13.1→9.13.2 parity at 11/12 + the 2 correctness unknowns (monotone recirc visibility; ACK+resp on one FIFO queue) = switch-run items. NEXT off-switch = Case-B variant (after clock-fix design) + gate run_master unsolClassMask behind --suppress-startup-unsolicited; NEXT on-switch (gated) = GATE 4 fwd + C1-C4 probe + Case-A microbench.**

## HISTORICAL — multi-CROB week8 series (separate line, dnp3_multicrob_harness/)

## Task (week8_next.md — Dr. Lin): Invalid-index CROB padding-candidate suite — COMPLETE ✅
Location: `dnp3_multicrob_harness/`. Rig-validated Vision↔Hulk 2026-07-08, all 8 cases pass.
- Added `run_master.py --crob-plan "idx:CODE,..."` (ordered; rejects dup/malformed; JSON records order).
- Analyzer boundary-index: dropped 0..N-1 assumption; new classifications multiple_invalid /
  decoy_only; added status_counts, byte lengths, frame counts. all-success default preserved.
- New `run_crob_padding_candidate_tests.py` (8 cases) -> captures/padding_candidates/ + reports/padding_candidates/.
- FIX run_outstation.py End(): write evidence at end of every SELECT/OPERATE batch (was missing
  the stack-level TOO_MANY_OPS-with-all-valid case, K16N17). all-success/failed-SELECT JSON unchanged.
- Result: invalid index -> OUT_OF_RANGE(12) per-index any position, no OPERATE, no output change;
  K5N17 shows OUT_OF_RANGE + TOO_MANY_OPS together; K16N17 -> too_many_ops. Padding NOT insertable.
- Memory: [[multicrob-invalid-index-padding]]. README + RESUME_STATE updated.
- Verified: py_compile x4; n16/n17 regressions pass; no codename; 8 pcapng + 8 JSON + manifest + md.

---

## Task (week8.md — Dr. Lin): Boundary-index CROB experiment — COMPLETE ✅
Location: `dnp3_multicrob_harness/`. Detailed notes: `dnp3_multicrob_harness/WORKING_NOTES.md`.

Goal: distinguish the OpenDNP3 per-request operation-count limit (`TOO_MANY_OPS`, status 8,
the N≥17 result) from a nonexistent-output-index rejection. Software-only, G12V1 only.

### Status: DONE and rig-validated (Vision↔Hulk, 2026-07-08)
- Valid K=5,N=5 → all SUCCESS, OPERATE sent, final state matches (5/5 operate).
- Invalid K=5,N=6 → index 5 rejected `OUT_OF_RANGE` (status 12) in SELECT response
  `[0,0,0,0,0,12]`; master sent NO OPERATE (operate_seen=0); batch discarded; no valid
  output changed. classification=`invalid_index_rejected_during_select_no_operate`.
- Both cases report task-level master SUCCESS/exit 0 → task SUCCESS ≠ outputs changed.
- Boundary is OUT_OF_RANGE (nonexistent index), cleanly distinct from TOO_MANY_OPS (count limit).

### Files changed
- `dnp3_multicrob_harness/analyze_multicrob_pcap.py` — added `--mode {all-success,boundary-index}`,
  `--configured-points`, `--expect-operate`; status-name map; classification. all-success default
  preserved (sweep unchanged).
- `dnp3_multicrob_harness/run_crob_boundary_index_test.py` — NEW rig orchestrator.
- `dnp3_multicrob_harness/README.md` — new "Boundary-index CROB test" section.
- `RESUME_STATE.md`, project memory (`multicrob-boundary-index-result.md`) — updated.
- run_outstation.py / run_master.py / replay / split / Class-0 / P4 — UNCHANGED (scope preserved).

### Verification done
- py_compile x4 OK; analyzer regressions n16 (all-success PASS) + n17 (boundary-index →
  too_many_ops); rig run produced fresh artifacts; no codename leak.

### Artifacts
- captures/boundary/crob_boundary_{valid_k5_n5,invalid_k5_n6}.pcapng
- reports/boundary/analyze_{valid_k5_n5,invalid_k5_n6}.json
- reports/boundary/boundary_index_{manifest.csv,results.md}

### Next action (optional, only if requested)
- Reproducibility re-run (`--only invalid`) or other K/N (`--valid-points 8 --invalid-extra 2`).
- Feeds the later padding-candidate question (response-side evidence: OUT_OF_RANGE vs TOO_MANY_OPS).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-17T23:52:41Z -->
### Compaction handoff — 2026-07-17T23:52:41Z
- Git: branch `research/ack-timing-phased`, 2 uncommitted file(s): dnp3_split_harness/phase04b_dcrn_attacker_eval.py dnp3_split_harness/scripts/phase04b_local_campaign.sh 
- Last verification run recorded: 2026-07-17T23:49:36Z	cd /home/philip/Projects/DNP3/dnp3_split_harness sed -i 's# \[ -n "\$obj" \] && attach "\$obj"# if [ -n "$obj" ]; then a
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- Phase 04B Gate C — 2026-07-17 -->
## Phase 04B (DCRN) — Gate C local paired campaign DONE; two-host rig BLOCKED on rig sudo pw

### Status
- **Gate C local paired campaign PASS** (veth vdcrn0 observer <-> vdcrn1/dcrn-srv server, DCRN on server tc, fq).
  NATIVE req->resp median 16.66ms; DCRN_FIXED 32.61ms (std 0.17); DCRN_COMMON_BOUNDED 37.54ms [32.44,42.61].
  Separate ACK->resp gap 18.14 (native) -> 0.18/0.20ms (DCRN guard delta). Transport clean: 0 retrans/reset/dupack.
- **Attacker eval (measured):** timing_all balanced-acc 0.720 -> 0.639 -> 0.436 (chance 0.333); mode_only + size
  unchanged 0.667; all=1.0. DCRN = timing normalizer, preserves mode/size by design (confirmed scope).
- **Two-host rig BLOCKED:** decps sudo on Vision/Hulk needs a password that is NOT the gambit password and is
  NOT stored (lab-hosts-dnp3: ask the user). Verified passwordless SSH works; gambit pw fails decps sudo on both.
  DCRN load on Hulk eno1 + tcpdump on Vision eno1 both need rig root. Driver + runbook READY.

### Files (this increment)
- reports/phases/phase_04b_dual_case_timing/gate_c_local_campaign.md (writeup)
- reports/phases/phase_04b_dual_case_timing/campaign_local/*.pcap + *.json + spec.json (+ manifests/campaign_local_sha256.txt)
- reports/phases/phase_04b_dual_case_timing/two_host_rig_runbook.md
- scripts/phase04b_local_campaign.sh (fixed set-u `local` split; ran clean)
- scripts/phase04b_rig_campaign.sh (dry-run default; RIG_PW transient; NOT wire-verified on rig)
- phase04b_dcrn_attacker_eval.py (sess[k % len] cycling for multi-run campaigns)
- phase_status.json (gate_c_local_campaign + two_host_rig blocks; loopback PASS, rig BLOCKED)

### Next action
- Get the rig decps sudo password from the user -> run scripts/phase04b_rig_campaign.sh (DRYRUN=0 RIG_PW=...).
- Keep next_phase_allowed=false; rig PASS only from measured rig PCAPs. Do not claim rig success from local.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-20T19:59:47Z -->
### Compaction handoff — 2026-07-20T19:59:47Z
- Git: branch `research/ack-timing-phased`, 13 uncommitted file(s): dnp3_split_harness/split_server.py research/tofino_dcrn_feasibility/p4/ack_delay/ACK_DELAY_CURRENT_STATUS.md research/inline_dnp3_size_normalization/ research/tofino_dcrn_feasibility/p4/ack_delay/SWITCH_ROLLBACK_RUNBOOK.md research/tofino_dcrn_feasibility/p4/ack_delay/defense1_read.py research/tofino_dcrn_feasibility/p4/ack_delay/defense1_setup.py research/tofino_dcrn_feasibility/p4/ack_delay/dcrn_defense1.conf research/tofino_dcrn_feasibility/p4/ack_delay/evidence/defense1_9.13.2/ research/tofino_dcrn_feasibility/p4/ack_delay/evidence/switch_snapshot.txt research/tofino_dcrn_feasibility/p4/ack_delay/evidence/switch_snapshot_20260720T150145.txt research/tofino_dcrn_feasibility/p4/ack_delay/launch_defense1.sh research/tofino_dcrn_feasibility/p4/ack_delay/minimal_c3_tcp_client.py 
- Last verification run recorded: 2026-07-20T19:58:32Z	cd /home/philip/Projects/DNP3/research/tofino_dcrn_feasibility/p4/ack_delay P=/home/philip/Projects/DNP3/dnp3_split_harn
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- Phase 05 / Case-A C3 clean-harness prep — 2026-07-20 -->
## Case-A (dcrn_defense1) C3 rerun prep — minimal TCP harness BUILT, C3 window GATED on counter reader

### Status (this increment)
- **Minimal single-transaction TCP harness DONE + smoke-tested + pushed to Hulk /tmp/.**
  - `ack_delay/minimal_c3_tcp_server.py` (outstation): accept -> kernel quickack pure ACK ->
    recv captured Class-0 READ (verify) -> re-assert TCP_QUICKACK -> response-readiness delay
    (native processing, NOT the defense) -> one write of the captured response -> hold socket OPEN.
  - `ack_delay/minimal_c3_tcp_client.py` (master): connect -> send captured READ -> recv+verify
    response -> hold socket OPEN. App timestamps DIAGNOSTIC only; wire capture is authoritative.
  - Loopback smoke (gambit 127.0.0.1): request_match=True, response_match=True, app_req_to_resp
    tracks readiness (~16.5ms at readiness=16). Ordinary TCP, NO pydnp3, genuine SEL-751 bytes
    (orig_0001.bin 22B / resp_0001.bin 54B). No IIN clear / WRITE / keepalive / 2nd request.
  - `ack_delay/c3_hulk_cycle.sh` (run ON Hulk): containment-correct per-transaction capture —
    capture -> ONE txn -> STOP CAPTURE -> (caller reads switch telemetry + resets flow) -> closeok
    -> close. TCP shutdown never enters the armed-flow capture. Params to CONFIRM-ON-SWITCH:
    C3_OBS_IFACE, NS_MASTER/NS_OUT, C3_REQ/C3_RESP. Pushed to Hulk /tmp/. bash -n clean.
- **C3 rerun GATED (hard prerequisite):** do NOT rerun C3 until ACK_MAXPASS / RESP_MAXPASS read
  reliably. Event-counter reader fix delegated to p4-dataplane-engineer (running) — dcrn_defense1
  events Counter reads 0 despite reg_held_count=9 + qid5 watermark=18; fix = diagnose or add
  dedicated event REGISTERS (keep <=12 stages), validate +1/reset->0.

### Next action (in order)
1. Land the p4-engineer counter-reader fix; validate ACK_MAXPASS/RESP_MAXPASS read reliably.
2. Reopen the narrow C3 switch window (snapshot+rollback per SWITCH_ROLLBACK_RUNBOOK.md; gc-switchd
   masked; restore decoy_paper3 after). Confirm C3_OBS_IFACE + netns on Hulk.
3. Native precheck: forward mode, confirm request->pureACK->response in the PCAP (separate ACK).
4. C3 matrix: NATIVE_FORWARD + CASE_A at readiness 2/5/10/16/20ms, >=10 valid txns/interval, reset
   switch state before each cycle, stay << HELD_MAX. Accept only if release tracks response arrival.
5. Restore switch (decoy_paper3), tear down Hulk rig, then the 5 pre-scale code fixes (exact ACK
   qualification, txn lifecycle, watermark bypass fail-open, generation freshness, true occupancy).

<!-- Case-A C3 window #1 — 2026-07-20: evstat verified, C1/C2 PASS, PARSER SHOWSTOPPER found, rolled back -->
## Case-A C3 switch window #1 — evstat fix verified on silicon; PARSER BUG blocks C3; rolled back

### What happened (PI GO'd full window; ran it end to end until an unexpected blocker)
- **evstat counter-reader fix VERIFIED off-switch AND on-silicon.** Root cause was Stats-ALU Counter
  sync (needs `operations_execute('SyncCounters')`; `from_hw` didn't force it on 9.13.2) — registers
  read live, which is why reg_held_count/watermark were always right. Fix = dedicated per-event
  registers evstat_ack[0=ACK_RELEASED,1=ACK_MAXPASS] / evstat_resp[0=RESP_RELEASED,1=RESP_MAXPASS].
  dcrn_defense1.p4 sha ce0b47e0. Local 9.13.1: 0 err, 11 ingress stages. On-switch --reset -> all evstat 0.
- **C1 PASS on real silicon:** bf-p4c 9.13.2 rebuild of the changed program = 0 errors, 11 ingress
  stages, evstat in bfrt. **C2 load PASS:** displaced decoy_paper3 (GO), bf_switchd bound dcrn_defense1,
  defense1_setup --mode forward + dp8 BF_LPBK_MAC_NEAR, dp8/dp9 up.
- **Rig connectivity fix (LOAD-BEARING, was missing from hulk_setup.sh):** the i40e NIC drops returning
  hairpinned frames whose src MAC is a local macvlan unless `ethtool --set-priv-flags enp59s0f0np0
  disable-source-pruning on`; also had to strip a stale 10.0.2.10 off the root NIC. After both: ping
  master->outstation 3/3 through the switch hairpin (RTT ~0.19ms). Captured in c3_hulk_rig_setup.sh.
- **NATIVE PRECHECK exposed a SHOWSTOPPER parser bug in dcrn_defense1.** Parser sends every non-SYN frame
  to dst_port==20000 into parse_dnp3_dl, which does an UNCONDITIONAL pkt.extract(hdr.dnp3_dl). A pure
  TCP ACK (zero payload) to dst 20000 -> extract past end-of-packet -> PARSER ERROR -> frame DROPPED.
  Wire proof: master pure ACKs to dst 20000 appear ONCE (dropped), request/response (payload) appear
  TWICE (hairpinned). Master's ACK of the response is dropped -> outstation retransmits 54B response
  5x (RTO backoff). Outstation's own pure ACK (src 20000) + ICMP unaffected. MASKED in the prior
  pydnp3 e2e because DNP3 CONFIRMs piggybacked the master's TCP ACK. Real-deployment showstopper.
- Positive signals BEFORE the retransmits: outstation's SEPARATE pure ACK is present + prompt
  (hold 0.023ms), first response arrives ~16.5ms -> native CLRT ~16.5ms confirmed, byte-identity holds.
  Case-A HOLD not yet validated (parser bug corrupts transport first).
- **Rolled back per runbook STOP-on-drop:** decoy_paper3 restored (bf_switchd on gf_v2b.conf),
  gc-switchd masked, Hulk rig torn down (source-pruning reverted). Switch + Hulk clean.

### Tooling built this window (all validated offline)
- minimal_c3_tcp_server.py / minimal_c3_tcp_client.py (single-txn TCP harness, SEL-751 bytes, no pydnp3)
- c3_hulk_cycle.sh (containment-correct per-txn capture on physical wire; apps as decps in netns)
- c3_analyze_pcap.py (wire-aware: master arrival=max(ts), Formby CLRT, ACK-hold, byte/transport checks)
- c3_hulk_rig_setup.sh (rig setup WITH the source-pruning + stale-IP fixes)

### Next action
1. Land the p4-engineer PARSER FIX (resumed agent ad188e03c5b99c642): parse DNP3 only when
   l4_len = ipv4.total_len-(ihl<<2)-(data_offset<<2) >= 10, else accept -> forwarded. Parser-only,
   byte-preserving, <=12 stages, evstat intact. Deliver fixed dcrn_defense1.p4 + local build evidence.
2. Re-open a fresh gated C3 window (needs PI GO): rebuild 9.13.2 on-switch, load, defense1_setup, dp8 lpbk,
   c3_hulk_rig_setup.sh (connectivity gate MUST pass), native precheck (clean transport, 0 retrans this
   time), then the C3 matrix native+Case-A 2/5/10/16/20ms >=10 txns. Analyze with c3_analyze_pcap.py.
3. Restore decoy + tear down Hulk after.

<!-- Case-A C3 window #2 — 2026-07-20: parser fix reloaded, CASE-A MECHANISM PROVEN ON SILICON -->
## Case-A C3 window #2 — parser fix reloaded; CASE-A CLRT-COLLAPSE PROVEN on Tofino

### Result (the C3 core hypothesis is CONFIRMED on real silicon)
- Parser fix (sha c9f4c109) rebuilt 9.13.2 on-switch (0 err, 11 stages, 171/256 parser TCAM),
  loaded, decoy displaced. Native precheck CLEAN — 0 retransmits (the parser drop is fixed).
- **NATIVE baseline:** Formby CLRT median tracks readiness exactly (2.44/5.47/10.48/16.50/20.51ms
  at 2/5/10/16/20ms), byte-identity 10/10. This is the response-readiness-dependent CLRT variation
  (separate-ACK structure) that Case A removes.
- **CASE-A:** the pure ACK is HELD on recirc and released on the response event, response after
  guard delta -> **CLRT collapses to ~0.03ms** (16.46->0.027ms proven at 16ms; 0.026ms at 2ms x10
  clean; 0.028-0.040ms at 20ms x3 fresh). Byte-identity 10/10 at ALL intervals; evstat
  ACK_RELEASED per txn, ACK_MAXPASS=RESP_MAXPASS=0 (event-governed, never fail-opens);
  zero-inversion invariant holds (ACK egresses before response). This is the defense working.
- **Recirc accumulation finding (measurement artifact, NOT a mechanism failure):** in a back-to-back
  100-txn matrix, held close-FINs from prior txns accumulate on the shaped recirc queue (10000 PPS
  qid5); congestion delays the response release past the outstation's 200ms TCP RTO -> the outstation
  retransmits -> the retransmit bypasses (ack_seen already consumed) and reaches the master ->
  measured CLRT inflates + transport dirties at higher intervals (later in the run). PROVEN it is
  accumulation not readiness: a cold reload -> fresh 20ms txns are clean (CLRT ~0.03ms). Fix for a
  clean per-interval table = cold-reload dcrn_defense1 before each interval (c3_matrix.sh reload_setup).
  Root causes are the flagged code findings (persistent armed state; reg_held_count no true-occupancy
  decrement; broad zero-payload ACK matching holds close-FINs).

### Operational lessons banked (all load-bearing on this rig)
1. Parser must gate DNP3 descent on L4 payload length (else pure ACKs to dst 20000 are dropped).
2. dp8 loopback MUST be re-applied after EVERY defense1_setup (it re-creates ports -> dp8 BF_LPBK_NONE).
3. i40e disable-source-pruning ON + strip stale 10.0.x off the root NIC (else hairpin frames dropped).
4. Cold-reload between intervals for clean matrix numbers (recirc state does not self-flush fast).
5. evstat registers are authoritative; the events Counter still reads 0 (SyncCounters op-name wrong).

### Tooling (this window): c3_matrix.sh (per-interval reload), c3_aggregate.py (reads evstat),
### c3_analyze_pcap.py (wire-aware), c3_hulk_rig_setup.sh (with fixes). Clean matrix re-run in progress.

### Next: finish clean native+case-a matrix (per-interval reload) -> aggregate -> restore decoy + Hulk.

<!-- Case-A C3 — CLEAN MATRIX DONE, WINDOW CLOSED 2026-07-20 -->
### C3 CLEAN MATRIX (per-interval reload) — DONE, window closed
- **CASE-A CLRT is a constant ~0.03ms at EVERY readiness** (2/5/10/16/20ms -> 0.028/0.033/0.028/
  0.028/0.027ms), vs **NATIVE CLRT = readiness** (2.48/5.49/10.41/16.49/20.52ms). 100/100 txns
  byte-identical + clean transport; ACK_RELEASED=10 per interval; ACK/RESP_MAXPASS=0 everywhere.
  **Precise claim (fully supported):** in the controlled single-flow hardware microbenchmark, Case A
  removed the response-readiness-dependent CLRT variation by reducing the visible ACK-to-response gap
  from 2.48-20.52 ms (native) to a device-independent hardware guard of ~0.03 ms. **C3 PASS (mechanism,
  single-flow microbenchmark).** NOT yet proven: continuous-operation stability, multi-flow, physical
  SEL-751 stack, cross-device classifier accuracy, combined ACK-bearing responses, guard indistinguishability.
- Evidence: research/tofino_dcrn_feasibility/p4/ack_delay/evidence/c3_matrix/ (summary + 10 rep pcaps
  + 100 tel.json). Switch RESTORED to decoy_paper3 (gf_v2b.conf), gc-switchd masked; Hulk torn down.
- UNCOMMITTED: dcrn_defense1.p4 (parser+evstat fixes, sha c9f4c109), defense1_read.py, c3_* tooling, evidence.
  Do not commit without PI go-ahead.

<!-- Case-A pre-scale hardening FIX 1+2+4 — DONE off-switch + committed 2026-07-20 -->
### Case-A pre-scale hardening (FIX 1+2+4) — off-switch DONE + committed (d380d1a)
- I took over the P4 directly (the p4-engineer agent kept dying spuriously). Hardened dcrn_defense1.p4
  sha 6e1b659b: FIX 1 exact pure-ACK qualification (FIN/RST/SYN/keepalive/dup/wrong-ack NOT held ->
  accumulation root cause fixed), FIX 2 lifecycle clear (armed getclr @response + pure-RST/FIN abort
  via a single armed_get_absclr SALU), FIX 4 binary flow_has_held_ack occupancy (replaces cumulative
  reg_held_count). Deferred: FIX 3 + FIX 5 (12/12 at limit; need evstat->egress offload for headroom).
- KEY BUG FOUND + FIXED: the WIP computed exp_ack = seq_no + (bit<32>)payload_len in one ALU op ->
  BIT_COLLISION / "invalid container action compiler cannot correctly interpret" (0 errors but WRONG
  on hardware). Fixed by materialising a 32b exp_addend via a SET in the prologue (clean 32+32 add);
  payload_len stays 16b (total_len+neg_ov overhead needs 16-bit wraparound).
- Local bf-p4c 9.13.1: 0 err, 2 benign warnings, 12/12 ingress stages, egress 1, crit path 7,
  byte-preserving, evstat intact. Tests: test_hardening_fix124.py 12/12 + test_defense1.py
  17/17. Evidence: evidence/defense1_9.13.1_hardened/STATUS.md. Committed d380d1a (Philip, no attribution).
- Switch on decoy, gc-switchd masked, Hulk torn down (unchanged this increment — all off-switch).
- NEXT (gated switch window, needs PI GO): continuous-traffic hardware campaign — 100+ consecutive
  Class-0 txns on ONE connection, shuffled readiness, NO cold reload; require zero retrans/reset/
  inversion/MAXPASS/stale, occupancy->0, no backlog. Only THEN case_a_continuous_operation = PASS.

<!-- Continuous campaign 2026-07-20: caught a HW REGRESSION in the hardened build -->
### Continuous-traffic campaign (hardened 6e1b659b) — transport PASS, DEFENSE FAIL (regression)
- 120 txns/one connection/shuffled readiness/no reload. **Transport PASS**: 120/120 byte-identical,
  0 retrans/reset, no degradation (accumulation fix works). **DEFENSE FAIL**: the ACK is NOT held —
  wire shows the pure ACK forwarded (doubled, immediate), CLRT tracks readiness (~10ms) not the
  ~0.03ms guard; egress evstat all 0. Hardened FIX 1 exact-qual rejects the pure ACK on silicon
  (qual==0) despite unit tests passing. C3-pass c9f4c109 (broad match) held it -> regression is in
  the ADDED flags_ok/amatch conditions (amatch = reg_expected_ack==ack_no the prime suspect).
- Secondary: the WIP moved evstat to EGRESS (pipe.DcrnEgress.evstat_*) -> committed defense1_read.py
  (reads ingress) KeyErrors; reg_held_count replaced by flow_has_held_ack. Reader stale for this build.
- Evidence: evidence/continuous_campaign_FAIL/ (pcap + logs + FINDING.md + debug plan). Switch restored
  to decoy, gc-switchd masked, Hulk torn down. **d380d1a hardening is off-switch-verified but has a HW
  hold regression -> NOT deployable; c9f4c109 remains known-good. case_a_continuous_operation=FAIL(hold).**
- NEXT: debug off-switch (compare hardened vs c9f4c109 hold path; audit expack lowering/SALU) then a
  gated probe window (fixed client port -> flow_id -> read reg_expected_ack vs ack_no).

<!-- Continuous campaign RESOLVED 2026-07-20: was a stale setup script, NOT a P4 regression -->
### Continuous campaign — RESOLVED: earlier FAIL was a stale setup script; hardened build PASSES
- The "regression" was NOT the P4. `defense1_setup.py` crashed on the removed reg_held_count (FIX4 ->
  flow_has_held_ack) BEFORE installing the fc_allowlist -> nothing armed -> ACK not held. Fixed
  defense1_setup (REG_GLOBAL=[]) + defense1_read (evstat->DcrnEgress, reg_held_count->occupancy scan).
- **Continuous campaign now PASS on Tofino:** 120 txns/one connection/shuffled readiness/NO reload:
  CLRT collapsed to constant ~0.026ms (head 0.031 ~= tail 0.026, no degradation), 120/120
  byte-identical, 0 retrans/reset, evstat ACK_RELEASED=120 RESP_RELEASED=120 MAXPASS=0. Occupancy
  residual=1 (not accumulating; minor follow-up). Single-txn: 16.46 native -> 0.024ms Case-A.
- **case_a_continuous_operation = PASS_MEASURED_ON_TOFINO.** Evidence:
  evidence/continuous_campaign_PASS/RESULT.md (+ _FAIL/ documents the setup-bug root cause).
- Switch LEFT LOADED with hardened dcrn_defense1 (PI: "leave switch for this experiment"); NOT restored.

<!-- SEL-751 faithful-replay experiment 2026-07-20: Case-A on authentic device traffic -->
### SEL-751 faithful-replay experiment — Case-A collapses the real device CLRT (PASS)
- Live SEL-751 NOT on testbed (10.0.0.1:20000 refuses; switch only dp8/dp9; SEL751.pcap = 2019 capture;
  no Vision, Hulk hosts both roles). Per PI: faithful REPLAY of the real SEL-751 timing through DCRN.
- Extracted 299 real SEL-751 txns (sel751_extract.py): native CLRT median 12.90ms (10.5-166 spread),
  all separate-ACK = the Formby fingerprint. Replayed 99 Class-0 (22B/54B) with REAL per-txn latency.
- **NATIVE (real timing): CLRT median 17.35ms (15.1-26.6 spread). CASE-A: collapsed to constant
  ~0.026ms (0.0-0.039, no degradation).** Both 99/99 byte-identical, 0 retrans/reset. Case-A flattens
  the SEL-751's variable native CLRT to a device-independent guard on authentic traffic, byte-preserving.
- Fidelity caveat: replay reproduces real BYTES + response-LATENCY distribution + separate-ACK STRUCTURE,
  NOT the SEL-751's own ~4ms ACK delay (replay quickacks) -> replay native CLRT ~17ms vs real device ~13ms;
  the collapse result is independent of that offset. Live-device run pending a physical relay on the switch.
- phase_status.case_a_physical_device_validation = PASS_FAITHFUL_REPLAY_ON_TOFINO. Evidence:
  evidence/sel751_replay/RESULT.md. Switch LEFT LOADED (case-a) per PI; Hulk rig up.

<!-- Formby CLRT classifier eval 2026-07-20: CLRT-value fingerprint neutralized -->
### Formby CLRT classifier eval — Case-A neutralizes the CLRT-value fingerprint (DONE)
- research-scientist designed (Formby-paper-grounded: model-free 1-D AUROC + ACK-mode positive control).
  Built a mode-matched 2-device anonymity set: device1=SEL-751 rig-native 17ms, device2=synth 35ms
  (dev_campaign.sh), both collapse to 0.026ms under Case-A.
- **E1 SEL-751 collapse:** Cliff's delta 1.000, KS 1.000, median 17.35->0.026ms (667x); static Formby
  template ID rate 0.99(native)->0.00(Case-A); ACK-mode control 1.00/1.00 (unchanged).
- **E2 device separability:** 1-D AUROC 1.000(native)->0.571(Case-A) [0.507,0.648]; balanced acc
  1.000->0.611. Case-A drives CLRT-value separability to near-chance.
- Caveats (in RESULT.md): anonymity-set-of-one (device2 rig-synth); CLRT-VALUE only (ACK-mode+size
  survive; joint attacker partially defeated, size floor ~0.50); replay not live (rig 17ms vs cap 13ms).
  Residual AUROC 0.57>0.5 = guard-delta jitter (constant-CLRT new-signature risk).
- phase_status.formby_attacker_evaluation = PASS_CLRT_VALUE_NEUTRALIZED. Evidence:
  evidence/formby_eval/ (RESULT.md + formby_clrt_collapse.png + formby_eval.py + 4 pcaps). Switch LEFT
  LOADED (case-a) per PI. sklearn absent -> numpy/scipy model-free metrics.

<!-- AUTONOMOUS PI RUN 2026-07-20: Case B end-to-end + viz + slides + Netronome research -->
## AUTONOMOUS PI RUN (Dr. Lin meeting prep) — plan + tracking
PI directive: run autonomously; complete everything; use expert agents. Deliverables:
1. Case B end-to-end: dcrn_defense2.p4 local compile (p4-engineer, in progress) -> gate met (refmodel 10/10
   + <=12 stages) -> HARDWARE run B1_FIXED (G_i=60ms) before/after for dev1(17ms)+dev2(35ms). [gate now
   AUTHORIZED by PI: they want Case-B results.] Switch left loaded per prior instruction.
2. CLUSTERING visualization: response-time clusters, BOTH cases, before/after. Shows a passive observer
   CANNOT fingerprint after. CLEAN: NO "CLRT"/"Formby" labels, LINEAR x-axis (plain numbers, not 10^x).
3. SLIDES for Dr. Lin weekly meeting: (a) case design+experiment; (b) before classification/clustering
   both cases; (c) eBPF software impl + challenges; (d) Tofino impl: replay device pcaps over TCP +
   delay on Tofino; (e) results both cases; (f) Tofino HW usage (TCAM etc) both cases + why timing+split+
   padding can't all fit on Tofino; (g) Netronome DPU/SmartNIC on Vision as Tofino replacement for testbed.
4. Netronome NFP SmartNIC/DPU research (sdn-networks-expert): feasibility to replace Tofino for the
   testbed (hold ACK/response, byte-preserving, per-flow state); programming model (P4/eBPF/Micro-C);
   pros/cons vs Tofino; can it host timing+split+padding together. -> feeds slide (g).
STATUS: Case-B off-switch design+refmodel(10/10)+calibration(G_i=60ms) DONE. dcrn_defense2.p4 compile running.
Netronome research launching. Case-A commits/tags PRESERVED (bf4acdf..e6c2280, tag ack-delay-caseA-c3-pass).

<!-- Case B HARDWARE 2026-07-20: device-independent constant CLRT on Tofino -->
### Case B hardware — device-INDEPENDENT constant CLRT on Tofino (PASS)
- dcrn_defense2.p4 6387accb loaded (9.13.2, 10 stages), B1_FIXED G_i=60ms (916 ticks, defense2_setup.py
  bounded_target 256 buckets), dp8 loopback. defense2_setup + dp8_loopback_ackB + dcrn_defense2.conf +
  launch_defense2.sh created (adapted from Case-A). Case-A dcrn_defense1 displaced (rebuildable/reloadable).
- **RESULT:** native CLRT dev1 17.35ms vs dev2 35.30ms (separable). Case-B CLRT dev1 106.99ms ==
  dev2 107.00ms (IQR +-0.02ms) -> DEVICE-INDEPENDENT constant. ACK forwarded immediately (0.02ms hold);
  response held to ACK-relative deadline; byte-identical 99/99; 0 retrans/reset; occupancy(reg_held_count)
  ->0; deadline-governed (107ms << MAX_PASS). 
- Offset: constant 107ms vs nominal G_i 60ms = ~47ms recirc-drain under load (single-txn ~21ms). CONSTANT
  + device-independent -> defense holds; value tunable; characterize under load sweep for B2.
- Both cases now proven on Tofino: Case A COLLAPSES CLRT to ~0.026ms; Case B FIXES to constant ~107ms.
  Both make CLRT device-independent (defeat fingerprinting). phase_status.case_b=PASS. Evidence
  evidence/defense2_hardware/RESULT.md. Switch LEFT LOADED (Case-B) + Hulk rig up per "leave switch".
- NEXT (autonomous): clustering viz both cases before/after (clean, linear axis) -> Dr. Lin slides ->
  Netronome research (after 1hr per PI).

<!-- Netronome research DONE 2026-07-20 + slide g filled -->
### Netronome SmartNIC feasibility (deferred 1hr, then run) — DONE; slide (g) filled
- sdn-networks-expert study (source-verified): VERDICT viable-with-caveats but NOT the card to buy new.
  NFP is a run-to-completion processor -> NO 12-stage wall + GBs memory -> timing+size+split CO-RESIDE
  (dissolves the Tofino-1 blocker; the ~47ms Case-B offset is a Tofino recirc/shaper artifact, not
  fundamental). No native "tx at T" but ms hold = descriptor ring + timer-poll thread (no recirc/shaper).
  Caveats: Micro-C in Corigine's proprietary SDK (rewrite not port); eBPF-offload subset/maintenance;
  Corigine vendor risk (new-buy availability/support/pricing need a quote). REC: pilot on-hand Agilio CX
  to prove co-residency; if BUYING -> BlueField-3 (native ConnectX accurate-scheduling +-900ns timer,
  supported DOCA, no EOL). Brief: research/tofino_dcrn_feasibility/netronome_smartnic_feasibility.md.
- Slide (g) of the Dr. Lin deck FILLED (verdict + Tofino/Netronome/BlueField capability table).
  Deck re-published (same URL) + repo copy refreshed. Viz + slides STILL DRAFTS pending PI clean-up pass.
- AUTONOMOUS RUN COMPLETE: Case B (design/refmodel/compile/hardware) + both-cases clustering viz + 8-slide
  deck + Netronome brief. All committed (Philip's name, no attribution; Case-A tag preserved). Switch LEFT
  LOADED (Case-B) + Hulk rig up per "leave switch". NEXT (needs PI): clean viz/slides; decide Netronome vs
  BlueField pilot; restore switch when experiments truly done.

<!-- Case B B2_COMMON_BOUNDED 2026-07-21: completes Case B -->
### Case B B2_COMMON_BOUNDED (completes Case B) — device-independent bounded, drain-masked
- defense2_setup.py --bounded-band 55,65 (256 buckets ~U[55,65]ms, global-counter-walked, device-independent).
  dev1==dev2 median 107.0ms, AUROC 0.594 (near chance), CLRT bounded [82,107]ms, byte-identical 99/99.
- HONEST: bounded DISTRIBUTION masked by the ~47ms recirc-drain offset (IQR [107,107] = collapses toward
  B1 constant). Tofino recirc/shaper timing-mechanism limit -> reinforces the SmartNIC-with-real-timer case.
- CASE B COMPLETE (B1_FIXED + B2_COMMON_BOUNDED both on hardware). phase_status.case_b=PASS(B1+B2).

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-07-21T10:34:20Z -->
### Compaction handoff — 2026-07-21T10:34:20Z
- Git: branch `research/ack-timing-phased`, 4 uncommitted file(s): dnp3_split_harness/split_server.py research/inline_dnp3_size_normalization/ research/tofino_dcrn_feasibility/p4/ack_delay/evidence/visualization/pcap_screenshots.png who-control-your-control-system-device-fingerprinting-cyber-physical-systems.pdf 
- Last verification run recorded: 2026-07-21T05:17:23Z	cd /home/philip/Projects/DNP3 echo "=== restore all deleted tracked files (return to committed state) ===" git restore "
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.
