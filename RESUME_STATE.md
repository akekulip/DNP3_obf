# DNP3 Experiment — Resume / State Checkpoint

_Last updated: 2026-07-26. Read this first to resume work._

> ═══════════════════════════════════════════════════════════════════════════════════════════
> **►►►►► PICK UP HERE — 2026-07-26: CORRECTED v2 PACKAGE COMPLETE ►►►►►**
>
> **Branch `research/timing-inline-corrected-v2`, HEAD `916e6cb`.** The live-inline Defense 2 result
> is real and is now stated accurately. The v1 bundle is preserved unchanged; do not cite it.
>
> **►► STANDING RULE: ALL WORK GOES ON `main`.** Commit AND push to `origin main` in the same
> pass. Do NOT create feature branches for tasks. The existing branches are KEPT (Philip:
> "leave them but make sure all put goes into main") but are not to be worked on — they are
> fully contained in `main`. Verify a push by reading it back with `git ls-remote --heads
> origin`; GitHub shows the DEFAULT branch, so anything off `main` looks like it never landed.
>
> **GIT / PUBLICATION STATE (2026-07-26):** everything is committed AND pushed. **`main` now carries
> the whole line** — fast-forwarded `dea8f8b..229530d` (314 commits, no merge commit, clean
> ancestor) and pushed; verified from the server. **Work on `main` from here**; the local checkout
> is on `main`. `research/timing-inline-corrected-v2` and `research/timing-final-meeting` were also
> pushed and are now fully contained in `main`, as are `research/caseA-ditto-queue` and
> `research/ack-timing-phased` — they hold nothing unique. **PENDING (Philip's call): delete those
> four remote branches so only `main` remains.** Local-only branches never pushed and not yet
> checked for containment: `research/ibspg-*`, `research/queue-backpressure-release`,
> `overnight-autonomy-20260723-2255`.
>
> **THE DELIVERABLE:** `meeting_package/timing_inline_v2/` (43 files, all verify against
> `SHA256SUMS`) + `timing_inline_v2_20260726_916e6cb.tar.gz`. Everything in it is generated from
> ONE manifest, `evidence/corrected_v2/authoritative_results.json`, computed from the four shipped
> pcaps. Rebuild with `meeting_package/timing_inline_v2/source/build_v2.sh`.
>
> **WHAT THE RESULT IS.** Running inline between the master and a physical SEL-751, the Tofino-1
> Defense 2 implementation forwarded the pure TCP ACK immediately and held the DNP3 RESPONSE until
> an ACK-relative deadline. The relay's dispersed native CLRT observations concentrated into a
> narrow cluster around the configured 25 ms target.
>
> | campaign | all-state sd ratio | steady-state sd ratio |
> |:--|--:|--:|
> | A | 224.4x | 34.5x |
> | B | 328.1x | 80.3x |
>
> Both variants are reported; NEITHER is "the" result. All-state variance is strongly influenced by
> the first (connection-cold) transaction of each capture: A 22.660 ms, B 37.215 ms.
>
> **WHAT WAS WRONG IN v1 AND IS NOW FIXED** (full list: `CORRECTIONS_REGISTER.md`, 16 items):
> - v1 quoted campaign B's numbers while shipping campaign A's pcaps. BOTH campaigns are real; both
>   pairs are now shipped and labelled.
> - CLRT is **Cross-Layer Response Time** (Formby et al., NDSS 2016), not "Command Loop".
> - Outstation DNP3 link address is **0**, not 10 (wire-verified; `CLAUDE.md:134` corrected).
> - "54 bytes" is the **TCP payload**; frame is 120 B, IP total 106 B.
> - Removed "exactly G", "every transaction identical", "carries no information", unqualified
>   "entropy zero", anonymity and fully-internal-seeding claims.
> - Entropy is now always quoted with bin width, origin 0.0 ms, half-open [lo, hi), and n.
>   **Campaign A protected occupies TWO 1 ms bins (0.4395 bits), not one** — its min 24.998 ms falls
>   the other side of the edge. Campaign B occupies one (0.0000 bits).
> - The realized CLRT is near, not equal to, the target: release tail A +0.057 ms, B +0.070 ms.
> - Blockers are **host-seeded**, then circulate internally; release is data-plane controlled.
>
> **HEADER FIXED 2026-07-26.** The false `compile-only, never loaded` comment (and the wrong
> filename on line 2) is corrected. That changed the source sha `fb3b10da…` -> `dd9b816a…`.
> **The LOADED binary was built from the OLD `fb3b10da…`**; the two files differ ONLY in the
> comment block (proven by stripping comments: 16,418 code chars identical both sides).
> `lab.env.inline` now pins BOTH (`P4_SRC_SHA256` and `P4_SRC_SHA256_AS_LOADED`). The switch
> staged copy and the archive copy were deliberately NOT re-staged — they are the build-input
> evidence. Do not "reconcile" them by reloading.
>
> **PROVENANCE PROVEN.** Source sha `fb3b10da…` holds a five-way match (repo, deliverables, archive,
> `lab.env.inline` pin, switch copy). The `compile-only, never loaded` header comment is STALE
> BOILERPLATE inherited from the predecessor; the artifact chain proves it WAS loaded. The two
> builds are **equivalent in MAU footprint (10/12 stages, 60 tables, 55 SRAM) but NOT byte-identical**
> (local `3b6ee6d7…` vs switch `180e44aa…`, 34 differing bytes). Detail:
> `SOURCE_TO_SILICON_PROVENANCE.md`. **The header has since been FIXED (see above): sha
> `fb3b10da…` -> `dd9b816a…`, comments only. Do NOT re-stage the switch copy or the archive copy
> to 'match' — they hold the as-loaded revision and are the build-input evidence.**
>
> **RELAY TIMING STATES CHARACTERIZED** (`evidence/corrected_v2/COLD_WARM_IDLE_CHARACTERIZATION.md`):
> - The "outliers" are a **connection-cold state, exactly one poll deep**. C2 by ordinal: poll 1
>   median 23.600 ms / max 102.805; polls 2-5 all ~2.1 ms median.
> - C1 (30 new connections): median 25.252, max 87.735. **50 % exceed 25 ms.**
> - C3 (steady, 100 polls): median 1.401, max 21.695. **0 % exceed 25 ms.**
> - C4 (idle 1/5/15/30 s, n=92): idleness does NOT re-create the cold state. 0/92 above 21.695 ms.
> - **The relay emits TCP keepalives every ~10.02 s while idle** (`seq = SND.NXT-1`). A keepalive is
>   a pure ACK carrying the expected_ack of the last READ, so it QUALIFIES under the ACK rule. This
>   is a naturally occurring instance of "correct ACK after completion" — if normal release does not
>   clear transaction state, a keepalive can re-arm a deadline.
>
> **G CONSEQUENCE (decision still open):** steady state is protectable at 25-40 ms; a single G
> covering the connection-cold state needs > ~103 ms. Recommendation on record: protect the steady
> state and declare the connection's first poll out of scope, since C4 shows the steady state is
> stable once established.
>
> **ANALYZER.** `evidence/corrected_v2/scripts/analyze_live_clrt.py` pairs on the expected ACK
> number, cross-checked by an independent tshark pipeline; they agree on every transaction to
> better than 1 µs. 10/10 adversarial tests pass (`test_analyzer_pairing.py`). Known limitation,
> asserted not hidden: two TCP streams with transactions IN FLIGHT SIMULTANEOUSLY cause a
> REJECTION with an explicit `validation_failure`, never a mispairing. Single-stream is unaffected.
> The v1 `clrt.py` paired by positional adjacency and was right only by luck of clean captures.
>
> **INTERNAL SEEDING (spike, not on the critical path):** FEASIBLE-AND-COMPILED via an ingress
> mirror session whose destination is a 64-node multicast group on dp8 — each token is a copy of the
> READ, so the generation byte rides in mirror metadata. `dnp3_timing_normalizer_selfseed.p4`
> compiles at 10/12 ingress (unchanged), egress 0→2, SRAM 55→61. NOT loaded, NOT measured.
> Detail: `research/timing_final/INTERNAL_SEEDING_SPIKE.md`.
>
> **SWITCH STATE:** still running `dnp3_timing_normalizer_inline` (`tn_inline_abs.conf`,
> bf_switchd PID 228141). NOT restored to queue_microbench — Philip said not to.
>
> **NOT DONE / EXPLICITLY OUT OF SCOPE this week** (Philip: "STOP SCOPE EXPANSION"): live/replay
> binary split, exact transaction matching in P4 with new counters, normal-release cleanup proof,
> T1-T18 negative tests, observed low-G campaign, >=100-transaction Phase A/B/C, internal seeding
> on silicon, live byte-identity proof.
>
> **KNOWN GAPS in the shipped result, stated in `LIMITATIONS_V2.md`:** live byte identity NOT
> proven (the relay leg cannot be tapped); blocker external visibility UNTESTED in the shipped
> captures (they used the narrow v1 filter that excludes 0x88C1 by construction — any new capture
> must use `(host 192.168.10.7 and tcp port 20000) or ether proto 0x88c1`).
>
> **INCIDENT 2026-07-26:** `deliverables/` (63 files) was found deleted from the working tree after
> the v2 package build. All files were committed, so `git restore deliverables/` recovered them
> intact and verified (v1 PDF 22 pp, p4 sha `fb3b10da…`, archive copy 30 files untouched). Nothing
> was lost. **I could not identify what removed it** — it happened after commit `916e6cb`, and the
> only command run between the commit and detection was `git log`. Treat as unexplained; verify
> `deliverables/` exists before trusting a working tree.
> ═══════════════════════════════════════════════════════════════════════════════════════════


> **►►►►►►► RESUME HERE — 2026-07-25 (latest): TIMING DELIVERABLE COMPLETE (direction.md + direcr2.md).
> Branch `research/timing-final-meeting`, tag `timing-final-meeting-v1` at `f5e3aee`. The Part 12 block
> below remains valid history (it is the mechanism this deliverable packages).**
>
> The one-week timing-only delivery is DONE end to end. All of `direction.md` (§2–§12) and `direcr2.md`
> (§13–§29) are satisfied and committed.
>
> - **Canonical program:** `research/timing_final/p4/dnp3_timing_normalizer.p4` (sha 82f572ce), 10/12
>   ingress stages, 0 egress, 0 TCAM; compiles clean on bf-p4c 9.13.1 (local) and 9.13.2 (switch). It is
>   the Part-12 HOLD_RESPONSE mechanism + the directive-§3 G-selection guard.
> - **Result (real SEL-751 frames, replay):** protected CLRT median 24.999 ms, sd 0.010 ms (native sd
>   10.33 ms); CLRT-magnitude entropy **2.73 → 0.00 bits** @1 ms; byte-identity 100/100; release tail
>   1734.5 ns sd 7.34 ns. Claim discipline held: timing/CLRT channel ONLY — NOT size, NOT device
>   anonymity (ACK-mode + TCP-stack untouched, accuracy 1.000; anonymity-set-of-one), NOT a live inline
>   session (replay), NOT production-ready.
> - **Docs (`research/timing_final/`):** TIMING_REFERENCE_IMPLEMENTATION / TIMING_FINGERPRINTING_ANALYSIS
>   / TIMING_MECHANISM_EXPLAINED / TIMING_FINAL_RESULT / REVIEW_FINDINGS_AND_ACTIONS / FINAL_EXPERIMENT_PLAN;
>   DEMO_SCRIPT_2_MINUTES + TECHNICAL_TALK_5_MINUTES; evidence/ (native, protected G-sweep + final100_g25,
>   g_guard, fingerprinting, 10 figures via `scripts/make_pub_figures.py`, MANIFEST, final_state).
> - **Lab interface (`research/timing_final/`):** `make` targets preflight/build/load/configure-tm/
>   demo-native/demo-protected/analyze/figures/restore + guarded `make demo MODE=replay TRIALS=10 G_MS=25`
>   (add `DRYRUN=1` to touch nothing). Analyzer cross-checked vs tshark (Δ 0.7 µs).
> - **Tutorial package (`deliverables/timing_tutorial/`):** self-contained `index.html` (sidebar, copy
>   buttons, 12 embedded figures) + 17pp PDF (both from `source/tutorial_source.md` via `build_tutorial.sh`);
>   7 editable SVG diagrams (`source/make_diagrams.py`); README_FIRST, QUICKSTART, LAB_RUNBOOK,
>   WIRESHARK_GUIDE (tshark-verified fields), CODE_WALKTHROUGH, TROUBLESHOOTING, CLEAN_ROOM_TEST;
>   example_pcaps (native_demo 486pkt / protected_demo 200pkt — master 192.168.10.1, outstation .7).
> - **Meeting package:** `deliverables/build_meeting_package.sh` regenerates `deliverables/meeting_package/`
>   (START_HERE.html + everything) → `timing_meeting_package_20260725_f5e3aee.tar.gz` + verified SHA256SUMS
>   (61 files). The assembled dir + tar.gz are gitignored (regenerable).
> - **Clean-room (§27):** 11/11 steps exit 0 — on-switch path dry-run (switch is restored to
>   `queue_microbench`, so loading is gated), offline analysis executed for real and reproduces the headline.
> - **Switch state:** RESTORED to `queue_microbench` (evidence/final_state/restoration_report.txt). No
>   hardware change was made in this delivery; any live on-switch demo needs explicit authorization.
> - **LIVE ON-SILICON DEMO — PASSED 2026-07-25 (Philip authorized "proceed"; commit 4e0c325).**
>   `demo_all.sh --mode replay --trials 10 --g-ms 25 --yes` ran end to end on the physical testbed:
>   loaded dnp3_timing_normalizer, injected real replay traffic from Vision+Hulk, captured+verified
>   native and protected, restored the switch. Result: native CLRT median **1.970 ms** (sd 0.011) →
>   protected **24.998 ms** (sd 0.014), n=10; 10/10 released; **0 unmatched (byte-identity), 0 external
>   blocker frames**; all 10 verifier gates PASS; RESTORATION PASS (switch back on queue_microbench).
>   Evidence: `research/timing_final/evidence/live_demo/`. Getting here required fixing SEVEN latent
>   lab-script bugs (the live demo_all path had only ever been dry-run) — see
>   [[timing-live-demo-lab-script-bugs]] memory; the mechanism itself was unchanged.
> - **NEXT (all gated on Philip):** the security-result step = a fleet of separate-ACK devices
>   normalized to a shared G with ACK-mode/TCP-stack held constant. Do NOT resume size work.
>
> ---
> **Prior position — 2026-07-25 (earlier): PART 12 STARTED. Gate 12.1 PASS (compile only).
> This block is valid history; the Parts 9+11 block below it remains valid history.**
>
> **Branch `research/ibspg-hold-response`** (new, off `9bb3c91`), HEAD `aa070ed`. Part 11's branch is
> left at its completion commit `3d5222e`. Part 12 = the **HOLD_RESPONSE** branch of the unified
> transaction state machine: the ACK is **forwarded immediately** (stamps `t_ack`), only the
> **RESPONSE** is held queue-resident, and it is released when a **deadline-checking blocker**
> self-terminates at `t_ack + G`. The emitted ACK→response interval therefore becomes `G` regardless of
> the device's native interval — this is the CLRT normalization that defeats the Formby fingerprint, and
> Part 11's ordering result is its substrate. There is **no drain role and no drain register**: the only
> release causes are the deadline and the fail-open budget, so no injected packet can cause a release
> (strictly stronger isolation than Part 9).
>
> **Gate 12.1 = PASS.** `research/ibspg_hold_response/p4/ibspg_hold_response/ibspg_hold_response.p4`
> (sha `fa073cf6`) compiles **0 errors, 12/12 ingress stages** on BOTH local bf-p4c 9.13.1 and on-switch
> 9.13.2, identical resources (44 logical tables / 36 SRAM / 0 TCAM) — no drift. The on-switch compile
> was **non-destructive**: `bf_switchd` was never restarted and stayed on `part11_abs.conf`, PID 112251
> before and after. Evidence: `.../ibspg_hold_response_compile_note.md`; gates:
> `research/ibspg_hold_response/PART12_HOLD_RESPONSE_PLAN.md`.
>
> **Compile lessons (each cost a cycle, do not rediscover):** a bit-slice inside a gateway condition is
> rejected ("condition expression too complex"); a bit-slice of a 32-bit arithmetic field breaks PHV
> allocation outright even as a plain assignment (12 unallocated slices — the invalid-SuperCluster trap,
> naming ts32/dl_val/dl_now/hdr.ib.seq/ingress_mac_tstamp). Deadline expiry is therefore decided by a
> **ternary match on the sign bit of (now − deadline)** — same bit, no PHV slicing constraint.
>
> **Gate 12.2 = PASS (silicon).** The switch now runs **Part 12**: `ibspg_paired` was displaced and
> `bf_switchd` relaunched on `/home/decps/part12/part12_abs.conf` (PID 139143), binding `p4_name:
> ibspg_hold_response`. Static config installs clean — `strict_priority_verified: true`, Q_BLOCK
> `max_priority` reads back **7**, Q_RESP **LOW** (two levels are all this branch needs; the ACK is
> never queued). **All 18 bfrt objects resolve** (7 registers, 11 counters — name risk closed before
> any traffic gate). dp8 (MAC-near loopback), dp9/Vision and dp11/Hulk all read `PORT_UP=True` at 25G
> from hardware. Evidence: `research/ibspg_hold_response/evidence/GATE_12_2_LOAD_AND_CONFIG.md`.
>
> **► SWITCH STATE NOW: `ibspg_hold_response` (Part 12) LOADED AND CONFIGURED, ready for gate 12.3.**
> Rollback to Part 11 is one command: `sudo bash /home/decps/part11/launch_part11.sh`. Build + conf +
> launcher live in `/home/decps/part12/`. Reset regs/counters between trials with the Part 11 setup
> script and the Part 12 name lists (both in the evidence file).
>
> **★ GATES 12.3–12.8 = PASS ON SILICON (2026-07-25).** Full detail:
> `research/ibspg_hold_response/IBSPG_HOLD_RESPONSE_RESULT.md`. Headline: **the deadline release
> normalizes the ACK→response interval to within ~1.7 µs of the target, with 23 ns of spread across
> G = 1…40 ms** — roughly 3 orders of magnitude tighter than the recirculation-hold it replaces
> (which was ms-scale and calibration-sensitive), and calibration-free (nothing tuned per G).
> - **12.3 control (K=0):** response passes through in 2.10 ms — without a blocker ring nothing holds
>   it. This is what makes the hold results meaningful.
> - **12.4 hold without a deadline:** 128.0 M blocker passes, no release, then fail-open.
> - **12.5 deadline release (G=20 ms):** observed **20.0017 ms**, all 64 blockers deadline-terminated
>   (`tdl=64, ttmo=0, tstale=0`). Cross-checked independently on the Vision host clock: **19.990 ms**.
> - **12.6 sweep {1,2,5,10,17,25,40} ms:** error **1721–1744 ns**, constant across a 40× range with
>   nothing tuned per point. 17/25 ms (SEL-751 native CLRT p95/p99) hit as precisely as every other.
>   **WORDING CORRECTED 2026-07-25:** this offset was earlier called "one loopback RTT" — **withdrawn**;
>   the measured single-token dp8 loop RTT is ≈408 ns, so ≈1.72 µs is ≈4.2× a traversal and cannot be
>   one. Supported wording = "the programmed deadline plus a stable ≈1.72 µs **release tail**",
>   decomposed as c1 (deadline→first blocker termination) **14.4 ns mean** + c2 (termination→egress)
>   **1720.1 ns mean, sd 1.14**. c2's internal composition is NOT instrumented ([OPEN]).
> - **12.7 negatives:** stale-generation and unrelated-slot ACKs are forwarded but arm nothing
>   (`aarm=0, abyp=1, tdl=0`) → the response falls through to fail-open instead of releasing at G.
>   Only a qualifying ACK sets the release time.
> - **12.8 byte-identity + isolation:** 11/11 verifier checks. **Two independent isolation proofs**:
>   zero `0x88c1` frames in the Vision capture (the filter was widened to admit them and a
>   `b3_no_blocker_escape` check added BEFORE any trial — otherwise the absence would have been a
>   filter artifact), and **dp11 `FramesTransmittedOK = 0`** for the Hulk port that cannot be captured
>   on (it is the inject interface). dp8 loopback `TX = RX = 411,276,249` — blocker circulation is
>   entirely internal.
> - **Fail-open fingerprint (expected, not an anomaly):** the first blocker to exhaust its pass budget
>   clears `reg_active`, so the remaining K−1 terminate as *stale* → `ttmo=1, tstale=63`.
>
> - **★ 12.9 CAMPAIGNS = PASS: 200/200 across TWO campaigns.** Campaign A fixed G=20 ms (n=100);
>   campaign B randomized G over all 8 targets (n=100, **campaign exit code 0**, 03:29:45.94Z →
>   03:41:01.59Z, 100 unique ids, 0 duplicates, 0 missing, 0 non-zero trial rc). Both: 100% released by
>   deadline, 100% on-chip deadline arithmetic verified, 0 escapes, 0 premature releases, 0 failures.
>   Error A mean 1734.53 sd 7.34 · B mean 1733.99 sd 8.38 — indistinguishable. **Per-G breakdown shows
>   NO target-specific behaviour** (medians 1728–1739 ns, sd 7–9 ns, from G=1 ms to 40 ms, interleaved).
>   Port accounting: dp9 TX=423 ≈ 2 frames/trial over 209 trials; dp11 TX=0; dp8 TX=RX=908,070,328.
> - (campaign A detail) **100/100 reps at G=20 ms.** Every rep released by the DEADLINE
>   (`tdl=64` ×100; `ttmo=0` and `tstale=0` ×100 — the fail-open path was never entered, so the
>   campaign measures the mechanism, not its safety net). ACK-before-response 100/100 on the wire and
>   on-chip. Deadline error **mean 1734.5 ns, sd 7.3 ns, min 1720 / p95 1745 / max 1747 — total spread
>   27 ns across 100 consecutive transactions.** Release tail 1717–1723 ns. Log:
>   `research/ibspg_hold_response/evidence/part12/rep_campaign_100/reps12.log`.
>
> **⇒ PART 12 IS COMPLETE — all gates 12.1–12.9 PASS. Report:
> `research/ibspg_hold_response/IBSPG_HOLD_RESPONSE_RESULT.md` (26 sections, evidence-tagged).
> Part 12 HEAD = `f00a5fd`.**
>
> **► SWITCH RESTORED to `queue_microbench_abs.conf`** (NOT Part 11, per `direction.md`): bf_switchd
> PID 185496, exactly one instance, bfrt confirms `Binding with p4_name queue_microbench successful`.
> Cleanup verified first (no generator/tcpdump/bfrt client/campaign process anywhere). Hosts reachable:
> switch 10.10.54.81, Vision 10.10.54.19 (retains 192.168.10.1 on eno1), Hulk 10.10.54.158.
>
> **► PART 13 STARTED — clean worktree `/home/philip/Projects/DNP3-part13`, branch
> `research/ibspg-dnp3-replay-integration`, created from `f00a5fd`.** Replay-first; NO physical SEL, NO
> DNP3 writes/control. Staged gates 13.1–13.9 per the directive.
>
> **★ Gate 13.1 = PASS (offline, independently verified)** — `research/ibspg_dnp3_replay/`
> (`GATE_13_1_CORPUS_AUDIT.md`, `corpus_audit.json`, `audit_corpus.py`, `dnp3_pcap.py`), commit
> `029c8de`. Facts Part 13 must build on: **every capture holds TWO DNP3 TCP streams** (the named
> device + a common `10.0.0.2` endpoint); only **READ(1) / DIRECT_OPERATE(5) / RESPONSE(129)** occur
> anywhere (no CONFIRM, no unsolicited, no SBO); **SEL751/10.0.0.1 is separate-ACK with CLRT median
> 12.898 ms** (matches the documented ~12.9 ms) and is the right corpus for the first HOLD_ACK /
> HOLD_RESPONSE gates; AB1400/10.0.0.12 and ION7550/10.0.0.11 are combined. **Two unanticipated
> findings: ION7550 uses DNP3 link address 100, NOT the lab-stated 10**, and ION7550L/10.0.0.11 shows
> req→ACK median 43.3 ms / CLRT 28.75 ms, off every other stream. Verified by me rather than taken on
> the agent's word (it was stopped mid-run): re-running the script reproduces `corpus_audit.json`
> byte-identically, and an independent tshark pipeline reproduces CLRT median 12.898 ms and 299
> separate-ACK transactions exactly.
>
> **★ Part 13 pre-work — stage audit (commit `82a30ab`), a MEASURED NEGATIVE that changes planning:**
> the "drop `reg_ts_first_block` to reclaim a stage" lever recorded in the Part 11/12 notes **buys
> ZERO stages** (a variant with it fully removed still compiles to 12/12). The program is
> **serial-dependency-bound**, not resource-bound: 12 stages, exactly ONE table each, 0 TCAM. The only
> real headroom is the **parser (2 ingress states used)** ⇒ Gate 13.2 should push DNP3 role
> classification into the PARSER so the MAU sees a pre-computed role byte like today's synthetic
> `hdr.ib.role`, and keep ONE fixed slot through 13.7 to defer the flow_id hash + slot-lookup table.
> **Binding constraint for 13.2: the Part 12 program already fits at 12/12 stages with ZERO spare**, so
> DNP3 parsing must be paid for out of non-load-bearing telemetry (reclaim lever: `reg_ts_first_block`),
> never out of fail-open, generation safety, token isolation, or parser validation.
>
> **TIMING WORDING (locked):** "the programmed deadline plus a stable ≈1.72 µs **release tail**".
> Never "one loopback RTT" — the measured single-token dp8 loop RTT is 408 ns.
>
> (superseded phrasing below retained) The next gate is **DNP3 integration**
> (replay first, then the physical SEL — and note `direction.md` requires stopping before any SEL
> involvement): drive the HOLD_RESPONSE branch with real DNP3 ACK + response frames instead of
> synthetic role markers, using the parser-hardened classifier, exact admitted-flow→slot mapping,
> generation, expected-ACK and DNP3 application sequence from
> `research/unified_queue_release/UNIFIED_TRANSACTION_STATE_MACHINE.md`.
>
> **Harness:** `research/ibspg_hold_response/harness/{ibspg_p12_gen,ibspg_p12_read,ibspg_p12_verify}.py`
> + `part12_trial.sh` (env-parameterized: `K G_MS SCENARIO RESP_DELAY_MS RUNID`, `DRYRUN=1` prints the
> remote commands without executing). One trial:
> `K=64 G_MS=20 SCENARIO=normal RUNID=x bash part12_trial.sh` → one `RESULT ...` line. The Part 11
> control plane `research/ibspg_paired/control/ibspg_paired_setup.py` is reused **as-is** (it is
> name-parameterized) — do not fork it. Authorization basis for proceeding:
> `research/unified_queue_release/direction.md` (autonomous through bounded synthetic silicon
> experiments; stop only for physical intervention, destructive risk, management-connectivity risk,
> firmware/OS changes, or SEL involvement).
>
> **Repo hygiene note (unrelated to Part 12, needs Philip's call):** the working tree carries **15
> uncommitted deletions** of root documents (`acj_delay2.md`, `corrective.md`, `test_cases.md`,
> `when_how.md`, `PAPER_OUTLINE.md`, `ASSUMPTIONS_AND_UNKNOWNS.md`, `CROb.md`, `week8*.md`, the two
> Week pptx files, the original task prompt, the overnight reports) plus an uncommitted
> `--response-readiness-ms` feature in `dnp3_split_harness/split_server.py` from the 2026-07-20 C3 work.
> No copies exist elsewhere on disk; all are recoverable from git (`git restore <path>`). Nothing was
> restored or committed — deliberate cleanup vs accident is Philip's call.
>
> ---

> **►►►►►► RESUME HERE — 2026-07-25 (IBSPG in-network timing-normalization line). This is the ACTIVE
> work; it supersedes the 2026-07-23 block below for the CURRENT line. (The 2026-07-23 threads —
> queue size-normalization, physical SEL-751 — remain valid separate background, not the active task.)**
>
> ## WHERE WE ARE: Parts 9 (controlled drain) + 11 (paired ACK-before-response) are COMPLETE & PASS on Tofino-1.
> **Active branch `research/ibspg-paired`, HEAD `3d5222e`.** The IBSPG (Internal-Blocker Strict-Priority
> Gate) mechanism holds a DNP3 packet queue-resident in a low-priority TM queue, starved by a high-priority
> recirculating "blocker" reservoir, and releases it on a deliberate data-plane event — all on-switch,
> inline, byte-preserving, no controller in the fast path.
>
> ### The load-bearing findings (silicon-proven)
> 1. **Root cause of the original IBSPG failure = `max_priority` was never set** (only inert `min_priority`).
>    FIX: set `max_priority` (the remaining-bandwidth strict field). Proven Part 3. [research/ibspg-root-cause-repair]
> 2. **The hold needs a blocker RESERVOIR, K≥64 — NOT a single token.** A single blocker leaks the held
>    packets in ~540 ns; K=1/8/18/32 leak, K≥64 hold (0 leak). This CORRECTS the earlier Part-8 "K=1
>    suffices" claim (that was a too-short test on the shallower oracle). Required depth scales with the
>    program's pipeline+loopback in-flight time.
> 3. **Part 9 controlled drain WORKS** (all gates + 100/100 reps): a slot+generation-guarded DRAIN packet
>    terminates the blocker and releases the held packets **byte-identically + FIFO to an external host**;
>    unrelated/stale-gen drains do NOT release; budget-expiry is a separate fail-open watchdog; the blocker
>    never egresses to a host. Drain-recognition ~15 ns, end-to-end ~1.7 µs (≈ one loopback RTT).
> 4. **Part 11 paired ACK-before-response WORKS** (all gates + 100/100 reps, both injection orders): a held
>    ACK is released before its held response, **structurally** via three strict-priority levels on dp8
>    (Q_BLOCK qid7 max_priority 7 > Q_ACK qid5 pri 3 > Q_RESP qid1 pri 0). Holds even when the response is
>    injected FIRST; collapses to interleave when the ACK/RESP priority gap is removed (causal control).
>    ACK→RESP strict-priority handoff ~25–58 ns.
>
> ### SWITCH STATE — **KEEP LOADED** (Philip: "keep the switch on for the next phases")
> Switch `10.10.54.81` (user `decps`, creds in `~/.lab_env` as `$SSHPASS`) is running **`ibspg_paired`**
> (`bf_switchd` on `/home/decps/part11/part11_abs.conf`, ASIC attached). **Do NOT restore the microbench**
> unless asked. If a restore is ever needed: `sudo pkill -x bf_switchd; sudo bash /home/decps/queue_microbench/launch_mb.sh`
> → `queue_microbench_abs.conf`. The 3-level TM priority is currently CONFIGURED (Q_BLOCK 7 > Q_ACK 3 > Q_RESP 0).
>
> ### LAB TOPOLOGY (CORRECTED — this was a costly error earlier, do not re-confuse)
> - **dp9 ↔ Vision** (master, `10.10.54.19`, NIC `enp59s0f0np0` MAC `3c:fd:fe:cc:5d:c0`). Released frames
>   egress dp9, so **capture released frames on VISION**, not Hulk.
> - **dp11 ↔ Hulk** (outstation, `10.10.54.158`, NIC `enp59s0f0np0`). **Inject from Hulk** (lands on dp11).
> - **dp8** = internal MAC-near loopback (the hold/blocker queues live here; qid7 Q_BLOCK, qid5 Q_ACK, qid1 Q_RESP/Q_HOLD).
> - SDE on switch: `/home/decps/Downloads/bf-sde-9.13.2`. Local bf-p4c: `/home/philip/bf-sde-9.13.1`.
>
> ### LAB GOTCHAS (each cost real time — obey them)
> - **AF_PACKET raw inject needs `sudo`** (silent `PermissionError` otherwise → 0 frames, looks like a dead link).
> - **i40e source-pruning** drops reflected frames whose src MAC the NIC transmitted → inject held frames with
>   a **neutral src** (`02:00:00:00:00:0a`) and the **real dest NIC MAC** as dst (Vision `3c:fd:fe:cc:5d:c0`).
>   (`ethtool --set-priv-flags <if> disable-source-pruning on` bounces the link — prefer the neutral-src route.)
> - **Injected frames are deterministic → reconstruct them in the verifier (`--held-spec`/`--paired-spec`)**;
>   do NOT run tcpdump on the inject interface concurrently (it conflicts and drops the inject).
> - **MID priority "3" programs fine** on `tf1.tm.queue.sched_cfg` `max_priority` (HIGH reads back as "7").
> - Counters need a `SyncCounters`/from_hw read; ns timestamp registers wrap at 2^32 (~4.29 s).
>
> ### HARNESS & HOW TO RUN
> - Part 9 (controlled drain): `research/ibspg_controlled_drain/` — `p4/ibspg_controlled_drain/ibspg_controlled_drain.p4`
>   (SHA `3632264f`), `control/ibspg_part9_setup.py`, `harness/{ibspg_part9_gen,ibspg_part9_read,ibspg_part9_verify}.py`,
>   `harness/part9_trial.sh`. Result: `IBSPG_CONTROLLED_DRAIN_RESULT.md`. Staged on switch `~/part9/`, Hulk `~/ibspg_part9_gen.py`.
> - Part 11 (paired): `research/ibspg_paired/` — `p4/ibspg_paired/ibspg_paired.p4` (SHA `9feae154`, 12/12 stages),
>   `control/ibspg_paired_setup.py`, `harness/{ibspg_paired_gen,ibspg_paired_read,ibspg_paired_verify}.py`,
>   `harness/part11_trial.sh`, plan `PART11_PAIRED_ACK_BEFORE_RESPONSE_PLAN.md`, result `IBSPG_PAIRED_RESULT.md`.
>   Staged on switch `~/part11/`, Hulk `~/ibspg_paired_gen.py`.
> - **Run one paired trial** (env-parameterized, from `research/ibspg_paired/harness/`):
>   `K=64 NACK=4 NRESP=28 DRAIN=match HOLD_MS=700 INJORDER=ack-first RUNID=t1 bash part11_trial.sh` →
>   a `RESULT ...` line (`verify=PASS abr=true` = ordered byte-identical release). `DRAIN` ∈ match|unrel|stale|none.
> - **Configure the 3-level priority** (on switch, after a reload): `python3 ~/part11/ibspg_paired_setup.py
>   --prog ibspg_paired --config --paired --qb 7 --qa 5 --qh 1 --ack-pri 3 --host-ports 9,11` → expect
>   `strict_priority_verified: true`. Reset counters/regs between trials with `--reset --regs ... --counters ...`.
> - **Reload the program** (if switch was restarted): `sudo bash /home/decps/part11/launch_part11.sh`.
>
> ### NEXT STEPS (gated on Philip — do not start unprompted) — NEXT GATE IS PART 12, not 13
> - **Part 12 — HOLD_RESPONSE branch (NEXT).** Distinct from Part 11: here the **ACK is forwarded
>   immediately** (record `t_ack_tick`), **only the RESPONSE is held** queue-resident, and it is released on
>   a **data-plane DEADLINE** `deadline_tick = t_ack + G` — NOT an external DRAIN packet. This is the
>   Defense-2 / CLRT-interval-NORMALIZATION mechanism: observed CLRT = release − t_ack = G (fixed, regardless
>   of the device's native CLRT), which is the actual Formby-CLRT-defeating goal; Part 11's ordering is its
>   substrate. Mechanism: the recirculating blocker becomes **deadline-checking** — each loop compares `now`
>   (ingress_mac_tstamp) vs `deadline_tick` and self-terminates when `now >= deadline` → strict priority then
>   serves Q_RESPONSE_HOLD → response released. "established-before-admit, release on deadline", TEST_ONLY
>   synthetic timing (NOT real DNP3 yet). Authoritative spec:
>   `research/unified_queue_release/UNIFIED_TRANSACTION_STATE_MACHINE.md` (HOLD_RESPONSE branch) +
>   `research/ibspg_root_cause_repair/IBSPG_POST_FIX_EXPERIMENT_PLAN.md` P12. New P4 vs ibspg_paired:
>   add BYPASS for the ACK + a `t_ack_tick`/`deadline_tick` register pair + a deadline compare in the blocker
>   loop (watch the 12/12 stage budget — counter-trim lever available). Gate style mirrors Parts 9/11
>   (compile → deadline-accuracy sweep of G → negatives → byte-id host-PCAP → reps → isolation).
> - **Part 13 — DNP3 integration** (replay first, then physical SEL): drive HOLD_RESPONSE/paired with real
>   DNP3 ACK+response frames instead of synthetic markers.
> - Optional: counter-attribution refinement (drain currently counts `1 controlled + K−1 stale` cascade — cosmetic);
>   reservoir-depth-vs-pipeline-depth characterization (why K≥64 here vs K=1 on the 4-stage oracle).
> - Memory notes: `ibspg-controlled-drain-part9.md` (+ MEMORY.md index). Frozen Part 1–8 files & the ring
>   oracle & `ibspg_controlled_drain.p4` must not be modified; new parts get new files/branches.
>
> ---
>
> > **►►►► RESUME HERE — 2026-07-23 CLOSE (older threads: size-normalization + physical SEL; background, not active).**
> ORIGINAL 2026-07-23 BLOCK BELOW (still valid for those separate threads):

> **►►►► RESUME HERE — 2026-07-23 CLOSE. Supersedes ALL blocks below (incl. the 2026-07-22 block:
> its "build the v1.1 size-pattern builder" task is DONE and the full HW experiment already ran).**
>
> **Branch `research/caseA-ditto-queue`, HEAD `c9e5788`. Two threads, both at a clean stop.**
>
> **THREAD A — Queue Level-1 SIZE normalization: PASS on Tofino-1 (DONE, committed, tagged).**
> `queue_microbench_trace_v1.p4` padded every trace frame to ONE 128 B state on silicon: 3 reproducible
> telemetry-ON runs (150 frames each), 0 loss / 0 reorder, all outputs 128 B, size MI 0.909→0.000 bits;
> A/B (telemetry OFF) confirms the digest is measurement-only. **Scope:** Level-1 *declared*
> `input_size_class` (NOT live DNP3), size channel only, 3-flow corpus. Commits `fae72cb`
> (dataplane+harness), `43b3ed0` (HW run+evidence), `6f33eb4` (figure); **tag `queue-trace-level1-hw-pass`**.
> Reports: `research/tofino_dcrn_feasibility/p4/queue_microbench/autonomous_run_20260722/`
> (HARDWARE_RESULT.md, MORNING_EXECUTIVE_SUMMARY.md, FINAL_STATE.md, HARDWARE_RESULT_figure.html).
> **Switch RESTORED to the queue-microbench baseline** (`launch_mb.sh` → `queue_microbench_abs.conf`;
> cover/metronome/telemetry OFF, verified). Frozen `dcrn_defense1/2` + telemetry copies UNTOUCHED.
> Analyzer 32-bit ingress_tstamp-wrap bug fixed + regression test; 20/20 harness tests pass.
> `next_phase_allowed=false` — Level-2 live-DNP3 classify / corpus expansion / joint size+time are GATED.
>
> **THREAD B — Physical SEL-751 Phase-5 connectivity: REACHABLE but DNP3 SESSION REFUSED (committed `c9e5788`).**
> Relay is physically on the **unmanaged TP-Link TL-SG1024S** lab switch (Tofino NOT inline, per meeting
> Phase 5). Vision = master. REACHABLE: relay **192.168.10.7/24**, MAC `00:30:A7:02:4C:A2` (Schweitzer),
> ping 0% loss, **TCP:20000 handshake completes**; DNP3 addrs from `Traffic Trace/SEL751.pcap` = outstation
> **10**, master **1**. **BLOCKER:** relay accepts the TCP handshake then **closes it itself** (relay-initiated
> FIN, median 1.9 ms, n=427) with **zero DNP3 bytes exchanged** → 0 measurements decoded. Not a network
> fault; likely **DNP3 not enabled on the port / master-IP allowlist / single session already held** —
> resolvable only from the relay config (AcSELerator/console; **QuickSet NOT installed**). Address 10 never
> reached the DNP3 layer, so it is NOT implicated. Report+evidence: `research/physical_sel751/`
> (SEL751_DIRECT_CONNECTIVITY_REPORT.md, evidence/native_class0.pcap, pinned-safe `native_class0_probe.py`,
> SEL751_CONNECTION_TOPOLOGY.html). **Vision temp IP `192.168.10.100/24` LEFT ON eno1** for a one-shot retry
> (remove on request). **DISCLOSED deviation:** the probe used opendnp3's DEFAULT channel retry →
> reconnected ~55/s for ~8 s (434 sessions), exceeding "one TCP session" — but ZERO DNP3/control/write bytes
> were ever sent (0x0564 = 0 both ways). **Any retry MUST use a no-retry single-connect transport.**
>
> **NEXT TASK (Thread B):** obtain the relay's DNP3 settings — is a DNP3 session enabled on this port, is
> there an allowed-master-IP restriction, is a session already open. If a master IP is required, set Vision
> to it; then retry ONCE with a no-retry single-connect probe. Do NOT re-probe before that (avoid TCP churn),
> do NOT guess DNP3 addresses, do NOT put the Tofino inline (gated). Detail in the report's §Next steps.
>
> ---
> **◀ SUPERSEDED — the 2026-07-22 block below is HISTORICAL (its v1.1-builder task is complete) ▶**
>
> **►►►► RESUME HERE — 2026-07-22 CLOSE / 2026-07-23 PICKUP. Supersedes ALL blocks below.**
>
> **NEXT TASK when you resume: build the DNP3 size-pattern builder v1.1 (OFF-SWITCH ONLY). Do NOT
> compile, load, or modify the switch or P4. Do NOT touch Defense 1/2 sources.** Full v1.1 spec is in
> the "▼ V1.1 DIRECTION" block at the bottom of this checkpoint — execute those 13 corrections + the
> test regressions, then STOP.
>
> **STATE AT CLOSE (2026-07-22).** Branch `research/caseA-ditto-queue`, HEAD `e7e7223`.
> - **Track 1 (telemetry copies of the FROZEN Case-A defenses) — DONE off-switch, NOT loaded.** Both
>   frozen defenses have verified non-invasive learning-digest copies (release predicates byte-identical;
>   measurement-only; `(run_id, flow_id, txn_ack=tcp.ack_no)` correlation):
>   - `dcrn_defense1_telem.p4` — off-switch bf-p4c 9.13.1 PASS, **12/12 stages**; `E_D1 = ack_rel −
>     resp_evt` (event-governed). Rollback tag `d1-telem-v1-verified`=`8077c40`; v2 (txn_ack added +
>     redundant `reg_resp_tick` dropped) = `a769dee`. Review: `.../ack_delay/DEFENSE1_TELEMETRY_REVIEW.md`.
>   - `dcrn_defense2_telem.p4` — off-switch 9.13.1 PASS **10/12 stages**; **on-switch bf-p4c 9.13.2
>     compile-parity PASS** (10/12, identical MAU totals; staged at switch `/home/decps/dcrn_m1/
>     build_ackB_telem_9132`, **NOT loaded**). `E_D2 = release_tick − deadline_tick` (deadline-governed;
>     release_tick = egress-refreshed `bridge.tstamp_tick`). Tag `d2-telem-v1-verified`=`49c1b0b`.
>     Review: `.../ack_delay/DEFENSE2_TELEMETRY_REVIEW.md`. **Terminology:** `FAIL_OPEN_MAXPASS` + negative
>     `E_D2` = **`PREDEADLINE_MAXPASS`, cause UNRESOLVED** (insufficient MAX_PASS / non-refreshing clock /
>     deadline too far / tstamp wrap / stale deadline — do NOT call it "stuck clock").
>   - Deep audit + housekeeping earlier: `.../queue_microbench/DEEP_CODE_AND_RESULTS_AUDIT.md`.
>   - **The Defense 2 SWITCH LOAD + A/B harness was STOPPED per instruction** (not built). If ever
>     resumed it needs a telem control-plane driver + a D2 digest collector + a TCP-DNP3 traffic/AB
>     runner (none exist).
> - **Size-pattern builder v1 — COMMITTED `e7e7223`**, `research/tofino_dcrn_feasibility/p4/queue_microbench/
>   size_pattern_builder/`. Off-switch, trace-grounded. Deliverables: `extract_inventory.py`,
>   `generate_candidates.py`, `evaluate_candidates.py`, `test_pattern_builder.py` (6 pass),
>   `packet_inventory.{csv,json}`, `queue_pattern_candidates/{maxonly,quant2,quant3}.json`,
>   `evaluation.json`, `SIZE_PATTERN_BUILDER_REPORT.md`; `queue_microbench_setup.py --pattern-json`
>   dry-run added; `size_pattern_builder_v1.zip` (review copy, untracked). **v1 findings:** SEL-751 roles
>   cross-check the Zeek `dnp3.log` exactly; separate-ACK (SEL 304 pure-ACKs) vs combined (AB1400/ION7550
>   3–4) confirmed; empirical wire ≤127 B; real traffic = READ + DIRECT_OPERATE only (no SBO). `maxonly`
>   (single 127 B state) recommended but **NOT approved** — user found v1 has "blocking analysis defects"
>   → **v1.1 required first (spec below).**
> - **SWITCH left UNTOUCHED:** `bf_switchd` on `/home/decps/queue_microbench/out/queue_microbench_abs.conf`
>   (queue microbench, **cover=OFF, metronome=OFF, telemetry_enable=0**, loaded p4 sha `0239af8f58d8a014`,
>   bin `fbddefa750827ebf`); gc-switchd masked+inactive. **Restore target for ANY future temporary
>   displacement = the queue microbench (NOT `decoy_paper3`)** — the queue impl is the current priority.
>
> ---
> **▼ V1.1 DIRECTION (execute off-switch on resume; do NOT modify P4/switch). Regenerate inventory/
> candidates/evaluation, tests, and the corrected report. STOP after.**
> The builder is directionally correct; v1 has blocking analysis defects. Required corrections:
> 1. Add `flow` to the transaction-shape grouping key: `(device, capture_id, flow, transaction_id)`.
> 2. Preserve packet order by timestamp + capture index. Do NOT sort all non-response packets ahead of
>    responses (v1's `txn_shapes` sort is the bug).
> 3. Classify a pure ACK ONLY when payload length is 0 AND ACK=1 with SYN=FIN=RST=0. Record TCP flags,
>    seq, ack_no, IP header length, TCP header length, capture index, retransmission status, connection
>    phase.
> 4. Determine `ack_mode_observed` PER TRANSACTION: `separate` | `combined` | `ambiguous` | `incomplete`.
>    Do NOT hard-code ACK mode from device name.
> 5. Replace `wire_size` with explicit metrics: (a) captured L2 bytes excl. FCS; (b) Ethernet frame bytes
>    excl. FCS with minimum-frame handling; (c) frame bytes incl. FCS; (d) wire occupancy incl. preamble+IFG.
> 6. Correct the rounding implementation; add `single128_corpus_baseline = [128]` LABELLED a baseline for
>    the current 3-PCAP corpus, NOT the final deployment pattern.
> 7. Rebuild TRANSACTION_WINDOW schedules SEPARATELY for: separate-ACK READ; combined-ACK READ;
>    separate-ACK direct-operate; combined-ACK direct-operate; synthetic SBO (clearly labelled synthetic).
>    A common schedule MUST explicitly add the missing outstation-ACK slot for combined-ACK transactions
>    when ACK-mode hiding is claimed.
> 8. Compute cover-OFF padding overhead from ACTUAL packets in each flow-separated transaction, reported
>    master→outstation and outstation→master SEPARATELY. Do NOT multiply mean packet padding by the 6-slot
>    window (v1's `pad_per_txn` bug).
> 9. Replace `log2(#states)` as the PRIMARY leakage result with MEASURED: mutual information (mapped size ↔
>    device); MI (mapped size ↔ operation); balanced classification accuracy with grouped CV by flow or
>    capture. Keep `log2(k)` only as a labelled theoretical upper bound.
> 10. Run ranking SENSITIVITY over several leakage weights (not the arbitrary weight 20).
> 11. Expand corpus inventory OR create explicit SCOPES: 3-device base fingerprint corpus; long captures;
>     multi-CROB/control corpus; large Class-0/multi-segment corpus; synthetic SBO only where real SBO absent.
> 12. Correct the report's P4 blocker: changing ONE fixed padding-header width CANNOT map variable 54–127 B
>     packets to one common size. Document real options: per-length fixed pad actions; two-edge outer
>     encapsulation; off-ASIC gateway/DPU.
> 13. Fix deliverable file integrity: `evaluate_candidates.py` must be Python source; each candidate
>     filename must match its internal `candidate_id`.
> **Re-run tests with explicit regressions for:** two flows same txn id; post-response ACK ordering;
> SYN/FIN/RST exclusion; separate vs combined ACK transactions; retransmission dedup; 127→128 mapping;
> per-direction overhead.
> ---
>
> **►► (earlier 2026-07-22 TM-microbench checkpoint — retained as context below).**
>
> **Direction (Dr. Lin, `meeting_direction.md` + `meeting.md`): a queue/Ditto scheduler INSTEAD of
> recirculation, for Case A / SEL-751; write the paper LAST.** Branch `research/caseA-ditto-queue`
> (pushed to origin). Roadmap: `PLAN.md`. Memory: `memory/dnp3-joint-size-time-architecture.md`.
>
> **LOCKED joint size-and-time architecture** (`CASE_A_QUEUE_DESIGN.md`): the "pattern" is the ordered
> **SIZE-state list `P=[S0..S(L-1)]`**; **timing = the scheduler's interval τ / rate R** (NOT a
> timing-valued pattern). Padding maps small packets (ACK/request/CROB/Select/Operate/confirmation) to
> states; splitting maps selected large responses to a size-state sequence (on-switch splitting INFEASIBLE
> → pace pre-split); size-labelled TM queues + scheduler enforce order+timing together. CROB/SBO in scope
> (common schedule + chaff). Claim = joint size/seg/timing obfuscation, NOT volume independence (needs
> chaff). Timing target NOT locked (SEL-751 native CLRT p95 17.2 / p99 25.1 ms are candidates —
> `QUEUE_PATTERN_FROM_TRACES.md`, reframed as timing-behaviour not "the pattern").
>
> **★ PHASE 4 TM MICROBENCH — BUILT + RUN ON LIVE TOFINO-1 (2026-07-22, switch+Hulk, Vision OFF, no
> SmartNIC).** In `research/tofino_dcrn_feasibility/p4/queue_microbench/`. On-switch bf-p4c **9.13.2: 0
> err, 6/12 ingress stages** (= local 9.13.1 parity). dp9 hairpin (Vision down); dp9 pg-map READ from the
> switch = **pg_id=2, pg_port_nr=1**. **RESULT (`.../queue_microbench/runs/RESULTS_switchside.txt` +
> pcaps):** the locked TM **max-rate (UPPER) PPS shaper is a rate CAP, not a pacer** — a sparse flow
> (input < R, our ~5 Hz case) passes through with NO cadence; a backlogged flow CLUMPS into ~4.4 s bursts
> (median dequeue 0) below ~R≈600 pps, smooth only ≥600. The **pktgen metronome** (τ=10 ms) makes a steady
> 100 pps ±1 from zero input (works, but is NOT the TM scheduler). **⇒ the max-rate shaper alone cannot
> clock a sparse ~5 Hz DNP3 flow.**
>
> **★★ MIN-RATE + DWRR RUN ON LIVE TOFINO-1 (2026-07-22, switch + Hulk, Vision OFF) — COMPLETES the locked
> TM-scheduler sweep. RESULT: neither min-rate/guaranteed-rate NOR DWRR can pace a sparse flow directly;
> the "round-robin could pace cheaply without chaff" idea is REFUTED on silicon.** Ground truth = switch-side
> dp9 MAC counters (`mb_sample.py`), not host pcaps. Evidence: `.../queue_microbench/runs/RESULTS_minrate_dwrr.txt`
> + 5 `mb_*.txt` per-second sampler logs. Measured:
> - **min-rate R=100 backlog:** median DEQ=0, ~441-frame clump every ~4 s (mean ~105) — IDENTICAL to the
>   max-rate shaper at 100. **R=600 backlog:** smooth ~660 pps — IDENTICAL to max-rate at 600. **R=600 SPARSE
>   (input ~50 pps):** DEQ=50=input, depth 0 — NO up-pacing to 600. The floor is a floor-on-BACKLOG, not a
>   metronome.
> - **DWRR sparse (50 pps):** DEQ=50 passthrough, no cadence. **DWRR backlog both real queues (no cap):** S1
>   drains ~77k pps (≈½ input), depth 0 — DWRR only splits competing NON-EMPTY queues by weight (~50/50 here)
>   and drains at ~line rate; NO absolute pacing.
> - So for a ~5 Hz DNP3 cadence the ONLY sparse-flow clock remains **(1) the pktgen/recirc METRONOME**
>   (proven: ~100 pps ±1 from zero input) or **(2) Ditto-style CHAFF-FILL** keeping queues backlogged
>   ≥~600 pps (high overhead). Matches GridCloak `exp_tm_floor.py` (PPS floor starves <~1200 pps w/o chaff).
> - **Setup code (this session):** `queue_microbench_setup.py` gained `--mech minrate` + `--mech dwrr`
>   (control-plane only, NO P4 recompile — datapath identical whenever mech_reg != MECH_PKTGEN,
>   `queue_microbench.p4:546-553`). bfrt idioms VERIFIED from GridCloak (min-rate `exp_tm_floor.py:77-93`,
>   DWRR `legacy/gc_dwrr_setup.py`). **Procedure fix found on silicon:** per-queue `entry_mod` does NOT clear
>   prior fields → the first DWRR backlog was silently capped by the leftover min-rate R=600; fixed so
>   `--mech dwrr` writes `min_rate_enable=False`+`max_rate_enable=False` (confirmed cleared, re-ran clean).
>
> **★★ ICS DESIGN CORRECTIONS APPLIED (2026-07-22, Philip review) — code + report + design doc aligned.**
> Philip's review (ICS/SCADA + Ditto-style, non-negotiable points) is now implemented and documented:
> - **Internal clock vs external cover separated in the P4.** An idle `MB_METRO` tick NO LONGER
>   auto-becomes external chaff — it is consumed INTERNALLY by default (transmit nothing). Added a
>   `cover_mode` register (OFF default / WINDOW / CONTINUOUS) + `window_active`; the idle-tick path emits
>   one external cover packet ONLY in CONTINUOUS or WINDOW+window_active. Added `ctr_cover` (external
>   cover) + corrected `ctr_tick` (idle tick consumed internally). Local bf-p4c 9.13.1: **0 err, 7/12
>   ingress stages** (up from 6; two new register reads), 1.37 MB binary, p4 sha e65b352f.
> - **Setup:** `--cover-mode {off,window,continuous}` (default off) + `--window-active`; seeds
>   cover_mode/window_active; **mandatory strict-priority READBACK that ABORTS on mismatch when cover is
>   armed** (no silent fallback). py_compile + dry-run all modes PASS.
> - **★ Recirc = HOLD, not chaff; metronome GATED to cover modes (design decision 2026-07-22).** Recirc
>   is the packet-delay primitive (needed in every mode; TM can't hold a sparse frame). The pktgen
>   metronome + slot-grid is a CHAFF construct (defines fillable empty slots). So: **cover=OFF (default)
>   = recirc-hold to event/absolute-deadline = the frozen `dcrn_defense1/2` mechanism, NO metronome, NO
>   grid;** cover=WINDOW/CONTINUOUS = metronome+grid activates. Unifies the two lines (dcrn deadline-hold
>   = default pacer; queue metronome = chaff-mode pacer). Folded into `CASE_A_QUEUE_DESIGN.md` §0.10 +
>   report §0.5.3a + §16.5 step 2a. **CODE REFACTOR DONE + VERIFIED ON SILICON (2026-07-22):** cover=OFF
>   holds reals to an absolute DEADLINE (pass-count `SEQ_HELD_DL` carried in the packet, dcrn_defense2
>   mechanism, no metronome/tokens/per-flow-reg); metronome armed only when cover != OFF. bf-p4c 9.13.1 +
>   on-switch 9.13.2: 0 err, **7/12 stages (no increase)**, p4 sha e5b19477. Silicon smoke (cover=off):
>   40 reals → ctr_encap=40 ctr_grad=40 (held+released via deadline), ctr_cover=0 ctr_tick=0 (zero
>   external filler, metronome off), no stuck frames. Calibration finding: dp68 HOLD cap
>   (HOLD_LOOP_PPS=100000) PACES the loop → pass latency = 1e6/HOLD_LOOP_PPS = 10 us/pass (not raw ~1 us);
>   hold_passes = hold_ms*1000/10 → 1700 for 17 ms (`--hold-ms`/`--pass-latency-us` knobs).
> - **RECIRC-CLOCK AUDIT DONE (`runs/AUDIT_recirc_clock.md`) — RESOLVED both anomalies; my earlier
>   "~3.17 ms ceiling" was WRONG.** Added `ctr_recirc` (P4 counter per deadline-hold pass; sha 6e2265ff,
>   7 stages). **Issue 1 RESOLVED — NO pass ceiling:** deterministic single-frame sweep shows passes =
>   hold_passes EXACTLY (1000→1000 … 40000→40000, released via hold_passes==0). The "~4096/3.17 ms
>   plateau" was a BURST-PCAP ARTIFACT (overlapping long holds mispaired the tx↔rx match). Clean isolated
>   dumps: 30000→135.5 ms, 40000→236.7 ms. ⇒ the deadline SCALES; 17–25–40 ms reachable WITHOUT the DCRN
>   fix. **Issue 2 RESOLVED (mechanism):** the HOLD cap throttles AFTER the 16384-pass burst credit
>   (~0.65 µs/pass sub-burst → ~10 µs/pass at cap). **SWITCH-SIDE TIMER built + validated (point 3):**
>   added `mb.t_in` (ingress global_tstamp at encap) + `last_hold_reg` (hold_ns=now−t_in at release);
>   deterministic, host-independent; AGREES with clean hairpin (30k→137 vs 135.5, 40k→234 vs 236.7).
>   p4 sha bdca672e, 7 stages. Reader harness/last_hold.py. **TRANSITION CHARACTERIZED:** pre-burst
>   **0.617 µs/pass linear**, **breakpoint EXACTLY 16384 passes** (=max_burst_size, 10.11 ms), post-burst
>   ramps to **~9.7 µs/pass** (the cap), baseline ~0. **ISOLATED TARGET SWEEP (point 5, switch-side, 6
>   samples, all deadline-released grad+6, ZERO fail-open):** 5 ms→**5.000±0.000**, 10 ms→**9.999±0.000**
>   (pre-burst EXACT, zero jitter); 17 ms→19.67±1.44, 25 ms→23.25±1.22, 40 ms→36.94±0.45 (post-burst
>   jittery + calibration-sensitive — CLRT 17–25 ms lives in the steep region; a lower burst credit would
>   make it precise). DCRN fix STILL NOT applied. **NEXT: concurrent-held + background-load sweeps**
>   (point 5 cont / 7). Case A semantics unchanged (D1 event / D2 refreshing-timestamp; pass-count =
>   retention microbench + fail-open bound). Switch cover=off @ 2 ms; decoy DISPLACED (no longer needed).
>   Tools: hold_probe.py, mb_read.py (ctr_recirc), dp68_rx.py, last_hold.py; runs/AUDIT_recirc_clock.md.
> - **Architecture renamed:** the pacer is the **pktgen-driven size-state slot scheduler**, NOT the TM
>   scheduler (TM does not pace a sparse flow). Docs updated: `QUEUE_MICROBENCH_IMPLEMENTATION_REPORT.md`
>   §0.5 (authoritative corrections), `CASE_A_QUEUE_DESIGN.md` §0 (ICS refinements). Scope corrected to
>   "joint size+timing for transmitted packets," NOT yet "READ vs SBO indistinguishable" (needs
>   direction-aware canonical schedule + cover). Overhead computed per link class (154 kbps/dir @10 ms).
>   Padding plan = two-edge encrypted outer encapsulation (inner packet preserved), NOT TCP seq
>   translation (now an alt study). Splitting only on the hybrid path, not Tofino-only physical.
>   Gates before physical/TCP: enforce ACK-ordering, flow-aware state, fine-grained (sub-slot) timing.
>
> **SWITCH STATE now: MICROBENCH LOADED — experiment takes priority over decoy_paper3 (Philip
> 2026-07-22, reversed the earlier restore).** The UPDATED cover-mode `queue_microbench.p4` (sha
> e65b352f) was recompiled on-switch (bf-p4c 9.13.2: 0 err, **7/12 ingress stages**, cover_mode in
> bfrt) and loaded: `bf_switchd` PID 2434541, tmux `mb`, conf `out/queue_microbench_abs.conf`
> (model_json_path removed — recompile didn't regen aug_model.json; optional on HW), launcher
> `launch_mb.sh`. Setup verified on silicon (cover=OFF default): ports/pktgen/queues up, mech_reg=0,
> cover_mode=0, window_active=0, pat_state installed. **Strict-priority enum RESOLVED on silicon**
> (`min_priority` HIGH reads `'7'`, cover `LOW`; REAL=HIGH>cover verified) — the mandatory readback
> passes, and **cover arms only when priority verifies** (demonstrated: `--cover-mode continuous`→
> cover_mode=2; bad priority→abort). Left in safe **cover=off**. decoy_paper3 DISPLACED (files intact,
> restore = `launch_gf_v2b.sh`); gc-switchd masked; Hulk clean.
>
> **►► NEXT (Philip's call, all off-switch first):** the mechanism is settled (pktgen metronome is the
> pacer). Recommended order (report §14 + §0.5): (1) re-run the timing test in cover=OFF to confirm zero
> external filler when idle + measure INTERNAL recirc overhead (dp68 pps, passes/real); (2) compute the
> SIZE pattern `P` from the six captures (Q-P, off-switch); (3) two-edge outer-encapsulation prototype
> (Tofino + Vision sanitizer); (4) joint `(P, τ, cover_mode, window)` optimize; (5) bounded
> transaction-window cover; (6) continuous cover only as an optional comparison. Each switch step gated.
>
> **SWITCH STATE (persists until switch reboot / tmux death):** chip runs the **microbench** — `bf_switchd`
> in tmux session `mb`, conf `/home/decps/queue_microbench/out/queue_microbench_abs.conf`, shaper left at
> R=600. **`dcrn_ackB` + the `decoy_paper3` launcher were KILLED** (Philip: "kill all those and run it");
> **gc-switchd masked+inactive**. **decoy_paper3 is DISPLACED — restoring it is Philip's call.** Resume on
> the switch: if `bf_switchd` died, recompile on-switch (`/home/decps/Downloads/bf-sde-9.13.2/install/bin/
> bf-p4c --target tofino --arch tna -g -o out queue_microbench.p4`, set SDE_INSTALL/LD_LIBRARY_PATH),
> rewrite the abs-path conf, relaunch `bf_switchd` in tmux (passwordless sudo), then
> `python3.8 queue_microbench_setup.py --mode final --mech shaper|dwrr --rate-pps <R>`. Access: switch
> `decps@10.10.54.15` (key ssh, **passwordless sudo**); Hulk `decps@10.10.54.158` (`sshpass -e`, first
> `source ~/.lab_env`; Hulk sudo needs the piped pw). **Bash needs `dangerouslyDisableSandbox` for
> ssh/scp.**
>
> ---
>
> **►► PRIOR POSITION (2026-07-21) — recirc baseline + Case B design; superseded above for the queue line.**

> **►►► CURRENT POSITION (2026-07-21) — supersedes ALL blocks below.**
>
> **LOCKED taxonomy (Philip, 2026-07-21) — memory `memory/dnp3-clrt-case-taxonomy.md`:**
> **Case A = SEPARATE-ACK** device (SEL-751 `10.0.0.1`, has CLRT) → **two defenses, both PROVEN ON
> TOFINO SILICON** (SDE 9.13.2, single-host Hulk loopback rig, Vision off): **Defense 1 = hold the ACK**
> (`dcrn_defense1.p4`; CLRT 17→~0.026 ms; event-governed) and **Defense 2 = hold the response**
> (`dcrn_defense2.p4`; CLRT→~107 ms device-independent constant; deadline-governed). **Case B = COMBINED-ACK**
> devices (AB1400 `10.0.0.12`, ION7550 `10.0.0.11` — ACK piggybacked, no separate ACK, CLRT undefined,
> currently BYPASSED, NO defense built). File map: ackA=Defense 1, ackB=Defense 2.
>
> **Both defenses confirmed RUN on the switch:** Defense 1 = `evidence/continuous_campaign_PASS/RESULT.md`
> (120 txns, CLRT const ~0.026 ms, byte-identical 120/120) + `evidence/formby_eval/RESULT.md` (AUROC
> 1.00→0.57, ID 0.99→0.00); Defense 2 = `evidence/defense2_hardware/RESULT.md` (99 txns, CLRT ~107 ms
> device-indep, 99/99). `phase_status.json` = both PASS_MEASURED_ON_TOFINO. (NB: defense2_hardware
> b_dev1/b_dev2 are SEPARATE-ACK profiles dev1=SEL/17 ms + dev2=35 ms, NOT AB/ION.) Single-host loopback
> replay, not a live device on the testbed.
>
> **Deliverables this session (in `research/tofino_dcrn_feasibility/p4/ack_delay/`):** (1) Weekly slide
> deck for Dr. Lin — 13 slides, Artifact `https://claude.ai/code/artifact/4afcb05a-c1b3-4f84-8a18-a69d67...`
> (see `evidence/visualization/dnp3_slides_meeting.html`), relabeled to Defense 1/2 + Case A/B.
> (2) `ACK_DELAY_TECHNICAL_REPORT.md` (software eBPF/EDT+timing_policy → Tofino, real code).
> (3) `../netronome_vision_onbox_inspection.md` — Netronome **Agilio CX 2×40G (NFP-4000)** confirmed on
> Vision, live 10 G DAC to Hulk (192.168.100.1↔.2); HW can host the full harness but on-NIC hold needs the
> Agilio P4C SDK (absent). (4) Real-device figures + pcaps under `evidence/visualization/` &
> `evidence/pcap_clean/` (SEL Defense-1 gap/hold + Defense-2 before/after/zoom; clean single-txn pcaps).
> (5) Artifact bundle `evidence/dnp3_ack_delay_artifacts_2026-07-21.zip`. Figure generators
> `render_*.py`.
>
> **CASE B (combined-ACK) DEFENSE DESIGN STUDY = DONE (2026-07-21, 5-agent), DESIGN ONLY.** Doc
> `case_b_defense_design.md`; memory `memory/case-b-combined-defense-design.md`. A Case-B defense is NOT a
> CLRT defense → composes **B-E5** (request-anchored response-hold, byte-preserving) + **B-SIZE**
> (size-normalization, byte-modifying — size is the DOMINANT residual, ION 61 B) + **B-MODE** (homogenize
> toward combined). Co-residency: timing+ACK-drop fit one Tofino; size→DPU/Vision-host; Netronome hosts
> all 3 once SDK acquired. New safety limit: holding a combined response also holds the request-ACK →
> ceiling = request-RTO ~207 ms, fail-open on request retransmit. **FAKE-ACK (Philip asked): REJECTED for
> live path** (all 4 experts) — byte-generating, wrong direction (make-all-combined wins), creates a CLRT
> from nothing + a synthetic-ACK detector, and spoofs an IED (CIP-008/007, IEC-62443). Eval: **P-pair
> AB-vs-ION (chance 0.5) is the acid test**; two-number pre-registration.
>
> **next_phase_allowed=false — nothing touched the switch this session (all design + figures).**
> RECOMMENDED NEXT (gated, Philip's call): the **offline AB-vs-ION byte-transform smoke test**
> (unprivileged, no switch/P4) — does closing timing+size drive the two combined devices to coin-flip.
>
> ---
>
> **►► CURRENT POSITION (2026-07-20) supersedes the 2026-07-17 block below.** Phase 04B DCRN is
> PASS on the two-host rig; Philip authorized moving DCRN **onto the Tofino switch**, code was written
> (`research/tofino_dcrn_feasibility/p4/dcrn.p4` + `dcrn_setup.py`), and the local `bf-p4c 9.13.1`
> compile-fit loop reached **M1 PASS (2026-07-20): 0 errors, fits 9/12 ingress stages**; both genuine
> compile unknowns (17-deep dependency chain; runtime-operand `check_deadline` SALU predicate) resolved.
> Full detail + honest 9-vs-~7-stage deviation: repo-root `WORKING_NOTES.md` "Current focus" section +
> `research/tofino_dcrn_feasibility/p4/M1_local_compile_result.md`. **GATED / NOT done:** on-switch SDE
> 9.13.2 compile + `make install`, dp8<->dp9 byte-identical wire forwarding, all of M2+ — the switch step
> needs Philip's explicit go/no-go. The "3 decisions are Philip's" block below is partly stale
> (decision #1 build-on-switch already taken).

## ►► RESUME HERE (current position, 2026-07-17)

**Branch `research/ack-timing-phased`** (63+ commits ahead of `main`, NOT merged; backed up to
GitHub `akekulip/DNP3_obf`). **Working tree clean, 61 tests pass.** Governing plan `acj_delay2.md`
(strict phase-gated; `next_phase_allowed=false` until PI authorizes). Also read
`dnp3_split_harness/WORKING_NOTES.md`.

**Phased chain:** 00 PASS · 01 PASS · 02 **PASS** · 03A **PASS** (human gate 13/13) · 04
**CONDITIONAL PASS** (consolidated closeout) · 05 (ACK-mode normalization) **PASS (with scoped
limitations)** · 04B (DCRN dual-case timing normalizer) **PASS_MEASURED** (two-host rig, kernel 6.8,
2026-07-18; PI authorized advance, `next_phase_allowed=true`).

**►► TOFINO / P4 FEASIBILITY STUDY = DONE (2026-07-18).** Report:
`research/tofino_dcrn_feasibility/tofino_dcrn_feasibility_report.md` (synthesized from 3 parallel agents:
p4-dataplane-engineer / sdn-networks-expert / principal-investigator; raw contributions in that dir's
`agent_contributions/`). **VERDICT: realize DCRN's ms-scale timing hold at the EDGE, not on the
Tofino-1 ASIC.** The two DCRN release constructs — `skb->tstamp` (EDT) + `fq` — have NO TNA equivalent;
everything DCRN does before release (arm t0, classify pure-ACK vs combined, per-flow state, deadline
math, fail-open) maps directly. The on-switch **recirculation-hold (option B) is FEASIBLE-WITH-CONSTRAINTS
but UNBUILT and DNP3-rate-bound** — affordable only because ~1 s poll spacing is 20–60× the ~42 ms hold;
the deciding ceiling is **traffic RATE, not any chip resource** (recirc ≈0.4–1.5 Gbps ≪ ~1.6 Tbps
budget; 42 ms ≪ ~150 ms RTO cap). Pure on-switch rate-shaping is **ruled out** (a shaper delays only on
existing backlog → a lone response at an idle queue leaves immediately, and a size-coupled delay
re-injects the size fingerprint). Recommended split: **edge hold** (host qdisc-EDT where we own the
outstation; inline SmartNIC/DPU where we don't) + **Tofino = classify/telemetry/policy distribution**.
SOTA: NetWarden (Tofino, but hold in software slowpath + synthesizes ACKs) and ditto (line-rate but
pads+chaffs) both corroborate that the ms-hold is off the ASIC datapath — DCRN's novelty is the
**byte-preserving, no-synthesis** dual-case absolute-deadline normalizer + the edge-bound feasibility
result. Size + ACK-mode residuals unchanged (out of scope).

**►► NEXT = 3 DECISIONS ARE PHILIP'S (all GATED — nothing compiled, no P4 written):** (1) headline
framing — edge-bound-hold + switch-classify/telemetry (defensible today, security/grid venue) vs. the
on-switch recirc-hold (more novel, P4/systems venue, riskier); (2) **authorize a COMPILE-ONLY Stage-1 P4
probe** (classify+arm, NO hold built) to upgrade "likely feasible" to a `bf-p4c` resource report — needs
explicit go/no-go per the plan's final gate; (3) device-**family** external validity needs additional
physical devices (separate data line). Do NOT start the P4 probe unprompted.
Teaching report for the whole of 04B: `dnp3_split_harness/reports/dnp3_phase04b_dcrn_report.html`.

**Headline result:** egress *timing* scheduling normalizes WHEN packets leave but cannot conceal the
**ACK mode** or **response size**. Socket-side coalescing (own the socket) safely normalizes the ACK
mode (wire-demonstrated, byte-identical, no drops); with the eBPF EDT timing primitive it drives
joint device fingerprinting to the size-only floor (balanced acc 0.856 → ~0.50). **Size is the last
residual** (out of the byte-preserving scope).

**►► NEWEST WORK — Phase 04B (DCRN dual-case timing normalizer), 2026-07-17, commit `c607c5a`.**
`corrective.md` governs. DCRN = tc ingress(arm request + class-independent target) + egress(classify
separate pure-ACK vs combined ACK-bearing response → skb EDT) + `fq`; normalizes the visible timing of
**both** native structures below TCP, so it can't change the ACK mode. Wire-proven earlier (Gate A/B).
**Gate C full paired local campaign PASS** (`scripts/phase04b_local_campaign.sh`, veth, capture on the
client-side observer): NATIVE req→resp median **16.66 ms** → DCRN_FIXED **32.61 ms** (std 0.17) →
DCRN_COMMON_BOUNDED **37.54 ms** in [32.44, 42.61]; separate ACK→resp gap **18.14 → 0.18/0.20 ms**;
transport clean (0 retrans/reset/dup-ack), byte-identical. Attacker eval (measured, chance 0.333):
timing balanced-acc **0.720→0.639→0.436**, mode_only + size unchanged 0.667, all=1.0 — DCRN is a
timing normalizer, preserves ACK mode + size by design. 98 tests pass; conformance 43/0. Evidence in
`reports/phases/phase_04b_dual_case_timing/{gate_c_local_campaign.md,campaign_local/}`.
**Pre-rig audit (2026-07-17, commit `07b633d`)** — 7-point audit PASS with a named residual: the FIXED
0.19 ms guard delta is a device-correlated scheduler error (p=0.0002); BOUNDED closes pure timing to
chance, FIXED does not → **use BOUNDED, not FIXED**. Per-profile, 0 ordering/deadline violations,
feature purity clean, 100-split CV with CIs. See `pre_rig_audit.md`.

**★ TWO-HOST VISION/HULK RIG = PASS (measured on hardware, 2026-07-18, commit `1c6c0c3`).** DCRN on
Hulk eno1, capture on Vision eno1, kernel 6.8, RUNS=5 (5/5 ok/cond). Timing req→resp median NATIVE
16.81 → DCRN_FIXED 32.73 → DCRN_COMMON_BOUNDED 37.81 ms (mirrors loopback). Transport clean (0
retrans/reset/ordering/deadline). Attacker pure-timing CV: NATIVE 0.731 → FIXED 0.740 [0.642,0.839]
→ BOUNDED 0.289 [0.177,0.401]. **Rig confirms: the FIXED guard residual survives real-path jitter;
BOUNDED closes the timing channel; mode+size persist (out of scope). USE BOUNDED.** Required a libbpf
port (rig tc is libbpf 1.3, rejects the legacy object) — Gate A rig verifier-accepted (`5aae33c`).
See `two_host_rig_results.md`. `next_phase_allowed=false` (Tofino/size-padding need PI authorization).

**Immediate next actions — ALL GATED (need explicit PI go-ahead):**
- ~~Consolidate Phase 05 into a formal CONDITIONAL_PASS closeout~~ — **DONE 2026-07-17**.
- ~~Per-device defended-wire classifier eval~~ — **DONE on loopback + TWO-HOST RIG 2026-07-17**
  (`phase05_defended_wire_eval.py` loopback + `phase05_rig_defended_wire.py`/`phase05_rig_replay.py`
  rig; `defended_wire_eval.md` + `rig_defended_wire_eval.md`; joint RF loopback 1.000→0.767→0.700, rig
  1.000→0.756→0.681; SEL↔AB1400 collapse, ION7550 stays size-identified → size is the confirmed
  residual; 2160/2160 byte-identical, 0 retrans/reset in both). PHYSICAL three-device eval still deferred.
**Phase 05 is CLOSED (PASS with scoped limitations).** Deferred / separate lines (NOT Phase 05
blockers; each needs explicit PI authorization to start — `next_phase_allowed=false`):
1. **PHYSICAL three-device eval** (real SEL-751/AB1400/ION7550 hardware — NOT on this rig) — external
   validation that removes the reproduction caveat.
2. **Tofino/P4** drop path for real-inline / uncontrolled sockets → `p4-dataplane-engineer`.
3. Separate **size-padding** line (the confirmed dominant residual).
4. Housekeeping (on request): merge to `main`; refresh GitHub backup.

**Run gotchas:** capture → `sg wireshark`; tc/netem → `unshare -rn`; **BPF load → PI `sudo` only**
(`unprivileged_bpf_disabled=2`, no non-sudo path). No sudo for other execution. Forward commits only
(amend guard-blocked); commits in Philip's name only.

---

## ★ SESSION 2026-07-16 (latest): Phase 03A ACK-separation MEASURED (capture unblocked) — STOP for human review
Branch `research/ack-timing-phased`. Capture is no longer blocked: `philip` was added to the
`wireshark` group, so all packet capture runs under **`sg wireshark -c '...'`** (a group switch,
**not** sudo — do not use sudo for experiment execution). Phase 03A (socket-level ACK-separation
characterization, per `acj_delay2.md`) is now **CONDITIONAL PASS** from fresh loopback PCAPs
(results commit `5d4a6e7`, tooling `c13453c`):
- **Matrix** (7 configs, 875 txns): fixed25 / bounded20-30 keep the native **COMBINED** ACK for
  non-first requests (0/100 separate, Wilson95 [0,0.037]) — normalization introduces no separate ACK.
- **Delay sweep** (coarse 0–100 ms + **refined 1 ms** 35–40 ms): the separate-pure-ACK transition
  is **probabilistic**, not sharp — 0% ≤35 ms → 1.2/7.5/18.8/47.5% at 36/37/38/39 → 100% at 40 ms
  (50% near 39 ms). Separated regime = prompt pure ACK (~0.01 ms) then response at the delay.
- **0 retransmissions / dup-ACKs / resets; 100% byte-identical (2875/2875).**
- Deliverables under `dnp3_split_harness/reports/phases/phase_03/`: rewritten
  `phase_03_ack_separation.md` (22-pt template), `phase_status.json`, `tables/` (committed
  summaries + merged `phase03_delay_sweep.csv` + manifests), `figures/` (7 figs + metadata via new
  `phase03_figures.py`), `validation/` (human packet-validation worksheet — **reviewer verdicts
  BLANK by design; a human must complete it**, with the referenced pcaps). Phase 02 wire addendum
  updated: **PASS condition met by measurement**; formal flip deferred to the human packet review.
- **RQ3 socket-option factorial now CLOSED** (results commit `589257a`, run `20260716T145525Z`,
  600 txns, one factor at a time at 25/50 ms): **TCP_NODELAY on/off has NO effect** on ACK
  separation; **TCP_QUICKACK FORCES separation** — server-side quickack flips COMBINED→SEPARATE
  even at 25 ms (80/80 vs baseline 0/80), so the separate ACK is a delayed-ACK effect controllable
  from user space; **response size (17–2407 B) has no effect**. Added `fig08`,
  `phase03_socket_option_summary.csv`, `phase03_environment_dependence.csv`, and 2 RQ3 rows to the
  human worksheet. All plan-required Phase 03 outputs now produced.
- **PI GOVERNANCE VERDICT 2026-07-16 = CONDITIONAL PASS.** Three required follow-ups DONE (commit
  `3dfbeb0`): (1) **CRC-split decomposition** — `phase01_reconstruct.py` now emits `ack_mode`
  (COMBINED/SEPARATE/UNDETERMINED) + `response_delivery` (FULL/MULTI_SEGMENT/AMBIGUOUS); crc-split
  non-first = ack_mode COMBINED 100/100, delivery FULL 50 + MULTI_SEGMENT 50 (the 50 former OTHER
  rows resolved); legacy `classification` unchanged; +5 unit tests. (2) **3 wording corrections**
  (quick-ACK "state"; replay-client-exchange vs DNP3-task; response-size narrowed to 25/50 ms
  anchors).
- **INTEGRITY CORRECTION (2nd review):** the per-frame packet assessment of 6 cases was
  **AI-assisted (reviewer=ChatGPT), NOT a human inspection**. I had wrongly transcribed it as
  `reviewer=akekulip` — REVERTED. The **human packet-inspection gate is 0 of 13** (worksheet
  reviewer columns all blank). The AI-assisted checks are SUPPLEMENTARY only
  (`validation/phase03_ai_assisted_packet_analysis_2026-07-16.md`, `human_gate_credit: false`) and
  must NOT go in the reviewer column. A human must personally open each PCAP and sign all 13 rows.
- **QUICKACK CAPABILITY CORRECTION:** QUICKACK forces a prompt/separate ACK and can delay the
  RESPONSE (app scheduling), but does **NOT** hold/delay an already-generated ACK. Delaying an
  existing ACK needs tc/eBPF, inline bridge, DPDK, programmable NIC, P4/Tofino, or kernel mod. Do
  NOT call QUICKACK "the Phase 04 mechanism lever" — it is a feasibility input only.
- **WORKSHEET REGENERATED (3rd review, commit `32baac1`):** now uses ORTHOGONAL columns
  (`software_ack_mode` + `software_response_delivery` + `reviewer_ack_mode` +
  `reviewer_response_delivery` + `ack_mode_agreement` + `delivery_agreement` +
  `first_payload_frame`/`final_payload_frame`). Extractor gained `first_payload_frame` etc. The
  crc-split row is fixed: **COMBINED_ACK_RESPONSE / MULTI_SEGMENT, first_payload_frame=15** (old
  `resp_frame=39` was a LATER segment). All 13 software rows match the reviewer's AI-assisted table.
  `PHASE_03A_RESUME.md` marked **HISTORICAL — SUPERSEDED** (current authority =
  `reports/phases/phase_03/phase_03_ack_separation.md`). Phase 02 pydnp3 integration log VERIFIED
  real (6/6 task_completed) → reference kept.
- **★ PHASE 03A = PASS (2026-07-16, commit `7ba9d82`).** PI (Philip Akekudaga) personally inspected
  all 13 worksheet rows and confirmed agreement with the software on BOTH ack_mode and
  response_delivery (**13/13, 0 disagreements**, method=manual packet inspection). Worksheet reviewer
  columns filled; AI-assisted cross-check stays supplementary (`human_gate_credit=false`).
  **Phase 02 also flips CONDITIONAL PASS → PASS** per the documented single-gate policy (Phase 02
  depends on the same ACK-mode confirmation).
- **★ PHASE 04 FEASIBILITY ANALYSIS DONE (2026-07-16, commit `1f3f36d`) — implementation NOT started.**
  PI authorized "start phase 04"; per the plan, Phase 04 opens with the feasibility report BEFORE any
  implementation. Deliverable `dnp3_split_harness/reports/phases/phase_04/ack_control_feasibility.md`
  (+ `phase_status.json`) answers all 9 plan questions via a 2-expert analysis (sdn-networks-expert +
  power-systems-expert), lead-integrated + env-verified.
  - **Real mechanism identified:** eBPF on tc `clsact` egress + per-flow LRU map + **EDT**
    (`skb->tstamp` + `fq`) — holds a REAL pure ACK + response to independent departure times, forges
    nothing. Env-verified on this host: `sch_fq` present, `flower tcp_flags` supported, `bpf_timer`
    in kernel BTF, `skb->tstamp` in UAPI (`bpftool` NOT installed). Sequence: netem smoke test →
    eBPF host-local → re-host onto a 2-NIC transparent bridge.
  - **P4 split:** the classify+per-flow-register DECISION half ports to Tofino; the multi-ms
    scheduled ACK RELEASE does NOT (Tofino can't buffer for precise multi-ms delays; recirc
    infeasible; TM shaping is rate-based/coarse).
  - **Key risk/finding:** binding timer is TCP RTO (~211 ms), not DNP3 (seconds) → bounded holds
    (≤~40 ms) safe; invariant ack≤resp must degenerate to piggyback (never simultaneous
    pure-ACK+resp). Gap-magnitude normalization does NOT reduce ACK-mode fingerprinting
    (0.810→0.810) and can RAISE timing leakage (0.511→0.797); clean byte-preserving path = normalize
    toward SEPARATE by delaying the response past ~40 ms (kernel emits a natural ACK), ONLY where we
    own the socket; **size is the irreparable residual**.
  - **FLAGGED (needs separate fix):** `reports/ack_fingerprint_eval.md` prose says the timing family
    "collapses (0.511 to 0.797)" but that's an INCREASE (ARI −0.000→0.433 too) — prose contradicts
    its own tables.
- **★ PHASE 04 netem SMOKE TEST DONE + POSITIVE (2026-07-16, commit `2f39aff`).** PI authorized
  "the netem smoke test" (that step only). `phase04_netem_smoke.py` runs inside `unshare -rn`
  (user netns, **non-sudo**, isolated loopback — tc/netem needs CAP_NET_ADMIN and there's no
  wireshark-style group for it, so use `unshare -rn`, NOT sudo). Result: **tc/netem held the
  server's existing pure ACK independently of the response** — request→ACK 0.011→30.02 ms,
  ACK→response gap 50.45→20.31 ms (shrank), request→response ~50 ms unchanged; 40/40 held the
  ack<resp invariant; 0 retrans/reset; 100/100 byte-identical. Egress control point VALIDATED.
  Concretely reproduced the classifier fragility: a `tcp_flags` mask omitting PSH (`0x17`) wrongly
  delayed PSH+ACK responses → fixed to `0x1f`; confirms robust pure-ACK classification needs eBPF
  payload-length, not tc flags. Deliverables: `reports/phases/phase_04/netem_smoke_result.md` +
  `netem_smoke/` (pcaps + summary).
- **★ PHASE 04 REVIEW CORRECTIONS applied (2026-07-16, commit `c597acc`).** Reviewer verdicts:
  mechanism-feasibility = **CONDITIONAL PASS**, netem smoke = PASS, full eBPF impl = NOT approved.
  **MOST IMPORTANT CORRECTION — capability boundary:** independent ACK/response scheduling is
  possible ONLY when a separate ACK ALREADY EXISTS. Combined-mode devices (AB1400/ION7550) carry the
  ACK and DNP3 response in ONE packet → inline eBPF/Tofino can delay the combined packet only;
  **combined→separate normalization is IMPOSSIBLE without ACK synthesis / TCP splitting / owning the
  socket.** normalize-toward-COMBINED (suppress the existing separate ACK, rely on piggyback) is the
  only no-synthesis route for separate-mode devices (untested, has RTO/packet-count/fail-open risks).
  I had OVERSTATED this as "independent release of both" — corrected. Other fixes: architecture is
  tc INGRESS(record request state)+EGRESS(classify+EDT); EDT not behaviourally verified → minimal
  EDT load-and-release test required first; `bpf_timer` NOT for packet holding (EDT holds; timer only
  cleanup/watchdog); flag classification unsafe even at `0x1f` (prod = payload_len==0 & ACK &
  !SYN/RST/FIN); netem "0 resets" = within established sessions (10 RST/ACK per pcap are pre-connection
  probes); fingerprint result relabelled "trace-transformation evaluation" not defended-wire.
- **GATE:** `next_phase_allowed=false`. **eBPF PROTOTYPE NOT built / NOT authorized.** Prerequisites
  before impl authorization: (1) Phase 03A human gate — **CONFIRMED COMPLETE** (PI clarified
  2026-07-16 his earlier sign-off stands, 13/13; prerequisite satisfied); (2) minimal EDT
  load-and-release test — **✅ SATISFIED (PASS, PI-run 2026-07-16, commit `3e37eee`).** PI ran
  `sudo bash reports/phases/phase_04/edt_test/run_edt_test.sh`: a loaded tc-egress BPF program
  (`edt.o`, id 151, jited) set `skb->tstamp` and **fq enforced the 30 ms EDT** — ping RTT ~0.024 →
  ~60.069 ms. BPF-written tstamp honored like SO_TXTIME (no mono_delivery_time issue on 5.15).
  Enforcement half also corroborated non-sudo via SO_TXTIME. **The EDT release primitive is
  CONFIRMED on this host.** (Benign: old iproute2 rejected the `-g` debug `.BTF` section; program
  loaded fine — drop `-g` to silence.) NOTE: BPF loading needs real CAP_BPF here
  (`unprivileged_bpf_disabled=2`), so every BPF-load run is a privileged invocation or a one-time
  `setcap cap_bpf,cap_net_admin+ep` on a loader (capture/netem stay non-sudo via `sg wireshark` /
  `unshare -rn`).
  (3) scope = narrowed target (feasibility §8a). **ALL PREREQS MET; eBPF prototype AUTHORIZED + BUILT
  2026-07-16 (commit `577cb6b`).**
- **★ eBPF EDT PROTOTYPE = PASS (PI-run 2026-07-16, commit `97a842c`, run `20260716T231044Z`).**
  `reports/phases/phase_04/ebpf_prototype/` (`ack_edt.c` tc-egress BPF + `phase04_ebpf_prototype.py`
  driver + `run_prototype.sh` root wrapper). PI ran `sudo bash run_prototype.sh`: `ack_edt.o` loaded
  + **verifier-accepted** (id 152, jited), then **independently pinned the existing separate pure
  ACK and the DNP3 response to per-flow EDT targets** — request→ACK ~0.01→**20.047 ms**,
  request→response ~5→**40.355 ms**, gap→**20.001 ms**; 40/40 separate; 0 retrans/dup-ACK/reset;
  50/50 byte-identical. `fq` enforced the BPF-set tstamps; ack<resp invariant holds by construction;
  nothing forged/edited. **CORE PHASE 04 MECHANISM PROVEN** (independent, byte-preserving,
  synthesis-free ACK+response scheduling) for separate-mode flows. Details: `ebpf_prototype_result.md`.
- **★ ATTACKER EVAL DONE (2026-07-16, commit `88b9ece`) — eBPF EDT does NOT defeat the fingerprint.**
  `phase04_attacker_eval.py` (+ `ack_fingerprint_eval` `ebpf_edt` scenario, additive) → trace-transformation
  eval (native device traces transformed by the ebpf_edt model; NOT defended-wire).
  RF acc (chance 0.400): ack_only 0.810→**0.800**, timing 0.511→**0.401**(=chance), size 0.500→0.500,
  all 0.888→**0.900**. **The eBPF EDT closes the TIMING channel cleanly** (timing→chance, no
  re-encoding — unlike the flawed gap-only norm) **but does NOT defeat fingerprinting:** ack_only
  stays 0.800 (is_separate leaks; the 20/40ms targets even ADD a request→ACK tell → all edges UP to
  0.900), size 0.500 unchanged. Only `plus_ackmode` (hide the mode; NOT byte-preserving) collapses
  ack_only to 0.400. **Measured confirmation of the capability boundary:** a no-synthesis
  byte-preserving mechanism normalizes WHEN packets leave, not WHETHER a separate ACK exists or HOW
  LARGE the response is. Report: `reports/phases/phase_04/attacker_eval.md`.
- **★★ PHASE 04 CONSOLIDATED = CONDITIONAL PASS (closeout 2026-07-16, commit `d17dc0e`).** Closeout
  report `reports/phases/phase_04/phase_04_separate_ack_manipulation.md` (8-section). Components:
  core_mechanism PASS, netem_control_point PASS, ebpf_edt_timing_normalization PASS,
  attacker_evaluation PASS_WITH_CAPABILITY_BOUNDARY, ack_mode_normalization NOT_IMPLEMENTED,
  size_normalization OUT_OF_SCOPE, bridge_and_rig_validation DEFERRED. `next_phase_allowed=false`.
- **RIGOROUS ATTACKER EVAL (superseded the quick one):** `phase04_attacker_eval.py` now does
  capture-level split (leakage-free) + bootstrap 95% CI + repeated stratified 5×5 CV (optimistic band,
  caveated) + BALANCED ACCURACY + macro-F1 + per-device P/R + confusion + paired bootstrap; seed
  20260716; **baseline = majority-class 0.400 (uniform 0.333)**. Balanced acc native→ebpf_edt:
  ack_only 0.759→0.666, timing 0.482→**0.334**(baseline), size 0.500, all 0.856→**0.833**.
  **KEY: the aligned-target ablation (`ebpf_edt_aligned` ACK=resp=40ms) is IDENTICAL to ebpf_edt** →
  residual is the categorical ACK-mode + size channels, NOT the timing-target choice. The raw-acc
  'rise' 0.889→0.900 is a CLASS-IMBALANCE artifact (balanced acc FALLS). plus_ackmode = counterfactual
  ORACLE (not implemented); even it leaves all=0.500 (size leaks) → fingerprint does NOT collapse to
  baseline. **Result: egress scheduling removes timing leakage but cannot conceal transport-structure
  (ACK mode) + response-size fingerprints.**
- **TERMINOLOGY FIXED:** ACK suppression is **DNP3-payload-preserving but NOT packet-presence-preserving**
  (operation table in feasibility §3a); plus_ackmode is a counterfactual oracle.
- **★★ PHASE 05 ACK-MODE NORMALIZATION FEASIBILITY DONE (2026-07-16, commit `6a3bbad`) — implementation NOT started.**
  `reports/phases/phase_05_ack_mode_normalization/ack_mode_normalization_feasibility.md` (2-expert analysis
  + effectiveness eval). **EFFECTIVENESS (trace-transformation, balanced acc, baseline 0.400/0.333):**
  suppression closes the ACK-mode channel timing couldn't — ack_only 0.759→0.482 (mode only);
  **suppress+EDT reaches the size-only floor (all 0.856→0.501 ≈ oracle 0.500)**. Residual = response
  SIZE (out of scope, separate padding line). **Static TCP headers (TTL 64/win 29200/MSS 1460/wscale 7)
  IDENTICAL across the 3 devices** → p0f static fingerprinting doesn't distinguish them.
  **MECHANISM (key reconciliation):** the SAFE hold-then-decide design is **architecturally IMPOSSIBLE
  as a tc-egress DROP** (can't cancel a queued skb; the ACK egresses BEFORE the response). Only
  immediate predictive `TC_ACT_SHOT` is realizable inline — irreversible, proactive fail-open only,
  irreducible slow-txn residual. **BUT the safe behaviour IS realizable as SOCKET-SIDE COALESCING where
  we own the socket** (no quickack + response within the delayed-ACK window → kernel piggybacks the ACK;
  zero drops, perfect fail-safety, byte-preserving, NO BPF) — **already wire-demonstrated in Phase 03**
  (fixed25/bounded full stay COMBINED). Suppression DROP is **Tofino-NATIVE** (mark_to_drop; the inverse
  of the Tofino-hostile EDT hold). `bpf_timer` incompatible with the legacy loader → in-band disarm.
  Adds `ack_fingerprint_eval` suppress/suppress_edt scenarios.
- **★ SOCKET-COALESCING DEFENDED-WIRE DEMO = PASS (2026-07-16, commit `2a66344`).** `phase05_coalescing_demo.py`
  (sg wireshark, non-sudo, no BPF, no drops, no netns). On the ACTUAL wire: undefended (quickack) 80/80
  separate → defended (no quickack, response in delayed-ACK window) **0/80 separate**; **200/200
  byte-identical; 0 retrans/reset.** So socket coalescing normalizes the REQUEST ACK mode
  separate→combined on the wire, byte-preservingly, no drops. The 40 residual server pure-ACKs in the
  defended capture are handshake + CONFIRM-ACKs (NON-discriminating; `is_separate` keys on the
  request-ACK, which is normalized — matches the safety analysis). Validates the mechanism on the wire,
  anchoring the trace-transformation effectiveness (is_separate→0 is real). Evidence:
  `reports/phases/phase_05_ack_mode_normalization/coalescing_demo/`.
- **REMAINING (gated, `next_phase_allowed=false`):** per-device DEFENDED-WIRE classifier eval needs a
  multi-device RIG (the harness has one replay server = one "device"; deferred). Other open lines: the
  Tofino-native drop path for real-inline devices (needs `p4-dataplane-engineer`); the separate
  size-padding line (response size is the last residual, out of the byte-preserving scope). Each BPF-load
  run (if the inline-drop path is pursued) needs PI sudo (`unprivileged_bpf_disabled=2`).
- **PHASED CHAIN NOW:** Phase 02 PASS · Phase 03A PASS · Phase 04 CONDITIONAL PASS · Phase 05
  (ACK-mode normalization) **CONDITIONAL PASS** (consolidated closeout 2026-07-17). Branch
  `research/ack-timing-phased`, not merged to main.

## ★ SESSION 2026-07-17 (latest): Phase 05 CLOSED → PASS (with scoped limitations)
PI directed a rigorous closeout correction (senior-researcher/reproducibility audit). Executed:
- **Audit:** branch research/ack-timing-phased; response-segmentation audit = **720/720 selected
  responses SINGLE-SEGMENT** (0 multi-seg; first_segment==full_reconstruction; source_hash==replay_hash)
  → full-response-byte / response-size claims VALID (`response_reconstruction_audit.csv`). Response
  sizes: SEL 37-54B, AB1400 54B, ION7550 61B → ION distinct, SEL/AB share 54B (why SEL↔AB collapse, ION
  size-identified).
- **Feature decomposition** (`ack_fingerprint_eval.py`): old `ack_only` (mixed mode+timing) RENAMED
  `ack_combined` + split into `mode_only`(is_separate), `ack_timing`, `ack_combined`, `timing`, `size`,
  `all`. `mode_only` after coalescing = zero-variance constant → flagged `constant_non_discriminating`,
  reported as majority baseline (NOT a learned score). supervised() now records accuracy + balanced_acc
  + macro_f1 + per-family train variance + confusion + seed(0) + RF/LR params. Re-ran loopback (fresh)
  + re-analyzed the committed rig capture (--skip-run) with new families.
- **Central result (mode_only categorical ACK feature):** native 0.667 → coalesced **0.333
  (constant/non-discriminating)** on BOTH loopback and rig. Rig authoritative joint `all` 1.000→0.756→0.681;
  loopback 1.000→0.759→0.322 (coalesced_edt UNSTABLE on loopback = timing-norm jitter across the
  capture-level split; rig is authoritative). `size` 0.667 stable = **dominant stable residual**.
- **Reports:** rewrote `phase_05_ack_mode_normalization.md` as a 15-section authoritative closeout
  (PASS with scoped limitations); rewrote `defended_wire_eval.md` + `rig_defended_wire_eval.md` with new
  families + precise "two-host defended-wire replay ... using profiles derived from captured SEL-751/
  AB1400/ION7550 traffic" wording; `phase_status.json` → **status=PASS**, components per scoped spec,
  open_blockers=[], full provenance (run IDs, hashes, params, seed, split). Removed ALL stale
  "deferred/no-rig/no-NIC" contradictions.
- **Tests:** added `test_response_reconstruction.py` (single/multi-seg, dedup, order, boundary,
  byte-equality), `test_phase05_features.py` (families + mode_only constant handling),
  `test_phase05_status_schema.py` (fails on status/blocker/reason/stale-language contradictions). **73
  tests pass** (was 61). Forward commits only (evidence commit + closeout-metadata commit recording the
  evidence SHA). `next_phase_allowed=false` (human authorization to start Phase 06).

## ★ SESSION 2026-07-17: Phase 05 TWO-HOST RIG defended-wire eval — DONE, PASS (confirms loopback)
PI authorized "run the physical rig eval on the real devices." Premise correction surfaced + confirmed:
the physical SEL-751/AB1400/ION7550 are NOT on the reachable rig (Vision master ↔ Hulk replay
outstation; the devices are external 10.0.0.x captures). PI chose the **two-host rig-replay** eval:
Hulk replays each device's real bytes + ACK mode over the real 1G mgmt net, Vision drives the client,
capture on Hulk eno1 (non-sudo; decps in wireshark group). Built `phase05_rig_defended_wire.py`
(gambit orchestrator) + `phase05_rig_replay.py` (stdlib rig server/client). **Result (run
`20260717T162006Z_phase05_rig_defended_wire`, chance 0.333, 119 test txns/device):**
- **Wire integrity:** client **2160/2160 byte-identical**; SEL separate-ACK fraction **1.00→0.00**
  (coalesced); **0 retransmissions / 0 resets / 0 dup-ACKs** across 714 non-first txns × 3 conditions;
  18/18 streams mapped.
- **Classifier (RF):** joint `all` **1.000 → 0.756 (coalesced) → 0.681 (coalesced+timing)**; `ack_only`
  **0.751 → 0.524 → 0.317**; `size` **0.667 throughout**. SEL-751↔AB1400 collapse; ION7550 stays
  119/119 by SIZE → size is the confirmed residual. **CONFIRMS loopback** (loopback 1.000→0.767→0.700
  vs rig 1.000→0.756→0.681; size floor 0.667 both).
- **Honesty:** real-hardware reproduction of measured observables (real NICs/switch), NOT the physical
  devices; PHYSICAL three-device eval remains the only stronger, deferred check.
- **Bug fixed this session:** the orchestrator's server-start `ssh -f` hung under
  `subprocess.run(capture_output=True)` (backgrounded ssh holds the stdout pipe → no EOF); fixed to
  DEVNULL fds + timeout. Manual 8-txn test + the full run both PASS. RIG RUN GOTCHAS: start detached
  rig procs with `ssh -f` + DEVNULL (not captured pipes); never open a port-20000 connection while the
  server is at accept() (desyncs the session); capture non-sudo via the wireshark group on Vision/Hulk.
- Deliverables: `reports/phases/phase_05_ack_mode_normalization/rig_defended_wire_eval.{md,json}` +
  `defended_wire_rig/rig_capture.pcap` (sha256 89afba00…). `phase_status.json` component
  `two_host_rig_replay_defended_wire_eval = PASS`; closeout §14-G/§17/§22 updated. 61 tests still pass.
  `next_phase_allowed=false`.

## ★ SESSION 2026-07-17: Phase 05 PER-DEVICE DEFENDED-WIRE EVAL — DONE (loopback), PASS
PI authorized the defended-wire eval. Built `phase05_defended_wire_eval.py`: replays each real device's
(SEL-751/AB1400/ION7550, base+L) real request/response first-segment BYTES through a loopback replay
server under three wire conditions (native ACK mode / socket-coalesced / coalesced+timing), captures on
`lo` (`sg wireshark`, no sudo/BPF/netns/drops), re-characterizes with the existing extractor
(`characterize_ack_traces`), and classifies the DEFENDED captures with the existing capture-level-split
classifier (`ack_fingerprint_eval.supervised`). Reuses tested tooling; excludes the first txn/stream
(handshake quickack artifact). **Result (canonical run `20260717T142828Z_phase05_defended_wire`, chance
0.333, 119 test txns/device):**
- **Wire integrity:** SEL separate-ACK fraction **1.00→0.00** under coalescing; **byte-identical
  2160/2160**; **0 retransmissions / 0 resets / 0 dup-ACKs** across 714 non-first txns × 3 conditions.
- **Classifier (RF):** joint `all` **1.000 → 0.767 (coalesced) → 0.700 (coalesced+timing)**; `ack_only`
  **0.728 → 0.389 → 0.344**; `size` **0.667 throughout** (untouched). Confusion: coalescing removes
  SEL-751's separate-ACK tell → **SEL-751↔AB1400 collapse into mutual confusion**, while **ION7550 stays
  119/119 identified by response SIZE** in every condition → **SIZE is the confirmed residual** (out of
  the byte-preserving scope). This CONFIRMS the trace-transformation conclusion on real defended captures.
- **Honesty:** loopback reproduction of each device's MEASURED observables (real bytes/sizes, native ACK
  mode, native timing) through the real kernel TCP stack — NOT a physical 3-device capture; native
  all=1.000 reflects low-noise loopback; timing features carry ±~0.03 run-to-run jitter (categorical
  separate-ACK + size floor stable). PHYSICAL multi-device rig eval remains the stronger deferred check.
- Deliverables: `reports/phases/phase_05_ack_mode_normalization/defended_wire_eval.{md,json}` +
  `defended_wire/{SEL751_native,SEL751_coalesced,ION7550_coalesced}.pcap` (representative; full pcaps
  under git-ignored `runs/`). `phase_status.json` component `per_device_defended_wire_classifier_eval =
  PASS_LOOPBACK`; closeout §11/§14-F/§17/§19/§22 updated. 61 tests still pass. `next_phase_allowed=false`.

## ★ SESSION 2026-07-17: Phase 05 CONSOLIDATED → CONDITIONAL PASS (documentation of already-done work)
Consolidated the two committed Phase 05 sub-reports (feasibility `6a3bbad` + socket-coalescing wire
demo `2a66344`) into a formal closeout following the plan's 23-point phase-report template:
`reports/phases/phase_05_ack_mode_normalization/phase_05_ack_mode_normalization.md` (verdict
**CONDITIONAL PASS**) + rewrote `phase_status.json` to the closeout form (component matrix,
`supported_claims`/`unsupported_claims`, input SHA-256s, `run_ids`, `next_phase_allowed=false`).
No experiment re-run — this documents completed, already-committed work. Grounding verified this
session: `python3 -m pytest -q` → **61 passed**; six source device PCAPs + two demo captures hashed;
env gambit / Linux 5.15.0-139 / Python 3.8.10. **No new primitive built or run** — the one-primitive
gate is untouched; `next_phase_allowed=false` stands. Updated `WORKING_NOTES.md` + this file.

## ★ GIT STATE (2026-07-15): PUSHED to private GitHub backup — all primitives now committed
Repo at `~/Projects/DNP3` (branch `main`, tracking `origin`). **Backed up to the private repo
`https://github.com/akekulip/DNP3_obf`** (HEAD `00748b7`; `gh` authed as akekulip over HTTPS;
refresh the backup any time with `git push`). **Authorship rule (hard):** every commit/push is
in Philip's name ONLY — NO `Co-Authored-By: Claude`, `Claude-Session:`, or "Generated with
Claude" trailers; this overrides the harness default (see `docs/project-memory/no-claude-commit-attribution.md`).
The two pre-existing commits (`5acf404`, `761d919`) still carry old Claude trailers in their
bodies — user chose "push as-is" for the backup; their author is still akekulip. A clean-up
(strip trailers) needs a history rewrite + force-push, which the risk-guard blocks, so it is
user-run only if ever wanted.
**The size-padding line is now COMMITTED** (was previously held out): commit `e694ac8` adds
`dnp3_split_harness/run_outstation.py` (padding-capable outstation), `reports/pad_rig/`,
`pad_rig_results.md`, `reports/dnp3_timing_obfuscation_briefing.html`. **Important:** the
one-primitive-at-a-time GATE still governs BUILDING/RUNNING the *next* primitive — the push was
a backup, NOT a green light to advance. `.gitignore` keeps `.claude/` (rig sudo pw lives in
`.claude/logs/evidence.log`), `logs/`, `runs/`, and secrets out of git. A snapshot of the
project-memory notes is backed up under `docs/project-memory/` (no credentials; `<pw>` placeholder only).

## ★ SESSION 2026-07-15: ACK-delay before/after + ACK fingerprinting + educational tutorial; GitHub backup
Audited `ack_delay.md` (all §1–11 present; 22/22 tests pass; rig reports real — timing matrix
930 txns, ACK-separation 1808 txns @ 40 ms) and added three new deliverables in
`dnp3_split_harness/`:
- **Before/after on the real device traces** — `trace_before_after.py` →
  `reports/trace_before_after.{csv,json,md,png}`. Drives the *shipped* `timing_policy` over the
  REAL per-transaction native timings from the six PCAPs. Combined devices req→resp ~16 ms →
  fixed-25 / bounded[20,30]. SEL-751 ACK→response gap: native 12.2 ms → ack-delay 4.2 (shrinks),
  resp-delay 20.2 (grows), gap-normalized 20.0 (CV→0). Panel-3 is an ECDF (delta-safe).
- **ACK-based fingerprinting before/after** — `ack_fingerprint_eval.py` →
  `reports/ack_fingerprint_eval.{json,md}` + `ack_fingerprint_clusters.png`. sklearn RF/LR +
  KMeans/Agglomerative (ARI), capture-level split. **KEY RESULT:** gap-normalization does NOT
  defeat ACK fingerprinting — `ack_only` RF accuracy 0.810→0.810, cluster ARI 0.654→0.658 —
  because a separate ACK still *exists*; only the `plus_ackmode` what-if (also hide the ACK mode;
  NOT byte-preserving, NOT the shipped defense) drops it to chance 0.400 / ARI 0.000, and even
  then response SIZE still leaks (`all` 0.888 → 0.500).
- **Master report + educational tutorial** — `reports/ack_delay_master_report.md` (end-to-end,
  incl. the socket program and how the ACK is delayed for combined vs separate-ACK devices) and
  `reports/ack_delay_tutorial.html` (self-contained animated teaching page: plain-language primer
  §00, interactive 40 ms delay→ACK-mode slider, combined/separate ACK animations, tabbed code
  walkthrough, before/after toggle with the real numbers, both result PNGs embedded as base64,
  jargon hover tooltips wired to screen-reader `aria-describedby`). Verified via headless Chrome,
  JS clean, structure balanced.
- **NEXT (all gated on sign-off):** (a) byte-preserving size padding — built + rig-tested, now
  committed; (b) **ACK-mode normalization** (host-side ≥40 ms hold or P4 hold-and-release) to kill
  the ACK-mode fingerprint the eval exposed; (c) validation against physical SEL-751/AB1400/ION7550;
  (d) the P4/Tofino data-plane port.

## ★ SESSION 2026-07-15: SIZE-PADDING built + RIG-VALIDATED (HELD, uncommitted); briefing HTML extended

Built the size-padding primitive on the real OpenDNP3 outstation and ran it on the rig —
turns the previously-projected size defense into a rig-measured mechanism.

- **Code:** `run_outstation.py` gained `--pad-analog/--pad-binary/--pad-counter` (add real
  inert Class0 input points on top of function points). Also switched `configure_stack()`
  from `DatabaseSizes.AllTypes(db_size)` to **per-type `DatabaseSizes(...)`** — REQUIRED
  because AllTypes returned all db_size slots per type, so response size tracked db_size not
  the point counts and padding did nothing. Per-type → response = exactly the configured
  points; padding moves size precisely. Read-only, no control code, no byte forging.
- **Rig result (Hulk real outstation ↔ Vision master, tcpdump on eno1):** device A (40 pts)
  = 214 B; device B (80 pts) = 361 B; **device A + 40 padding pts = 361 B = byte-identical
  to B**, 80 pts decoded, 0 resets/0 retransmits/0 errors. Size channel normalized on real
  hardware. Report `dnp3_split_harness/reports/pad_rig_results.md`; pcaps in
  `reports/pad_rig/`. (device-ID 0.90→0.797 stays a trace-feature simulation — one rig ≠
  three devices; the sim reproduces the attacker eval exactly.)
- **Briefing HTML** (`reports/dnp3_timing_obfuscation_briefing.html`, artifact
  https://claude.ai/code/artifact/713c83e1-967b-4e31-a44e-ead0421606c6): added the
  rig size-normalization figure (Fig 13), a before/after **clustering** view of the
  fingerprint (Fig 14, devices separate→merge as channels close), the defense-stack chart,
  a plain-language code section, and moved the size-padding scorecard card to
  "mechanism validated · rig". Rebuilt/re-validated (JS render harness clean).
- **Gambit gotcha:** local `pkill`/`fuser` at the START of a Bash block signals the shell's
  own process group → exit 144 and the block aborts; and backgrounded pydnp3 outstations
  are flaky under the Bash tool. Do outstation runs on the RIG via ssh -f, not gambit.



## ★ SESSION 2026-07-14 (latest+): ack_delay.md Phase-2A ACK-SEPARATION — RIG-VALIDATED

With rig sudo now available, ran the deferred §5A socket-level ACK-separation probe on
Vision↔Hulk (probe server on Hulk :20051, measuring client on Vision, capture via
**server-side tcpdump on Hulk eno1** — the tool's own capture came back empty under
sudo-over-ssh, so used external tcpdump). Swept app-write delays 0–50 ms, 1808 txns.

- **Finding:** delaying the outstation's application write **induces a pure TCP ACK
  before the DNP3 response — no forging — with a sharp threshold at 40 ms** (the Linux
  delayed-ACK timeout, kernel 6.8). ≤38 ms → COMBINED (ACK piggybacks, sep-frac ≈0);
  40 ms → 0.93; ≥42 ms → 1.00. 0 resets. Raw-packet verified (delayed-ACK timer fires
  at ~40 ms, then quickack takes over for held bursts).
- **Consequence:** bounds Phase 1 — the 10–25 ms normalization targets stay in the
  combined regime (Formby CLRT gap stays ~0, no accidental separate-ACK signature);
  enables Phase-2 gap manipulation by holding ≥40 ms (natural separate ACK, no P4
  recirculation), at the cost of a ≥40 ms visible-time floor.
- **Report:** `dnp3_split_harness/reports/ack_separation_rig_results.md`. Artifacts:
  `reports/ack_separation_rig/` (2 pcaps + client matrix csv). Caveat: host/kernel
  behaviour on this stack + probe server (not a real device), not a protocol guarantee.

## ★ SESSION 2026-07-14 (latest): ack_delay.md Phase-1 RIG MATRIX — DONE, clean

Ran the deferred Vision↔Hulk rig matrix for the Phase-1 timing normalization (the
bar the loopback matrix pointed to). Deployed the current `dnp3_split_harness/` to
both rig hosts first (they only had the pre-split combined dir; no `timing_policy.py`).

- **Server-side matrix:** 7 configs × 30 integrity-poll reps = **930 timed
  transactions**. Real pydnp3 master (Vision) ↔ timing `split_server` (Hulk) over the
  1 G mgmt net. **0 deadline-miss, 0 bypass, 0 resets**, byte-preservation PASS on
  every response. Fixed mode pins visible request→response exactly: fixed-10 → 10.000,
  fixed-25 → 25.000 (median=p95=p99=max); bounded stays in-band; full and CRC-split
  identical. Master decoded ~808 measurements/batch, 120 `OnTaskComplete`/config.
- **Wire capture (sudo tcpdump on Hulk eno1, 3 configs × 20 reps):** 440 pkts each,
  **0 retransmit / 0 reset / 0 dup-ack / 0 out-of-order / 0 zero-window**. Wire
  req→resp: native 1.36 ms median; fixed-25 **25.36 ms, ±0.1 ms spread** (min 25.32,
  max 25.43); bounded 17.2 ms median. Confirms the 25 ms hold is safely below RTO.
- **Scope honesty:** the rig outstation is the *replay server*, so native times are
  replay-fast (~1 ms), NOT real-device ~16 ms. This validates mechanism + safety +
  byte-preservation + TCP health on real hardware; device size/timing-leak closure
  still needs the physical SEL-751/AB1400/ION7550.
- **Report:** `dnp3_split_harness/reports/rig_timing_matrix_results.md`. Artifacts:
  `dnp3_split_harness/reports/rig_timing/` (rig_matrix_results.json, per-config
  timing_decisions.jsonl, 3 pcaps). Deployed code lives on Hulk+Vision at
  `~/Projects/DNP3/dnp3_split_harness/`. Committed in git `5acf404` (see GIT STATE above).

## ★ SESSION 2026-07-14 (late): ack_delay.md AUDIT + 5 fixes — DONE, on disk, NOT committed

Independent 3-agent audit of `ack_delay.md` vs `dnp3_split_harness/` code. Verdict: **Phase 1
complete & honest; Phase 2 scaffolded but not wired** (5B `plan_ack_response_release` is a
scheduling calculator — a user-space app CANNOT move a kernel-owned pure TCP ACK, so
ack-delay/independent/gap modes are inherently rig/P4 work, not a wiring TODO; 5A pure-ACK
emission unproven — needs `CAP_NET_RAW` capture). Claims-discipline clean (all 7 forbidden
overclaims appear only negated).

**Fixes applied & verified this session (all files under `dnp3_split_harness/`):**
1. **Six mandated timestamps** — added `send_start_ns`/`send_complete_ns` to
   `timing_policy.TimingDecision` (+`send_duration_ms` in `to_log_dict`); `split_server.serve_once`
   stamps them around `_send_chunks` and logs one full row after send (`_apply_timing` now
   *returns* the decision, returns None when timing off). Verified in live loopback log; ordering
   correct. **22/22 unit tests pass, byte-identity ALL PASS.**
2. **RF + GB now run** — `attacker_eval.py`: sklearn behind an import guard.
   **KEY: sklearn 1.3.2 IS on host system `python3`** (`~/.local/lib/python3.8`); only the
   research venv lacks it → **run with `python3 attacker_eval.py`** (system, not the venv).
   Trees added to device-ID, detect-the-defense, AND permutation importance. Corroborate: native
   device-ID GB 0.917 / RF 0.889 vs logreg 0.897; detect constant-25 AUC RF/GB 0.999 vs LR 0.990;
   perm imp `resp_size`/`req_size` dominate. Runtime ≈2 min (permutation shuffles).
3. **Report figure attribution** — the `[20,30]→23.3ms` figure in the capstone report was NOT
   stray; it's from `tests/loopback_smoke.py` (bounded 20-30), distinct from the §6 matrix
   (`run_timing_experiment.py`, bounded 15-25 → 23.9ms). Added source attribution; §0/§8 updated
   so no "RF/GB unavailable" claim remains.

Regenerated: `reports/attacker_eval.{md,json}` (sklearn_available=true, 4 models). Edited:
`timing_policy.py`, `split_server.py`, `attacker_eval.py`, `reports/ack_timing_implementation_report.md`.
**To re-verify:** `cd dnp3_split_harness && python3 -m pytest tests/test_timing_policy.py -q &&
python3 tests/loopback_smoke.py && python3 attacker_eval.py`. (Committed in git `5acf404`.)

**Separately this session:** resumed the `dnp3-uns` autoresearch `bridge-latency` experiment
(different repo, `~/Projects/dnp3-uns`) — converged −62%, briefing artifact published. See
memory `dnp3-uns-autoresearch-bridge-latency`.

---

## ★ ACK/LATENCY TIMING — PHASE 1 (2026-07-14, ack_delay.md) — DONE (loopback) + rig-deferred

Third obfuscation primitive (timing axis) implemented in **`dnp3_split_harness/`**,
layered on the byte-preserving replay/split server. Timing changes only *when* bytes
leave, never *which* — `b"".join(chunks) == response` still holds.

- New `timing_policy.py` (ReleaseScheduler/TimingProfile/TimingDecision/FlowTimingState/
  BypassReason + Phase-2 `plan_ack_response_release` + `wait_until`). Correct design:
  `actual_release = max(response_ready, request_arrival + target_delay)`, class-independent
  sampling, per-flow FIFO, 5 fail-open bypasses.
- `split_server.py` hooked before `_send_chunks`; **native mode is wire-identical** (hold=0,
  adds `timing_decisions.jsonl`). CLI: `--timing-mode native|fixed|bounded --target-*-ms
  --timing-seed --max-hold-ms --rto-safe-ms --max-queue-depth --strict-safety`.
- Verified: `tests/test_timing_policy.py` 22/22; `tests/loopback_smoke.py` byte-identity
  ALL PASS + visible time → target; matrix `run_timing_experiment.py` (fixed-25 → 25.17ms,
  0 miss/bypass). RTO measured ≈211 ms (`rto_probe.py`); floor must exceed native ~16 ms.
  Attacker eval: native device-ID 0.897; timing defense closes timing channel only (size +
  ACK-mode residuals persist → stays ~0.90). Phase-2A pure-ACK detection needs privileged
  capture (unresolved on this box). **Capstone: `dnp3_split_harness/reports/ack_timing_implementation_report.md`.**
- **NEXT (rig):** run the matrix + RTO probe host-to-host on Vision/Hulk (commands in the
  report / `reports/rto_probe_notes.md` / `reports/ack_separation_notes.md`); then Phase-2B
  live ACK/response independent delay; then P4.

---

## ★ INVALID-INDEX CommandStatus REFACTOR (2026-07-14, DNP3_inval.md) — DONE + rig-re-validated

Removed the harness's manufactured/assumed OUT_OF_RANGE decision for an unconfigured
CROB index. **Empirically proven:** OpenDNP3 does NOT validate a CROB index natively
(SuccessCommandHandler + DB sized K -> index K returns SUCCESS on the wire; the stack
delivers the out-of-range index to the application handler). The application
`ICommandHandler` is the sole authority.

Refactor (`dnp3_multicrob_harness/`): new **`ControlPointBackend`** in
`run_outstation.py` is the application authority; it returns the native
`opendnp3.CommandStatus`. `ControlTestState` delegates index existence to it; the command
handler dropped the hardcoded `_status_map` and returns the backend's native status.
Encoding is a single-source constant `NONEXISTENT_INDEX_COMMAND_STATUS`
(= OUT_OF_RANGE, retained for byte-continuity with prior captures; NOT_SUPPORTED(4) is
the IEEE-1815-aligned alternative — flip the constant + re-baseline to adopt). Runners /
master / analyzer only observe-and-report (guarded by a unit test that they never
reference the CommandStatus enum). New `tests/test_control_point_backend.py` (8/8 pass).

**Rig re-run 2026-07-14 (Vision↔Hulk), behaviour byte-identical to prior week8 runs:**
padding suite 8/8 pass (invalid end/begin/middle -> 5/OUT_OF_RANGE, no OPERATE;
K16N17 -> 16/TOO_MANY_OPS); boundary valid K5N5 + invalid K5N6 pass. Deliverables (all
7 DNP3_inval.md outputs): `dnp3_multicrob_harness/reports/invalid_index_status_refactor.md`.

---

_Prior checkpoint (2026-07-06) below._

## ★ LAYOUT CHANGE (2026-07-06): one harness → two independent trees

The former single `dnp3_experiment_harness/` was split into **two fully independent,
standalone harnesses** (one per implementation). The original folder has been retired.

- **`dnp3_split_harness/`** — the obfuscation research line (CRC-boundary splitting +
  request-aware replay). Contains **no control-command code** (spec-clean). Its
  governing spec is `dnp3_split_harness/docs/implementation_guide.md`.
- **`dnp3_multicrob_harness/`** — the standalone multi-CROB Select-Before-Operate
  protocol/API check. Governing doc `dnp3_multicrob_harness/docs/multi_crob_validation.md`.

Each tree has its own `lab_config.py`, `README.md`, `requirements.txt`, and its own
`docs/ reports/ captures/`. The two share no code. The split-tree runners are the
former runners with the CROB code removed; the multi-CROB-tree runners are the former
combined runners verbatim. See each tree's `README.md`.

**Loopback re-validated on the split (2026-07-06, gambit):**
- split tree — baseline READ delivered measurements; exact-replay ≡ crc-split
  (identical 800-measurement set) with byte-preservation PASS.
- multi-CROB tree — Tests A/B/C/D all pass (C = two CROBs in one command set →
  idx0=True/idx1=False; D = index 99 OUT_OF_RANGE, no OPERATE, idx0 safe).

**multi-CROB tree RIG-RE-VALIDATED (2026-07-06, Vision↔Hulk):** deployed via rsync;
ran Tests A/B/C/D with the outstation on Hulk (`run_outstation.py --control-test`) and
master on Vision, **capturing a PCAP per test**. All `master rc=0`, no aborts,
summaries written; tshark confirms the CROBs on the wire (Test C `Select`+`Operate`
each = `Control Relay Output Block Obj:12 Var:01, 2 points`; Test D SELECT carries
Point 0 + Point 99, idx99 rejected OUT_OF_RANGE). PCAPs in
`dnp3_multicrob_harness/captures/multi_crob_{test_a,test_b,sbo_test_c,negative_test_d}.pcap`.

**★ multi-CROB HIGHEST-N phase implemented + rig-swept (2026-07-06, per `next_steps.md`).**
Converted the fixed two-CROB check into a reproducible highest-N experiment:
- Outstation `--control-point-count N` (indexes 0..N-1, alternating init, reject N<1),
  monotonic SELECT timeout → NO_SELECT, `Start`/`End` discard of a partially-failed
  SELECT batch, JSON evidence (`--run-id`).
- Master `--crob-count N` (even→LATCH_ON/odd→LATCH_OFF; A/B/C kept as aliases), JSON
  summary, SBO timing measured only around SelectAndOperate (not the ~2s bring-up),
  **non-zero exit** on timeout/non-success, flushing hard-exit (no bare os._exit).
- New `analyze_multicrob_pcap.py` (scapy + `dnp3_crc.py`): reassembles DNP3 from raw
  bytes, validates all CRCs, verifies G12V1 qualifier 0x28 / Count=N / distinct indexes
  / identical SELECT&OPERATE / N success statuses → JSON pass/fail.
- New `run_multicrob_sweep.py` (rig orchestration) → `reports/sweep_manifest.csv` +
  `reports/sweep/analyze_n<N>.json` + `captures/sweep/multicrob_n<N>.pcapng` per N.
- **RESULT: Nmax=16** for the default rig config (reproduced 3×). N≤16 pass; at N≥17 the
  OpenDNP3 outstation `maxControlsPerRequest` (default 16) rejects the excess with
  `TOO_MANY_OPS` (stack-level, before the app handler), so the master sends no OPERATE.
  Command-count limit, NOT fragmentation. Report: `reports/sweep_results.md`.
- The split tree's Vision↔Hulk rig re-run is still the one remaining authoritative check.

**★ multi-CROB BOUNDARY-INDEX phase implemented + rig-validated (2026-07-08, per
`week8.md`, Dr. Lin).** Distinguishes the operation-count limit (`TOO_MANY_OPS`) from a
nonexistent-output-index rejection (`OUT_OF_RANGE`). NO runner changes (outstation
already returns OUT_OF_RANGE for index ≥ K; master `--crob-count` already generates
0..N-1). New/changed:
- `analyze_multicrob_pcap.py` gained `--mode {all-success,boundary-index}`,
  `--configured-points K`, `--expect-operate {absent,present,either}` (all-success is
  the default; existing sweep usage unchanged). Adds a status-name map + classification
  keyed on the first non-zero SELECT-response status.
- New `run_crob_boundary_index_test.py` (rig orchestration, modeled on
  `run_multicrob_sweep.py`): runs valid K=5/N=5 (all-success) + invalid K=5/N=6
  (boundary-index), fresh outstation + PCAPNG per case, pulls JSON, analyzes, writes
  `reports/boundary/boundary_index_{manifest.csv,results.md}`.
- **RESULT (rig Vision↔Hulk 2026-07-08):** valid K5N5 → all 5 SUCCESS, OPERATE sent,
  final state matches (5/5 operate). invalid K5N6 → SELECT statuses `[0,0,0,0,0,12]`
  = SUCCESS×5 + **OUT_OF_RANGE(12)** for index 5; outstation `select_seen=6
  select_success=5 operate_seen=0 rejected_indexes=[5]`, batch discarded
  (`pending_selection_count=0`), **no valid output changed** (final_state_matches=False).
  Master did NOT send OPERATE. classification=`invalid_index_rejected_during_select_no_operate`.
  KEY: both cases report task-level master SUCCESS/exit 0 — task SUCCESS ≠ outputs changed.
  So the boundary is per-index **OUT_OF_RANGE** (status 12), cleanly distinct from the
  N≥17 **TOO_MANY_OPS** (status 8). Artifacts:
  `captures/boundary/crob_boundary_{valid_k5_n5,invalid_k5_n6}.pcapng`,
  `reports/boundary/analyze_{valid_k5_n5,invalid_k5_n6}.json`,
  `reports/boundary/boundary_index_{manifest.csv,results.md}`. README "Boundary-index
  CROB test" section added. NOT padding — characterizes response-side evidence only.

**★ multi-CROB INVALID-INDEX "padding candidate" suite implemented + rig-validated
(2026-07-08, per `week8_next.md`, Dr. Lin).** Extends the boundary-index work to invalid-index
placement, multiple/decoy invalid CROBs, and the invalid-vs-count-limit interaction. Changes:
- `run_master.py` gained `--crob-plan "idx:CODE,idx:CODE,..."` (explicit ordered CROBs;
  overrides `--crob-count`/`--crob-test`; rejects duplicate/malformed/bad-code; ONE
  CommandSet/one SBO; master JSON records the plan in transmitted order). `--crob-count`
  path unchanged.
- `analyze_multicrob_pcap.py` boundary-index mode: relaxed the 0..N-1 index assumption
  (plans are arbitrary order), added classifications `multiple_invalid_indexes_rejected` +
  `decoy_only_invalid_rejected`, and now reports `status_counts`, `invalid_indexes_in_select`,
  per-index status map, SELECT req/resp byte lengths + data-link frame counts.
- `run_crob_padding_candidate_tests.py` (NEW): 8 fixed cases -> `captures/padding_candidates/`
  + `reports/padding_candidates/{analyze_<case>.json, padding_candidate_manifest.csv,
  padding_candidate_results.md}`.
- **run_outstation.py FIX (additive):** `End()` now writes JSON evidence at the end of every
  SELECT or OPERATE batch (was: only failed-SELECT or OPERATE). Needed because a stack-level
  `TOO_MANY_OPS` with all handler-seen ops valid + no OPERATE (case 8) previously wrote NO
  outstation JSON. All-success/failed-SELECT final JSON unchanged.
- **RESULT (rig 2026-07-08, all 8 analyzer_pass=True):** invalid index is rejected per-index
  with `OUT_OF_RANGE`(12) regardless of position (end/begin/middle), master sends no OPERATE,
  no valid output changes. Multiple invalid -> `multiple_invalid_indexes_rejected`; all-invalid
  decoy -> `decoy_only_invalid_rejected`. **K=5,N=17 shows BOTH mechanisms in one response**
  (`status_counts {SUCCESS:5, OUT_OF_RANGE:11, TOO_MANY_OPS:1}`: ops 0-4 ok, 5-15 OUT_OF_RANGE,
  17th op index16 TOO_MANY_OPS). **K=16,N=17 -> `too_many_ops`** (count limit dominates;
  matches prior all-valid N=17). Every case task=SUCCESS/exit0 (task SUCCESS != execution).
  Interpretation (supported): invalid-index CROBs don't execute outputs but ARE visible via
  non-success SELECT statuses; partial SELECT failure prevents OPERATE, so invalid-index
  padding can't be inserted into a real control transaction without extra response-side
  handling. README "Invalid-index CROB padding candidate tests" section added. Memory:
  [[multicrob-invalid-index-padding]].
- **Tutorial updated (2026-07-08):** `docs/multi_crob_tutorial.html` gained section 15
  "The boundary — valid, invalid, too many" (OUT_OF_RANGE vs TOO_MANY_OPS, the 8-case
  table, and an interactive boundary explorer whose client-side model reproduces all 8
  rig cases exactly); "Limits & next" renumbered to 16 with the envelope/boundary marked
  done. Validated (tag balance, rail links, `node --check` on the JS, widget-vs-rig
  parity). NOT yet re-published to the claude.ai Artifact (outward-facing; ask first).
- The split tree's Vision↔Hulk rig re-run is still the one remaining authoritative check.

**★ ACK-TIMING NORMALIZATION research study COMPLETE (2026-07-13, per
`dnp3_multicrob_harness/ack.md`, Dr. Lin).** A rigorous seven-agent evidence study on
byte-preserving randomized timing normalization of ACK-bearing DNP3 responses (the third,
timing obfuscation axis). RESEARCH/DESIGN ONLY — no harness source changed. Deliverables in
new repo-root dir `research/ack_timing_normalization/`.
- **Measured anchor (this session, `analyze_ack.py` over existing multi-CROB rig PCAPs, no
  code changed):** response processing time rises linearly with CROB count — SELECT-resp
  0.179 ms/CROB R²=0.9985, OPERATE-resp 0.214 ms/CROB R²=0.9954, 3× over N=1→16; baseline
  9/9 piggyback, req→ACK 0.239 ms / req→response 1.014 ms. **Caveat: n=1 per N-level (a clean
  10-point line, not a replicated law); one device; CROB-count ≠ database-size.**
- **10 spec deliverables + measured_timing_data.md + final_synthesis.md + GROUNDING.md**:
  executive_summary, literature_review (4 tiers), paper_matrix.csv (102 papers, 21 cols),
  bibliography.bib (101 verified entries; metadata/abstract-level, 2 preprints flagged),
  software_design, hardware_design, evaluation_plan, research_gaps_and_novelty, advisor_brief,
  sources_audit. Six agent evidence reports under `agent_reports/`.
- **Skeptical IEEE/ACM reviewer pass (Agent G): major-revision**; all blocking overclaims fixed
  (device-identity→configuration; unreplicated leak flagged; "designed to remove" not "destroys";
  provisional not "measured" RTO budget; safe watchdog; NetWarden novelty delta; beacon risk;
  added Class-0 DB-size + normalizer-detectability experiments). Citations verified; codename clean.
- **Findings:** binding constraint = master's effective TCP RTO (MEASURE on Vision; ~200 ms floor,
  not universal), not DNP3 timers (5–60 s); no link-layer ACK (verified); shape read plane + gate
  controls via operator criticality allowlist (safety dominates); normalization beats jitter only
  vs a repeated-poll observer; software scheduler in split_server.py is the zero-hardware first
  build; Tofino absolute-delay only via unbuilt recirc-hold (BlueField/FPGA are native homes).
- **Interactive HTML briefing** (integrates exec summary + advisor brief + literature + 102 refs):
  `research/ack_timing_normalization/ack_timing_briefing.html`, published PRIVATE Artifact
  https://claude.ai/code/artifact/e5051b83-acf3-4089-8678-c0ba2d81f976
- **NOT built/run:** no defense executed; effective RTO unmeasured; DB-size (Class-0) channel
  unmeasured. Next: measure RTO on Vision → E1' replicated Class-0 sweep → E2 one defended run.

**★ SPLIT/PAD/TIMING COMBINED-POLICY research study COMPLETE (2026-07-13, per
`when_how.md`, Dr. Lin).** WHEN/HOW to combine the three DNP3 obfuscation mechanisms (split, pad,
timing). Nine specialist agents + hostile reviewer. RESEARCH/DESIGN ONLY — no code changed. Builds
on the ack_timing_normalization package. Deliverables in `research/split_pad_timing_policy/`.
- **NEW measured anchor (this session, scapy over existing multi-CROB sweep PCAPs, no code changed):**
  response **SIZE** also encodes CROB count — **14.6 B/CROB, R²=0.9999**, 37→256 B (N=1→16), even
  cleaner than the timing leak. Read-plane size ∝ point count (~5.7 B/analog point, prior). Split:
  2407 B → 141/71/36/18 chunks (bpc 1/2/4/8), byte-preserving, total bytes unchanged. Same n=1-per-N /
  one-device caveat. → `measured_evidence.md`.
- **Core finding (the study's spine):** CROB count leaks on BOTH size (R²=0.9999) AND timing (R²≈0.99).
  **Timing is closeable now** (class-independent normalization, un-averageable unlike jitter); **size is
  NOT** — split preserves total bytes (and relocates the leak to packet count / creates a beacon), and
  **no byte-preserving DNP3 padding exists at any layer** (measured + parser-level negative result).
  Closing size needs a FUTURE encrypted-tunnel phase (~+590% bw). Honest asymmetry + two negative
  results = the contribution, not "we hid everything."
- **19 spec deliverables + final_synthesis.md + measured_evidence.md + GROUNDING.md** (executive_summary,
  terminology_and_threat_model, literature_review, paper_matrix.csv [14 new works, 21-col schema],
  bibliography.bib [115 = 101 prior + 14 new verified], split/padding/timing_analysis,
  combined_decision_policy, software/tofino/dpu_fpga_design, safety_and_operations, evaluation_plan,
  overhead_model, research_gaps_and_novelty, advisor_brief, sources_audit, implementation_roadmap).
  9 agent reports in `agent_reports/`.
- **Hostile reviewer (Agent J): major-revision**; held on 8/9 attack points, all 5 flagged new cites
  verified, codename clean. Fixes applied: RTO **three-inequality** model (bpc=1 IS feasible — corrects a
  wrong cumulative-vs-RTO bound); **cleartext-now/tunnel-later** threat-model reconciliation + the A0
  direct-payload-read baseline experiment; realigned malformed matrix rows; n=1/N caveats + [M]-label
  fixes; size-decorrelate default conditioned on the self-leak test.
- **Key corrections captured:** master reassembles ANY byte-offset split (CRC-align = auditability, not
  a requirement); split survives the wire via PACING not NODELAY; split RTO binds on Hulk tail /
  hold RTO on Vision, per-hop not cumulative; per-flow FIFO not min-heap; target host Python 3.8;
  Tofino can PACE but not CREATE the split; a lone shaped device is a beacon (shape fleet-wide).
- **Interactive HTML briefing** (integrates all findings, pedagogical w/ live examples): dual-channel
  leak chart, split simulator, padding negative-result cards, averaging-attacker demo, decision-policy
  explorer, 116-ref library. `research/split_pad_timing_policy/split_pad_timing_briefing.html`, published
  PRIVATE Artifact https://claude.ai/code/artifact/bd9fe88b-fe41-4881-b59d-1e14ca9e0714
- **Next experiments:** A0 direct-read baseline (most important) + measure effective RTO (Vision+Hulk) +
  replicate n=1/N leaks (E1/E1′) → one defended split+timing run. No defense built/run yet.

Everything below is the pre-split history; paths that read `dnp3_experiment_harness/`
now live under `dnp3_split_harness/` (or, for the multi-CROB parts, `dnp3_multicrob_harness/`).

## What this project is
Groundwork for a DNP3 traffic **obfuscation** research effort (codename must NOT
appear anywhere — keep all names generic). The end goal is in-network obfuscation
of an outstation's response **size / segmentation / timing** so a passive observer
can't fingerprint the device. This repo (`dnp3_experiment_harness/`) is the
software-validation harness, not the final (P4) implementation.

**Governing spec (the authority):**
`dnp3_split_harness/docs/implementation_guide.md`.
Phase rule still in force: **no CRC recompute, no DNP3 field/length modification,
no random padding, no P4, no proxy/MITM, no control commands.**

## Lab topology (rig)
- **Master** = Vision `10.10.54.19` (runs `run_master.py`).
- **Outstation** = Hulk `10.10.54.158:20000`. In the replay phase the split server
  runs here in the outstation's place (real outstation stopped first).
- **Dev/analysis box** = this host (gambit) `10.10.54.133` — has pydnp3, used for
  loopback validation and to drive the rig over SSH.
- DNP3 link addresses: master=1, outstation=10.
- **Rig SSH**: user `decps` on both hosts (same lab password). Credentials are in
  `~/.claude/.../memory/rig-ssh-access.md` and shell history — NOT stored here.
- Real outstation launch (to restore after experiments), run on Hulk in the harness dir:
  `python3 run_outstation.py` (reads sizes from lab_config.py: DB 300 / 200 analog /
  50 binary / 50 counter). The old hardcoded `run_slave.py` was removed in the 2026-06-18
  cleanup — `run_outstation.py` is the only outstation runner now.

## Current status — DONE and rig-validated
1. **Baseline / segmentation** (research Q1–Q4): OpenDNP3 naturally segments large
   responses (e.g. 200+50+50-pt read → 9 app fragments / 49 link frames / 20 TCP
   segments). Captures: `captures/baseline/Vision_Master.pcapng`,
   `Hulk_outstation.pcapng` (byte-identical; the ground truth).
2. **Exact + TCP-split replay** (Q5/Q6): byte-preserving replay accepted by master;
   TCP write boundaries irrelevant to DNP3 reassembly.
3. **CRC-boundary split** (the chosen "DNP3-aware" split): cut the stream only on
   existing DNP3 CRC block boundaries — reuse CRCs, **recompute nothing**,
   concatenation byte-identical. 2407 B response → 141 chunks, all valid. Rig-proven.
4. **No-IP UX layer built** (per the guide): `lab_config.py` + `run_outstation.py` /
   `run_master.py` / `split_server.py` + `extract_payloads.py` / `map_response.py` /
   `analyze_ack.py`. All thin wrappers over the reusable classes; no IP typed ever.
5. **★ Ordered confirm-aware replay — SUCCESSFUL application-level replay.**
   The breakthrough. Replaying the captured responses **in capture order** (one per
   received master request) keeps the live master on its captured trajectory, so its
   READ lands on app_seq 3, matches the captured READ response, and the master
   **ACCEPTS** it: delivers **800 measurements** to `soe.csv` and sends a **DNP3
   CONFIRM** — all byte-preserving (no sequence rewrite, no CRC recompute).
   Proof pcap: `captures/replay/ordered_rig.pcap`. Report:
   `reports/ordered_replay_results.md`. Guide §18 success criteria all met (incl.
   the previously-open #3 "SOE matches baseline").
6. **★ Replay server refactored (2026-06-18) and RE-VALIDATED on the rig.**
   The 565-line monolithic `dnp3_split_replay_server.py` was split into four
   single-responsibility modules (parser / exchange map / TCP server / thin CLI;
   see Key files). Behavior is byte-for-byte preserved. Re-run end-to-end on the
   rig (Hulk split server <- Vision master, 2026-06-18): **800 measurements**
   delivered to `soe.csv` (rows dated 2026-06-18, identical to the prior runs),
   master sent the **DNP3 CONFIRM** (pcap frame 296), READ response split into the
   same **141 CRC-boundary chunks** (histogram 18Bx123 / 10Bx9 / 12Bx8 / 7Bx1),
   pcap clean (301 pkts, 0 retransmits / 0 resets). Proof:
   `captures/replay/refactor_rig.pcap`, `logs/replay/refactor_split_server.log`.

7. **★ Consolidation + correctness refactor (2026-06-25).** Active root reduced to
   the canonical set (README, lab_config, run_outstation, run_master, split_server,
   extract_payloads, map_response, analyze_ack, dnp3_crc) + `archive_original/`,
   `archive_experiments/`, `docs/`, `future_work/`. Changes:
   - **One config.** The three runners now `import lab_config` (single source of
     truth) instead of each inlining a mirror block — no more config drift. (This
     reverses the 2026-06-22 self-contained "flatten"; deliberate, per request.)
   - **One replay server.** Exact + split merged into `split_server.py`
     `--delivery full|crc-boundary`; the old `dnp3_replay_server.py`,
     `dnp3_ordered_replay_server.py`, `legacy_single_response_server.py`, and
     `dnp3_crc_splitter.py` moved to `archive_experiments/`.
   - **Multi-fragment fix.** The CONFIRM-triggered continuation RESPONSE is now
     split too (group2 1657 B -> 97 chunks), not just the READ fragment (group1
     2407 B -> 141 chunks). Previously the continuation was sent as one write.
   - **TCP frame reassembly.** `FrameReader` buffers the stream and emits exactly
     one DNP3 link frame per request (LEN-derived wire length), so the server no
     longer assumes one recv() == one frame.
   - **TCP_NODELAY** set on the accepted socket so chunk write boundaries are not
     coalesced by Nagle.
   - The governing spec moved to `docs/implementation_guide.md`.
   **RIG-VALIDATED on Vision↔Hulk (2026-06-25)** after a loopback dev check. Synced
   via rsync; all three paths pass over the 1G mgmt net: baseline (real outstation,
   **2700 SOE rows**), crc-boundary split (**800 measurements**, group1→**141**
   chunks, CONFIRM app_seq=3, continuation group2→**97** chunks, byte-preservation
   PASS), and `--delivery full` (800 measurements). Proof pcap on Hulk eno1:
   `captures/replay/consolidation_rig_20260625.pcap` (446 pkts, **0 retransmits /
   0 resets / 0 out-of-order**; 241 small outstation→master TCP segments vs ~20
   native — the CRC-split visible on the wire).

8. **★ Three-level validation + measurement receipt (2026-06-25).** Validation is
   now byte-equivalence + DNP3 acceptance + **measurement equivalence**, not just
   the CONFIRM. Ran the full clean pipeline on the rig (fresh deterministic
   outstation -> one Class 0 read + pcap + baseline_soe.csv -> extract that pcap
   into a fresh replay dir -> exact replay (`--delivery full`) -> CRC split ->
   compare): **baseline_soe == exact_replay_soe == crc_split_soe**, all 2400
   unique `(group/variation, type, index, value)` tuples identical (timestamp +
   header_index excluded). The capture was a 6-fragment response (READ + 5
   CONFIRM-driven continuations); every data fragment was CRC-split (141/141/141/
   141/141/7 chunks), handshake replies left whole. Artifacts on gambit in
   `runs/run_01/` (baseline.pcap, payloads/, 3 CSVs, crc_split_summary.txt).
   (Note: a clean Class 0 read returns 2400 rows = `AllTypes(300)` x 8 types,
   verified all-unique / no append; not a duplication artifact.)
   `run_master.py` now emits a **human-readable measurement receipt** after each
   scan (console + `logs/master/<phase>_summary.txt`), with `--baseline <csv>`
   giving a PASS/FAIL block on gv+type+index+value, `--receipt-rows N`,
   `--summary <path>`, `--no-summary`.

9. **★ Multi-CROB Select-Before-Operate validation (2026-07-03) — DONE, rig +
   loopback validated.** A separate, software-only protocol/API check (per
   `CROb.md`): can one DNP3 SELECT/OPERATE transaction carry multiple valid CROBs
   (Control Relay Output Block, Group 12 Var 1)? **Yes.** Additive-only changes to
   the two runners; **replay/split path (`split_server.py`) untouched**; the Class 0
   READ path still works (rig baseline still delivers 2400 measurements).
   - `run_outstation.py --control-test`: two in-memory simulated binary output
     points (index 0=False, 1=True) via `ControlTestState` + `ControlTestCommandHandler`
     (accept indexes 0/1 + LATCH_ON/LATCH_OFF; OPERATE requires a matching prior
     SELECT; clears consumed selection; prints the state block). Normal behavior is
     unchanged without the flag (`control_test=False` → ExperimentCommandHandler).
   - `run_master.py --action multi-crob-sbo [--crob-test A|B|C] [--control-test-negative]`:
     builds ONE `CommandSet` with the CROBs and issues one `SelectAndOperate`.
   - Tests A (idx0 LATCH_ON→True), B (idx1 LATCH_OFF→False), C (**both in one set** →
     idx0=True/idx1=False), D (negative: idx99 rejected OUT_OF_RANGE, no OPERATE, no
     unsafe change) — **all pass on the rig AND loopback**, master rc=0.
   - **PCAP** `captures/multi_crob_sbo.pcap` (rig Test C): SELECT (frame 13) and
     OPERATE (frame 16) each = `Control Relay Output Block (Obj:12, Var:01), 2 points`
     (Index 0 Latch On, Index 1 Latch Off); responses echo both with `Control Status:
     Req. Accepted (0)`, CRCs Good.
   - **pydnp3/pybind11 gotcha (worked around):** the non-copyable `ICommandTaskResult`
     can't be marshalled to a Python command callback on Py3.12 (aborts) / hangs on
     Py3.8. The master captures task-level completion via `OnTaskComplete` (which
     blocks the single DNP3 thread while the MAIN thread writes the summary + exits;
     file I/O on the callback thread deadlocks). Per-index evidence is the outstation
     log + PCAP. Report: `reports/multi_crob_sbo_results.md`; guide:
     `docs/multi_crob_validation.md`; README section 16. See
     [[pydnp3-sbo-command-result-gotcha]] in project memory for the full workaround.
   - **Interactive tutorial (2026-07-03):** `docs/multi_crob_tutorial.html` — a
     self-contained, funnel-structured explainer (DNP3 → layers → frame → app layer →
     objects/groups/variations → CROB → multiple CROBs → SBO → our build, setup, code,
     tests, the debugging journey, evidence, limits). Interactive widgets (hex/object
     decoders, CROB builder, SBO player, test runner, thread-deadlock viz, 5-tab code
     viewer). Published as a claude.ai Artifact:
     https://claude.ai/code/artifact/9da3dc61-a06b-47e9-9cfc-bee73c538741
     (redeploy by re-running the Artifact tool on that file).

## How to run (short commands)

**Split line — cd into `dnp3_split_harness/` first:**
Baseline:
```
# Hulk:   python3 run_outstation.py
# Vision: python3 run_master.py --phase baseline   # -> logs/master/baseline_soe.csv
```
Replay / split (split server replaces outstation; request-aware, crc-boundary default):
```
# Hulk:   sudo fuser -k 20000/tcp ; python3 split_server.py                  # crc-boundary
#         (exact replay instead:   python3 split_server.py --delivery full)
# Vision: python3 run_master.py --phase crc-split   # -> logs/master/crc-split_soe.csv
```

**Multi-CROB line — cd into `dnp3_multicrob_harness/` first:**
```
# Hulk:   python3 run_outstation.py --control-test
# Vision: python3 run_master.py --action multi-crob-sbo --crob-test C
```
All lab settings in `lab_config.py` (DEFAULT_SPLIT_MODE="crc-boundary",
DEFAULT_BLOCKS_PER_CHUNK=1, DEFAULT_CHUNK_DELAY_MS=10). The three runners now
IMPORT lab_config (single source of truth) instead of inlining it. run_master
writes a per-phase CSV: `--phase baseline|exact-replay|crc-split` ->
`logs/master/<phase>_soe.csv` (no more mixing runs in one soe.csv).

**Replay paths.** `split_server.py` runs ONE path — the **request-aware** TCP
replay server. As of the **2026-06-22 flatten refactor** it is fully
self-contained: the request parser, captured-exchange map, CRC-boundary splitter,
and TCP server are all inlined into `split_server.py` (it loads only itself +
`lab_config.py`, and needs no pydnp3). It parses each master request's DNP3
function code + app sequence, replies with ONLY its matching captured response,
splits solely the READ response on CRC boundaries, waits for the master CONFIRM,
and **refuses to fire a captured response at a request that does not match one**
(the §2.1/§12 safety fix for the blind-byte-dumper bug seen in `split_reader.pcap`).
Two alternatives remain as standalone scripts (run directly, not via split_server.py):
- `dnp3_ordered_replay_server.py` — positional confirm-aware replay
  (the earlier milestone path; proof `captures/replay/ordered_rig.pcap`).
- `legacy_single_response_server.py` — legacy single-shot byte-split
  server (serves one `--response` file; used by `scripts/run_split_replay_test.sh`).

Rig-validated: `request_aware_rig.pcap` (2026-06-15), `refactor_rig.pcap`
(2026-06-18, post-module-refactor), and **`flatten_rig.pcap` (2026-06-22,
post-flatten/self-contained)** — all deliver the identical 800 measurements +
CONFIRM, byte-preserving, 141 CRC-boundary chunks, 301-pkt pcap with 0
retransmits / 0 resets. Reports: `reports/request_aware_replay_results.md`.
The 2026-06-22 flatten (self-contained runners, one flat folder) is now **rig-
validated**: ran the deployed flat harness Vision↔Hulk — baseline master read OK +
CONFIRM, and the split/replay path delivered exactly 800 measurements to
`logs/master/soe.csv`, READ split into 141 CRC chunks (byte-preservation PASS),
master CONFIRM (app_seq 3), connection closed cleanly.

## Key files (canonical layout — 2026-06-25)
Active Python sources are directly in `dnp3_experiment_harness/` and all read the
single `lab_config.py` (they `import lab_config` — no inline mirrors).
- `lab_config.py` — single source of truth for every lab setting.
- `run_outstation.py` — outstation (ExperimentOutstation + command handler).
- `run_master.py` — master (ExperimentMaster + visitors + per-phase CSV SOE;
  `--phase baseline|exact-replay|crc-split`).
- `split_server.py` — THE canonical replay/split server (no pydnp3): FrameReader
  reassembly + request parser + CRC-boundary splitter + captured-exchange map +
  TCP server. `--delivery full` = exact replay, `--delivery crc-boundary` = split
  (default). Splits both the READ fragment and its CONFIRM-triggered continuation.
- `dnp3_crc.py` — CRC-16/DNP helpers (used by `map_response.py`).
- `extract_payloads.py` (PCAP→payloads+metadata), `map_response.py` (decode header
  fields), `analyze_ack.py` (TCP-ACK fingerprint) — no-IP tools (import lab_config;
  no-arg uses defaults, flags override).
- `docs/implementation_guide.md` — the governing spec (was
  `DNP3_REPLAY_SPLIT_NO_IP_COMMANDS_GUIDE.md`).
- `archive_experiments/` — superseded standalone servers + CLI kept for reference:
  `dnp3_replay_server.py`, `dnp3_ordered_replay_server.py`,
  `legacy_single_response_server.py`, `dnp3_crc_splitter.py`, `split_reader.pcap`.
- `future_work/` — EXPERIMENTAL (NOT used by the current path):
  `dnp3_aware_splitter.py` (rebuilds frames + recomputes CRCs) + `dnp3_frame_codec.py`.
- `.../payloads/replay/` — response set extracted from `Hulk_outstation.pcapng`
  (orig_0001..0005 / resp_0001..0009 + metadata.json) driving the request-aware replay.
- `.../payloads/from_live/read_response_full.bin` — assembled 2407 B READ response.
- `.../reports/` — request_aware_replay_results.md, ordered_replay_results.md,
  split_aggressiveness_sweep.md, from_live_split_results.md, baseline_segmentation.md,
  replay_results.md, split_results.md, field_map_results.md, tcp_ack_fingerprinting.md,
  original_code_audit.md.

## Persistent memory
Project memory is at
`~/.claude/projects/-home-philip-Projects-DNP3-dnp3-experiment-harness/memory/`
(governing-spec, rig-topology, rig-ssh-access, dnp3-aware-split-approach,
replay-stale-sequence-result). Index in that folder's `MEMORY.md`.

## NOT in scope this phase / known boundaries
- The recompute-based transport re-segmentation in `future_work/dnp3_aware_splitter.py`
  (archived) is a SEPARATE line, NOT the chosen approach — do not default to it.
- No live data-plane proxy/MITM yet; split server only replaces the outstation at
  its own IP:port.

## Suggested next steps
1. ~~**Split-aggressiveness sweep**~~ **DONE 2026-06-18** (`reports/split_aggressiveness_sweep.md`):
   blocks_per_chunk 1/2/4/8 → READ split into 141/71/36/18 chunks; master accepted
   ALL (800 measurements + CONFIRM each), pcaps clean (0 retransmits/resets). Proof:
   `captures/replay/sweep_bpc{1,2,4,8}.pcap`. Max byte-preserving fragmentation = bpc=1.
2. **Baseline-vs-split figure** for the writeup (9 native large frames → 141 ≤18 B segments).
3. Decide whether to begin the next phase (in-network proxy / true DNP3-aware
   modification) — gated by the guide until explicitly started.
