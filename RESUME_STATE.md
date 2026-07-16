# DNP3 Experiment — Resume / State Checkpoint

_Last updated: 2026-07-16. Read this first to resume work._

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
  load-and-release test — **PARTIAL 2026-07-16 (commits `f55c522`, `98f2e6c`).** **fq EDT
  ENFORCEMENT half VALIDATED non-sudo** via SO_TXTIME (`edt_test/so_txtime_test.py`): a
  SO_TXTIME-tagged packet held exactly 30.034 ms vs 0.008 ms, CLOCK_MONOTONIC — fq paces by
  skb->tstamp on this host. **BPF LOAD half BLOCKED:** `edt.c` compiles but `tc filter add bpf` =
  EPERM (`kernel.unprivileged_bpf_disabled=2` needs real CAP_BPF; BPF loading is GLOBAL so
  `unshare -rn` does NOT grant it — unlike capture via `sg wireshark` / netem via `unshare -rn`; no
  passwordless sudo, re-verified). **No non-sudo path for BPF loading.** To finish: PI runs one
  privileged command — `sudo bash reports/phases/phase_04/edt_test/run_edt_test.sh` (turnkey,
  netns-isolated) — or defer eBPF. Residual risk LOW (only the BPF-written-tstamp path unproven;
  enforcement + clock domain confirmed). See `reports/phases/phase_04/edt_load_release_test.md`.
  (3) scope = narrowed target (feasibility §8a), not universal ACK/response control. Do NOT build
  the mechanism without a NEW explicit sign-off.

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
