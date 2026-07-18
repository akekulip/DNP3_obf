# WORKING NOTES — DNP3 ACK-timing obfuscation (phased plan `acj_delay2.md`)

**Read `../RESUME_STATE.md` first (top block), then this.** Branch `research/ack-timing-phased`
(63+ commits ahead of `main`, NOT merged). Governing plan: `/home/philip/Projects/DNP3/acj_delay2.md`
(strict phase-gated: STOP + human sign-off each phase; `next_phase_allowed=false` until authorized).
Supported interpreter: **Python 3.8** (pydnp3 only builds there). This file supersedes the stale
pre-phased notes.

## Task
In-network obfuscation of a DNP3 outstation's response so a passive observer cannot fingerprint the
device — byte-preserving (no CRC recompute / field edits / synthesis), phase-gated toward a P4/Tofino
data plane. Software-validation harness only.

## Status by phase (all committed, working tree clean, 61 tests pass)
- **Phase 00** repo audit — PASS.
- **Phase 01** real-device trace characterization — PASS.
- **Phase 02** combined-response timing normalization — **PASS**.
- **Phase 03A** socket-level ACK-separation characterization — **PASS** (human gate 13/13 signed).
- **Phase 04** separate ACK/response manipulation — **CONDITIONAL PASS** (consolidated closeout
  `reports/phases/phase_04/phase_04_separate_ack_manipulation.md`). Core mechanism proven; timing
  normalized; ACK-mode + response-size fingerprints remain.
- **Phase 05** ACK-mode normalization — **PASS (with scoped limitations)** (authoritative 15-section
  closeout `reports/phases/phase_05_ack_mode_normalization/phase_05_ack_mode_normalization.md`).
  Socket coalescing normalizes request ACK mode SEPARATE→COMBINED on the wire (single-server demo +
  per-profile loopback eval + two-host Vision↔Hulk replay eval), byte-preserving, 0 drops. Feature
  decomposition (§8): **mode_only 0.667→0.333 (constant/non-discriminating)** = categorical ACK mode
  removed; **size 0.667 = dominant stable residual** (ION7550 61B distinct; SEL/AB share 54B → collapse).
  Rig authoritative joint `all` 1.000→0.756→0.681 (loopback coalesced_edt unstable — jitter). Reconstruction
  audit: **720/720 single-segment** (first==full, source_hash==replay_hash). Physical target devices /
  inline suppression / Tofino / size-padding = deferred external/separate lines, NOT blockers.
  `next_phase_allowed=false` (human authorization only).

## Key established facts / mechanisms
- **Fingerprint result:** egress *timing* scheduling normalizes WHEN packets leave but cannot conceal
  the categorical **ACK mode** or **response size**. eBPF EDT (timing) + ACK-mode normalization
  together drive joint device balanced accuracy 0.856 → ~0.50 (size-only floor). Size is the last
  residual (out of the byte-preserving scope — separate padding line).
- **Capability boundary:** an existing separate ACK is controllable; the *existence* of a separate
  ACK is not universally controllable without synthesis. ACK suppression = DNP3-payload-preserving
  but NOT packet-presence-preserving.
- **Safe ACK-mode normalization = socket-side COALESCING** where we own the socket (no `TCP_QUICKACK`
  + response within the delayed-ACK window → kernel piggybacks the ACK). Wire-demonstrated
  (`phase05_coalescing_demo.py`): is_separate 100%→0%, byte-identical, 0 drops. Egress `TC_ACT_SHOT`
  drop is realizable only inline (irreversible; proactive fail-open only) — the drop is Tofino-native.
- **eBPF EDT prototype** (`reports/phases/phase_04/ebpf_prototype/`) is proven on the wire.
- **RTO ≈ 211 ms** (this setup); safe hold ≤ ~40 ms.

## Environment gotchas (how to run experiments — NO sudo for execution)
- **Capture:** `sg wireshark -c '...'` (philip is in the wireshark group). NOT sudo.
- **tc / netem:** `unshare -rn` (user netns — namespace-scoped CAP_NET_ADMIN, non-sudo).
- **BPF program LOAD:** has NO non-sudo path (`kernel.unprivileged_bpf_disabled=2` needs real
  CAP_BPF; `unshare -rn` does NOT grant it). Each BPF-load run needs a PI `sudo` invocation (turnkey
  scripts: `edt_test/run_edt_test.sh`, `ebpf_prototype/run_prototype.sh`).
- `git commit --amend` BLOCKED by the fable5 guard → forward commits only. Commits in Philip's name
  ONLY (no Claude attribution).

## Immediate next actions (ALL GATED — `next_phase_allowed=false`; need explicit PI authorization)
- ~~Consolidate Phase 05 into a formal closeout~~ — **DONE** (CONDITIONAL PASS;
  `phase_05_ack_mode_normalization.md` + updated `phase_status.json`, 23-point template).
- ~~Per-device defended-wire classifier eval~~ — **DONE on loopback + TWO-HOST RIG 2026-07-17**
  (loopback `phase05_defended_wire_eval.py`; rig `phase05_rig_defended_wire.py`+`phase05_rig_replay.py`;
  `defended_wire_eval.md` + `rig_defended_wire_eval.md`). Rig (real Vision↔Hulk) confirms loopback:
  joint RF 1.000→0.756→0.681, 2160/2160 byte-identical, 0 retrans/reset. PHYSICAL three-device eval
  (real SEL-751/AB1400/ION7550 hardware — not on this rig) remains deferred.
1. **Tofino/P4** drop path for real-inline devices → route to `p4-dataplane-engineer`.
2. Separate **size-padding** research line (the confirmed last residual — ION7550 stays size-identified).
3. Housekeeping (on request): merge `research/ack-timing-phased` → `main`; refresh GitHub backup.

## Rig-run gotchas (two-host defended-wire eval)
- Start detached rig procs with `ssh -f` **and DEVNULL fds** (`subprocess.run(..., stdin/stdout/stderr=DEVNULL)`),
  NOT `capture_output=True` — a backgrounded `ssh -f` holds the stdout pipe open, so a captured run blocks
  forever waiting for EOF (this silently hung the orchestrator until fixed).
- NEVER open a port-20000 connection to the Hulk server while it is parked at `accept()` — a stray
  connect consumes a session slot and desyncs the whole run. Diagnose read-only (server.log, capture size).
- Capture is non-sudo on the rig: `decps` is in the `wireshark` group and `dumpcap` has cap_net_admin/raw
  on both Vision and Hulk. Run over the 1G mgmt net (no Tofino / no IP assignment needed).

<!-- ============================================================ -->
<!-- ★ AUTHORITATIVE RESUME POINT — 2026-07-18 (supersedes all above) -->
## ►► RESUME HERE (2026-07-18) — Phase 04B DCRN COMPLETE, next = Tofino

**State:** branch `research/ack-timing-phased`, working tree CLEAN, fully pushed to GitHub
`akekulip/DNP3_obf` (HEAD `6cf2246`). Read `RESUME_STATE.md` (repo root) + this file first.

**Phase 04B (DCRN — Dual-Case Release-time Normalizer) = PASS_MEASURED, gate OPEN.**
- What it is: byte-preserving in-kernel eBPF timing normalizer. tc ingress (arm request → class-independent
  target) + egress (classify pure-ACK vs response → set `skb->tstamp` EDT) + `fq` releases. Only mutation is
  the departure timestamp; payload never touched. FIXED (one target) vs BOUNDED (random target in
  [32.39,42.39] ms).
- Gate A/B/C local PASS; pre-rig 7-check audit PASS; **TWO-HOST VISION↔HULK RIG PASS (kernel 6.8, real NICs,
  2026-07-18)**. Timing req→resp median NATIVE 16.81 → FIXED 32.73 → BOUNDED 37.81 ms; 0 retrans/reset/
  ordering/deadline all conditions; byte-identical.
- **KEY FINDING (use BOUNDED, not FIXED):** attacker pure response-timing balanced-acc (100-split CV,
  chance 0.333) NATIVE 0.731 → FIXED 0.740 (ABOVE chance — the 0.06–0.19 ms guard delta is a device-
  correlated scheduler error, p=0.0002) → BOUNDED 0.289 (CI spans chance). Mode+size persist (all=1.0),
  out of byte-preserving scope. `fixed_policy=PASS_MECHANISM_FAILS_PRIVACY_OBJECTIVE`,
  `common_bounded_policy=PASS_MECHANISM_AND_TIMING_EVALUATION`.
- **libbpf port (durable lesson):** rig tc = iproute2-6.1 + libbpf 1.3 (kernel 6.8) rejects the gambit
  legacy `bpf_elf_map` object. Fix: one source, two map ABIs behind `#ifdef DCRN_LIBBPF_MAPS` (BTF `.maps`,
  pin-by-name, `-g`). Build both via `scripts/phase04b_build_bpf.sh`; ship `bpf/phase04b_dcrn.libbpf.o`.
  Hulk has NO clang → build on gambit. Rig gotchas: `~`→/root under sudo (use /home/decps abs paths);
  `sudo -S a; b` only sudo's `a`; background remote procs need `ssh -f`; replay server is one-shot (restart
  per run, one tcpdump spans runs); `local a=$1 b=${a}` trips set -u (split it). Rig sudo pw is decps's own,
  user-supplied, transient-only (in NO tracked file).

**Deliverables (all committed + pushed):**
- Teaching HTML report (whole of 04B, from zero): `reports/dnp3_phase04b_dcrn_report.html`.
- `reports/phases/phase_04b_dual_case_timing/`: phase_status.json (PASS_MEASURED, next_phase_allowed=true),
  gate_c_local_campaign.md, pre_rig_audit.md, two_host_rig_results.md, two_host_rig_runbook.md,
  campaign_local/ + campaign_rig/ evidence (pcaps+json) + manifests (sha256) + gate_a_rig probe.
- Tools: phase04b_dcrn_audit.py (7-check audit), phase04b_dcrn_analyze.py, phase04b_dcrn_attacker_eval.py.
- Rig driver: scripts/phase04b_rig_campaign.sh + phase04b_rig_capture.sh (+ rig_vision_side.sh).

**NEXT PHASE (PI-authorized) = TOFINO / P4 IMPLEMENTATION FEASIBILITY.** Research whether DCRN's ms-scale
EDT hold can move into the Tofino/P4 data plane (which won't buffer ms) — rate shaping / scheduled dequeue /
hybrid decide-on-switch + hold-at-edge — plus carry the size + ACK-mode residuals. Route via
`p4-dataplane-engineer` / `sdn-networks-expert` / `principal-investigator`. Cheap carry-overs: higher-RUNS
rig rerun to tighten CIs; set BOUNDED as DCRN default.
