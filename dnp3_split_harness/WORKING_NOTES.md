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
- **Phase 05** ACK-mode normalization — **CONDITIONAL PASS** (consolidated closeout
  `reports/phases/phase_05_ack_mode_normalization/phase_05_ack_mode_normalization.md`). Feasibility +
  socket-coalescing wire demo (is_separate 100%→0%, byte-identical, 0 drops) + **per-device
  defended-wire eval DONE on loopback** (`defended_wire_eval.md`, `phase05_defended_wire_eval.py`):
  replay real device bytes through the coalescing server, classify defended captures — joint RF
  1.000→0.767→0.700, 2160/2160 byte-identical, 0 retrans/reset; SEL↔AB1400 collapse, ION7550 stays
  size-identified → **size is the confirmed residual**. Inline drop path + PHYSICAL rig + size-padding
  still deferred.

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
