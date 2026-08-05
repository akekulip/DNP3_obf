# CLAUDE.md

Guidance for Claude Code when working in this repository. Read
`RESUME_STATE.md` first to pick up current state, then this file for the rules
and layout.

## ►► CURRENT STATE & AUTHORITY (2026-07-30) — read before touching the timing work

**Case A Defense 3 (predetermined in-network ACK delay) is the COMPLETE, VALIDATED
implementation** and everything about it lives in **`defense3/`**. Start with
**`defense3/REPORT.pdf`** (and `REPORT.md`) and **`defense3/README.md`**. The mechanism holds
the outstation's pure TCP ACK to `t_ACK + D` and releases it independently of the RESPONSE,
compressing the SEL-751's CLRT distribution. It was built as a Tofino-1 P4 program with a
K=64 in-switch blocker reservoir, repaired for three audit-confirmed defects (R1/R2/R3), and
validated on silicon against the physical SEL-751.

- **Canonical final source:** `defense3/p4/case_a_defense3.p4` — R1/R2/R3 are **unconditional**
  (no defect toggles). The toggled A/B source is `defense3/p4/probes/case_a_defense3_toggled.p4`;
  the pre-audit unrepaired control is `defense3/archive/pre_audit/case_a_defense3_fixed_ack_delay.p4`.
- **Control-plane authorities (single source of truth):** `defense3/control/parameter_policy.py`
  (the ONE D/budget/H/RTO/poll-rate admissibility authority — no harness writes `tbl_params`
  directly) and `defense3/control/counter_map.py` (the shared counter indices).
- **Default program everywhere is `case_a_defense3`.** The unrepaired program is a historical
  control, loaded only behind an explicit `--load-unrepaired-control`; it is NOT a safe restore
  baseline. Safe restore = the final repaired build or the frozen Defense 2.

**►► DEFENSE 4 DIRECTION (2026-08-05 scope reset) — read `defense4/README.md` before any Defense 4 work.**
Defense 4 = one **Tofino-1 at the outstation edge** (master → observed WAN → switch → relay), built in
priority order:
1. **Priority 1 — the unified Defense 4 timing engine** (one P4 program; the proven D1/D2/D3 mechanisms as
   selectable modes + a combined dual-deadline mode; four logical queues on one internal loopback
   scheduler domain). This is the active work.
2. **Priority 2 — size obfuscation** (deferred; does not resume until the timing core passes its own
   committed timing PASS checkpoint).
- **CROB fixed-K (real-plus-inert-decoy) work is DEFERRED SIZE WORK, not the timing core.** The earlier
  fixed-K emulator campaign is stopped; it is recoverable from git history (commits `92cb620`…`0155e0`)
  but is not active. All outer-encapsulation / two-edge / decoder / filler-grid / slot-template / MB-8 /
  Candidate A/A2/A3 material has been removed from the active tree (recoverable from history).
- **Complete Defense 4 is NOT demonstrated** (nothing on silicon).
- **Hardware changes require Philip's explicit authorization** (loading P4, TM/port config, contacting the
  relay, physical SELECT/OPERATE). Tofino-1 data-plane only. Physical SEL-751 stays READ-only.

**Superseded earlier direction (do NOT act on it):** the former "fixed-D fails its gates /
build the READ-anchored, self-timed single-packet hold instead" note was an *intermediate*
analysis. The fixed-D predetermined ACK delay WAS built (with the R1/R2/R3 repairs) and works;
the READ-anchored pivot was not the path taken. The old `meeting_direction.md` is archived at
`defense3/archive/directions/meeting_direction_2026-07-29.md`. Remaining open items are all
lab-blocked and listed in `defense3/REPORT.md` §12 and `RESUME_STATE.md`.

**LOCKED terminology (still valid) — `research/.../CASE_A_TERMINOLOGY.md`:**
- **Case A = SEPARATE-ACK device (SEL-751)** — has a CLRT. **CURRENT SCOPE.** The physical relay
  measures **~1.4–1.9 ms median** (n=100, n=300).
- **Case B = COMBINED-ACK devices (AB1400, ION7550)** — no separate ACK, no CLRT. **OUT OF SCOPE**
  (later extension).
- **CLRT** (ACK→response) is used **only for Case A / separate-ACK.**

**FROZEN baselines — do NOT delete or rewrite** (they are the restore path and the scientific
record): `research/defense2_pktgen/` (silicon-proven Defense 2), the feasibility baseline under
`research/tofino_dcrn_feasibility/p4/ack_delay/`, `dnp3_split_harness/archive_original/`, and the
single restore runner `research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh
--restore-only`. **Hardware/switch changes remain gated** on explicit Philip authorization.

## What this project is

Groundwork for a DNP3 traffic **obfuscation** research effort. The end goal is
in-network obfuscation of an outstation's response **size / segmentation /
timing** so a passive observer cannot fingerprint the device. This repo is the
**software-validation harness**, not the final (P4) implementation.

**Naming rule (hard):** the internal project codename must **never** appear
anywhere — file names, comments, README/report text, class names, or logs. Use
generic, descriptive names only (`dnp3_split_harness`, `split_server`,
etc.). If you find the codename, treat it as a bug to remove.

## Governing spec

`dnp3_split_harness/docs/implementation_guide.md` is the authority for the
splitting/obfuscation line. The phase rule in force:

> **No CRC recompute. No DNP3 field/length modification. No random padding. No
> P4. No proxy/MITM. No control commands.**

The current obfuscation primitive — **CRC-boundary splitting** — works *without
modifying any DNP3 byte*: the captured stream is cut only on existing DNP3 CRC
block boundaries, so `b"".join(chunks) == original` and every chunk ends on an
already-valid CRC. Do not introduce byte modification, CRC recompute, padding,
or a live proxy unless that next phase is explicitly started.

## Repository layout

As of 2026-07-06 the former single `dnp3_experiment_harness/` is split into **two
independent, standalone harnesses** (one per implementation). They share no code;
each has its own `lab_config.py`, `README.md`, `requirements.txt`, `docs/`,
`reports/`, `captures/`. Read each tree's `README.md`.

- `dnp3_split_harness/` — **the obfuscation research line** (CRC-boundary splitting
  + request-aware replay). Contains **no control-command code** (spec-clean). This
  is where obfuscation work happens.
- `dnp3_multicrob_harness/` — the standalone multi-CROB Select-Before-Operate
  protocol/API check (a separate, non-obfuscation line that deliberately issues
  controls).
- `PyDNP3/` — original unmodified pydnp3 example scripts; reference for coding
  style. Do not treat as the active code.
- `Traffic Trace/` — source PCAPs (per-device DNP3 captures) and Zeek/Bro
  analysis scripts/logs.
- `Claude Code Prompt- General DNP3 Experiment Harness.md` — the original task
  prompt (style + naming constraints).
- `RESUME_STATE.md` — current state checkpoint; update it when state changes.

### Inside `dnp3_split_harness/`

Every script reads the **single** `lab_config.py` (they `import lab_config` — no
inline config mirrors).

- `lab_config.py` — **single source of truth** for all lab settings (IPs, port,
  link addrs, split defaults). Edit this one file if lab roles change.
- `run_outstation.py` — baseline outstation, READ-only, controls rejected (needs
  pydnp3). No control-test code.
- `run_master.py` — master (needs pydnp3). Writes a **per-phase** CSV:
  `--phase baseline|exact-replay|crc-split` → `logs/master/<phase>_soe.csv`. No
  multi-CROB action.
- `split_server.py` — **the one canonical** request-aware replay/split server;
  needs **no** pydnp3. Reassembles whole DNP3 frames from the TCP stream
  (`FrameReader`), matches each request's function code + app sequence, replies
  only with its matching captured response, **refuses to fire at a request it
  cannot match**, sets `TCP_NODELAY`, waits for the master CONFIRM.
  `--delivery full` = exact verbatim replay; `--delivery crc-boundary` (default) =
  split every data RESPONSE on CRC boundaries — **both** the READ fragment *and*
  its CONFIRM-triggered continuation (handshake replies stay whole).
- `extract_payloads.py` / `map_response.py` / `analyze_ack.py` — no-IP PCAP/field
  tools (flags override `lab_config.py` defaults). `dnp3_crc.py` — CRC-16/DNP
  helpers used by `map_response.py`.
- `docs/implementation_guide.md` — the governing spec.
- `archive_experiments/` — **superseded, kept for reference**: former standalone
  servers, the `dnp3_crc_splitter.py` CLI, and `split_reader.pcap`.
- `future_work/` — **archived, experimental, NOT used**: recompute-based
  splitter/codec (rebuilds frames + recomputes CRCs). A separate line; do not
  default to it.
- `archive_original/` — unmodified original scripts, preserved, never delete.
- `payloads/`, `captures/`, `runs/`, `logs/`, `reports/` — data, PCAPs, validation
  artifacts, run logs/SOE CSVs, write-ups.

### Inside `dnp3_multicrob_harness/`

- `lab_config.py` — its own copy (topology only).
- `run_outstation.py` — outstation; `--control-test` swaps in a command handler
  backed by two simulated binary output points (index 0/1). Unchanged without the
  flag. (This is the former combined runner, verbatim.)
- `run_master.py` — master; `--action multi-crob-sbo [--crob-test A|B|C]
  [--control-test-negative]` builds one `CommandSet` and issues one
  `SelectAndOperate`.
- `docs/multi_crob_validation.md` (how to run + Wireshark), `docs/multi_crob_tutorial.html`
  (interactive explainer), `reports/multi_crob_sbo_results.md`,
  `captures/multi_crob_sbo.pcap`.

## Lab topology (rig)

- **Master** = Vision `10.10.54.19` (runs `run_master.py`).
- **Outstation** = Hulk `10.10.54.158:20000` (real outstation, or split server in
  its place during replay).
- **Dev/analysis box** = this host (gambit) `10.10.54.133` — has pydnp3, used for
  loopback validation and to drive the rig over SSH.
- DNP3 link addresses: **master=1, outstation=0** on the PHYSICAL SEL-751 (verified on the wire
  2026-07-25: READ dst=0/src=1 func=1; RESPONSE dst=1/src=0 func=129, CRC-validated). The older
  "outstation=10" came from the 10.0.0.x capture corpus and is WRONG for the physical relay.
- SSH credentials are in project memory + shell history, **never** stored in the
  repo.

## How to run

**Split line — cd into `dnp3_split_harness/` first.**

Baseline (master ↔ real outstation):
```bash
# Hulk:   python3 run_outstation.py
# Vision: python3 run_master.py --phase baseline   # -> logs/master/baseline_soe.csv
```

Replay / split (split server replaces the outstation; master command unchanged):
```bash
# Hulk:   sudo fuser -k 20000/tcp ; python3 split_server.py            # crc-boundary
#         exact replay instead:     python3 split_server.py --delivery full
# Vision: python3 run_master.py --phase crc-split   # -> logs/master/crc-split_soe.csv
```

**Multi-CROB line — cd into `dnp3_multicrob_harness/` first.**
```bash
# Hulk:   python3 run_outstation.py --control-test
# Vision: python3 run_master.py --action multi-crob-sbo --crob-test C
```

`split_server.py` asserts `b"".join(chunks) == response` before sending. Vary
granularity via `--blocks-per-chunk` / `--chunk-delay-ms` (or the
`DEFAULT_BLOCKS_PER_CHUNK` / `DEFAULT_CHUNK_DELAY_MS` defaults in `lab_config.py`).
Defaults: `crc-boundary` split, 1 block/chunk, 10 ms delay.

## Working conventions

- **No IPs in commands.** Everything reads `lab_config.py`; runners forward extra
  `--flags` to the underlying CLI to override.
- **Preserve the existing style** from `PyDNP3/` / `archive_original/`:
  module-level `logging.getLogger(__name__)`, thin CLI wrappers over reusable
  classes, no print-debugging.
- **One config.** All scripts `import lab_config`; never reintroduce inline
  config mirrors. Change lab roles in `lab_config.py` only.
- **Byte preservation is the invariant** this phase. Any change to the
  replay/split path must keep `concatenation == original` and stay free of CRC
  recompute / field edits. Loopback (127.0.0.1) is the dev smoke test, but the
  success bar is a **rig (Vision/Hulk)** run: 800 measurements to the per-phase
  CSV + a DNP3 CONFIRM, clean pcap with 0 retransmits/resets. Don't claim rig
  success from a loopback run.
- **Safety defaults:** unsolicited responses OFF, controls rejected
  (`NOT_SUPPORTED`). No control commands (`DirectOperate`/`SelectAndOperate`/
  cold restart) in baseline. Don't enable unsolicited for clean captures.
- After meaningful changes, update `RESUME_STATE.md` and the relevant file in
  `reports/`.

## Persistent memory

Project memory lives under
`~/.claude/projects/-home-philip-Projects-DNP3/memory/` (and a harness-scoped
variant). Check its `MEMORY.md` index for rig topology, SSH access, the
governing spec, and prior results before starting.

## Paper figures

Any figure destined for a manuscript follows the `ieee-paper-figures` skill (IEEE column
sizes, 9 pt Times New Roman, vendored `utils_mpl.py`, Inkscape 1.4.2 assembly + batch
export). Tutorial and worked examples: `~/Projects/Tooling/inkscape_python_figures/`.
