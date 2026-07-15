# CLAUDE.md

Guidance for Claude Code when working in this repository. Read
`RESUME_STATE.md` first to pick up current state, then this file for the rules
and layout.

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
- DNP3 link addresses: master=1, outstation=10.
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
