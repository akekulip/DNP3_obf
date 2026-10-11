# Single-pipe candidate: attended hardware runbook (draft, not executed)

Nothing in this file has been run. Each step needs Philip's recorded authorization (CLAUDE.md: no program load,
port/TM/PRE/pktgen/mirror change or traffic without it; physical OPERATE is attended-only). Read the current
Tooling connectivity map and inspect the live daemon and program first; do not infer live state from this file.

## 0. Preconditions

- A 9.13.2 build of `simplify/single_pipe/single_pipe.p4`, made compile-only on the switch with
  `installed_sdk_build.py` and retained as `simplify/evidence/single_pipe_9132_01/` (stages, PHV, bfrt.json,
  tofino.bin hashes). Compare with the 9.13.4 result in `simplify/evidence/opensource_9134_02/` (10 / 11).
- The open-source model run (`simplify/evidence/model_single_pipe_01/`) passed.
- Record before touching anything: the loaded program name, its `bfrt.json` and `tofino.bin` sha256 (this also
  closes the open gap that the 2026-10-11 padding run's loaded `tofino.bin` is not bound to a repo build), port
  table, and the current Egress/Ingress rows. Keep them as the rollback bundle.

## 1. Load

- Stop the daemon by PID, not with `pkill -f` over ssh (`protocol/hw_vepa/README.md`).
- Start `bf_switchd` with the 9.13.2 build's conf (single pipeline, `pipe_scope` all pipes).
- Timing setup: `stage_reduction/control/defense4_timing_setup.py configure-all` with the campaign parameters
  (default `--bor-loopback-speed 25G`), then `verify`.
- Egress rows: `simplify/single_pipe/cp_single_pipe.e_conn_rows(slot, outstation, master)` for the relay tuple
  (outstation 192.168.10.7:20000 on dev 64, master 192.168.10.1:<pinned port> on dev 9). Forward rows bind to
  egress 9, reverse rows to egress 64. Install with the BF Runtime client used by `protocol/hw_vepa/switch_slot.py`.
- Read back every row and the outcome counter (`Egress.outcome`, unchanged indices) before traffic.

## 2. SYN scrub check (one connection, READ only)

- Capture on Vision, both directions. Open one master connection; send 5 READs.
- Pass: the SYN leaving dev 64 carries MSS followed by 16 NOP bytes (`simplify/tools/syn_option_audit.py` on the
  relay-side capture, if one is available; otherwise the SYN-ACK at the master); the SEL-751 SYN-ACK carries MSS
  only; outcome ARM_MAP (13) +1; every READ response arrives as 58 bytes with valid DNP3 CRCs and TCP/IP
  checksums (`protocol/hw_vepa/wire_check.py`); master ACKs reverse-translated (REV_TRANSLATE, 9).
- Fail: a SYN-ACK with timestamps or SACK, or ARM_NAT (14). Stop and roll back.

## 3. Timing + padding together (attended)

- READ block with the obfuscated arm: response held and released, then padded on egress 9.
- SELECT/OPERATE: physical OPERATE only attended, per CLAUDE.md.
- Compare the observed ACK-to-response gap with the configured release as in `hw_vepa/clrt_check.py`.

## 4. Rollback

- Reload the recorded previous program and conf; reinstall its rows from the rollback bundle; read back the
  hashes and rows and compare.

## Pass record

Write `simplify/evidence/hw_single_pipe_01/` with captures, counter snapshots, row readbacks, the loaded
program hashes and a STATUS.md in the format of `protocol/evidence/hw_vepa_padding_01/STATUS.md`.
