# DNP3 CRC-Boundary Split Harness

Software-validation harness for the **traffic-obfuscation research line**: in-network
obfuscation of an outstation's response **size / segmentation / timing** so a passive
observer cannot fingerprint the device. This repo is the harness that proves the
primitive in software; it is **not** the final (P4) implementation.

This tree is one of two independent harnesses split out from the original combined
harness (the other is `../dnp3_multicrob_harness/`). It contains **only** the
splitting/replay research line and, deliberately, **no control-command code** — which
keeps it aligned with the governing "no control commands" phase rule.

**Naming rule (hard):** the internal project codename must never appear anywhere —
file names, comments, logs, or reports. Use generic descriptive names only.

## The primitive — CRC-boundary splitting

Cut a captured DNP3 response into TCP chunks **only on existing DNP3 CRC block
boundaries**. No DNP3 byte is modified, no CRC is recomputed, and
`b"".join(chunks) == original` — every chunk ends on an already-valid CRC. The live
OpenDNP3 master reassembles the identical application message regardless of how finely
the response is chopped.

**Governing spec:** `docs/implementation_guide.md`. Phase rule in force: **no CRC
recompute, no DNP3 field/length modification, no random padding, no P4, no
proxy/MITM, no control commands.**

## Layout

- `lab_config.py` — single source of truth for all lab settings (IPs, port, link
  addresses, split defaults). Every script `import lab_config`; no inline mirrors.
- `run_outstation.py` — baseline outstation (READ-only; controls rejected).
- `run_master.py` — master; writes a per-phase CSV `logs/master/<phase>_soe.csv`
  (`--phase baseline|exact-replay|crc-split`) plus a measurement receipt.
- `split_server.py` — **the** canonical request-aware replay/split server (needs no
  pydnp3). Reassembles whole DNP3 frames, matches each request's function code + app
  sequence, replies only with the matching captured response, refuses to fire at an
  unmatched request. `--delivery full` = exact verbatim replay; `--delivery
  crc-boundary` (default) = split every data RESPONSE on CRC boundaries (both the READ
  fragment and its CONFIRM-triggered continuation).
- `dnp3_crc.py`, `extract_payloads.py`, `map_response.py`, `analyze_ack.py` — CRC
  helpers and no-IP PCAP/field tools.
- `docs/implementation_guide.md` — the governing spec.
- `payloads/`, `captures/`, `runs/`, `reports/` — replay payload set, PCAPs,
  validation artifacts, and write-ups.
- `archive_experiments/`, `archive_original/`, `future_work/` — superseded servers,
  unmodified originals, and the (not-used) recompute-based splitter line.

## How to run (cd into this directory first)

Baseline (master ↔ real outstation):
```bash
# outstation host:  python3 run_outstation.py
# master host:       python3 run_master.py --phase baseline   # -> logs/master/baseline_soe.csv
```

Replay / split (split server replaces the outstation; master command unchanged):
```bash
# outstation host:  sudo fuser -k 20000/tcp ; python3 split_server.py          # crc-boundary
#                    exact replay instead:     python3 split_server.py --delivery full
# master host:       python3 run_master.py --phase crc-split   # -> logs/master/crc-split_soe.csv
```

All settings come from `lab_config.py` (`DEFAULT_SPLIT_MODE="crc-boundary"`,
`DEFAULT_BLOCKS_PER_CHUNK=1`, `DEFAULT_CHUNK_DELAY_MS=10`). Vary granularity with
`--blocks-per-chunk` / `--chunk-delay-ms`. `split_server.py` asserts
`b"".join(chunks) == response` before sending.

## Lab topology (rig)

- Master = Vision `10.10.54.19` (`run_master.py`).
- Outstation = Hulk `10.10.54.158:20000` (real outstation, or split server in its
  place during replay).
- Dev/analysis box = gambit `10.10.54.133` (has pydnp3; loopback validation).
- DNP3 link addresses: master=1, outstation=10.

## Validation status

- **Rig-validated** (Vision↔Hulk): byte-preserving CRC-boundary split accepted by the
  live master — 800 measurements delivered + DNP3 CONFIRM, READ fragment → 141 chunks,
  CONFIRM continuation → 97 chunks, clean pcap (0 retransmits / 0 resets). Aggressiveness
  sweep bpc 1/2/4/8 → 141/71/36/18 chunks, all accepted. See `reports/`.
- **Loopback re-validated 2026-07-06** after this harness was split out from the
  combined harness: baseline READ delivered measurements; exact-replay and crc-split
  produced the **identical** measurement set (800 = 800) with byte-preservation PASS —
  confirming the split path is unchanged. Loopback is the dev smoke test; the rig run
  is the authoritative bar.
