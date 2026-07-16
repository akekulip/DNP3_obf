---
name: dnp3-harness-verified
description: State of the DNP3 experiment harness and what has been live-verified
metadata: 
  node_type: memory
  type: project
  originSessionId: a1652c5e-2f90-4c4f-9658-90a51824211e
---

**UPDATE 2026-07-06 — split into TWO independent harnesses (current top-level layout).**
The former single `dnp3_experiment_harness/` was broken into two fully independent,
standalone trees (one per implementation) and the original folder RETIRED:
- `~/Projects/DNP3/dnp3_split_harness/` — the obfuscation research line (CRC-boundary
  splitting + request-aware replay). **No control-command code** (spec-clean).
  Governing spec `docs/implementation_guide.md`. Its runners are the former runners
  with the CROB code removed.
- `~/Projects/DNP3/dnp3_multicrob_harness/` — the standalone multi-CROB SBO check
  (governing doc `docs/multi_crob_validation.md`). Its `run_outstation.py`/`run_master.py`
  are the former COMBINED runners, verbatim.
Each tree has its own `lab_config.py` / `README.md` / `requirements.txt` / `docs/` /
`reports/` / `captures/`; they share no code. Split verified byte-identical for all
unedited files (incl. `split_server.py`); **loopback re-validated 2026-07-06** — split
tree: baseline READ ok + exact-replay ≡ crc-split (identical 800 set) + byte-preservation
PASS; multi-CROB tree: Tests A/B/C/D pass. Rig run remains the authoritative bar. All
`dnp3_experiment_harness/…` paths below now live under `dnp3_split_harness/` (or, for
multi-CROB parts, `dnp3_multicrob_harness/`).

---

Project (historically at `~/Projects/DNP3/dnp3_experiment_harness/`, now
`dnp3_split_harness/`) — a general (un-branded; NO codename) DNP3
traffic-**obfuscation** validation harness. End goal:
in-network obfuscation of an outstation's response size/segmentation/timing so a
passive observer can't fingerprint the device. This repo is the software-validation
stage, NOT the final P4 implementation. Governing spec (the authority):
`dnp3_split_harness/docs/implementation_guide.md`. Current phase rule: **no CRC recompute,
no DNP3 field/length modification, no random padding, no P4, no proxy/MITM, no
control commands** — the split server only REPLACES the outstation at its own
IP:port (it is an endpoint, not a man-in-the-middle). `RESUME_STATE.md` at the repo
root is the canonical checkpoint — read it first. See [[pydnp3-install]], [[lab-hosts-dnp3]],
[[pydnp3-sbo-command-result-gotcha]].

**UPDATE 2026-06-25 — consolidation + correctness refactor (current state; supersedes
the 2026-06-22 flatten described below).** Governing spec moved to
`docs/implementation_guide.md`. Active root is now just: README, lab_config,
run_outstation, run_master, split_server, extract_payloads, map_response,
analyze_ack, dnp3_crc + dirs archive_original/ archive_experiments/ docs/
future_work/. Four changes: (1) **One config** — the three runners now
`import lab_config` (single source of truth); the self-contained inline mirrors are
GONE (reverses the flatten's main idea, deliberately). (2) **One replay server** —
exact+split merged into `split_server.py --delivery full|crc-boundary`; the old
`dnp3_replay_server.py`/`dnp3_ordered_replay_server.py`/`legacy_single_response_server.py`
+ `dnp3_crc_splitter.py` + `split_reader.pcap` moved to `archive_experiments/`.
(3) **Multi-fragment fix** — the CONFIRM-triggered continuation RESPONSE is now ALSO
split (group2 1657 B → **97 chunks**), not just the READ fragment (group1 2407 B →
141 chunks); previously the continuation went out as one write. (4) **TCP correctness**
— a `FrameReader` reassembles whole DNP3 frames from the stream (no longer assumes
one recv()==one frame) and the accepted socket sets `TCP_NODELAY`. run_master writes a
**per-phase CSV** (`--phase baseline|exact-replay|crc-split` → `logs/master/<phase>_soe.csv`).
**RIG-VALIDATED on Vision↔Hulk (2026-06-25).** Synced via rsync (active root now the
consolidated layout). All three paths pass over the 1G mgmt net: (a) baseline — Hulk
real `run_outstation.py` ← Vision `run_master.py --phase baseline` → **2700 SOE rows**
to `logs/master/baseline_soe.csv`; (b) crc-boundary split — Hulk `split_server.py` ←
Vision `run_master.py --phase crc-split` → **800 measurements**, group1 READ→**141
chunks**, master **CONFIRM(app_seq3)**, continuation group2→**97 chunks** (the
multi-fragment fix, now real on-wire), byte-preservation PASS on every chunk, clean
close; (c) `--delivery full` → 800 measurements, one write/group. Proof pcap captured
on Hulk eno1 (`dumpcap`, no sudo — decps in wireshark group) =
`captures/replay/consolidation_rig_20260625.pcap` (446 pkts, **0 retransmits / 0 resets
/ 0 out-of-order**; **241** small outstation→master TCP payload segments vs ~20 native
— the CRC-split obfuscation visible on the wire). SSH gotchas held: `ssh -f` to detach
remote servers, bracket-trick `pkill -f "run_[o]utstation.py"`, no sudo needed (port
20000 binds fine, dumpcap via wireshark group). NOTE: Vision has an unrelated
pre-existing `outstation-demo` listener on :20000 — NOT part of this harness; leave it.

**Chosen split = CRC-boundary split (byte-preserving), NOT re-segmentation.**
`dnp3_crc_splitter.py` (also inlined into `split_server.py`) cuts the captured byte stream only on boundaries
that already follow an existing DNP3 CRC (header block 8+2, each data block ≤16+2),
reusing every CRC, recomputing nothing → `b"".join(chunks) == original`. The 2407 B
READ response → **141 chunks** (histogram 18B×123 / 10B×9 / 12B×8 / 7B×1).
`future_work/dnp3_aware_splitter.py` + `future_work/dnp3_frame_codec.py` (rebuild
frames + RECOMPUTE CRCs) are a SEPARATE, NOT-chosen line — archived under
`future_work/` (2026-06-18), do not default to them.

**Breakthrough — application-level acceptance (rig-validated).** Replaying captured
responses so the master stays on its captured trajectory (its READ lands on app_seq
3, matching the captured READ response seq3/CON=1) makes the live OpenDNP3 master
ACCEPT the split replay: delivers **800 measurements** to `logs/master/soe.csv` and
sends a **DNP3 CONFIRM** — all byte-preserving, no sequence rewrite, no CRC recompute.
Two proven paths: `request-aware` (default; parse each request's func code+app_seq,
reply with only its match, refuse unmatched) and `ordered` (positional). Proof pcaps:
`captures/replay/{ordered_rig,request_aware_rig,refactor_rig}.pcap` (all 301 pkts,
0 retransmits/resets, RESPONSE reassembled @frame 294, master CONFIRM @frame 296).

**FLATTEN refactor (2026-06-22) — current layout.** Goal: fewest files loaded per
entry point + one flat folder. All Python sources now sit directly in
`dnp3_experiment_harness/` (subpackages `pydnp3_harness/`, `replay_tools/`,
`analysis_tools/` are GONE). The three entry points are **self-contained** — each
inlines its own lab-config block (mirror of `lab_config.py`) and loads ONLY itself
(1 file) at runtime; `lab_config.py` stays as the shared config for the
extract/map/analyze wrappers:
- `run_master.py` = ExperimentMaster + 8 visitors + CSVSOEHandler + CLI (needs pydnp3).
- `run_outstation.py` = ExperimentOutstation + command handler + CLI (needs pydnp3).
- `split_server.py` = request parser + CRC splitter + CapturedExchange + TCPSplitReplayServer,
  all inlined (needs NO pydnp3).
Deleted (inlined/redundant): the whole `pydnp3_harness/`, plus `dnp3_request_parser.py`,
`captured_exchange.py`, `tcp_split_replay_server.py`, `dnp3_split_replay_server.py`.
Kept as flat standalone tools: `dnp3_crc.py`, `dnp3_crc_splitter.py`,
`dnp3_replay_server.py`, `dnp3_ordered_replay_server.py`, `legacy_single_response_server.py`,
and the three self-contained no-IP tools `extract_payloads.py` (PCAP→payloads+metadata),
`map_response.py` (decode header fields, imports `dnp3_crc`), `analyze_ack.py` (TCP-ACK
fingerprint). The wrapper+backend pairs (extract_dnp3_payloads / dnp3_field_map /
analyze_tcp_ack_behavior) were folded into those three single files on 2026-06-22
(no-arg uses lab_config defaults, flags override). NOTE: the analyze tool was
accidentally deleted earlier in the move and **reconstructed** — validated against
`large_read.pcap` (summary CSV byte-identical to the saved report). The flatten merged code only (byte-for-byte behavior preserved) and is now
**RIG-VALIDATED (2026-06-22)**: deployed the flat harness to Vision+Hulk via rsync
(removed old `pydnp3_harness/`/`replay_tools/`/`analysis_tools/`), ran baseline
(Vision run_master → Hulk run_outstation: connected, multi-frame RESPONSE, master
CONFIRM, 2700 SOE rows) and the split/replay path (Hulk split_server ← Vision
run_master): exactly **800 measurements** in soe.csv, READ split into **141 CRC
chunks** (byte-preservation PASS on every response), master **CONFIRM (app_seq 3)**,
connection closed cleanly, pcap **301 pkts / 0 retransmits / 0 resets** — identical
to refactor_rig. Proof: `captures/replay/flatten_rig.pcap` (on gambit + Hulk). SSH
to the rig is passwordless key auth as `decps`; deploy with
`rsync -az --delete --exclude logs/ --exclude captures/`.

Earlier history: a 2026-06-18 refactor had split the 565-line monolithic
`dnp3_split_replay_server.py` into small modules (request_parser/captured_exchange/
tcp_split_replay_server/thin-CLI) under `replay_tools/`, rig-revalidated; the 2026-06-22
flatten then re-inlined those into `split_server.py`. A 2026-06-22 earlier step also
merged the `*_base.py` class files into `experiment_master/outstation.py`, since folded
into the run_* scripts.

**No-IP runners (lab_config.py).** `run_outstation.py` (real outstation, baseline),
`run_master.py` (one scan-all-classes READ), `split_server.py` (replace outstation).
No IPs typed; all settings in `lab_config.py`. The old hardcoded `run_slave.py` was
removed in the 2026-06-18 cleanup (superseded by `run_outstation.py`).

**Cleanup 2026-06-18:** removed dead/duplicate files — top-level `visitors.py` (dup of
`pydnp3_harness/visitors.py`), `run_slave.py`, `payloads/split/` (unreferenced
reframed outputs of the non-chosen aware-splitter), empty `payloads/baseline_large/`,
`__pycache__`. Kept `split_reader.pcap` (cited bug evidence) and all of `replay_tools/`.

**Baseline fact (research Q1–Q4):** OpenDNP3 NATIVELY segments a large response
(200+50+50-pt read → 9 app fragments / 49 link frames / 20 TCP segments, ≤292 B/frame).
That native segmentation is what `Vision_Master.pcapng` / `Hulk_outstation.pcapng`
show — distinct from the CRC-boundary split, which is the obfuscation primitive.

**Env limits:** can't run `sudo tcpdump` on gambit (no passwordless sudo / CAP_NET_RAW),
but `dumpcap` on Vision/Hulk has `cap_net_raw` and `decps` is in the `wireshark` group
→ live capture there needs NO sudo. Port 20000 on Hulk is normally free (no real
outstation auto-runs). Next steps: split-aggressiveness sweep (DEFAULT_BLOCKS_PER_CHUNK
1/2/4/8), baseline-vs-split figure, then decide on the in-network proxy phase (gated).
