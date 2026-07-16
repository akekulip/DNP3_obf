# Phase 03A — Wire Capture and ACK-Separation Characterization

**Status: BLOCKED on a capture-capable environment.** The full analysis pipeline is built and
**validated on real captures**; only the packet-capture step cannot run in this environment.
No wire data is fabricated.

## Primary question (restated)

Does delaying the existing ACK-bearing DNP3 response (fixed 25 ms or bounded 20–30 ms) cause the
TCP stack to emit a **separate pure TCP ACK before the DNP3 response**? This can only be answered
from a PCAP — it is never inferred.

## Environment blocker (item 1)

Recorded by `phase03_capture.py` preflight (`capture_environment.json`):

- host `gambit`, kernel 5.15.0-139-generic; user `philip` in groups `philip sudo ollama` —
  **not in `wireshark`**.
- `dumpcap` is present at `/usr/bin/dumpcap` but is `root:wireshark` mode `rwxr-xr--`, so it is
  **not executable by this user** → capture is permission-denied.
- No passwordless sudo; the Vision/Hulk rig is not reachable this session.
- Per the Phase 03A rules, I do **not** change group permissions or use elevated access without
  explicit human approval. So a capture-capable environment must be provided.

## What is already built and PROVEN (capture-independent)

- **`phase03_analyze.py`** — reads one PCAP per config, reconstructs every transaction with the
  **validated Phase 01 extractor** (COMBINED/SEPARATE/OTHER classification + request→ACK,
  ACK→response, request→response timing), and reports per-config ACK-mode counts and fractions
  with **Wilson 95% CIs**, timing distributions, and retransmission/duplicate-ACK/reset rates.
- **Validated on the existing real-device captures** (proving the whole classify→CI pipeline):
  - SEL-751: n=299, **100% separate** (Wilson95 [0.987, 1.000]).
  - AB1400: n=399, **0% separate** (Wilson95 [0.000, 0.009]) — 100% combined.
  - ION7550: n=799, **0% separate** (Wilson95 [0.000, 0.005]) — 100% combined.
- **`phase03_capture.py`** — the loopback capture runner: for each config it captures a `lo`
  PCAP with `dumpcap` while a **real pydnp3 master** drives the timing-enabled `split_server`
  (`--mode matrix` for the 7 configs; `--mode sweep` for the app-write delay sweep 0…100 ms,
  expressed through the existing fixed timing mode — no new scheduler flag, Phase 02 scheduler
  untouched). It preflights capture and, if unavailable, records the environment and exits 3
  without fabricating data.
- **Wilson CI** added to `phase01_stats.py` (tested). 56 unit tests pass.

## How Phase 03A runs the moment capture is enabled

```bash
cd dnp3_split_harness
# 1. wire matrix (7 configs, real pydnp3 master, dumpcap on lo):
python3 phase03_capture.py --run-dir runs/<UTC>_phase_03a_wire --mode matrix
python3 phase03_analyze.py --run-dir runs/<UTC>_phase_03a_wire --pcap-dir runs/<UTC>_phase_03a_wire/pcaps
# 2. if no separation at 20-30 ms, the app-write delay sweep (0..100 ms) + refine:
python3 phase03_capture.py --run-dir runs/<UTC>_phase_03a_wire --mode sweep
python3 phase03_analyze.py --run-dir runs/<UTC>_phase_03a_wire --pcap-dir runs/<UTC>_phase_03a_wire/pcaps
```
Enabling capture (needs your approval): add `philip` to the `wireshark` group and restart the
session, **or** run on the Vision/Hulk rig, **or** provide a capture-permitted host/bridge.

## Outputs this will produce (per §8)

`tables/phase03_ack_transactions.csv`, `tables/phase03_ack_summary.csv`,
`tables/phase03_delay_sweep.csv`; `figures/ack_mode_by_config`, `separation_probability_by_delay`,
`request_to_ack_cdf`, `ack_to_response_cdf`, `request_to_response_cdf`;
`validation/phase03_human_packet_validation.csv`; and the Phase 02 wire addendum verdict.

## Gate

Independent ACK-delay manipulation must NOT begin until capture works, native and normalized ACK
modes are measured, the separation transition is characterized, retransmissions/resets are
reported, ordering is verified, and human packet inspection is complete. `next_phase_allowed =
false`.

```
STOP: Phase 03A is blocked on a capture-capable environment; awaiting human decision.
```
