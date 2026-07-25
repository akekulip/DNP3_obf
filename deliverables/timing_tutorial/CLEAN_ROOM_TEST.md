# CLEAN_ROOM_TEST.md (direcr2 §27)

> **Update (2026-07-25): the on-switch path has since been validated LIVE, not only in dry-run.**
> `demo_all.sh --mode replay --trials 50 --g-ms 25 --yes` ran end-to-end on the physical Tofino-1
> (load → configure → capture → inject → verify → restore): native CLRT median 1.979 ms → protected
> 25.001 ms (n=30), 30/30 released, 0 unmatched, 0 blocker escape, all verifier gates PASS,
> RESTORATION PASS. Evidence: `research/timing_final/evidence/live_demo/`. The dry-run record below
> documents the original methodology (it was run before the live demo was authorized).


A fresh-terminal acceptance run of the tutorial package. Recorded: every command, its exit code, and
whether it was executed for real or in dry-run. **All 11 steps returned exit 0.**

## Safety constraint on this run

The switch is currently restored to the production `queue_microbench` program. Loading the timing
normalizer displaces that program — a hardware change gated on explicit authorization (and the switch
must remain restored). Therefore the **on-switch steps were run in dry-run mode** (`DRYRUN=1`, which
forwards `--dry-run` and prints the remote commands without touching hardware), and the **offline
analysis steps were executed for real** against the packaged example PCAPs (they need no switch). This
is the honest clean-room result achievable without a gated hardware action; the on-switch behaviour was
separately measured during the §5 campaign (see `evidence/`).

## Results

| # | step | command | mode | exit |
|--:|---|---|---|:--:|
| 1 | help | `make help` | real | 0 |
| 2 | preflight | `make preflight DRYRUN=1` | dry-run | 0 |
| 3 | build | `make build DRYRUN=1` | dry-run | 0 |
| 4 | load | `make load DRYRUN=1` | dry-run | 0 |
| 5 | configure queues | `make configure-tm G_MS=25 DRYRUN=1` | dry-run | 0 |
| 6 | run native | `make run-native TRIALS=10 DRYRUN=1` | dry-run | 0 |
| 7 | run protected | `make run-protected TRIALS=10 G_MS=25 DRYRUN=1` | dry-run | 0 |
| 8 | restore | `make restore DRYRUN=1` | dry-run | 0 |
| 9 | analyze | `make analyze PCAP=example_pcaps/protected_demo.pcap G_MS=25` | **real** | 0 |
| 10 | fingerprint | `python3 scripts/fingerprint_eval.py --native-live … --protected …` | **real** | 0 |
| 11 | figures | `make_pub_figures.py --figdir …` | **real** | 0 |

HTML and PDF were opened and visually verified separately (sidebar navigation, all diagrams and
figures rendering, copy buttons, 17-page PDF with page numbers and table of contents).

## What the real (offline) steps produced

- **analyze** (step 9): `n=100 median=24.9989 ms sd=0.0101 ms p99=25.0242 ms`; independent tshark
  cross-check median 24.9982 ms — agree within **0.7 µs** (W3 gate PASS). Confirms the packaged
  `protected_demo.pcap` is normalized to G = 25 ms and the analyzer's numbers do not depend on a single
  parser.
- **fingerprint** (step 10): CLRT-magnitude entropy — native live relay **2.39 bits** @1 ms → protected
  **0.00 bits** @1 ms (and 2.94 → 0.00 @500 µs). Reproduces the headline reduction from the packaged
  captures alone.
- **figures** (step 11): all 10 publication figures regenerated from the packaged PCAPs/JSON.

## Missing dependencies / manual corrections

None. No package was missing; no manual correction was needed. `tshark` (4.4.9) and the research venv
(`~/.venvs/research/bin/python`, for matplotlib) were present; the stdlib analyzer and
`fingerprint_eval.py` run under the system `python3`.

## Note for a true on-hardware clean-room

To run steps 2–8 for real, a person with authorization runs the identical commands **without**
`DRYRUN=1` from a host connected to the switch (Vision/Hulk), after which `make analyze` / `make
figures` consume the freshly captured PCAPs instead of the packaged examples. `make restore` returns
the switch to `queue_microbench`. See `LAB_RUNBOOK.md` and `TROUBLESHOOTING.md`.
