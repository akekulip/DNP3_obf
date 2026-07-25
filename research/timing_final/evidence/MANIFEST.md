# Evidence package — timing_final (directive §7)

Single source of truth for the timing deliverable. Every reported number traces to a file here.
This tree is the §7 `evidence/timing_final/` package (namespaced under `research/timing_final/`).

## Required subdirectories (all 15 present, §7)

| subdir | contents |
|---|---|
| `build/` | compile.log + compile_note.md (bf-p4c 9.13.1 + on-switch 9.13.2, 10/12 stages, full resource table) |
| `source/` | dnp3_timing_normalizer.p4 (sha 82f572ce) — canonical program |
| `tm_readback/` | `*.tm.json` — Traffic-Manager strict-priority readback (Q_BLOCK max_priority=7 HIGH, Q_RESP LOW) |
| `native/` | Stage A: native120.pcap + analysis (physical relay, median 2.03 ms, p99 11.42 ms) |
| `protected/` | Stage B: sweep_g{5..40}.{pcap,read.json} + final100_g25.* (100-rep headline, G=25 ms) |
| `g_guard/` | low-G demo: lowg_g1 (guard fires) + protnative_g25 (protection applied) |
| `repetition/` | the 100-rep raw per-trial output (final100_g25.transactions.csv, read.json) |
| `pcaps/` | README.md — complete PCAP inventory with packet counts + SHA-256 (files live in native/, protected/, smoke/) |
| `counters/` | final100_g25.read.json — on-chip counters (6400 tokens all deadline-terminated) |
| `registers/` | `*.registers.json` — on-chip register readback (reg_native_clrt, reg_protection, reg_deadline, reg_tag) |
| `packet_identity/` | final100_g25.summary.json — per-transaction CLRT + byte-identity via analyze_clrt |
| `token_isolation/` | blocker_isolation.txt — 0 blocker (0x88c1) frames on native+protected wire; STAGE_B_RESULT.md |
| `fingerprinting/` | fingerprint_eval.json (CLRT entropy + cross-device channels) |
| `figures/` | the 10 publication figures (fig01..fig10), reproducible via scripts/make_pub_figures.py |
| `final_state/` | restoration_report.txt + cleanup_restore.log + clean_room_acceptance.log + git_status.txt |
| `smoke/` | smoke.pcap — on-silicon validation of the D1-fixed program |

## §7 "preserve" items → where each lives

| preserve item | file |
|---|---|
| exact commands | `build/compile_note.md` (compile cmd); `final_state/clean_room_acceptance.log`; scripts + MANIFEST reproduce lines |
| timestamps | PCAP frame timestamps; log filenames (`logs/*.YYYYMMDD-HHMMSS.log`) |
| compiler versions | `build/compile_note.md` (bf-p4c 9.13.1 local + 9.13.2 switch) |
| source hash | `build/compile_note.md` (sha 82f572ce); `source/dnp3_timing_normalizer.p4` |
| compile logs | `build/compile.log` |
| resource files | `build/compile_note.md` resource table (stages/tables/SRAM/TCAM/ALU) |
| TM queue configuration | `tm_readback/*.tm.json` |
| raw per-trial output | `repetition/final100_g25.transactions.csv` + `protected/*.read.json` |
| complete PCAPs | `pcaps/README.md` (inventory) + native/, protected/, smoke/ |
| verifier JSON | `packet_identity/final100_g25.summary.json`; `native/native.validation.json`; `protected/final100_g25.validation.json` |
| campaign exit codes | `final_state/clean_room_acceptance.log` (11/11 exit 0); `STAGE_B_RESULT.md` gate PASSes |
| cleanup output | `final_state/cleanup_restore.log` |
| restoration output | `final_state/restoration_report.txt` |
| git status | `final_state/git_status.txt` |

Token isolation (blocker frames never reach the master): `native120.pcap` and `final100_g25.pcap`
contain 0 blocker (EtherType 0x88c1) frames on the wire — `token_isolation/blocker_isolation.txt`,
corroborated at campaign level in `STAGE_B_RESULT.md`.

Headline: native CLRT sd 10.33 ms / 2.73 bits @1 ms  →  protected sd 0.010 ms / 0.00 bits @1 ms,
on the physical SEL-751's real data_offset=8 frames, G=25 ms, 100 reps, all review gates PASS.
Every figure reproduces from committed pcaps/JSON:
`~/.venvs/research/bin/python scripts/make_pub_figures.py`.
