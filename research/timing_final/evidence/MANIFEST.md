# Evidence package — timing_final (directive §7)

Single source of truth for the timing deliverable. Every reported number traces to a file here.

| subdir | contents |
|---|---|
| `build/` | compile.log + compile_note.md (bf-p4c 9.13.1 + on-switch 9.13.2, 10/12 stages) |
| `source/` | dnp3_timing_normalizer.p4 (sha 82f572ce) — canonical program |
| `native/` | Stage A: native120.pcap + analysis (physical relay, median 2.03 ms, p99 11.42 ms) |
| `protected/` | Stage B: sweep_g{5..40}.{pcap,read.json} + final100_g25.* (100-rep headline, G=25 ms) |
| `g_guard/` | low-G demo: lowg_g1 (guard fires) + protnative_g25 (protection applied) |
| `fingerprinting/` | fingerprint_eval.json (CLRT entropy + cross-device channels) |
| `figures/` | the 10 publication figures (fig01..fig10), reproducible via scripts/make_pub_figures.py |
| `counters/` | final100_g25.read.json — on-chip counters (6400 tokens all deadline-terminated) |
| `packet_identity/` | final100_g25.summary.json — per-transaction CLRT + byte-identity via analyze_clrt |
| `final_state/` | restoration_report.txt (switch back on queue_microbench) |
| `smoke/` | smoke.pcap — 3-txn on-silicon validation of the D1-fixed program |

Token isolation (blocker frames never reach the master): `protected/final100_g25.pcap` contains
0 blocker (EtherType 0x88c1) frames at Vision — verified in `STAGE_B_RESULT.md`.

Headline: native CLRT sd 10.33 ms / 2.73 bits @1 ms  →  protected sd 0.010 ms / 0.00 bits @1 ms,
on the physical SEL-751's real data_offset=8 frames, G=25 ms, 100 reps, all review gates PASS.
Figures reproduce from committed pcaps/JSON: `~/.venvs/research/bin/python scripts/make_pub_figures.py`.
