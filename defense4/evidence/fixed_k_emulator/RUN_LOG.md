# Fixed-K emulator experiment — autonomous run log

**Live state for the fixed-K (K=R+D real-plus-inert-decoy) Defense 4 emulator experiment
(`defense4/autonomous_run.md`). EMULATOR ONLY — no switch, no physical SEL-751, no SELECT/OPERATE to
the physical relay. All work below is on gambit loopback or the Vision↔Hulk emulator.**

## Status: FOUNDATION BUILT + VERIFIED (the two hard problems are solved); campaign is the next stage.

## 1. Verified this session (with evidence)

| item | status | evidence |
|---|---|---|
| **Inert-decoy outstation backend** — a configured decoy accepts SELECT/OPERATE (native SUCCESS) but never actuates / changes state / increments the actuation counter; real points do all three | **DONE, TESTED** | `run_outstation.py` (`ControlPointBackend.is_decoy/real_indexes`, `ControlTestState.operate` inert branch + `actuation_count`); `fixed_k/test_inert_decoy.py` 5/5 PASS; existing `tests/test_control_point_backend.py` 8/8 PASS (historical all-real behaviour preserved) |
| **Persistent multi-SBO master** — the pydnp3 binding is structurally single-shot (non-copyable `ICommandTaskResult` marshalling aborts on Py3.12 / hangs on Py3.8). Solved with a small C++ OpenDNP3 master | **DONE, VERIFIED** | `fixed_k/nsbo_master.cpp` compiles against the prebuilt `libopendnp3.so`; loopback smoke = **8/8 SBOs on ONE persistent connection** |
| **Persistent-connection capture path** | **VERIFIED** | loopback dumpcap: **78 pkts, 1 client SYN, 2 FIN (teardown only at end), 0 RST, 8 SELECT + 8 OPERATE** — the exact persistent signature |
| **Fail-closed target guard** | **VERIFIED** | `nsbo_master` REFUSES `192.168.10.0/24` (physical SEL-751); allows only `127.0.0.1` / `10.10.54.x` |

Build: `g++ -std=c++14 -I <repo>/cpp/lib/include nsbo_master.cpp -L <repo>/build/cpp/lib -lopendnp3 -lpthread -Wl,-rpath,<repo>/build/cpp/lib -o nsbo_master` (repo = `/home/philip/Projects/opendnp3-community`, g++ 9.4.0, C++14).

## 2. Specialist-agent designs obtained (all read-only / design)

- **Persistent-master (source archaeology):** pydnp3 0.1.0 (Py3.8, Kisensum) is single-shot for SBO; C++ is the clean path (result delivered by const-ref, no marshalling). Emulator readiness string = `Outstation running. Press Ctrl+C to shut down.`; emulator link addrs master=1 / outstation=10 / port 20000.
- **Multi-transaction PCAP analyzer (ground-truthed vs a real persistent capture):** use scapy raw-byte + `dnp3_crc` (CRC validation is impossible in tshark; tshark only for TCP-expert cross-check). Extend `analyze_multicrob_pcap.py` (keep timestamps/flags/seq/ack; replace single-txn `next(...)` locate with a SELECT-opens/OPERATE-closes state machine). **Two load-bearing corrections:** (a) **OPERATE app_seq = SELECT app_seq + 1** (mod 16), NOT equal — pair by time-ordered forward match on each request's own app_seq; (b) OpenDNP3 **startup chatter** (EN_UNSOL func 20 / WRITE func 2 / integrity poll) precedes the SBOs on the same connection and must be skipped (only func 3 opens a txn). Full JSON + CSV schemas provided (size min/max/unique-count per message type ⇒ `size_constant` one-liner; TCP-cleanliness booleans; per-txn feature CSV).
- **Timing side-channel preregistration (frozen protocol content):** features `sel_lat_ms / int_gap_ms / opr_lat_ms / sbo_total_ms` (+ optional ACK gaps under a 95%-availability admission rule); KW + ε² + Spearman + Cliff's δ + RandomForest classifier (RepeatedStratifiedKFold 5×5, balanced-accuracy, Nadeau–Bengio CI) + permutation null + per-feature KSG mutual information; BH FDR over the 27-test confirmatory family; PASS/FAIL/INCONCLUSIVE decision rule that can only affirm absence with a bounded effect size + at-chance classifier at ≥0.80 power. **`opr_lat_ms` is the prime leak suspect** (real controls execute during OPERATE).
  - **★ CRITICAL POWER FINDING:** ≥30 valid/cell DETECTS a leak (FAIL) at every K, but at **K=4 it is only ~59% powered to CERTIFY absence** at the ρ*=0.20 / δ_BA=0.05 bounds. **Freeze the target at ≥60 valid reps/cell** so an overall evidence-of-absence PASS is licensable; at 30/cell, K=4 caps at INCONCLUSIVE on the absence side.

## 3. Point model (frozen for the campaign)

Real-point pool `0..15`, inert-decoy pool `16..31`. For cell (K,R): R indexes from the real pool + (K−R) from the decoy pool, K valid CROBs, **same ordered list in SELECT and OPERATE**, seeded ordering (seed recorded). Emulator: `run_outstation.py --control-test --control-point-count 32 --decoy-indexes 16,…,31`.

## 4. Remaining steps (the campaign) — NEXT LEVEL

1. **Preregistered protocol** → `defense4/evidence/fixed_k_emulator/PROTOCOL_<ts>.md` (freeze §1–§6 incl. the ≥60-rep rule, seeds, artifact layout, safety checks). Commit before the full campaign.
2. **Multi-transaction analyzer** `fixed_k/analyze_fixedk_pcap.py` (from the analyzer spec) + unit test on the smoke pcap.
3. **Stats driver** `fixed_k/run_criterion_6_8.py` (from the preregistration) — `$RESEARCH_PYTHON` (numpy/scipy/sklearn/pandas).
4. **Campaign runner** `fixed_k/run_fixed_k_campaign.py` — restartable, per-cell persistent capture (dumpcap on the outstation host), timestamped run ID, tmux, writes progress after each cell, resumes without overwriting completed raw evidence, fail-closed target guard.
5. **Smoke cells** (4,1),(4,4),(16,1),(16,16); inspect PCAPs/JSON before the full run.
6. **Full campaign** 28 cells × **≥60 valid reps**, randomized order; preserve every failed attempt; retry only infra failures ≤2×.
7. **Stats + adversarial review** (spawn the reviewer agent, read-only) → correct confirmed defects.
8. **Evidence package** (SHA-256 manifest, RESULTS.md), doc updates (evidence ledger, impl plan, RESUME_STATE, CLAUDE.md, harness README), commit + push, verify main sync.

## 5. Claim ceiling (do not exceed)

If every size + correctness gate passes: *"The fixed-K, real-plus-inert-decoy CROB construction normalized
SELECT, OPERATE, and response sizes across R=1…K for K=4,8,16 on the OpenDNP3 emulator."* NOT: physical
relay inertness/safety, complete Defense 4, unified-timing-engine validation, READ-vs-SBO
indistinguishability. **Complete Defense 4 remains NOT DEMONSTRATED.**
