# A2 — read-only current switch-state snapshot (2026-08-07T02:47Z)

Collected read-only before any overnight write. Raw artifacts: `state_snapshot_20260807T024713Z/`.

## Live state (matches the prior report on identity, differs on effectiveness)

| item | value | vs prior report |
|---|---|---|
| bf_switchd | 1 daemon, pid 685449, up ~55 min | matches |
| conf / program | `/home/decps/d4_build/defense4_caseA.conf` / `defense4_caseA` | matches |
| loaded binary | `build9132/pipe/tofino.bin` sha256 `0ec4e452…e90e1242` | matches recorded deployment binary AND staged binary |
| committed P4 source sha256 | `1272679c…c46f678b` | **matches the recorded deployment-source hash** — source→binary provenance confirmed |
| BF-SDE | 9.13.2 | matches |
| watchdog procs | 0 | matches (nothing will revert) |
| stale marker | `d4_complete.marker` = 2026-08-07T01:48:24Z | present (from bring-up; harmless, no watchdog running) |
| relay reachability | ping 0.38 ms; a live READ responds | forwarding confirmed |
| `tbl_params` | mode=4 (D4), **d_ticks=32768**, **da_dr=65536**, budget=18000, read_len=18 | see discrepancy below |
| registers | reg_tag=0 (INACTIVE), reg_deadline/reg_tresp stale (Δ=32768=D_R), reg_ack_rel=0xC0, reg_failopen=0 | idle, no active txn |
| queues (evidence-dump) | qid7 wm=43, qid6 wm=1, qid5 wm=64, **qid4 wm=0**, all drops=0 | reservoirs standing; RESPONSE-hold queue never occupied |
| pktgen | pkt_counter=128, cf_pktgen_admit=128, cf_pktgen_drop=0, app_enable=true | one 2K=128 seed, all admitted |

## DISCREPANCY recorded before any change (do not hide)

The running Defense 4 is loaded and forwarding, but its **policy does not meaningfully shape
timing**:

- `d_ticks=32768` and `da_dr=65536`. From the proven D3 quantization (2 ms → d_word 1,999,872,
  so 1 tick ≈ 1 ns), these are **D_A ≈ 32.768 µs and D_A+D_R ≈ 65.536 µs** — roughly 60× below
  the ~2 ms native SEL-751 CLRT. The value 0x8000 was passed as if it were an encoded word; it
  is 32,768 ticks.
- Direct consequence, measured now: a live READ through the running D4 returns **clrt ≈ 2.82 ms**
  (native range) and **qid4 (RESP-hold) watermark = 0** — the RESPONSE deadline (t_A + 65.536 µs)
  has already expired by the time the ~2.8 ms native RESPONSE arrives, so the RESPONSE is released
  immediately and never dwells in qid4. The D4 policy currently exercises classification and queue
  traversal, not response shaping.
- Therefore, per the overnight rule (leave D4 running only if "the final mode and parameters have
  passed the corrected campaign"), the current parameters have NOT passed a corrected campaign. The
  final switch state will be resolved after the experiment gate (Part C/F), not assumed from here.

## Preserved-valid facts (unchanged)

Program loads and forwards real SEL-751 READ traffic; binary provenance is clean; the four-queue
strict-priority structure and the 2K=128 reservoir split are configured and standing (qid7 wm=43,
qid5 wm=64). No TM drops. No watchdog armed.
