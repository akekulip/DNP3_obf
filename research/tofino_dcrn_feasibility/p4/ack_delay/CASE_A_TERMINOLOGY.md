# CASE_A_TERMINOLOGY.md — Locked naming (authoritative)

_Per `meeting_direction.md` §1 (NON-NEGOTIABLE TERMINOLOGY) and the 2026-07-21 meeting. This is the
single source of truth for how the project names things. Do not reinterpret or rename the cases._

## Two DEVICE TRAFFIC CASES (a property of the device — NOT defenses)

| | **Case A — SEPARATE ACK** | **Case B — COMBINED ACK** |
|---|---|---|
| Device(s) | **SEL-751** (10.0.0.1) | **AB1400** (10.0.0.12), **ION7550** (10.0.0.11) |
| Structure | request → **pure TCP ACK** → DNP3 response | request → **one packet (ACK + response)** |
| CLRT (ACK→response) | **defined** — native median **~12.9 ms** | **undefined** (no standalone ACK) |
| Scope | **CURRENT research scope** | **OUT OF SCOPE now** — later extension |

**CLRT** = the Formby cross-layer response-time feature (ACK→response). Use the term **only for Case A
(separate-ACK)**. Never use CLRT for AB1400/ION7550 combined-response traffic.

## Case A contains TWO DEFENSES (not "Case A" / "Case B")

| | **Defense 1 — delay the ACK** | **Defense 2 — delay the response** |
|---|---|---|
| Native | request → ACK ────── response | request → ACK ──── response |
| Defended | request ────── ACK → response | request → ACK ──────────── response |
| Effect | ACK→response gap → **~0** (reduce) | ACK→response gap → **G** (increase/normalize) |
| Program | **`dcrn_defense1.p4`** | **`dcrn_defense2.p4`** |
| Governing | event (response arrival) | ACK-relative deadline `t_ack + G` |
| Status | PASS_MEASURED_ON_TOFINO (recirc) | PASS_MEASURED_ON_TOFINO (recirc) |

**★ Never call Defense 2 "Case B."** (master direction §13.) The two defenses both live under **Case A
(separate-ACK)**. Case B is the combined-ACK *device* case, a separate later phase.

## File-name scheme (renamed 2026-07-21 to remove the old "ackA/ackB/caseA/caseB" mislabels)
- P4 / control plane: `dcrn_defense1.p4` / `dcrn_defense2.p4`, `defense1_setup.py` / `defense2_setup.py`,
  `defense1_read.py`, `dcrn_defense{1,2}.conf`, `launch_defense{1,2}.sh`.
- Reference models / tests: `refmodel/defense{1,2}_state_machine.py`, `tests/test_defense{1,2}.py`.
- Evidence: `evidence/defense{1,2}_9.13.*/`, `evidence/defense2_hardware/`,
  `evidence/pcap_{clean,raw}/defense{1,2}_{clean,raw}.pcap`.
- Design doc: `ACK_DELAY_DEFENSE2_DESIGN.md` (Defense 2 design; formerly `ACK_DELAY_CASE_B_DESIGN.md`).
- **`case_b_defense_design.md` is the one correctly-named file** — it is the *combined-ACK Case B*
  design study (deferred later extension), NOT Defense 2. Keep it.
- Internal P4 control-block names (`DcrnIngress`, register/table names) are **unchanged** — only the
  *program* name and file names changed; the frozen implementation's logic and bfrt control paths are
  intact.

## What is frozen (do not delete/overwrite/rewrite — master direction §4)
The recirculation implementation `dcrn_defense1.p4` + `dcrn_defense2.p4` (the valid feasibility
baseline; the meeting keeps it as the comparison baseline), the tag `ack-delay-caseA-c3-pass`
(`bf4acdff`), and the hardware-evidence dirs (`evidence/{formby_eval, defense2_hardware, sel751_replay,
continuous_campaign_PASS}/`). Raw captures under `Traffic Trace/` and `evidence/pcap_raw/` are never
modified.

## Current direction (meeting 2026-07-21)
Focus Case A / SEL-751. Preserve the recirc baseline. Study & adapt **Ditto** (NDSS 2022) queue
scheduling as a more defensible, load-stable timing mechanism (vs recirculation). Move to the physical
SEL-751. Begin the paper now. Leave Case B (combined) for later. See `meeting_direction.md`,
`meeting.md`, `CURRENT_STATE_AUDIT.md`, and prior queue/TM design in
`research/split_pad_timing_policy/tofino_design.md`.
