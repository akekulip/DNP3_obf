# Defense 3 — a predetermined ACK-delay for DNP3 on an Intel Tofino switch

**Everything about Defense 3 lives in this one directory.** Design, source, control plane,
test harness, every gate's raw evidence, the physical campaign against a real relay, and
the analysis.

**If you read one file, read [`REPORT.pdf`](REPORT.pdf)** — 37 pages, single column, every
figure, typeset from [`REPORT.tex`](REPORT.tex). The same content in Markdown is
[`REPORT.md`](REPORT.md). It explains the whole thing from
first principles — what the problem is, why this approach was chosen, the arithmetic,
the implementation, every trap found on the way, all the measurements, and an honest
verdict. It assumes you know nothing about DNP3, Tofino, P4 or this project.

---

## What this is, in three sentences

A power-grid protection relay answers a status request over the network. The *delay*
between its low-level network acknowledgement and its actual answer is a physical
property of that specific device, and an eavesdropper can use it as a fingerprint to
identify what equipment is on the network. Defense 3 makes a network switch hold the
relay's acknowledgement back by a fixed, chosen amount of time so that it
**compresses the SEL-751's CLRT distribution under the tested conditions** — the delay an
eavesdropper measures carries far less of the device's signature.

**Result in one line:** the mechanism works and the CLRT distribution compresses by a factor
of about 238 — but the defense is **readily detectable in the measured sessions** by the same
eavesdropper (detection established in *this* dataset, not proven universal), a second timing
channel it does not touch remains, and an external audit confirmed three defects (two
state-ordering, plus a host-injected-token path) which are **all three now repaired and
validated on silicon** — with two scoped caveats: defect 2's *cross-transaction*
generation-wrap case is model-checked rather than physically reproduced, and a parser
metadata compiler warning remains open. See [`REPORT.pdf`](REPORT.pdf) §7.5–§7.8, §9–§12 and
[`AUDIT_RESPONSE.md`](AUDIT_RESPONSE.md).

---

## Directory map

| path | what is in it |
|---|---|
| **[`REPORT.pdf`](REPORT.pdf)** | **the full explanation, typeset, single column, 37 pages, 9 figures. Start here.** |
| `REPORT.tex` | the LaTeX source of that PDF (build: `tectonic -X compile REPORT.tex`) |
| [`REPORT.md`](REPORT.md) | the same content as Markdown, for reading in the repo |
| `figures/src/fig1…fig9_*.py` | one script per figure; each recomputes and prints what it plots |
| `figures/out/` | the figures as vector PDF + 300 dpi PNG (`out/report/` = the widths the PDF uses) |
| `p4/case_a_defense3.p4` | **the CANONICAL production program — R1/R2/R3 unconditional, loaded and validated on Tofino-1.** The entire mechanism, reasoning inline. A no-flag build is the safe repaired program (no defect toggles) |
| `p4/probes/case_a_defense3_toggled.p4` | the toggled A/B source (`D3_REPAIR_R1/R2/R3`): flags-off = unrepaired control, flags-on ≡ production |
| `archive/pre_audit/case_a_defense3_fixed_ack_delay.p4` | the **original, unrepaired** program (historical control; its 9/12-stage logs are the baseline) |
| `archive/pre_audit/case_a_defense3_repair_candidate.p4` | the pre-canonical repaired source (superseded by `p4/case_a_defense3.p4` + the toggled probe) |
| [`REPAIR_HISTORY.md`](REPAIR_HISTORY.md) | the repair narrative (R1/R2/R3), and why the pre-audit sources are archived |
| `p4/probe_salu_immediate.p4` | compile-only probe: does the compiler mis-handle large constants in stateful hardware? (§7.1) |
| `p4/probe_retire_dependency.p4` | compile-only probe: the dependency cycle that killed the first repair attempt (§8.2) |
| `setup/…_setup.py` | control plane — ports, queues, priorities, the packet generator, all the safety assertions |
| `run/poll_defense3.py` | the synthetic test driver (gates 1–4) |
| `run/run_defense3.sh` | the runner: loads nothing, asserts everything, always restores |
| `harness/campaign.sh`, `harness/block.py`, `harness/setarm.py` | the physical campaign harness (real relay; 480-txn original D-sweep + two 960-txn repaired campaigns) |
| `analysis/analyze_defense3.py` | scores one synthetic transaction against 17 requirements |
| `analysis/analyze_gate34.py` | scores the multi-transaction and boundary-case gates |
| `analysis/analyze_check2.py` | scores the trigger-latency measurement |
| `analysis/analyze_dsweep.py` | scores the physical D-sweep |
| `analysis/analyze_observer.py` | what an eavesdropper actually gets |
| `analysis/test_tag_domain.py` | 2 675 assertions on the state machine, mutation-checked |
| `analysis/assert_salu_asm.py` | fails the build when the *compiled assembly* is wrong even though the compiler said OK |
| `artifacts/assembly/` | the compiled stateful-hardware assembly for each build — the evidence for §7 |
| `artifacts/resources/` | the compiler's own resource reports for each build |
| `evidence/` | every gate's raw JSON, scored output, and the physical captures |
| `evidence/physical/` | the real-relay work: packet captures, the D-sweep data, the analyses |
| `design/` | the design round, the panel memos, and the state-machine review |
| `docs/AUTHORITY_…` | a snapshot of the direction this work was executed against |
| **[`AUDIT_RESPONSE.md`](AUDIT_RESPONSE.md)** | **item-by-item verification of the external audit — what is confirmed, what is refuted, and the ordered fix list** |
| `analysis/analyze_blocked.py` | block-clustered re-analysis: bootstrap by connection, leave-one-round-out |
| `control/parameter_policy.py`, `control/counter_map.py` | the single parameter-safety authority and shared counter map |
| `../RESUME_STATE.md` | current project state and next actions (`RESUME_DEFENSE3.md` is a pointer to it) |

## Reproducing

Software only, no hardware, ~30 seconds:

```bash
python3 analysis/test_tag_domain.py          # 2 675 assertions on the state machine
python3 analysis/analyze_defense3.py --self-test
python3 analysis/analyze_gate34.py --self-test
python3 analysis/analyze_check2.py --self-test
python3 analysis/analyze_dsweep.py    evidence/physical/dsweep_blocks.jsonl /tmp/a.json
python3 analysis/analyze_observer.py  evidence/physical/dsweep_blocks.jsonl /tmp/b.json
```

Rebuild every figure and the PDF (needs `tectonic`, no hardware):

```bash
for f in 1_dsweep 2_mechanism 3_observer 4_timelines 5_statemachine 6_trigger 7_scatter 8_topology 9_ksweep; do
  $RESEARCH_PYTHON figures/src/fig$f.py
done
for f in 3_observer 4_timelines 5_statemachine 6_trigger 8_topology; do
  D3_FIG_W=4.35 $RESEARCH_PYTHON figures/src/fig$f.py     # the widths REPORT.pdf uses (single-column figs)
done
~/.local/bin/tectonic -X compile REPORT.tex
```

(fig1, fig2, fig7 and fig9 are double-column at 7.16 in and are used at natural size.)

Compiling the switch program needs the Intel P4 Studio compiler (`bf-p4c` 9.13.1 or
9.13.2). Running on hardware needs the switch and the relay. Both are covered in
[`REPORT.pdf`](REPORT.pdf) §13.

## Status

| | |
|---|---|
| designed, compiled, loaded | ✅ |
| synthetically validated | ✅ gates 1–4, all cases |
| physically validated | ✅ against a real SEL-751 relay (see campaign totals below) |
| CLRT distribution compressed | ✅ ~238× standard-deviation reduction (not flattened to a constant) |
| all known audit defects repaired | ✅ **all three repaired and validated on silicon** (R1 §7.6, R2 §7.7, R3 §7.8). **Compiled-state correctness is *checked*, not exhaustively proven** (2 675 mutation-checked model assertions, not a proof over the compiled program). Two scoped caveats: defect 2's *cross-transaction* generation-wrap case is model-checked, not physically reproduced; and the parser `meta`-uninitialized compiler warning is still open |
| stale-response isolation | ✅ re-established on the repaired build, 6/6, master-side capture |
| device anonymity | ❌ **not** demonstrated — see §11 |

**Physical campaign totals** (both are valid; they answer different questions):

| campaign | transactions | defended |
|---|---|---|
| original D-sweep (unrepaired build) | 480 | 400 |
| first repaired campaign (R1+R3) | 960 | 800 |
| second repaired campaign (R1+R2+R3) | 960 | 800 |
| **cumulative, all three** | **2 400** | **2 000** |
| **repaired campaigns alone** | **1 920** | **1 600** |

The original 480/400 figures are what §10–§11's D-sweep and Figure 1 report; the repaired
1 920/1 600 are the mechanism under the final build. Neither is "the" number.

## Things this directory does not contain

- **Defense 2** (holds the *response* instead of the acknowledgement) — frozen at
  `../research/defense2_pktgen/`. Never modify it; it is the known-good state the switch
  is returned to.
- **The restore runner** — `../research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --restore-only`.
  Deliberately not copied: there must be exactly one copy of the thing that puts the
  hardware back.
- **Compiler output trees** (`p4/build_*`) — ~15 MB each and fully reproducible; only the
  assembly and resource reports are kept, in `artifacts/`.
