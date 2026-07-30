# Defense 3 — a predetermined ACK-delay for DNP3 on an Intel Tofino switch

**Everything about Defense 3 lives in this one directory.** Design, source, control plane,
test harness, every gate's raw evidence, the physical campaign against a real relay, and
the analysis.

**If you read one file, read [`REPORT.md`](REPORT.md).** It explains the whole thing from
first principles — what the problem is, why this approach was chosen, the arithmetic,
the implementation, every trap found on the way, all the measurements, and an honest
verdict. It assumes you know nothing about DNP3, Tofino, P4 or this project.

---

## What this is, in three sentences

A power-grid protection relay answers a status request over the network. The *delay*
between its low-level network acknowledgement and its actual answer is a physical
property of that specific device, and an eavesdropper can use it as a fingerprint to
identify what equipment is on the network. Defense 3 makes a network switch hold the
relay's acknowledgement back by a fixed, chosen amount of time so that the delay an
eavesdropper measures no longer reveals the device.

**Result in one line:** it works — the fingerprint's spread collapses by a factor of ~240
— but the defense is trivially visible to the same eavesdropper, and a second timing
channel it does not touch remains. See [`REPORT.md`](REPORT.md) §9–§11.

---

## Directory map

| path | what is in it |
|---|---|
| **[`REPORT.md`](REPORT.md)** | **the full explanation. Start here.** |
| `p4/case_a_defense3_fixed_ack_delay.p4` | the switch program — the entire mechanism, ~2 200 lines with the reasoning inline |
| `p4/probe_salu_immediate.p4` | compile-only probe: does the compiler mis-handle large constants in stateful hardware? (§7.1) |
| `p4/probe_retire_dependency.p4` | compile-only probe: the dependency cycle that killed the first repair attempt (§8.2) |
| `setup/…_setup.py` | control plane — ports, queues, priorities, the packet generator, all the safety assertions |
| `run/poll_defense3.py` | the synthetic test driver (gates 1–4) |
| `run/run_defense3.sh` | the runner: loads nothing, asserts everything, always restores |
| `harness/campaign.sh`, `harness/block.py`, `harness/setarm.py` | the physical campaign harness (real relay, 480 transactions) |
| `analysis/analyze_defense3.py` | scores one synthetic transaction against 17 requirements |
| `analysis/analyze_gate34.py` | scores the multi-transaction and boundary-case gates |
| `analysis/analyze_check2.py` | scores the trigger-latency measurement |
| `analysis/analyze_dsweep.py` | scores the physical D-sweep |
| `analysis/analyze_observer.py` | what an eavesdropper actually gets |
| `analysis/test_tag_domain.py` | 2 256 assertions on the state machine, mutation-checked |
| `analysis/assert_salu_asm.py` | fails the build when the *compiled assembly* is wrong even though the compiler said OK |
| `artifacts/assembly/` | the compiled stateful-hardware assembly for each build — the evidence for §7 |
| `artifacts/resources/` | the compiler's own resource reports for each build |
| `evidence/` | every gate's raw JSON, scored output, and the physical captures |
| `evidence/physical/` | the real-relay work: packet captures, the D-sweep data, the analyses |
| `design/` | the design round, the panel memos, and the state-machine review |
| `docs/AUTHORITY_…` | a snapshot of the direction this work was executed against |
| `RESUME_DEFENSE3.md` | current state and the next action |

## Reproducing

Software only, no hardware, ~30 seconds:

```bash
python3 analysis/test_tag_domain.py          # 2 256 assertions on the state machine
python3 analysis/analyze_defense3.py --self-test
python3 analysis/analyze_gate34.py --self-test
python3 analysis/analyze_check2.py --self-test
python3 analysis/analyze_dsweep.py    evidence/physical/dsweep_blocks.jsonl /tmp/a.json
python3 analysis/analyze_observer.py  evidence/physical/dsweep_blocks.jsonl /tmp/b.json
```

Compiling needs the Intel P4 Studio compiler (`bf-p4c` 9.13.1 or 9.13.2). Running on
hardware needs the switch and the relay. Both are covered in [`REPORT.md`](REPORT.md) §13.

## Status

| | |
|---|---|
| designed, compiled, loaded | ✅ |
| synthetically validated | ✅ gates 1–4, all cases |
| physically validated | ✅ 480 transactions against a real SEL-751 relay |
| CLRT concealment | ✅ demonstrated, ~240× spread reduction |
| device anonymity | ❌ **not** demonstrated — see §11 |

## Things this directory does not contain

- **Defense 2** (holds the *response* instead of the acknowledgement) — frozen at
  `../research/defense2_pktgen/`. Never modify it; it is the known-good state the switch
  is returned to.
- **The restore runner** — `../research/case_a_read_anchored_dual_release/run/run_four_queue_oracle.sh --restore-only`.
  Deliberately not copied: there must be exactly one copy of the thing that puts the
  hardware back.
- **Compiler output trees** (`p4/build_*`) — ~15 MB each and fully reproducible; only the
  assembly and resource reports are kept, in `artifacts/`.
