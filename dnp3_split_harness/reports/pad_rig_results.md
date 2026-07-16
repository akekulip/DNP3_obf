# Response-Size Padding — Rig Results (Vision ↔ Hulk)

_Generated 2026-07-15. Builds and rig-runs the size-padding primitive that the attacker
evaluation and the briefing previously carried only as a projection. This closes the
**size** channel of the device fingerprint at the mechanism level on real hardware._

## What was built

`run_outstation.py` (the real OpenDNP3 outstation) gained a size-padding primitive:

- New flags `--pad-analog N`, `--pad-binary N`, `--pad-counter N` — add **N real, valid
  Class0 input points on top of the function points**. They report deterministic values
  like any other point but represent no physical I/O (a byte-legitimate size pad).
- `configure_stack()` now uses **per-type `DatabaseSizes(numBinary, 0, numAnalog,
  numCounter, …)`** instead of `AllTypes(db_size)`. This was required: `AllTypes(N)`
  allocates N of *every* type and a Class-0 poll returns all of them, so the response
  size tracked `db_size`, not the configured point counts — padding had no effect.
  Per-type sizing makes the response contain **exactly** the configured points
  (real + pad), so padding moves the size precisely.

No CRC recompute, no field/length edit, no forged bytes, no control code: OpenDNP3 builds
the larger valid response and its CRCs natively. Read-only; controls still rejected.

## Method

- **Outstation:** Hulk `10.10.54.158:20000`, real OpenDNP3 stack (pydnp3), one config per run.
- **Master:** Vision `10.10.54.19`, one Class-0 integrity poll (`run_master.py --action
  scan-class0`).
- **Wire witness:** `tcpdump` on Hulk `eno1`, `tcp port 20000`. Response bytes measured as
  the total outstation-egress TCP payload; frame = largest single response segment.
- Three configs: two "device" profiles of different natural size, and the small one padded
  up to the large one's total point count.

## Result — a small device padded to size-match a large one

| config | points (analog+binary) | response bytes | largest frame | decoded pts | resets | retransmits |
|---|---|---:|---:|---:|---:|---:|
| device A (small) | 20 + 20 real | **214** | 163 | 40 | 0 | 0 |
| device B (large) | 40 + 40 real | **361** | 292 | 80 | 0 | 0 |
| device A **+ padding** | 20+20 real **+ 20+20 pad** | **361** | 292 | 80 | 0 | 0 |

- **Before padding:** device A (214 B) and device B (361 B) are trivially separable by
  response size — a size fingerprint.
- **After padding:** device A's response is **byte-identical in size to device B**
  (361 B total, 292 B largest frame). The size channel is normalized.
- **Valid throughout:** the master completed its integrity poll and decoded all 80 points
  (40 real + 40 padding, indistinguishable on the wire), with **0 resets, 0 retransmits,
  0 error status**. The padding points are genuine Class0 points, reported normally — no
  `OUT_OF_RANGE` signature (which invalid-index padding would produce).

## What this establishes vs. leaves open

**Established on the rig (real):** the size-padding *mechanism* — adding real-but-inert
input points normalizes the on-wire response size, is byte-legitimate and fully decodable,
and costs no TCP health. Response size **can** be equalized across profiles on real hardware.

**Still a simulation (honest):** the device-ID drop this enables (0.90 → **0.797**;
`size_only` accuracy 0.500 → chance 0.400) is measured on the trace features of three real
devices — one rig outstation cannot reproduce three device models simultaneously. The
feature-level simulation reproduces the attacker eval exactly (native 0.897, size_only
0.500), so the projected padded numbers are trustworthy, but they are a projection, not a
three-device rig capture.

## Artifacts

`reports/pad_rig/` — `pad_devA.pcap`, `pad_devB.pcap`, `pad_devA_pad.pcap`. Reproduce:
outstation `python3 run_outstation.py --host 0.0.0.0 --num-analog 20 --num-binary 20
[--pad-analog 20 --pad-binary 20]`; master `python3 run_master.py --host 10.10.54.158
--action scan-class0`; capture `tcpdump -i eno1 -s0 -w cap.pcap tcp port 20000` on Hulk.
