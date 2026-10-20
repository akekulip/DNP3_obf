# full_read_01 — measurement-object size obfuscation for the full READ (Dr. Lin, 2026-10-19)

This experiment implements and tests Dr. Lin's October-19 request: a full READ carrying several
measurement types, response sizes normalized to fixed targets at **DNP3 control-unit (object)
granularity** — not arbitrary filler bytes — with the master and outstation unchanged, in two request
cases. It is offline only; the hardware lock (`unsafe_restoration: true`) is intact and untouched.

**Two kinds of added points (do not conflate):** Case A (request expansion) makes the outstation
return additional **real configured measurements**. Case B (response padding) appends **synthetic,
zero-valued g1 padding points** that are not outstation measurements — they are labelled as padding
everywhere below and carry value 0 with flags `0x00`.

### Report corrections (M0, 2026-10-19)
1. **Real vs padding points.** Case B's appended g1 points are synthetic padding (value 0, flags 0x00),
   never described as outstation measurements; Case A's extra points are real configured measurements.
2. **Link frame vs TCP payload.** A target size is a **TCP payload** in octets (what the attacker
   observes). The 292 B reference is one complete **DNP3 link frame** (IEEE 1815 §9.2.4.2 max). The
   base full READ is one 247 B link frame = 247 B TCP payload; the large-DB native is **two** link
   frames [292, 85] = a 377 B TCP payload across two segments — a multi-frame payload, not one frame.
3. **Observation point & consistency.** The attacker's point is the **master-facing link** (proxy
   listen port 20001). Per case: Case B keeps the request identical on both legs and changes only the
   master-facing response size; Case A changes the request on the **outstation-facing** leg (port
   20000) so the outstation returns more real points, while the **master-facing** request stays native.
   `verify_demo.py` checks both legs.
4. **Target set scope.** The {141, 292} set here is **READ-only** (from READ native sizes {49, 141,
   247}). The integrated m12 candidate uses shared READ+SBO targets, where SBO sizes are quantized at
   22+13k and 141/292 are **not** SBO-attainable — see the m12 plan, not this READ-only milestone.

## What is built and verified (software, real OpenDNP3 4648fcb)

`endpoint/FullReadGate.cpp` is the SocketGatePad58B outstation/master with a multi-type database
(binary input g1, binary output status g10, analog input g30 = the paper's SEL-751 analog map,
counter g20) and a master `read-mode` of `range` | `class0` | `integrity` | `analog`. It records
every delivered point of every type, every IIN, and every task result. Built at the pinned commit by
`endpoint/run_full_read.py build`; captured on loopback inside `unshare -rn` with `dumpcap`.

`fullread.py` decodes a capture with the independent IEEE 1815-2012 oracle of `read_reencode_01`
(`dnp3_std`, scope widened once to the measurement objects a full READ returns) and `capture.py`:
per-object group/variation/qualifier/index/size, link frames, transport FIR/FIN/seq, fragments, TCP
segments, first-response and complete-response times.

### Native full READ (200 polls each, base database)

| mode | request | response objects | link frames | TCP payload | complete (median) |
|---|---|---|---|---|---|
| range (g10v2 0..22) | 22 B, g10v2 qual 01 | g10v2 ×23 | [49] | 49 B | 0.12 ms |
| class0 (g60v1) | 18 B | g1×16, g30×21, g20×8, g10×23 | [247] | 247 B | 0.12 ms |
| integrity (g60 v2/3/4/1) | 27 B | g1×16, g30×21, g20×8, g10×23 | [247] | 247 B | 0.05 ms |
| analog (g30 0..20) | 22 B | g30×21 | [141] | 141 B | 0.15 ms |
| integrity, **large** DB (42 analog) | 27 B | g1×16, g30×42, g20×8, g10×23 | **[292, 85]** | 292 + 85 B | **41.3 ms** |

The full READ is a Class-0 (g60v1, qual 0x06) or integrity (g60 v2/v3/v4/v1) request; it returns
static data across four object blocks in ascending group order. On the base database it is one
247-byte link frame in one TCP segment. On the larger database it overflows one link frame and the
master receives two frames, [292, 85], in two TCP segments with a **~41 ms** inter-frame gap
(observed; cause unconfirmed, recorded as-is, not investigated).

### Padding construction (`pad_oracle.py`)

A response keeps every original link frame and object octet. FIN is cleared on its last transport
segment (an affine CRC change to that 16-byte block) and **one** link frame is appended: a
continuation transport segment (FIR=0, FIN=1, sequence + 1) carrying one added **binary-input (g1v2)**
object block, indices immediately after the configured binary inputs, flags `0x00`. The master
reassembles one application fragment and receives the original points unchanged plus the added points.
A link frame of U user octets occupies `10 + U + 2·ceil(U/16)`, so the smallest reachable padding is
19 octets; `plan_padding` gives the exact (points, qualifier) for a required growth, or None.

### Target sizes (`pad_oracle.select_targets`)

T_max = one full link frame = **292 octets** (IEEE 1815 §9.2.4.2: ≤250 user octets incl. the
transport octet; a complete frame ≤292 incl. header and CRCs; masters accept ≥2048). From the native
distribution the rule compares {T_max/2, T_max} and {T_max/4, T_max/2, T_max}, snaps each down to a
reachable size, and keeps three only if mean added octets fall ≥15 % **and** some target still merges
two native shapes. For {49, 141, 247} it selects **{141, 292}** (two). A single max target is 292.

### Demonstration and independent check (`proxy_demo.py`, `verify_demo.py`)

`proxy_demo.py` runs the real master ↔ a DNP3-layer proxy (the attacker's observation point, the
master-facing link) ↔ the real outstation, applying `pad_oracle` to each READ. `verify_demo.py`
re-decodes **both** captured legs and the master's own record and passes only when: every
master-facing response is in the target set (or native when ineligible); every link CRC is valid and
the fragment reassembles; the outstation's object octets are the exact prefix of the delivered
response; every requested point is delivered with the outstation's value and flags; every other
delivered point is a declared padding point (g1 index ≥16, value 0, flags 0x00); all tasks SUCCESS;
no IIN beyond the native run.

All nine runs pass (`evidence/*/verify.json`):

- **Case B (response padding)** to the single max 292: integrity, class0, range, analog — every
  master-facing response 292 B, originals preserved, padding carried as g1 points.
- **Case B** to the selected {141, 292}: integrity→292, range→141, analog→141 (native, no padding
  needed).
- **Case A (request expansion)**: the proxy appends real g30/g20/g10 ranges to the analog READ; the
  outstation returns 47 additional **real** measurements (247 B, as the integrity READ), and the
  master-facing request stays native (22 B request → 39 B at the outstation). `caseA_analog_expand_max`
  then pads that to 292 with 25 synthetic g1 points.

Prior negative confirmed: requesting non-existent indexes returns OUT_OF_RANGE, so padding uses real
configured points (Case A) or appended valid points (Case B), never invalid indexes.

### Tests

`tests/test_pad_oracle.py` (8) — frame-length arithmetic vs the standard, exact/None padding plans,
target reaching and point preservation re-checked by `dnp3_std`, the merge rule, request expansion and
its fragment limit. Runs with the existing `seg61_01` and `read_reencode_01` gates: **73 passed**.

## P4 hardware integration — designed, not built; the blocker

The current silicon candidate **m11_09** normalizes only the fixed 49-byte range READ (→61 B) and the
37-byte SBO response, end to end: N (pipe-0 ingress) classifies those exact shapes with exact CRC and
length checks and fixed sequence deltas; **E** (pipe-0 egress) pads them; T (pipe-1 ingress) times the
read lane. The full READ is a different shape at every layer, so the integration needs:

1. **N read lane.** New parser length rows (integrity request ip.len 67; 247-byte response ip.len 287),
   a read-response parse of the 247-byte frame, a `read_response_profile` entry, and sequence/owner/
   `next_seq` entries for the new lengths — so the full READ gets the read-lane timing and its native
   seq/ack are tracked. Range-READ and SBO rows are preserved.
2. **E padder.** A parser path for `dl.len=0xD6` (214) reading only the first 16-byte block (≈28 B
   parsed, well under the 160-B egress-parser budget); an eligibility table that clears FIN and
   recomputes that block's CRC; and the append of one padding frame (link header + transport + g1v2
   header + 25 points + block CRCs ≈ 45 B of new, PHV-pinned headers) with a third deparser TCP-checksum
   branch summing those fields in parity order.
3. **Mapper image length.** The reverse-ACK withhold window and forward offsets use the compile
   constant `r_IMAGE_LEN = 61` (and `-61` = `0xFFFFFFC3`). The full READ needs a per-shape image length
   (292), generalizing `classify_fwd`/`classify_rev`, the `img_*` SALUs and `fwd_prep`.

**Concrete resource finding (measured, both SDKs).** `compiler_table.csv` for m11_09 shows E (p0
egress) occupies **all 12 egress MAU stages (0–11)**. The append padder adds an eligibility table, a
CRC-recompute (Hash unit + stage) and a third deparser checksum branch over ~45 new fields on top of
the existing range-READ and SBO padding; these do not fit the p0 egress pipe, which is already full,
and the p0 deparser already carries two full per-shape checksum branches.

**Constructive path (the small local correction).** The same table also shows **N p0 ingress uses 11
of 12 stages and p1 egress is empty (0 stages)**. The full-READ padder's natural home is therefore
**p1 egress**, which is unused, rather than the full p0 egress. In m11_09 the final master-facing
departure crosses p0 egress (the B′ mapper), so moving the full-READ padding to p1 egress means routing
the full-READ response through pipe 1 on its last pass; that is an architecture change to the pipe
routing, not a cram into a full pipe, and it keeps the range-READ/SBO padding in p0 untouched. The
mapper image-length generalization is independent of placement and feasible in either pipe.

This is left for a hardware-enabled session: the testbed is locked (`unsafe_restoration: true` after
`dev_m11_09_20261019_01`'s failed restore check) and the recorded authority (2026-10-18) forbids a new
data plane. The software mechanism above proves the construction, its conformance, and both request
cases independently of the switch; p1 egress is the identified home for the silicon padder.

## Reproduce

```bash
cd defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/full_read_01
python3 endpoint/run_full_read.py build --work /tmp/full_read_build
B=/tmp/full_read_build/build/full_read_gate
python3 endpoint/run_full_read.py run --binary $B --output evidence/native_integrity_base --mode integrity --db base --reads 200
python3 proxy_demo.py run --binary $B --output evidence/caseB_two_integrity --mode integrity --reads 200 --targets 141,292
python3 verify_demo.py evidence/caseB_two_integrity --native evidence/native_integrity_base --fixture evidence/native_integrity_base --targets 141,292
python3 -m pytest tests -q
```

## Files

- `endpoint/FullReadGate.cpp`, `endpoint/DecoyGateCommandHandler.h`, `endpoint/run_full_read.py` — multi-type endpoints, build + capture.
- `fullread.py` — capture decoder (widens `dnp3_std` once to measurement objects).
- `pad_oracle.py` — padding construction, target selection, request expansion.
- `proxy_demo.py`, `verify_demo.py` — real-stack demonstration and independent check.
- `tests/test_pad_oracle.py` — offline regressions.
- `evidence/` — native samples and the nine Case A/B runs with `verify.json`.
