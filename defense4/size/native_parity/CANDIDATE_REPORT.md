# Native READ/SBO size-parity candidates

Find legal DNP3 encodings where a READ response and an SBO (Select-Before-Operate)
echo response leave the outstation at the **same native byte size**, so a later
switch only has to split both at existing CRC boundaries. The switch inserts no
bytes. The sizes match because the endpoints are configured with real (even) and
decoy (odd) points that make the two responses the same length by construction.

Everything here is derived from DNP3 encoding rules in `length_synth.py` and
checked against the measured SEL-751 anchors by `test_length_synth.py`
(87 checks, all pass, exit 0). Nothing below is a remembered size constant.

## What the claim is, and is not

- **Is:** the two responses have the **same TCP-payload length** and, because the
  wire model is strictly increasing in the user-data length `u`, the **same
  CRC-block geometry** (same block count, same residual, same boundary offsets,
  same segment-length vector).
- **Is not:** DPI equality. A parser still sees different object groups (G12 CROB
  vs G10/G30 status), and the CROB carries control-code and timing fields a status
  object does not. Both responses share function code `0x81` and a 2-byte IIN, but
  the object bytes differ. The defense hides **size and segmentation**, not object
  identity.
- **Scope:** the outstation **response** direction (the fingerprinting target).
  Request-direction sizes differ (a READ request is ~20 B, an SBO SELECT request
  is ~45 B); this is a known limitation, not closed here.

## The model (derived, then anchor-checked)

Data-link wire size for `u` user-data octets (transport byte + application bytes):

```
link_size(u) = 10 + u + 2*ceil(u/16)
```

`10` = link header (start 2 + length 1 + control 1 + dest 2 + source 2 + header
CRC 2). Each `<=16`-octet user-data block carries its own 2-octet CRC. `link_size`
is **strictly increasing**, so equal wire size forces equal `u`, which forces equal
block geometry. That is why native size equality gives segmentation equality for
free on single-frame responses.

Response application overhead ahead of any object: `RESP_FIXED = 5` (transport 1 +
app control 1 + app function 1 + IIN 2).

Derived per-transaction user-data lengths:

| Transaction | Object header | Per point | Formula for `u` |
|---|---|---|---|
| SBO echo, K CROBs | G12V1, qual `0x17` = 4 B | index prefix 1 + CROB 11 = 12 | `u_SBO(K) = 9 + 12K` |
| READ G10V2 / G1V2, N pts | qual `0x00` = 5 B | 1 (flag octet) | `u_READ = 10 + N` |
| READ G30V1 / G20V1, N pts | qual `0x00` = 5 B | 5 (flag + 32-bit) | `u_READ = 10 + 5N` |

The CROB is 11 B: control code 1 + count 1 + on-time 4 + off-time 4 + status 1.
The `0x17` qualifier (1-byte count, 1-byte index prefix) is what pins the per-CROB
cost at 12, and the two SBO anchors confirm it.

### How the formulas match the anchors

| Anchor (SEL-751, 2026-08-12) | wire | inverts to `u` | formula |
|---|---|---|---|
| SBO 1-CROB echo | 35 | 21 | `u_SBO(1)=9+12` |
| SBO 2-CROB echo | 49 | 33 | `u_SBO(2)=9+24` |
| READ 32 G10V2 status pts | 58 | 42 | `10+32` |
| READ binary-in (16 pts) | 40 | 26 | `10+16` |
| Class-0 poll | 134 | 110 | multi-object (consistent) |

The two anchor families **triangulate** the fixed constants independently: the
READ anchor `42 = 5 + 5 + 32` pins `RESP_FIXED = 5`; the SBO anchor `21 = 5 + 4 +
12` then pins the G12 header at 4. `test_length_synth.py` checks this, and
mutation-tests every fixed overhead: perturbing the link header, block CRC,
`RESP_FIXED`, G12 header, or per-CROB size by ±1 breaks at least one anchor.
(Honest exception: the 16-octet block size is a DNP3 spec constant; the 35/49
anchors are consistent with it but do not distinguish 15 from 16 — only block=17
is anchor-rejectable. The test asserts exactly that.)

## Selected candidates

Predicted SBO grid (K=1..5): `u = 21, 33, 45, 57, 69` -> wire `35, 49, 61, 75, 89`.
An intersection exists whenever a legal READ encoding lands on that same `u`.

- **C04 (primary): 2-CROB SBO == 23-point G10V2 read, 49 B.**
  1 real breaker CROB + 1 decoy CROB. The cover story is a routine read of 23
  binary-output-status points. Smallest decoy count that still carries cover.
  Boundaries `10/28/46/49`, balanced split `[28, 21]`.

- **C05 (secondary): 3-CROB SBO == 7-point G30V1 analog read, 61 B.**
  1 real + 2 decoy CROBs. The cover is a 7-point analog metering poll (voltages,
  currents, power) — an extremely natural SEL-751 read, and only 7 configured
  points. Boundaries `10/28/46/61`, split `[28, 33]`. Costs one more decoy than
  C04 but the READ side is more plausible.

- **C01/C02 (viable): 1-CROB SBO == 11-point G10V2/G1V2 read, 35 B.**
  Exact size match, but K=1 means zero decoys, so the SBO carries no cover padding.
  Useful only if an 11-point read is the reference class.

## Tier-1 Pareto table (natural minimal encodings, both sides)

Tier-1 = outstation's natural minimal encoding: SBO command echo with the indexed
`0x17` qualifier, static READ with the start-stop `0x00` qualifier at low indices.
Physical risk on the READ side is none (read-only). SBO physical risk is the decoy
CROBs (see prerequisite below). OpenDNP3 result and SEL-751 compatibility are TBD
(offline this run).

| ID | wire B | u | SBO (real+decoy) | READ | CRC boundaries | split |
|---|---|---|---|---|---|---|
| C01 | 35 | 21 | 1 (0 decoy) | G1V2 N=11 (0x00) | 10/28/35 | 10+25 |
| C02 | 35 | 21 | 1 (0 decoy) | G10V2 N=11 (0x00) | 10/28/35 | 10+25 |
| C03 | 49 | 33 | 2 (1 decoy) | G1V2 N=23 (0x00) | 10/28/46/49 | 28+21 |
| **C04** | 49 | 33 | 2 (1 decoy) | **G10V2 N=23 (0x00)** | 10/28/46/49 | 28+21 |
| **C05** | 61 | 45 | 3 (2 decoy) | **G30V1 N=7 (0x00)** | 10/28/46/61 | 28+33 |
| C06 | 61 | 45 | 3 (2 decoy) | G20V1 N=7 (0x00) | 10/28/46/61 | 28+33 |
| C07 | 61 | 45 | 3 (2 decoy) | G1V2 N=35 (0x00) | 10/28/46/61 | 28+33 |
| C08 | 61 | 45 | 3 (2 decoy) | G10V2 N=35 (0x00) | 10/28/46/61 | 28+33 |
| C09 | 75 | 57 | 4 (3 decoy) | G1V2 N=47 (0x00) | 10/28/46/64/75 | 46+29 |
| C10 | 75 | 57 | 4 (3 decoy) | G10V2 N=47 (0x00) | 10/28/46/64/75 | 46+29 |
| C11 | 89 | 69 | 5 (4 decoy) | G1V2 N=59 (0x00) | 10/28/46/64/82/89 | 46+43 |
| C12 | 89 | 69 | 5 (4 decoy) | G10V2 N=59 (0x00) | 10/28/46/64/82/89 | 46+43 |

Full 16-column table for all 118 intersections (Tier-1 + Tier-2) is in
`candidates.csv` / `candidates.json`.

## The arithmetic obstruction (honest negative results)

With the natural start-stop encoding, fixed overhead `A = 10`, so a point-size-`s`
object hits target `u` only when `(u - 10)` is divisible by `s`. The SBO grid gives
`u - 10 in {11, 23, 35, 47, 59}`.

| per-point `s` | objects | `(u-10) mod s` | intersects at |
|---|---|---|---|
| 1 | G1V2, G10V2 | always 0 | every K (1..5) |
| 5 | G30V1, G20V1 | {0,1,2,3,4} | **only K=3** (N=7) |
| 3 | G30V2, G20V2 | always 2 | **never** |
| 4 | G30V3, G20V5 | always 3 | **never** |
| 2 | G30V4, G20V6 | always 1 | **never** |

So 16-bit analog, no-flag analog, and their counter twins **cannot** natively land
on the SBO grid with the minimal encoding. The obstruction is a fixed residue: the
targets are all odd (kills `s=2`), all `≡ 2 (mod 3)` (kills `s=3`), all `≡ 3
(mod 4)` (kills `s=4`).

## Residue-class engineering (Tier-2, works but forced)

Changing the fixed overhead `A` shifts the residue and can create intersections
the minimal encoding cannot reach. This is real and the solver enumerates it
(106 Tier-2 rows), but each lever is an encoding a relay would not emit naturally:

- **2-byte start-stop range** (`0x01`, `A=12`): `u-12 in {9,21,33,45,57}` becomes
  divisible by 3, so **G30V2/G20V2 (16-bit analog) now hits every K**. Cost: the
  outstation only emits a 2-byte range when point indices reach >= 256, so this
  demands high-index configured points.
- **Limited-quantity count** (`0x07`, `A=9`): `u-9 in {12,24,36,48,60}` is all
  even, so **`s=2` and `s=4` objects now intersect**. Cost: count qualifiers are a
  request form; using them in a static response is atypical.
- **Indexed count** (`0x17`) on a static read: adds a 1-byte prefix per point, so
  G30V1 shifts to `u = 9 + 6N` and hits every K. Cost: indexed is the natural
  qualifier for **event/Class** polls, not a static integrity read.

Recommendation: keep Tier-2 as a size-math fallback only. Prefer Tier-1, where
both sides use the encoding the relay actually emits.

## CRC-boundary segmentation (for the switch)

After choosing a common size `S`, the switch applies the **same** deterministic,
byte-preserving split to both READ and SBO responses. Boundaries come from parsed
frame structure (`crc_boundaries(u)`), not from packet length. For the selected
sizes:

- `S = 49` (C04): boundaries `10, 28, 46, 49`; prefer the balanced cut `[28, 21]`
  over `[46, 3]`.
- `S = 61` (C05): boundaries `10, 28, 46, 61`; balanced cut `[28, 33]`.

`test_length_synth.py` splits real serialized frames at these boundaries and
confirms `b"".join(chunks) == original` for K=1..3 (byte preservation).

## Mandatory hardware prerequisite (no action taken this run)

The decoy CROBs are odd-index output points. Before any physical experiment, each
decoy index must be **proven physically disconnected or unmapped from breaker
control** at the relay, and the index must be configured at both endpoints. This
run is software-only: no relay writes, no SELECT/OPERATE, no P4 load. OpenDNP3
acceptance and SEL-751 point-map compatibility remain TBD and are the next gate.

## Reproduce

```bash
cd defense4/size/native_parity
python3 test_length_synth.py        # 87 checks, exit 0
python3 length_synth.py --emit      # prints all 118 intersections; writes json/csv
```
