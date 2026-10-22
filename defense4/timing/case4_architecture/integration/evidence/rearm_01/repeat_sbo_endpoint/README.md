# Repeated-SBO endpoint

`build_endpoint.py` builds two binaries against the pinned OpenDNP3 4648fcb library (sha256 `6b99199e…9c72`) and
records every source, binary and library hash in `build/build_manifest.json`:

- `case4_socket_gate_pad58b` from `sources/SocketGatePad58B.cpp`: the pinned record, rebuilt byte-identical
  (`8d78cf2f…0553`). Neither the source nor the binary changed.
- `case4_socket_gate_read_schedule` from `sources/SocketGateReadSchedule.cpp`: the same fork, plus the opt-in READ-class
  schedule below. The manifest records it under `read_schedule_endpoint`.

## READ-class schedule (2026-10-21)

The schedule is test-workload preparation only. It lets the hardware fixture issue every declared READ class,
interleaved with SELECT/OPERATE on one connection.

| control | side | values | unset |
|---|---|---|---|
| `CASE4_READ_SCHEDULE` | master | `rotate4` | the existing range READ in every slot |
| `CASE4_DB` | outstation (and master, for its fixture check) | `base`, `large` | the existing 23-point BOS database |

When `CASE4_READ_SCHEDULE` is set on the master, `CASE4_DB` must be set there too. Give both endpoints the same
`CASE4_DB`. With both controls unset, every request and response byte, and the TCP segmentation, is the existing
binary's. This was checked on loopback in `loopback_evidence_20261021/a_*` and `a2_*`, and
`tests/test_read_schedule.py` checks it again.

**Fixed order.** Every READ on the connection is one slot, k = 0, 1, 2, …. The leading `read-count` READs come
first, then the READ after each SELECT/OPERATE cycle. Slot k issues `ORDER[k mod 4]`, where
ORDER = `range, analog, class0, integrity`:

| class | request (OpenDNP3 call) | request objects |
|---|---|---|
| range | the existing READ (`read-range` 8 or 16) | G10V2 q0x00 (or q0x01) 0–22 |
| analog | `ScanRange(G30V0, 0, 20)` | G30V0 q0x01 0–20 |
| class0 | `ScanClasses(Class0)` | G60V1 q0x06 |
| integrity | `ScanClasses(AllClasses)` | G60V2, G60V3, G60V4, G60V1 q0x06 |

**Counts per trial.** One trial has T = read-count + `CASE4_SBO_CYCLES` READs. Class j (0 = range … 3 = integrity)
is issued floor(T/4) + (1 if j < T mod 4 else 0) times. The Gate-2 shape (1 leading READ, 64 cycles, T = 65) gives
range 17, analog 16, class0 16 and integrity 16, alongside 64 SELECT and 64 OPERATE. The SELECT/OPERATE count,
on-times, start delay, read pause and gap are unchanged.

**Databases.** The fixture is the one in `full_read_01/endpoint/FullReadGate.cpp`: BI G1 0–15, BOS G10 0–22 (the
existing seed), AI G30 0–20, and counters G20 0–7. `large` extends AI to 0–41.

**Sizes measured on loopback** (2026-10-21, `loopback_evidence_20261021/b_rotate4_{base,large}`; all link CRCs are
valid and every exchange of a class has the same shape):

| class | request octets | base: response link frames (TCP segments) | large: response link frames (TCP segments) |
|---|---|---|---|
| range | 20 | 49 (49) | 49 (49) |
| analog | 22 | 141 (141) | 141 (141) |
| class0 | 18 | 247 (247) | 292 + 85 = 377 (292, 85) |
| integrity | 27 | 247 (247) | 292 + 85 = 377 (292, 85) |
| SELECT / OPERATE | 35 | 37 (37) | 37 (37) |

On the large DB, class0 and integrity are naturally segmented: two transport segments, FIR then FIN, in two link
frames. Every response carries IIN 0x9000.

**Records.** The master's JSON gains these fields:

- `read_schedule`, `db` and `reads_per_class` (issued and succeeded counts).
- `read_commands`: one append-only record per issued READ, with slot, class, function `READ` (1), the request objects,
  the issue and completion times, the decoded response headers, `response_apdu_octets` and `response_link_octets`,
  a fixture match, and success. The two octet counts are derived from the decoded headers (`length_basis`); the
  capture is the authority. On loopback they equal the captured lengths for every READ.
- `class` on each entry of `reads`, and `read_class` on each cycle.

In `reads` and `cycles`, `matches_seed` and `read_matches_seed` now mean that the scan equals the fixture of its
class. For range that is still the 23-point seed. The outstation JSON gains `db`.

**Loopback check.** `loopback_capture.py run|decode|compare` runs both endpoints in `unshare -rn` with dumpcap on
`lo`. It decodes the capture with `read_complete_01`'s `capture.py` and `dnp3_std.py`.

## Two-READ-target schedules (2026-10-22)

The schedule binary adds a fifth READ class and three schedules. With none of the new controls set, the wire bytes
and records are unchanged (`test_unset_schedule_is_the_existing_workload_on_the_wire`, rotate4 tests).

- **`mixed`**: ONE READ request carrying two object headers, `Scan({Range8(1,2,0,15), Range8(30,1,0,7)})`
  (G1V2 binary inputs 0–15 and G30V1 analog inputs 0–7, base database). It is not two READs and not a binary-only READ.
- **Schedules** (`CASE4_READ_SCHEDULE`; base database only): `mixed_full` alternates mixed and integrity over every
  READ slot (mixed, SELECT, OPERATE, integrity, SELECT, OPERATE, ...); `mixed` and `full` issue one class only, for
  recovery blocks that must isolate a class.
- **`CASE4_PAD_EXPECT=<class>=<n>[,...]`** (master): the padding a switch is declared to add. The check is strict.
  A padded READ fails unless all of the following hold:
  - The original points equal the class fixture (values and flags).
  - No index repeats, for any object type.
  - For mixed, integrity and class0, the original headers match the class's native header structure: group and
    variation, qualifier and object count of every header, in order.
  - The padding is exactly n G1V2 points at 1024..1024+n-1, each with value 0 and flags 0x00, in one q0x01 header
    placed before every original header.

  A class with no declaration must contain no added point, so a padding-off arm fails on any padding. Declaring a
  class the schedule never issues is rejected.

  The master never sees the response's IIN or its link and transport octets. Those are checked only by the capture
  readout.

  The record changes as follows:
  - Each READ gains `padding_expected` and `padding_points`.
  - Each response header gains `reserved`.
  - The top level gains `pad_expect`.
  - `response_*_octets` count the original headers only, so they give the native size.

  With no new control set, the extra keys are the only change to the record.
- **`CASE4_FIXTURE_VARIANT=0..9`** (both endpoints; default 0 keeps the existing values): shifts the BI pattern and
  the AI and counter values. Odd values also add the RESTART quality bit (0x02) to the BI/AI/counter flags. Focused
  cases use it to show that no consumer depends on one capture's measurement bytes.

Measured on loopback (base database, variants 0 and 1, `read_complete_01/evidence/m1_two_read_01/native_capture_v*`):

| class | request octets | response octets: link frame (TCP segment) | response headers |
|---|---|---|---|
| mixed | 25 | 91 (91) | G1V2 q0x00 ×16, G30V1 q0x00 ×8 |
| integrity | 27 | 247 (247) | G1V2 ×16, G30V1 ×21, G20V1 ×8, G10V2 ×23 (q0x00) |

The padded encodings (91 → [50, 91] = 141, 247 → [24, 247] = 271) are accepted live by the master's strict check,
with the stream passing through a software padding proxy. Every rejection rule has a negative case:
- padding added but not declared, or declared but missing
- wrong padding count
- a changed original value
- padding at the wrong index, with non-zero flags, after the originals, in a header that also carries original
  indices, or encoded as G1V1
- a repeated analog point
- reordered original headers

See `read_complete_01/software/live_two_read.py` and `read_complete_01/evidence/m1_two_read_01/summary.json`. With
`rotate4` and variant 0, the request and response streams and the TCP segmentation are byte-identical to the
pre-change build, on both databases (`m1_two_read_01/rotate4_unchanged_vs_head.json`).
