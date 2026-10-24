# Relay native READ baseline and derived padded shapes — 2026-10-24 (SEL-751, READ-only)

Evidence **tier 3** (physical SEL-751 through the switch). This is the native READ baseline the
2026-10-24 directive asks for, and it removes the PROVISIONAL mark from the two relay READ targets:
both `91 -> 141` and `134 -> 158` are now derived from real relay bytes, not from a measured length.

## What ran

`active_harness/relay_native_baseline.py --live --each 3`, from Vision root namespace
`192.168.10.1` to the relay `192.168.10.7:20000`, one persistent TCP connection, SELECT/OPERATE
impossible (both requests assert function 0x01 READ; the driver can emit nothing else). The switch
was running the production `case4_response_path` (SDK 9.13.2, cold) — the passthrough path, which
forwards unchanged, so what arrived at Vision is the relay's native response. OK 6/6.

Two READ workloads (the two-READ-target profile, `protocol/hw_vepa/read_classes.classify_request`):

| workload  | request objects                         | native wire | link LEN | frames | response objects (g,v,lo..hi) |
|-----------|-----------------------------------------|-------------|----------|--------|-------------------------------|
| mixed     | G1V2 q00 0..15, G30V1 q00 0..7          | **91 B**    | 76       | 1      | G1V2 0..15, G30V1 0..7        |
| integrity | G60 V2/V3/V4/V1 q06 (all-classes poll)  | **134 B**   | 115      | 1      | G1V2 0..15, G10V2 0..31, G30V4 0..20 |

Each response is a single CRC-valid link frame, transport FIR|FIN (one segment), application
function 0x81, IIN 0x0080. The native **lengths** are stable across the three repetitions (91, 134);
the **content** varies (live measurement values, flags, rolling app sequence), which is exactly the
property the padder needs — the derived constants must not depend on any measurement.

This confirms the 2026-10-23 measurement (mixed 91, integrity 134) and shows the relay's integrity
database is 134 B, not the software outstation's 247 B — so the `247 -> 271` full-READ target does
not apply to the relay.

## Derived padded shapes (general_read_padding.pad_read, reserved indices 1024..4095)

Run on each of the three real natives per workload; every declared constant is identical across the
three content-varying samples (`derived_shapes_20261024.json`, `constants_invariant: true`):

| workload  | native | target | added | points | construction | prefix frame | frames out |
|-----------|--------|--------|-------|--------|--------------|--------------|------------|
| mixed     | 91     | 141    | 50    | 26     | prefix       | 1            | [50, 91]   |
| integrity | 134    | 158    | 24    | 4      | prefix       | 1            | [24, 134]  |

`134 -> 158` is the smallest reachable nonshrinking target (prefix floor is +24: 134+24 = 158;
135..157 are unreachable). It uses the same +24 / 4-point prefix construction as the software full
`247 -> 271`, differing only in the native link LEN (115) and the link-header CRC delta — both read
from the packet, not invented.

## Corrections folded in (Philip, 2026-10-24)

1. **Reusable master** validates these mixed/integrity READs and reassembles the DNP3 transport
   layer (`active_harness/read_requests.py`, `dnp3_codec.TransportAssembler`). Used here.
2. **TCP splitting is not DNP3 segmentation.** The driver reassembles link frames (Reassembler)
   and the transport layer (TransportAssembler) separately; TCP boundaries are never read as DNP3
   segmentation. (Both responses happen to be one link frame, one transport segment.)
4. **Capture is at Vision, which is one side of the switch.** For this NATIVE baseline the switch
   production path forwards unchanged, so the Vision-side bytes are the relay's native response and
   are sufficient to derive the shapes. A two-sided switch capture (relay-facing egress) is still
   required for the formal timing evidence of a padded run and is NOT claimed here.

Targets 141 and 158 are therefore **derived**, no longer provisional. The SBO shape is a separate,
later step and is not part of this READ-only baseline.

## Files

- `native_20261024.json` — per-transaction raw request + response wire bytes, link/transport decode, lengths.
- `derived_shapes_20261024.json` — pad_read derivation on each real native, the invariant constants, the response layouts.
- `../../../../../../active_harness/relay_native_baseline.py` — the READ-only driver (dry-run default; live needs DEFENSE4_HW_AUTHORIZED=1).

Derivation interpreter: `$RESEARCH_PYTHON` (general_read_padding and its std/fullread deps).
