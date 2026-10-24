"""Strict software wire model for Case 4's Option B' (whitelisted-qualifier) pattern.

`SELECTED_PATTERN.md`'s 2026-10-08 "later the same day" update retires Option B
(`case4_pad58.py`, G41V2/qualifier-0x27): the pinned OpenDNP3 library
(`cpp/lib/src/gen/QualifierCode.cpp`) implements exactly seven qualifier codes
-- 0x00, 0x01, 0x06, 0x07, 0x08, 0x17, 0x28 -- and 0x27 is not one of them.
`APDUParser::ParseQualifier`'s `default:` branch returns UNKNOWN_QUALIFIER for
any other byte, and `APDUParser::Parse`'s two-pass design aborts the ENTIRE
fragment on a non-OK result, destroying the real native data too.

This module (Option B') is a new sibling, not an edit to `case4_pad58.py`. It
reuses only `case4_padding.build_frame`/`decode_frame`, the same way
`case4_pad58.py` itself does, and re-states (does not import) the small native-
profile constants that module also carries, since they describe this effort's
fixed READ/control eligibility test, not a public API `case4_pad58.py` exports.

Byte arithmetic was independently re-derived against the pinned library's own
source before being used here (not taken from `SELECTED_PATTERN.md`'s arithmetic
on faith):

- `cpp/lib/src/app/parsing/APDUParser.cpp`'s `ParseHeader` runs a whitelist
  check (`IWhiteList::IsAllowed`) before dispatch, and `ParseQualifier`'s
  switch then routes 0x07/0x08 to `CountParser` and 0x17/0x28 to
  `CountIndexParser`.
- `CountParser::ParseCountOfObjects` (`cpp/lib/src/app/parsing/CountParser.cpp`)
  only recognizes Group50/51/52 for qualifiers 0x07/0x08 when the parse
  expects contents (`ParserSettings::Default()`, used for every response this
  project cares about) -- G41V2/V3 and G12V1 are NOT in that switch, so 0x07/0x08
  on an Analog Output Block or CROB filler hits `default:` and returns
  `ParseResult::INVALID_OBJECT_QUALIFIER`, aborting the whole fragment exactly
  like 0x27 did. **0x07/0x08 are therefore unusable for this filler at all,
  not merely a corner case** -- a finding beyond what `SELECTED_PATTERN.md`
  itself assumed when it floated them as an option for the READ empty-header
  construction.
- `CountIndexParser::ParseCountOfObjects` (same directory) DOES list
  `Group41Var1`, `Group41Var2`, `Group41Var3`, `Group41Var4` and `Group12Var1`
  for qualifiers 0x17/0x28, so those four GV/qualifier combinations are the
  only ones this filler may use.
- For the CONTROL (SELECT/OPERATE) role, the master additionally runs this
  through `CommandSetOps::IsAllowed` (`cpp/lib/src/master/CommandSetOps.cpp`),
  which further restricts qualifier to {0x17, 0x28} and GV to
  {Group12Var1, Group41Var1..4} -- the same set `CountIndexParser` supports,
  so nothing CONTROL-specific is lost by using an indexed qualifier.
- Per-point sizes come directly from each type's own `Size()` static method
  in `cpp/lib/src/gen/objects/Group41.h`/`Group12.h`: G41V2 (16-bit AO)
  content = 3 bytes (value int16 + status), G41V3 (32-bit float AO) content =
  5 bytes (value float32 + status), G12V1 (CROB) content = 11 bytes. A point's
  wire size is `content + index_width` (index_width = 1 for 0x17, 2 for 0x28);
  header size is 4 bytes for 0x17 (1-byte count) and 5 bytes for 0x28 (2-byte
  count).

Solving `header + point*k = target` for every whitelisted (GV, qualifier)
combination and k an integer >= 1:

- **CONTROL needs 19 bytes.** G41V3 at qualifier 0x28 (header 5B, point
  2+4+1=7B) gives `5 + 7*k = 19` exactly at k=2 (two real analog points, no
  empty-count construction needed). No other whitelisted combination reaches
  19 with k>=1 (checked exhaustively: G41V1/V2/V4 and G12V1 at either
  qualifier all leave a non-integer k). **Empirically confirmed against the
  real pinned master/outstation**: the padded SELECT echo is accepted, the
  master emits a real OPERATE, and the second round trip completes a genuine
  SBO actuation (`endpoint_gate/TestCase4Pad58B.cpp`'s control test case).
- **READ needs 9 bytes, and the first design here for it was wrong -- caught
  only by actually running it against the real master, not by source review
  alone.** No single whitelisted-qualifier object, of any GV this library
  supports via `CountIndexParser` (not just G41, the full list:
  Group2/4/11/12/13/22/23/32/41/42/43/50Var4), reaches 9 with k>=1 real
  points -- the smallest possible single-object encoding is a 1-byte-content
  type at 0x17 (4 + 2k) or 0x28 (5 + 3k), and neither solves for an integer
  k>=1 at 9. The arithmetic-only candidate this module first shipped with
  was two header-only, count=0 objects (a 4-byte 0x17 header plus a 5-byte
  0x28 header, 4+5=9). **That candidate is wrong**: `NumParser::ParseCount`
  (`cpp/lib/src/app/parsing/NumParser.cpp`) explicitly rejects a parsed count
  of zero with `ParseResult::COUNT_OF_ZERO` -- a non-OK result that, exactly
  like Option B's `UNKNOWN_QUALIFIER`, aborts the whole two-pass
  `APDUParser::Parse` before pass 2 ever dispatches anything, so the real
  23-point READ data that precedes the filler is lost too (confirmed
  empirically: `points_received_after_padded=0` on the first --pad58b run).
  **The qualifier actually used here instead is `0x06` (`ALL_OBJECTS`)**,
  which `APDUParser::ParseQualifier` routes to `HandleAllObjectsHeader`
  (`cpp/lib/src/app/parsing/APDUParser.cpp`) -- a path that never calls
  `NumParser` at all and consumes no bytes beyond the 3-byte object header
  itself (`ObjectHeaderParser::ParseObjectHeader` reads exactly group+
  variation+qualifier, nothing else). Three such headers -- G41V1, G41V2,
  G41V3, each qualifier 0x06 -- are 3+3+3 = 9 bytes exactly, carry no count
  field and no point data, and cannot hit `COUNT_OF_ZERO` because the count
  parser is never invoked for this qualifier. `IAPDUHandler`'s base class has
  no `ProcessHeader(const AllObjectsHeader&)` override pulling in semantics
  either `MeasurementHandler` or `CommandSetOps` care about, so (as for the
  indexed fillers above) it is ignored per-header rather than failing the
  parse. **Empirically confirmed**: all 23 real READ points are delivered
  (`points_received_after_padded=23`) with this construction.

On the master's own RESPONSE-side dispatch, neither role's filler is ever
reconstructed into "real" measurements: for READ, `MeasurementHandler`
(`cpp/lib/src/master/MeasurementHandler.h`) does not override `ProcessHeader`
for the `AnalogOutputInt16`/`AnalogOutputFloat32` (G41Vx) target types, so the
`IAPDUHandler` base class's default `ProcessUnsupportedHeader()` runs instead
-- sets IIN `FUNC_NOT_SUPPORTED` on this header only, does not fail the parse.
For CONTROL, `CommandSetOps::ProcessAny` rejects any header whose zero-based
position in the fragment (`header.headerIndex`) is `>= commands->m_headers.size()`
with `IINBit::PARAM_ERROR` -- again per-header, not fragment-fatal -- which is
exactly why this filler must be a SEPARATE, APPENDED object (header index 1
when the native echo is header index 0), never a rewrite of the native header
in place (that different mechanism is what killed Option A's qualifier-rewrite
candidate: `TypedCommandHeader::ApplySelectResponse`'s
`if (commands.Count() > this->records.size()) return;` guard, which only
fires when the SAME header's own count exceeds the request's).

An inert filler point is an externally verified profile prerequisite, not a
property this byte codec can infer from an index or a value.
"""
from dataclasses import dataclass
import struct
from case4_padding import build_frame, decode_frame

# --- READ filler: three ALL_OBJECTS (qualifier 0x06) headers, 3 bytes each,
# no count field, no point data -- 3 + 3 + 3 = 9 bytes. The earlier design
# (two count=0 headers) is dead: NumParser::ParseCount rejects a parsed count
# of zero outright (ParseResult::COUNT_OF_ZERO), which aborts the whole
# fragment exactly like case4_pad58's qualifier 0x27 did. ALL_OBJECTS never
# calls NumParser at all, so it cannot hit that failure.
GROUP41_VAR1_ALL_OBJECTS = bytes([0x29, 0x01, 0x06])
GROUP41_VAR2_ALL_OBJECTS = bytes([0x29, 0x02, 0x06])
GROUP41_VAR3_ALL_OBJECTS = bytes([0x29, 0x03, 0x06])
READ_FILLER = GROUP41_VAR1_ALL_OBJECTS + GROUP41_VAR2_ALL_OBJECTS + GROUP41_VAR3_ALL_OBJECTS
assert len(READ_FILLER) == 9

# --- CONTROL filler: one G41V3 (32-bit float AO) object, qualifier 0x28, 2 points. ---
GROUP41_VAR3_QUAL28 = bytes([0x29, 0x03, 0x28])
CONTROL_FILLER_POINTS = 2

HEADER_READ23 = bytes.fromhex('0a02000016')   # G10V2, qualifier 0x00, range 0..22 (23 points) -- same native profile as case4_pad58
HEADER_CROB28 = bytes.fromhex('0c01280100')   # G12V1, qualifier 0x28, count 1 -- shared with case4_padding/case4_pad58

READ_NATIVE_LEN = 33
CONTROL_NATIVE_LEN = 23
PADDED_LEN = 42


@dataclass(frozen=True)
class AnalogFloatPoint:
    """One G41V3 (32-bit floating-point Analog Output Block) point: uint16 index
    (the 0x28 qualifier's own index width) + IEEE-754 float32 value + uint8
    status/flags -- 2 + 4 + 1 = 7 bytes, matching `Group41Var3::Size() == 5`
    (content only) plus the 2-byte 0x28 index prefix.
    """
    index: int
    value: float
    status: int

    def __post_init__(self):
        if not 0 <= self.index <= 0xffff:
            raise ValueError('G41V3 qualifier 0x28 index prefix is a uint16')
        if not isinstance(self.value, (int, float)):
            raise ValueError('G41V3 variation 3 analog value must be numeric')
        if not 0 <= self.status <= 0xff:
            raise ValueError('G41V3 status/flags is one byte')

    @property
    def packed(self):
        return struct.pack('<Hf', self.index, self.value) + bytes([self.status])


def _analog_float_object(points):
    """Build one G41V3/qualifier-0x28 object: 5-byte header + count*7 bytes."""
    if not 1 <= len(points) <= 0xffff:
        raise ValueError('G41V3 qualifier 0x28 count field is a uint16, at least 1 point')
    for p in points:
        if not isinstance(p, AnalogFloatPoint):
            raise ValueError('filler must be a sequence of AnalogFloatPoint')
    return GROUP41_VAR3_QUAL28 + struct.pack('<H', len(points)) + b''.join(p.packed for p in points)


def pad_read_response(frame):
    """Return (image, delta); unsupported input passes unchanged.

    Eligible only for the one supported READ profile this effort covers: a
    complete, CRC-valid frame holding a 23-point G10V2 response (qualifier
    0x00, range 0..22), one transport/application fragment, response
    function code 0x81 -- identical eligibility test to `case4_pad58`'s own.
    Unlike `case4_pad58.pad_read_response`, this filler carries no caller-
    supplied point data at all (three ALL_OBJECTS headers reach the exact
    9-byte gap; see module docstring for why no single indexed object with
    real point data can, and why the first count=0 design was wrong), so
    there is no `points` argument to validate or pass through.
    """
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != READ_NATIVE_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_READ23):
        return frame, 0
    image = build_frame(head, user + READ_FILLER)
    return image, len(image) - len(frame)


def unpad_read_response(image):
    """Pure structural inverse of pad_read_response.

    Raises ValueError on any image that is not itself a READ/whitelisted-
    qualifier two-empty-header padded construction, instead of silently
    returning a guess.
    """
    head, user = decode_frame(image)
    if (len(user) != PADDED_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_READ23 or
            user[READ_NATIVE_LEN:] != READ_FILLER):
        raise ValueError('not a case4_pad58b READ image')
    return build_frame(head, user[:READ_NATIVE_LEN])


def pad_control_response(frame, points):
    """Return (image, delta); unsupported input passes unchanged.

    Eligible for a complete, CRC-valid native SELECT/OPERATE echo: response
    function code 0x81 and the single native G12V1 CROB echo at qualifier
    0x28, count 1 (`case4_padding`'s own control-response shape, identical
    eligibility test to `case4_pad58.pad_control_response`). `points` must be
    exactly two AnalogFloatPoints -- the only whitelisted-qualifier
    construction that reaches the needed 19 bytes with real point data (see
    module docstring: G41V3/qualifier-0x28, header 5B + 2*7B = 19B). A
    different count is a caller contract violation, not an ineligible frame.
    """
    if len(points) != CONTROL_FILLER_POINTS:
        raise ValueError('control filler must carry exactly two analog points to reach 58 bytes')
    try:
        head, user = decode_frame(frame)
    except ValueError:
        return frame, 0
    if (len(user) != CONTROL_NATIVE_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_CROB28 or user[-1] != 0):
        return frame, 0
    image = build_frame(head, user + _analog_float_object(points))
    return image, len(image) - len(frame)


def unpad_control_response(image):
    """Pure structural inverse of pad_control_response.

    Raises ValueError on any image that is not itself a control/whitelisted-
    qualifier two-point padded construction, instead of silently returning a
    guess. Checks the filler's fixed object-header prefix (group, variation,
    qualifier, count) only -- not individual point payloads, which vary by
    caller -- the same granularity `case4_pad58.unpad_control_response` uses.
    """
    head, user = decode_frame(image)
    expected_header = GROUP41_VAR3_QUAL28 + struct.pack('<H', CONTROL_FILLER_POINTS)
    if (len(user) != PADDED_LEN or user[0] & 0xc0 != 0xc0 or
            user[1] & 0xf0 != 0xc0 or user[2] != 0x81 or
            user[5:10] != HEADER_CROB28 or user[22] != 0 or
            user[CONTROL_NATIVE_LEN:CONTROL_NATIVE_LEN + len(expected_header)] != expected_header):
        raise ValueError('not a case4_pad58b control image')
    return build_frame(head, user[:CONTROL_NATIVE_LEN])
