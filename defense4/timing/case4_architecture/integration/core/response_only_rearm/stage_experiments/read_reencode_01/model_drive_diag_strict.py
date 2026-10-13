"""combined_nt_diag_01/model_drive_diag.py for the strict-response policy (controls native).

The retained driver hardcodes the master-visible frontier after the second connection's SELECT response
as 7059 + 58 = 7117 (padded control image) and after its OPERATE response as 7117 + 58 = 7175. Under the
strict policy both control responses stay 37 octets: 7059 + 37 = 7096 and 7096 + 37 = 7133. This wrapper
replaces exactly those three literals and runs the driver unchanged otherwise. Use it through
model_drive_oracle.py with CASE4_STRICT_CONTROLS=1. The result JSON's driver_sha256 is the retained file's;
this wrapper's own hash identifies the edit.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE.parent / 'combined_nt_diag_01/model_drive_diag.py'
EDITS = (('operate = vectors.packet(24, 4056, 7117, payload=vectors.native_select(1, 4))',
          'operate = vectors.packet(24, 4056, 7096, payload=vectors.native_select(1, 4))'),
         ('vectors.packet(24, 7117, 4091, reverse=True, payload=image)',
          'vectors.packet(24, 7096, 4091, reverse=True, payload=image)'),
         ("step('qualified_RST', vectors.packet(20, 4091, 7175), vectors.packet(20, 4091, 7124))",
          "step('qualified_RST', vectors.packet(20, 4091, 7133), vectors.packet(20, 4091, 7124))"))

source = TARGET.read_text()
for old, new in EDITS:
    assert source.count(old) == 1, old
    source = source.replace(old, new)
assert '7117' not in source and '7175' not in source
exec(compile(source, str(TARGET) + ' [strict frontier]', 'exec'), {'__name__': '__main__', '__file__': str(TARGET)})
