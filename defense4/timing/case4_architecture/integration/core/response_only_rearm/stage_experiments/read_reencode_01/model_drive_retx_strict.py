"""retx_passthrough_01/model_drive_retx.py for the strict-response policy (controls native).

The retained driver hardcodes the master-visible frontier after the SELECT response as 959 + 58 = 1017
(the padded control image). Under the strict policy that response stays 37 octets, so the master's
OPERATE acknowledges 959 + 37 = 996 and the OPERATE response starts there. This wrapper replaces exactly
those two literals and runs the driver unchanged otherwise. Use it through model_drive_oracle.py with
CASE4_STRICT_CONTROLS=1:

  launch_model.sh ... -d model_drive_oracle.py -- <abs path of this file>
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE.parent / 'retx_passthrough_01/model_drive_retx.py'
EDITS = (('operate = vectors.packet(24, 156, 1017, payload=vectors.native_select(1, 4))',
          'operate = vectors.packet(24, 156, 996, payload=vectors.native_select(1, 4))'),
         ('operate_image = vectors.packet(24, 1017, 191, reverse=True, payload=image)',
          'operate_image = vectors.packet(24, 996, 191, reverse=True, payload=image)'))

source = TARGET.read_text()
for old, new in EDITS:
    assert source.count(old) == 1, old
    source = source.replace(old, new)
assert '1017' not in source
code = compile(source, str(TARGET) + ' [strict frontier]', 'exec')
exec(code, {'__name__': '__main__', '__file__': str(TARGET)})
