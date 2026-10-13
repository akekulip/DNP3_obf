"""Run a retained model driver unchanged, with the READ oracle switched to the re-encoding.

The retained drivers take every expected padded READ frame from case4_pad58b.pad_read_response,
imported through the module cache. This wrapper replaces that one function with reencode.py before
the driver starts, so the same assertions check the re-encoded bytes. Control padding is untouched unless
CASE4_STRICT_CONTROLS=1, which makes the control oracle return the native frame (strict-policy builds).

  launch_model.sh -p OUT -o NEW -d model_drive_oracle.py -- <driver.py>
"""
import os
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[5] / 'framework/size')]
import case4_pad58b  # noqa: E402
import reencode  # noqa: E402


def pad_read_response(frame):
    image = reencode.reencode_frame(frame)
    if image is None:
        return frame, 0          # ineligible: native, as pad_read_response reports it
    return image, len(image) - len(frame)


def native_control_response(frame, points):
    return frame, 0              # strict policy: SELECT/OPERATE responses stay native


case4_pad58b.pad_read_response = pad_read_response
if os.environ.get('CASE4_STRICT_CONTROLS') == '1':
    case4_pad58b.pad_control_response = native_control_response

if __name__ == '__main__':
    target = Path(sys.argv[1]).resolve()
    sys.argv = [str(target)] + sys.argv[2:]
    runpy.run_path(str(target), run_name='__main__')
