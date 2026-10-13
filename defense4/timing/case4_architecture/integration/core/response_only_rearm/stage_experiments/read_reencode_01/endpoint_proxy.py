"""pad58b_proxy.py with the strict-response policy: READ responses re-encoded (reencode.py), every
other frame (SELECT/OPERATE echoes included) forwarded byte-for-byte. Same two-connection relay,
same JSONL tee; only the per-frame decision differs."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE.parents[5] / 'framework/size/endpoint_gate'
sys.path[:0] = [str(HERE), str(GATE)]
import pad58b_proxy  # noqa: E402
import reencode  # noqa: E402


def maybe_reencode(frame):
    try:
        image = reencode.reencode_frame(frame)
    except ValueError:          # StdError included: malformed frames pass through untouched
        image = None
    return (image, 'read') if image is not None else (frame, 'passthrough')


pad58b_proxy.maybe_pad = maybe_reencode

if __name__ == '__main__':
    raise SystemExit(pad58b_proxy.main())
