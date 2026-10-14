"""pad58b_proxy.py relay with the 61-octet profile: each eligible response frame is replaced by its 61-octet image
(encode61.encode); a SELECT/OPERATE response image is three link frames written with ONE sendall, so it leaves as one
write on the master socket. Requests and ineligible frames are forwarded byte for byte."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE.parents[5] / 'framework/size/endpoint_gate'
sys.path[:0] = [str(HERE), str(GATE)]
import pad58b_proxy  # noqa: E402
import encode61  # noqa: E402


def maybe_encode(frame):
    try:
        image = encode61.read61(frame)
        if image is not None:
            return image, 'read'
        image = encode61.ctl61(frame)
        if image is not None:
            return image, 'control'
    except ValueError:
        pass
    return frame, 'passthrough'


pad58b_proxy.maybe_pad = maybe_encode

if __name__ == '__main__':
    raise SystemExit(pad58b_proxy.main())
