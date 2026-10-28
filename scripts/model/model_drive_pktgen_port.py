"""Timer token byte format used by model admission and stale-token probes."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / 'checks'), str(Path(__file__).resolve().parent.parent / 'hardware')]
from model_driver import Model as Model, Report as Report  # noqa: E402
import port_map

__all__ = ['Model', 'Report', 'PKTGEN_RETURN', 'FRONT', 'PORTS', 'token']

PKTGEN_RETURN = port_map.PKTGEN_RETURN
FRONT = 164                      # a pipe-1 front-panel port (164-191 are enabled on the switch)
PORTS = [9, 64, PKTGEN_RETURN, FRONT]


def token(gen, packet_id, profile, pipe=1):
    """Tofino-1 pktgen timer header (pad(3)=0 | pipe(2) | app(3), pad, batch, packet) + padding."""
    return bytes([pipe << 3 | profile]) + bytes([profile]) + struct.pack('!HH', gen, packet_id) + bytes(58)

