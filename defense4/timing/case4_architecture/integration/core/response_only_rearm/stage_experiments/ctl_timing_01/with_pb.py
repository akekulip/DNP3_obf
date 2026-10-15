"""Run an existing seg61_02 model driver against a piggyback-bound (m3) build with a real pb.

The seg61_02 drivers write t_Ingress.set_params without pb; the bfrt client then fills pb = 0, which the hardware
installer refuses. This wrapper adds CTL_PB (model ns) to every such write that lacks it, then runs the driver
named by CTL_TARGET_DRIVER unchanged.
"""
import os
import runpy
import sys
from pathlib import Path

target = Path(os.environ['CTL_TARGET_DRIVER'])
pb = int(os.environ['CTL_PB'])
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))          # integration/core
import model_driver  # noqa: E402

_set_default = model_driver.Model.set_default


def set_default(self, table, action, data=None):
    if action == 't_Ingress.set_params' and data is not None and 'pb' not in data:
        data = dict(data, pb=pb)
    return _set_default(self, table, action, data)


model_driver.Model.set_default = set_default
sys.argv = [str(target)]
runpy.run_path(str(target), run_name='__main__')
