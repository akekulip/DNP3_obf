#!/usr/bin/env python3
"""Import the frozen frame builders and their safety guard, unchanged.

The guard in `implementation/harness/relay_operate_guarded.py` is the innermost step of
control-frame construction: it refuses any DNP3 binary-output index outside {1, 3}, and index
6 (remote bit RB07, which drives OUT102 breaker CLOSE) by name. That contract is not
reimplemented here. It is imported from the frozen file so the authorized set and the refusal
path stay byte-identical to the ones the campaign ran under.

The frozen modules import each other by bare name, so their directory is placed on `sys.path`
and nothing in it is modified.
"""
from __future__ import annotations

import os
import sys

FROZEN_HARNESS = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 os.pardir, "implementation", "harness"))

if not os.path.isdir(FROZEN_HARNESS):
    raise RuntimeError("frozen harness directory not found at %s" % FROZEN_HARNESS)
if FROZEN_HARNESS not in sys.path:
    sys.path.insert(0, FROZEN_HARNESS)

from relay_operate_guarded import (                                        # noqa: E402
    AUTHORIZED_POINTS, ForbiddenPointError, assert_frame_targets_authorized,
    build_operate, build_select,
)
from relay_read_g10_23 import read_frame, START as READ_START, STOP as READ_STOP  # noqa: E402

__all__ = ["AUTHORIZED_POINTS", "ForbiddenPointError", "assert_frame_targets_authorized",
           "build_operate", "build_select", "read_frame", "READ_START", "READ_STOP",
           "FROZEN_HARNESS"]
