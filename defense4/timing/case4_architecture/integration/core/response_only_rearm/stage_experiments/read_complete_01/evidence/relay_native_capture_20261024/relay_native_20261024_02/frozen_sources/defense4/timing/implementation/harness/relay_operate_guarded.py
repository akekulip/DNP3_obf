"""Guarded 2-CROB SELECT/OPERATE builder for the physical SEL-751 BOR run.

Safety contract (see sel_isolation_audit/40_isolation_fanout_trace.md):
  * OPERATE/SELECT may target ONLY DNP3 Binary-Output indices in AUTHORIZED_POINTS
    = {1, 3}  (-> remote bits RB02, RB04), which the isolation audit PROVED have
    empty fanout (they drive no output, TRIP, CLOSE, or protection equation).
  * Index 6 (-> RB07) drives OUT102 = breaker CLOSE in setting groups 2/3. It, and
    every index outside {1, 3}, is REFUSED here. The guard is the innermost step of
    frame construction, so no control frame for a forbidden point can be built at all.

This module builds frames only; it never opens a socket. The caller sends bytes.
"""

from dnp3_wire import (
    CROB_BODY, build_frame, deframe, parse_request,
    OUTSTATION_ADDR, MASTER_ADDR, FUNC_SELECT, FUNC_OPERATE,
)

# The ONLY indices any control frame in this run may target.
AUTHORIZED_POINTS = frozenset({1, 3})
# Named forbidden index for a clear error, per the isolation audit.
_BREAKER_CLOSE_INDEX = 6  # BO index 6 -> RB07 -> OUT102 (breaker CLOSE, groups 2/3)


class ForbiddenPointError(PermissionError):
    """Raised when a control frame would target a point outside AUTHORIZED_POINTS."""


def _assert_authorized(indices) -> None:
    """Refuse unless EVERY index is in AUTHORIZED_POINTS. No frame is built otherwise."""
    idxs = list(indices)
    if not idxs:
        raise ForbiddenPointError("refused: empty point list")
    for idx in idxs:
        if idx not in AUTHORIZED_POINTS:
            extra = " (RB07 -> OUT102 breaker CLOSE)" if idx == _BREAKER_CLOSE_INDEX else ""
            raise ForbiddenPointError(
                "refused: DNP3 BO index %r not in authorized set %s%s"
                % (idx, sorted(AUTHORIZED_POINTS), extra)
            )


def build_guarded_crob_object(indices=(1, 3)) -> bytes:
    """G12 V1, qual 0x17, one CROB per authorized index. Guard runs BEFORE any bytes exist."""
    _assert_authorized(indices)
    idxs = list(indices)
    body = bytes([0x0C, 0x01, 0x17, len(idxs)])
    for idx in idxs:
        body += bytes([idx]) + CROB_BODY
    return body


def build_guarded_request(func: int, app_seq: int, indices=(1, 3)) -> bytes:
    """Build a guarded 2-CROB SELECT (0x03) or OPERATE (0x04) frame for {1,3} only."""
    if func not in (FUNC_SELECT, FUNC_OPERATE):
        raise ValueError("only SELECT/OPERATE may be issued")
    _assert_authorized(indices)  # belt-and-suspenders: guard again at request level
    transport = 0xC0 | (app_seq & 0x0F)
    app_ctrl = 0xC0 | (app_seq & 0x0F)
    userdata = bytes([transport, app_ctrl, func]) + build_guarded_crob_object(indices)
    return build_frame(userdata, dst=OUTSTATION_ADDR, src=MASTER_ADDR, ctrl=0xC4)


def build_select(app_seq: int, indices=(1, 3)) -> bytes:
    return build_guarded_request(FUNC_SELECT, app_seq, indices)


def build_operate(app_seq: int, indices=(1, 3)) -> bytes:
    return build_guarded_request(FUNC_OPERATE, app_seq, indices)


def assert_frame_targets_authorized(frame_bytes: bytes) -> list:
    """Post-build sentinel: deframe a built request and confirm its points ⊆ {1,3}.
    Returns the parsed point list; raises if anything outside the authorized set slipped in."""
    frames = list(deframe(frame_bytes))
    if not frames:
        raise ForbiddenPointError("refused: no DNP3 frame found in built bytes")
    _total, userdata = frames[0]
    info = parse_request(userdata)
    pts = info["points"] if info else []
    _assert_authorized(pts)
    return pts
