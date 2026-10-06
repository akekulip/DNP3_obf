"""Configuration profiles for the framework cases, with fail-closed activation and restoration.

Historical timing cases plus an offline Case 4 joint configuration. Case 4 activation is
blocked until a source-bound compiled schema and write mapping support the joint mechanism.
Mode numbers are read from the P4 source, not typed here. The program has no shaping field, so nothing in
this module can enable shaping; that is asserted from the compiled schema on every activation.
"""
from __future__ import annotations

import math
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_HOLD_MS = 40.0       # the control-plane clamp; a test asserts it equals timing_only_profile.MAX_D_A_MS


def _top():
    """The repository's admission binding. Imported lazily so this module also runs on the switch host, which has no checkout."""
    root = HERE.parents[3]
    if (root / "defense4").exists() and str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from defense4.timing.active_control import timing_only_profile as top   # noqa: WPS433
    return top

TICK_NS = 256
PARAMS, BOR, RELEASE = "tbl_params", "tbl_bor_params", "tbl_read_release_params"
A_PARAMS, A_BOR, A_REL = "Ingress.set_params", "Ingress.set_bor_params", "Ingress.set_read_release"
CASES = ("off", "combined", "ack_focused", "response_focused", "case4")
PADDING_PROFILES = ("crob_trailing_header_one_decoy",)
SPLIT_PROFILES = ("57_28_29", "49_28_21")


class ActivationError(RuntimeError):
    def __init__(self, message, record=None):
        super().__init__(message)
        self.record = record if record is not None else {}


def q(ns):
    return (int(ns) // TICK_NS) * TICK_NS


@dataclass(frozen=True)
class Profile:
    case: str
    d_a_ms: float = 0.0
    gap_ms: float = 1.0
    budget: int = 18000
    loop_ns: int = 1711            # token loop period: an estimate (H = budget x loop is not a wall-clock guarantee)
    connection_id: str = ""
    build_id: str = ""
    readiness_expiry_ms: float = 30.0
    heartbeat_request_us: float = 100.0
    completion_deadline_ms: float | None = None
    measured_heartbeat_max_us: float | None = None
    measured_drain_max_ms: float | None = None
    measured_release_max_us: float | None = None
    padding_profile: str = "crob_trailing_header_one_decoy"
    split_profile: str = "57_28_29"
    translation_capacity: int = 2


def hold_bound_ms(p):
    """Case 4 measured bound, or the historical token-horizon estimate.

    The legacy budget-times-loop result is retained for old profiles; it is not
    a measured wall-clock guarantee and cannot authorize the joint mechanism.
    """
    if p.case == "case4":
        measurements = (p.measured_heartbeat_max_us, p.measured_drain_max_ms,
                        p.measured_release_max_us, p.completion_deadline_ms)
        if any(v is None for v in measurements):
            return None
        # Request-anchored completion plus measured expiry service, release and drain.
        # A requested heartbeat interval and a nominal token loop are not measurements.
        return (max(p.readiness_expiry_ms, p.completion_deadline_ms, p.d_a_ms + p.gap_ms)
                + p.measured_heartbeat_max_us / 1000 + p.measured_release_max_us / 1000
                + p.measured_drain_max_ms)
    return max(p.d_a_ms, p.budget * p.loop_ns / 1e6)


def problems(p, consts):
    out = []
    if p.case not in CASES:
        return ["case %r is not one of %s" % (p.case, ", ".join(CASES))]
    for name in ("d_a_ms", "gap_ms", "loop_ns"):
        value = getattr(p, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            out.append("%s must be finite and non-negative" % name)
    if isinstance(p.budget, bool) or not isinstance(p.budget, int) or not (1 <= p.budget < 2 ** 32):
        out.append("budget out of range")
    if out:
        return out
    d, g = q(p.d_a_ms * 1e6), q(p.gap_ms * 1e6)
    if p.case == "off":
        return out
    if g == 0:
        out.append("gap truncates to 0 ns at the %d ns tick" % TICK_NS)
    if p.case == "combined" and d == 0:
        out.append("combined needs D_A > 0 (D_A = 0 is the ack_focused case)")
    if p.case in ("ack_focused", "response_focused") and d != 0:
        out.append("%s holds nothing for D_A; D_A must be 0, got %r ms" % (p.case, p.d_a_ms))
    if d + g >= 2 ** 31:
        out.append("D_A + gap exceeds the modular half-range")
    if p.case == "case4":
        for name in ("readiness_expiry_ms", "heartbeat_request_us"):
            value = getattr(p, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                out.append("%s must be positive and finite" % name)
        for name in ("completion_deadline_ms", "measured_heartbeat_max_us", "measured_drain_max_ms", "measured_release_max_us"):
            value = getattr(p, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not math.isfinite(value) or value <= 0):
                out.append("%s must be positive and finite when supplied" % name)
        if p.padding_profile not in PADDING_PROFILES:
            out.append("unsupported padding profile")
        if p.split_profile not in SPLIT_PROFILES:
            out.append("unsupported split profile")
        if isinstance(p.translation_capacity, bool) or not isinstance(p.translation_capacity, int) or p.translation_capacity != 2:
            out.append("Case 4 supports exactly two insertion boundaries")
        if out:
            return out
        if p.readiness_expiry_ms + p.gap_ms > MAX_HOLD_MS:
            out.append("readiness expiry plus gap exceeds the 40 ms policy cap")
        if p.completion_deadline_ms is not None and p.completion_deadline_ms < max(p.readiness_expiry_ms, p.d_a_ms) + p.gap_ms:
            out.append("completion deadline cannot truncate the requested readiness/ACK gap")
    bound = hold_bound_ms(p)
    if bound is not None and bound > MAX_HOLD_MS:
        out.append("worst-case hold %.3f ms exceeds the %.1f ms clamp" % (bound, MAX_HOLD_MS))
    return out


def plan(p, consts):
    """Ordered writes and the exact readback expected after each. The release block is disabled first and
    enabled last, so no step leaves a half-configured policy armed."""
    bad = problems(p, consts)
    if bad:
        raise ValueError("; ".join(bad))
    d, g = q(p.d_a_ms * 1e6), q(p.gap_ms * 1e6)
    if p.case == "case4":
        config = {name: getattr(p, name) for name in (
            "readiness_expiry_ms", "heartbeat_request_us", "completion_deadline_ms",
            "measured_heartbeat_max_us", "measured_drain_max_ms", "measured_release_max_us",
            "padding_profile", "split_profile", "translation_capacity")}
        blockers = ["joint Case 4 compiled schema and source-bound write mapping are unavailable"]
        if hold_bound_ms(p) is None:
            blockers.append("measured heartbeat, drain, release and completion bounds are required")
        return {"case": p.case, "case4": config, "quantised_ns": {"d_a": d, "gap": g},
                "policy_cap_ms": MAX_HOLD_MS, "hold_bound_ms": hold_bound_ms(p),
                "writes": [], "expect": {}, "activation_blockers": blockers}
    mode = {"off": consts["MODE_OFF"], "combined": consts["MODE_D4_DUAL"], "ack_focused": consts["MODE_D4_DUAL"],
            "response_focused": consts["MODE_D2_RESP"]}[p.case]
    enabled = 0 if p.case == "off" else 1
    params = dict(action_name=A_PARAMS, d_ticks=d, read_len=0, budget=p.budget, mode=mode, da_dr=d + g)
    bor = dict(action_name=A_BOR, a_ticks=d, r_ticks=d + g, anchor_req=1)
    off = dict(action_name=A_REL, enabled=0, gap_ticks=g)
    on = dict(action_name=A_REL, enabled=enabled, gap_ticks=g)
    return {"case": p.case, "quantised_ns": {"d_a": d, "gap": g, "d_a_residual": int(round(p.d_a_ms * 1e6)) - d,
                                              "gap_residual": int(round(p.gap_ms * 1e6)) - g},
            "writes": [(RELEASE, off), (PARAMS, params), (BOR, bor), (RELEASE, on)],
            "expect": {PARAMS: params, BOR: bor, RELEASE: on}}


def admission_problem(p, admission):
    """Delegate to the repository's binding check, charged with the worst-case hold (not D_A alone)."""
    if p.case == "case4" and hold_bound_ms(p) is None:
        return "Case 4 has no measured heartbeat/drain/release/completion bound"
    top = _top()
    tp = top.TimingOnlyProfile(connection_id=p.connection_id, build_id=p.build_id,
                               d_a_ms=hold_bound_ms(p), clrt_new_ms=p.gap_ms)
    return top._admission_problem(admission, tp)


def _same(got, want):
    return {k: v for k, v in got.items()} == want


def activate(device, p, consts, *, mock, admission=None, backup_path=None):
    record = {"source": "mock" if mock else "switch", "is_evidence_of_switch_state": not mock,
              "profile": p.__dict__.copy(), "steps": [], "admission": admission}
    steps = plan(p, consts)                                   # raises before any write
    record["plan"] = {k: v for k, v in steps.items() if k != "writes"}
    schema = getattr(device, "schema", None)
    if schema is not None and schema.has_field(PARAMS, "shape_enable"):
        raise ActivationError("the program exposes a shaping field; this adapter is for programs without one", record)
    if p.case == "case4":
        record["failure"] = {"stage": "schema", "reason": steps["activation_blockers"][0]}
        raise ActivationError(steps["activation_blockers"][0], record)
    if schema is not None:
        # Validate the entire plan before any device read, backup or write.
        # Discovering a missing field halfway through would leave partial state.
        for table, fields in steps["writes"]:
            schema.check_write(table, fields)
    if p.case != "off" and not mock:
        why = admission_problem(p, admission)
        if why:
            record["failure"] = {"stage": "admission", "reason": why}
            raise ActivationError("admission does not authorise this policy: " + why, record)
    record["before"] = {t: device.read(t) for t in (PARAMS, BOR, RELEASE)}
    if backup_path is not None:       # on disk BEFORE the first write; 'x' refuses to overwrite an earlier backup
        import json
        with open(backup_path, "x", encoding="utf-8") as stream:
            json.dump(record["before"], stream, indent=2, sort_keys=True)
    for table, fields in steps["writes"]:
        device.write(table, fields)
        got = device.read(table)
        ok = _same(got, fields)
        record["steps"].append({"table": table, "wrote": fields, "read_back": got, "match": ok})
        if not ok:
            record["failure"] = {"stage": table, "reason": "readback differs from what was written"}
            raise ActivationError("readback mismatch on %s" % table, record)
    record["after"] = {t: device.read(t) for t in steps["expect"]}
    for t, want in steps["expect"].items():
        if not _same(record["after"][t], want):
            record["failure"] = {"stage": "final", "reason": "final readback differs on %s" % t}
            raise ActivationError("final readback mismatch on %s" % t, record)
    return record


def restore(device, before):
    """Write a saved snapshot back (release disabled first, then params, bor, then the saved release) and verify."""
    for t in (PARAMS, BOR, RELEASE):
        if not before.get(t):
            raise ActivationError("no saved state for %s; refusing to guess a restore" % t, {"before": before})
    rel = dict(before[RELEASE]); rel["enabled"] = 0
    order = [(RELEASE, rel), (PARAMS, before[PARAMS]), (BOR, before[BOR]), (RELEASE, before[RELEASE])]
    steps = []
    for table, fields in order:
        device.write(table, fields)
        got = device.read(table)
        steps.append({"table": table, "wrote": fields, "read_back": got, "match": _same(got, fields)})
        if not steps[-1]["match"]:
            raise ActivationError("restore readback mismatch on %s" % table, {"steps": steps})
    return {"restored": True, "steps": steps}
