"""Configuration profiles for the framework cases, with fail-closed activation and restoration.

Cases: `off`, `combined` (D4, D_A > 0), `ack_focused` (D4, D_A = 0), `response_focused` (MODE_D2_RESP).
Mode numbers are read from the P4 source, not typed here. The program has no shaping field, so nothing in
this module can enable shaping; that is asserted from the compiled schema on every activation.
"""
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
CASES = ("off", "combined", "ack_focused", "response_focused")


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


def hold_bound_ms(p):
    """Worst-case ACK or response hold: the watchdog horizon, which the ACK can reach even when D_A is smaller."""
    return max(p.d_a_ms, p.budget * p.loop_ns / 1e6)


def problems(p, consts):
    out = []
    if p.case not in CASES:
        return ["case %r is not one of %s" % (p.case, ", ".join(CASES))]
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
    if hold_bound_ms(p) > MAX_HOLD_MS:
        out.append("worst-case hold %.3f ms exceeds the %.1f ms clamp" % (hold_bound_ms(p), MAX_HOLD_MS))
    if not (1 <= p.budget < 2 ** 32):
        out.append("budget out of range")
    return out


def plan(p, consts):
    """Ordered writes and the exact readback expected after each. The release block is disabled first and
    enabled last, so no step leaves a half-configured policy armed."""
    bad = problems(p, consts)
    if bad:
        raise ValueError("; ".join(bad))
    d, g = q(p.d_a_ms * 1e6), q(p.gap_ms * 1e6)
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
