#!/usr/bin/env python3
"""The timing-only activation path, with shaping never enabled at any point.

Why this exists
---------------
`implementation/control/defense4_rrc_bor_unified12_setup.py` is the frozen record of what ran.
Its successful `configure-all` ends with `set_shape_enable(..., on=True)`, and the campaign did
not leave it there: every block's `provenance/MANIFEST.json` records that each block then forced
`shape_set.py` to 0. A run that performs only `configure-all` therefore ends up with the size
carve ON, which is not the campaign's configuration. That actually happened once, on 2026-09-15,
and the evidence is in `relay_rto_20260915/CORRECTION_20260915.md`.

The correction is not to switch shaping off afterwards. It is to have an activation path in
which shaping is never switched on. **This module contains no code that can write
`shape_enable = 1`.** Shaping is established off before any traffic path is configured, and is
re-read independently after every step. The shaping capability still exists in the frozen setup
for whoever needs it; it is deliberately not reimplemented here.

What this module is, and is not
-------------------------------
It is a plan and a verification harness. It is **not** a device adapter, and it does not
implement the bfrt transport. The frozen path reaches the switch through `bfrt_grpc.client`,
imported only inside its hardware functions, and delegates each step to helpers that exist on the
switch. None of that can be exercised, or even imported, off the switch, so no adapter is written
here and none is implied: `ADAPTER_STATUS` states this in the plan and in every record.

Consequently a record produced with a mock `Device` describes the mock, and says so. Generic
success flags are not accepted as evidence that a particular field holds a particular value:
every expectation is compared field by field against a readback of the table it belongs to, and
shaping is re-read from `tbl_params` on its own rather than being noticed in whatever another
step happened to return.

Boundaries
----------
* This module produces no published number. Nothing here has been run against hardware.
* It imports nothing from `implementation/`. A wrapper that imports frozen helpers can silently
  resolve them from another worktree, so this path takes none. The tests assert that.
* It never opens a socket, a gRPC channel or a device. All device access goes through the
  `Device` protocol below, which the caller supplies.
* Activation is fail-closed. The first failed validation, write or mismatched readback aborts the
  sequence, the record reports `status: "aborted"`, and that partial record is attached to the
  raised error. There is no partial success.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field, asdict
from typing import Any, Protocol

# The deadline words the data plane consumes are nanoseconds with a zero low byte, i.e. whole
# multiples of the 256 ns tick. This mirrors the frozen setup's quantisation and its assertions
# that D_A, the configured CLRT_new and their sum all have a zero low byte.
TICK_NS = 256

#: Tofino-1 device-port and queue-id ranges. A value outside these cannot be configured, so it is
#: a configuration error rather than something to discover on the switch.
MAX_DEV_PORT = 511
MAX_QID = 31

ADAPTER_STATUS = (
    "no device adapter is implemented here. The frozen path reaches the switch through "
    "bfrt_grpc.client and helpers that exist only on the switch, so this module plans and "
    "verifies through a caller-supplied Device and cannot itself configure anything."
)

#: The loaded binary arms its holds only in the dual mode. D1, D2 and D3 are declared in the
#: program and accepted by the control plane, but no arming path exists for them in the build the
#: campaign ran, so offering them here would suggest a capability the binary does not have.
ARMING_MODES = ("OFF", "D4")
ACCEPTED_BUT_NEVER_ARMING = ("D1", "D2", "D3")


class ActivationError(RuntimeError):
    """Raised when a step fails. Activation stops; nothing later is attempted.

    `record` carries the partial verification record, including which step failed and everything
    read back before it, so a failure keeps its evidence instead of discarding it.
    """

    def __init__(self, message: str, record: dict[str, Any] | None = None):
        super().__init__(message)
        self.record = record if record is not None else {}


class Device(Protocol):
    """The only way this module touches anything. Supplied by the caller."""

    def write(self, table: str, fields: dict[str, Any]) -> None: ...

    def read(self, table: str) -> dict[str, Any]: ...


def quantize_ns(ms: float) -> int:
    """Milliseconds to a deadline word: nanoseconds truncated to a whole 256 ns tick.

    The low byte is cleared, so the result always satisfies the frozen setup's `word & 0xFF == 0`
    assertion. A positive duration below one tick truncates to zero, which is not a short hold but
    no hold at all; `validate()` rejects that rather than letting it through silently. The caller
    is told the residual in the plan.
    """
    if not isinstance(ms, (int, float)) or isinstance(ms, bool) or not math.isfinite(ms):
        raise ValueError("duration must be a finite number, got %r" % (ms,))
    ns = int(round(ms * 1e6))
    return (ns // TICK_NS) * TICK_NS


@dataclass(frozen=True)
class TimingOnlyProfile:
    """The timing-paper configuration. There is no shaping field: it cannot be turned on."""

    mode: str = "D4"                       # D4 arms the holds; OFF is the Timing OFF arm
    d_a_ms: float = 20.0                   # the ACK hold
    clrt_new_ms: float = 4.0               # the configured CLRT_new (the code field D_R_ms)
    budget: int = 18000                    # fail-open pass budget B
    port_master: int = 9
    port_relay: int = 64
    port_loopback_rrc: int = 8
    port_loopback_bor: int = 10
    port_pktgen: int = 68
    reservoir_depth_k: int = 64
    # (label, qid, priority). The qid and the priority are separate numbers that happen to
    # coincide in the frozen plan; nothing requires them to, so they are validated separately.
    queue_plan_rrc: tuple = (("ACK_BLOCK", 7, 7), ("ACK_HOLD", 6, 6),
                             ("RESP_BLOCK", 5, 5), ("RESP_HOLD", 4, 4))
    queue_plan_bor: tuple = (("OP_BLOCK", 3, 3), ("OP_HOLD", 2, 2))
    pktgen_apps: tuple = (("2K_operate", 1, 0xE1000000), ("3K_read_select", 2, 0xE1010000))

    # Not a parameter. Stated as a constant so that reading the profile answers the question.
    SHAPE_ENABLE: int = field(default=0, init=False)


def _int_problems(name: str, v: Any, lo: int, hi: int) -> list[str]:
    if isinstance(v, bool) or not isinstance(v, int):
        return ["%s must be an integer, got %r" % (name, v)]
    if not (lo <= v <= hi):
        return ["%s is %d, outside the usable range %d..%d" % (name, v, lo, hi)]
    return []


def validate(p: TimingOnlyProfile) -> list[str]:
    """Everything checkable before a single write. Returns the problems; empty means valid.

    This never raises on a bad value: a NaN or an infinity is a problem to report, not an
    exception to propagate out of a validator.
    """
    problems: list[str] = []
    if p.mode not in ARMING_MODES:
        extra = (" It is accepted by the control plane but never arms in the loaded build."
                 if p.mode in ACCEPTED_BUT_NEVER_ARMING else "")
        problems.append("mode %r is not one of %s.%s"
                        % (p.mode, ", ".join(ARMING_MODES), extra))
    if p.SHAPE_ENABLE != 0:
        problems.append("shape_enable is %r; the timing-only profile requires 0" % p.SHAPE_ENABLE)

    words: dict[str, int] = {}
    for name, ms in (("d_a_ms", p.d_a_ms), ("clrt_new_ms", p.clrt_new_ms)):
        if isinstance(ms, bool) or not isinstance(ms, (int, float)):
            problems.append("%s must be a number, got %r" % (name, ms))
            continue
        if not math.isfinite(ms):
            problems.append("%s is not finite (%r)" % (name, ms))
            continue
        if ms <= 0:
            problems.append("%s must be positive, got %r" % (name, ms))
            continue
        word = quantize_ns(ms)
        words[name] = word
        if word == 0:
            problems.append("%s is %g ms, which truncates to 0 ns at the %d ns tick; that is no "
                            "hold at all, not a short one" % (name, ms, TICK_NS))

    if len(words) == 2:
        d_a, clrt = words["d_a_ms"], words["clrt_new_ms"]
        for name, word in (("D_A", d_a), ("CLRT_new", clrt), ("D_A+CLRT_new", d_a + clrt)):
            if word & 0xFF:
                problems.append("%s word %d does not land on a %d ns tick" % (name, word, TICK_NS))
        if d_a + clrt >= 2 ** 31:
            problems.append("D_A+CLRT_new exceeds the modular half-range")

    ports = {"port_master": p.port_master, "port_relay": p.port_relay,
             "port_loopback_rrc": p.port_loopback_rrc, "port_loopback_bor": p.port_loopback_bor,
             "port_pktgen": p.port_pktgen}
    for name, v in ports.items():
        problems += _int_problems(name, v, 0, MAX_DEV_PORT)
    if len(set(ports.values())) != len(ports):
        problems.append("ports are not distinct: %s" % sorted(ports.values()))

    ladder = list(p.queue_plan_rrc) + list(p.queue_plan_bor)
    qids = [q[1] for q in ladder]
    pris = [q[2] for q in ladder]
    for label, qid, pri in ladder:
        problems += _int_problems("%s qid" % label, qid, 0, MAX_QID)
        problems += _int_problems("%s priority" % label, pri, 0, MAX_QID)
    if len(set(qids)) != len(qids):
        problems.append("queue ids are not distinct: %s" % qids)
    if len(set(pris)) != len(pris):
        problems.append("queue priorities are not distinct: %s; strict priority needs an order"
                        % pris)
    for plan_name, plan in (("rrc", p.queue_plan_rrc), ("bor", p.queue_plan_bor)):
        got = [q[2] for q in plan]
        if got != sorted(got, reverse=True):
            problems.append("%s ladder priorities %s are not in descending order, so the blocker "
                            "does not outrank the packet it blocks" % (plan_name, got))

    problems += _int_problems("budget", p.budget, 1, 2 ** 31 - 1)
    problems += _int_problems("reservoir_depth_k", p.reservoir_depth_k, 1, 4096)
    return problems


def build_plan(p: TimingOnlyProfile) -> dict[str, Any]:
    """The machine-readable plan: what was asked for, what will be written, what is expected.

    The step order follows the frozen `hw_configure_all`, with one deliberate difference: shaping
    is established off **first**, before any traffic path is configured, rather than being left to
    a later step. Configuring the forwarding path first and only then attending to shaping is how
    a run ends up carrying traffic in a state nobody intended.

    The final step of the frozen sequence, which enables shaping, has no counterpart here.
    """
    d_a, clrt = quantize_ns(p.d_a_ms), quantize_ns(p.clrt_new_ms)
    steps = [
        {"step": 1, "name": "shaping off before anything forwards", "table": "tbl_params",
         "write": {"shape_enable": 0},
         "expect": {"shape_enable": 0}},
        {"step": 2, "name": "port shaper disarmed", "table": "tm.port.sched_shaping",
         "write": {"disarm": [p.port_loopback_rrc, p.port_loopback_bor]},
         "expect": {"shaper_armed": False}},
        {"step": 3, "name": "ports", "table": "$PORT",
         "write": {"bring_up": [p.port_loopback_rrc, p.port_loopback_bor, p.port_master,
                                p.port_relay, p.port_pktgen]},
         "expect": {"port_up": [p.port_loopback_rrc, p.port_loopback_bor, p.port_master,
                                p.port_relay]}},
        {"step": 4, "name": "registers initialised", "table": "registers",
         "write": {"clear": ["reg_tag", "reg_deadline", "reg_tresp"]},
         "expect": {"cleared": True}},
        {"step": 5, "name": "queues", "table": "tm.queue.sched_cfg",
         "write": {"rrc": [list(q) for q in p.queue_plan_rrc],
                   "bor": [list(q) for q in p.queue_plan_bor]},
         "expect": {"qid_priority_map": {q[0]: [q[1], q[2]] for q in
                                         list(p.queue_plan_rrc) + list(p.queue_plan_bor)}}},
        {"step": 6, "name": "pktgen buffers and patterns, apps disabled",
         "table": "pktgen.app_cfg",
         "write": {"apps": [list(a) for a in p.pktgen_apps], "enable": False,
                   "blockers_per_reservoir": p.reservoir_depth_k},
         "expect": {"app_enable": False}},
        {"step": 7, "name": "mirror and session", "table": "tbl_session",
         "write": {"mirror_to": p.port_pktgen},
         "expect": {"session_installed": True}},
        {"step": 8, "name": "timing params", "table": "tbl_params",
         "write": {"mode": p.mode, "d_ticks": d_a, "da_dr": d_a + clrt,
                   "budget": p.budget, "shape_enable": 0},
         "expect": {"mode": p.mode, "d_ticks": d_a, "da_dr": d_a + clrt,
                    "budget": p.budget, "shape_enable": 0}},
        {"step": 9, "name": "commit map readback", "table": "tbl_commit",
         "write": {}, "expect": {"map_complete": True}},
        {"step": 10, "name": "pktgen apps enabled last", "table": "pktgen.app_cfg",
         "write": {"enable": True}, "expect": {"app_enable": True}},
        {"step": 11, "name": "final shaping assertion", "table": "tbl_params",
         "write": {}, "expect": {"shape_enable": 0}},
    ]
    return {
        "adapter_status": ADAPTER_STATUS,
        "profile": dict(asdict(p)),
        "modes": {"arming": list(ARMING_MODES),
                  "accepted_but_never_arming": list(ACCEPTED_BUT_NEVER_ARMING),
                  "note": "D1 to D3 are declared in the program and accepted by the control "
                          "plane, but the loaded build has no arming path for them"},
        "quantisation": {
            "tick_ns": TICK_NS,
            "d_a_ms_requested": p.d_a_ms, "d_a_ns_written": d_a,
            "d_a_residual_ns": int(round(p.d_a_ms * 1e6)) - d_a,
            "clrt_new_ms_requested": p.clrt_new_ms, "clrt_new_ns_written": clrt,
            "clrt_new_residual_ns": int(round(p.clrt_new_ms * 1e6)) - clrt,
            "release_budget_D_ns": d_a + clrt,
        },
        "shaping": {
            "written": 0,
            "established_before_any_traffic_path": True,
            "reread_independently_after_every_step": True,
            "note": "this path contains no code that can write shape_enable = 1",
        },
        "not_configured_here": [
            "blocker packet formats and the codebook, which the frozen helpers install",
            "PRE and multicast configuration",
            "anything requiring bfrt_grpc, which exists only on the switch",
        ],
        "steps": steps,
    }


def _assert_shaping_off(device: Device, record: dict[str, Any], where: str) -> dict[str, Any]:
    """Re-read shaping on its own. Not inferred from another step's return value."""
    probe = device.read("tbl_params")
    value = probe.get("shape_enable")
    if value is None:
        record["failure"] = {"stage": where, "reason": "shape_enable absent from tbl_params; "
                                                       "its state could not be established"}
        raise ActivationError("shape_enable could not be read after %s" % where, record)
    if int(value) != 0:
        record["failure"] = {"stage": where, "reason": "shaping is enabled", "shape_enable": value}
        raise ActivationError("shaping is enabled after %s" % where, record)
    return probe


def activate(p: TimingOnlyProfile, device: Device, *, mock: bool,
             admission: dict[str, Any] | None = None) -> dict[str, Any]:
    """Apply the plan fail-closed, asserting every readback. Returns the verification record.

    `mock` is recorded in the result so a mocked run can never be presented as evidence of switch
    state. `admission` is the verdict from `delay_admission.evaluate` for this policy: a non-mock
    activation requires one, and a refused or rejected policy is never applied. Raises
    ActivationError on the first failure, with the partial record attached.
    """
    record: dict[str, Any] = {
        "source": "mock" if mock else "switch",
        "is_evidence_of_switch_state": (not mock),
        "adapter_status": ADAPTER_STATUS,
        "profile_mode": p.mode,
        "shape_enable_requested": 0,
        "status": "aborted",
        "admission": admission,
        "steps": [],
    }

    problems = validate(p)
    if problems:
        record["failure"] = {"stage": "validation", "problems": problems}
        raise ActivationError("profile rejected before any write: " + "; ".join(problems), record)

    if not mock:
        if admission is None:
            record["failure"] = {"stage": "admission", "reason": "no admission verdict supplied"}
            raise ActivationError("a non-mock activation needs an admission verdict for this "
                                  "policy; none was supplied", record)
        if admission.get("verdict") in ("refused", "rejected"):
            record["failure"] = {"stage": "admission", "verdict": admission.get("verdict")}
            raise ActivationError("admission %s this policy; it will not be applied"
                                  % admission.get("verdict"), record)

    plan = build_plan(p)
    record["plan"] = plan

    for step in plan["steps"]:
        entry = {"step": step["step"], "name": step["name"], "table": step["table"]}
        try:
            if step["write"]:
                # Belt and braces: refuse to emit a write that would enable shaping, whatever a
                # future edit to build_plan might do.
                if int(step["write"].get("shape_enable", 0)) != 0:
                    raise ActivationError("step %s would enable shaping" % step["name"], record)
                device.write(step["table"], step["write"])
            got = device.read(step["table"])
        except ActivationError:
            raise
        except Exception as exc:                                  # device-level failure
            entry.update(status="failed", error="%s: %s" % (type(exc).__name__, exc))
            record["steps"].append(entry)
            record["failure"] = {"stage": step["name"], "reason": "device error"}
            raise ActivationError("step %s failed: %s" % (step["name"], exc), record)

        mismatches = {k: {"want": v, "got": got.get(k)}
                      for k, v in step["expect"].items() if got.get(k) != v}
        entry.update(readback=got, mismatches=mismatches,
                     status=("ok" if not mismatches else "mismatch"))
        record["steps"].append(entry)
        if mismatches:
            record["failure"] = {"stage": step["name"], "mismatches": mismatches}
            raise ActivationError("step %s read back wrong: %s" % (step["name"], mismatches),
                                  record)

        # Shaping is re-read from its own table after EVERY step, rather than being noticed in
        # whatever this step's readback happened to contain.
        entry["shaping_probe"] = _assert_shaping_off(device, record, step["name"])

    record["status"] = "activated"
    return record


def render(record: dict[str, Any]) -> str:
    """The verification record as JSON, for archiving beside a run."""
    return json.dumps(record, indent=1, sort_keys=False)


if __name__ == "__main__":                                        # offline plan only
    prof = TimingOnlyProfile()
    problems = validate(prof)
    print("profile valid" if not problems else "PROBLEMS: %s" % problems)
    print(json.dumps(build_plan(prof), indent=1))
    print("\n" + ADAPTER_STATUS)
