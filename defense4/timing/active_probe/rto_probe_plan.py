#!/usr/bin/env python3
"""A corrected retransmission probe. Plans by default; never applies anything on import.

This does NOT replace `relay_rto_20260915/rto_probe.py`. That script produced the archived
captures and is immutable provenance; it stays exactly as it ran. This is the version to use
next time, and it exists because the original has four defects that the 2026-09-15 review found:

1. **PSH-clear is not a payload test.** The original selected packets with
   `--tcp-flags SYN,RST,PSH,ACK ACK`, describing the result as "only pure ACKs". A data-bearing
   segment may perfectly well have PSH clear, so the rule's description was not true in general.
2. **The rule was not scoped to the probe.** It matched *every* outgoing connection to the
   relay's DNP3 port, so anything else talking to that relay would have been affected too.
3. **Failures were invisible.** `subprocess.run` was called without checking its return code,
   and the cleanup path printed that the rule had been removed whether or not it had been.
4. **Nothing recorded what was running.** No timing mode, no shape state, no loaded-build
   identity, so the captures could not be tied to a configuration.

A second review on 2026-09-15 found four more, in this module rather than in the original, all
of which are now fixed and covered by tests:

5. **The hold was recorded but never taken.** `run_steps` wrote `held_seconds: 40.0` into the
   record and returned in a fraction of a millisecond. The lifecycle is now bounded and timed
   against an injectable clock, and the record carries the elapsed time actually spent, which is
   measured rather than copied from the request.
6. **Cleanup protection started too late.** The protected block began after verification, so a
   failure *during* verification could leave an installed rule behind. Protection now begins on
   the instruction after a successful install.
7. **Any non-zero return counted as successful removal.** `iptables -C` exits 1 when the rule is
   absent and 2 when it could not look, so "permission denied" was being read as "removed".
   Absence is now established only by the specific absent code.
8. **The recorded interface was not enforced.** The plan named an interface that the generated
   rule never matched on. The documented selection and the executed selection are now the same
   rule, and the rule carries a probe-specific comment so cleanup removes this probe's rule and
   nothing else.

Boundaries. `plan()` is pure: it computes and returns, touching nothing. `apply()` refuses
unless the caller passes `live=True` AND the environment guard `DEFENSE4_HW_AUTHORIZED=1` is
set, which this repository's offline work never sets. READ only: this module builds no SELECT,
no OPERATE and no retry, and it does not touch the point allowlist or replace the guarded
driver in `active_harness/`. Nothing here has been run against a host.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import shlex
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Callable

GUARD_ENV = "DEFENSE4_HW_AUTHORIZED"
IPV4_HEADER_BYTES = 20

#: `iptables -C` exits 1 when the rule is absent. Any other non-zero status means the check
#: itself failed, which is not evidence of absence.
RULE_ABSENT_RC = 1

#: The smallest DNP3 application payload the probe's master sends, used to state the margin
#: between the zero-payload bound and the smallest data segment on the connection.
SMALLEST_DNP3_READ_BYTES = 20


class ProbeRefused(RuntimeError):
    """Raised instead of doing anything when a precondition is not met.

    When raised after execution has begun, `record` carries everything that happened, including
    the cleanup attempt, so a failure never discards its own evidence.

    The record is resolved when it is read, not when the error is constructed. Cleanup runs in a
    `finally` block after the raise statement has already executed, so a snapshot taken at
    construction time would always show the cleanup as not yet attempted.
    """

    def __init__(self, message: str, record: Any = None):
        super().__init__(message)
        self._record = record

    @property
    def record(self) -> dict[str, Any]:
        if self._record is None:
            return {}
        as_dict = getattr(self._record, "as_dict", None)
        return as_dict() if callable(as_dict) else self._record


class Direction(str, Enum):
    """Which packet is withheld. These are different experiments, not one parameterised one.

    They differ in the chain, in who is deprived of feedback, and in what the capture can show.
    Withholding the master's ACK stops the master acknowledging the outstation's response, so it
    is the outstation's retransmission timer that fires. Dropping the outstation's response on
    the master host removes the response before the master's kernel sees it, so the master's own
    stack never acknowledges it and the copies observed on the wire arrived before the drop.
    """

    WITHHOLD_MASTER_ACK = "withhold the master's pure ACKs toward the outstation"
    DROP_OUTSTATION_RESPONSE = "drop the outstation's response before the master's stack sees it"

    @property
    def chain(self) -> str:
        return "OUTPUT" if self is Direction.WITHHOLD_MASTER_ACK else "INPUT"

    @property
    def interface_flag(self) -> str:
        return "-o" if self is Direction.WITHHOLD_MASTER_ACK else "-i"


@dataclass(frozen=True)
class Connection:
    """The one established connection the probe is allowed to touch."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    interface: str
    tcp_header_bytes: int          # observed on THIS connection, options included
    ip_header_bytes: int = IPV4_HEADER_BYTES

    def four_tuple(self) -> str:
        return "%s:%d -> %s:%d" % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def problems(self, *, for_execution: bool) -> list[str]:
        """Why this connection cannot be used. Execution demands a complete tuple."""
        errs: list[str] = []
        if self.ip_header_bytes != IPV4_HEADER_BYTES:
            errs.append("only a 20-byte IPv4 header is supported; got %d. An IPv4 options "
                        "header or IPv6 changes the length arithmetic and needs a different "
                        "selector" % self.ip_header_bytes)
        if not (20 <= self.tcp_header_bytes <= 60):
            errs.append("tcp_header_bytes %d is outside the legal 20..60 range"
                        % self.tcp_header_bytes)
        elif self.tcp_header_bytes % 4:
            errs.append("tcp_header_bytes %d is not a multiple of 4" % self.tcp_header_bytes)
        for name in ("src_ip", "dst_ip"):
            value = getattr(self, name)
            if not value:
                errs.append("%s is empty" % name)
                continue
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                errs.append("%s is %r, which is not a single IPv4 host address; this probe is "
                            "scoped to one connection and must not be given a network or a "
                            "prefix" % (name, value))
        if not self.interface:
            errs.append("interface is empty")
        for name in ("src_port", "dst_port"):
            port = getattr(self, name)
            if not (1 <= port <= 65535):
                errs.append("%s %r is not a usable port%s"
                            % (name, port,
                               "; the ephemeral port must be read from the established "
                               "connection" if (port == 0 and for_execution) else ""))
        return errs


@dataclass(frozen=True)
class RunContext:
    """What has to be recorded for a capture to mean anything later."""

    capture_host: str
    capture_point: str             # e.g. "master-facing NIC on the master host"
    capture_precision: str         # e.g. "nanosecond (tcpdump --time-stamp-precision=nano)"
    timing_mode: str               # OFF / D4 / ...
    shape_enable: int              # the field whose absence caused the 2026-09-15 confusion
    loaded_program: str
    loaded_program_sha256: str
    notes: str = ""

    def problems(self) -> list[str]:
        errs = [name for name in ("capture_host", "capture_point", "capture_precision",
                                  "timing_mode", "loaded_program", "loaded_program_sha256")
                if not getattr(self, name) or getattr(self, name) == "UNSET"]
        out = ["%s is unset" % n for n in errs]
        if self.shape_enable not in (0, 1):
            out.append("shape_enable is %r; it must be read back from the device as 0 or 1"
                       % self.shape_enable)
        return out


@dataclass
class ExecutionRecord:
    """Everything that happened, kept whether the probe succeeded or failed."""

    probe_id: str
    status: str = "not started"
    steps: list = field(default_factory=list)
    rule_installed: bool = False
    rule_removed: bool = False
    cleanup_verified: bool = False
    requested_hold_seconds: float = 0.0
    elapsed_seconds: float | None = None
    watchdog_seconds: float = 0.0
    watchdog_expired: bool = False
    workload_abandoned: bool = False
    workload_error: str = ""
    primary_error: str = ""
    errors: list = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def payload_length_rule(conn: Connection) -> list[str]:
    """The zero-payload selector, stated as a length bound rather than as a flag guess.

    The property wanted is "this segment carries no application bytes". iptables has no direct
    payload-length match, so the bound is computed from the connection's own observed headers:
    a segment carrying no payload is exactly `IPv4 header + TCP header` bytes long, and the TCP
    header length is read from the established connection rather than assumed.

    This is an exact-length match, not a general zero-payload test. It holds only for the packet
    layout `problems()` validates: a 20-byte IPv4 header with no options, and a TCP header length
    that does not change mid-connection. A data segment shorter than the bound would also match;
    on this probe the smallest data segment is the bound plus the 20-byte DNP3 READ, and the plan
    reports that margin so the caller can check the assumption rather than trust it.
    """
    exact = conn.ip_header_bytes + conn.tcp_header_bytes
    return ["-m", "length", "--length", "%d:%d" % (exact, exact)]


def build_rule(conn: Connection, direction: Direction, probe_id: str) -> list[str]:
    """The full rule body: one connection, one interface, and this probe's own comment.

    The comment is what makes cleanup safe. `iptables -D` deletes the first rule matching the
    body it is given, so without an owner tag a delete could remove an identical rule belonging
    to another experiment. With it, this probe can only ever delete its own.
    """
    rule = ["-p", "tcp", direction.interface_flag, conn.interface]
    if direction is Direction.WITHHOLD_MASTER_ACK:
        rule += ["-s", conn.src_ip, "--sport", str(conn.src_port),
                 "-d", conn.dst_ip, "--dport", str(conn.dst_port),
                 # ACK set, SYN/RST/FIN clear, so the handshake and teardown are not caught
                 "--tcp-flags", "SYN,RST,FIN,ACK", "ACK",
                 *payload_length_rule(conn)]
    else:
        # The outstation's response travels the other way, and it carries data, so a
        # zero-payload selector would be wrong here.
        rule += ["-s", conn.dst_ip, "--sport", str(conn.dst_port),
                 "-d", conn.src_ip, "--dport", str(conn.src_port),
                 "--tcp-flags", "SYN,RST,FIN,ACK", "ACK"]
    rule += ["-m", "comment", "--comment", probe_id, "-j", "DROP"]
    return rule


def plan(conn: Connection, ctx: RunContext, hold_seconds: float,
         direction: Direction = Direction.WITHHOLD_MASTER_ACK,
         probe_id: str | None = None) -> dict[str, Any]:
    """Compute the whole probe without performing any part of it."""
    if (not isinstance(hold_seconds, (int, float)) or isinstance(hold_seconds, bool)
            or not math.isfinite(hold_seconds) or hold_seconds <= 0):
        # NaN fails every comparison, so `<= 0` alone lets it through and produces a completed
        # zero-duration run.
        raise ProbeRefused("hold_seconds must be a positive finite number, got %r" % hold_seconds)
    problems = conn.problems(for_execution=False)
    if problems:
        raise ProbeRefused("connection is not usable: " + "; ".join(problems))

    probe_id = probe_id or ("d4-rto-probe-%s" % uuid.uuid4().hex[:12])
    rule = build_rule(conn, direction, probe_id)
    exact = conn.ip_header_bytes + conn.tcp_header_bytes
    body = " ".join(shlex.quote(a) for a in rule)
    chain = direction.chain

    selector: dict[str, Any] = {
        "direction": direction.value,
        "chain": chain,
        "interface_enforced": "%s %s" % (direction.interface_flag, conn.interface),
    }
    if direction is Direction.WITHHOLD_MASTER_ACK:
        selector.update({
            "intent": "segments carrying zero application bytes, on this connection only",
            "implemented_as": "exact total length %d B (IPv4 %d + TCP %d observed)"
                              % (exact, conn.ip_header_bytes, conn.tcp_header_bytes),
            "not_implemented_as": "PSH-clear, which is not a payload-length test",
            "supported_layout_only": "20-byte IPv4 header, no options; constant TCP header "
                                     "length for the life of the connection",
            "smallest_data_segment_on_this_connection_B": exact + SMALLEST_DNP3_READ_BYTES,
            "margin_B": SMALLEST_DNP3_READ_BYTES,
        })
    else:
        selector.update({
            "intent": "the outstation's data segments toward the master, on this connection only",
            "implemented_as": "4-tuple reversed, ACK set, no length bound because the response "
                              "carries data",
            "note": "this is a different experiment from withholding the master's ACK, and its "
                    "capture shows copies that arrived before the drop, not delivery",
        })

    return {
        "mode": "dry-run plan; nothing has been applied",
        "probe_id": probe_id,
        "connection": asdict(conn),
        "scope": "exactly one 4-tuple: %s, on %s" % (conn.four_tuple(), conn.interface),
        "context": asdict(ctx),
        "selector": selector,
        "commands": {
            "install": "iptables -A %s %s" % (chain, body),
            "verify_installed": "iptables -C %s %s" % (chain, body),
            "remove": "iptables -D %s %s" % (chain, body),
            "verify_removed": "iptables -C %s %s   # must exit %d once removed"
                              % (chain, body, RULE_ABSENT_RC),
        },
        "hold_seconds": float(hold_seconds),
        "watchdog_seconds": float(hold_seconds) + 45.0,
        "ownership": {
            "comment": probe_id,
            "why": "iptables -D removes the first rule matching the body it is given, so the "
                   "comment is what keeps this probe from deleting another experiment's rule",
        },
        "required_evidence": [
            "return code of every install, verify and remove call, recorded not discarded",
            "the rule absent from iptables -S after cleanup, established by return code %d"
            % RULE_ABSENT_RC,
            "capture point, interface and timestamp precision",
            "timing mode, shape_enable and the loaded program's sha256, read back not assumed",
            "host clock samples spanning the capture",
            "the elapsed hold, measured rather than copied from the request",
        ],
        "refusals": [
            "no SELECT, no OPERATE, no retry",
            "no change to the point allowlist",
            "the guarded driver in active_harness/ is not replaced",
        ],
    }


def explain(p: dict[str, Any]) -> str:
    return json.dumps(p, indent=1)


def apply(p: dict[str, Any], runner, **kw) -> dict[str, Any]:
    """Guarded entry point. Refuses unless explicitly authorised, then runs the steps."""
    if not kw.pop("live", False):
        raise ProbeRefused("apply() requires live=True; the default is a dry run")
    if os.environ.get(GUARD_ENV) != "1":
        raise ProbeRefused("apply() requires %s=1; this repository's offline work never sets it"
                           % GUARD_ENV)
    return run_steps(p, runner, **kw)


def run_steps(p: dict[str, Any], runner, *,
              clock: Callable[[], float] = time.monotonic,
              sleeper: Callable[[float], None] = time.sleep,
              workload: Callable[[float], Any] | None = None,
              slice_seconds: float = 0.5) -> dict[str, Any]:
    """Execute the plan, checking every step and actually taking the hold.

    No guard here: `apply()` owns that. Split out so the lifecycle can be tested offline against
    a scripted runner and a fake clock WITHOUT any test setting the hardware-authorisation flag,
    which nothing in this repository sets. `runner(argv) -> (returncode, stdout, stderr)` is
    injected; nothing here shells out.

    The hold is taken, not recorded: the function waits until the requested duration has elapsed
    on `clock`, or until the watchdog expires, and reports the measured elapsed time. A
    `workload` may be supplied to run the capture or observation for the duration instead of
    sleeping; it is still bounded by the same watchdog.
    """
    conn = p.get("connection", {})
    ctx = p.get("context", {})
    problems = Connection(**conn).problems(for_execution=True) if conn else ["no connection"]
    problems += RunContext(**ctx).problems() if ctx else ["no context"]
    if problems:
        raise ProbeRefused("refusing to execute an incomplete plan: " + "; ".join(problems))

    if (not isinstance(slice_seconds, (int, float)) or isinstance(slice_seconds, bool)
            or not math.isfinite(slice_seconds) or slice_seconds <= 0):
        raise ProbeRefused("slice_seconds must be a positive finite number, got %r"
                           % (slice_seconds,))
    rec = ExecutionRecord(probe_id=p["probe_id"],
                          requested_hold_seconds=float(p["hold_seconds"]),
                          watchdog_seconds=float(p["watchdog_seconds"]))

    def step(name, argv, *, expect):
        """`expect` is the return code that means success for this step."""
        try:
            rc, out, err = runner(argv)
        except Exception as exc:                      # the runner itself failed
            rec.steps.append({"step": name, "argv": argv, "exception": repr(exc)})
            rec.errors.append("%s raised %r" % (name, exc))
            raise
        ok = (rc == expect)
        rec.steps.append({"step": name, "argv": argv, "returncode": rc, "stdout": out,
                          "stderr": err, "expected_returncode": expect, "ok": ok})
        if not ok:
            rec.errors.append("%s returned %r, expected %r: %s"
                              % (name, rc, expect, (err or "").strip()))
        return ok

    install = shlex.split(p["commands"]["install"])
    verify = shlex.split(p["commands"]["verify_installed"])
    remove = shlex.split(p["commands"]["remove"])

    if not step("install", install, expect=0):
        rec.status = "aborted before install"
        raise ProbeRefused("install failed; nothing was held and no capture is valid", rec)
    rec.rule_installed = True

    # From here the rule exists, so every path out of this function must attempt cleanup. The
    # protection therefore starts on the instruction after the install, not after verification.
    try:
        if not step("verify_installed", verify, expect=0):
            rec.status = "aborted after install"
            raise ProbeRefused("rule did not verify after install", rec)
        started = clock()
        deadline = started + rec.requested_hold_seconds
        watchdog = started + rec.watchdog_seconds
        if workload is not None:
            # The workload runs on its own thread so the watchdog can act while it is still
            # running. A thread cannot be killed safely, so an overrunning workload is abandoned
            # and reported as abandoned rather than silently waited on: cleanup proceeds, and the
            # record says the observation was not bounded.
            done = threading.Event()
            box: dict = {}

            def _run():
                try:
                    box["value"] = workload(rec.requested_hold_seconds)
                except BaseException as exc:                      # kept, not swallowed
                    box["exception"] = exc
                finally:
                    done.set()

            worker = threading.Thread(target=_run, name="probe-workload", daemon=True)
            worker.start()
            while not done.is_set() and clock() < watchdog:
                sleeper(min(slice_seconds, max(0.0, watchdog - clock())))
                if not done.is_set() and clock() < deadline:
                    continue
            if not done.is_set():
                rec.watchdog_expired = True
                rec.workload_abandoned = True
                rec.errors.append(
                    "watchdog expired while the workload was still running; it was abandoned "
                    "and the observation is not bounded by this function")
            elif "exception" in box:
                rec.errors.append("workload raised %r" % (box["exception"],))
                rec.workload_error = repr(box["exception"])
        else:
            while clock() < deadline:
                if clock() >= watchdog:
                    break
                sleeper(min(slice_seconds, max(0.0, deadline - clock())))
        rec.elapsed_seconds = clock() - started
        if clock() >= watchdog and not rec.watchdog_expired:
            rec.watchdog_expired = True
            rec.errors.append("watchdog expired after %.3f s; the hold was cut short"
                              % rec.elapsed_seconds)
    except BaseException as exc:
        # A failure in the held phase must not discard the record, and must not skip cleanup.
        rec.errors.append("held phase raised %r" % (exc,))
        rec.primary_error = repr(exc)
        raise ProbeRefused("the probe failed while the rule was installed: %r" % (exc,), rec)
    finally:
        # Cleanup and its verification must survive a runner that raises, so each is attempted
        # independently and its failure is recorded rather than propagated over the primary one.
        removed = gone = False
        try:
            removed = step("remove", remove, expect=0)
        except Exception as exc:
            rec.errors.append("remove raised %r" % (exc,))
        try:
            # `iptables -C` exits 1 when the rule is absent. Any other non-zero status means the
            # check could not be made, which is not evidence of absence.
            gone = step("verify_removed", verify, expect=RULE_ABSENT_RC)
        except Exception as exc:
            rec.errors.append("verify_removed raised %r" % (exc,))
        rec.rule_removed = bool(removed)
        rec.cleanup_verified = bool(removed and gone)

    if not rec.cleanup_verified:
        rec.status = "cleanup unverified"
        rec.errors.append("the rule may still be installed; removal was NOT confirmed")
        raise ProbeRefused("the rule may still be installed; it was NOT confirmed removed", rec)
    if rec.watchdog_expired:
        rec.status = "watchdog expired"
        raise ProbeRefused("watchdog expired before the hold completed", rec)
    if rec.workload_error:
        rec.status = "workload failed"
        raise ProbeRefused("the observation workload raised: %s" % rec.workload_error, rec)
    # Completion means the hold was actually served for the duration that was requested. A
    # workload that returns at once has not held anything, and must not be reported as complete.
    if rec.elapsed_seconds is None or rec.elapsed_seconds + 1e-9 < rec.requested_hold_seconds:
        rec.status = "hold not served"
        rec.errors.append("elapsed %.6f s is short of the requested %.6f s"
                          % (rec.elapsed_seconds or 0.0, rec.requested_hold_seconds))
        raise ProbeRefused("the requested hold was not served", rec)
    rec.status = "completed"
    return rec.as_dict()


if __name__ == "__main__":
    conn = Connection(src_ip="192.168.10.1", src_port=40001, dst_ip="192.168.10.7",
                      dst_port=20000, interface="enp59s0f0np0", tcp_header_bytes=32)
    ctx = RunContext(capture_host="master", capture_point="master-facing NIC",
                     capture_precision="nanosecond", timing_mode="UNSET", shape_enable=-1,
                     loaded_program="UNSET", loaded_program_sha256="UNSET",
                     notes="context must be filled from the real run before execution")
    print(explain(plan(conn, ctx, hold_seconds=40.0)))
    print("\nplan only; apply() needs live=True and %s=1" % GUARD_ENV)
