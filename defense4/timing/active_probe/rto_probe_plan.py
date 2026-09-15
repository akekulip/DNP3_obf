#!/usr/bin/env python3
"""A corrected retransmission probe. Plans by default; never applies anything on import.

This does NOT replace `relay_rto_20260915/rto_probe.py`. That script produced the archived
captures and is immutable provenance; it stays exactly as it ran. This is the version to use
next time, and it exists because the original has four defects that the 2026-09-15 review found:

1. **PSH-clear is not a payload test.** The original selected packets with
   `--tcp-flags SYN,RST,PSH,ACK ACK`, describing the result as "only pure ACKs". A data-bearing
   segment may perfectly well have PSH clear, so the rule's description was not true in general.
   It happened to select the right packets on that connection, which is luck rather than design.
2. **The rule was not scoped to the probe.** It matched *every* outgoing connection to the
   relay's DNP3 port, so anything else talking to that relay would have been affected too.
3. **Failures were invisible.** `subprocess.run` was called without checking its return code,
   and the cleanup path printed that the rule had been removed whether or not it had been.
4. **Nothing recorded what was running.** No timing mode, no shape state, no loaded-build
   identity, so the captures could not be tied to a configuration. That is exactly how the
   archived captures ended up taken with shaping enabled without anyone noticing; see
   `relay_rto_20260915/CORRECTION_20260915.md`.

Boundaries. `plan()` is pure: it computes and returns, touching nothing. `apply()` refuses
unless the caller passes `live=True` AND the environment guard `DEFENSE4_HW_AUTHORIZED=1` is
set, which this repository's offline work never sets. READ only: this module builds no SELECT,
no OPERATE and no retry, and it does not touch the point allowlist or replace the guarded
driver in `active_harness/`.
"""
from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass, asdict
from typing import Any

GUARD_ENV = "DEFENSE4_HW_AUTHORIZED"
IPV4_HEADER_BYTES = 20


class ProbeRefused(RuntimeError):
    """Raised instead of doing anything when a precondition is not met."""


@dataclass(frozen=True)
class Connection:
    """The one established connection the probe is allowed to touch."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    interface: str
    tcp_header_bytes: int          # observed on THIS connection, options included

    def four_tuple(self) -> str:
        return "%s:%d -> %s:%d" % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


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


def payload_length_rule(conn: Connection) -> list[str]:
    """The zero-payload selector, stated as a length bound rather than as a flag guess.

    The property wanted is "this segment carries no application bytes". iptables has no direct
    payload-length match, so the bound is computed from the connection's own observed headers:
    a segment carrying no payload is exactly `IPv4 header + TCP header` bytes long, and the TCP
    header length is read from the established connection rather than assumed.

    The residual risk is stated rather than hidden: a *data* segment shorter than that bound
    would also match. On this probe that cannot happen, because the only application data the
    master sends on this connection is the 20-byte DNP3 READ, so its smallest data segment is
    the bound plus 20. `explain()` reports the bound and this margin so the caller can check the
    assumption instead of trusting it.
    """
    exact = IPV4_HEADER_BYTES + conn.tcp_header_bytes
    return ["-m", "length", "--length", "%d:%d" % (exact, exact)]


def build_rule(conn: Connection) -> list[str]:
    """The full iptables rule body, scoped to exactly one connection."""
    return [
        "-p", "tcp",
        "-s", conn.src_ip, "--sport", str(conn.src_port),
        "-d", conn.dst_ip, "--dport", str(conn.dst_port),
        # ACK set, and SYN/RST/FIN clear, so the handshake and teardown are not caught
        "--tcp-flags", "SYN,RST,FIN,ACK", "ACK",
        *payload_length_rule(conn),
        "-j", "DROP",
    ]


def plan(conn: Connection, ctx: RunContext, hold_seconds: float) -> dict[str, Any]:
    """Compute the whole probe without performing any part of it."""
    if hold_seconds <= 0:
        raise ProbeRefused("hold_seconds must be positive, got %r" % hold_seconds)
    rule = build_rule(conn)
    exact = IPV4_HEADER_BYTES + conn.tcp_header_bytes
    return {
        "mode": "dry-run plan; nothing has been applied",
        "connection": asdict(conn),
        "scope": "exactly one 4-tuple: %s" % conn.four_tuple(),
        "context": asdict(ctx),
        "selector": {
            "intent": "segments carrying zero application bytes, on this connection only",
            "implemented_as": "exact total length %d B (IPv4 %d + TCP %d observed)"
                              % (exact, IPV4_HEADER_BYTES, conn.tcp_header_bytes),
            "not_implemented_as": "PSH-clear, which is not a payload-length test",
            "smallest_data_segment_on_this_connection_B": exact + 20,
            "margin_B": 20,
        },
        "commands": {
            "install": "iptables -A OUTPUT " + " ".join(shlex.quote(a) for a in rule),
            "verify_installed": "iptables -C OUTPUT " + " ".join(shlex.quote(a) for a in rule),
            "remove": "iptables -D OUTPUT " + " ".join(shlex.quote(a) for a in rule),
            "verify_removed": "iptables -C OUTPUT " + " ".join(shlex.quote(a) for a in rule)
                              + "   # must exit non-zero once removed",
        },
        "hold_seconds": hold_seconds,
        "watchdog_seconds": hold_seconds + 45,
        "required_evidence": [
            "return code of every install, verify and remove call, recorded not discarded",
            "the rule absent from iptables -S OUTPUT after cleanup, checked not assumed",
            "capture point, interface and timestamp precision",
            "timing mode, shape_enable and the loaded program's sha256, read back not assumed",
            "host clock samples spanning the capture",
        ],
        "refusals": [
            "no SELECT, no OPERATE, no retry",
            "no change to the point allowlist",
            "the guarded driver in active_harness/ is not replaced",
        ],
    }


def explain(p: dict[str, Any]) -> str:
    return json.dumps(p, indent=1)


def apply(p: dict[str, Any], runner, *, live: bool = False) -> dict[str, Any]:
    """Guarded entry point. Refuses unless explicitly authorised, then runs the steps."""
    if not live:
        raise ProbeRefused("apply() requires live=True; the default is a dry run")
    if os.environ.get(GUARD_ENV) != "1":
        raise ProbeRefused("apply() requires %s=1; this repository's offline work never sets it"
                           % GUARD_ENV)
    return run_steps(p, runner)


def run_steps(p: dict[str, Any], runner) -> dict[str, Any]:
    """Execute the plan, checking every step. No guard here: `apply()` owns that.

    Split out so the step logic can be tested offline against a scripted runner WITHOUT any
    test needing to set the hardware-authorisation flag, which nothing in this repository sets.
    `runner(argv) -> (returncode, stdout, stderr)` is injected; nothing here shells out.
    """
    record: dict[str, Any] = {"status": "aborted", "steps": [], "rule_removed": False}

    def step(name, argv, expect_zero=True):
        rc, out, err = runner(argv)
        ok = (rc == 0) if expect_zero else (rc != 0)
        record["steps"].append({"step": name, "argv": argv, "returncode": rc,
                                "stdout": out, "stderr": err, "ok": ok})
        return ok

    install = shlex.split(p["commands"]["install"])
    verify = shlex.split(p["commands"]["verify_installed"])
    remove = shlex.split(p["commands"]["remove"])

    if not step("install", install):
        raise ProbeRefused("install failed; nothing was held and no capture is valid")
    if not step("verify_installed", verify):
        step("remove_after_failed_verify", remove)
        raise ProbeRefused("rule did not verify after install")
    try:
        record["held_seconds"] = p["hold_seconds"]
    finally:
        removed = step("remove", remove)
        gone = step("verify_removed", verify, expect_zero=False)
        record["rule_removed"] = bool(removed and gone)

    if not record["rule_removed"]:
        record["failure"] = "the rule may still be installed; it was NOT confirmed removed"
        raise ProbeRefused(record["failure"])
    record["status"] = "completed"
    return record


if __name__ == "__main__":
    conn = Connection(src_ip="192.168.10.1", src_port=0, dst_ip="192.168.10.7", dst_port=20000,
                      interface="enp59s0f0np0", tcp_header_bytes=32)
    ctx = RunContext(capture_host="master", capture_point="master-facing NIC",
                     capture_precision="nanosecond", timing_mode="UNSET", shape_enable=-1,
                     loaded_program="UNSET", loaded_program_sha256="UNSET",
                     notes="source port and context must be filled from the real connection")
    print(explain(plan(conn, ctx, hold_seconds=40.0)))
    print("\nplan only; apply() needs live=True and %s=1" % GUARD_ENV)
