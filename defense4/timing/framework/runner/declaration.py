"""Fail-closed declaration and campaign budgets; validation never starts traffic.

Explicit run lists fix each operation, arm and D_A before collection. SBO units are
pairs, hence two attempted transactions. Warmups, prechecks and state READs count
against the same ceiling as primary data. Legacy Cartesian declarations remain
readable but also receive the attempt-ceiling check.
"""
import hashlib
import json
import math
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
OPS = {"READ", "SELECT"}
ARMS = {"OFF", "RESPONSE_READY", "LEGACY_D4", "CASE4"}
ORDERS = {"counterbalanced", "fixed"}
MAX_TOTAL_ATTEMPTS = 18360
REQUIRED = ("id", "declared_on", "source", "build", "policy", "workload", "endpoints",
            "observation_points", "tolerances", "failure_outcomes", "termination")
RUN_REQUIRED = ("id", "phase", "op", "arm", "da_ms", "blocks", "primary_per_block",
                "warmup_per_block", "precheck_per_block", "state_reads_per_block",
                "interval_ms", "transaction_timeout_ms", "setup_budget_ms")


def _need(d, keys, where, out):
    for k in keys:
        if k not in d:
            out.append(f"{where}: missing '{k}'")


def _number(value, minimum=0):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and value >= minimum
    except OverflowError:
        return False


def _count(value, minimum=0):
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _attended_sbo(decl):
    c = decl.get("collection", {})
    return (isinstance(c, dict) and c.get("attended_only") is True
            and c.get("scope") == "sbo_smoke" and c.get("hardware_authorized") is False)


def budget_summary(decl):
    """Computed upper bounds, never an admission or hardware authorization.

    Duration charges every attempted transaction its full application timeout,
    every trial unit a full spacing interval, and setup per block. OPERATE in an
    SBO pair is immediate after SELECT; spacing is between pairs only. Retries
    must be separately declared attempts, never added by a runner implicitly.
    """
    w = decl["workload"]
    if "run_list" in w:
        runs = w["run_list"]
    else:
        runs = [dict(op=op, blocks=w["blocks"], primary_per_block=w["attempted_per_block"],
                     warmup_per_block=w["warmup_exchanges"], precheck_per_block=w.get("precheck_exchanges", 0),
                     state_reads_per_block=w.get("state_reads_per_block", 0), interval_ms=w["interval_ms"],
                     transaction_timeout_ms=w.get("transaction_timeout_ms", 500),
                     setup_budget_ms=w.get("setup_budget_ms", 1000))
                for op in w["ops"] for _arm in decl["policy"]["arms"] for _da in decl["policy"]["da_ms"]]
    summary = dict(attempted_transactions=0, primary_transactions=0, warmup_transactions=0,
                   precheck_transactions=0, state_read_transactions=0, blocks=0, max_duration_ms=0)
    for row in runs:
        blocks, multiplier = row["blocks"], (2 if row["op"] == "SBO" else 1)
        units = 0
        for source, target in (("primary_per_block", "primary_transactions"),
                               ("warmup_per_block", "warmup_transactions"),
                               ("precheck_per_block", "precheck_transactions")):
            count = row[source] * blocks
            units += count
            summary[target] += count * multiplier
        states = row["state_reads_per_block"] * blocks
        summary["state_read_transactions"] += states
        attempts = units * multiplier + states
        summary["attempted_transactions"] += attempts
        summary["blocks"] += blocks
        summary["max_duration_ms"] += (attempts * row["transaction_timeout_ms"]
            + (units + states) * row["interval_ms"] + blocks * row["setup_budget_ms"])
    summary["max_duration_ms"] = math.ceil(summary["max_duration_ms"])
    return summary


def _runs_problem(decl, out):
    w, p = decl["workload"], decl["policy"]
    _need(w, ("ops", "seed", "order"), "workload", out)
    ops = w.get("ops", [])
    allowed = OPS | ({"SBO"} if _attended_sbo(decl) else set())
    if not isinstance(ops, list) or not ops or any(not isinstance(op, str) or op not in allowed for op in ops):
        out.append("workload.ops must contain READ or SELECT; SBO needs a separate attended-only sbo_smoke declaration; OPERATE is attended-only")
    if isinstance(ops, list) and "SBO" in ops and ops != ["SBO"]:
        out.append("attended SBO must be in a separate declaration")
    if not isinstance(w.get("order"), str) or w["order"] not in ORDERS:
        out.append(f"workload.order must be one of {sorted(ORDERS)}")
    if isinstance(w.get("seed"), bool) or not isinstance(w.get("seed"), int):
        out.append("workload.seed must be an integer (recorded, not drawn)")
    if "run_list" in w:
        rows = w["run_list"]
        if not isinstance(rows, list) or not rows:
            out.append("workload.run_list must be a non-empty explicit list")
            return
        ids = set()
        for i, row in enumerate(rows):
            where = f"workload.run_list[{i}]"
            if not isinstance(row, dict):
                out.append(where + " must be an object")
                continue
            _need(row, RUN_REQUIRED, where, out)
            for key in ("id", "phase"):
                if not isinstance(row.get(key), str) or not row[key]:
                    out.append(f"{where}.{key} must be a non-empty string")
            identity = row.get("id")
            if isinstance(identity, str):
                if identity in ids:
                    out.append(f"{where}: duplicate run id {identity!r}")
                ids.add(identity)
            if (not isinstance(row.get("op"), str) or row["op"] not in allowed
                    or not isinstance(ops, list) or row["op"] not in ops):
                out.append(where + ".op must be declared in workload.ops; SBO is attended-only")
            if row.get("arm") not in p.get("arms", []):
                out.append(where + ".arm must be declared in policy.arms")
            if not _number(row.get("da_ms")) or row.get("da_ms") not in p.get("da_ms", []):
                out.append(where + ".da_ms must be declared in policy.da_ms")
            for key in ("blocks", "primary_per_block", "warmup_per_block", "precheck_per_block", "state_reads_per_block"):
                if not _count(row.get(key), 1 if key in ("blocks", "primary_per_block") else 0):
                    out.append(f"{where}.{key} must be an integer in range")
            for key in ("interval_ms", "transaction_timeout_ms", "setup_budget_ms"):
                if not _number(row.get(key), 0 if key == "setup_budget_ms" else 0.000001):
                    out.append(f"{where}.{key} must be finite and in range")
        row_ops = [row.get("op") for row in rows if isinstance(row, dict)]
        if (isinstance(ops, list) and all(isinstance(op, str) for op in ops + row_ops)
                and set(row_ops) != set(ops)):
            out.append("run-list operations must match workload.ops")
    else:
        _need(w, ("attempted_per_block", "blocks", "interval_ms", "warmup_exchanges"), "workload", out)
        for key in ("attempted_per_block", "blocks", "warmup_exchanges", "precheck_exchanges", "state_reads_per_block"):
            value = w.get(key, 0)
            if not _count(value, 1 if key in ("attempted_per_block", "blocks") else 0):
                out.append(f"workload.{key} must be an integer in range")
        for key, default in (("interval_ms", None), ("transaction_timeout_ms", 500), ("setup_budget_ms", 1000)):
            if not _number(w.get(key, default), 0 if key == "setup_budget_ms" else 0.000001):
                out.append(f"workload.{key} must be finite and in range")


def validate(decl: dict) -> list:
    out = []
    if not isinstance(decl, dict):
        return ["declaration must be an object"]
    _need(decl, REQUIRED, "declaration", out)
    if out:
        return out
    for key in ("source", "build", "policy", "workload", "termination"):
        if not isinstance(decl[key], dict):
            out.append(f"{key} must be an object")
    if out:
        return out
    for key in ("source", "build"):
        sha = decl[key].get("sha256", "")
        if not isinstance(sha, str) or not HEX64.fullmatch(sha):
            out.append(f"{key}.sha256 must be 64 lowercase hex characters")
    b = decl["build"]
    _need(b, ("sde", "stages_ingress", "stages_egress"), "build", out)
    for key in ("stages_ingress", "stages_egress"):
        if not _count(b.get(key)) or b.get(key, 99) > 12:
            out.append("build exceeds the 12-stage Tofino-1 limit or has an invalid stage count")
    p = decl["policy"]
    _need(p, ("arms", "da_ms", "gap_ms", "anchor"), "policy", out)
    arms, delays = p.get("arms"), p.get("da_ms")
    if not isinstance(arms, list) or not arms or any(not isinstance(a, str) or a not in ARMS for a in arms):
        out.append(f"policy.arms must be a non-empty subset of {sorted(ARMS)}")
    if isinstance(arms, list) and all(isinstance(a, str) for a in arms) and len(set(arms)) != len(arms):
        out.append("policy.arms has duplicate dimensions")
    if isinstance(delays, list) and all(_number(x) for x in delays) and len(set(delays)) != len(delays):
        out.append("policy.da_ms has duplicate dimensions")
    if p.get("anchor") not in ("request", "native_ack"):
        out.append("policy.anchor must be 'request' or 'native_ack'")
    if not isinstance(delays, list) or not delays or any(not _number(x, 0.000001) for x in delays):
        out.append("policy.da_ms must be a non-empty list of positive finite values")
    if not _number(p.get("gap_ms"), 0.000001):
        out.append("policy.gap_ms must be positive and finite")
    # Do not inspect rows against malformed policy lists or compute an invalid budget.
    if isinstance(arms, list) and isinstance(delays, list):
        _runs_problem(decl, out)
    if not decl["observation_points"]:
        out.append("observation_points must name at least one capture point")
    failures = decl["failure_outcomes"]
    if not isinstance(failures, (dict, list)):
        out.append("failure_outcomes must be an object or list")
        failures = []
    for name in ("late", "fallback", "missing", "rejected", "bypassed", "malformed"):
        if name not in failures:
            out.append(f"failure_outcomes must account for '{name}'")
    t = decl["termination"]
    _need(t, ("max_total_attempts", "abort_on"), "termination", out)
    if not _count(t.get("max_total_attempts"), 1):
        out.append("termination.max_total_attempts must be a positive integer")
    elif t["max_total_attempts"] > MAX_TOTAL_ATTEMPTS:
        out.append("termination.max_total_attempts exceeds the global 18,360 ceiling")
    if "run_list" in decl["workload"] and not _number(t.get("max_duration_ms"), 0.000001):
        out.append("termination.max_duration_ms must bound the explicit run-list duration")
    if out:
        # Retain the useful warmup diagnostic even when another field is invalid.
        if decl["workload"].get("warmup_exchanges", 0) and t.get("warmup_raw_retained") is not True:
            out.append("a warm-up exclusion requires termination.warmup_raw_retained = true")
        return out
    try:
        summary = budget_summary(decl)
    except (OverflowError, ValueError):
        return ["computed duration exceeds the numeric range"]
    attempts = summary["attempted_transactions"]
    if attempts > MAX_TOTAL_ATTEMPTS:
        out.append(f"computed {attempts} attempts exceeds the global 18,360 ceiling")
    if attempts > t["max_total_attempts"]:
        out.append(f"computed {attempts} attempts exceeds termination.max_total_attempts")
    if "max_duration_ms" in t and (not _number(t["max_duration_ms"], 0.000001)
            or summary["max_duration_ms"] > t["max_duration_ms"]):
        out.append("computed duration exceeds termination.max_duration_ms")
    for count, retained, label in (("warmup_transactions", "warmup_raw_retained", "warm-up"),
                                   ("precheck_transactions", "precheck_raw_retained", "precheck"),
                                   ("state_read_transactions", "state_read_raw_retained", "state READ")):
        if summary[count] and t.get(retained) is not True:
            out.append(f"{label} raw evidence requires termination.{retained} = true")
    return out


def validate_campaign(declarations, *, max_total_attempts=MAX_TOTAL_ATTEMPTS, max_duration_ms=None):
    """Validate combined budgets so splitting a campaign cannot reset its ceiling."""
    out = []
    if not isinstance(declarations, list) or not declarations:
        return ["campaign must contain declarations"]
    for i, decl in enumerate(declarations):
        out.extend(f"campaign[{i}]: {problem}" for problem in validate(decl))
    if not _count(max_total_attempts, 1) or max_total_attempts > MAX_TOTAL_ATTEMPTS:
        out.append("campaign attempt limit must be within the global 18,360 ceiling")
    if max_duration_ms is not None and not _number(max_duration_ms, 0.000001):
        out.append("campaign duration limit must be positive and finite")
    if out:
        return out
    summaries = [budget_summary(decl) for decl in declarations]
    attempts = sum(s["attempted_transactions"] for s in summaries)
    if attempts > MAX_TOTAL_ATTEMPTS:
        out.append(f"campaign computes {attempts} attempts above the global 18,360 ceiling")
    if attempts > max_total_attempts:
        out.append("campaign attempts exceed its declared limit")
    if max_duration_ms is not None and sum(s["max_duration_ms"] for s in summaries) > max_duration_ms:
        out.append("campaign duration exceeds its declared limit")
    return out


def digest(decl: dict) -> str:
    return hashlib.sha256(json.dumps(decl, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load(path) -> dict:
    return json.loads(Path(path).read_text())
