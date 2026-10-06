"""Experiment declaration: committed before collection, validated fail-closed.

A declaration fixes what will be measured so that nothing is chosen after seeing data. validate()
returns a list of problems; an empty list is the only pass. No third-party dependency.
"""
import hashlib
import json
import re
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
OPS = {"READ", "SELECT"}               # OPERATE is attended-only and never declared here
ARMS = {"OFF", "RESPONSE_READY", "LEGACY_D4"}
ORDERS = {"counterbalanced", "fixed"}
REQUIRED = ("id", "declared_on", "source", "build", "policy", "workload", "endpoints",
            "observation_points", "tolerances", "failure_outcomes", "termination")


def _need(d, keys, where, out):
    for k in keys:
        if k not in d:
            out.append(f"{where}: missing '{k}'")


def validate(decl: dict) -> list:
    out = []
    if not isinstance(decl, dict):
        return ["declaration must be an object"]
    _need(decl, REQUIRED, "declaration", out)
    if out:
        return out
    for k in ("source", "build"):
        sha = decl[k].get("sha256", "")
        if not HEX64.match(sha):
            out.append(f"{k}.sha256 must be 64 lowercase hex characters")
    _need(decl["build"], ("sde", "stages_ingress", "stages_egress"), "build", out)
    if decl["build"].get("stages_ingress", 99) > 12 or decl["build"].get("stages_egress", 99) > 12:
        out.append("build exceeds the 12-stage Tofino-1 limit")
    p = decl["policy"]
    _need(p, ("arms", "da_ms", "gap_ms", "anchor"), "policy", out)
    if not set(p.get("arms", [])) <= ARMS or not p.get("arms"):
        out.append(f"policy.arms must be a non-empty subset of {sorted(ARMS)}")
    if p.get("anchor") not in ("request", "native_ack"):
        out.append("policy.anchor must be 'request' or 'native_ack'")
    if not p.get("da_ms") or any(x <= 0 for x in p["da_ms"]):
        out.append("policy.da_ms must be a non-empty list of positive values")
    w = decl["workload"]
    _need(w, ("ops", "attempted_per_block", "blocks", "interval_ms", "warmup_exchanges", "seed", "order"),
          "workload", out)
    if not set(w.get("ops", [])) <= OPS or not w.get("ops"):
        out.append(f"workload.ops must be a non-empty subset of {sorted(OPS)} (OPERATE is attended-only)")
    if w.get("order") not in ORDERS:
        out.append(f"workload.order must be one of {sorted(ORDERS)}")
    if not isinstance(w.get("seed"), int):
        out.append("workload.seed must be an integer (recorded, not drawn)")
    for k in ("attempted_per_block", "blocks", "interval_ms"):
        if not isinstance(w.get(k), (int, float)) or w.get(k, 0) <= 0:
            out.append(f"workload.{k} must be positive")
    if w.get("warmup_exchanges", 0) and not decl["termination"].get("warmup_raw_retained"):
        out.append("a warm-up exclusion requires termination.warmup_raw_retained = true")
    if not decl["observation_points"]:
        out.append("observation_points must name at least one capture point")
    for name in ("late", "fallback", "missing", "rejected", "bypassed", "malformed"):
        if name not in decl["failure_outcomes"]:
            out.append(f"failure_outcomes must account for '{name}'")
    t = decl["termination"]
    _need(t, ("max_total_attempts", "abort_on"), "termination", out)
    return out


def digest(decl: dict) -> str:
    """Stable identity of a declaration, recorded in every run manifest."""
    return hashlib.sha256(json.dumps(decl, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load(path) -> dict:
    return json.loads(Path(path).read_text())
