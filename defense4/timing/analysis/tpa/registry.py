"""Baseline registry: load, validate, and enforce pooling compatibility.

The registry is the authored authority for every timing dataset: what it is, where
its raw evidence lives, and what may be pooled with what. This module verifies the
registry against the committed raw files (paths, sha256, per-transaction schema,
units, timing definitions) and refuses to pool datasets that measure different
things, ran a different deadline policy, or were captured under different
definitions.

``measures`` semantics (the single most important pooling key):
  - ``native_clrt``          native CLRT C = t_R - t_A  (OFF passthrough)
  - ``defended_clrt_out``    master-facing CLRT_out under a deadline policy
  - ``defended_clrt_out_failopen`` master-facing CLRT_out in the fail-open regime

A native dataset and a defended dataset are NEVER poolable: one is the input
distribution the policy is designed against, the other is the policy output. Two
defended datasets running different (D_A, D_R) or budget are also NEVER poolable.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

from . import repo

logger = logging.getLogger(__name__)

# Registry fields that pin a dataset's identity; every one must match for two
# datasets to be poolable. Includes the policy (d_a_ms, d_r_ms, budget) so that
# outputs of different policies are never merged.
POOL_KEYS = (
    "measures",
    "unit_clrt",
    "t_A_def",
    "t_R_def",
    "C_def",
    "device",
    "binary_sha256",
    "capture_point",
    "state",
    "traffic_class",
    "d_a_ms",
    "d_r_ms",
    "budget",
)

REQUIRED_DATASET_FIELDS = (
    "id",
    "campaign",
    "measures",
    "device",
    "state",
    "traffic_class",
    "capture_point",
    "timestamp_source",
    "unit_clrt",
    "t_A_def",
    "t_R_def",
    "C_def",
    "d_a_ms",
    "d_r_ms",
    "budget",
    "poolable_with",
    "blocks",
)

VALID_MEASURES = {"native_clrt", "defended_clrt_out", "defended_clrt_out_failopen"}


class RegistryError(Exception):
    """Hard validation failure: a mismatch that must stop analysis."""


def is_unpinned(value) -> bool:
    return isinstance(value, str) and value.strip().upper().startswith("UNPINNED")


def numeric_constraint(value) -> float | None:
    """Parse an evidenced-constraint value into a float, or None if it is UNKNOWN.

    A constraint whose value is a string tagged ``UNKNOWN`` (case-insensitive) is
    treated as unavailable and returns None; the analysis must then leave the
    corresponding margin UNKNOWN rather than invent a bound. A plain number, or a
    string with a leading number (e.g. ``"400.0 (from gap_s)"``), is usable.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        if value.strip().upper().startswith("UNKNOWN"):
            return None
        try:
            return float(value.split()[0])
        except (ValueError, IndexError):
            return None
    return None


def load_registry(path: Path) -> dict:
    with open(path) as f:
        reg = yaml.safe_load(f)
    if not isinstance(reg, dict) or "datasets" not in reg:
        raise RegistryError(f"{path}: registry must be a mapping with a 'datasets' list")
    return reg


def collect_unpinned(reg: dict) -> list[dict]:
    """Every dataset field whose value is marked UNPINNED, for honest reporting."""
    out = []
    for ds in reg["datasets"]:
        for k, v in ds.items():
            if is_unpinned(v):
                out.append({"dataset": ds.get("id"), "field": k, "note": v})
    return out


def _validate_block_rows(rows: list[dict], unit_clrt: str, tol_ms: float = 0.05) -> None:
    """Confirm the per-transaction schema and that clrt matches t_R - t_A in the
    declared unit, for EVERY row (not only the first). Catches mixed / mislabeled
    time units and a single malformed row buried anywhere in the block.

    When a row carries ``t_read`` (the master READ / request timestamp t_Q), also
    confirm the read-to-ack interval a = (t_ack - t_read) * 1000 equals the recorded
    ``read_to_ack_ms`` in the same unit; a mismatch there is the same class of
    unit/definition defect as a bad clrt.
    """
    if not rows:
        raise RegistryError("block has zero rows")
    need = {"t_ack", "t_resp", "clrt_ms", "poll", "read_to_ack_ms"}
    if unit_clrt != "ms":
        raise RegistryError(
            f"unit_clrt='{unit_clrt}' unsupported; raw clrt_ms is milliseconds. "
            "A dataset declaring seconds against millisecond data is rejected."
        )
    for i, r in enumerate(rows):
        missing = need - set(r.keys())
        if missing:
            raise RegistryError(f"row {i} schema missing fields: {sorted(missing)}")
        # t_ack / t_resp are epoch seconds; clrt_ms must equal (t_resp-t_ack)*1000.
        recomputed = (r["t_resp"] - r["t_ack"]) * 1000.0
        if abs(recomputed - r["clrt_ms"]) > tol_ms:
            raise RegistryError(
                f"unit/timing-def mismatch at row {i}: clrt_ms={r['clrt_ms']:.4f} "
                f"but (t_resp-t_ack)*1000={recomputed:.4f} (>{tol_ms} ms apart)"
            )
        # a = t_A - t_Q, verified when the request timestamp is present.
        if "t_read" in r:
            recomputed_a = (r["t_ack"] - r["t_read"]) * 1000.0
            if abs(recomputed_a - r["read_to_ack_ms"]) > tol_ms:
                raise RegistryError(
                    f"read-to-ack (a) mismatch at row {i}: read_to_ack_ms="
                    f"{r['read_to_ack_ms']:.4f} but (t_ack-t_read)*1000="
                    f"{recomputed_a:.4f} (>{tol_ms} ms apart)"
                )


def validate(reg: dict, repo_root: Path, verify_sha: bool = True) -> list[str]:
    """Validate every dataset against the committed raw evidence.

    Returns a list of non-fatal warnings; raises RegistryError on any hard failure
    (missing field, missing file, sha mismatch, unit/timing-def mismatch, bad
    ``measures`` label, malformed ``poolable_with``).
    """
    warnings: list[str] = []
    ids = {ds.get("id") for ds in reg["datasets"]}
    for ds in reg["datasets"]:
        dsid = ds.get("id", "<no id>")
        for fld in REQUIRED_DATASET_FIELDS:
            if fld not in ds:
                raise RegistryError(f"{dsid}: missing required field '{fld}'")
        if ds["measures"] not in VALID_MEASURES:
            raise RegistryError(f"{dsid}: invalid measures '{ds['measures']}'")
        for peer in ds["poolable_with"]:
            if peer not in ids:
                raise RegistryError(f"{dsid}: poolable_with references unknown id '{peer}'")
        for blk in ds["blocks"]:
            p = repo.resolve(repo_root, blk["path"])
            if not p.exists():
                raise RegistryError(f"{dsid}: missing raw file {blk['path']}")
            if verify_sha:
                actual = repo.sha256_file(p)
                if actual != blk["sha256"]:
                    raise RegistryError(
                        f"{dsid}: sha256 mismatch for {blk['path']}\n"
                        f"  registry={blk['sha256']}\n  actual  ={actual}"
                    )
            d = json.loads(p.read_text())
            _validate_block_rows(d.get("rows", []), ds["unit_clrt"])
            if d.get("n_rows") not in (None, len(d["rows"])):
                warnings.append(f"{dsid}:{blk['path']} n_rows header != len(rows)")
        for fld in POOL_KEYS:
            if is_unpinned(ds.get(fld)):
                warnings.append(f"{dsid}: pool key '{fld}' is UNPINNED (pooling uses it)")
    _check_pool_symmetry(reg, warnings)
    return warnings


def _check_pool_symmetry(reg: dict, warnings: list[str]) -> None:
    by_id = {ds["id"]: ds for ds in reg["datasets"]}
    for ds in reg["datasets"]:
        for peer_id in ds["poolable_with"]:
            peer = by_id[peer_id]
            ok, reason = poolable(ds, peer)
            if not ok:
                raise RegistryError(
                    f"declared poolable_with is INCOMPATIBLE: {ds['id']} <-> {peer_id}: {reason}"
                )
            if ds["id"] not in peer["poolable_with"]:
                warnings.append(
                    f"poolable_with not symmetric: {peer_id} omits {ds['id']}"
                )


def poolable(a: dict, b: dict) -> tuple[bool, str]:
    """Two datasets may be pooled only if every POOL_KEY matches and neither
    matched key is UNPINNED. Returns (ok, reason)."""
    for k in POOL_KEYS:
        va, vb = a.get(k), b.get(k)
        if is_unpinned(va) or is_unpinned(vb):
            return False, f"pool key '{k}' is UNPINNED on one side"
        if va != vb:
            return False, f"pool key '{k}' differs: {va!r} != {vb!r}"
    return True, "compatible"


def pool_groups(reg: dict) -> dict[str, list[str]]:
    """Connected components over the (validated) poolable_with graph.

    Every declared edge is already known compatible (validate() enforced it), so a
    component is a legitimate pool. Returns {representative_id: [member_ids]}.
    """
    by_id = {ds["id"]: ds for ds in reg["datasets"]}
    seen: set[str] = set()
    groups: dict[str, list[str]] = {}
    for ds in reg["datasets"]:
        if ds["id"] in seen:
            continue
        stack, comp = [ds["id"]], []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            comp.append(cur)
            stack.extend(p for p in by_id[cur]["poolable_with"] if p not in seen)
        groups[sorted(comp)[0]] = sorted(comp)
    return groups
