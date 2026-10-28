"""Read the actual final compiler context; edits and failed attempts are not stage savings."""
import hashlib
import json
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_current_observation_map_matches_shipped_action_bodies():
    path = ROOT / 'scripts/model/telemetry_from_log.py'
    spec = importlib.util.spec_from_file_location('current_observations', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.verified_observations(ROOT/'p4/response_only.p4')['actions']


def stage_numbers(value):
    if isinstance(value, dict):
        if "stage_number" in value:
            yield value["stage_number"]
        for child in value.values():
            yield from stage_numbers(child)
    elif isinstance(value, list):
        for child in value:
            yield from stage_numbers(child)


@pytest.mark.parametrize("pipe,direction,limit", [
    ("p0", "ingress", 10), ("p0", "egress", 10),
    ("p1", "ingress", 8), ("p1", "egress", 4),
])
def test_current_final_allocation_meets_target(pipe, direction, limit):
    selected = json.loads((ROOT / "results/analysis/stage_cut/current_build.json").read_text())
    build = ROOT / selected["build"]
    report = json.loads((build / "compile_local/manifest.json").read_text())
    assert report["exit_code"] == 0
    assert hashlib.sha256((ROOT / 'p4/response_only.p4').read_bytes()).hexdigest() == selected['source_sha256']
    assert report["source_sha256"] == selected["source_sha256"]
    context = build / "compile_local/out" / pipe / "context.json"
    assert hashlib.sha256(context.read_bytes()).hexdigest() == report["artifact_sha256"][pipe + "/context.json"]
    tables = json.loads(context.read_text())["tables"]
    occupied = [n for table in tables if table.get("direction") == direction for n in stage_numbers(table)]
    assert occupied, "empty/unobserved pipeline cannot qualify"
    depth = max(occupied) + 1
    assert depth <= limit, "%s %s uses %d stages; required <=%d" % (pipe, direction, depth, limit)
