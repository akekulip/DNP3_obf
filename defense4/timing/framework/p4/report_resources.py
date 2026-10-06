"""Summarize source-bound compiler stage evidence without copying SDK outputs."""
import hashlib
import json
import re
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(build):
    build = Path(build)
    manifest = json.loads((build / "manifest.json").read_text())
    source = build / manifest["source"]
    if digest(source) != manifest["source_sha256"]:
        raise ValueError("compiler source snapshot differs from its manifest")
    inputs_verified = None
    if "inputs_sha256" in manifest:
        inputs_path = build / "inputs.json"
        if digest(inputs_path) != manifest["inputs_sha256"]:
            raise ValueError("compiler inputs snapshot differs from its manifest")
        inputs = json.loads(inputs_path.read_text())
        if inputs["output_sha256"] != manifest["source_sha256"]:
            raise ValueError("joint composition does not identify the compiler source")
        inputs_verified = True
    stages = {"ingress": set(), "egress": set()}
    assembly = {}
    for relative, expected in manifest["artifact_sha256"].items():
        if not relative.endswith(".bfa"):
            continue
        path = build / relative
        if digest(path) != expected:
            raise ValueError("assembler output differs from its manifest")
        assembly[relative] = expected
        for stage, direction in re.findall(r"^stage (\d+) (ingress|egress):", path.read_text(), re.M):
            stages[direction].add(int(stage))
    required = ("ingress",) if manifest["source"] == "case4_ingress_mapping.p4" else ("ingress", "egress")
    if manifest["exit_code"] == 0 and not all(stages[d] for d in required):
        raise ValueError("size/joint compiler evidence requires both ingress and egress stages")
    span = {direction: max(values) + 1 if values else None for direction, values in stages.items()}
    return {
        "source": manifest["source"],
        "source_sha256": manifest["source_sha256"],
        "compiler": manifest["compiler"],
        "compiler_exit_code": manifest["exit_code"],
        "inputs_identity_verified": inputs_verified,
        "assembler_sha256": assembly,
        "stage_indices": {direction: sorted(values) for direction, values in stages.items()},
        "stage_span": span,
        "required_directions": list(required),
        "within_stage_limits": manifest["exit_code"] == 0 and bool(assembly)
        and all(span[d] is not None and span[d] <= 12 for d in required),
        "software_only": True,
        "scope": (
            "joint component coexistence only; no complete Case4, runtime or admission proof"
            if "inputs_sha256" in manifest else
            "standalone component compilation; no joint fit, runtime or admission proof"
        ),
    }


if __name__ == "__main__":
    report = summarize(sys.argv[1])
    print(json.dumps(report, indent=2))
