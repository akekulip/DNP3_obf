"""Compose current timing ingress and ledger-free size egress for compiler fit only."""
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1] / "response_ready/src/defense4_response_ready.p4"
WIRE = HERE / "case4_wire_only.p4"
OUT = HERE / "case4_joint_component_probe.p4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def generate():
    timing_bytes = TIMING.read_bytes()
    wire_bytes = WIRE.read_bytes()
    timing = timing_bytes.decode()
    wire = wire_bytes.decode()
    timing_ingress = timing[:timing.index("\nstruct eg_meta_t")]
    declarations = wire[wire.index("const bit<16> RRC_49"):wire.index("parser IgParser")]
    egress = wire[wire.index("parser EgParser"):wire.index("Pipeline(")]
    names = re.findall(r"^(?:header|struct) (\w+)", declarations, re.M)
    names += ["RRC_49", "RRC_57", "EgParser", "Egress", "EgDeparser"]
    renames = {name: "size_" + name for name in names}
    tokens = re.compile(r"\b(?:" + "|".join(map(re.escape, renames)) + r")\b")
    size = tokens.sub(lambda match: renames[match.group()], declarations + egress)
    header = """/* NON-DEPLOYABLE JOINT COMPONENT FIT PROBE.
 * Timing ingress is preserved; only the former empty egress is replaced.
 * No TCP translation ledger or timing/padding association integration.
 * Size ingress response CRC/shape guards are absent. PRE carving is unconfigured.
 * Neither this source nor a compiler PASS proves a working joint Case 4 system.
 */
"""
    result = header + timing_ingress + "\n" + size + "\n" + (
        "Pipeline(IgParser(), Ingress(), IgDeparser(), size_EgParser(), "
        "size_Egress(), size_EgDeparser()) pipe;\nSwitch(pipe) main;\n"
    )
    OUT.write_text(result)
    inputs = {
        "timing_source": str(TIMING), "timing_source_sha256": sha(timing_bytes),
        "timing_ingress_prefix_sha256": sha(timing_ingress.encode()),
        "wire_source": str(WIRE), "wire_source_sha256": sha(wire_bytes),
        "output_sha256": sha(result.encode()),
        "scope": "compiler coexistence only; no ledger, response guards or joint association",
        "software_only": True, "deployment_permitted": False,
    }
    OUT.with_suffix(".inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    return inputs


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
