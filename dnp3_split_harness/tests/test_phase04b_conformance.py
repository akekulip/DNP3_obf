"""eBPF <-> Python DCRN decision-core conformance (corrective.md sec 4).

Compiles the userspace harness that shares bpf/phase04b_dcrn_common.h with the eBPF data plane, feeds
it a battery of decision commands (target selection, cumulative-ACK coverage, reverse classification,
release scheduling), and asserts the C output matches the Python oracle
(phase04b_dcrn_policy.py) bit-for-bit. Writes a machine-readable conformance result. This does NOT
prove the kernel enforces the EDT -- only that the shared decision logic is identical (the kernel
enforcement is validated later from the PI-run PCAPs).

    python3 -m pytest tests/test_phase04b_conformance.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import phase04b_dcrn_policy as D

BPF = os.path.join(HERE, "bpf")
SRC = os.path.join(BPF, "phase04b_dcrn_conformance.c")
OUT_JSON = os.path.join(HERE, "reports", "phases", "phase_04b_dual_case_timing", "conformance.json")


def _build_harness():
    cc = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        return None
    binp = tempfile.mktemp(prefix="dcrn_conf_")
    r = subprocess.run([cc, "-O2", "-I", BPF, "-o", binp, SRC], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("harness build failed:\n" + r.stderr)
    return binp


def _battery():
    cmds, expected, labels = [], [], []

    def add(cmd, exp, label):
        cmds.append(cmd); expected.append(exp); labels.append(label)

    LO, HI, FX, DH = 32390000, 42390000, 32390000, 151000000
    add("TARGET 1 20260717 5 %d %d %d %d" % (LO, HI, FX, DH),
        str(D.select_target_ns(1, 20260717, 5, LO, HI, FX, )), "target_fixed")
    for ctr in range(0, 24):
        add("TARGET 2 20260717 %d %d %d 0 %d" % (ctr, LO, HI, DH),
            str(D.select_target_ns(2, 20260717, ctr, LO, HI, 0)), "target_bounded_%d" % ctr)
    add("TARGET 0 1 9 1 2 3 100", "0", "target_native")

    for a, e in [(135, 135), (200, 135), (100, 135), (2, 0xFFFFFFF0), (0xFFFFFFF0, 2)]:
        add("COVERS %d %d" % (a, e), "1" if D.ack_covers(a, e) else "0", "covers_%d_%d" % (a, e))

    classify = [
        (54, 1, 0, 0, 0, 1, 0, 1),   # ACK-bearing response
        (0, 1, 0, 0, 0, 0, 0, 1),    # pure ACK
        (8, 1, 0, 0, 0, 1, 1, 1),    # CONFIRM -> bypass
        (54, 1, 0, 0, 0, 1, 0, 0),   # response not covering -> bypass
        (0, 1, 0, 0, 0, 0, 0, 0),    # ACK not covering -> bypass
        (0, 0, 1, 0, 0, 0, 0, 1),    # SYN -> bypass
        (0, 1, 0, 1, 0, 0, 0, 1),    # FIN -> bypass
    ]
    for c in classify:
        add("CLASSIFY %d %d %d %d %d %d %d %d" % c, str(D.classify_reverse_core(*c)),
            "classify_%s" % "_".join(map(str, c)))

    release = [
        (2, 16000000, 32390000, 0, 200000, 0),   # combined response -> deadline
        (1, 3700000, 32390000, 1, 200000, 0),    # separate pure ACK -> deadline
        (2, 16000000, 32390000, 1, 200000, 0),   # separate response (FIFO unreliable) -> deadline+guard
        (2, 16000000, 32390000, 1, 200000, 1),   # separate response (FIFO reliable) -> deadline
        (2, 40000000, 32390000, 0, 200000, 0),   # late -> pass immediately, deadline miss
    ]
    for c in release:
        rel, miss = D.release_ns(c[0], c[1], c[2], bool(c[3]), c[4], bool(c[5]))
        add("RELEASE %d %d %d %d %d %d" % c, "%d %d" % (rel, miss), "release_%s" % "_".join(map(str, c)))

    return cmds, expected, labels


def test_ebpf_python_conformance():
    binp = _build_harness()
    if binp is None:
        try:
            import pytest
            pytest.skip("no C compiler available to build the conformance harness")
        except ImportError:
            return
    cmds, expected, labels = _battery()
    r = subprocess.run([binp], input="\n".join(cmds) + "\n", capture_output=True, text=True)
    os.remove(binp)
    got = r.stdout.strip().splitlines()
    assert len(got) == len(expected), "harness produced %d lines, expected %d" % (len(got), len(expected))
    mism = [{"label": labels[i], "cmd": cmds[i], "python": expected[i], "c": got[i]}
            for i in range(len(expected)) if got[i].strip() != expected[i].strip()]
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w") as fh:
        json.dump({"cases": len(expected), "mismatches": len(mism), "conformant": not mism,
                   "shared_header": "bpf/phase04b_dcrn_common.h",
                   "note": "decision-logic conformance only; kernel EDT enforcement validated from PI-run PCAPs",
                   "detail": mism[:20]}, fh, indent=2)
    assert not mism, "eBPF<->Python decision mismatches: %s" % mism[:5]


if __name__ == "__main__":
    test_ebpf_python_conformance()
    print("conformance OK; wrote", OUT_JSON)
