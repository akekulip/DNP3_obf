#!/usr/bin/env python3
"""Independently audit TCP retransmission flags in hash-bound capture inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

FILTER = ("tcp.analysis.retransmission || tcp.analysis.fast_retransmission || "
          "tcp.analysis.spurious_retransmission")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(measurements, out):
    source_bytes = measurements.read_bytes()
    doc = json.loads(source_bytes)
    captures = [(Path(p), expected) for p, expected in doc["inputs_sha256"].items()
                if Path(p).suffix in {".pcap", ".pcapng"}]
    if not captures:
        raise ValueError("no hash-bound captures in measurement inputs")
    version = subprocess.run(["tshark", "--version"], check=True, text=True,
                             capture_output=True).stdout.splitlines()[0]
    records = []
    for path, expected in sorted(captures):
        if sha(path) != expected:
            raise ValueError("capture changed since validation: " + str(path))
        run = subprocess.run(["tshark", "-n", "-r", str(path), "-Y", FILTER,
                              "-T", "fields", "-e", "frame.number"],
                             check=True, text=True, capture_output=True, timeout=60)
        if sha(path) != expected:
            raise ValueError("capture changed during audit: " + str(path))
        records.append(dict(capture=str(path), sha256=expected,
                            retransmission_frames=[int(x) for x in run.stdout.split()],
                            stderr=run.stderr))
    if measurements.read_bytes() != source_bytes:
        raise ValueError("measurement summary changed during audit; retry against stable summary")
    result = dict(tshark_version=version, filter=FILTER, captures=records,
                  measurements_sha256=hashlib.sha256(source_bytes).hexdigest(),
                  generator_sha256=sha(Path(__file__)), summary_status=doc["status"],
                  capture_count=len(records),
                  flagged_frame_count=sum(len(x["retransmission_frames"]) for x in records),
                  note="Wireshark TCP analysis flags; absence is not proof against uncaptured loss.")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.measurements, args.out)
    print(json.dumps({k:result[k] for k in ("summary_status", "capture_count", "flagged_frame_count")}))


if __name__ == "__main__":
    main()
