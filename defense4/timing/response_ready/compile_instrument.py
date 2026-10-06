#!/usr/bin/env python3
"""Exclusively reserve an instrument variant and retain its parent-source identity.

Offline compiler only. No BFRT connection, deployment, or hardware acquisition.
The ordinary compiler evidence helper performs the full target compile; failures
remain in the reserved directory and cannot be overwritten.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--source',type=Path,default=HERE/'src/defense4_response_ready.p4')
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    core=args.source.read_bytes()
    variant=b'#define CASE4_INSTRUMENT 1\n'+core
    (output/'source_core.p4').write_bytes(core)
    candidate=output/'source_instrument.p4';candidate.write_bytes(variant)
    command=[sys.executable,str(HERE.parent/'stage_reduction/build.py'),str(candidate),
             str(output/'compiled'),'--max-ingress','12']
    identity=dict(core_source=str(args.source.resolve()),core_sha256=hashlib.sha256(core).hexdigest(),
                  instrument_sha256=hashlib.sha256(variant).hexdigest(),command=command,
                  variant='CASE4_INSTRUMENT',learn_bytes=36,hardware_contact=False)
    (output/'source_binding.json').write_text(json.dumps(identity,indent=2)+'\n')
    result=subprocess.run(command)
    identity['exit_code']=result.returncode
    (output/'result.json').write_text(json.dumps(identity,indent=2)+'\n')
    return result.returncode

if __name__=='__main__':raise SystemExit(main())
