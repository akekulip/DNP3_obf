#!/usr/bin/env python3
"""Candidate-only installer entrypoint; baseline SHA/mirror gates retained."""
import argparse
import importlib.util
import re
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
BASE = HERE.parent.parent / 'response_only'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


# Load the unchanged installer and its dependencies, then choose candidate rows
# through one explicit module injection. The other hardware entrypoints stay on
# their existing baseline profile.
sys.path[:0] = [str(BASE), str(BASE / 'hw')]
installer = module('rearm_base_installer', BASE / 'hw' / 'bringup_composite.py')
candidate_cp = module('rearm_candidate_cp', HERE.parent / 'cp.py')
installer.rows.cp = candidate_cp

baseline_ports = installer.build_ports


def candidate_ports(build_out):
    """Check the private parser, then reuse the baseline's port invariants."""
    path = Path(build_out) / 'response_only.p4pp'
    if not path.is_file():
        return {}, ['compiled candidate source is missing: ' + str(path)]
    text = path.read_text(errors='replace')
    dispatch = (r'transition\s+select\(eg\.egress_port\)\s*\{\s*'
                r'9w\d+\s*:\s*provenance;\s*9w\d+\s*:\s*provenance;\s*default:\s*accept;\s*\}')
    provenance = (r'state\s+provenance\s*\{\s*pkt\.extract\(hdr\.prov\);\s*'
                  r'transition\s+select\(hdr\.prov\.reserved\)\s*\{\s*'
                  r'16w0:\s*eth;\s*default:\s*reject;\s*\}\s*\}')
    matches = list(re.finditer(dispatch, text))
    if len(matches) != 1 or len(re.findall(provenance, text)) != 1:
        return {}, ['candidate E must dispatch exactly two ports through reserved-zero provenance to Ethernet']
    match = matches[0]
    # Only the verified dispatch target differs from the baseline reader's
    # syntax. Literal ports and all common port/loopback checks are unchanged.
    normalized = text[:match.start()] + match.group().replace('provenance;', 'eth;') + text[match.end():]
    with tempfile.TemporaryDirectory(prefix='rearm_port_check_') as temporary:
        (Path(temporary) / path.name).write_text(normalized)
        return baseline_ports.read(temporary)


installer.build_ports = SimpleNamespace(read=candidate_ports,
                                        check_endpoints=baseline_ports.check_endpoints,
                                        loopback_ports=baseline_ports.loopback_ports)


profile = module('rearm_sealed_profile', HERE / 'sealed_profile.py')
original_readback = installer.readback
sealed_readback = module('rearm_sealed_readback', BASE / 'hw' / 'readback.py')
sealed_readback.T_REGISTER_INIT = dict(original_readback.T_REGISTER_INIT)
del sealed_readback.T_REGISTER_INIT['quarantine_reg']


def configure(build_out):
    sealed = profile.select(build_out)
    installer.readback = sealed_readback if sealed else original_readback
    return sealed


def build_argument(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--build-out', required=True)
    return parser.parse_known_args(argv)[0].build_out


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if '--help' not in args and '-h' not in args:
        configure(build_argument(args))
    return installer.main(args)


if __name__ == '__main__':
    sys.exit(main())
