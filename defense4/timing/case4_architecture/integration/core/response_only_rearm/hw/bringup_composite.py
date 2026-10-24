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
    # relay_sbo (c48+) also strips provenance on the physical relay departure. Accept that one extra
    # entry only when it is this build's compiled t_RELAY_PORT, and remove it before the baseline reader.
    relay = re.findall(r'const PortId_t t_RELAY_PORT\s*=\s*9w(\d+)', text)
    departure = None
    if len(relay) == 1:
        entry = r'(transition\s+select\(eg\.egress_port\)\s*\{\s*9w\d+\s*:\s*provenance;)(\s*9w%s\s*:\s*provenance;)' % relay[0]
        found = list(re.finditer(entry + r'(\s*9w\d+\s*:\s*provenance;\s*default:\s*accept;\s*\})', text))
        if len(found) == 1:
            departure = int(relay[0])
            text = text[:found[0].start()] + found[0].group(1) + found[0].group(3) + text[found[0].end():]
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
        ports, errors = baseline_ports.read(temporary)
    if departure is not None and not errors:
        ports['e_relay_departure'] = departure
    return ports, errors


installer.build_ports = SimpleNamespace(read=candidate_ports,
                                        check_endpoints=baseline_ports.check_endpoints,
                                        loopback_ports=baseline_ports.loopback_ports)


# read_complete_01 policy builds: the pipe-1 READ padder is enabled per connection by p1_conn, installed exactly
# when E's fwd_conn row enables padding (cp.p1_pad_rows). Only a build whose compiled program has that table
# gets the row; every other build installs exactly the rows it did before.
P1_PAD = {'enabled': False}
original_rows_build = installer.rows.build


def p1_ops(master, outstation, pad_enable):
    if not P1_PAD['enabled']:
        return []
    return [dict(kind='p4', pipe=0xffff, table=table, priority=priority, action=action,
                 key=[(f, v, None) for f, v in key], data=list(data))
            for table, key, action, data, priority in candidate_cp.p1_pad_rows(outstation, master, pad_enable)]


def rows_with_p1(master, outstation, decoy, ports, read_dst=0x0000, read_src=0x0100, pad_enable=True):
    rows = original_rows_build(master, outstation, decoy, ports, read_dst, read_src, pad_enable=pad_enable)
    return rows + p1_ops(master, outstation, pad_enable)


installer.rows.build = rows_with_p1
original_plan = installer.plan


def plan_with_p1(a, ports):
    """The baseline plan keeps only p0.r_/p0.n_ rows, so the p1 row is placed here: after E's rows and before
    any N row, so no READ is bound by N before the padder's enable is in place (rc01_hw_b08_20261021_01)."""
    ops = original_plan(a, ports)
    master, outstation = installer.rows.endpoints(a.master_ip, a.master_port, a.master_dev,
                                                  a.relay_ip, a.relay_port, a.relay_dev)
    extra = p1_ops(master, outstation, a.pad_enable)
    if not extra:
        return ops
    first_n = next((i for i, op in enumerate(ops) if (op.get('table') or '').startswith('p0.n_')), None)
    if first_n is None:
        raise SystemExit('REFUSED: the plan has no N row to place the pipe-1 padder enable before')
    return ops[:first_n] + extra + ops[first_n:]


installer.plan = plan_with_p1


profile = module('rearm_sealed_profile', HERE / 'sealed_profile.py')
original_readback = installer.readback
sealed_readback = module('rearm_sealed_readback', BASE / 'hw' / 'readback.py')


def configure(build_out):
    p4pp = Path(build_out) / 'response_only.p4pp'
    P1_PAD['enabled'] = p4pp.is_file() and 'p1_conn' in p4pp.read_text(errors='replace')
    descriptor = profile.describe(build_out)
    sealed = descriptor['sealed']
    # Rebuild from the original map so a later three-bank install restores all banks.
    sealed_readback.T_REGISTER_INIT = {name: value for name, value in original_readback.T_REGISTER_INIT.items()
                                      if name != 'quarantine_reg' and
                                      (not name.startswith('child_seen') or name in profile.child_registers(descriptor))}
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
