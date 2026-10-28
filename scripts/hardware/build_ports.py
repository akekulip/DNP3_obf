"""Every port the bring-up uses, read from the build itself: out/response_only.p4pp, which bf-p4c writes next
to bfrt.json. The ports are compile-time constants of N, E and T, so nothing here is a constant of ours.

Measured 2026-10-11 (evidence/recirc_ports_01/STATUS.md): on this switch only pipe-local port 68 recirculates
(dev 68 and 196). Every other looping port a build names must be a front-panel port put in MAC loopback.
"""
import re
from pathlib import Path

# our name -> constant in the composed source (n_ = N, t_ = T role prefixes from compose.py)
NAMES = dict(n_ack_return='n_N_ACK_RETURN', return_port='n_RETURN_PORT', n_handoff='n_READ_HANDOFF_PORT',
             pktgen_return='t_PKTGEN_RETURN', t_in='t_T_IN', hb_return='t_HB_RETURN', held_return='t_HELD_RETURN',
             forward='t_FORWARD_PORT', relay='t_RELAY_PORT', t_n_return='t_N_RETURN')
LOOP_NAMES = ('return_port', 'n_ack_return', 'pktgen_return', 't_in', 'hb_return', 'held_return')
INTERNAL_RECIRC_LOCAL = 68
DEAD_RECIRC_LOCALS = (69, 70, 71)
NEVER_LOOP = (9, 10, 11, 64)          # Vision, two cabled ports, the SEL-751 relay leg (STATUS.md "in use")


def read(build_out, timing_contract=None):
    """(ports dict, errors). Errors when a constant is missing or defined twice, or the roles disagree."""
    path = Path(build_out) / 'response_only.p4pp'
    if not path.is_file():
        return {}, ['%s is missing: the ports compiled into this build cannot be read' % path]
    text = path.read_text(errors='replace')
    ports, errs = {}, []
    for ours, const in NAMES.items():
        if ours == "hb_return" and timing_contract == "response_ready_ack_d_no_j_v3":
            if re.search(r"const PortId_t t_HB_RETURN\s*=", text):
                errs.append("no-J build retains the OPERATE HB port")
            continue
        found = re.findall(r'const PortId_t %s\s*=\s*9w(\d+)' % const, text)
        if len(found) != 1:
            errs.append('build defines %s %d times' % (const, len(found)))
        else:
            ports[ours] = int(found[0])
    sid = re.findall(r'const MirrorId_t t_CLONE_SESSION_ID\s*=\s*10w(\d+)', text)
    if len(sid) != 1:
        errs.append('build defines t_CLONE_SESSION_ID %d times' % len(sid))
    else:
        ports['clone_session'] = int(sid[0])
    # E's egress parser dispatches on two literal ports: the master's and N's ACK lap (make_e.py).
    e_ports = re.findall(r'transition select\(eg\.egress_port\)\s*\{\s*9w(\d+)\s*:\s*eth;\s*9w(\d+)\s*:\s*eth;', text)
    if len(e_ports) != 1:
        errs.append('build has %d E egress-port dispatches, expected 1' % len(e_ports))
    else:
        ports['e_ports'] = sorted(int(p) for p in e_ports[0])
    if errs:
        return ports, errs
    if ports['n_handoff'] != ports['t_in']:
        errs.append('N hands off to %d but T listens on %d' % (ports['n_handoff'], ports['t_in']))
    if ports['t_n_return'] != ports['return_port']:
        errs.append("T's N_RETURN %d is not N's RETURN_PORT %d" % (ports['t_n_return'], ports['return_port']))
    if ports['n_ack_return'] not in ports['e_ports']:
        errs.append("E dispatches on %s, which lacks N's ACK lap port %d" % (ports['e_ports'], ports['n_ack_return']))
    active_loops = loop_names(timing_contract)
    loops = [ports[n] for n in active_loops]
    if len(set(loops)) != len(loops):
        errs.append('looping ports are not distinct: %s' % {n: ports[n] for n in active_loops})
    for name in ('return_port', 'n_ack_return'):
        if ports[name] // 128 != 0:
            errs.append('%s %d is not in pipe 0' % (name, ports[name]))
    pipes = {ports[n] // 128 for n in active_loops if n not in ('return_port', 'n_ack_return')}
    if len(pipes) != 1:
        errs.append("T's ports span pipes %s" % sorted(pipes))
    if ports['pktgen_return'] % 128 != INTERNAL_RECIRC_LOCAL:
        errs.append('PKTGEN_RETURN %d is not a pipe-local 68: the generator delivers tokens only there' % ports['pktgen_return'])
    return ports, errs


def loop_names(timing_contract=None):
    return tuple(n for n in LOOP_NAMES if n != "hb_return") if timing_contract == "response_ready_ack_d_no_j_v3" else LOOP_NAMES


def loopback_ports(ports, timing_contract=None):
    """The looping ports that are front-panel ports (not a pipe-local 68), by role name."""
    return {n: ports[n] for n in loop_names(timing_contract) if ports[n] % 128 != INTERNAL_RECIRC_LOCAL}


def check_endpoints(ports, master_dev, relay_dev, timing_contract=None):
    """Errors unless the build was composed for these endpoint ports and no looping port is a port in use."""
    errs = []
    if ports['forward'] != master_dev:
        errs.append('build has t_FORWARD_PORT = %d, this plan needs %d' % (ports['forward'], master_dev))
    if ports['relay'] != relay_dev:
        errs.append('build has t_RELAY_PORT = %d, this plan needs %d' % (ports['relay'], relay_dev))
    if master_dev not in ports['e_ports']:
        errs.append("E dispatches on %s, which lacks the master's port %d" % (ports['e_ports'], master_dev))
    for name, port in sorted(loopback_ports(ports, timing_contract=timing_contract).items()):
        if port in NEVER_LOOP or port in (master_dev, relay_dev):
            errs.append('%s is dev_port %d, a port in use: it must never be put in loopback' % (name, port))
        if port % 128 in DEAD_RECIRC_LOCALS:
            errs.append('%s is dev_port %d: pipe-local 69-71 have $PORT entries but do not recirculate on this '
                        'switch and take no loopback (measured, evidence/recirc_ports_01); this build cannot run '
                        'here' % (name, port))
    return errs
