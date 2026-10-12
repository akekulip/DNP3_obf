#!/usr/bin/env python3
"""Vision side of a software-endpoint run through the switch. Run with sudo python3 on Vision.

  vision_run.py setup            clean TCP profile in ns_vepa_a / ns_vepa_b, disable-source-pruning on
  vision_run.py restore          sysctls back to 1/1/1 and 32768 60999, disable-source-pruning off
  vision_run.py state            print the NIC flag and the namespace sysctls
  vision_run.py casea on --delay-ms D | casea off
                                 make the outstation side present a separate ACK followed by a late response,
                                 as the SEL-751 does: a quickack route in ns_vepa_b (immediate ACKs) and a netem
                                 delay of D ms on mvB applied only to the outstation's DNP3 response segments
                                 (IP total length 89 or 77). This emulates relay processing time; say so in
                                 any result that uses it. Without it the OpenDNP3 outstation answers in about
                                 0.3 ms with the ACK on the response, so there is no separate ACK to time.
  vision_run.py run LABEL --master-port P --reads N [--range 8|16] [--gap-ms G] [--connect-must-fail]

`run` starts the OpenDNP3 outstation in ns_vepa_b (192.168.10.62:20000) and the master in ns_vepa_a
(192.168.10.61, source port pinned to P through that namespace's ip_local_port_range), does N READs
(Group 10 Var 2, points 0..22) and one SELECT/OPERATE, and writes everything into a NEW directory
RUNS/LABEL: out.pcap (tcpdump -Q out on the parent NIC: frames as the endpoints sent them), in.pcap
(-Q in: frames as the switch returned them), master.json, outstation.json, state.txt, result.json.
Nothing here touches the parent NIC's addresses or routes, or any global sysctl."""
import argparse
import json
import os
import random
import re
import subprocess
import sys
import time

import loss  # shared packet classes and iptables rule lifecycle; deployed beside this file

PARENT = 'enp59s0f0np0'
NS_M, NS_O = 'ns_vepa_a', 'ns_vepa_b'
IP_M, IP_O, PORT_O = '192.168.10.61', '192.168.10.62', 20000
HOME = '/home/decps/pad58b_20261011'
BIN, LIB, RUNS = HOME + '/case4_socket_gate_pad58b', HOME + '/lib', HOME + '/runs'
PROFILE = ('net.ipv4.tcp_timestamps', 'net.ipv4.tcp_sack', 'net.ipv4.tcp_window_scaling')
DEFAULT_RANGE = '32768 60999'


def sh(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)


def start_delay_ms(max_ms, seed):
    """The pre-connect delay for a run: uniform over 0..max_ms ms, but a pure function of the seed so a paired
    block can replay the identical start phase and the result can record exactly what was applied."""
    return random.Random(seed).randint(0, max_ms) if max_ms > 0 else 0


def nsx(ns, *cmd, **kw):
    return sh('ip', 'netns', 'exec', ns, *cmd, **kw)


def run_checked(*cmd, **kw):
    r = sh(*cmd, **kw)
    if r.returncode:
        raise RuntimeError('command failed (rc %d): %s\n%s' % (r.returncode, ' '.join(cmd), r.stderr.strip()))
    return r


def set_sysctl_checked(ns, key, value):
    """Write a namespace sysctl and read it back; raise if the kernel did not take the value. The kernel
    renders a port range tab-separated, so compare on whitespace-split tokens."""
    nsx(ns, 'sysctl', '-w', '%s=%s' % (key, value))
    rb = nsx(ns, 'sysctl', '-n', key).stdout.strip()
    if rb.split() != str(value).split():
        raise RuntimeError('sysctl readback mismatch in %s: %s is %r, wanted %r' % (ns, key, rb, str(value)))
    return rb


def parse_tcpdump_stats(stderr):
    """tcpdump prints a termination summary on stderr: 'N packets captured', 'N received by filter',
    'N dropped by kernel', and sometimes 'N dropped by interface'. Return them so capture loss is retained."""
    out = {}
    for label, key in (('captured', 'captured'), ('received by filter', 'received'),
                       ('dropped by kernel', 'dropped_kernel'), ('dropped by interface', 'dropped_interface')):
        m = re.search(r'(\d+)\s+packets?\s+' + re.escape(label), stderr)
        if m:
            out[key] = int(m.group(1))
    return out


def state():
    flags = sh('ethtool', '--show-priv-flags', PARENT).stdout.splitlines()
    lines = [' '.join(next(l for l in flags if 'source-pruning' in l).split())]
    for ns in (NS_M, NS_O):
        lines.append(ns + ' ' + ' | '.join(nsx(ns, 'sysctl', *PROFILE, 'net.ipv4.ip_local_port_range').stdout.split('\n')).strip(' |'))
    return '\n'.join(lines) + '\n' + casea_state()


def pruning(value):
    r = sh('ethtool', '--set-priv-flags', PARENT, 'disable-source-pruning', value)
    if r.returncode:
        sys.exit('ethtool failed: ' + r.stderr)
    time.sleep(8)          # the i40e PF resets on this change; wait for the link


def casea(on, delay_ms):
    nsx(NS_O, 'tc', 'qdisc', 'del', 'dev', 'mvB', 'root')
    route = ['ip', 'route', 'replace', '192.168.10.0/24', 'dev', 'mvB', 'src', IP_O]
    if not on:
        r = nsx(NS_O, *route)
    else:
        r = nsx(NS_O, *route, 'quickack', '1')
        cmds = [['tc', 'qdisc', 'add', 'dev', 'mvB', 'root', 'handle', '1:', 'prio', 'bands', '3', 'priomap'] + ['0'] * 16,
                ['tc', 'qdisc', 'add', 'dev', 'mvB', 'parent', '1:2', 'handle', '20:', 'netem', 'delay', '%dms' % delay_ms, 'limit', '1000']]
        for total_len in (89, 77):       # 49-byte READ response, 37-byte SELECT/OPERATE response
            cmds.append(['tc', 'filter', 'add', 'dev', 'mvB', 'parent', '1:', 'protocol', 'ip', 'u32', 'match', 'ip', 'protocol', '6', '0xff',
                         'match', 'u16', '0x%04x' % total_len, '0xffff', 'at', '2', 'flowid', '1:2'])
        for c in cmds:
            r = nsx(NS_O, *c)
            if r.returncode:
                break
    if r.returncode:
        sys.exit('casea failed: ' + r.stderr)


def casea_state():
    return ('route: ' + nsx(NS_O, 'ip', 'route', 'show', '192.168.10.0/24').stdout.strip() + '\n' +
            'qdisc: ' + ' | '.join(nsx(NS_O, 'tc', 'qdisc', 'show', 'dev', 'mvB').stdout.strip().splitlines()))


def profile(value, port_range):
    for ns in (NS_M, NS_O):
        for k in PROFILE:
            set_sysctl_checked(ns, k, value)
    set_sysctl_checked(NS_M, 'net.ipv4.ip_local_port_range', port_range)


def wait_port_free(port, tries=80):
    for _ in range(tries):
        if ':%d ' % port not in nsx(NS_M, 'ss', '-tan').stdout:
            return
        time.sleep(1)
    raise RuntimeError('master port %d still busy' % port)


def run_connection(run_dir, label, master_port, reads, rng, gap_ms, start_delay_max, start_seed, drop=None,
                   connect_must_fail=False):
    """One connection with its own captures, outstation and master. run_dir must not exist (a label is never
    reused). Returns the result dict, which is also written to run_dir/result.json."""
    os.makedirs(run_dir)                      # refuses to reuse a label

    # snapshot the prior state before touching anything
    open(os.path.join(run_dir, 'state.txt'), 'w').write(state() + '\n')

    set_sysctl_checked(NS_M, 'net.ipv4.ip_local_port_range', '%d %d' % (master_port, master_port))
    wait_port_free(master_port)               # a tuple just closed by its master sits in TIME-WAIT for 60 s

    flt = 'tcp and host %s and host %s' % (IP_M, IP_O)
    env = ['env', 'CASE4_PAD58B_SOCKET_GATE=1', 'LD_LIBRARY_PATH=' + LIB]
    stop = os.path.join(run_dir, 'stop')
    result = {'label': label, 'master_port': master_port, 'reads': reads, 'range': rng, 'gap_ms': gap_ms,
              'start_delay_ms_max': start_delay_max, 'start_seed': start_seed,
              'start_delay_ms_applied': start_delay_ms(start_delay_max, start_seed)}
    caps = {}
    ost = None
    rule = None
    try:
        for d in ('out', 'in'):                # stderr kept, not DEVNULL, so a startup error is not hidden
            caps[d] = subprocess.Popen(['tcpdump', '-i', PARENT, '-Q', d, '-s0', '-U', '-n',
                                        '-w', os.path.join(run_dir, d + '.pcap'), flt],
                                       stderr=subprocess.PIPE, text=True)
        time.sleep(2.0)
        for d, c in caps.items():              # capture-ready confirmation
            if c.poll() is not None:
                raise RuntimeError('tcpdump -Q %s exited early (rc %s): %s' % (d, c.returncode, (c.stderr.read() or '').strip()))
            if not os.path.exists(os.path.join(run_dir, d + '.pcap')):
                raise RuntimeError('tcpdump -Q %s wrote no capture file' % d)

        ost = subprocess.Popen(['ip', 'netns', 'exec', NS_O] + env +
                               [BIN, 'outstation', IP_O, str(PORT_O), stop, str(60 + reads // 5 + reads * (gap_ms + 60) // 1000)],
                               stdout=subprocess.PIPE, text=True)
        ready = ost.stdout.readline().strip()
        result['outstation_ready'] = ready == 'READY'
        if ready == 'READY':
            if drop:                                                     # fail fast, before any traffic
                rule = loss.LossRule(nsx, drop, IP_M, IP_O, master_port, PORT_O).install()
            time.sleep(result['start_delay_ms_applied'] / 1000.0)        # the connection start phase
            t0 = time.time()
            try:
                mst = nsx(NS_M, *env, BIN, 'master', IP_O, str(PORT_O), stop + '.master', str(reads), IP_M, str(rng),
                          str(gap_ms), timeout=reads * 4 + 30 + reads * gap_ms // 1000)
                result.update(master_rc=mst.returncode, master_wall_s=round(time.time() - t0, 3))
                open(os.path.join(run_dir, 'master.json'), 'w').write(mst.stdout)
            except subprocess.TimeoutExpired:
                result.update(master_rc=None, master_timeout=True, master_wall_s=round(time.time() - t0, 3))
            time.sleep(1.0)
    finally:
        # bounded, comprehensive cleanup of everything this run started, even on an exception above
        if rule is not None:
            rule.finish()                    # counters first, then the rules come out whatever happened above
            rule.remove()
            result['loss'] = rule.record()
        open(stop, 'w').close()
        if ost is not None:
            try:
                open(os.path.join(run_dir, 'outstation.json'), 'w').write(ost.communicate(timeout=30)[0] or '')
            except subprocess.TimeoutExpired:
                ost.kill()
                ost.wait()
        time.sleep(1.0)
        tcpdump_stats = {}
        for d, c in caps.items():
            c.terminate()
            try:
                _, err = c.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                c.kill()
                _, err = c.communicate()
            tcpdump_stats[d] = parse_tcpdump_stats(err or '')   # retain capture loss/drop statistics
        result['tcpdump'] = tcpdump_stats

    for d in ('out', 'in'):
        path = os.path.join(run_dir, d + '.pcap')
        result['frames_' + d] = len(sh('tcpdump', '-r', path, '-n').stdout.splitlines()) \
            if os.path.exists(path) and os.path.getsize(path) > 24 else 0
    result['ok'] = (result.get('master_rc') == 2) if connect_must_fail else (result.get('master_rc') == 0)
    if drop:
        result['loss_exact'] = bool(result.get('loss', {}).get('exact'))
    json.dump(result, open(os.path.join(run_dir, 'result.json'), 'w'), indent=1)
    return result


def run_reconnect(label, master_port, reconnect_port, reads, rng, gap_ms, start_delay_max, start_seed):
    """Reconnect scenario: RUNS/label/{c1,c2,c3}, each a complete connection with its own pcaps and endpoint JSON.

      c1  the installed master port: READs + SBO + normal close (must succeed, else the scenario stops)
      c2  a NEW source port the switch has no rows for: defined behaviour is that it completes natively
      c3  the SAME installed tuple again, once TIME-WAIT clears: N does not re-arm, so nothing is asserted here;
          the connect result, application result and timeouts are recorded to characterize the limitation.
    ok = c1 and c2 completed; c3 never changes it."""
    parent = os.path.join(RUNS, label)
    os.makedirs(parent)                                   # refuses to reuse a label
    open(os.path.join(parent, 'state.txt'), 'w').write(state() + '\n')
    plan = (('c1', master_port, 'installed'), ('c2', reconnect_port, 'unknown_port'),
            ('c3', master_port, 'installed_again'))
    out = {'scenario': 'reconnect', 'label': label, 'connections': {}, 'ok': False}
    for name, port, role in plan:
        try:
            res = run_connection(os.path.join(parent, name), '%s_%s' % (label, name), port, reads, rng, gap_ms,
                                 start_delay_max, start_seed)
        except RuntimeError as e:                         # e.g. the port never left TIME-WAIT: recorded, not fatal
            res = {'label': '%s_%s' % (label, name), 'master_port': port, 'ok': False, 'error': str(e)}
        res['role'] = role
        out['connections'][name] = res
        if name == 'c1' and not res.get('ok'):
            break
    c = out['connections']
    out['ok'] = bool(c.get('c1', {}).get('ok') and c.get('c2', {}).get('ok'))
    json.dump(out, open(os.path.join(parent, 'scenario.json'), 'w'), indent=1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('setup', 'restore', 'state', 'casea', 'run'))
    ap.add_argument('label', nargs='?')
    ap.add_argument('--master-port', type=int)
    ap.add_argument('--reads', type=int, default=10)
    ap.add_argument('--range', type=int, choices=(8, 16), default=16)
    ap.add_argument('--gap-ms', type=int, default=0, help='spacing between READ requests')
    ap.add_argument('--start-delay-ms', type=int, default=0,
                    help='maximum pre-connect delay; the applied delay is uniform in 0..N and fixed by --start-seed')
    ap.add_argument('--start-seed', type=int, default=0)
    ap.add_argument('--delay-ms', type=int, default=25)
    ap.add_argument('--connect-must-fail', action='store_true')
    ap.add_argument('--scenario', choices=('reconnect',),
                    help='reconnect: c1 on the installed port, c2 on a new unknown port (expected native), c3 on the '
                         'installed tuple again (characterized, not asserted); each its own evidence under RUNS/LABEL/')
    ap.add_argument('--reconnect-port', type=int, help='source port of c2 (default: master port + 1)')
    ap.add_argument('--drop', metavar='CLASS[:N]',
                    help='drop exactly the Nth packet of a class at the receiving namespace ingress (see loss.py); '
                         'classes: ' + ', '.join(loss.names()))
    a = ap.parse_args()

    if a.mode == 'setup':
        profile('0', DEFAULT_RANGE)
        if 'source-pruning : on' not in state():
            pruning('on')
    if a.mode == 'casea':
        if a.label not in ('on', 'off'):
            sys.exit('casea on|off')
        casea(a.label == 'on', a.delay_ms)
    if a.mode == 'restore':
        casea(False, 0)
        profile('1', DEFAULT_RANGE)
        if 'source-pruning : off' not in state():
            pruning('off')
    if a.mode != 'run':
        print(state())
        sys.exit(0)

    if not a.label or not re.fullmatch(r'[A-Za-z0-9_]+', a.label) or a.master_port is None:
        sys.exit('run needs LABEL and --master-port')
    drop = None
    if a.drop:
        try:
            drop = loss.parse_drop(a.drop, a.reads)      # a bad spec stops the run before anything is created
        except ValueError as e:
            sys.exit(str(e))
    if a.scenario == 'reconnect':
        out = run_reconnect(a.label, a.master_port, a.reconnect_port or a.master_port + 1, a.reads, a.range, a.gap_ms,
                            a.start_delay_ms, a.start_seed)
        print(json.dumps(out))
        sys.exit(0 if out['ok'] else 1)
    try:
        result = run_connection(os.path.join(RUNS, a.label), a.label, a.master_port, a.reads, a.range, a.gap_ms,
                                a.start_delay_ms, a.start_seed, drop, a.connect_must_fail)
    except RuntimeError as e:
        sys.exit(str(e))
    print(json.dumps(result))
    sys.exit(0 if result['ok'] else 1)


if __name__ == '__main__':
    main()
