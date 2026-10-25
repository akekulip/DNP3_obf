#!/usr/bin/env python3
"""Vision side of a software-endpoint run through the switch. Run with sudo python3 on Vision.

  vision_run.py setup            clean TCP profile in ns_vepa_a / ns_vepa_b, disable-source-pruning on
                                 and record the parent NIC's receive-offload baseline (once; see restore)
  vision_run.py restore          sysctls back to 1/1/1 and 32768 60999, disable-source-pruning off, receive
                                 offloads re-applied from the setup baseline and verified (nonzero exit if not)
  vision_run.py state            print the NIC flag and the namespace sysctls
  vision_run.py casea on --delay-ms D | casea off
                                 make the outstation side present a separate ACK followed by a late response,
                                 as the SEL-751 does: a quickack route in ns_vepa_b (immediate ACKs) and a netem
                                 delay of D ms on mvB applied only to the outstation's DNP3 response segments
                                 (IP total lengths CASEA_DELAYED_IP_LEN: every declared single-frame native READ
                                 response and the 37-byte SELECT/OPERATE response). This emulates relay processing time; say so in
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
import threading

import capture_observation
import loss  # shared packet classes and iptables rule lifecycle; deployed beside this file


def authorize_relay_run(args):
    """Trusted application entrypoint for the frozen wrapper's explicit --apply intent."""
    if args.endpoint_profile != 'sel751' or args.mode != 'run':
        raise ValueError('explicit apply is supported only by the physical SEL-751 run entrypoint')
    if not args.label or not re.fullmatch(r'[A-Za-z0-9_]+', args.label) or not 1024 <= args.master_port <= 65535:
        raise ValueError('invalid fixed-profile label or source port')
    if not 1 <= args.reads <= 65 or not 0 <= args.sbo_cycles <= 64 or args.sbo_cycles >= args.reads:
        raise ValueError('invalid bounded physical workload')
    if args.run_sbo not in (0, 1) or (args.sbo_cycles and not args.run_sbo):
        raise ValueError('invalid guarded SBO controls')
    if args.read_schedule not in (None, 'mixed_full', 'mixed', 'full') or any(
            not 0 <= value <= 5000 for value in (args.gap_ms, args.read_pause_ms, args.close_grace_ms)):
        raise ValueError('unsupported physical READ schedule or bounded timing')
    if args.endpoint_binary or args.pad_expect or getattr(args, 'db', None) is not None:
        raise ValueError('software endpoint and unsupported loss controls are forbidden on the physical profile')
    if args.drop:
        import relay_loss
        relay_loss.parse_drop(args.drop, args.read_schedule, args.relay_padding)
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1' and not args.apply:
        raise ValueError('physical run requires authorization environment or explicit --apply')
    from relay_master import preflight
    preflight()  # fixed frozen {1,3} builders; no socket or capture
    if args.apply:
        os.environ['DEFENSE4_HW_AUTHORIZED'] = '1'


def relay_offload_lifecycle(mode, baseline_path=None, run=None, loss_baseline=False):
    """Campaign-level recovery survives failure of a per-capture offload context."""
    baseline_path = OFFLOAD_BASELINE if baseline_path is None else baseline_path
    run = capture_observation.sh if run is None else run
    if mode == 'setup':
        if os.path.exists(baseline_path):
            raise RuntimeError('physical setup refused: pending offload baseline exists; restore first')
        baseline = capture_observation.record_offload_baseline(baseline_path, PARENT, run=run)
        if loss_baseline:
            import relay_loss
            if os.path.exists(HOME + '/relay_loss_state.json'):
                raise RuntimeError('pending physical loss ownership exists; restore first')
            baseline['iptables'] = relay_loss.firewall_snapshot(run=run)
            with open(baseline_path, 'w') as stream:
                json.dump(baseline, stream, indent=2)
        return baseline
    if mode == 'restore':
        import relay_loss
        cleanup = relay_loss.restore_owned(HOME + '/relay_loss_state.json', run=run)
        errors = capture_observation.restore_offload_baseline(baseline_path, PARENT, run=run)
        errors += cleanup['errors']
        return dict(errors=errors, restored=not errors, loss=cleanup)
    raise ValueError('physical offload lifecycle supports setup/restore only')


def run_relay_connection(run_dir, label, master_port, reads, gap_ms=0, read_pause_ms=25,
                         run_sbo=True, close_grace_ms=0, sbo_cycles=0, read_schedule=None,
                         qualify_capture=False, start_delay_max=0, start_seed=0, close_mode='graceful', **unused):
    """Capture one real master socket. Never start an outstation or alter TCP settings."""
    from relay_master import workload
    from endpoint_profiles import MASTER_IP, RELAY_IP
    os.makedirs(run_dir)
    open(os.path.join(run_dir, 'state.txt'), 'w').write(state() + '\n')
    result = dict(label=label, endpoint_profile='sel751', master_port=master_port, reads=reads,
                  observation_scope='single master NIC TX/RX; switch residence and OPERATE J unproven',
                  endpoint_controls=dict(read_pause_ms=read_pause_ms, run_sbo=bool(run_sbo),
                                         close_grace_ms=close_grace_ms), tcpdump={}, ok=False)
    caps, loss_owner = {}, [None]
    def capture():
        try:
            result['source_port_wait'] = wait_relay_port_free(master_port)
            if result['source_port_wait']['result'] != 'free':
                raise RuntimeError('physical source port unavailable: ' + str(result['source_port_wait']))
            flt = 'tcp and host %s and host %s and port 20000' % (MASTER_IP, RELAY_IP)
            for direction in ('out', 'in'):
                command = ['tcpdump', '--immediate-mode', '-i', PARENT, '-Q', direction, '-s0', '-U', '-n',
                           '-w', os.path.join(run_dir, direction + '.pcap'), flt]
                caps[direction] = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
            time.sleep(2)
            for direction, proc in caps.items():
                if proc.poll() is not None or not os.path.isfile(os.path.join(run_dir, direction + '.pcap')):
                    raise RuntimeError('relay capture failed before traffic: ' + direction)
            if unused.get('drop'):
                import relay_loss
                loss_owner[0] = relay_loss.RelayLoss(unused['drop'], master_port, label, HOME + '/relay_loss_state.json',
                                                     capture=os.path.join(run_dir, 'in.pcap'))
                loss_owner[0].install()
            time.sleep(start_delay_ms(start_delay_max, start_seed) / 1000)
            master = workload(master_port, reads, schedule=read_schedule or 'mixed_full', sbo_cycles=sbo_cycles,
                              run_sbo=run_sbo, gap_ms=gap_ms, read_pause_ms=read_pause_ms,
                              close_grace_ms=close_grace_ms, close_mode=close_mode,
                              loss_target=loss_owner[0] if loss_owner[0] is not None and loss_owner[0].identity else None)
            json.dump(master, open(os.path.join(run_dir, 'master.json'), 'w'), indent=2)
            result.update(ok=master['ok'], master_rc=0 if master['ok'] else 1)
            result['close_observation'] = wait_relay_close(run_dir, master_port, close_mode)
        except Exception as error:
            result.update(error=str(error), master_rc=1)
        finally:
            if loss_owner[0] is not None:
                try:
                    result['loss'] = loss_owner[0].finish()
                except Exception as error:
                    import relay_loss
                    result['loss'] = dict(exact=False, error=str(error),
                                         restoration=relay_loss.restore_owned(HOME + '/relay_loss_state.json'))
                result['ok'] = bool(result['ok'] and result['loss'].get('exact') and
                                    result['loss'].get('restoration', {}).get('restored'))
            for direction, proc in caps.items():
                proc.terminate()
                try:
                    _, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _, stderr = proc.communicate()
                result['tcpdump'][direction] = parse_tcpdump_stats(stderr or '')
            json.dump(result, open(os.path.join(run_dir, 'result.json'), 'w'), indent=2)
        return result
    if qualify_capture:
        with capture_observation.offload_capture_context(run_dir, interface=PARENT):
            return capture()
    return capture()


def wait_relay_port_free(port, tries=80):
    """Passive host TCP-state barrier; no namespace/profile/sysctl mutation."""
    start = time.monotonic()
    for poll in range(1, tries + 1):
        probe = sh('ss', '-tan')
        if probe.returncode:
            return dict(result='probe_error', error=probe.stderr, polls=poll)
        if ':%d ' % port not in probe.stdout:
            return dict(result='free', polls=poll, elapsed_s=time.monotonic() - start)
        time.sleep(1)
    return dict(result='busy', polls=tries, elapsed_s=time.monotonic() - start)


def wait_relay_close(run_dir, master_port, mode, tries=60):
    """Retain capture until close is observed or 3 seconds expire; no packet/socket creation."""
    import wire_check
    from endpoint_profiles import MASTER_IP, RELAY_IP, RELAY_PORT
    start, last_error = time.monotonic(), None
    for poll in range(1, tries + 1):
        try:
            outgoing = [p for p in wire_check.parse(os.path.join(run_dir, 'out.pcap'))[0] if
                        (p['src'], p['dst'], p['sport'], p['dport']) == (MASTER_IP, RELAY_IP, master_port, RELAY_PORT)]
            incoming = [p for p in wire_check.parse(os.path.join(run_dir, 'in.pcap'))[0] if
                        (p['src'], p['dst'], p['sport'], p['dport']) == (RELAY_IP, MASTER_IP, RELAY_PORT, master_port)]
            complete = any(p['flags'] & wire_check.RST for p in outgoing) if mode == 'rst' else (
                any(p['flags'] & wire_check.FIN and any(q['flags'] & wire_check.ACK and
                    q['ack'] == (p['seq'] + p['len'] + 1) & 0xffffffff for q in outgoing) for p in incoming) and
                any(p['flags'] & wire_check.FIN and any(q['flags'] & wire_check.ACK and
                    q['ack'] == (p['seq'] + p['len'] + 1) & 0xffffffff for q in incoming) for p in outgoing))
            if complete:
                return dict(complete=True, mode=mode, polls=poll, elapsed_s=time.monotonic() - start)
        except Exception as error:  # a live pcap may end in an unfinished record during the read
            last_error = str(error)
        time.sleep(.05)
    return dict(complete=False, mode=mode, polls=tries, elapsed_s=time.monotonic() - start, error=last_error)


def run_relay_series(label, master_port, reads, close_mode, close_grace_ms, read_schedule):
    parent = os.path.join(RUNS, label)
    os.makedirs(parent)
    open(os.path.join(parent, 'state.txt'), 'w').write(state() + '\n')
    result = dict(scenario='physical_same_tuple', label=label, close_mode=close_mode, connections={}, ok=False)
    for index in range(1, 4):
        name = 'c%d' % index
        try:
            result['connections'][name] = run_connection(
                os.path.join(parent, name), label + '_' + name, master_port, reads, 8, 0, 0, 12344 + index,
                read_pause_ms=25, run_sbo=True, close_grace_ms=close_grace_ms, qualify_capture=True,
                read_schedule=read_schedule, endpoint_profile='sel751', relay_close_mode=close_mode)
            if relay_restore_uncertain(result['connections'][name], os.path.join(parent, name), qualified=True):
                for pending in range(index + 1, 4):
                    result['connections']['c%d' % pending] = dict(ok=False, ran=False,
                                                        error='capture/loss restoration unverified; stopped')
                break
        except (RuntimeError, ValueError, OSError) as error:
            result['connections'][name] = dict(ok=False, error=str(error), master_port=master_port)
            if relay_restore_uncertain(result['connections'][name], os.path.join(parent, name), qualified=True):
                for pending in range(index + 1, 4):
                    result['connections']['c%d' % pending] = dict(ok=False, ran=False,
                                                        error='capture restoration unverified; stopped')
                break
    result['ok'] = len(result['connections']) == 3 and all(record.get('ok') for record in result['connections'].values())
    result.update(planned_connections=3, attempted_connections=sum(record.get('ran', True) for record in result['connections'].values()),
                  completed_connections=sum(record.get('ok', False) for record in result['connections'].values()))
    json.dump(result, open(os.path.join(parent, 'scenario.json'), 'w'), indent=2)
    return result


def relay_restore_uncertain(record, run_dir=None, qualified=False):
    uncertain = bool(record.get('restoration_uncertain') or 'restore failed' in str(record.get('error', '')).lower() or
                    (record.get('loss') is not None and record['loss'].get('restoration', {}).get('restored') is not True))
    if qualified and run_dir is not None and os.path.isdir(run_dir):
        try:
            restoration = json.load(open(os.path.join(run_dir, 'capture_offloads.json')))
            uncertain = uncertain or restoration.get('restore_ok') is not True
        except (OSError, ValueError, TypeError):
            uncertain = True
    if uncertain:
        record['restoration_uncertain'] = True
    return uncertain

PARENT = 'enp59s0f0np0'
NS_M, NS_O = 'ns_vepa_a', 'ns_vepa_b'
IP_M, IP_O, PORT_O = '192.168.10.61', '192.168.10.62', 20000
HOME = os.path.dirname(os.path.abspath(__file__))
BIN, LIB, RUNS = HOME + '/case4_socket_gate_pad58b', HOME + '/lib', HOME + '/runs'
PROFILE = ('net.ipv4.tcp_timestamps', 'net.ipv4.tcp_sack', 'net.ipv4.tcp_window_scaling')
DEFAULT_RANGE = '32768 60999'
OFFLOAD_BASELINE = HOME + '/offload_baseline.json'   # campaign receive-offload baseline (setup/restore)
RX_COALESCE_BASELINE = HOME + '/rx_coalesce_baseline.json'   # host diagnostic only (setup --rx-coalesce-diag)
CPU_LATENCY_STATE = HOME + '/cpu_latency_state.json'          # host diagnostic only (setup --cpu-latency-diag)
READ_SCHEDULES = ('rotate4', 'mixed_full', 'mixed', 'full')   # CASE4_READ_SCHEDULE (read-schedule endpoint only)
# CASE4_PAD_EXPECT (master only): the padding the switch is declared to add per READ class, '<class>=<n>[,...]'.
# A padded arm passes it so the endpoint's STRICT check requires exactly that padding; a padding-off arm passes
# nothing, so any added point fails the master.
PAD_EXPECT_RE = re.compile(r'(range|analog|class0|integrity|mixed)=[1-9][0-9]{0,3}(,(range|analog|class0|integrity|mixed)=[1-9][0-9]{0,3})*')
DBS = ('base', 'large')                              # CASE4_DB


def endpoint_env(read_pause_ms, run_sbo, close_grace_ms, sbo_cycles, read_schedule=None, db=None):
    """The env prefix both endpoints run under. CASE4_SBO_CYCLES, CASE4_READ_SCHEDULE and CASE4_DB appear only when
    set, so an unset control leaves the command of every older endpoint unchanged."""
    return (['env', 'CASE4_PAD58B_SOCKET_GATE=1', 'LD_LIBRARY_PATH=' + LIB,
             'CASE4_READ_PAUSE_MS=%d' % read_pause_ms, 'CASE4_RUN_SBO=%d' % int(run_sbo),
             'CASE4_CLOSE_GRACE_MS=%d' % close_grace_ms] + (['CASE4_SBO_CYCLES=%d' % sbo_cycles] if sbo_cycles else []) +
            (['CASE4_READ_SCHEDULE=%s' % read_schedule] if read_schedule else []) +
            (['CASE4_DB=%s' % db] if db else []))


def endpoint_binary(name):
    """The endpoint binary beside this file: the configured file name, else the default pad58b endpoint."""
    return BIN if name is None else HOME + '/' + name


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


DISTRIBUTIONS = ('normal', 'paretonormal')
# IP total lengths of the outstation responses the separate-ACK fixture delays (SEL-751 emulation: separate ACK, then
# the delayed response): the native single-frame READ responses of every declared READ class -- range 49, mixed 91,
# analog 141, class0/integrity 247 (read_classes.NATIVE_SEGMENTS, base database) -- and the 37-byte SELECT/OPERATE
# response. Until 2026-10-22 only 89 and 77 were listed, so the mixed (131) and full (287) READ responses left
# undelayed and a quarter of them piggybacked on the ACK (rc01_hw_c25_20261022_01_reference, off arm).
CASEA_DELAYED_IP_LEN = (40 + 49, 40 + 91, 40 + 141, 40 + 247, 40 + 37)


def casea(on, delay_ms, jitter_ms=0, distribution=None):
    nsx(NS_O, 'tc', 'qdisc', 'del', 'dev', 'mvB', 'root')
    route = ['ip', 'route', 'replace', '192.168.10.0/24', 'dev', 'mvB', 'src', IP_O]
    if not on:
        r = nsx(NS_O, *route)
    else:
        if jitter_ms and distribution not in DISTRIBUTIONS:
            sys.exit('casea: jitter needs --distribution %s' % '|'.join(DISTRIBUTIONS))
        spread = ['%dms' % jitter_ms, 'distribution', distribution] if jitter_ms else []
        r = nsx(NS_O, *route, 'quickack', '1')
        cmds = [['tc', 'qdisc', 'add', 'dev', 'mvB', 'root', 'handle', '1:', 'prio', 'bands', '3', 'priomap'] + ['0'] * 16,
                ['tc', 'qdisc', 'add', 'dev', 'mvB', 'parent', '1:2', 'handle', '20:', 'netem', 'delay', '%dms' % delay_ms] + spread + ['limit', '1000']]
        for total_len in CASEA_DELAYED_IP_LEN:
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
    start = time.monotonic()
    for poll in range(1, tries + 1):
        probe = nsx(NS_M, 'ss', '-tan')
        if probe.returncode:
            return dict(port=port, polls=poll, elapsed_s=round(time.monotonic() - start, 3),
                        result='probe_error', error=probe.stderr.strip(), probe_rc=probe.returncode)
        if ':%d ' % port not in probe.stdout:
            return dict(port=port, polls=poll, elapsed_s=round(time.monotonic() - start, 3), result='free')
        time.sleep(1)
    return dict(port=port, polls=tries, elapsed_s=round(time.monotonic() - start, 3), result='busy')


def tcp_rto_readback(master_port, endpoint='master'):
    """Passive Linux TCP_INFO rendering from ss; no socket or kernel tuning."""
    if endpoint not in ('master', 'outstation'):
        raise ValueError('endpoint must be master or outstation')
    namespace = NS_M if endpoint == 'master' else NS_O
    local_port, peer_port = (master_port, PORT_O) if endpoint == 'master' else (PORT_O, master_port)
    command = ['ss', '-tin', 'state', 'established', '( sport = :%d and dport = :%d )' % (local_port, peer_port)]
    record = dict(observed_at_epoch_ns=time.time_ns(), observed_at_monotonic_ns=time.monotonic_ns(),
                  endpoint=endpoint, namespace=namespace, local_port=local_port, peer_port=peer_port,
                  source='ip netns exec %s ss -tin (Linux TCP_INFO)' % namespace,
                  command=command, units='ms', status='unavailable', rto_ms=[])
    try:
        result = nsx(namespace, *command, timeout=2)
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode:
            record.update(status='error', reason='ss_nonzero_exit')
        else:
            record['rto_ms'] = [float(v) for v in re.findall(r'\brto:([0-9]+(?:\.[0-9]+)?)', result.stdout)]
            record['status'] = 'ok' if record['rto_ms'] else 'unavailable'
            if not record['rto_ms']:
                record['reason'] = 'no_established_socket_rto_observed'
    except (OSError, subprocess.SubprocessError) as error:
        record.update(status='error', reason=type(error).__name__, error=str(error))
    return record


def _text_output(value):
    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else (value or '')


def _run_master_evidence(run_dir, master_port, command, timeout):
    """Retain partial output on timeout and sample RTO while the blocking master runs.

    The sampler is bounded to 120 read-only probes per endpoint, each with a two-second timeout.
    Monotonic timestamps describe collection only and are never subtracted from pcap epoch.
    """
    done, samples = threading.Event(), []

    def sample():
        for _ in range(120):
            if done.wait(0.05 if not samples else 0.25):
                return
            for endpoint in ('master', 'outstation'):
                if done.is_set():
                    return
                samples.append(tcp_rto_readback(master_port, endpoint=endpoint))

    sampler = threading.Thread(target=sample, name='passive-tcp-rto', daemon=True)
    sampler.start()
    timed_out = False
    try:
        result = nsx(NS_M, *command, timeout=timeout)
        stdout, stderr, rc = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout, stderr, rc = error.stdout, error.stderr, None
    finally:
        done.set()
        sampler.join(timeout=3)
    for name, value in (('master.json', stdout), ('master.stdout', stdout), ('master.stderr', stderr)):
        with open(os.path.join(run_dir, name), 'w') as stream:
            stream.write(_text_output(value))
    endpoint_status = {}
    for endpoint in ('master', 'outstation'):
        endpoint_samples = [s for s in samples if s['endpoint'] == endpoint]
        usable = any(s['status'] == 'ok' and any(v > 0 for v in s['rto_ms']) for s in endpoint_samples)
        status = 'ok' if usable else ('error' if endpoint_samples and all(s['status'] == 'error' for s in endpoint_samples)
                                      else 'unavailable')
        endpoint_status[endpoint] = dict(status=status, sample_count=len(endpoint_samples),
                                         reason=None if usable else ('no_positive_rto_observed' if endpoint_samples else
                                                                    'master_finished_before_endpoint_probe'))
    both_observed = all(value['status'] == 'ok' for value in endpoint_status.values())
    readback = dict(schema_version='vision-tcp-rto-v2', samples=list(samples), endpoints=endpoint_status,
                    status='ok' if both_observed else 'unavailable',
                    maximum_samples=240, maximum_samples_per_endpoint=120,
                    command_timeout_s=2, sample_interval_s=0.25,
                    reason=None if both_observed else 'both_endpoint_positive_rtos_not_observed')
    with open(os.path.join(run_dir, 'tcp_rto.json'), 'w') as stream:
        json.dump(readback, stream, indent=1, allow_nan=False)
    return dict(master_rc=rc, master_timeout=timed_out,
                endpoint_collection=dict(schema_version='vision-endpoint-collection-v1',
                                         status='timeout' if timed_out else 'completed', partial=timed_out,
                                         stdout='master.stdout', stderr='master.stderr'),
                tcp_rto=readback)


def run_connection(run_dir, label, master_port, reads, rng, gap_ms, start_delay_max, start_seed, drop=None,
                   connect_must_fail=False, read_pause_ms=25, run_sbo=True, close_grace_ms=0, capture_immediate=False,
                   qualify_capture=False, sbo_cycles=0, read_schedule=None, db=None, endpoint_binary_name=None,
                   pad_expect=None, endpoint_profile='software', relay_close_mode='graceful'):
    if endpoint_profile == 'sel751':
        if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('physical run requires authorization before capture/socket creation')
        if connect_must_fail or endpoint_binary_name or pad_expect:
            raise ValueError('unsupported physical relay control; refusing before traffic')
        return run_relay_connection(run_dir, label, master_port, reads, gap_ms=gap_ms,
                                    read_pause_ms=read_pause_ms, run_sbo=run_sbo,
                                    close_grace_ms=close_grace_ms, sbo_cycles=sbo_cycles,
                                    read_schedule=read_schedule, qualify_capture=qualify_capture,
                                    start_delay_max=start_delay_max, start_seed=start_seed, close_mode=relay_close_mode, drop=drop)
    if endpoint_profile != 'software':
        raise ValueError('unknown endpoint profile')
    """One connection with its own captures, outstation and master. run_dir must not exist (a label is never
    reused). capture_immediate enables tcpdump's immediate mode for live observers.
    sbo_cycles N>0 (repeated-SBO endpoint only): reads is the total READ count; the master issues reads-N READs,
    then N cycles of SELECT->OPERATE followed by one READ, all on this connection.
    read_schedule/db (read-schedule endpoint only): CASE4_READ_SCHEDULE and CASE4_DB to both endpoints;
    endpoint_binary_name: the endpoint file beside this script (default case4_socket_gate_pad58b).
    Returns the result dict and capture arguments, also written to run_dir/result.json."""
    for key, value in (('read_pause_ms', read_pause_ms), ('close_grace_ms', close_grace_ms)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 5000:
            raise ValueError('%s must be an integer in 0..5000' % key)
    if run_sbo not in (False, True, 0, 1):
        raise ValueError('run_sbo must be 0 or 1')
    if type(sbo_cycles) is not int or not 0 <= sbo_cycles <= 64:
        raise ValueError('sbo_cycles must be an integer in 0..64')
    if sbo_cycles and (not run_sbo or reads < sbo_cycles + 1):
        raise ValueError('sbo_cycles needs run_sbo and reads >= sbo_cycles + 1 (one READ before the first cycle)')
    if type(capture_immediate) is not bool:
        raise ValueError('capture_immediate must be a boolean')
    if type(qualify_capture) is not bool:
        raise ValueError('qualify_capture must be a boolean')
    if read_schedule is not None and read_schedule not in READ_SCHEDULES:
        raise ValueError('read_schedule must be one of %s' % (READ_SCHEDULES,))
    if db is not None and db not in DBS:
        raise ValueError('db must be one of %s' % (DBS,))
    if read_schedule is not None and db is None:
        raise ValueError('read_schedule needs db on both endpoints')
    if pad_expect is not None and (read_schedule is None or not PAD_EXPECT_RE.fullmatch(str(pad_expect))):
        raise ValueError('pad_expect must be <class>=<n>[,...] and needs a read_schedule, got %r' % (pad_expect,))
    if endpoint_binary_name is not None and not re.fullmatch(r'[A-Za-z0-9_.-]+', str(endpoint_binary_name)) or \
            endpoint_binary_name in ('.', '..'):
        raise ValueError('endpoint binary must be a file name beside vision_run.py, got %r' % (endpoint_binary_name,))
    os.makedirs(run_dir)                      # refuses to reuse a label

    def run_main():
        return _run_connection_created(run_dir, label, master_port, reads, rng, gap_ms, start_delay_max, start_seed,
                                       drop, connect_must_fail, read_pause_ms, run_sbo, close_grace_ms,
                                       capture_immediate, qualify_capture, sbo_cycles, read_schedule, db,
                                       endpoint_binary_name, pad_expect)

    if qualify_capture:
        return capture_observation.run_with_qualified_capture(run_dir, run_main, interface=PARENT)
    return run_main()


def _run_connection_created(run_dir, label, master_port, reads, rng, gap_ms, start_delay_max, start_seed, drop=None,
                            connect_must_fail=False, read_pause_ms=25, run_sbo=True, close_grace_ms=0,
                            capture_immediate=False, qualify_capture=False, sbo_cycles=0, read_schedule=None, db=None,
                            endpoint_binary_name=None, pad_expect=None):

    # snapshot the prior state before touching anything
    open(os.path.join(run_dir, 'state.txt'), 'w').write(state() + '\n')

    set_sysctl_checked(NS_M, 'net.ipv4.ip_local_port_range', '%d %d' % (master_port, master_port))
    port_wait = wait_port_free(master_port)   # the existing TIME-WAIT barrier; record its result

    flt = 'tcp and host %s and host %s' % (IP_M, IP_O)
    env = endpoint_env(read_pause_ms, run_sbo, close_grace_ms, sbo_cycles, read_schedule, db)
    binary = endpoint_binary(endpoint_binary_name)
    extra_seconds = (reads * (gap_ms + read_pause_ms) + close_grace_ms + 999) // 1000
    stop = os.path.join(run_dir, 'stop')
    result = {'label': label, 'master_port': master_port, 'reads': reads, 'range': rng, 'gap_ms': gap_ms,
              'start_delay_ms_max': start_delay_max, 'start_seed': start_seed,
              'start_delay_ms_applied': start_delay_ms(start_delay_max, start_seed)}
    result['endpoint_controls'] = dict(read_pause_ms=read_pause_ms, run_sbo=bool(run_sbo), close_grace_ms=close_grace_ms)
    if sbo_cycles:
        result['endpoint_controls']['sbo_cycles'] = sbo_cycles
    if read_schedule:
        result['endpoint_controls']['read_schedule'] = read_schedule
    if db:
        result['endpoint_controls']['db'] = db
    if pad_expect:
        result['endpoint_controls']['pad_expect'] = pad_expect
    if endpoint_binary_name is not None:
        result['endpoint_binary'] = binary
    result['capture_immediate'] = capture_immediate
    result['qualify_capture'] = qualify_capture
    result['capture_commands'] = {}
    result['source_port_wait'] = port_wait
    if port_wait['result'] != 'free':
        result.update(ok=False, error=('master port %d still busy' % master_port if port_wait['result'] == 'busy'
                                       else 'master port probe failed: ' + port_wait['error']))
        json.dump(result, open(os.path.join(run_dir, 'result.json'), 'w'), indent=1)
        return result
    caps = {}
    ost = None
    rule = None
    try:
        for d in ('out', 'in'):                # stderr kept, not DEVNULL, so a startup error is not hidden
            command = ['tcpdump', '-i', PARENT, '-Q', d, '-s0', '-U', '-n',
                       '-w', os.path.join(run_dir, d + '.pcap'), flt]
            if capture_immediate:
                command.insert(1, '--immediate-mode')
            result['capture_commands'][d] = command
            caps[d] = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
        time.sleep(2.0)
        for d, c in caps.items():              # capture-ready confirmation
            if c.poll() is not None:
                raise RuntimeError('tcpdump -Q %s exited early (rc %s): %s' % (d, c.returncode, (c.stderr.read() or '').strip()))
            if not os.path.exists(os.path.join(run_dir, d + '.pcap')):
                raise RuntimeError('tcpdump -Q %s wrote no capture file' % d)

        ost = subprocess.Popen(['ip', 'netns', 'exec', NS_O] + env +
                               [binary, 'outstation', IP_O, str(PORT_O), stop, str(60 + reads * 4 + extra_seconds)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready = ost.stdout.readline().strip()
        result['outstation_ready'] = ready == 'READY'
        if ready == 'READY':
            if drop:                                                     # fail fast, before any traffic
                rule = loss.LossRule(nsx, drop, IP_M, IP_O, master_port, PORT_O).install()
            time.sleep(result['start_delay_ms_applied'] / 1000.0)        # the connection start phase
            t0 = time.time()
            command = env + (['CASE4_PAD_EXPECT=%s' % pad_expect] if pad_expect else []) + [
                binary, 'master', IP_O, str(PORT_O), stop + '.master', str(reads - sbo_cycles),
                             IP_M, str(rng), str(gap_ms)]
            result.update(_run_master_evidence(run_dir, master_port, command,
                                              reads * 4 + sbo_cycles * 4 + 30 + extra_seconds))
            result['master_wall_s'] = round(time.time() - t0, 3)
            time.sleep(1.0)
    finally:
        # bounded, comprehensive cleanup of everything this run started, even on an exception above
        if rule is not None:
            rule.finish()                    # counters first, then the rules come out whatever happened above
            rule.remove()
            result['loss'] = rule.record()
        open(stop, 'w').close()
        if ost is not None:
            ost_timeout = False
            try:
                ost_stdout, ost_stderr = ost.communicate(timeout=30)
            except subprocess.TimeoutExpired as error:
                ost_timeout = True
                ost.kill()
                ost_stdout, ost_stderr = ost.communicate()
                ost_stdout = ost_stdout or error.stdout
                ost_stderr = ost_stderr or error.stderr
            for name, value in (('outstation.json', ost_stdout), ('outstation.stdout', ost_stdout),
                                ('outstation.stderr', ost_stderr)):
                with open(os.path.join(run_dir, name), 'w') as stream:
                    stream.write(_text_output(value))
            result['outstation_collection'] = dict(schema_version='vision-endpoint-collection-v1',
                                                   status='timeout' if ost_timeout else 'completed',
                                                   partial=ost_timeout, ready_line=ready)
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


def run_reconnect(label, master_port, reconnect_port, reads, rng, gap_ms, start_delay_max, start_seed,
                  read_pause_ms=25, run_sbo=True, close_grace_ms=0, qualify_capture=False, sbo_cycles=0,
                  read_schedule=None, db=None, endpoint_binary_name=None, pad_expect=None, endpoint_profile='software'):
    """Reconnect scenario: RUNS/label/{c1,c2,c3}, each a complete connection with its own pcaps and endpoint JSON.

      c1  the installed master port: READs + SBO + normal close (must succeed, else the scenario stops)
      c2  a NEW source port the switch has no rows for: defined behaviour is that it completes natively
      c3  the SAME installed tuple again, once TIME-WAIT clears: N does not re-arm, so nothing is asserted here;
          the connect result, application result and timeouts are recorded to characterize the limitation.
    A failed c1 or c2 stops the scenario; c3 is not comparable after a failed prerequisite.
    ok = c1 and c2 completed; c3 never changes it.
    read_schedule/db/endpoint_binary_name go to every connection; pad_expect (the switch's declared READ padding) only
    to the installed tuple (c1, c3): c2 has no switch rows, so its master must see native READs with no added point."""
    if pad_expect is not None and (read_schedule is None or not PAD_EXPECT_RE.fullmatch(str(pad_expect))):
        raise ValueError('pad_expect needs read_schedule and the form <class>=<n>[,...]')
    parent = os.path.join(RUNS, label)
    os.makedirs(parent)                                   # refuses to reuse a label
    open(os.path.join(parent, 'state.txt'), 'w').write(state() + '\n')
    plan = (('c1', master_port, 'installed'), ('c2', reconnect_port, 'unknown_port'),
            ('c3', master_port, 'installed_again'))
    out = {'scenario': 'reconnect', 'label': label, 'connections': {}, 'ok': False}
    for name, port, role in plan:
        try:
            res = run_connection(os.path.join(parent, name), '%s_%s' % (label, name), port, reads, rng, gap_ms,
                                 start_delay_max, start_seed, read_pause_ms=read_pause_ms,
                                 run_sbo=run_sbo, close_grace_ms=close_grace_ms,
                                 qualify_capture=qualify_capture, sbo_cycles=sbo_cycles,
                                 read_schedule=read_schedule, db=db, endpoint_binary_name=endpoint_binary_name,
                                 pad_expect=pad_expect if name != 'c2' else None,
                                 **({'endpoint_profile': endpoint_profile} if endpoint_profile != 'software' else {}))
        except RuntimeError as e:                         # e.g. the port never left TIME-WAIT: recorded, not fatal
            res = {'label': '%s_%s' % (label, name), 'master_port': port, 'ok': False, 'error': str(e)}
        res['role'] = role
        out['connections'][name] = res
        if endpoint_profile == 'sel751' and relay_restore_uncertain(res, os.path.join(parent, name), qualify_capture):
            for pending, pending_port, pending_role in plan[len(out['connections']):]:
                out['connections'][pending] = dict(role=pending_role, master_port=pending_port, ran=False, ok=False,
                                                   error='capture/loss restoration unverified; stopped')
            break
        if endpoint_profile != 'sel751' and name in ('c1', 'c2') and not res.get('ok'):
            if name == 'c2':
                out['connections']['c3'] = {'role': 'installed_again', 'master_port': master_port,
                                             'ran': False, 'ok': False, 'comparable': False,
                                             'error': 'not run: c2 native prerequisite failed'}
            break
    c = out['connections']
    out['ok'] = bool(c.get('c1', {}).get('ok') and c.get('c2', {}).get('ok'))
    if endpoint_profile == 'sel751':
        out['ok'] = out['ok'] and bool(c.get('c3', {}).get('ok'))
        out.update(planned_connections=3, attempted_connections=sum(record.get('ran', True) for record in c.values()),
                   completed_connections=sum(record.get('ok', False) for record in c.values()))
    json.dump(out, open(os.path.join(parent, 'scenario.json'), 'w'), indent=1)
    return out


def bounded_ms(value):
    if not re.fullmatch(r'[0-9]+', value) or not 0 <= int(value) <= 5000:
        raise argparse.ArgumentTypeError('expected a decimal integer in 0..5000')
    return int(value)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--endpoint-profile', choices=('software', 'sel751'), default='software')
    ap.add_argument('--apply', action='store_true', help='explicit frozen-wrapper authorization for a validated physical run')
    ap.add_argument('--relay-padding', type=int, choices=(0, 1), default=0)
    ap.add_argument('--loss-baseline', action='store_true', help='physical setup: retain host firewall baseline for independent restore')
    ap.add_argument('mode', choices=('setup', 'restore', 'state', 'casea', 'run'))
    ap.add_argument('label', nargs='?')
    ap.add_argument('--master-port', type=int)
    ap.add_argument('--reads', type=int, default=10)
    ap.add_argument('--range', type=int, choices=(8, 16), default=16)
    ap.add_argument('--gap-ms', type=int, default=0, help='spacing between READ requests')
    ap.add_argument('--read-pause-ms', type=bounded_ms, default=25, help='endpoint completion pause after each READ')
    ap.add_argument('--run-sbo', type=int, choices=(0, 1), default=1, help='perform one real SELECT/OPERATE after READs')
    ap.add_argument('--close-grace-ms', type=bounded_ms, default=0, help='endpoint pause before normal close')
    ap.add_argument('--sbo-cycles', type=int, default=0,
                    help='repeated-SBO endpoint: N cycles of SELECT->OPERATE then READ (reads counts every READ)')
    ap.add_argument('--start-delay-ms', type=int, default=0,
                    help='maximum pre-connect delay; the applied delay is uniform in 0..N and fixed by --start-seed')
    ap.add_argument('--start-seed', type=int, default=0)
    ap.add_argument('--delay-ms', type=int, default=25)
    ap.add_argument('--cpu-latency-diag', action='store_true',
                    help='setup only: host diagnostic -- a supervised helper holds a zero request on '
                         '/dev/cpu_dma_latency until restore stops it and verifies the baseline')
    ap.add_argument('--rx-coalesce-diag', action='store_true',
                    help='setup only: host diagnostic -- adaptive RX off, rx-usecs 0 (baseline recorded; restore '
                         'puts it back and verifies)')
    ap.add_argument('--jitter-ms', type=int, default=0, help='netem jitter of the separate_ack response delay')
    ap.add_argument('--distribution', choices=DISTRIBUTIONS, help='netem jitter distribution (needed with --jitter-ms)')
    ap.add_argument('--connect-must-fail', action='store_true')
    ap.add_argument('--scenario', choices=('reconnect', 'persistence'),
                    help='reconnect: c1 on the installed port, c2 on a new unknown port (expected native), c3 on the '
                         'installed tuple again (characterized, not asserted); each its own evidence under RUNS/LABEL/')
    ap.add_argument('--reconnect-port', type=int, help='source port of c2 (default: master port + 1)')
    ap.add_argument('--close-mode', choices=('graceful', 'rst'), default='graceful')
    ap.add_argument('--drop', metavar='CLASS[:N]',
                    help='drop exactly the Nth packet of a class at the receiving namespace ingress (see loss.py); '
                         'classes: ' + ', '.join(loss.names()))
    ap.add_argument('--qualify-capture', action='store_true',
                    help='opt-in physical packet-boundary qualification evidence for this run')
    ap.add_argument('--read-schedule', choices=READ_SCHEDULES,
                    help='read-schedule endpoint: CASE4_READ_SCHEDULE for the master (needs --db)')
    ap.add_argument('--db', choices=DBS, help='read-schedule endpoint: CASE4_DB for both endpoints')
    ap.add_argument('--endpoint-binary', help='endpoint file beside this script (default case4_socket_gate_pad58b)')
    ap.add_argument('--pad-expect', help='read-schedule endpoint, padded arm: CASE4_PAD_EXPECT for the master only '
                                         '(<class>=<n>[,...]; needs --read-schedule)')
    a = ap.parse_args()
    if a.apply and (a.endpoint_profile != 'sel751' or a.mode != 'run'):
        sys.exit('--apply is only supported for the physical SEL-751 run entrypoint')
    if a.endpoint_profile == 'sel751' and a.mode == 'run':
        try:
            authorize_relay_run(a)
        except (ValueError, TypeError) as error:
            sys.exit(str(error))

    if a.endpoint_profile == 'sel751' and a.mode != 'run':
        if a.mode not in ('setup', 'restore', 'state'):
            sys.exit('physical relay does not use an emulated fixture')
        lifecycle = relay_offload_lifecycle(a.mode, loss_baseline=a.loss_baseline) if a.mode in ('setup', 'restore') else None
        if lifecycle is not None:
            print(json.dumps(dict(endpoint_profile='sel751', mode=a.mode, offload=lifecycle)))
        print(state())
        if a.mode == 'restore' and lifecycle['errors']:
            sys.exit('physical receive offload restore failed: ' + '; '.join(lifecycle['errors']))
        return

    if a.mode == 'setup':
        # before ANY change: no block (diagnostic or not) starts on a host carrying a CPU-latency state or constraint
        if os.path.exists(CPU_LATENCY_STATE):
            sys.exit('setup refused: a CPU-latency diagnostic state exists (%s); restore first' % CPU_LATENCY_STATE)
        effective_now = capture_observation.read_cpu_latency()
        if effective_now != capture_observation.CPU_LATENCY_UNCONSTRAINED or capture_observation.device_held():
            sys.exit('setup refused: CPU latency constraint %r or the device is held before setup' % effective_now)
        capture_observation.record_offload_baseline(OFFLOAD_BASELINE, PARENT)
        if a.rx_coalesce_diag:
            baseline, effective = capture_observation.rx_coalesce_diagnostic(RX_COALESCE_BASELINE, PARENT)
            print('rx coalescing diagnostic: baseline adaptive-rx %s rx-usecs %d; effective adaptive-rx %s rx-usecs %d'
                  % (baseline['adaptive_rx'], baseline['rx_usecs'], effective['adaptive_rx'], effective['rx_usecs']))
        if a.cpu_latency_diag:
            held = capture_observation.cpu_latency_hold(CPU_LATENCY_STATE)
            print('cpu latency diagnostic: baseline %d us; effective %d us; helper pid %d'
                  % (held['baseline'], held['effective'], held['pid']))
        profile('0', DEFAULT_RANGE)
        if 'source-pruning : on' not in state():
            pruning('on')
    if a.mode == 'casea':
        if a.label not in ('on', 'off'):
            sys.exit('casea on|off')
        casea(a.label == 'on', a.delay_ms, a.jitter_ms, a.distribution)
    if a.mode == 'restore':
        # CPU release first (independent and cheap), then every restore step isolated: an exception or sys.exit in
        # one step never skips another; all failures are reported together at the end (nonzero exit)
        messages = []

        def attempt(label, step):
            try:
                result = step()
            except BaseException as error:      # noqa: BLE001 - includes SystemExit from casea/pruning
                messages.append('%s raised: %r' % (label, error))
                return None
            return result
        released = attempt('cpu latency restore', lambda: capture_observation.cpu_latency_release(CPU_LATENCY_STATE))
        if released is not None:
            cpu_errors, evidence = released
            print('cpu latency release evidence: %s' % json.dumps(evidence, sort_keys=True))
            if evidence.get('applied') and not evidence.get('diagnostic_valid'):
                print('CPU LATENCY DIAGNOSTIC INVALID: the zero request was not verified in force at release')
            if cpu_errors:
                messages.append('cpu latency restore failed: ' + '; '.join(cpu_errors))
        attempt('fixture off', lambda: casea(False, 0))
        attempt('namespace profile', lambda: profile('1', DEFAULT_RANGE))
        attempt('source pruning', lambda: None if 'source-pruning : off' in state() else pruning('off'))
        offload = attempt('receive offload restore',
                          lambda: capture_observation.restore_offload_baseline(OFFLOAD_BASELINE, PARENT))
        coalesce = attempt('rx coalescing restore',
                           lambda: capture_observation.restore_rx_coalesce(RX_COALESCE_BASELINE, PARENT))
        if coalesce:
            messages.insert(0, 'rx coalescing restore failed: ' + '; '.join(coalesce))
        if offload:
            messages.append('receive offload restore failed: ' + '; '.join(offload))
        for label, read in (('cpu latency after restore', lambda: '%d us' % capture_observation.read_cpu_latency()),
                            ('rx coalescing after restore', lambda: ' '.join(
                                '%s=%s' % kv for kv in sorted(capture_observation.snapshot_rx_coalesce(PARENT).items())
                                if kv[0] != 'raw'))):
            try:
                print('%s: %s' % (label, read()))
            except Exception as error:  # noqa: BLE001 - a read-back print never masks the restore outcome
                print('%s: unreadable (%s)' % (label, error))
        if messages:
            try:
                print(state())
            except Exception:           # noqa: BLE001
                pass
            sys.exit('; '.join(messages))
    if a.mode != 'run':
        print(state())
        sys.exit(0)

    if not a.label or not re.fullmatch(r'[A-Za-z0-9_]+', a.label) or a.master_port is None:
        sys.exit('run needs LABEL and --master-port')
    drop = None
    if a.drop:
        try:
            if a.endpoint_profile == 'sel751':
                import relay_loss
                drop = relay_loss.parse_drop(a.drop, a.read_schedule, a.relay_padding)
            else:
                drop = loss.parse_drop(a.drop, a.reads)      # a bad spec stops the run before anything is created
        except ValueError as e:
            sys.exit(str(e))
    if a.scenario == 'persistence':
        if a.endpoint_profile != 'sel751':
            sys.exit('persistence scenario requires the physical relay profile')
        result = run_relay_series(a.label, a.master_port, a.reads, a.close_mode, a.close_grace_ms, a.read_schedule)
        print(json.dumps(result))
        sys.exit(0 if result['ok'] else 1)
    if a.scenario == 'reconnect':
        try:
            out = run_reconnect(a.label, a.master_port, a.reconnect_port or a.master_port + 1, a.reads, a.range,
                                a.gap_ms, a.start_delay_ms, a.start_seed, a.read_pause_ms, bool(a.run_sbo),
                                a.close_grace_ms, a.qualify_capture, a.sbo_cycles, read_schedule=a.read_schedule,
                                db=a.db, endpoint_binary_name=a.endpoint_binary, pad_expect=a.pad_expect,
                                endpoint_profile=a.endpoint_profile)
        except ValueError as e:
            sys.exit(str(e))
        print(json.dumps(out))
        sys.exit(0 if out['ok'] else 1)
    try:
        result = run_connection(os.path.join(RUNS, a.label), a.label, a.master_port, a.reads, a.range, a.gap_ms,
                                a.start_delay_ms, a.start_seed, drop, a.connect_must_fail,
                                a.read_pause_ms, bool(a.run_sbo), a.close_grace_ms,
                                qualify_capture=a.qualify_capture, sbo_cycles=a.sbo_cycles,
                                read_schedule=a.read_schedule, db=a.db, endpoint_binary_name=a.endpoint_binary,
                                pad_expect=a.pad_expect, endpoint_profile=a.endpoint_profile, relay_close_mode=a.close_mode)
    except (RuntimeError, ValueError) as e:
        sys.exit(str(e))
    print(json.dumps(result))
    sys.exit(0 if result['ok'] else 1)


if __name__ == '__main__':
    main()
