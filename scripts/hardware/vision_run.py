"""Vision side of a physical SEL-751 run through the switch. Run with sudo python3 on Vision.

  vision_run.py setup     record the parent NIC's receive-offload baseline (refused while one is pending) and,
                          with --loss-baseline, the host firewall; print the namespace state
  vision_run.py restore   remove owned loss rules, re-apply the receive offloads (and any pending --mirror-iface
                          offloads) from their baselines and verify them (nonzero exit if not)
  vision_run.py state     print the NIC flag, the namespace sysctls and the ns_vepa_b route and qdisc
  vision_run.py run LABEL --master-port P --reads N [...]

`run` never starts an outstation: the relay_master workload drives the SEL-751 from one real master socket
(source port P), and the NEW directory RUNS/LABEL receives out.pcap (tcpdump -Q out on the parent NIC: frames as
the master sent them), in.pcap (-Q in: frames as the switch returned them), master.json, state.txt and
result.json. `casea` is refused: the physical relay uses no emulated fixture."""
import argparse
import contextlib
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
import time
import capture_observation
import loss

def authorize_relay_run(args):
    """Trusted application entrypoint for the frozen wrapper's explicit --apply intent."""
    if args.mode != 'run':
        raise ValueError('explicit apply is supported only by the physical SEL-751 run entrypoint')
    if not args.label or not re.fullmatch('[A-Za-z0-9_]+', args.label) or (not 1024 <= args.master_port <= 65535):
        raise ValueError('invalid fixed-profile label or source port')
    if not 1 <= args.reads <= 65 or not 0 <= args.sbo_cycles <= 64 or args.sbo_cycles >= args.reads:
        raise ValueError('invalid bounded physical workload')
    if args.run_sbo not in (0, 1) or (args.sbo_cycles and (not args.run_sbo)):
        raise ValueError('invalid guarded SBO controls')
    if args.sbo_select_only not in (0, 1) or (args.sbo_select_only and not (args.sbo_cycles and args.run_sbo)):
        raise ValueError('invalid guarded SBO controls: --sbo-select-only needs --sbo-cycles and --run-sbo 1')
    if args.read_schedule not in (None, 'mixed_full', 'mixed', 'full') or any((not 0 <= value <= 5000 for value in (args.gap_ms, args.read_pause_ms, args.close_grace_ms))):
        raise ValueError('unsupported physical READ schedule or bounded timing')
    if args.endpoint_binary or args.pad_expect or getattr(args, 'db', None) is not None:
        raise ValueError('software endpoint and unsupported loss controls are forbidden on the physical profile')
    if args.drop:
        import relay_loss
        relay_loss.parse_drop(args.drop, args.read_schedule, args.relay_padding)
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1' and (not args.apply):
        raise ValueError('physical run requires authorization environment or explicit --apply')
    from relay_master import preflight
    preflight()
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
        mirror = restore_mirror_offloads(run) if os.path.exists(MIRROR_OFFLOAD_BASELINE) else None
        if mirror is not None:
            errors += mirror['errors']
        result = dict(errors=errors, restored=not errors, loss=cleanup)
        if mirror is not None:
            result['mirror'] = mirror
        return result
    raise ValueError('physical offload lifecycle supports setup/restore only')

def restore_mirror_offloads(run):
    """Campaign restore: put back the --mirror-iface receive aggregation that a run left pending (killed before
    stop(), or its own restore failed). The baseline file is removed only once the interface verifies equal to it."""
    try:
        with open(MIRROR_OFFLOAD_BASELINE) as stream:
            interface = json.load(stream)['interface']
    except (OSError, ValueError, KeyError) as error:
        return dict(interface=None, errors=['mirror offload baseline unreadable: %s' % error], restored=False)
    errors = capture_observation.restore_offload_baseline(MIRROR_OFFLOAD_BASELINE, interface, run=run)
    return dict(interface=interface, errors=['mirror interface %s: %s' % (interface, e) for e in errors],
                restored=not errors)

def run_relay_connection(run_dir, label, master_port, reads, gap_ms=0, read_pause_ms=25, run_sbo=True, close_grace_ms=0, sbo_cycles=0, read_schedule=None, qualify_capture=False, start_delay_max=0, start_seed=0, close_mode='graceful', **unused):
    """Capture one real master socket. Never start an outstation or alter TCP settings. select_only (E4b) reaches the
    workload, and the endpoint record, only when set."""
    select_only = unused.get('select_only', False)
    from relay_master import workload
    from endpoint_profiles import MASTER_IP, RELAY_IP
    os.makedirs(run_dir)
    open(os.path.join(run_dir, 'state.txt'), 'w').write(state() + '\n')
    result = dict(label=label, endpoint_profile='sel751', master_port=master_port, reads=reads, observation_scope='single master NIC TX/RX; switch emission not observed', endpoint_controls=dict(read_pause_ms=read_pause_ms, run_sbo=bool(run_sbo), close_grace_ms=close_grace_ms), tcpdump={}, ok=False)
    if select_only is not False:
        result['endpoint_controls']['sbo_select_only'] = select_only
    caps, loss_owner = ({}, [None])
    mirror = MirrorCapture(run_dir, unused['mirror_iface']) if unused.get('mirror_iface') is not None else None

    def capture():
        try:
            result['source_port_wait'] = wait_relay_port_free(master_port)
            if result['source_port_wait']['result'] != 'free':
                raise RuntimeError('physical source port unavailable: ' + str(result['source_port_wait']))
            flt = 'tcp and host %s and host %s and port 20000' % (MASTER_IP, RELAY_IP)
            for direction in ('out', 'in'):
                command = ['tcpdump', '--immediate-mode', '-i', PARENT, '-Q', direction, '-s0', '-U', '-n', '-w', os.path.join(run_dir, direction + '.pcap'), flt]
                caps[direction] = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
            time.sleep(2)
            for direction, proc in caps.items():
                if proc.poll() is not None or not os.path.isfile(os.path.join(run_dir, direction + '.pcap')):
                    raise RuntimeError('relay capture failed before traffic: ' + direction)
            if mirror is not None:
                mirror.start()
            if unused.get('drop'):
                import relay_loss
                loss_owner[0] = relay_loss.RelayLoss(unused['drop'], master_port, label, HOME + '/relay_loss_state.json', capture=os.path.join(run_dir, 'in.pcap'))
                loss_owner[0].install()
            time.sleep(start_delay_ms(start_delay_max, start_seed) / 1000)
            if os.environ.get('RELAY_EVENT_CLEAR') == '1':
                import event_clear
                from session import Session
                with Session(RELAY_IP, 20000, source_address=(MASTER_IP, master_port)) as session:
                    master = event_clear.clear(session)
                json.dump(master, open(os.path.join(run_dir, 'event_clear.json'), 'w'), indent=2)
                result.update(ok=master['ok'], master_rc=0 if master['ok'] else 1, event_clear=True)
                return result
            master = workload(master_port, reads, schedule=read_schedule or 'mixed_full', sbo_cycles=sbo_cycles,
                              run_sbo=run_sbo, gap_ms=gap_ms, read_pause_ms=read_pause_ms,
                              close_grace_ms=close_grace_ms, close_mode=close_mode,
                              loss_target=loss_owner[0] if loss_owner[0] is not None and loss_owner[0].identity
                              else None, **({'select_only': select_only} if select_only is not False else {}))
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
                    result['loss'] = dict(exact=False, error=str(error), restoration=relay_loss.restore_owned(HOME + '/relay_loss_state.json'))
                result['ok'] = bool(result['ok'] and result['loss'].get('exact') and result['loss'].get('restoration', {}).get('restored'))
            for direction, proc in caps.items():
                proc.terminate()
                try:
                    _, stderr = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _, stderr = proc.communicate()
                result['tcpdump'][direction] = parse_tcpdump_stats(stderr or '')
            if mirror is not None:
                result['mirror'] = mirror.stop()
                if not result['mirror']['ok']:
                    result['ok'] = False
                    failed = '; '.join(result['mirror']['failures'])
                    result.setdefault('error', 'diagnostic mirror capture failed: ' + failed)
            json.dump(result, open(os.path.join(run_dir, 'result.json'), 'w'), indent=2)
        return result
    with capture_observation.offload_capture_context(run_dir, interface=PARENT):
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
    start, last_error = (time.monotonic(), None)
    for poll in range(1, tries + 1):
        try:
            outgoing = [p for p in wire_check.parse(os.path.join(run_dir, 'out.pcap'))[0] if (p['src'], p['dst'], p['sport'], p['dport']) == (MASTER_IP, RELAY_IP, master_port, RELAY_PORT)]
            incoming = [p for p in wire_check.parse(os.path.join(run_dir, 'in.pcap'))[0] if (p['src'], p['dst'], p['sport'], p['dport']) == (RELAY_IP, MASTER_IP, RELAY_PORT, master_port)]
            complete = any((p['flags'] & wire_check.RST for p in outgoing)) if mode == 'rst' else any((p['flags'] & wire_check.FIN and any((q['flags'] & wire_check.ACK and q['ack'] == p['seq'] + p['len'] + 1 & 4294967295 for q in outgoing)) for p in incoming)) and any((p['flags'] & wire_check.FIN and any((q['flags'] & wire_check.ACK and q['ack'] == p['seq'] + p['len'] + 1 & 4294967295 for q in incoming)) for p in outgoing))
            if complete:
                return dict(complete=True, mode=mode, polls=poll, elapsed_s=time.monotonic() - start)
        except Exception as error:
            last_error = str(error)
        time.sleep(0.05)
    return dict(complete=False, mode=mode, polls=tries, elapsed_s=time.monotonic() - start, error=last_error)

def run_relay_series(label, master_port, reads, close_mode, close_grace_ms, read_schedule):
    parent = os.path.join(RUNS, label)
    os.makedirs(parent)
    open(os.path.join(parent, 'state.txt'), 'w').write(state() + '\n')
    result = dict(scenario='physical_same_tuple', label=label, close_mode=close_mode, connections={}, ok=False)
    for index in range(1, 4):
        name = 'c%d' % index
        try:
            result['connections'][name] = run_connection(os.path.join(parent, name), label + '_' + name, master_port, reads, 8, 0, 0, 12344 + index, read_pause_ms=25, run_sbo=True, close_grace_ms=close_grace_ms, qualify_capture=True, read_schedule=read_schedule, endpoint_profile='sel751', relay_close_mode=close_mode)
            if relay_restore_uncertain(result['connections'][name], os.path.join(parent, name), qualified=True):
                for pending in range(index + 1, 4):
                    result['connections']['c%d' % pending] = dict(ok=False, ran=False, error='capture/loss restoration unverified; stopped')
                break
        except (RuntimeError, ValueError, OSError) as error:
            result['connections'][name] = dict(ok=False, error=str(error), master_port=master_port)
            if relay_restore_uncertain(result['connections'][name], os.path.join(parent, name), qualified=True):
                for pending in range(index + 1, 4):
                    result['connections']['c%d' % pending] = dict(ok=False, ran=False, error='capture restoration unverified; stopped')
                break
    result['ok'] = len(result['connections']) == 3 and all((record.get('ok') for record in result['connections'].values()))
    result.update(planned_connections=3, attempted_connections=sum((record.get('ran', True) for record in result['connections'].values())), completed_connections=sum((record.get('ok', False) for record in result['connections'].values())))
    json.dump(result, open(os.path.join(parent, 'scenario.json'), 'w'), indent=2)
    return result

def relay_restore_uncertain(record, run_dir=None, qualified=False):
    uncertain = bool(record.get('restoration_uncertain') or 'restore failed' in str(record.get('error', '')).lower() or (record.get('loss') is not None and record['loss'].get('restoration', {}).get('restored') is not True))
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
NS_M, NS_O = ('ns_vepa_a', 'ns_vepa_b')
HOME = os.path.dirname(os.path.abspath(__file__))
RUNS = HOME + '/runs'
PROFILE = ('net.ipv4.tcp_timestamps', 'net.ipv4.tcp_sack', 'net.ipv4.tcp_window_scaling')
OFFLOAD_BASELINE = HOME + '/offload_baseline.json'
MIRROR_OFFLOAD_BASELINE = HOME + '/mirror_offload_baseline.json'
READ_SCHEDULES = ('rotate4', 'mixed_full', 'mixed', 'full')
PAD_EXPECT_RE = re.compile('(range|analog|class0|integrity|mixed)=[1-9][0-9]{0,3}(,(range|analog|class0|integrity|mixed)=[1-9][0-9]{0,3})*')
DBS = ('base', 'large')
MIRROR_IFACE = re.compile('[A-Za-z0-9_.-]{1,15}')
MIRROR_FILES = ('mirror.pcap', 'mirror_iface_before.json', 'mirror_iface_after.json', 'mirror_offloads.json',
                'mirror_capture.json')

class MirrorCapture:
    """--mirror-iface (c72_diag_mirror only): relay-leg copies arriving on a separate capture interface. Identity
    before and after, receive aggregation off for the run (offload_capture_context, restored on every exit path) and
    an unfiltered tcpdump -Q in verified as started before traffic. start() raises before traffic on any failure;
    stop() never raises and records every failure in mirror_capture.json, which then fails the run."""

    def __init__(self, run_dir, interface, run=None, popen=None, sleep=None):
        self.dir, self.interface = (run_dir, interface)
        self.run = capture_observation.sh if run is None else run
        self.popen = subprocess.Popen if popen is None else popen
        self.sleep = time.sleep if sleep is None else sleep
        self.pcap = os.path.join(run_dir, 'mirror.pcap')
        self.command = ['tcpdump', '-i', interface, '-Q', 'in', '-s0', '-U', '-n', '--immediate-mode', '-w', self.pcap]
        self.proc, self.offloads = (None, contextlib.ExitStack())
        self.baseline, self.baseline_written = (MIRROR_OFFLOAD_BASELINE, False)
        self.record = dict(interface=interface, command=self.command, started=False, failures=[])

    def identity(self, name):
        """ethtool -i, ip -j -s link show and the ethtool -S rx counters of the interface into NAME; returns errors."""
        out, errors = (dict(interface=self.interface, observed_at_epoch_ns=time.time_ns(), commands={}), [])
        commands = (('driver', ['ethtool', '-i', self.interface]), ('stats', ['ethtool', '-S', self.interface]),
                    ('link', ['ip', '-j', '-s', 'link', 'show', self.interface]))
        for key, argv in commands:
            result = self.run(argv)
            out['commands'][key] = dict(argv=argv, returncode=result.returncode, stdout=result.stdout,
                                        stderr=result.stderr)
            if result.returncode:
                errors.append('%s failed (rc %d): %s' % (' '.join(argv), result.returncode,
                                                         (result.stderr or '').strip()))
        lines = out['commands']['driver']['stdout'].splitlines()
        out['driver'] = dict((part.strip() for part in line.split(':', 1)) for line in lines if ':' in line)
        try:
            out['link'] = json.loads(out['commands']['link']['stdout'])
        except ValueError as error:
            out['link'] = None
            errors.append('ip -j -s link show %s: unparsable JSON (%s)' % (self.interface, error))
        counters = re.findall('^\\s*(\\S*rx\\S*):\\s*(\\d+)\\s*$', out['commands']['stats']['stdout'], re.M | re.I)
        out['rx_counters'] = {name: int(value) for name, value in counters}
        if not out['rx_counters']:
            errors.append('ethtool -S %s reported no rx counters' % self.interface)
        out['errors'] = errors
        with open(os.path.join(self.dir, name), 'w') as stream:
            json.dump(out, stream, indent=1)
        return errors

    def start(self):
        try:
            if os.path.exists(self.baseline):
                raise RuntimeError('a mirror offload baseline is pending at %s; restore first' % self.baseline)
            errors = self.identity('mirror_iface_before.json')
            if errors:
                raise RuntimeError('mirror interface identity before traffic failed: ' + '; '.join(errors))
            capture_observation.record_offload_baseline(self.baseline, self.interface, run=self.run)
            self.baseline_written = True         # vision_run.py restore repairs the interface if this run dies
            self.offloads.enter_context(capture_observation.offload_capture_context(
                self.dir, interface=self.interface, run=self.run, evidence_name='mirror_offloads.json'))
            self.proc = self.popen(self.command, stderr=subprocess.PIPE, text=True)
            self.sleep(2)
            exited, header = (self.proc.poll(), os.path.isfile(self.pcap) and os.path.getsize(self.pcap) >= 24)
            if exited is not None or not header:
                raise RuntimeError('mirror capture on %s failed before traffic (tcpdump rc %s, pcap header written %s)'
                                   % (self.interface, exited, header))
            self.record['started'] = True
        except Exception as error:
            self.record['failures'].append(str(error))
            raise

    def stop(self):
        failures = self.record['failures']
        try:
            if self.proc is not None:
                early = self.proc.poll()
                if early is not None and self.record['started']:
                    failures.append('mirror tcpdump exited early (rc %s)' % early)
                self.proc.terminate()
                try:
                    _, stderr = self.proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    _, stderr = self.proc.communicate()
                self.record['tcpdump'] = parse_tcpdump_stats(stderr or '')
                stats = self.record['tcpdump']
                missing = [key for key in ('captured', 'received', 'dropped_kernel') if key not in stats]
                if missing:
                    failures.append('mirror tcpdump statistics not reported: ' + ', '.join(missing))
            if not (os.path.isfile(self.pcap) and os.path.getsize(self.pcap) >= 24):
                failures.append('mirror.pcap missing or without a pcap header')
            self.record['pcap_bytes'] = os.path.getsize(self.pcap) if os.path.isfile(self.pcap) else None
        except Exception as error:
            failures.append('mirror capture stop failed: %r' % error)
        try:
            errors = self.identity('mirror_iface_after.json')
            failures += ['mirror interface identity after traffic: ' + e for e in errors]
        except Exception as error:
            failures.append('mirror interface identity after traffic failed: %r' % error)
        try:
            self.offloads.close()
        except Exception as error:
            failures.append('mirror receive offload restore failed: %s' % error)
        try:
            with open(os.path.join(self.dir, 'mirror_offloads.json')) as stream:
                self.record['offload_restore_ok'] = json.load(stream).get('restore_ok')
        except (OSError, ValueError) as error:
            self.record['offload_restore_ok'] = None
            failures.append('mirror_offloads.json unreadable: %s' % error)
        if self.baseline_written and self.record['offload_restore_ok'] is True:
            try:
                pending = capture_observation.restore_offload_baseline(self.baseline, self.interface, run=self.run)
            except Exception as error:
                pending = [repr(error)]
            failures += ['mirror offload baseline not cleared: ' + e for e in pending]
        self.record['offload_baseline_pending'] = os.path.exists(self.baseline)
        self.record['ok'] = not failures
        try:
            with open(os.path.join(self.dir, 'mirror_capture.json'), 'w') as stream:
                json.dump(self.record, stream, indent=1)
        except OSError as error:
            failures.append('mirror_capture.json not written: %s' % error)
            self.record['ok'] = False
        return self.record

def sh(*cmd, **kw):
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)

def start_delay_ms(max_ms, seed):
    """The pre-connect delay for a run: uniform over 0..max_ms ms, but a pure function of the seed so a paired
    block can replay the identical start phase and the result can record exactly what was applied."""
    return random.Random(seed).randint(0, max_ms) if max_ms > 0 else 0

def nsx(ns, *cmd, **kw):
    return sh('ip', 'netns', 'exec', ns, *cmd, **kw)

def parse_tcpdump_stats(stderr):
    """tcpdump prints a termination summary on stderr: 'N packets captured', 'N received by filter',
    'N dropped by kernel', and sometimes 'N dropped by interface'. Return them so capture loss is retained."""
    out = {}
    for label, key in (('captured', 'captured'), ('received by filter', 'received'), ('dropped by kernel', 'dropped_kernel'), ('dropped by interface', 'dropped_interface')):
        m = re.search('(\\d+)\\s+packets?\\s+' + re.escape(label), stderr)
        if m:
            out[key] = int(m.group(1))
    return out

def state():
    flags = sh('ethtool', '--show-priv-flags', PARENT).stdout.splitlines()
    lines = [' '.join(next((l for l in flags if 'source-pruning' in l)).split())]
    for ns in (NS_M, NS_O):
        lines.append(ns + ' ' + ' | '.join(nsx(ns, 'sysctl', *PROFILE, 'net.ipv4.ip_local_port_range').stdout.split('\n')).strip(' |'))
    return '\n'.join(lines) + '\n' + casea_state()

DISTRIBUTIONS = ('normal', 'paretonormal')
def casea_state():
    return 'route: ' + nsx(NS_O, 'ip', 'route', 'show', '192.168.10.0/24').stdout.strip() + '\n' + 'qdisc: ' + ' | '.join(nsx(NS_O, 'tc', 'qdisc', 'show', 'dev', 'mvB').stdout.strip().splitlines())

def run_connection(run_dir, label, master_port, reads, rng, gap_ms, start_delay_max, start_seed, drop=None,
                   connect_must_fail=False, read_pause_ms=25, run_sbo=True, close_grace_ms=0, capture_immediate=False,
                   qualify_capture=False, sbo_cycles=0, read_schedule=None, db=None, endpoint_binary_name=None,
                   pad_expect=None, endpoint_profile='sel751', relay_close_mode='graceful', mirror_iface=None,
                   sbo_select_only=False):
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('physical run requires authorization before capture/socket creation')
    if connect_must_fail or endpoint_binary_name or pad_expect:
        raise ValueError('unsupported physical relay control; refusing before traffic')
    return run_relay_connection(run_dir, label, master_port, reads, gap_ms=gap_ms, read_pause_ms=read_pause_ms,
                                run_sbo=run_sbo, close_grace_ms=close_grace_ms, sbo_cycles=sbo_cycles,
                                read_schedule=read_schedule, qualify_capture=qualify_capture,
                                start_delay_max=start_delay_max, start_seed=start_seed, close_mode=relay_close_mode,
                                drop=drop, mirror_iface=mirror_iface,
                                **({'select_only': True} if sbo_select_only else {}))

def run_reconnect(label, master_port, reconnect_port, reads, rng, gap_ms, start_delay_max, start_seed, read_pause_ms=25, run_sbo=True, close_grace_ms=0, qualify_capture=False, sbo_cycles=0, read_schedule=None, db=None, endpoint_binary_name=None, pad_expect=None, endpoint_profile='sel751'):
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
    os.makedirs(parent)
    open(os.path.join(parent, 'state.txt'), 'w').write(state() + '\n')
    plan = (('c1', master_port, 'installed'), ('c2', reconnect_port, 'unknown_port'), ('c3', master_port, 'installed_again'))
    out = {'scenario': 'reconnect', 'label': label, 'connections': {}, 'ok': False}
    for name, port, role in plan:
        try:
            res = run_connection(os.path.join(parent, name), '%s_%s' % (label, name), port, reads, rng, gap_ms, start_delay_max, start_seed, read_pause_ms=read_pause_ms, run_sbo=run_sbo, close_grace_ms=close_grace_ms, qualify_capture=qualify_capture, sbo_cycles=sbo_cycles, read_schedule=read_schedule, db=db, endpoint_binary_name=endpoint_binary_name, pad_expect=pad_expect if name != 'c2' else None, **{'endpoint_profile': endpoint_profile})
        except RuntimeError as e:
            res = {'label': '%s_%s' % (label, name), 'master_port': port, 'ok': False, 'error': str(e)}
        res['role'] = role
        out['connections'][name] = res
        if relay_restore_uncertain(res, os.path.join(parent, name), qualify_capture):
            for pending, pending_port, pending_role in plan[len(out['connections']):]:
                out['connections'][pending] = dict(role=pending_role, master_port=pending_port, ran=False, ok=False, error='capture/loss restoration unverified; stopped')
            break
    c = out['connections']
    out['ok'] = bool(c.get('c1', {}).get('ok') and c.get('c2', {}).get('ok'))
    out['ok'] = out['ok'] and bool(c.get('c3', {}).get('ok'))
    out.update(planned_connections=3, attempted_connections=sum((record.get('ran', True) for record in c.values())), completed_connections=sum((record.get('ok', False) for record in c.values())))
    json.dump(out, open(os.path.join(parent, 'scenario.json'), 'w'), indent=1)
    return out

def bounded_ms(value):
    if not re.fullmatch('[0-9]+', value) or not 0 <= int(value) <= 5000:
        raise argparse.ArgumentTypeError('expected a decimal integer in 0..5000')
    return int(value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--endpoint-profile', choices=('sel751',), default='sel751')
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
    ap.add_argument('--sbo-cycles', type=int, default=0, help='repeated-SBO endpoint: N cycles of SELECT->OPERATE then READ (reads counts every READ)')
    ap.add_argument('--sbo-select-only', type=int, choices=(0, 1), default=0,
                    help='E4b, physical run with --sbo-cycles only: each cycle is a guarded SELECT with no OPERATE')
    ap.add_argument('--start-delay-ms', type=int, default=0, help='maximum pre-connect delay; the applied delay is uniform in 0..N and fixed by --start-seed')
    ap.add_argument('--start-seed', type=int, default=0)
    ap.add_argument('--delay-ms', type=int, default=25)
    ap.add_argument('--cpu-latency-diag', action='store_true', help='retired: no effect')
    ap.add_argument('--rx-coalesce-diag', action='store_true', help='retired: no effect')
    ap.add_argument('--jitter-ms', type=int, default=0, help='netem jitter of the separate_ack response delay')
    ap.add_argument('--distribution', choices=DISTRIBUTIONS, help='netem jitter distribution (needed with --jitter-ms)')
    ap.add_argument('--connect-must-fail', action='store_true')
    ap.add_argument('--scenario', choices=('reconnect', 'persistence'), help='reconnect: c1 on the installed port, c2 on a new unknown port (expected native), c3 on the installed tuple again (characterized, not asserted); each its own evidence under RUNS/LABEL/')
    ap.add_argument('--reconnect-port', type=int, help='source port of c2 (default: master port + 1)')
    ap.add_argument('--close-mode', choices=('graceful', 'rst'), default='graceful')
    ap.add_argument('--drop', metavar='CLASS[:N]', help='drop exactly the Nth packet of a class at the receiving namespace ingress (see loss.py); classes: ' + ', '.join(loss.names()))
    ap.add_argument('--event-clear', action='store_true', help='physical SEL-751 only: poll class-2 events and confirm them once, then check IIN (READ/CONFIRM)')
    ap.add_argument('--qualify-capture', action='store_true', help='opt-in physical packet-boundary qualification evidence for this run')
    ap.add_argument('--read-schedule', choices=READ_SCHEDULES, help='read-schedule endpoint: CASE4_READ_SCHEDULE for the master (needs --db)')
    ap.add_argument('--db', choices=DBS, help='read-schedule endpoint: CASE4_DB for both endpoints')
    ap.add_argument('--endpoint-binary', help='retired software-outstation option; refused on the physical relay')
    ap.add_argument('--pad-expect', help='read-schedule endpoint, padded arm: CASE4_PAD_EXPECT for the master only (<class>=<n>[,...]; needs --read-schedule)')
    ap.add_argument('--mirror-iface', metavar='IFACE',
                    help='c72_diag_mirror only: capture the relay-leg copies arriving on IFACE (mirror.pcap)')
    a = ap.parse_args()
    if a.mirror_iface is not None and (a.mode != 'run' or a.scenario or a.drop or a.event_clear or a.connect_must_fail
                                       or not MIRROR_IFACE.fullmatch(a.mirror_iface) or a.mirror_iface == PARENT):
        sys.exit('--mirror-iface IFACE is only for one plain physical SEL-751 run, on an interface other than '
                 + PARENT)
    if a.sbo_select_only and (a.mode != 'run' or a.scenario or a.drop or a.event_clear or a.connect_must_fail):
        sys.exit('--sbo-select-only 1 is only for one plain physical SEL-751 run with --sbo-cycles')
    if a.event_clear:
        if a.mode != 'run' or a.drop or a.scenario:
            sys.exit('--event-clear is only for one plain physical SEL-751 run')
        os.environ['RELAY_EVENT_CLEAR'] = '1'
    if a.apply and a.mode != 'run':
        sys.exit('--apply is only supported for the physical SEL-751 run entrypoint')
    if a.mode == 'run':
        try:
            authorize_relay_run(a)
        except (ValueError, TypeError) as error:
            sys.exit(str(error))
    if a.mode != 'run':
        if a.mode not in ('setup', 'restore', 'state'):
            sys.exit('physical relay does not use an emulated fixture')
        lifecycle = relay_offload_lifecycle(a.mode, loss_baseline=a.loss_baseline) if a.mode in ('setup', 'restore') else None
        if lifecycle is not None:
            print(json.dumps(dict(endpoint_profile='sel751', mode=a.mode, offload=lifecycle)))
        print(state())
        if a.mode == 'restore' and lifecycle['errors']:
            sys.exit('physical receive offload restore failed: ' + '; '.join(lifecycle['errors']))
        return
    if not a.label or not re.fullmatch('[A-Za-z0-9_]+', a.label) or a.master_port is None:
        sys.exit('run needs LABEL and --master-port')
    drop = None
    if a.drop:
        try:
            import relay_loss
            drop = relay_loss.parse_drop(a.drop, a.read_schedule, a.relay_padding)
        except ValueError as e:
            sys.exit(str(e))
    if a.scenario == 'persistence':
        result = run_relay_series(a.label, a.master_port, a.reads, a.close_mode, a.close_grace_ms, a.read_schedule)
        print(json.dumps(result))
        sys.exit(0 if result['ok'] else 1)
    if a.scenario == 'reconnect':
        try:
            out = run_reconnect(a.label, a.master_port, a.reconnect_port or a.master_port + 1, a.reads, a.range, a.gap_ms, a.start_delay_ms, a.start_seed, a.read_pause_ms, bool(a.run_sbo), a.close_grace_ms, a.qualify_capture, a.sbo_cycles, read_schedule=a.read_schedule, db=a.db, endpoint_binary_name=a.endpoint_binary, pad_expect=a.pad_expect, endpoint_profile=a.endpoint_profile)
        except ValueError as e:
            sys.exit(str(e))
        print(json.dumps(out))
        sys.exit(0 if out['ok'] else 1)
    try:
        result = run_connection(os.path.join(RUNS, a.label), a.label, a.master_port, a.reads, a.range, a.gap_ms,
                                a.start_delay_ms, a.start_seed, drop, a.connect_must_fail, a.read_pause_ms,
                                bool(a.run_sbo), a.close_grace_ms, qualify_capture=a.qualify_capture,
                                sbo_cycles=a.sbo_cycles, read_schedule=a.read_schedule, db=a.db,
                                endpoint_binary_name=a.endpoint_binary, pad_expect=a.pad_expect,
                                endpoint_profile=a.endpoint_profile, relay_close_mode=a.close_mode,
                                mirror_iface=a.mirror_iface,
                                **({'sbo_select_only': True} if a.sbo_select_only else {}))
    except (RuntimeError, ValueError) as e:
        sys.exit(str(e))
    print(json.dumps(result))
    sys.exit(0 if result['ok'] else 1)
if __name__ == '__main__':
    main()
