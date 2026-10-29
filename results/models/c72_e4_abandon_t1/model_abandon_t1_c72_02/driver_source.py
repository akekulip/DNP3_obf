"""E4: the abandoned SELECT with timing enabled (ABANDON_T=1). A separate labelled scenario, NOT a gate driver.

The gate's model_abandon.py (T=0) is loaded unchanged for its stimulus builders, endpoint binding and timing
parameters. Its bytes must stay those of the passing c72 gate run (driver_sha256 00059dce...), whose dependency
closure binds them: editing it blocks the c72 model gate. Run with scripts/model/run_abandon_t1.py.

Rows: (report row, stimulus frames in order, frames expected at the master, frames expected at the relay, release).
Derived from the current contract, with file:line citations, in results/models/c72_e4_abandon_t1/EXPECTATIONS.json;
tests/model/test_abandon_timed.py keeps the two equal. 'response_ready_D': the relay's genuine ACK is held until the
whole response reaches T and leaves at ACK commit; the response leaves no earlier than ACK commit + D. Unlike the
T=0 stimulus, the relay ACKs the SELECT before answering it: under this contract a response with no genuine ACK
commit in its generation is never released."""
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
GATE_DRIVER = HERE / 'model_abandon.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = load('_abandon_gate_driver', GATE_DRIVER)          # module level only; its main() never runs here
helpers, cp, rp, encode61, repeat_builders = gate.helpers, gate.cp, gate.rp, gate.encode61, gate.repeat_builders
Model, Report, gc, same_frame, vectors = gate.Model, gate.Report, gate.gc, gate.same_frame, gate.vectors
PM, MASTER, RELAY, IMAGE_LEN, CANCELS = gate.PM, gate.MASTER, gate.RELAY, gate.IMAGE_LEN, gate.CANCELS
Sequences, crob, READ_OBJECTS, READ_BODY = gate.Sequences, gate.crob, gate.READ_OBJECTS, gate.READ_BODY
SCOPE = ('E4 abandoned SELECT with timing enabled (ABANDON_T=1), contract response_ready_ack_d_no_j_v3; a separate '
         'labelled scenario, not part of the model gate')

TIMED_CONTRACT = 'response_ready_ack_d_no_j_v3'
TIMED_RESULTS = 'abandon_t1_results.json'
TIMED_STEPS = (
    ('SYN', ('SYN',), (), ('SYN',), 'immediate'),
    ('SYNACK', ('SYNACK',), ('SYNACK',), (), 'immediate'),
    ('final_ACK', ('final_ACK',), (), ('final_ACK',), 'immediate'),
    ('READ_request', ('READ_request',), (), ('READ_request',), 'immediate'),
    ('READ_ACK_and_response_61', ('READ_server_ACK', 'READ_response_61'),
     ('READ_server_ACK', 'READ_response_61'), (), 'response_ready_D'),
    ('SELECT_request', ('SELECT_request',), (), ('SELECT_request',), 'immediate'),
    ('SELECT_ACK_and_response_61', ('SELECT_server_ACK', 'SELECT_response_61'),
     ('SELECT_server_ACK', 'SELECT_response_61'), (), 'response_ready_D'),
    ('READ_after_SELECT_cancels_selection_forwarded', ('READ_after_SELECT',), (), ('READ_after_SELECT',),
     'immediate'),
    ('RST_after_abandoned_SELECT_forwarded', ('RST',), (), ('RST',), 'immediate'),
    ('new_SYN_after_abandoned_SELECT_admitted', ('new_SYN',), (), ('new_SYN',), 'immediate'),
)
# T actions that an ordinary response-ready exchange never takes: stale flushes, duplicate and old-epoch drops.
TIMED_FORBIDDEN = ('flush_ack_stale', 'flush_response_stale', 'drop_duplicate_response', 'drop_old_epoch',
                   'drop_tin')
TIMED_EVIDENCE = TIMED_FORBIDDEN + ('admit_request', 'hold_ack', 'admit_response', 'release_ack_commit',
                                    'release_response_counted')


def clock_view():
    """The running model's own log, the T-clock source of the response-ready proof (as model_repeat's timed phase)."""
    return load('_abandon_clock_view', HERE / 'model_log_view.py')


def timed_scenario(m, ports, report, work):
    """E4 rows judged by TIMED_STEPS. Every row is asserted: a drop, extra or reordered frame, a missing T-clock
    proof or stale N work state is a failure, never a characterization."""
    meta = report.record['meta']
    build = Path(os.environ.get('PORT_MAP', 'unbound/inputs.json')).parent.name
    meta.update(scenario='E4_abandoned_SELECT_timing_enabled', model_gate=False,
                expectations='results/models/%s_e4_abandon_t1/EXPECTATIONS.json' % build,
                timed_steps=[list(step) for step in TIMED_STEPS])
    if not report.add('timed_scenario_preconditions',
                      dict(timing_contract=TIMED_CONTRACT, read_cancels_selection=True, ABANDON_T='1'),
                      dict(timing_contract=meta.get('timing_contract'), read_cancels_selection=CANCELS,
                           ABANDON_T=os.environ.get('ABANDON_T')), characterization=False):
        return
    view = clock_view()
    log = view.log_path()
    if log is None:
        raise ValueError('the T=1 scenario needs the model T-clock log')
    gap = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']['gap']
    rows, cells, seqs = {step[0]: step for step in TIMED_STEPS}, [], Sequences()

    def immediate(name, sent, expected, master=True):
        """One exact frame at the far endpoint, nothing elsewhere (model_repeat's step); stimulus as at T=0."""
        step = rows[name]
        if step[4] != 'immediate' or bool(step[3]) != master or bool(step[2]) == master:
            raise ValueError('TIMED_STEPS disagrees with the %s stimulus' % name)
        expected = rp.preserve_options(sent, expected)
        rp.advance_timestamp()
        got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
        flat = [frame for frames in got.values() for frame in frames]
        delivered = got.get(RELAY.dev_port if master else MASTER.dev_port, [])
        good = len(flat) == 1 and len(delivered) == 1 and same_frame(delivered[0], expected, sent)
        cells.append(work())
        report.add(name, 'one exact frame', 'drop' if not flat else '%d frames' % len(flat), ok=good,
                   characterization=False, received=got, want=expected.hex(), work=cells[-1])
        return good

    def answered(kind, app, body, c, s, growth):
        """The relay's genuine ACK and whole response as one pair (model_repeat.response_ready_pair), then the
        T-clock proof (model_repeat.repeat_clock_proof). Frames are built in T=0's order and timestamp ticks."""
        name = '%s_ACK_and_response_61' % kind
        if rows[name][4] != 'response_ready_D' or len(rows[name][2]) != 2 or rows[name][3]:
            raise ValueError('TIMED_STEPS disagrees with the %s stimulus' % name)
        ack = vectors.packet(16, s, c, reverse=True)
        want_ack = rp.preserve_options(ack, vectors.packet(16, s + growth, c, reverse=True))
        rp.advance_timestamp()
        native = seqs.response(app, body, kind)
        image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
        response = vectors.packet(24, s, c, reverse=True, payload=native)
        want_response = rp.preserve_options(response, vectors.packet(24, s + growth, c, reverse=True, payload=image))
        rp.advance_timestamp()
        offset = view.size(log)
        got, exact = repeat_builders.response_ready_pair(m, ports, RELAY.dev_port, ack, response, want_ack,
                                                         want_response, same_frame, master_port=MASTER.dev_port)
        cells.append(work())
        report.add(name, 'one exact ACK then whole response', sum(map(len, got.values())), ok=exact,
                   characterization=False, received=got, want=[want_ack.hex(), want_response.hex()], work=cells[-1])
        records = [record for record in view.records_since(log, offset) if record.get('pipe') == 1]
        proof = repeat_builders.repeat_clock_proof(records, gap)
        actions = [action.rsplit('.', 1)[-1] for record in records for action in record.get('actions', [])]
        report.add('%s_T_clock_response_ready_ACK_then_D' % kind, dict(passed=True, forbidden=[]),
                   dict(passed=proof['passed'], forbidden=sorted(set(actions) & set(TIMED_FORBIDDEN))),
                   characterization=False, response_ready_clock_proof=proof, t_record_count=len(records),
                   t_records=[dict(port=record.get('port'), t_units=record.get('t_units'), actions=record['actions'])
                              for record in records if set(TIMED_EVIDENCE) & {a.rsplit('.', 1)[-1]
                                                                              for a in record.get('actions', [])}])
        return native

    c, s, growth = 100, 900, 0
    immediate('SYN', vectors.packet(2, c, mss=1460), vectors.packet(2, c, mss=1460))
    immediate('SYNACK', vectors.packet(18, s, c + 1, reverse=True, mss=1460),
              vectors.packet(18, s, c + 1, reverse=True, mss=1460), master=False)
    c, s = c + 1, s + 1
    immediate('final_ACK', vectors.packet(16, c, s), vectors.packet(16, c, s))
    for kind, fc, objects, body in (('READ', 1, READ_OBJECTS, READ_BODY),
                                    ('SELECT', 3, crob(100), bytes(2) + crob(100))):
        request, app = seqs.request(fc, objects)
        seqs.next_app()
        immediate('%s_request' % kind, vectors.packet(24, c, s + growth, payload=request),
                  vectors.packet(24, c, s, payload=request))
        c += len(request)
        native = answered(kind, app, body, c, s, growth)
        s += len(native)
        growth += rp.growth(native, IMAGE_LEN)
    meta['work_after_select'] = cells[-1]
    request, app = seqs.request(1, READ_OBJECTS)
    seqs.next_app()
    forwarded = immediate('READ_after_SELECT_cancels_selection_forwarded', vectors.packet(24, c, s + growth,
                          payload=request), vectors.packet(24, c, s, payload=request))
    meta['read_after_select'] = [{'attempt': 0, 'waited_s': 0, 'forwarded_exact': forwarded, 'work': cells[-1]}]
    c += len(request)
    rst = immediate('RST_after_abandoned_SELECT_forwarded', vectors.packet(20, c, s + growth), vectors.packet(20, c, s))
    syn = immediate('new_SYN_after_abandoned_SELECT_admitted', vectors.packet(2, 5000, mss=1460),
                    vectors.packet(2, 5000, mss=1460))
    meta['recovery'] = {'rst_forwarded_exact': rst, 'new_syn_forwarded_exact': syn, 'work': cells[-1]}
    report.add('N_work_free_after_every_step', [[4]] * len(cells), [cell.get('phase') for cell in cells],
               characterization=False)


def main():
    """The gate driver's model setup (model_abandon.main, unchanged there) with T enabled, then the E4 rows."""
    timed = int(os.environ.get('ABANDON_T', '0'))
    report = Report(os.environ['PROG'], physical=False, scope=SCOPE,
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    gate_driver_sha256=hashlib.sha256(GATE_DRIVER.read_bytes()).hexdigest())
    rp.report_endpoint(report)
    try:
        m = Model(ports=[], enable=False)
        ports = sorted({MASTER.dev_port, RELAY.dev_port})
        m.enable_ports(ports + helpers.FRONT_LOOPS)
        m.enable_ports([p for p in helpers.LOOP_PORTS if p not in helpers.FRONT_LOOPS])
        reflectors = [helpers.Reflector(p) for p in helpers.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        rows = cp.n_ports_rows(MASTER.dev_port, RELAY.dev_port, MASTER.ip_int, RELAY.ip_int,
                               n_ack_return=PM.n_ack_return)
        rows += cp.n_connection_rows(RELAY, MASTER, n_ack_return=PM.n_ack_return)
        rows += cp.n_read_rows(RELAY, MASTER)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), vectors.decoy_config()))
        for source, dest in ((MASTER, RELAY), (RELAY, MASTER)):
            key = {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                   'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, RELAY, MASTER, n_ack_return=PM.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        if rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(RELAY, MASTER, True):
                m.add(table, dict(key), action, dict(data), priority)
        profile = {}
        if os.environ.get('PORT_MAP'):
            inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
            profile = inputs.get('supported_profile') or {}
            if profile.get('timing_contract') is not None:
                profiles = load('_abandon_t1_model_profile', HERE / 'model_profile.py')
                profile = profiles.resolve(inputs, Path(os.environ['PORT_MAP']).with_name('response_only.p4'))
        report.record['meta']['timing_contract'] = profile.get('timing_contract')
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', gate.timing_params_for_profile(profile, timed))
        mirror = m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
                         [mirror.make_key([gc.KeyTuple('$sid', 7)])],
                         [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                                            gc.DataTuple('$ucast_egress_port', helpers.PKTGEN_RETURN),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def work():
            cell = m.register_read('p0.n_Ingress.work.work', 0, pipe=0)
            return {k.rsplit('.', 1)[-1]: v for k, v in cell.items()}

        timed_scenario(m, ports, report, work)
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False, characterization=False)
    ok = report.finish(Path(os.environ['OUT']) / TIMED_RESULTS)
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
