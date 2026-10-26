"""Switch counters a build no longer carries, recounted from the model's own log (c68, Philip 2026-10-25).

c68 removed write-only measurement state (T outcomes, N count_first/count_busy/count_term). The model drivers still
assert on those counts, so for a build without them Model.register_read answers from the model log: every
"Execute Action:" line is one executed action, and the action -> cell map is read from c67's source, the last
source that still carried the counters. The model log is a simulator artifact; this costs the switch nothing.

Semantics follow c67:
  T outcomes        one cell per T pass, the LAST counting action of that pass wins (md.outcome_code), pipe 1.
  N count_* cells   one bump per executed counting action, pipe 0.
  E outcome Counter one packet per pipe-0 egress pass, indexed by the pass's last m.result write (count_t ran
                    unconditionally at the end of r_Egress; m.result starts at 0). A write is an executed r_Egress
                    action whose c67 body sets m.result to a constant (c68's compiler drops writes nothing reads
                    any more, e.g. rev_translate's), or a logged "Destination:" / "m.result[7:0] = 0x.." write
                    (out_drop(why) takes its value from action data).
Functional model execution only, never hardware.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
C67 = HERE / 'response_only_rearm/stage_experiments/ctl_timing_01/evidence/m12p_c67_sdk9132/response_only.p4'
C67_SHA = 'e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1'
E_COUNTER = 'p0.r_Egress.outcome'
REGISTERS = ('p1.t_Ingress.outcomes', 'p0.n_Ingress.count_first', 'p0.n_Ingress.count_busy',
             'p0.n_Ingress.count_term')
# c68 split drop_timer_stale(index) into two data-free actions; their c67 cells were the index values.
RENAMED = {'t_Ingress.drop_timer_stale_operate': 23, 't_Ingress.drop_timer_stale_read': 24}
EGRESS = re.compile(r':-:(0x[0-9a-fA-F]+):<\d+,0,\d+>:(.*)$')   # a pipe-0 egress line: its pass id and text
RESULT = re.compile(r'^\s*m\.result\[7:0\] = 0x([0-9a-fA-F]+)')
# a hit logs "Execute Action:", a miss "Execute Default Action:"
LINE = re.compile(r':(0x[0-9a-fA-F]+|-):(0x[0-9a-fA-F]+|-):<(\d+),(\d+),(\d+)>:Execute (?:Default )?Action: (\S+)')


def _actions(text, control):
    """{control.action: body} for every action declared in one control's text."""
    out = {}
    for match in re.finditer(r'\baction\s+(\w+)\s*\([^)]*\)\s*\{', text):
        depth, pos = 1, match.end()
        while depth:
            depth += {'{': 1, '}': -1}.get(text[pos], 0)
            pos += 1
        out['%s.%s' % (control, match.group(1))] = text[match.end():pos - 1]
    return out


def action_map(source=None, timing_contract=None):
    """{qualified action: (register, cell)} from c67's counting sites."""
    text = Path(source or C67).read_text()
    if source is None and hashlib.sha256(text.encode()).hexdigest() != C67_SHA:
        raise ValueError('telemetry map source is not the pinned c67 source')
    consts = {m.group(1): int(m.group(2)) for m in re.finditer(r'const bit<32> (t_OUT_\w+) = (\d+);', text)}
    n_text = text[text.index('control n_Ingress('):text.index('control n_IgDeparser(')]
    t_text = text[text.index('control t_Ingress('):]
    mapping = {}
    for name, body in _actions(t_text, 't_Ingress').items():
        found = re.findall(r'\bcount\((t_OUT_\w+)\)', body)
        if found:
            mapping[name] = ('p1.t_Ingress.outcomes', consts[found[-1]])
    for name, cell in RENAMED.items():
        mapping[name] = ('p1.t_Ingress.outcomes', cell)
    for name, body in _actions(n_text, 'n_Ingress').items():
        for register, cell in re.findall(r'\b(count_first|count_busy|count_term)_bump\.execute\(4w(\d+)\)', body):
            mapping[name] = ('p0.n_Ingress.' + register, int(cell))
    if timing_contract == 'response_ready_ack_d_no_j_v3':
        removed = {'rewait_operate','flush_operate_stale','release_operate_counted',
                   'drop_operate_dup','drop_timer_stale_operate'}
        mapping = {name: value for name, value in mapping.items() if name.split('.')[-1] not in removed}
    if not mapping:
        raise ValueError('no counting actions found')
    return mapping


def e_result_map(source=None):
    """{r_Egress.action: m.result constant} from c67's E actions."""
    text = Path(source or C67).read_text()
    consts = {m.group(1): int(m.group(2)) for m in re.finditer(r'const bit<8> (r_OUT_\w+) = (\d+);', text)}
    e_text = text[text.index('control r_Egress('):text.index('control r_EgDeparser(')]
    out = {}
    for name, body in _actions(e_text, 'r_Egress').items():
        found = re.findall(r'm\.result\s*=\s*(r_OUT_\w+)\s*;', body)
        if found:
            out[name] = consts[found[-1]]
    return out


_CACHE = {}


def counts(log_path, mapping=None):
    """{(register, cell): count} for the whole log, read incrementally (complete lines only)."""
    key = str(log_path)
    state = _CACHE.get(key)
    if state is None or mapping is not None:
        port_map = os.environ.get('PORT_MAP')
        contract = ((json.loads(Path(port_map).read_text()).get('supported_profile') or {}).get('timing_contract')
                    if port_map else None)
        state = dict(offset=0, totals={}, last_t={}, last_e={}, destination=set(), mapping=mapping or action_map(timing_contract=contract),
                     e_results=e_result_map())
        if mapping is None:
            _CACHE[key] = state
    with open(log_path, 'rb') as log:
        log.seek(state['offset'])
        data = log.read()
    end = data.rfind(b'\n') + 1
    state['offset'] += end
    totals = state['totals']
    for line in data[:end].decode(errors='replace').splitlines():
        egress = EGRESS.search(line)
        if egress:
            passed, text = egress.group(1), egress.group(2)
            previous = state['last_e'].get(passed)
            code = previous if previous is not None else 0
            if passed in state['destination']:
                state['destination'].discard(passed)
                written = RESULT.match(text)
                if written:
                    code = int(written.group(1), 16)
            elif text.strip() == 'Destination:':
                state['destination'].add(passed)
            else:
                executed = re.match(r'Execute (?:Default )?Action: (r_Egress\.\w+)', text)
                if executed and executed.group(1) in state['e_results']:
                    code = state['e_results'][executed.group(1)]
            if code != previous:
                if previous is not None:
                    totals[(E_COUNTER, previous)] -= 1
                state['last_e'][passed] = code
                totals[(E_COUNTER, code)] = totals.get((E_COUNTER, code), 0) + 1
            continue
        match = LINE.search(line)
        if not match or match.group(6) not in state['mapping']:
            continue
        register, cell = state['mapping'][match.group(6)]
        if register == 'p1.t_Ingress.outcomes':
            passed = (match.group(1), match.group(4))                    # one cell per T pass, last wins
            previous = state['last_t'].get(passed)
            if previous is not None:
                totals[(register, previous)] -= 1
            state['last_t'][passed] = cell
        totals[(register, cell)] = totals.get((register, cell), 0) + 1
    return dict(state['totals'])


def build_has_telemetry():
    """False only when the build's supported profile declares switch_telemetry false."""
    port_map = os.environ.get('PORT_MAP')
    if not port_map:
        return True
    profile = json.loads(Path(port_map).read_text()).get('supported_profile') or {}
    return profile.get('switch_telemetry', True) is not False


def model_log():
    logs = sorted(Path(os.environ.get('OUT', '.')).glob('model_*.log'))
    if len(logs) != 1:
        raise ValueError('expected one model log in OUT, found %d' % len(logs))
    return logs[0]


def wait_idle(path, quiet=0.05, timeout=2.0):
    """Let the model finish logging its pending passes (the log stops growing for `quiet` s)."""
    last, since, start = path.stat().st_size, time.monotonic(), time.monotonic()
    while time.monotonic() - start < timeout:
        time.sleep(0.005)
        size = path.stat().st_size
        if size != last:
            last, since = size, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return


def register_value(name, index):
    """The register_read() answer shape for a removed counter: {field: [value]}. As fast as the register read it
    replaces: drivers poll counters inside a finite retry budget (model_packets half_closed_rst), so this waits only
    for the model's last log write to land (10 ms quiet, 50 ms at most), never for a busy model to fall idle."""
    log = model_log()
    wait_idle(log, quiet=0.01, timeout=0.05)
    value = counts(log).get((name, index), 0)
    return {name.split('.', 1)[1] + '.f1': [value]}


def record_check(name, index, real):
    """Verification on a build that still has the counters (c67): append the real value beside the log-derived one
    to $OUT/telemetry_shim_check.jsonl. The register is read after the pass that bumped it, so the log is idle."""
    values = next(iter(real.values()))
    pipe = 1 if name.startswith('p1.') else 0
    actual = values[pipe] if isinstance(values, list) and len(values) > 1 else (
        values[0] if isinstance(values, list) else values)
    log = model_log()
    wait_idle(log)
    derived = counts(log).get((name, index), 0)
    with open(Path(os.environ.get('OUT', '.')) / 'telemetry_shim_check.jsonl', 'a') as out:
        out.write(json.dumps(dict(register=name, cell=index, register_value=actual, log_value=derived,
                                  match=actual == derived)) + '\n')


class _Key:
    def __init__(self, tuples):
        self.index = {t.name: t.value for t in tuples}['$COUNTER_INDEX']


class _Data:
    def __init__(self, packets):
        self.packets = packets

    def to_dict(self):
        return {'$COUNTER_SPEC_PKTS': self.packets, '$COUNTER_SPEC_BYTES': 0}


class CounterTable:
    """Stands in for the BF Runtime table of E's removed outcome Counter: operations_execute, make_key and entry_get
    with one $COUNTER_INDEX key, as the model drivers call them. With `real` (verification on c67) it answers from the
    real counter and records the log-derived value beside it."""
    def __init__(self, real=None):
        self.real = real

    def operations_execute(self, target, operation):
        if self.real is not None:
            self.real.operations_execute(target, operation)

    def make_key(self, tuples):
        return (_Key(tuples), self.real.make_key(tuples) if self.real is not None else None)

    def entry_get(self, target, keys, flags=None):
        for key, real_key in keys:
            log = model_log()
            wait_idle(log, quiet=0.01, timeout=0.05)
            derived = counts(log).get((E_COUNTER, key.index), 0)
            if self.real is None:
                yield _Data(derived), key
                continue
            for data, got in self.real.entry_get(target, [real_key], flags):
                value = data.to_dict()['$COUNTER_SPEC_PKTS']
                actual = sum(value) if isinstance(value, list) else value
                with open(Path(os.environ.get('OUT', '.')) / 'telemetry_shim_check.jsonl', 'a') as out:
                    out.write(json.dumps(dict(register=E_COUNTER, cell=key.index, register_value=actual,
                                              log_value=derived, match=actual == derived)) + '\n')
                yield data, got
