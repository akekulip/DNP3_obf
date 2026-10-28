"""Model action observations used by the functional regression assertions.

The explicit action map is verified against the selected source's action bodies.
One T observation is assigned per ingress pass (last mapped action wins); N
observations count executed actions; E observations use the last classified action
per egress pass. These describe simulator execution, not physical BFRT registers.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
OBSERVATIONS = HERE / 'action_observations.json'
E_COUNTER = 'p0.r_Egress.outcome'
REGISTERS = ('p1.t_Ingress.outcomes', 'p0.n_Ingress.count_first', 'p0.n_Ingress.count_busy')
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


def verified_observations(source=None):
    source = Path(source) if source is not None else Path(os.environ['PORT_MAP']).with_name('response_only.p4')
    text = source.read_text()
    declared = json.loads(OBSERVATIONS.read_text())
    if declared.get('source_sha256') != hashlib.sha256(source.read_bytes()).hexdigest():
        raise ValueError('model observation semantics need review for a different canonical source')
    actions = {}
    for role, end in (('n_Ingress','n_IgDeparser'), ('r_Egress','r_EgDeparser'), ('t_Ingress','t_IngressDeparser')):
        region = text[text.index('control ' + role + '('):text.index('control ' + end + '(')]
        actions.update(_actions(region, role))
    for name, expected in declared['action_body_sha256'].items():
        if name not in actions or hashlib.sha256(actions[name].encode()).hexdigest() != expected:
            raise ValueError('model observation semantics need review for changed P4 action: ' + name)
    return declared


def action_map(source=None, timing_contract=None):
    return {name: tuple(value) for name, value in verified_observations(source)['actions'].items()}


def e_result_map(source=None):
    return verified_observations(source)['egress_results']


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


class _Key:
    def __init__(self, tuples):
        self.index = {t.name: t.value for t in tuples}['$COUNTER_INDEX']


class _Data:
    def __init__(self, packets):
        self.packets = packets

    def to_dict(self):
        return {'$COUNTER_SPEC_PKTS': self.packets, '$COUNTER_SPEC_BYTES': 0}


class CounterTable:
    """Observation adapter for assertions written against E's old outcome interface."""
    def operations_execute(self, target, operation):
        pass

    def make_key(self, tuples):
        return _Key(tuples)

    def entry_get(self, target, keys, flags=None):
        for key in keys:
            log = model_log()
            wait_idle(log, quiet=0.01, timeout=0.05)
            yield _Data(counts(log).get((E_COUNTER, key.index), 0)), key
