"""Differential engine: frozen pre-restructure oracle vs the regenerated native_binding.p4.

Both sources are executed by the whole-program harness interpreter (ExtSource, an AST evaluator
that handles parametrised actions, ternary/range keys, int<32> and the real ExpectedWorkRecord
sub-control), not by the fragment regex evaluator. Each case sets the post-parser state directly
(the parser, `ports`, `network` and `connection` are covered by the harness suites), runs the
whole Ingress apply body of each source from the same state, and compares everything observable
outside the pipeline: private-header contents and validity, drop control, egress port, bypass,
the emit-loop flag and every register (owner, epoch, client, server, counter, WorkRecord and all
eight binding banks).

The CRC/profile block is replaced identically in both sources: the flags it would set are
inputs. In the oracle the old `data_guard` still runs on them; in the new source `guard` reads
them as keys.
"""
import copy
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
ARCH = HERE.parents[2]
sys.path.insert(0, str(ARCH / 'integration/core/harness'))
sys.path.insert(0, str(ARCH / 'protocol'))
from interp_ext import ExtSource  # noqa: E402
from source_eval import block  # noqa: E402

ORACLE = HERE / 'tests/oracle_35bf9aa3_native_binding.p4'
NEW = HERE / 'native_binding.p4'
HEAD = 'if(m.packet_kind==8w5||m.packet_kind==8w6||m.packet_kind==8w7){'
PRIVATE = ('envelope', 'work_generation', 'expected_cell', 'event')
OUT_PORT = 7
BANKS = ('pair_real_links_real_tcp_src', 'pair_real_tcp_dst_real_tcp_ports', 'pair_real_object_real_on',
         'pair_real_off_native_start', 'pair_native_end_server_start',
         'pair_frozen_decoy_object_frozen_decoy_on')
PAIR_FIELDS = (('compare_real_links', 'compare_real_tcp_src'), ('compare_real_tcp_dst', 'compare_real_tcp_ports'),
               ('compare_real_object', 'compare_real_on'), ('compare_real_off', 'compare_native_start'),
               ('compare_native_end', 'compare_server_start'),
               ('compare_frozen_decoy_object', 'compare_frozen_decoy_on'))


def stubbed(text, oracle):
    """Cut the table/CRC front end that the fragment inputs replace, identically in both."""
    for pattern in (r'ports\.apply\(\);network\.apply\(\);', r'(?<![\w.])connection\.apply\(\);'):
        text, count = re.subn(pattern, '', text)
        assert count == 1, pattern
    start = text.index(HEAD)
    end = start + len(HEAD) + len(block(text, HEAD[:-1] + '{')) + 1
    tail = 'else{m.data_valid=8w1;}'
    if oracle:
        assert text[end:].startswith(tail)
        stop = text.index(tail, end) + len(tail)
        replacement = HEAD + 'data_guard.apply();}' + tail
    else:
        stop, replacement = end, ''
        read = 'else if(m.packet_kind==8w9||m.packet_kind==8w11){'
        if text[end:].startswith(read):          # the READ validation block: its flags are inputs here too
            stop = end + len(read) + len(block(text[end:], read[:-1] + '{')) + 1
    return text[:start] + replacement + text[stop:]


class Tracing(ExtSource):
    """ExtSource that records which const entry (or the default) each table application took."""
    def apply_table(self, name):
        table = self.frame.ctrl.tables[name]
        keys = [(self.ev(node)[0], kind) for node, kind in table['keys']]
        slot = 'default'
        for position, (terms, _action, _args) in enumerate(table['entries']):
            if all(self.match(term, key) for term, (key, _) in zip(terms, keys)):
                slot = position
                break
        self.hits.add((name, slot))
        return ExtSource.apply_table(self, name)


class Engine:
    def __init__(self, new_text=None):
        self.old = Tracing(stubbed(ORACLE.read_text(), True), HERE)
        self.new = Tracing(stubbed(new_text or NEW.read_text(), False), HERE)
        self.old.hits, self.new.hits = set(), set()
        self.coverage = {'old': set(), 'new': set()}

    @staticmethod
    def load(src, case):
        src.begin_pass(case['ingress_port'])
        src.reset_registers()
        src.valid = dict(case['valid'])
        src.env.update(case['env'])
        for name, value in case['cells'].items():
            src.cells[name][0] = copy.deepcopy(value)

    def prepare(self, case):
        """Fill the binding banks so a stage-0 compare matches (or misses in one component)."""
        variant = case.get('bank')
        if variant is None:
            return
        src = self.old
        self.load(src, case)
        pk = case['env']['m.packet_kind']
        src.action('calculate_native_end')
        src.action({6: 'compare_response_inputs', 5: 'compare_select_inputs', 7: 'compare_operate_inputs'}.get(
            pk, 'compare_operate_inputs'))
        get = lambda n: src.env.get('m.' + n, 0)  # noqa: E731
        cells = case['cells']
        for bank, (a, b) in zip(BANKS, PAIR_FIELDS):
            cells[('', bank)] = {'first': get(a), 'second': get(b)}
        app = get('compare_application')
        cells[('', 'application')] = (app if pk == 6 else (app - 1) & 0xffffffff)
        cells[('', 'frozen_decoy_off')] = get('compare_frozen_decoy_off')
        if variant == 'match15' and pk == 7:
            cells[('', 'application')] = (app + 15) & 0xffffffff
        if isinstance(variant, int):                     # one component off
            names = list(BANKS) + ['application', 'frozen_decoy_off']
            target = names[variant % len(names)]
            value = cells[('', target)]
            if isinstance(value, dict):
                value['first'] = (value['first'] + 1) & 0xffffffff
            else:
                cells[('', target)] = (value + 3) & 0xffffffff

    @staticmethod
    def observe(src):
        keys = {k: v for k, v in src.env.items() if k.startswith(('hdr.',)) and src.valid.get(k.split('.')[1], False)}
        # unlisted egress state defaults to zero
        keys['md.drop_ctl'] = src.env.get('md.drop_ctl', 0)
        keys['tm.ucast_egress_port'] = src.env.get('tm.ucast_egress_port', 0)
        keys['tm.bypass_egress'] = src.env.get('tm.bypass_egress', 0)
        keys['m.emit_loop'] = src.env.get('m.emit_loop', 0)
        valid = {k: bool(v) for k, v in src.valid.items() if not (k == 't0' and not v)}   # t0 exists only in the new source
        cells = {k: copy.deepcopy(v) for k, v in src.cells.items()}
        return {'fields': keys, 'valid': valid, 'cells': cells}

    def run(self, src, case):
        self.load(src, case)
        src.apply_control('Ingress')
        return self.observe(src)

    def compare(self, case):
        self.prepare(case)
        self.old.hits, self.new.hits = set(), set()
        a, b = self.run(self.old, case), self.run(self.new, case)
        self.old_ran_body = any(t == 'epoch_t' for t, _ in self.old.hits)
        # The READ application register exists only in the new source. Non-READ traffic must leave it at 0.
        read_app = b['cells'].pop(('', 'read_app'), [0])
        if read_app != [0] and not is_read_candidate(case):
            b['cells'][('', 'read_app')] = read_app
        self.last_new = b
        self.coverage['old'] |= self.old.hits
        self.coverage['new'] |= self.new.hits
        if a == b:
            return None, a
        diff = []
        for part in ('fields', 'valid', 'cells'):
            for key in sorted(set(a[part]) | set(b[part]), key=str):
                if a[part].get(key) != b[part].get(key):
                    diff.append((part, key, a[part].get(key), b[part].get(key)))
        return diff, a

    def drive_epoch(self, case):
        """m.epoch_diff after the pass, for the one intentional (sign) difference."""
        out = []
        for src in (self.old, self.new):
            self.load(src, case)
            src.apply_control('Ingress')
            out.append(src.env.get('m.epoch_diff', 0))
        return out


# ---- case generation ------------------------------------------------------------------------
FLAG_SETS = ((1, 1, 0, 0, 0, 0), (0, 1, 0, 0, 0, 0), (1, 0, 0, 0, 0, 0), (1, 1, 1, 0, 0, 0),
             (1, 1, 0, 1, 0, 0), (1, 1, 0, 0, 1, 0), (1, 1, 0, 0, 0, 1), (0, 0, 1, 1, 1, 1))
PACKET_KINDS = tuple(range(9)) + (255,)
KINDS = tuple(range(9)) + (255,)
OWNER_PHASES = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
INTERESTING = (0, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13)
CLIENTS, SERVERS, ACKS = (100, 880, 900, 0), (100, 900, 0), (900, 0)
TCP_FLAGS = (2, 18, 16, 17, 20, 4, 24)


def case_for(index, stage, pk, kind, direction, flags, shape, work, counter, **over):
    rnd = random.Random(index)
    owner_phase = rnd.choice(INTERESTING if rnd.random() < .7 else OWNER_PHASES)
    owner = owner_phase << 16 | (1 if rnd.random() < .9 else 2)
    expected = owner if rnd.random() < .6 else (rnd.choice(INTERESTING) << 16 | (1 if rnd.random() < .9 else 2))
    owner = over.get('owner', owner)
    expected = over.get('expected', expected)
    ack = over.get('ack', rnd.choice(ACKS))
    env = {'m.stage': stage, 'm.kind': kind if stage else 0, 'm.packet_kind': pk, 'm.direction': direction,
           'm.shape_valid': shape, 'm.parsed': 1, 'm.network_valid': int(rnd.random() > .03),
           'm.port_valid': int(rnd.random() > .03), 'm.response': int(pk == 6), 'm.output_port': OUT_PORT,
           'tm.ucast_egress_port': OUT_PORT, 'tm.bypass_egress': 1,
           'm.enabled': flags[0], 'm.profile': flags[1], 'm.badh': flags[2], 'm.badb': flags[3],
           'm.bad1': flags[4], 'm.badt': flags[5],
           'm.decoy_index': 1, 'm.decoy_code': 3, 'm.decoy_repeat': 1, 'm.decoy_on': 100, 'm.decoy_off': 200,
           'hdr.tcp.seq': 100, 'hdr.tcp.ack': ack, 'hdr.tcp.flags': over.get('tcp_flags', rnd.choice(TCP_FLAGS)),
           'hdr.tcp.sport': 30001, 'hdr.tcp.dport': 20000, 'hdr.ip.src': 0x0a000001, 'hdr.ip.dst': 0x0a000002,
           'hdr.dl.src': 1, 'hdr.dl.dst': 2, 'hdr.first.w0': 0x03c10000, 'hdr.first.w1': 0x01280100,
           'hdr.first.w2': 0x010203, 'hdr.first.w3': 0x64, 'hdr.second.w0': 0x7, 'hdr.second.w1': 0x8,
           'hdr.second.w3': 0x9, 'hdr.tail.off': 0x55, 'hdr.response_tail.w0': 0x11, 'hdr.response_tail.w1': 0x22}
    valid = {h: True for h in ('eth', 'ip', 'tcp', 'dl', 'first', 'second', 'tail', 'response_tail')}
    for h in PRIVATE:
        valid[h] = bool(stage)
    if stage:
        env.update({'hdr.event.event': stage << 8 | kind, 'hdr.event.reserved': 0 if rnd.random() > .05 else 1,
                    'hdr.work_generation.generation': 29, 'hdr.expected_cell.expected_cell': expected,
                    'hdr.envelope.epoch': over.get('epoch', rnd.choice((17, 17, 18)))})
        phase, matches = work
        cells_work = {'generation': 29 if matches else 7, 'phase': phase}
    else:
        cells_work = {'generation': 5, 'phase': work[0]}
    cells = {('', 'owner'): owner, ('', 'epoch'): 17, ('', 'client'): over.get('client', rnd.choice(CLIENTS)),
             ('', 'server'): over.get('server', rnd.choice(SERVERS)), ('', 'counter'): counter, ('work', 'work'): cells_work}
    case = {'ingress_port': 68 if stage else 1, 'env': env, 'valid': valid, 'cells': cells,
            'bank': None, 'index': index,
            'label': dict(stage=stage, pk=pk, kind=kind, direction=direction, flags=flags, shape=shape,
                          work=work, counter=counter)}
    if pk in (6, 7) and rnd.random() < .5:
        case['bank'] = rnd.choice(('match', 'match', 'match15', 0, 1, 2, 3, 4, 5, 6, 7))
    if 'bank' in over:
        case['bank'] = over['bank']
    return case


def routing_grid(samples=3):
    index = 0
    for sample in range(samples):
        for stage in range(4):
            for pk in PACKET_KINDS:
                for kind in (KINDS if stage else (0,)):
                    for direction in range(3):
                        for flags in FLAG_SETS:
                            for shape in (0, 1):
                                if stage:
                                    works = [(p, m) for p in (1, 2, 3, 4) for m in (1, 0)]
                                    counters = (0,)
                                else:
                                    works = [(p,) for p in (1, 2, 3, 4)]
                                    counters = (0, 0xffffffff)
                                for work in works:
                                    for counter in counters:
                                        index += 1
                                        yield index, (stage, pk, kind, direction, flags, shape, work, counter)


VALID_STAGE0 = ((1, 1), (2, 2), (3, 1), (4, 1), (4, 2), (5, 1), (6, 2), (7, 1))
RETURN_PAIRS = tuple((k, k) for k in range(1, 8)) + ((8, 1), (8, 2), (8, 3))
GOOD = FLAG_SETS[0]
OWNERS = (0,) + tuple(p << 16 | c for p in OWNER_PHASES for c in (1, 2))


def deep_stage0():
    """Valid stage-0 packets across owner phase, sequence state, TCP flags and bank state."""
    index = 10_000_000
    for pk, direction in VALID_STAGE0:
        banks = ('match', 'match15', None, 0, 1, 2, 3, 4, 5, 6, 7) if pk in (6, 7) else (None,)
        flags_set = TCP_FLAGS if pk < 5 else (16,)
        for phase in (1, 2, 3, 4):
            for owner in OWNERS:
                for client in CLIENTS:
                    for server in SERVERS:
                        for ack in ACKS:
                            for tcp_flags in flags_set:
                                for bank in banks:
                                    index += 1
                                    yield index, (0, pk, 0, direction, GOOD, 1, (phase,), 0), dict(
                                        owner=owner, client=client, server=server, ack=ack,
                                        tcp_flags=tcp_flags, bank=bank)


def deep_return():
    """Valid return passes across owner cell, expected cell, epoch agreement and WorkRecord state."""
    index = 20_000_000
    for stage in (1, 2, 3):
        for kind, pk in RETURN_PAIRS:
            for phase in (1, 2, 3, 4):
                for matches in (1, 0):
                    for owner in OWNERS:
                        for expected in (owner, owner + 0x10000, owner ^ 3, 0):
                            for epoch in (17, 18):
                                index += 1
                                banks = ('match', None) if kind in (5, 6, 7) else (None,)
                                for bank in banks:
                                    yield index, (stage, pk, kind, 1, GOOD, 1, (phase, matches), 0), dict(
                                        owner=owner, expected=expected, epoch=epoch, bank=bank)


def is_read_candidate(case):
    """Stage-0 server pure ACK (packet kind 3, direction 2): READ_ACK kind 10, an intentional difference."""
    label = case['label']
    return label['stage'] == 0 and label['pk'] == 3 and label['direction'] == 2


_engine = None


def run_chunk(args):
    """Worker entry: (list of grid tuples) -> (n, mismatches, outcome-class histogram)."""
    global _engine
    _engine = _engine or Engine()
    n, bad, hist = 0, [], {}
    for item in args:
        index, spec, over = (item + ({},))[:3] if len(item) == 2 else item
        case = case_for(index, *spec, **over)
        if is_read_candidate(case):
            _engine.compare(case)          # must still execute cleanly; outcome is a READ intentional difference
            hist[('READ-INTENTIONAL',)] = hist.get(('READ-INTENTIONAL',), 0) + 1
            n += 1
            continue
        diff, obs = _engine.compare(case)
        n += 1
        if case['label']['stage'] >= 1 and not _engine.old_ran_body:
            # H2: the oracle did nothing on a return pass the guard refused and let the private
            # envelope out of a front-panel port. The restructured source aborts it instead. Absolute
            # property checked here: such a pass is denied, or recirculated to the return port, or its
            # private headers are gone; never forwarded with an envelope.
            new = _engine.last_new
            leak = (new['valid'].get('event') and new['fields']['md.drop_ctl'] == 0
                    and new['fields']['tm.ucast_egress_port'] != 68)
            hist[('H2-GUARD-MISS',)] = hist.get(('H2-GUARD-MISS',), 0) + 1
            if leak:
                bad.append((case['label'], case['bank'], 'private envelope leaves on a front-panel port'))
            continue
        ev = obs['fields'].get('hdr.event.event') if obs['valid'].get('event') else None
        tag = ('ev=%s' % (hex(ev) if ev is not None else 'none'), 'drop=%d' % obs['fields']['md.drop_ctl'],
               'port=%d' % obs['fields']['tm.ucast_egress_port'])
        hist[tag] = hist.get(tag, 0) + 1
        if diff:
            bad.append((case['label'], case['bank'], diff))
    return n, bad, hist, _engine.coverage
