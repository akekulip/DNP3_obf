"""Whole-program source interpreter for native_binding.p4 (SOURCE LEVEL, not the Tofino target).

Subclasses the existing restricted interpreters (protocol/egress/source_packets.Source ->
tests/source_control.Source -> protocol/source_eval.Source). The frozen ones evaluate by regex and
string substitution and cannot express ig.* reads, range/ternary keys, typed bit widths, slice
assignment, RegisterAction pairs or a sub-control call. This subclass overrides expr/run/table/
action/register/packet_parser/apply_control/deparse with a parsed-AST evaluator and keeps the
inherited header/meta width tables, field-order renderer and block() helper.
"""
import re
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ARCH / 'protocol/egress'), str(ARCH / 'tests'), str(ARCH / 'protocol')]
from source_packets import Source as PacketSource, folded, checksum  # noqa: E402
from source_eval import block  # noqa: E402
import p4syntax  # noqa: E402
from tna_dialect import normalize  # noqa: E402
from p4syntax import Parser, match_brace, parse_expr, parse_statements, split_top  # noqa: E402

INTRINSIC = {'ig.ingress_port': 9, 'ig.global_tstamp': 48, 'md.drop_ctl': 3, 'tm.ucast_egress_port': 9, 'tm.bypass_egress': 1}
PARAM = re.compile(r'(?:(in|inout|out)\s+)?(?:bit<(\d+)>|(PortId_t)|(bool)|(\w+))\s+(\w+)$')


class ParserError(Exception):
    pass


class Frame:
    def __init__(self, ctrl, path):
        self.ctrl, self.path, self.loc, self.locw = ctrl, path, {}, {}


class Control:
    def __init__(self, text, name):
        self.name = name
        head = text.index('control ' + name + '(')
        opening = text.index('(', head)
        closing = p4syntax.match_paren(text, opening)
        self.params = []
        for part in split_top(text[opening + 1:closing - 1]):
            kind, bits, port, boolean, other, pname = PARAM.match(part).groups()
            self.params.append((kind or 'in', int(bits) if bits else 9 if port else 1 if boolean else None, pname))
        body = text[text.index('{', closing) + 1:match_brace(text, text.index('{', closing)) - 1]
        self.registers, self.ras, self.actions, self.tables = {}, {}, {}, {}
        self.insts, self.hashes, self.polys, self.apply_body = {}, {}, {}, []
        self.scan(body)

    def scan(self, body):
        at = 0
        while at < len(body):
            if body[at].isspace():
                at += 1
                continue
            word = re.match(r'(action|table|apply)\b', body[at:])
            if word:
                opening = body.index('{', at)
                end = match_brace(body, opening)
                head, inner = body[at:opening].strip(), body[opening + 1:end - 1]
                if word[1] == 'action':
                    self.add_action(head, inner)
                elif word[1] == 'table':
                    self.add_table(head.split()[1], inner)
                else:
                    self.apply_body = parse_statements(inner)
                at = end
                continue
            depth, end = 0, at
            while not (body[end] == ';' and depth == 0):
                depth += (body[end] == '{') - (body[end] == '}')
                end += 1
            self.add_decl(body[at:end].strip())
            at = end + 1

    def add_action(self, head, inner):
        name, params = re.match(r'action\s+(\w+)\s*\((.*)\)$', head, re.S).groups()
        bound = []
        for part in split_top(params):
            _, bits, port, boolean, _, pname = PARAM.match(part).groups()
            bound.append((pname, int(bits) if bits else 9 if port else 1))
        self.actions[name] = (bound, parse_statements(inner))

    def add_table(self, name, body):
        keys = []
        found = re.search(r'\bkey\s*=\s*\{(.*?)\}', body, re.S)
        for item in (found[1].split(';') if found else ()):
            if item.strip():
                expr, kind = item.rsplit(':', 1)
                keys.append((parse_expr(expr.strip()), kind.strip()))
        entries = []
        found = re.search(r'\bentries\s*=\s*\{', body)
        if found:
            opening = found.end() - 1
            for item in body[opening + 1:match_brace(body, opening) - 1].split(';'):
                if item.strip():
                    entries.append(self.entry(name, item.strip(), len(keys)))
        default = re.search(r'default_action\s*=\s*(\w+)\s*\(([^)]*)\)', body)
        self.tables[name] = dict(keys=keys, entries=entries, runtime=[],
                                 default=(default[1], [parse_expr(a) for a in split_top(default[2])]) if default else ('NoAction', []))

    def entry(self, table, item, count):
        depth = 0
        for at, char in enumerate(item):
            depth += char == '('
            depth -= char == ')'
            if char == ':' and depth == 0:
                left, right = item[:at].strip(), item[at + 1:].strip()
                break
        if left.startswith('(') and p4syntax.match_paren(left, 0) == len(left):
            left = left[1:-1]
        terms = []
        for text in split_top(left):
            if text == '_':
                terms.append(('any',))
            elif '&&&' in text:
                terms.append(('mask',) + tuple(parse_expr(t) for t in text.split('&&&')))
            elif '..' in text:
                terms.append(('range',) + tuple(parse_expr(t) for t in text.split('..')))
            else:
                terms.append(('val', parse_expr(text)))
        if len(terms) != count:
            raise ValueError('key mismatch in table ' + table)
        action, args = re.match(r'(\w+)\((.*)\)$', right, re.S).groups()
        return terms, action, [parse_expr(a) for a in split_top(args)]

    def add_decl(self, text):
        reg = re.match(r'Register<\s*(.+?)\s*,\s*bit<\d+>\s*>\s*\(\s*(\d+)\s*,\s*(.*)\)\s*(\w+)$', text, re.S)
        act = re.match(r'RegisterAction<.*?>\((\w+)\)\s*(\w+)\s*=\s*\{\s*void\s+apply\((.*?)\)\s*\{(.*)\}\s*\}$', text, re.S)
        inst = re.match(r'(\w+)\(\)\s*(\w+)$', text)
        poly = re.match(r'CRCPolynomial<.*?>\((.*)\)\s*(\w+)$', text, re.S)
        hashed = re.match(r'Hash<.*?>\(HashAlgorithm_t\.CUSTOM,\s*(\w+)\)\s*(\w+)$', text)
        if reg:
            self.registers[reg[4]] = (reg[1], int(reg[2]), reg[3].strip())
        elif act:
            params = [PARAM.match(p).groups() for p in split_top(act[3])]
            self.ras[act[2]] = (act[1], [(g[0], int(g[1]) if g[1] else None, g[4], g[5]) for g in params],
                                parse_statements(act[4]))
        elif inst:
            self.insts[inst[2]] = inst[1]
        elif poly:
            self.polys[poly[2]] = [parse_expr(a) for a in split_top(poly[1])]
        elif hashed:
            self.hashes[hashed[2]] = hashed[1]
        else:
            raise ValueError('unsupported declaration ' + text[:60])


def crc(data, args):
    coeff, reflected = args[0][1], args[1][1]
    init, xor = args[4][1], args[5][1]
    if not reflected:
        value = init
        for byte in data:
            value ^= byte << 8
            for _ in range(8):
                value = ((value << 1) ^ coeff if value & 0x8000 else value << 1) & 0xffff
        return value ^ xor
    flipped = int(format(coeff, '016b')[::-1], 2)
    value = int(format(init, '016b')[::-1], 2)
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (flipped if value & 1 else 0)
    return value ^ xor


class ExtSource(PacketSource):
    def __init__(self, text, include_dir=None):
        def include(match):
            if include_dir is None:
                raise ValueError('#include "%s" needs include_dir' % match[1])
            return Path(include_dir, match[1]).read_text()
        text = re.sub(r'^\s*#include\s+"([^"]+)"', include, text, flags=re.M)
        text = re.sub(r'^\s*#(?:ifndef|define|endif).*$', '', text, flags=re.M)
        # pkt.lookahead<bit<N>>() -> pkt.lookahead_N(): the expression parser has no generic call syntax
        text = re.sub(r'pkt\.lookahead\s*<\s*bit\s*<\s*(\d+)\s*>\s*>\s*\(\s*\)', r'pkt.lookahead_\1()', text)
        text = normalize(text)
        PacketSource.__init__(self, text)
        meta = block(self.text, 'struct meta_t')
        for name in re.findall(r'PortId_t\s+(\w+);', meta):
            self.width['m.' + name] = 9
        for name in re.findall(r'bool\s+(\w+);', meta):
            self.width['m.' + name] = 1
        for name in re.findall(r'MirrorId_t\s+(\w+);', meta):   # bit<10> on Tofino-1 (tofino1_specs.p4)
            self.width['m.' + name] = 10
        self.width.update(INTRINSIC)
        self.consts = {}
        for match in re.finditer(r'const\s+(?:PortId_t|MirrorId_t)\s+(\w+)\s*=\s*(\d+)w(0[xX][0-9a-fA-F]+|\d+)\s*;', self.text):
            self.consts[match[1]] = (int(match[3], 0), int(match[2]))
        for match in re.finditer(r'const\s+bit<(\d+)>\s+(\w+)\s*=\s*(0[xX][0-9a-fA-F]+|\d+)\s*;', self.text):
            self.consts[match[2]] = (int(match[3], 0), int(match[1]))
        self.structs = {n: [(f, int(w)) for w, f in re.findall(r'bit<(\d+)>\s+(\w+);', b)]
                        for n, b in re.findall(r'struct\s+(\w+)\s*\{([^}]*)\}', self.text)}
        self.header_order = re.findall(r'\w+\s+(\w+);', block(self.text, 'struct headers_t'))
        # Ingress and every control it instantiates, transitively (any number of externs).
        self.controls = {'Ingress': Control(self.text, 'Ingress')}
        pending = list(self.controls['Ingress'].insts.values())
        while pending:
            kind = pending.pop()
            if kind not in self.controls:
                self.controls[kind] = Control(self.text, kind)
                pending.extend(self.controls[kind].insts.values())
        self.cells = {}
        self.runtime_installed = []
        self.frame = Frame(self.controls['Ingress'], '')
        self.csum = None
        self.events, self.invalid_reads = [], set()
        self.pstates = self.parse_states('IgParser')
        self.emit = re.findall(r'pkt\.emit\(([\w.]+)\)', block(self.text, 'control IgDeparser('))
        self.reset_registers()

    # ---- state ----------------------------------------------------------------------------
    def reset_registers(self):
        self.cells = {}
        ingress = self.controls['Ingress']
        instances = [('', ingress)] + [(inst, self.controls[kind]) for inst, kind in ingress.insts.items()]
        for path, ctrl in instances:
            for name, (typ, size, init) in ctrl.registers.items():
                self.cells[(path, name)] = [self.initial(typ, init) for _ in range(size)]

    def initial(self, typ, init):
        if typ.startswith('bit<'):
            return int(init, 0)
        values = [int(v, 0) for v in re.findall(r'0[xX][0-9a-fA-F]+|\d+', init)]
        return {f: v for (f, _), v in zip(self.structs[typ], values)}

    def begin_pass(self, ingress_port):
        for key in list(self.env):
            if key.startswith(('hdr.', 'm.', 'md.', 'tm.')):
                del self.env[key]
        self.env['ig.ingress_port'] = ingress_port
        self.valid, self.events, self.invalid_reads = {}, [], set()
        self.frame = Frame(self.controls['Ingress'], '')

    def install(self, table, keys, action, args=(), priority=None):
        """priority: as BF Runtime $MATCH_PRIORITY, the LOWEST value wins among matching runtime rows. A row
        on a table with any ternary/range/lpm key, or with any (value, mask) term, must carry one (as the
        hardware requires); rows on all-exact tables keep priority None."""
        kinds = {kind for _, kind in self.controls['Ingress'].tables[table]['keys']}
        if priority is None and (kinds & {'ternary', 'range', 'lpm'} or any(isinstance(k, tuple) for k in keys)):
            raise ValueError('ternary runtime row on %s needs an explicit priority' % table)
        self.controls['Ingress'].tables[table]['runtime'].append((tuple(keys), action, list(args), priority))

    # ---- expressions ----------------------------------------------------------------------
    def lookup(self, name):
        frame = self.frame
        if name in frame.loc:
            return frame.loc[name], frame.locw.get(name)
        if name in self.consts:
            return self.consts[name]
        if name in self.width:
            if name.startswith('hdr.') and not self.valid.get(name.split('.')[1]):
                self.invalid_reads.add(name)
            return self.env.get(name, 0), self.width[name]
        raise ValueError('unsupported expression ' + name)

    def ev(self, node):
        kind = node[0]
        if kind == 'num':
            return node[1], node[2]
        if kind == 'name':
            return self.lookup(node[1])
        if kind == 'slice':
            value, _ = self.ev(node[1])
            hi, lo = node[2], node[3]
            return (value >> lo) & ((1 << (hi - lo + 1)) - 1), hi - lo + 1
        if kind == 'cast':
            value, _ = self.ev(node[3])
            if node[1] == 'int':
                value &= (1 << node[2]) - 1
                return (value - (1 << node[2]) if value >> (node[2] - 1) else value), None
            return value & ((1 << node[2]) - 1), node[2]
        if kind == 'un':
            value, width = self.ev(node[2])
            if node[1] == '!':
                return int(not value), 1
            if node[1] == '~':
                return ~value & ((1 << width) - 1), width
            return (-value if width is None else -value & ((1 << width) - 1)), width
        if kind == 'bin':
            return self.binary(node)
        if kind == 'call':
            return self.call(node[1], node[2], node)
        raise ValueError('unsupported expression node ' + kind)

    def binary(self, node):
        op = node[1]
        if op in ('&&', '||'):
            left, _ = self.ev(node[2])
            if (op == '&&') != bool(left):
                return int(bool(left)), 1
            return int(bool(self.ev(node[3])[0])), 1
        (a, aw), (b, bw) = self.ev(node[2]), self.ev(node[3])
        width = aw if aw is not None else bw
        if op == '++':
            if aw is None or bw is None:
                raise ValueError('concatenation needs sized operands')
            return (a << bw) | b, aw + bw
        if op in ('==', '!=', '<', '>', '<=', '>='):
            return int({'==': a == b, '!=': a != b, '<': a < b, '>': a > b, '<=': a <= b, '>=': a >= b}[op]), 1
        # operators are evaluated lazily: `a << b` with a 32-bit b allocates gigabytes
        value = {'+': lambda: a + b, '-': lambda: a - b, '*': lambda: a * b, '&': lambda: a & b,
                 '|': lambda: a | b, '^': lambda: a ^ b, '<<': lambda: a << b, '>>': lambda: a >> b,
                 '/': lambda: a // b if b else 0, '%': lambda: a % b if b else 0}[op]()
        return (value & ((1 << width) - 1) if width is not None else value), width

    def expr(self, text):
        return self.ev(parse_expr(text))[0]

    # ---- statements -----------------------------------------------------------------------
    def run(self, text):
        self.exec_all(parse_statements(text))

    def exec_all(self, stmts):
        for stmt in stmts:
            self.exec_stmt(stmt)

    def exec_stmt(self, stmt):
        if stmt[0] == 'assign':
            self.store(stmt[1], self.ev(stmt[2])[0])
        elif stmt[0] == 'if':
            self.exec_all(stmt[2] if self.ev(stmt[1])[0] else stmt[3])
        else:
            self.ev(stmt[1])

    def store(self, target, value):
        if target[0] == 'slice':
            old, width = self.ev(target[1])
            hi, lo = target[2], target[3]
            mask = ((1 << (hi - lo + 1)) - 1) << lo
            return self.store(target[1], (old & ~mask) | ((value << lo) & mask))
        name, frame = target[1], self.frame
        if name in frame.loc:
            width = frame.locw.get(name)
            frame.loc[name] = value & ((1 << width) - 1) if width else value
        elif name in self.width:
            self.env[name] = value & ((1 << self.width[name]) - 1)
        else:
            raise ValueError('unsupported assignment target ' + name)

    # ---- calls ----------------------------------------------------------------------------
    def call(self, path, args, node=None):
        ctrl = self.frame.ctrl
        owner, _, method = path.rpartition('.')
        if path.startswith('pkt.'):
            return self.pkt_call(method, args)
        if owner in ('ic', 'tc') and self.csum is not None:
            return self.csum_call(owner, method, args)
        if method in ('setValid', 'setInvalid'):
            self.valid[owner.split('.')[1]] = method == 'setValid'
            return 0, None
        if method == 'isValid' and owner.startswith('hdr.') and not args:
            return int(bool(self.valid.get(owner.split('.')[1]))), 1
        if method == 'execute' and owner in ctrl.ras:
            return self.execute(owner, self.ev(args[0])[0]), None
        if method == 'get' and owner in ctrl.hashes:
            return self.hash(owner, args[0])
        if method == 'apply' and not owner:
            raise ValueError('unsupported apply')
        if method == 'apply' and owner in ctrl.tables:
            self.apply_table(owner)
            return 0, None
        if method == 'apply' and owner in ctrl.insts:
            self.apply_instance(owner, args)
            return 0, None
        if not owner:
            self.run_action(path, [self.ev(a) for a in args])
            return 0, None
        raise ValueError('unsupported call ' + path)

    def hash(self, name, items):
        ctrl = self.frame.ctrl
        bits, total = 0, 0
        for item in items[1]:
            value, width = self.ev(item)
            if width is None:
                raise ValueError('hash input without a width')
            bits, total = (bits << width) | value, total + width
        if total % 8:
            raise ValueError('hash input not byte aligned')
        data = bits.to_bytes(total // 8, 'big')
        return crc(data, ctrl.polys[ctrl.hashes[name]]), 16

    def run_action(self, name, values):
        if name == 'NoAction':
            return
        params, body = self.frame.ctrl.actions[name]
        self.events.append('action ' + name)
        self.scoped(params, [v for v, _ in values], body)

    def scoped(self, params, values, body, after=None):
        frame, saved = self.frame, []
        for (pname, width), value in zip(params, values):
            saved.append((pname, frame.loc.get(pname), frame.locw.get(pname)))
            frame.loc[pname], frame.locw[pname] = value & ((1 << width) - 1), width
        try:
            self.exec_all(body)
            return after() if after else None
        finally:
            for pname, old, oldw in saved:
                if old is None:
                    frame.loc.pop(pname, None), frame.locw.pop(pname, None)
                else:
                    frame.loc[pname], frame.locw[pname] = old, oldw

    def execute(self, name, index):
        frame = self.frame
        reg, params, body = frame.ctrl.ras[name]
        typ = frame.ctrl.registers[reg][0]
        cell = self.cells[(frame.path, reg)][index]
        vname, rname, rwidth = params[0][3], params[1][3], params[1][1]
        if typ.startswith('bit<'):
            names, widths, values = [vname], [int(typ[4:-1])], [cell]
        else:
            fields = self.structs[typ]
            names = [vname + '.' + f for f, _ in fields]
            widths, values = [w for _, w in fields], [cell[f] for f, _ in fields]
        self.events.append('register %s.%s' % (reg, name))

        def after():
            if typ.startswith('bit<'):
                self.cells[(frame.path, reg)][index] = frame.loc[vname]
            else:
                for (field, _), pname in zip(fields, names):
                    cell[field] = frame.loc[pname]
            return frame.loc[rname]
        return self.scoped(list(zip(names + [rname], widths + [rwidth])), values + [0], body, after)

    def apply_instance(self, inst, args):
        ctrl = self.controls[self.frame.ctrl.insts[inst]]
        outer, frame = self.frame, Frame(ctrl, inst)
        copyout = []
        for (kind, width, pname), arg in zip(ctrl.params, args):
            frame.loc[pname], frame.locw[pname] = (self.ev(arg)[0] if kind != 'out' else 0) & ((1 << width) - 1), width
            if kind in ('inout', 'out'):
                copyout.append((pname, arg))
        self.events.append('control ' + inst)
        self.frame = frame
        try:
            self.exec_all(ctrl.apply_body)
        finally:
            self.frame = outer
        for pname, arg in copyout:
            self.store(arg, frame.loc[pname])

    def register(self, name, index):
        return self.execute(name, index)

    def action(self, name, args=()):
        params, _ = self.frame.ctrl.actions[name] if name != 'NoAction' else ([], [])
        self.run_action(name, [(a, None) for a in args])

    def table(self, name):
        self.apply_table(name)

    # ---- tables ---------------------------------------------------------------------------
    def apply_table(self, name):
        table = self.frame.ctrl.tables[name]
        keys = [(self.ev(node)[0], kind) for node, kind in table['keys']]
        for terms, action, args in table['entries']:
            if all(self.match(term, key) for term, (key, _) in zip(terms, keys)):
                return self.hit(name, action, args, 'const', keys)
        # A runtime key term is an int (exact) or a (value, mask) pair (ternary). Among matching rows the lowest
        # explicit priority wins (BF Runtime $MATCH_PRIORITY); install order never decides between ternary rows.
        hits = [(priority, values, action, args) for values, action, args, priority in table['runtime']
                if len(values) == len(keys) and all(
                    (k & v[1]) == (v[0] & v[1]) if isinstance(v, tuple) else k == v
                    for (k, _), v in zip(keys, values))]
        if hits:
            exact = [h for h in hits if h[0] is None]
            _, _, action, args = exact[0] if exact else min(hits, key=lambda h: h[0])
            return self.hit(name, action, args, 'runtime', keys)
        action, args = table['default']
        return self.hit(name, action, args, 'default', keys)

    def hit(self, table, action, args, via, keys):
        self.events.append('table %s -> %s (%s) keys=%s' % (table, action, via, [k for k, _ in keys]))
        self.run_action(action, [self.ev(a) if not isinstance(a, int) else (a, None) for a in args])

    def match(self, term, key):
        if term[0] == 'any':
            return True
        if term[0] == 'val':
            return self.ev(term[1])[0] == key
        if term[0] == 'range':
            return self.ev(term[1])[0] <= key <= self.ev(term[2])[0]
        value, mask = self.ev(term[1])[0], self.ev(term[2])[0]
        return key & mask == value & mask

    # ---- parser ---------------------------------------------------------------------------
    def parse_states(self, name):
        text = block(self.text, 'parser ' + name + '(')
        states = {}
        for found in re.finditer(r'\bstate\s+(\w+)\s*\{', text):
            end = match_brace(text, found.end() - 1)
            parser = Parser(text[found.end():end - 1])
            stmts = []
            while parser.peek() != 'transition':
                if not parser.accept(';'):
                    stmts.append(parser.statement())
            parser.next()
            states[found[1]] = (stmts, self.transition(parser))
        return states

    def transition(self, parser):
        if parser.peek() != 'select':
            target = parser.next()[1]
            parser.accept(';')
            return ('goto', target)
        parser.next(), parser.expect('(')
        keys = []
        while not parser.accept(')'):
            keys.append(parser.expr())
            parser.accept(',')
        parser.expect('{')
        cases = []
        while not parser.accept('}'):
            terms = []
            if parser.accept('default'):
                terms = None
            elif parser.peek() == '(' :
                parser.next()
                while not parser.accept(')'):
                    terms.append(self.keyset(parser))
                    parser.accept(',')
            else:
                terms.append(self.keyset(parser))
            parser.expect(':')
            cases.append((terms, parser.next()[1]))
            parser.accept(';')
        return ('select', keys, cases)

    def keyset(self, parser):
        if parser.peek() == '_':
            parser.next()
            return ('any',)
        first = parser.expr()
        if parser.accept('..'):
            return ('range', first, parser.expr())
        if parser.accept('&&&'):
            return ('mask', first, parser.expr())
        return ('val', first)

    def pkt_call(self, method, args):
        if method.startswith('lookahead_'):            # the next N bits at the cursor, not consumed
            width = int(method.split('_')[1])
            size = (width + 7) // 8
            if self.cursor + size > len(self.raw):
                raise ParserError('truncated lookahead')
            value = int.from_bytes(self.raw[self.cursor:self.cursor + size], 'big') >> (size * 8 - width)
            return value, width
        if method == 'extract':
            header = args[0][1]
            if header in ('ig', 'eg'):
                return 0, None
            name = header.split('.')[1]
            fields = [(k, w) for k, w in self.width.items() if k.startswith('hdr.%s.' % name)]
            size = sum(w for _, w in fields) // 8
            raw, cursor = self.raw, self.cursor
            if cursor + size > len(raw):
                raise ParserError('truncated extract of hdr.' + name)
            value, remaining = int.from_bytes(raw[cursor:cursor + size], 'big'), size * 8
            for key, width in fields:
                remaining -= width
                self.env[key] = (value >> remaining) & ((1 << width) - 1)
            self.valid[name] = True
            self.cursor += size
        return 0, None

    def csum_bytes(self, node):
        if node[0] == 'list':
            bits, total = 0, 0
            for item in node[1]:
                value, width = self.ev(item)
                bits, total = (bits << width) | value, total + width
            return bits.to_bytes(total // 8, 'big')
        return self.render(node[1].split('.')[1])

    def csum_call(self, owner, method, args):
        if method in ('add', 'subtract'):
            # Both accumulate additively: the 0xffeb constant the P4 tests is the folded sum
            # when ip.len (not tcp length) enters the pseudo-header. Target semantics unverified.
            self.csum[owner].extend(self.csum_bytes(args[0]))
            return 0, None
        data = bytes(self.csum[owner])
        if method == 'verify':
            return int(folded(data) != 65535), 1
        return checksum(data), 16

    def packet_parser(self, raw, parser='IgParser'):
        self.raw, self.cursor, self.csum = bytes(raw), 0, {'ic': bytearray(), 'tc': bytearray()}
        state, states = 'start', []
        self.parse_error = None
        try:
            for _ in range(64):
                if state in ('accept', 'reject'):
                    break
                states.append(state)
                stmts, transition = self.pstates[state]
                self.exec_all(stmts)
                if transition[0] == 'goto':
                    state = transition[1]
                    continue
                keys = [self.ev(k)[0] for k in transition[1]]
                state = None
                for terms, target in transition[2]:
                    if terms is None or all(self.match(t, k) for t, k in zip(terms, keys)):
                        state = target
                        break
                if state is None:
                    raise ParserError('no select match in state ' + states[-1])
            else:
                raise ParserError('parser exceeded bounded states')
        except ParserError as error:
            self.parse_error = '%s (state %s)' % (error, states[-1])
        self.parser_states, self.csum = states, None
        return self.parse_error is None and state == 'accept', self.cursor

    # ---- control / deparser ---------------------------------------------------------------
    def apply_control(self, name='Ingress'):
        self.frame = Frame(self.controls[name], '')
        self.exec_all(self.controls[name].apply_body)

    def deparse(self, name='IgDeparser', headers=None):
        order = headers or [h for h in self.header_order if 'hdr' in self.emit or 'hdr.' + h in self.emit]
        return b''.join(self.render(h) for h in order if self.valid.get(h, False))
