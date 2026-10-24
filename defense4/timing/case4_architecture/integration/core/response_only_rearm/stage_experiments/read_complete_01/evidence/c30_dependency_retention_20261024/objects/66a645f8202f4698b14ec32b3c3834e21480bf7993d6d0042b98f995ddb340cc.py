"""Tokenizer and recursive-descent parser for the P4 subset native_binding.p4 uses.

Produces plain tuples (an AST) that interp_ext.py evaluates. Source-level only:
nothing here models the Tofino target.
"""
import re

TOKEN = re.compile(
    r'\s*(?:(?P<num>\d+w0[xX][0-9a-fA-F]+|\d+w\d+|0[xX][0-9a-fA-F]+|\d+)'
    r'|(?P<id>[A-Za-z_]\w*)'
    r'|(?P<op>&&&|\.\.|\+\+|==|!=|>=|<=|&&|\|\||<<|>>|[-+*/%&|^~!<>=(){}\[\];:,.?]))')
LEVELS = (('||',), ('&&',), ('++',), ('|',), ('^',), ('&',), ('==', '!='),
          ('<', '>', '<=', '>='), ('<<', '>>'), ('+', '-'), ('*', '/', '%'))


def tokenize(text):
    out, at = [], 0
    text = text.rstrip()
    while at < len(text):
        match = TOKEN.match(text, at)
        if not match:
            raise ValueError('unsupported syntax near ' + repr(text[at:at + 30]))
        kind = match.lastgroup
        out.append((kind, match.group(kind)))
        at = match.end()
    return out


def match_brace(text, opening):
    depth, at = 0, opening
    while True:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
        if depth == 0:
            return at


def match_paren(text, opening):
    depth, at = 0, opening
    while True:
        depth += (text[at] == '(') - (text[at] == ')')
        at += 1
        if depth == 0:
            return at


def split_top(text, sep=','):
    parts, depth, last = [], 0, 0
    for at, char in enumerate(text):
        depth += char in '({[' 
        depth -= char in ')}]'
        if char == sep and depth == 0:
            parts.append(text[last:at])
            last = at + 1
    parts.append(text[last:])
    return [part.strip() for part in parts if part.strip()]


def number(text):
    if 'w' in text:
        width, value = text.split('w', 1)
        return ('num', int(value, 0), int(width))
    return ('num', int(text, 0), None)


class Parser:
    def __init__(self, text):
        self.toks = tokenize(text) if isinstance(text, str) else text
        self.at = 0

    def peek(self, ahead=0):
        at = self.at + ahead
        return self.toks[at][1] if at < len(self.toks) else None

    def next(self):
        tok = self.toks[self.at]
        self.at += 1
        return tok

    def accept(self, text):
        if self.peek() == text:
            self.at += 1
            return True
        return False

    def expect(self, text):
        if not self.accept(text):
            raise ValueError('expected %r near %r' % (text, self.peek()))

    def done(self):
        return self.at >= len(self.toks)

    def expr(self, level=0):
        if level == len(LEVELS):
            return self.unary()
        left = self.expr(level + 1)
        while self.peek() in LEVELS[level]:
            op = self.next()[1]
            left = ('bin', op, left, self.expr(level + 1))
        return left

    def unary(self):
        tok = self.peek()
        if tok in ('!', '~', '-'):
            self.next()
            return ('un', tok, self.unary())
        if tok == '(' and self.peek(1) in ('bit', 'int') and self.peek(2) == '<':
            self.at += 1
            kind = self.next()[1]
            self.expect('<')
            width = int(self.next()[1])
            self.expect('>')
            self.expect(')')
            return ('cast', kind, width, self.unary())
        return self.postfix(self.primary())

    def primary(self):
        kind, text = self.next()
        if kind == 'num':
            return number(text)
        if text == '(':
            node = self.expr()
            self.expect(')')
            return node
        if text == '{':
            items = []
            while not self.accept('}'):
                items.append(self.expr())
                self.accept(',')
            return ('list', items)
        if kind != 'id':
            raise ValueError('unexpected token ' + repr(text))
        if text in ('true', 'false'):
            return ('num', int(text == 'true'), 1)
        path = text
        while self.peek() == '.' and self.peek(1) is not None and self.toks[self.at + 1][0] == 'id':
            self.at += 1
            path += '.' + self.next()[1]
        if self.peek() == '(':
            self.at += 1
            args = []
            while not self.accept(')'):
                args.append(self.expr())
                self.accept(',')
            return ('call', path, args)
        return ('name', path)

    def postfix(self, node):
        while self.peek() == '[':
            self.at += 1
            hi = self.expr()
            self.expect(':')
            lo = self.expr()
            self.expect(']')
            node = ('slice', node, hi[1], lo[1])
        return node

    def statement(self):
        if self.peek() == 'if':
            self.next()
            self.expect('(')
            cond = self.expr()
            self.expect(')')
            then = self.branch()
            other = []
            if self.peek() == 'else':
                self.next()
                other = [self.statement()] if self.peek() == 'if' else self.branch()
            return ('if', cond, then, other)
        left = self.expr()
        if self.accept('='):
            node = ('assign', left, self.expr())
        else:
            node = ('expr', left)
        self.expect(';')
        return node

    def branch(self):
        if self.accept('{'):
            return self.block_rest()
        return [self.statement()]

    def block_rest(self):
        out = []
        while not self.accept('}'):
            if not self.accept(';'):
                out.append(self.statement())
        return out

    def statements(self):
        out = []
        while not self.done():
            if not self.accept(';'):
                out.append(self.statement())
        return out


def parse_statements(text):
    return Parser(text).statements()


def parse_expr(text):
    parser = Parser(text)
    node = parser.expr()
    if not parser.done():
        raise ValueError('trailing tokens in expression ' + text)
    return node
