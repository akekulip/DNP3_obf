"""Small asserted derivations shared by the isolated candidate generators."""
import re


def narrow_metadata(text, widths, ending):
    start, end = text.index('struct meta_t'), text.index(ending)
    block = text[start:end]
    for name, width in widths.items():
        block, count = re.subn(r'bit<8>\s+' + name + r';', 'bit<%d> %s;' % (width, name), block)
        assert count == 1, name
    text = text[:start] + block + text[end:]
    for name, width in widths.items():
        target = r'\bm\.' + name + r'\b'
        # Keep the baseline public action/control operands eight bits wide;
        # assignments explicitly truncate only the verified bounded enum.
        text = re.sub(target + r'(?!\s*=(?!=))', '(bit<8>)m.' + name, text)
        text = re.sub('(' + target + r'\s*=(?!=)\s*)([^;]+);',
                      lambda m: m[1] + '(bit<%d>)(%s);' % (width, m[2]), text)
    # Match keys retain their real width. Widening a key asks bf-p4c to allocate
    # a new PHV field for each zero-padded expression and defeats the reduction.
    def table(block):
        block = re.sub(r'/\*.*?\*/|//[^\n]*', '', block, flags=re.S)
        key = re.search(r'key\s*=\s*\{([^}]+)\}', block)
        if not key:
            return block
        key_widths = []
        for column in key[1].split(';'):
            if not column.strip():
                continue
            field = re.fullmatch(r'\s*\(bit<8>\)m\.(\w+)\s*:\s*\w+\s*', column)
            key_widths.append(widths.get(field[1]) if field else None)
        if not any(key_widths):
            return block
        block = re.sub(r'\(bit<8>\)(m\.\w+\s*:\s*\w+\s*;)', r'\1', block)
        entries = re.search(r'(const entries\s*=\s*\{)([^}]*)(\})', block)
        if not entries:
            return block
        rows = []
        for row in entries[2].split(';'):
            if not row.strip():
                continue
            left, right = row.split(':', 1)
            left = left.strip()
            grouped = left.startswith('(')
            columns = (left[1:-1] if grouped else left).split(',')
            assert len(columns) == len(key_widths), (block.split('{', 1)[0], left, len(key_widths))
            for i, width in enumerate(key_widths):
                if width:
                    limit = (1 << width) - 1
                    columns[i] = re.sub(r'8w(0x[0-9a-fA-F]+|\d+)',
                                        lambda m: '%dw%d' % (width, min(int(m[1], 0), limit)), columns[i])
                    columns[i] = re.sub(r'\bSH_\w+\b', lambda m: '(bit<%d>)%s' % (width, m[0]), columns[i])
            rows.append(('(' + ','.join(columns) + ')' if grouped else columns[0]) + ':' + right + ';')
        return block[:entries.start(2)] + ''.join(rows) + block[entries.end(2):]
    for match in reversed(list(re.finditer(r'\btable\s+\w+\s*\{', text))):
        depth, end = 1, match.end()
        while depth:
            depth += (text[end] == '{') - (text[end] == '}')
            end += 1
        text = text[:match.start()] + table(text[match.start():end]) + text[end:]
    return text
