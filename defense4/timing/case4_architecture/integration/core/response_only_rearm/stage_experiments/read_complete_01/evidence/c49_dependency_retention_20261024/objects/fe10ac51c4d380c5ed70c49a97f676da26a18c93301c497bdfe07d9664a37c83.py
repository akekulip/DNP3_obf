"""Rename a TNA-style program onto the names interp_ext.ExtSource evaluates (SOURCE LEVEL only).

ExtSource reads `headers_t`/`meta_t`, `IgParser`/`IgDeparser`, the prefixes `hdr.`/`m.`/`ig.`/`tm.`
and checksum objects named `ic`/`tc`. A program written with the stock TNA names (`header_t`,
`metadata_t`, `ig_intr_md`, `ig_tm_md`, `ig_dprsr_md`, `ig_prsr_md`, `IngressParser`, ...) is
renamed here, token for token; no statement is rewritten. Programs already in the harness
dialect (`struct headers_t` present) are returned unchanged.
"""
import re

TNA_TIMER = ('header pktgen_timer_header_t { bit<3> pad0; bit<2> pipe_id; bit<3> app_id; bit<8> pad1;'
             ' bit<16> batch_id; bit<16> packet_id; }\n')
INTRINSIC_KINDS = (('ingress_intrinsic_metadata_from_parser_t', 'ig'),
                   ('ingress_intrinsic_metadata_for_deparser_t', 'md'),
                   ('ingress_intrinsic_metadata_for_tm_t', 'tm'),
                   ('ingress_intrinsic_metadata_t', 'ig'))


def split_params(text):
    parts, depth, start = [], 0, 0
    for at, char in enumerate(text):
        depth += char in '(<{'
        depth -= char in ')>}'
        if char == ',' and depth == 0:
            parts.append(text[start:at])
            start = at + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def normalize(text):
    if re.search(r'\bstruct\s+headers_t\b', text):
        return text
    text = re.sub(r'^\s*#include\s+<[^>]+>[^\n]*$', '', text, flags=re.M)
    signature = re.search(r'\bcontrol\s+(\w+)\s*\(([^)]*ingress_intrinsic_metadata_for_tm_t[^)]*)\)', text)
    if not signature:
        return text
    names, header_type, meta_type = {}, None, None
    for param in split_params(signature[2]):
        words = param.split()
        kind, name = words[-2], words[-1]
        for intrinsic, canonical in INTRINSIC_KINDS:
            if kind == intrinsic:
                names[name] = canonical
                break
        else:
            if header_type is None:
                header_type, names[name] = kind, 'hdr'
            else:
                meta_type, names[name] = kind, 'm'
    names = {old: new for old, new in names.items() if old != new}
    pattern = '|'.join(r'\b%s\b' % re.escape(old) for old in sorted(names, key=len, reverse=True))
    if pattern:
        text = re.sub(pattern, lambda m: names[m[0]], text)
    text = re.sub(r'\b%s\b' % re.escape(header_type), 'headers_t', text)
    text = re.sub(r'\b%s\b' % re.escape(meta_type), 'meta_t', text)
    parser = re.search(r'\bparser\s+(\w+)\s*\([^)]*ingress_intrinsic_metadata_t', text)
    if parser:
        text = re.sub(r'\b%s\b' % parser[1], 'IgParser', text)
    deparser = re.search(r'\bcontrol\s+(\w+)\s*\(\s*packet_out', text)
    if deparser:
        text = re.sub(r'\b%s\b' % deparser[1], 'IgDeparser', text)
    for new, old in zip(('ic', 'tc'), re.findall(r'Checksum\(\)\s+(\w+)\s*;', text)):
        text = re.sub(r'\b%s\b' % old, new, text)
    if 'pktgen_timer_header_t' in text and not re.search(r'header\s+pktgen_timer_header_t\b', text):
        text = TNA_TIMER + text
    return text
