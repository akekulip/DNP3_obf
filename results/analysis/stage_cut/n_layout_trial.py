"""One-shot N layout experiment; the canonical P4 is the shipped source."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'results/builds/c69_baseline/response_only.p4'

def block(source, kind, name):
    start = re.search(r'\b'+kind+r'\s+'+name+r'\b', source).start()
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

def entries(table):
    body = table.split('const entries={', 1)[1].rsplit('}', 2)[0]
    return [(key.split(','), action, argument) for key, action, argument in
            re.findall(r'\(([^()]*)\):([a-zA-Z_0-9]+)\(([^()]*)\);', body)]

def ternary(text, width):
    if text == '_':
        return 0, 0
    parts = text.split('&&&')
    value = int(parts[0].split('w')[-1], 0)
    mask = int(parts[1].split('w')[-1], 0) if len(parts) == 2 else (1 << width) - 1
    return value & mask, mask

def intersect(left, right, width, shift=0):
    av, am = ternary(left, width)
    bv, bm = ternary(right, width-shift)
    bv, bm = bv << shift, bm << shift
    if (av ^ bv) & am & bm:
        return None
    mask, value = am | bm, (av & am) | (bv & bm)
    return '_' if not mask else f'{width}w0x{value:x}&&&{width}w0x{mask:x}'

WIDTHS = (8,3,1,32,32,32,2,8,32,1,2,8,32)

def uncovered(original, covers):
    remaining=[tuple(ternary(k,w) for k,w in zip(original,WIDTHS))]
    for cover in covers:
        cover=tuple(ternary(k,w) for k,w in zip(cover,WIDTHS))
        next_remaining=[]
        for cube in remaining:
            if any((a^b)&am&bm for (a,am),(b,bm) in zip(cube,cover)):
                next_remaining.append(cube)
                continue
            inside=list(cube)
            for column, ((a,am),(b,bm)) in enumerate(zip(cube,cover)):
                extra=bm&~am
                while extra:
                    bit=extra&-extra
                    outside=inside.copy()
                    iv,im=inside[column]
                    outside[column]=((iv&~bit)|((~b)&bit),im|bit)
                    next_remaining.append(tuple(outside))
                    inside[column]=((iv&~bit)|(b&bit),im|bit)
                    extra-=bit
        remaining=next_remaining
        if not remaining:break
    return bool(remaining)

def transform(source):
    first = block(source, 'table', 'first_event')
    close = block(source, 'table', 'close_phase_t')
    rows = []
    for key, action, argument in entries(first):
        covers=[]
        if action in ('first_close', 'first_close_ack'):
            for ck, ca, phase in entries(close):
                assert ca == 'qualify_close'
                merged = key.copy()
                for index, value, width, shift in ((7,ck[0],8,0),(6,ck[1],2,0),
                                                   (3,ck[2],32,16),(5,ck[3],32,0)):
                    merged[index] = intersect(merged[index], value, width, shift)
                    if merged[index] is None:
                        break
                else:
                    rows.append((merged,action+'_qualified',phase))
                    covers.append(merged)
        if not covers or uncovered(key,covers):
            rows.append((key,action,argument))
    body = ''.join('('+','.join(key)+'):'+action+'('+argument+');' for key,action,argument in rows)
    new = first.split('const entries={',1)[0] + 'const entries={' + body + '}}'
    new = new.replace('actions={','actions={first_close_qualified;first_close_ack_qualified;',1)
    new = re.sub(r'size=\d+;',f'size={len(rows)};',new)
    source = source.replace(first,new).replace(close,'')
    source = source.replace(block(source,'action','qualify_close'),'')
    source = source.replace('if(m.kind==8w4||m.packet_kind==8w3){close_phase_t.apply();}', '')
    for name in ('first_close','first_close_ack'):
        original = block(source,'action',name)
        qualified = original.replace(name+'()',name+'_qualified(bit<16> phase)',1)
        qualified = qualified.replace('m.desired','(bit<32>)phase')
        source = source.replace(original,original+'\n '+qualified)
    # Snapshot fields independent of owner read are constructed before owner_t.
    for name in ('snapshot','snapshot_retry','snapshot_epoch_zero'):
        original = block(source,'action',name)
        source = source.replace(original,original.replace('hdr.expected_cell.expected_cell=m.observed;',''))
    predicate = '(bit<8>)m.stage==8w0&&m.work_phase==32w4&&(m.work_op==8w1||(m.kind==8w4&&(bit<8>)m.shape_valid==8w1))'
    source = source.replace('owner_command.apply();owner_t.apply();',
        'owner_command.apply();\n    if('+predicate+'){snapshot_t.apply();}\n    owner_t.apply();')
    source = source.replace('snapshot_t.apply();first_event.apply();',
                            'hdr.expected_cell.expected_cell=m.observed;first_event.apply();')
    return source

def split_event(source):
    source = source.replace('header n_event_h{bit<16> event;', 'header n_event_h{bit<8> phase;bit<8> code;')
    source = source.replace('hdr.event.event[15:8]','hdr.event.phase').replace('hdr.event.event[7:0]','hdr.event.code')
    def assignment(match):
        rhs = match.group(1)
        if rhs.startswith('16w'):
            value = int(rhs[3:],0)
            return f'hdr.event.phase=8w{value>>8};hdr.event.code=8w{value&255};'
        if rhs == 'hdr.event.event+16w0x100':
            return 'hdr.event.phase=hdr.event.phase+8w1;'
        if rhs == 'event':
            return 'hdr.event.phase=event[15:8];hdr.event.code=event[7:0];'
        if '++' in rhs:
            high,low=rhs.split('++')
            return f'hdr.event.phase={high};hdr.event.code={low};'
        raise ValueError(rhs)
    source = re.sub(r'hdr\.event\.event=([^;]+);',assignment,source)
    source = source.replace('hdr.event.event','(hdr.event.phase++hdr.event.code)')
    committed = block(source,'table','committed_t')
    split_key = committed.replace('(hdr.event.phase++hdr.event.code):exact;',
                                  'hdr.event.phase:exact;hdr.event.code:exact;')
    split_key = re.sub(r'16w0x([0-9a-f]+):committed_to_t',
        lambda m:'(8w'+str(int(m[1],16)>>8)+',8w'+str(int(m[1],16)&255)+'):committed_to_t',split_key)
    source = source.replace(committed,split_key)
    source = source.replace('@pa_solitary("ingress", "m.expected_work_phase")',
        '@pa_solitary("ingress", "m.expected_work_phase")\n'
        '@pa_solitary("ingress", "hdr.event.phase")\n@pa_solitary("ingress", "hdr.event.code")\n'
        '@pa_container_size("ingress", "hdr.event.phase", 8)\n@pa_container_size("ingress", "hdr.event.code", 8)')
    # The two byte updates no longer share a PHV container. Fold the common
    # forwarding action into each exclusive terminal action.
    original = block(source,'action','abort_work')
    source = source.replace(original,original.replace('{','{next_stage();',1))
    original = block(source,'action','carry_current')
    source = source.replace(original,original.replace('{','{next_stage();',1))
    source = source.replace('     next_stage_t.apply();\n','')
    anchor = '(m.kind==8w17&&(bit<8>)m.stage==8w2)){if(m.owner_diff!=32w0){abort_t.apply();}}'
    assert source.count(anchor)==1
    source = source.replace(anchor,anchor[:-1]+'else{next_stage_t.apply();}}')
    # A single ordered decision avoids re-applying the same abort table in
    # nested branches, which creates a control edge after next_stage_t.
    for table in ('next_stage_t','abort_t','carry_t'):
        source = source.replace(block(source,'table',table),'')
    terminal = ('table terminal_t{key={m.epoch_diff:exact;m.kind:ternary;m.stage:ternary;'
                'm.owner_op:ternary;m.owner_diff:exact;}'
                'actions={next_stage;abort_work;carry_current;}size=8;const entries={')
    for kind in (8,25,24,10,12):
        terminal += f'(32w0,8w{kind},_,_,32w0):next_stage();'
    terminal += ('(32w0,8w17,2w2,_,32w0):next_stage();'
                 '(32w0,_,_,1w1,32w0):carry_current();}'
                 'const default_action=abort_work();}')
    abort = block(source,'action','abort_work')
    source = source.replace(abort,abort+'\n '+terminal,1)
    begin = source.index('     if(m.epoch_diff!=32w0){abort_t.apply();}')
    end = source.index('    }else if(m.work_phase==32w3)',begin)
    source = source[:begin]+'     terminal_t.apply();\n'+source[end:]
    return source

if __name__ == '__main__':
    (ROOT/'p4/response_only.p4').write_text(split_event(transform(BASE.read_text())))
