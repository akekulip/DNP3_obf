"""Exact echo object-set seam; status bytes remain endpoint results, not identity."""
from pathlib import Path
from generate_carving import generate as carver
SELECTED_KEYS=('hdr.dl.dst','hdr.dl.src','hdr.first.w0[31:24]','hdr.first.w0[23:16]',
'hdr.first.w2[15:0]','hdr.first.w3','hdr.second.w0','hdr.second.w1[31:16]',
'hdr.second.w3','hdr.tail.w0','hdr.tail.w1')
def generate():
    s=carver().replace('struct meta_t{','struct meta_t{bit<1> selected_match;')
    s=s.replace('m.parsed=1w0;','m.parsed=1w0;m.selected_match=1w0;')
    seam='action selected(){m.selected_match=1w1;}\ntable selected_objects{key={'+''.join(k+':exact;' for k in SELECTED_KEYS)+'}actions={selected;NoAction;}size=2;default_action=NoAction();}\n'
    s=s.replace(' action eligible()',seam+' action eligible()')
    s=s.replace('if(m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){connection.apply();}', 'if(m.badh==1w0&&m.bad0==1w0&&m.bad1==1w0&&m.badt==1w0){selected_objects.apply();if(m.selected_match==1w1){connection.apply();}}')
    return s
if __name__=='__main__':Path(__file__).with_name('selected_carving.p4').write_text(generate())
